#
# Copyright 2014 Quantopian, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from abc import ABCMeta, abstractmethod
import atexit
from bdb import Breakpoint
from contextlib import contextmanager
import errno
import os
import signal
from struct import pack, unpack
import sys

from gevent import socket, Timeout
import gipc
from logbook import Logger

from qdb.errors import (
    QdbFailedToConnect,
    QdbBreakpointReadError,
    QdbCommunicationError,
    QdbUnreachableBreakpoint,
    QdbAuthenticationError,
)

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

try:
    import cPickle as pickle
except ImportError:
    import pickle

log = Logger('Qdb')


@contextmanager
def capture_output():
    """
    Captures stdout and stderr for the duration of the body.
    """
    sys.stdout = StringIO()
    sys.stderr = StringIO()
    try:
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout.close()
        sys.stderr.close()
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__


def fmt_msg(event, payload=None, serial=None):
    """
    Packs a message to be sent to the server.
    Serial is a function to call on the frame to serialize it, e.g:
    json.dumps or pickle.dumps
    """
    frame = {
        'e': event,
        'p': payload,
    }
    return serial(frame) if serial else frame


def fmt_err_msg(error_type, data, serial=None):
    """
    Constructs an error message.
    """
    return fmt_msg(
        'error', {
            'type': error_type,
            'data': data,
        },
        serial=serial,
    )


def fmt_breakpoint(breakpoint):
    """
    formats breakpoint payload.
    """
    return {
        'file': breakpoint.file,
        'line': breakpoint.line,
        'temp': breakpoint.temporary,
        'cond': breakpoint.cond,
        'func': breakpoint.funcname,
    }


class CommandManager(object):
    """
    An abstract base class for the command managers that control the tracer.
    """
    __metaclass__ = ABCMeta

    def __init__(self, tracer):
        self.tracer = tracer

    def _fmt_stackframe(self, stackframe, line):
        """
        Formats stackframe payload data.
        """
        filename = stackframe.f_code.co_filename
        func = stackframe.f_code.co_name
        code = self.tracer.get_line(filename, line)
        return {
            'file': self.tracer.canonic(filename),
            'line': line,
            'func': func,
            'code': code,
        }

    def send_breakpoints(self):
        """
        Sends the breakpoint list event.
        """
        self.send_event(
            'breakpoints',
            [fmt_breakpoint(breakpoint) for breakpoint in Breakpoint.bpbynumber
             if breakpoint]
        )

    def send_watchlist(self):
        """
        Sends the watchlist event.
        """
        self.send_event(
            'watchlist',
            [{'expr': k, 'exc': exc, 'value': val}
             for k, (exc, val) in self.tracer.watchlist.iteritems()],
        )

    def send_print(self, input, exc, output):
        """
        Sends the print event with the given input and output.
        """
        self.send(fmt_msg(
            'print', {
                'input': input,
                'exc': exc,
                'output': output
            },
            serial=pickle.dumps)
        )

    def send_stack(self):
        """
        Sends the stack event.
        """
        # Starting at the frame we are in, we need to filter based on the
        # tracer's skip_fn rules. We will also format each stackframe.
        self.send_event(
            'stack',
            {
                'index': self.tracer.curindex,
                'stack': [self._fmt_stackframe(stackframe, line)
                          for stackframe, line in self.tracer.stack
                          if not self.tracer.skip_fn(
                              self.tracer.canonic(
                                  stackframe.f_code.co_filename))],
            }
        )

    def send_stdout(self):
        """
        Sends a print that denotes that this is coming from the process.
        This function is a nop if the tracer is not set to redirect the
        stdout and stderr to the client.
        """
        if self.tracer.redirect_stdout:
            self.tracer.stdout.seek(self.tracer.stdout_ptr)
            out = self.tracer.stdout.read()
            self.tracer.stdout_ptr += len(out)
            self.send_print('<stdout>', False, out)

    def send_error(self, error_type, error_data):
        """
        Sends a formatted error message.
        """
        self.send(fmt_err_msg(error_type, error_data, serial=pickle.dumps))

    def send_event(self, event, payload=None):
        """
        Sends a formatted event.
        """
        self.send(fmt_msg(event, payload, serial=pickle.dumps))

    def next_command(self, msg=None):
        """
        Processes the next command from the user.
        If msg is given, it is sent with self.send(msg) before processing the
        next command.
        """
        if msg:
            self.send(msg)
        self.user_next_command()

    @abstractmethod
    def send(self, msg):
        """
        Sends a raw (already pickled) message.
        """
        raise NotImplementedError

    @abstractmethod
    def user_next_command(self):
        """
        Processes the next command.
        This method must be overridden to dictate how the commands are
        processed.
        """
        raise NotImplementedError

    @abstractmethod
    def start(self, auth_msg=''):
        """
        Start acquiring new commands.
        """
        raise NotImplementedError

    @abstractmethod
    def stop(self):
        """
        Stop acquiring new commands.
        Use this to release and resources needed to generate the commands.
        """
        raise NotImplementedError


class NopCommandManager(CommandManager):
    """
    Nop command manager that never alters the state of the debugger.
    This is useful if you want to manage the debugger in an alternate way.
    """
    def user_next_command(self):
        pass

    def send(self, msg):
        pass

    def start(self, msg):
        pass

    def stop(self):
        pass


class RemoteCommandManager(CommandManager):
    """
    Manager that processes commands from the server.
    This is the default Qdb command manager.
    """
    def __init__(self, tracer):
        super(RemoteCommandManager, self).__init__(tracer)

        # Construct a pipe to talk to the reader.
        self.pipe = None

        # Attach the signal handler to manage the pause command.
        signal.signal(tracer.pause_signal, self._pause_handler)

        log.info('Connecting to (%s, %d)' % tracer.address)
        self.socket = None
        self.reader = None

    def _socket_connect(self):
        """
        Connects to the socket or raise a QdbFailedToConnect error.
        """
        for n in xrange(self.tracer.retry_attepts):
            # Try to connect to the server.
            try:
                self.socket = socket.create_connection(self.tracer.address)
                # If we made it here, we connected and no longer need to retry.
                break
            except socket.error:
                log.warn(
                    'Client %s failed to connect to (%s, %d) on attempt %d...'
                    % (self.tracer.uuid, self.tracer.address[0],
                       self.tracer.address[1], n + 1)
                )
        if self.socket is None:
            log.warn(
                'Failed to connect to (%s, %d), no longer retying.'
                % self.tracer.address
            )
            raise QdbFailedToConnect(
                self.tracer.address,
                self.tracer.retry_attepts
            )
        log.info('Client %s connected to (%s, %d)'
                 % (self.tracer.uuid, self.tracer.address[0],
                    self.tracer.address[1]))

    def start(self, auth_msg=''):
        """
        Begins processing commands from the server.
        """
        self.pipe, child_end = gipc.pipe()
        self._socket_connect()
        self.reader = gipc.start_process(
            target=ServerReader,
            args=(child_end, os.getpid(), self.socket.fileno(),
                  self.tracer.pause_signal),
        )
        with Timeout(5, QdbFailedToConnect(self.tracer.address,
                                           self.tracer.retry_attepts)):
            self.pipe.get()
        self.send(
            fmt_msg(
                'start', {
                    'uuid': self.tracer.uuid,
                    'auth': auth_msg,
                    'local': (0, 0),
                },
                serial=pickle.dumps,
            )
        )
        atexit.register(self.stop)

    def stop(self):
        """
        Stops the command manager, freeing its resources.
        """
        if self.reader:
            self.reader.terminate()
        self.socket.close()

    def format_breakpoint_dict(self, breakpoint):
        """
        Makes our protocol for breakpoints match the Bdb protocol.
        """
        if 'file' not in breakpoint and self.tracer.default_file:
            breakpoint['file'] = self.tracer.default_file
        if 'file' in breakpoint and 'line' in breakpoint:
            # Do some formatting here to make the params cleaner.
            breakpoint['filename'] = breakpoint.pop('file')
            breakpoint['lineno'] = breakpoint.pop('line')
            if 'temp' in breakpoint:
                breakpoint['temporary'] = breakpoint.pop('temp')
            if 'cond' in breakpoint:
                breakpoint['funcname'] = breakpoint.pop('func')

            return breakpoint

        raise QdbBreakpointReadError(breakpoint)

    def send(self, msg):
        """
        Sends a message to the server.
        """
        self.socket.sendall(pack('>i', len(msg)))
        self.socket.sendall(msg)

    def payload_check(self, payload, command):
        """
        Asserts that payload is not None, sending an error message if it is.
        returns False if payload is None, otherwise returns True.
        """
        if payload is None:
            self.send_error('payload', '%s: expected payload' % command)
            return False
        return True

    def _pause_handler(self, signum, stackframe):
        """
        Manager for the pause command.
        """
        if signum == self.tracer.pause_signal:
            self.tracer.set_step()

    def get_events(self):
        """
        Infinitly yield events from the Reader.
        """
        while self.reader.is_alive():
            try:
                event = self.pipe.get()
            except IOError as i:
                if i.errno == errno.EAGAIN:
                    continue
                raise
            yield event

    def get_commands(self):
        """
        Yields the commands out of the events.
        """
        for event in self.get_events():
            if event['e'] == 'error':
                self.handle_error(event.get('p'))
            else:
                command = getattr(self, 'command_' + event['e'], None)
                if not command:
                    self.send_error('event', 'Command %s does not exist'
                                    % event['e'])
                else:
                    yield lambda: command(event.get('p'))

    def handle_error(self, payload):
        if payload['type'] == 'auth':
            raise QdbAuthenticationError(payload['data'])
        else:
            raise QdbCommunicationError(payload)

    def user_next_command(self, msg=None):
        """
        Processes the next message from the reader.
        """
        try:
            return next(self.get_commands())()
        except StopIteration:
            raise QdbCommunicationError('No more commands from server')

    def command_step(self, payload):
        self.tracer.set_step()

    def command_return(self, payload):
        self.tracer.set_return(self.tracer.curframe)

    def command_next(self, payload):
        self.tracer.set_next(self.tracer.curframe)

    def command_until(self, payload):
        self.tracer.set_until(self.tracer.curframe)

    def command_continue(self, payload):
        self.tracer.set_continue()

    def command_eval(self, payload):
        """
        Evaluates and expression in self.tracer.curframe, reevaluates the
        watchlist, and defers to user control.
        """
        if not self.payload_check(payload, 'eval'):
            return self.next_command()
        with capture_output() as (out, err):
            try:
                self.tracer.eval_fn(
                    payload,
                    self.tracer.curframe,
                    'single',
                    exec_=True,
                )
            except Exception as e:
                self.send_print(
                    payload,
                    True,
                    self.tracer.exception_serializer(e)
                )
            else:
                out_msg = out.getvalue()[:-1] if out.getvalue() \
                    and out.getvalue()[-1] == '\n' else out.getvalue()
                self.send_print(payload, out_msg)

        self.tracer.update_watchlist()
        self.send_watchlist()
        self.next_command()

    def command_set_watch(self, payload):
        """
        Extends the watchlist and defers to user control.
        """
        if not self.payload_check(payload, 'set_watch'):
            return self.next_command()

        self.tracer.extend_watchlist(*payload)
        self.send_watchlist()
        self.next_command()

    def command_clear_watch(self, payload):
        """
        Clears expressions from the watchlist and defers to user control.
        """
        if not self.payload_check(payload, 'clear_watch'):
            return self.next_command()

        for w in payload:
            # Default to None so that clearing values that have not been set
            # acts as a nop instead of an error.
            self.tracer.watchlist.pop(w, None)

        self.send_watchlist()
        self.next_command()

    def command_set_break(self, payload):
        """
        Sets a breakpoint and defers to user control.
        """
        if not self.payload_check(payload, 'set_break'):
            return self.next_command()
        try:
            breakpoint = self.format_breakpoint_dict(payload)
        except QdbBreakpointReadError as b:
            err_msg = fmt_err_msg('set_break', str(b), serial=pickle.dumps)
            return self.next_command(err_msg)

        try:
            self.tracer.set_break(**breakpoint)
        except QdbUnreachableBreakpoint as u:
            err_msg = fmt_err_msg(
                'set_breakpoint',
                str(u),
                serial=pickle.dumps
            )
            return self.next_command(err_msg)

        self.next_command()

    def command_clear_break(self, payload):
        """
        Clears a breakpoint and defers to user control.
        """
        if not self.payload_check(payload, 'clear_break'):
            return self.next_command()
        try:
            breakpoint = self.format_breakpoint_dict(payload)
        except QdbBreakpointReadError as b:
            err_msg = fmt_err_msg('clear_break', str(b), serial=pickle.dumps)
            return self.next_command(err_msg)

        self.tracer.clear_break(**breakpoint)
        self.next_command()

    def command_list(self, payload):
        """
        List the contents of a file and defer to user control.
        """
        if not self.payload_check(payload, 'list'):
            return self.next_command()

        filename = payload.get('file') or self.tracer.default_file
        try:
            if self.tracer.skip_fn(filename):
                raise KeyError  # Handled the same, avoids duplication.
            if not (payload.get('start') or payload.get('end')):
                msg = fmt_msg(
                    'list',
                    self.tracer.get_file(payload['file']),
                    serial=pickle.dumps
                )
            else:
                # Send back the slice of the file that they requested.
                msg = fmt_msg(
                    'list',
                    '\n'.join(
                        self.tracer._file_cache[filename][
                            int(payload.get('start')):int(payload.get('end'))
                        ]
                    ),
                    serial=pickle.dumps
                )
        except KeyError:  # The file failed to be cached.
            msg = fmt_err_msg(
                'list',
                'File %s does not exist' % payload['file'],
                serial=pickle.dumps
            )
        except TypeError:
            # This occurs when we fail to convert the 'start' or 'stop' fields
            # to integers.
            msg = fmt_err_msg(
                'list',
                'List slice arguments convertable to type int',
                serial=pickle.dumps
            )

        self.next_command(msg)

    def _stack_shift(self, direction):
        """
        Shifts the stack up or down depending on dirction.
        If direction is positive, travel up, if direction is negative, travel
        down. If direction is 0, do nothing.
        Does not check if the frame you are shifting to exists.
        """
        if direction == 0:
            return
        offset = -1 if abs(direction) == direction else 1
        self.tracer.curindex += offset
        self.tracer.curframe = self.tracer.stack[self.tracer.curindex][0]
        self.tracer.curframe_locals = self.tracer.curframe.f_locals
        self.tracer.update_watchlist()
        self.send_watchlist()
        self.send_stack()
        self.lineno = None

    def command_up(self, payload):
        """
        Step up the stack and defer to user control.
        """
        if self.tracer.curindex == 0:
            # If this is the case, we cannot move up.
            self.send_error('up', 'Oldest frame')
        else:
            self._stack_shift(+1)
        self.next_command()

    def command_down(self, payload):
        """
        Step down the stack and defer to user control
        """
        if self.tracer.curindex == len(self.tracer.stack) - 1:
            # If this is the case, we cannot move down.
            self.send_error('down', 'Newest frame')
        else:
            self._stack_shift(-1)
        self.next_command()

    def command_locals(self, payload):
        """
        Sends back the current frame locals and defer to user control.
        """
        self.send_event('locals', self.tracer.curframe_locals)
        self.next_command()

    def command_start(self, payload):
        """
        Sends back initial information and defers to user control.
        """
        self.send_breakpoints()
        self.send_stdout()
        self.send_watchlist()
        self.send_stack()
        self.next_command()

    def command_disable(self, payload):
        """
        Disables the tracer.
        """
        if not self.payload_check(payload, 'disable'):
            return self.next_command()
        if payload not in ['soft', 'hard']:
            err_msg = fmt_err_msg(
                'disable',
                "payload must be either 'soft' or 'hard'",
                serial=pickle.dumps
            )
            return self.next_command(err_msg)
        self.tracer.disable(payload)


def get_events_from_socket(sck):
    """
    Yields valid events from the server socket.
    """
    while True:
        try:
            rlen = sck.recv(4)
            if len(rlen) != 4:
                return
            rlen = unpack('>i', rlen)[0]
            bytes_received = 0
            resp = ''
            with Timeout(1, False):
                while bytes_received < rlen:
                    resp += sck.recv(rlen - bytes_received)
                    bytes_received = len(resp)

            if bytes_received != rlen:
                return  # We are not getting bytes anymore.

            cmd = pickle.loads(resp)
            cmd['e']
        except (socket.error, pickle.UnpicklingError) as e:
            # We can no longer talk the the server.
            log.warn('Exception raised reading from socket')
            yield fmt_err_msg('socket', str(e))
            return
        except KeyError:
            log.warn('Client sent invalid cmd.')
            yield fmt_err_msg('event', "No 'e' field sent")
            return
        else:
            # Yields only valid commands.
            yield cmd


class ServerReader(object):
    """
    Object that reads from the server asyncronously from the process
    being debugged.
    """
    def __init__(self, debugger_pipe, session_pid, server_comm_fd,
                 pause_signal):
        self.pause_signal = pause_signal or signal.SIGUSR2
        self.debugger_pipe = debugger_pipe
        self.server_comm = socket.fromfd(server_comm_fd, 0, 0)
        self.session_pid = session_pid
        self.socket_error = None
        self.process_messages()

    def command_pause(self):
        """
        Manages the pause command by raising a user defined signal in the
        session process which will be caught by the command manager.
        """
        os.kill(self.session_pid, self.pause_signal)

    def process_messages(self):
        """
        Infinitly reads events off the server, if it is a pause, then it pauses
        the process, otherwise, it passes the message along.
        """
        self.debugger_pipe.put(fmt_msg('reader_started'))
        try:
            for event in get_events_from_socket(self.server_comm):
                if event['e'] == 'pause':
                    self.command_pause()
                else:
                    self.debugger_pipe.put(event)

                    # If we get here, we had a socket error that dropped us
                    # out of get_events(), signal this to the process.
            self.debugger_pipe.put(fmt_msg('disable', 'soft'))
        finally:
            log.info('ServerReader terminating')


class ServerLocalCommandManager(RemoteCommandManager):
    """
    Use this command manager if you know for certain that the tracer will be
    running on the same machine as the server. This circumvents the need for
    spinning up the Reader process and lets the server take over some of that
    responsibility. While using a normal RemoteCommandManager will work, this
    incurs less overhead.
    """
    def start(self, auth_msg=''):
        """
        Begins processing commands from the server.
        """
        self._socket_connect()
        self.send(
            fmt_msg(
                'start', {
                    'uuid': self.tracer.uuid,
                    'auth': auth_msg,
                    'local': (os.getpid(), self.tracer.pause_signal),
                },
                serial=pickle.dumps,
            )
        )

    def stop(self):
        self.socket.close()

    def get_events(self):
        return get_events_from_socket(self.socket)
