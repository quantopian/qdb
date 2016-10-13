#
# Copyright 2015 Quantopian, Inc.
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
from __future__ import print_function

from abc import ABCMeta, abstractmethod
import atexit
from bdb import Breakpoint
import errno
from functools import partial
import json
import os
from pprint import pprint
import signal
import socket
from struct import pack, unpack
from textwrap import dedent

from logbook import Logger

from qdb.compat import (
    Connection,
    PY3,
    gevent,
    input,
    items,
    print_,
    range,
    with_metaclass,
)
from qdb.errors import (
    QdbAuthenticationError,
    QdbBreakpointReadError,
    QdbCommunicationError,
    QdbFailedToConnect,
    QdbReceivedInvalidData,
    QdbUnreachableBreakpoint,
)
from qdb.utils import Timeout, tco

log = Logger('Qdb')


def fmt_msg(event, payload=None, serial=None):
    """
    Packs a message to be sent to the server.
    Serial is a function to call on the frame to serialize it, e.g:
    json.dumps.
    """
    #if event=="locals":
    #   payload = parse_variables(payload)

    frame = {
        'e': event,
        'p': payload,
    }
    if serial:
        js = serial(frame)
        return js
    else:
        return frame

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

def parse_variables(paydict):
    if isinstance(paydict,dict) and paydict:
        strdict={}
        print("parsing")
        for (k,v) in paydict.items():
            strdict[str(k)]=str(v)
        return strdict
    else:
        return paydict

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


class CommandManager(with_metaclass(ABCMeta, object)):
    """
    An abstract base class for the command managers that control the tracer.
    """

    def _fmt_stackframe(self, tracer, stackframe, line):
        """
        Formats stackframe payload data.
        """
        filename = stackframe.f_code.co_filename
        func = stackframe.f_code.co_name
        code = tracer.get_line(filename, line)
        return {
            'file': tracer.canonic(filename),
            'line': line,
            'func': func,
            'code': code,
        }

    def send_disabled(self):
        """
        Sends a message to the server to say that the tracer is done.
        """
        try:
            self.send_event('disabled')
        except socket.error:
            # We may safely ignore errors that occur here because we are
            # already disabled.
            pass

    def send_breakpoints(self):
        """
        Sends the breakpoint list event.
        """
        self.send_event(
            'breakpoints',
            [fmt_breakpoint(breakpoint) for breakpoint in Breakpoint.bpbynumber
             if breakpoint]
        )

    def send_watchlist(self, tracer):
        """
        Sends the watchlist event.
        """
        self.send_event(
            'watchlist',
            [{'expr': k, 'exc': exc, 'value': val}
             for k, (exc, val) in items(tracer.watchlist)],
        )

    def send_print(self, input_, exc, output):
        """
        Sends the print event with the given input and output.
        """
        self.send(fmt_msg(
            'print', {
                'input': input_,
                'exc': exc,
                'output': output
            },
            serial=json.dumps)
        )

    def send_stack(self, tracer):
        """
        Sends the stack event.
        This filters out frames based on the rules defined in the tracer's
        skip_fn. The index reported will account for any skipped frames, such
        that querying the stack at the index provided will return the current
        frame.
        """
        stack = []
        index = tracer.curindex
        skip_fn = tracer.skip_fn
        for n, (frame, line) in enumerate(tracer.stack):
            if skip_fn(frame.f_code.co_filename):
                if n < tracer.curindex:
                    index -= 1  # Drop the index to account for a skip
                continue  # Don't add frames we need to skip.

            stack.append(self._fmt_stackframe(tracer, frame, line))

        self.send_event(
            'stack', {
                'index': index,
                'stack': stack,
            }
        )

    def send_error(self, error_type, error_data):
        """
        Sends a formatted error message.
        """
        self.send(fmt_err_msg(error_type, error_data, serial=json.dumps))

    def send_event(self, event, payload=None):
        """
        Sends a formatted event.
        """
        self.send(fmt_msg(event, payload, serial=json.dumps))

    @tco
    def next_command(self, tracer, msg=None):
        """
        Processes the next command from the user.
        If msg is given, it is sent with self.send(msg) before processing the
        next command.
        """
        if msg:
            self.send(msg)
        return self.user_next_command(tracer)

    @abstractmethod
    def send(self, msg):
        """
        Sends a raw (already jsond) message.
        """
        raise NotImplementedError

    @abstractmethod
    def user_next_command(self, tracer):
        """
        Processes the next command.
        This method must be overridden to dictate how the commands are
        processed.
        """
        raise NotImplementedError

    @abstractmethod
    def start(self, tracer, auth_msg=''):
        """
        Start acquiring new commands.
        """
        raise NotImplementedError

    def stop(self):
        """
        Stop acquiring new commands.
        """
        self.send_disabled()
        self.user_stop()

    @abstractmethod
    def user_stop(self):
        """
        Use this to release and resources needed to generate the commands.
        """
        raise NotImplementedError


class NopCommandManager(CommandManager):
    """
    Nop command manager that never alters the state of the debugger.
    This is useful if you want to manage the debugger in an alternate way.
    """
    def user_next_command(self, tracer):
        pass

    def send(self, msg):
        pass

    def start(self, tracer, msg):
        pass

    def user_stop(self):
        pass


class RemoteCommandManager(CommandManager):
    """
    Manager that processes commands from the server.
    This is the default Qdb command manager.
    """
    def __init__(self):
        super(RemoteCommandManager, self).__init__()

        if gevent is not None:
            import gipc  # Only use gipc if we are running in gevent.
            self._pipe = gipc.pipe
            self._start_process = gipc.start_process
        else:
            import multiprocessing

            def _pipe(*args, **kwargs):
                a, b = multiprocessing.Pipe(*args, **kwargs)
                return Connection(a), Connection(b)

            self._pipe = _pipe

            def _start_process(*args, **kwargs):
                proc = multiprocessing.Process(*args, **kwargs)
                proc.start()
                return proc

            self._start_process = _start_process
        self.pipe = None
        self.socket = None
        self.reader = None

    def _socket_connect(self, tracer):
        """
        Connects to the socket or raise a QdbFailedToConnect error.
        """
        log.info('Connecting to (%s, %d)' % tracer.address)

        for n in range(tracer.retry_attepts):
            # Try to connect to the server.
            try:
                self.socket = socket.create_connection(tracer.address)
                # If we made it here, we connected and no longer need to retry.
                break
            except socket.error:
                log.warn(
                    'Client %s failed to connect to (%s, %d) on attempt %d...'
                    % (tracer.uuid, tracer.address[0],
                       tracer.address[1], n + 1)
                )
        if self.socket is None:
            log.warn(
                'Failed to connect to (%s, %d), no longer retying.'
                % tracer.address
            )
            raise QdbFailedToConnect(
                tracer.address,
                tracer.retry_attepts
            )
        log.info('Client %s connected to (%s, %d)'
                 % (tracer.uuid, tracer.address[0],
                    tracer.address[1]))

    def start(self, tracer, auth_msg=''):
        """
        Begins processing commands from the server.
        """
        self.pipe, child_end = self._pipe()
        self._socket_connect(tracer)
        self.reader = self._start_process(
            target=ServerReader,
            args=(child_end, os.getpid(),
                  self.socket.fileno(),
                  tracer.pause_signal),
        )
        with Timeout(5, QdbFailedToConnect(tracer.address,
                                           tracer.retry_attepts)):
            # Receive a message to know that the reader is ready to begin.
            while True:
                try:
                    self.pipe.get()
                    break
                except IOError as e:
                    # EAGAIN says to try the syscall again.
                    if e.errno != errno.EAGAIN:
                        raise

        self.send(
            fmt_msg(
                'start', {
                    'uuid': tracer.uuid,
                    'auth': auth_msg,
                    'local': (0, 0),
                },
                serial=json.dumps,
            )
        )
        signal.signal(
            tracer.pause_signal, partial(self._pause_handler, tracer)
        )
        atexit.register(self.stop)

    def user_stop(self):
        """
        Stops the command manager, freeing its resources.
        """
        if self.reader and self.reader.is_alive():
            self.reader.terminate()
        self.socket.close()

    def fmt_breakpoint_dict(self, tracer, breakpoint):
        """
        Makes our protocol for breakpoints match the Bdb protocol.
        """
        if 'file' not in breakpoint and tracer.default_file:
            breakpoint['file'] = tracer.default_file
        if 'file' in breakpoint and 'line' in breakpoint:
            # Do some formatting here to make the params cleaner.
            breakpoint['filename'] = breakpoint.pop('file')
            breakpoint['lineno'] = breakpoint.pop('line')

            breakpoint['temporary'] = breakpoint.pop('temp', None)
            breakpoint['funcname'] = breakpoint.pop('func', None)

            breakpoint.setdefault('cond', None)

            return breakpoint

        raise QdbBreakpointReadError(breakpoint)

    def send(self, msg):
        """
        Sends a message to the server.
        """
        self.socket.sendall(pack('>i', len(msg)))
        self.socket.sendall(msg.encode('utf-8'))

    def payload_check(self, payload, command):
        """
        Asserts that payload is not None, sending an error message if it is.
        returns False if payload is None, otherwise returns True.
        """
        if payload is None:
            self.send_error('payload', '%s: expected payload' % command)
            return False
        return True

    def _pause_handler(self, tracer, signum, stackframe):
        """
        Manager for the pause command.
        """
        if signum == tracer.pause_signal:
            tracer.set_step()

    def get_events(self):
        """
        Infinitely yield events from the Reader.
        """
        while self.reader.is_alive():
            try:
                event = self.pipe.get()
            except IOError as i:
                if i.errno == errno.EAGAIN:
                    continue
                raise
            yield event

    def get_commands(self, tracer):
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
                    yield lambda: command(tracer, event.get('p'))

    def handle_error(self, payload):
        if payload['type'] == 'auth':
            raise QdbAuthenticationError(payload['data'])
        else:
            raise QdbCommunicationError(payload)

    def user_next_command(self, tracer, msg=None):
        """
        Processes the next message from the reader.
        """
        try:
            return next(self.get_commands(tracer))()
        except StopIteration:
            raise QdbCommunicationError('No more commands from server')

    def command_step(self, tracer, payload):
        tracer.set_step()

    def command_return(self, tracer, payload):
        tracer.set_return(tracer.curframe)

    def command_next(self, tracer, payload):
        tracer.set_next(tracer.curframe)

    def command_until(self, tracer, payload):
        tracer.set_until(tracer.curframe)

    def command_continue(self, tracer, payload):
        tracer.set_continue()

    def command_pprint(self, tracer, payload):
        """
        Evaluates the expression with the pretty printer.
        """
        return self.command_eval(tracer, payload, pprint=True)

    def command_eval(self, tracer, payload, pprint=False):
        """
        Evaluates and expression in tracer.curframe, reevaluates the
        watchlist, and defers to user control.
        """
        if not self.payload_check(payload, 'eval'):
            return self.next_command.tailcall(tracer)

        tracer.eval_(payload, pprint)
        self.send_watchlist(tracer)
        return self.next_command.tailcall(tracer)

    def command_set_watch(self, tracer, payload):
        """
        Extends the watchlist and defers to user control.
        """
        if not self.payload_check(payload, 'set_watch'):
            return self.next_command.tailcall(tracer)

        tracer.extend_watchlist(*payload)
        self.send_watchlist(tracer)
        return self.next_command.tailcall(tracer)

    def command_clear_watch(self, tracer, payload):
        """
        Clears expressions from the watchlist and defers to user control.
        """
        if not self.payload_check(payload, 'clear_watch'):
            return self.next_command.tailcall(tracer)

        for w in payload:
            # Default to None so that clearing values that have not been set
            # acts as a nop instead of an error.
            tracer.watchlist.pop(w, None)

        self.send_watchlist(tracer)
        return self.next_command.tailcall(tracer)

    def command_set_break(self, tracer, payload):
        """
        Sets a breakpoint and defers to user control.
        """
        if not self.payload_check(payload, 'set_break'):
            return self.next_command.tailcall(tracer)
        try:
            breakpoint = self.fmt_breakpoint_dict(tracer, payload)
        except QdbBreakpointReadError as b:
            err_msg = fmt_err_msg('set_break', str(b), serial=json.dumps)
            return self.next_command.tailcall(tracer, err_msg)

        err_msg = None
        try:
            tracer.set_break(**breakpoint)
        except QdbUnreachableBreakpoint as u:
            err_msg = fmt_err_msg(
                'set_breakpoint',
                str(u),
                serial=json.dumps
            )

        return self.next_command.tailcall(tracer, err_msg)

    def command_clear_break(self, tracer, payload):
        """
        Clears a breakpoint and defers to user control.
        """
        if not self.payload_check(payload, 'clear_break'):
            return self.next_command.tailcall(tracer)
        try:
            breakpoint = self.fmt_breakpoint_dict(tracer, payload)
        except QdbBreakpointReadError as b:
            err_msg = fmt_err_msg('clear_break', str(b), serial=json.dumps)
            return self.next_command.tailcall(tracer, err_msg)

        tracer.clear_break(**breakpoint)
        return self.next_command.tailcall(tracer)

    def command_list(self, tracer, payload):
        """
        List the contents of a file and defer to user control.
        """
        if not self.payload_check(payload, 'list'):
            return self.next_command.tailcall(tracer)

        filename = payload.get('file') or tracer.default_file
        try:
            if tracer.skip_fn(filename):
                raise KeyError  # Handled the same, avoids duplication.
            if not (payload.get('start') or payload.get('end')):
                msg = fmt_msg(
                    'list',
                    tracer.get_file(payload['file']),
                    serial=json.dumps
                )
            else:
                # Send back the slice of the file that they requested.
                msg = fmt_msg(
                    'list',
                    '\n'.join(
                        tracer.get_file_lines(tracer.canonic(filename))[
                            int(payload.get('start')):int(payload.get('end'))
                        ]
                    ),
                    serial=json.dumps
                )
        except KeyError:  # The file failed to be cached.
            msg = fmt_err_msg(
                'list',
                'File %s does not exist' % payload['file'],
                serial=json.dumps
            )
        except TypeError:
            # This occurs when we fail to convert the 'start' or 'stop' fields
            # to integers.
            msg = fmt_err_msg(
                'list',
                'List slice arguments must be convertable to type int',
                serial=json.dumps
            )

        return self.next_command.tailcall(msg)

    def command_up(self, tracer, payload):
        """
        Step up the stack and defer to user control.
        This will 'ignore' frames that we should skip, potentially going up
        more than one stackframe.
        """
        try:
            tracer.stack_shift_direction(+1)
        except IndexError:
            self.send_error('up', 'Oldest frame')

        self.send_watchlist(tracer)
        self.send_stack(tracer)
        return self.next_command.tailcall(tracer)

    def command_down(self, tracer, payload):
        """
        Step down the stack and defer to user control
        This will 'ignore' frames that we should skip, potentially going down
        more than one stackframe.
        """
        try:
            tracer.stack_shift_direction(-1)
        except IndexError:
            self.send_error('down', 'Newest frame')

        self.send_watchlist(tracer)
        self.send_stack(tracer)
        return self.next_command.tailcall(tracer)

    def command_locals(self, tracer, payload):
        """
        Sends back the current frame locals and defer to user control.
        """
        self.send_event('locals', tracer.curframe_locals)
        return self.next_command.tailcall(tracer)

    def command_start(self, tracer, payload):
        """
        Sends back initial information and defers to user control.
        """
        self.send_breakpoints()
        self.send_watchlist(tracer)
        self.send_stack(tracer)
        return self.next_command.tailcall(tracer)

    def command_disable(self, tracer, payload):
        """
        Disables the tracer.
        """
        if not self.payload_check(payload, 'disable'):
            return self.next_command.tailcall(tracer)
        if payload not in ['soft', 'hard']:
            err_msg = fmt_err_msg(
                'disable',
                "payload must be either 'soft' or 'hard'",
                serial=json.dumps
            )
            return self.next_command.tailcall(err_msg)
        tracer.disable(payload)


def get_events_from_socket(sck):
    """
    Yields valid events from the server socket.
    """
    while True:
        try:
            sck.setblocking(True)
            resp = bytearray(4)
            if sck.recv_into(resp, 4) != 4:
                raise QdbReceivedInvalidData(resp)

            rlen = unpack('>i', resp)[0]
            resp = bytearray(rlen)
            sck.settimeout(1)
            if sck.recv_into(resp, rlen) != rlen:
                raise QdbReceivedInvalidData(resp)

            if PY3:
                resp = resp.decode('utf-8')
            else:
                resp = bytes(resp)

            cmd = json.loads(resp)
            if cmd['e'] == 'disabled':
                # We are done tracing.
                return
        except KeyError:
            log.warn('Client sent invalid cmd.')
            yield fmt_err_msg('event', "No 'e' field sent")
            return
        except Exception as e:
            # We can no longer talk to the server.
            log.warn('Exception raised reading from socket')
            yield fmt_err_msg('socket', str(e))
            return
        else:
            # Yields only valid commands.
            yield cmd


class ServerReader(object):
    """
    Object that reads from the server asynchronously from the process
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
        Infinitely reads events off the server. If it is a pause, then it
        pauses the process; otherwise, it passes the message along.
        """
        # Send a message to alert the tracer that we are ready to begin reading
        # messages.
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
    def start(self, tracer, auth_msg=''):
        """
        Begins processing commands from the server.
        """
        self._socket_connect(tracer)
        self.send(
            fmt_msg(
                'start', {
                    'uuid': tracer.uuid,
                    'auth': auth_msg,
                    'local': (os.getpid(), tracer.pause_signal),
                },
                serial=json.dumps,
            )
        )

    def user_stop(self):
        self.socket.close()

    def get_events(self):
        return get_events_from_socket(self.socket)


class TerminalCommandManager(CommandManager):
    def __init__(self):
        super(TerminalCommandManager, self).__init__()
        self._sticky = True
        self._redraw = True

        # Side effectful imports ;_;
        import rlcompleter  # NOQA
        import readline
        self.readline = readline
        readline.parse_and_bind("tab: complete")

    def pprint(self, msg):
        pprint(msg)

    def send(self, event):
        event = json.loads(event)
        evfn = getattr(self, 'event_' + event['e'], None)
        if not evfn:
            self.unknown_event(event['e'])
        else:
            evfn(event.get('p'))

    def writeln(self, msg=''):
        print_(msg)

    def writeerr(self, msg=''):
        self.writeln('*** error: ' + msg)

    def missing_argument(self, cmd):
        self.writeerr('{cmd}: missing argument(s)'.format(cmd=cmd))

    def unknown_event(self, e):
        self.writeerr('{0}: unknown event type'.format(e))

    def event_print(self, payload):
        out = payload['output']
        if out:
            self.writeln(
                '%s%s' % ('*** error: ' if payload['exc'] else '', out),
            )

    def event_stack(self, payload):
        frame = payload['stack'][payload['index']]  # Current frame
        self.writeln('> {file}:{line}'.format(**frame))
        if not self._sticky:
            self.writeln('--> ' + frame['code'])

    def event_watchlist(self, payload):
        self.writeln('watchlist: [')
        for watched in payload:
            self.writeln(
                '  > %s%s: %s'
                % ('*** error: ' if watched['exc'] else '',
                   watched['expr'], watched['value'])
            )
        self.writeln(']')

    def event_exception(self, payload):
        self.writeln('--* %s:%s' % (payload['type'], payload['value']))

    def event_breakpoints(self, payload):
        self.writeln('breakpoints: [')
        for breakpoint in payload:
            self.writeln(
                '  > {file} {line} {temp} {cond} {func}'.format(**breakpoint),
            )
        self.writeln(']')

    def event_error(self, payload):
        self.writeerr('{0}: {1}'.format(payload['type'], payload['data']))

    def event_return(self, payload):
        self.writeln('---> returning with %s' % payload)

    def event_disabled(self, payload):
        self.writeln()

    def start(self, tracer, auth_msg=''):
        pass

    def user_stop(self):
        pass

    def prompt_user(self):
        inp = input('(qdb) ').split(None, 1)
        if not inp:
            rl = self.readline
            inp = rl.get_history_item(rl.get_current_history_length())
        return inp

    def user_next_command(self, tracer):
        if self._sticky and self._redraw:
            self.do_list(None, tracer, recurse=False)
        self._redraw = False

        try:
            while True:
                try:
                    inp = self.prompt_user()
                    while not inp:
                        inp = self.prompt_user()
                    break
                except KeyboardInterrupt:
                    self.writeln()
        except EOFError:
            inp = ('quit',)

        cmd = inp[0]
        if cmd.endswith('?') and hasattr(self, 'do_' + cmd[:-1]):
            self.writeln(dedent(getattr(self, 'do_' + cmd[:-1]).__doc__))
            return self.user_next_command(tracer)

        command = getattr(self, 'do_' + cmd, None)
        if command is None:
            return self.do_print(' '.join(inp), tracer)
        else:
            try:
                arg = inp[1]
            except IndexError:
                arg = None

            return command(arg, tracer)

    def do_print(self, arg, tracer):
        """
        p(rint)
        Print the following expression
        """
        tracer.eval_(arg)
        return self.next_command.tailcall(tracer)
    do_p = do_print

    def do_step(self, arg, tracer):
        """
        s(tep)
        Execute the next line, function call, or return.
        """
        self._redraw = True
        tracer.set_step()
    do_s = do_step

    def do_return(self, arg, tracer):
        """
        r(eturn)
        Execute until the return event for the current stackframe.
        """
        self._redraw = True
        tracer.set_return(tracer.curframe)
    do_r = do_return

    def do_next(self, arg, tracer):
        """
        n(ext)
        Execute up to the next line in the current frame.
        """
        self._redraw = True
        tracer.set_next(tracer.curframe)
    do_n = do_next

    def do_until(self, arg, tracer):
        """
        unt(il)
        Execute until the line greater than the current is hit or until
        you return from the current frame.
        """
        self._redraw = True
        tracer.set_until(tracer.curframe)
    do_unt = do_until

    def do_continue(self, arg, tracer):
        """
        c(ontinue)
        Continue execution until the next breakpoint is hit. If there are
        no more breakpoints, stop tracing.
        """
        self._redraw = True
        tracer.set_continue()
    do_c = do_continue

    def do_watch(self, arg, tracer):
        """
        w(atch) EXPR
        Adds an expression to the watchlist.
        """
        if not arg:
            return self.missing_argument('w(atch)')
        tracer.extend_watchlist((arg,))
        return self.next_command.tailcall(tracer)
    do_w = do_watch

    def do_unwatch(self, arg, tracer):
        """
        unw(atch) EXPR
        Removes an expression from the watchlist if it is already being
        watched, otherwise does nothing.
        """
        if not arg:
            return self.missing_argument('unw(atch)')
        tracer.watchlist.pop(arg, None)
        return self.next_command.tailcall(tracer)
    do_unw = do_unwatch

    def do_break(self, arg, tracer, temp=False):
        """
        b(reak) BREAK-DICT
        Adds a breakpoint with the form:
        {'file': str, 'line': int, 'temp': bool, 'cond': str, 'func': str}
        """
        if not arg:
            self.missing_argument('b(reak)')
            return
        break_arg = self.parse_break_arg(arg, temp)
        if break_arg:
            tracer.set_break(**break_arg)
        return self.next_command.tailcall(tracer)
    do_b = do_break

    def do_clear(self, arg, tracer):
        """
        cl(ear) BREAK-DICT
        Clears a breakpoint with the form:
        {'file': str, 'line': int, 'temp': bool, 'cond': str, 'func': str}
        Only 'file' and 'line' are needed.
        """
        if not arg:
            self.missing_argument('cl(ear)')
            return
        break_arg = self.parse_break_arg(arg)
        if break_arg:
            tracer.clear_break(**break_arg)
        return self.next_command.tailcall(tracer)
    do_cl = do_clear

    def do_tbreak(self, arg, tracer):
        """
        tbreak BREAK-DICT
        Same as break, but with 'temp' defaulted to True.
        """
        return self.do_break(arg, tracer, temp=True)

    def do_list(self, arg, tracer, recurse=True):
        """
        l(ist) FILE [START, [END]]
        Shows the content of a file where START is the first line to show
        and END is the last. This acts like a Python slice.
        """
        start = end = None
        try:
            start, end = map(int, arg.split() if arg else ())
        except (TypeError, ValueError):
            pass

        curline = tracer.curframe.f_lineno
        if start is None and end is None and arg != ':':
            start = curline - 5
            if start < 0:
                start = 0
            end = curline + 5

        def prepend(ix_l):
            return (
                '%s ' % ('-->' if ix_l[0] == curline else '   ')
            ) + ix_l[1]

        self.writeln(
            '\n'.join(
                map(
                    prepend,
                    enumerate(
                        tracer.get_file_lines(
                            tracer.curframe.f_code.co_filename,
                        )[start:end],
                        1 if start is None else start + 1,
                    )
                )
            ),
        )
        if recurse:
            return self.next_command.tailcall(tracer)
    do_l = do_list

    def do_up(self, arg, tracer):
        """
        u(p)
        Steps up a stackframe if possible.
        """
        try:
            tracer.stack_shift_direction(+1)
        except IndexError:
            self.writeerr('up: top of stack')
        else:
            self.do_list(None, tracer, recurse=False)

        return self.next_command.tailcall(tracer)
    do_u = do_up

    def do_down(self, arg, tracer):
        """
        d(own)
        Steps down a stackframe if possible.
        """
        try:
            tracer.stack_shift_direction(-1)
        except IndexError:
            self.writeerr('down: bottom of stack')
        else:
            self.do_list(None, tracer, recurse=False)

        return self.next_command.tailcall(tracer)
    do_d = do_down

    def do_locals(self, arg, tracer):
        """
        locals
        Report back the current stackframe's locals.
        """
        self.writeln('locals: [')
        for p in items(tracer.curframe_locals):
            self.writeln('  %s=%s' % p)
        self.writeln(']')

        return self.next_command.tailcall(tracer)

    def do_quit(self, arg, tracer):
        """
        q(uit) [MODE]
        Stops the debugging session with the given mode, defaulting to
        'soft'.
        """
        if not arg or arg in ('soft', 'hard'):
            tracer.disable(arg or 'hard')
        else:
            self.writeerr("disable: argument must be 'soft' or 'hard'")

    def do_sticky(self, arg, tracer):
        """
        sticky
        Toggle sticky mode; printing the current context after every step.
        """
        self._sticky = not self._sticky
        if self._sticky:
            return self.do_list(None, tracer)
        return self.next_command.tailcall(tracer)
