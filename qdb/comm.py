from bdb import Breakpoint
from contextlib import contextmanager

try:
    import cPickle as pickle
except ImportError:
    import pickle

from multiprocessing import Process, Pipe
import os
import signal
import socket
from StringIO import StringIO
from struct import pack, unpack
import sys

from logbook import Logger

from qdb.errors import (
    QdbFailedToConnect,
    QdbBreakpointReadError,
    QdbCommunicationError,
    QdbUnreachableBreakpoint,
)

log = Logger('Qdb')


@contextmanager
def capture_output():
    """
    Captures stdout for the duration of the body.
    """
    sys.stdout = StringIO()
    try:
        yield sys.stdout
    finally:
        sys.stdout.close()
        sys.stdout = sys.__stdout__


def fmt_msg(event, payload=None):
    """
    Packs a message to be sent to the server.
    """
    if payload is None:
        return pickle.dumps({
            'e': event,
        })
    return pickle.dumps({
        'e': event,
        'p': payload
    })


def fmt_err_msg(error_type, data):
    """
    Constructs an error message.
    """
    return fmt_msg('error', {
        'type': error_type,
        'data': data,
    })


def fmt_breakpoint(breakpoint):
    """
    formats breakpoint payload.
    """
    return {
        'file': breakpoint.file,
        'line': breakpoint.line,
        'temp': breakpoint.temp,
        'cond': breakpoint.cond,
    }


# A message that denotes everything worked fine.
ACKMSG = fmt_msg('ack')


class CommandManager(object):
    """
    Manager that processes commands.
    """
    def __init__(self, debugger):
        self.debugger = debugger

        # Construct a pipe to talk to the reader.
        self.pipe, child_end = Pipe()

        # Attach the signal handler to manage the pause command.
        signal.signal(debugger.pause_signal, self._pause_handler)

        log.info('Connecting to (%s, %d)' % debugger.address)
        self.socket = None
        for n in xrange(self.debugger.retry_attepts):
            try:
                self.socket = socket.create_connection(debugger.address)
                break
            except socket.error:
                log.warn(
                    'Client %s failed to connect to (%s, %d) on attempt %d...'
                    % (self.debugger.uuid, debugger.address[0],
                       debugger.address[1], n + 1)
                )
        if self.socket is None:
            log.warn(
                'Failed to connect to (%s, %d), no longer retying.'
                % debugger.address
            )
            raise QdbFailedToConnect(debugger.address, debugger.retry_attepts)
        log.info('Client %s connected to (%s, %d)'
                 % (self.debugger.uuid, self.debugger.address[0],
                    self.debugger.address[1]))

        # Create the comminicator assuming we did not raise any exceptions.
        self.reader = Process(
            target=ServerReader,
            args=(child_end, os.getpid(), self.socket),
        )
        self._start()

    def _start(self):
        """
        Begins processing commands from the server.
        """
        self.send(
            fmt_msg('new_tracer', self.debugger.uuid)
        )
        self.reader.start()
        self._command_generator = self._get_commands()

    def unserialize_breakpoint(self, breakpoint_serial):
        """
        Parses a Breakpoint out of the serial data.
        This returns a dictionary with the parameters to pass to
        set_breakpoint.
        If no breakpoint can be parsed out of breakpoint_serial, a
        QdbBreakpointReadError is thrown with the serial data.
        """
        try:
            bp = pickle.loads(breakpoint_serial)
        except pickle.UnpicklingError:
            raise QdbBreakpointReadError(breakpoint_serial)

        if 'file' in bp and 'line' in bp:
            # Do some formatting here to make the params cleaner.
            if 'temp' in bp:
                bp['temporary'] = bp['temp']
                bp.pop('temp')
            if 'cond' in bp:
                bp['funcname'] = bp['func']
                bp.pop('func')

            return bp

        raise QdbBreakpointReadError(Breakpoint(**bp))

    def send_breakpoints(self):
        """
        Sends the serialized list of breakpoints to the server.
        """
        self.send_event(
            'breakpoints',
            map(fmt_breakpoint, self.debugger.get_all_breaks()),
        )

    def send_watchlist(self):
        """
        Sends the watchlist to the server.
        """
        self.send_event(
            'watchlist',
            map(lambda t: {'name': t[0], 'value': t[1]},
                self.debugger.watchlist.iteritems()),
        )

    def send_print(self, input_, output):
        """
        Sends the print command results.
        """
        msg = fmt_msg('print', {
            'input': input_,
            'output': output
        })
        self.send(msg)

    def fmt_stackframe(self, stackframe_line):
        """
        Formats stackframe payload data.
        """
        stackframe, line = stackframe_line
        filename = stackframe.f_code.co_filename
        func = stackframe.f_code.co_name
        code = self.debugger.get_line(filename, line)
        return {
            'file': self.debugger.canonic(filename),
            'line': line,
            'func': func,
            'code': code,
        }

    def send_stack(self):
        """
        Sends back the formated stack to the server.
        """
        # Starting at the frame we are in, we need to filter based on the
        # debugger's skip_fn rules. `s[0]` is the filename.
        stack = filter(
            lambda s: not self.debugger.skip_fn(s[0].f_code.co_filename),
            self.debugger.stack
        )
        self.send_event(
            'stack',
            map(self.fmt_stackframe, stack),
        )

    def send_stdout(self):
        """
        Sends a print that denotes that this is coming from the process.
        """
        self.debugger.stdout.seek(self.debugger.stdout_ptr)
        out = self.debugger.stdout.read()
        self.debugger.stdout_ptr = self.debugger.stdout.tell()
        self.send_print('<stdout>', out)

    def send_error(self, error_type, error_data):
        """
        Sends a formatted error message back to the server.
        """
        self.send(fmt_err_msg(error_type, error_data))

    def send_event(self, event, payload=None):
        """
        Sends a formatted event to the server.
        """
        self.send(fmt_msg(event, payload))

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
        if signum == self.debugger.pause_signal:
            self.debugger.set_step()

    def _get_events(self):
        """
        Infinitly yield events from the communicator.
        """
        while self.reader.is_alive():
            yield self.pipe.recv()

    def _get_commands(self):
        """
        Yields the commands out of the events.
        """
        for event in self._get_events():
            if event['e'] == 'error':
                self.handle_error(event.get('p'))
            else:
                command = getattr(self, 'command_' + event['e'], None)
                if not command:
                    self.send_error('event', 'event %s does not exist'
                                    % event['e'])
                else:
                    yield lambda: command(event.get('p'))

    def handle_error(self, payload):
        raise QdbCommunicationError(payload)

    def next_command(self, msg=None):
        """
        Returns the next command to be called with the current stackframe.
        If msg provided, it sends the msg back the server first.
        """
        # Send back the provided message.
        if msg:
            self.send(msg)
        try:
            return next(self._command_generator)()
        except StopIteration:
            raise QdbCommunicationError()

    def command_step(self, payload):
        self.debugger.set_step()

    def command_return(self, payload):
        self.debugger.set_return(self.debugger.curframe)

    def command_next(self, payload):
        self.debugger.set_next(self.debugger.curframe)

    def command_until(self, payload):
        self.debugger.set_until(self.debugger.curframe)

    def command_continue(self, payload):
        self.debugger.set_continue()

    def command_eval(self, payload):
        if not self.payload_check(payload, 'eval'):
            return self.next_command()
        with capture_output() as out:
            try:
                self.debugger.eval_fn(
                    payload,
                    self.debugger.curframe,
                    'single'
                )
            except Exception as e:
                self.send_print(
                    payload,
                    self.debugger.eval_exception_packager(e)
                )
            else:
                out_msg = out.getvalue()[:-1] if out.getvalue() \
                    and out.getvalue()[-1] == '\n' else out.getvalue()
                self.send_print(payload, out_msg)

        self.next_command()

    def command_set_watch(self, payload):
        if not self.payload_check(payload, 'set_watch'):
            return self.next_command()

        stackframe = self.debugger.curframe
        for w in payload:
            if w in stackframe.f_locals:
                obj = stackframe.f_locals[w]
            elif w in stackframe.f_globals:
                obj = stackframe.f_globals[w]
            else:
                err_msg = fmt_err_msg('set_watch', w)
                return self.next_command(err_msg)

            self.debugger.watchlist[w] = obj

        self.send_watchlist()

    def command_remove_watch(self, payload):
        if not self.payload_check(payload, 'clear_watch'):
            return self.next_command()

        for w in payload:
            self.watchlist.pop(w)

        self.send_watchlist()

    def command_set_break(self, payload):
        if not self.payload_check(payload, 'set_break'):
            return self.next_command()
        try:
            breakpoint = self.unserialize_breakpoint(payload)
        except QdbBreakpointReadError as b:
            err_msg = fmt_err_msg('set_break', str(b))
            return self.next_command(err_msg)

        try:
            self.debugger.add_breakpoint(**breakpoint)
        except QdbUnreachableBreakpoint as u:
            err_msg = fmt_err_msg('set_breakpoint', str(u))
            return self.next_command(err_msg)

        self.next_command()

    def command_clear_break(self, payload):
        if not self.payload_check(payload, 'clear_break'):
            return self.next_command()
        try:
            breakpoint = self.unserialize_breakpoint(payload)
        except QdbBreakpointReadError as b:
            err_msg = fmt_err_msg('clear_break', str(b))
            return self.next_command(err_msg)

        self.debugger.remove_breakpoint(**breakpoint)
        self.next_command()

    def command_list(self, payload):
        if not self.payload_check(payload, 'list'):
            return self.next_command()

        if 'file' not in payload:
            err_msg = fmt_err_msg('payload', 'list: expected field \'file\'')
            return self.next_command(err_msg)
        if not (payload.get('start') or payload.get('end')):
            msg = fmt_msg('list', self.debugger.get_file(payload['file']))
        else:
            # Send back the slice of the file that they requested.
            msg = fmt_msg(
                'list',
                self.debugger.file_cache[payload['file']][
                    payload.get('start'):payload.get('end')
                ]
            )

        self.next_command(msg)

    def command_start(self, payload):
        self.send_breakpoints()
        self.send_watchlist()
        self.send_stack()
        self.next_command()

    def command_disable(self, payload):
        if not self.payload_check(payload, 'disable'):
            return self.next_command()
        if payload not in ['soft', 'hard']:
            err_msg = fmt_err_msg(
                'disable',
                'payload must be either \'soft\' or \'hard\''
            )
            return self.next_command(err_msg)
        self.send(fmt_msg('disabled', None))
        self.debugger.disable(payload)


class ServerReader(object):
    """
    Object that reads from the server asyncronously from the process
    being debugged.
    """
    def __init__(self, debugger_pipe, session_pid, server_comm,
                 pause_signal=None):
        self.pause_signal = signal.SIGUSR2
        self.debugger_pipe = debugger_pipe
        self.server_comm = server_comm
        self.session_pid = session_pid
        self.socket_error = None
        self.process_messages()

    def command_pause(self):
        """
        Manages the pause command by raising a user defined signal in the
        session process which will be caught by the command manager.
        """
        os.kill(self.session_pid, self.pause_signal)

    def get_events(self):
        """
        Infinitly yields valid events off of the socket.
        """
        while True:
            try:
                cmd_len = self.server_comm.recv(4)
                if len(cmd_len) != 4:
                    # We did not get a valid length, the stream is corrupt.
                    return
                cmd_len = unpack('>i', cmd_len)[0]
                pre_unpickle = self.server_comm.recv(cmd_len)
                cmd = pickle.loads(pre_unpickle)
            except socket.error as e:
                # We can no longer talk the the server.
                self.debugger_pipe.send({'e': 'error', 'p': e})
                return
            except pickle.UnpicklingError as p:
                msg = fmt_err_msg('pickle', str(p))
                self.server_comm.sendall(pack('>i', len(msg)))
                self.server_comm.sendall(msg)
            else:
                # Yields only valid commands.
                yield cmd

    def process_messages(self):
        """
        Infinitly reads events off the server, if it is a pause, then it pauses
        the process, otherwise, it passes the message along.
        """
        for event in self.get_events():
            if event['e'] == 'pause':
                self.command_pause()
            else:
                self.debugger_pipe.send(event)

        # If we get here, we had a socket error that dropped us out of
        # get_events(), signal this to the process.
        self.debugger_pipe.send({'e': 'disable', 'e': 'soft'})
