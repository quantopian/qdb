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
from bdb import Bdb, Breakpoint, checkfuncname, BdbQuit
import signal
import sys
import traceback
from uuid import uuid4

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

from logbook import Logger, FileHandler

from qdb.comm import RemoteCommandManager, fmt_msg
from qdb.errors import QdbUnreachableBreakpoint, QdbQuit

try:
    import cPickle as pickle
except ImportError:
    import pickle

log = Logger('Qdb')


def default_eval_fn(src, stackframe, mode='eval', exec_=False):
    """
    Wrapper around vanilla eval with no safety.
    """
    code = compile(src, '<string>', mode)
    if exec_:
        exec(code, stackframe.f_globals, stackframe.f_locals)
        return
    return eval(code, stackframe.f_globals, stackframe.f_locals)


def default_exception_serializer(exception):
    """
    The default exception serializer for user exceptions in eval.
    """
    return '%s: %s' % (type(exception).__name__, str(exception))


class Qdb(Bdb, object):
    """
    The Quantopian Remote Debugger.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        """
        Qdb objects are singletons that persist until their disable method is
        called.
        """
        if not cls._instance:
            cls._instance = super(Qdb, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self,
                 host='localhost',
                 port=8001,
                 auth_msg='',
                 default_file=None,
                 eval_fn=None,
                 exception_serializer=None,
                 skip_fn=None,
                 pause_signal=None,
                 redirect_output=True,
                 retry_attepts=10,
                 uuid=None,
                 cmd_manager=None,
                 log_file=None):
        """
        Host and port define the address to connect to.
        The auth_msg is a message that will be sent with the start event to the
        server. This can be used to do server/tracer authentication.
        The default_file is a file to use if the file field is ommited from
        payloads.
        eval_fn is the function to eval code where the user may provide it,
        for example in a conditional breakpoint, or in the repl.
        skip_fn is simmilar to the skip list feature of Bdb, except that
        it should be a function that takes a filename and returns True iff
        the debugger should skip this file. These files will be suppressed from
        stack traces.
        The pause_signal is signal to raise in this program to trigger a pause
        command. If this is none, this will default to SIGUSR2.
        retry_attempts is the number of times to attempt to connect to the
        server before raising a QdbFailedToConnect error.
        The repr_fn is a function to use to convert objects to strings to send
        then back to the server. By default, this wraps repr by catching
        exceptions and reporting them to the user.
        The uuid is the identifier on the server for this session. If none is
        provided, it will generate a uuid4.
        cmd_manager should be a callable that takes a Qdb instance and manages
        commands by implementing a next_command method. If none, a new, default
        manager will be created that reads commands from the server at
        (host, port).
        """
        super(Qdb, self).__init__()
        self.address = host, port
        self.set_default_file(default_file)
        self.exception_serializer = exception_serializer or \
            default_exception_serializer
        self.eval_fn = eval_fn or default_eval_fn
        self._file_cache = {}
        self.redirect_output = redirect_output
        self.retry_attepts = retry_attepts
        self.skip_fn = skip_fn or (lambda _: False)
        self.pause_signal = pause_signal if pause_signal else signal.SIGUSR2
        self.uuid = str(uuid or uuid4())
        self.watchlist = {}
        # We need to be able to send stdout back to the user debugging the
        # program. We hold a handle to this in case the program resets stdout.
        if self.redirect_output:
            self.stdout = StringIO()
            self.stderr = StringIO()
            sys.stdout = self.stdout
            sys.stderr = self.stderr
        self.forget()
        self.log_handler = None
        if log_file:
            self.log_handler = FileHandler(log_file)
            self.log_handler.push_application()
        if not cmd_manager:
            cmd_manager = RemoteCommandManager
        self.cmd_manager = cmd_manager(self)
        self.cmd_manager.start(auth_msg)

    def clear_output_buffers(self):
        """
        Clears the output buffers.
        """
        self.stdout.close()
        self.stderr.close()
        self.stdout = StringIO()
        self.stderr = StringIO()
        sys.stdout = self.stdout
        sys.stderr = self.stderr

    def set_default_file(self, filename):
        """
        Safely sets the new default file.
        """
        self.default_file = self.canonic(filename) if filename else None

    def get_line(self, filename, line):
        """
        Checks for any user cached files before deferring to the linecache.
        """
        # The line - 1 is so that querying line 1 gives us the first line in
        # the file.
        return self._get_file_lines(filename)[line - 1]

    def get_file(self, filename):
        """
        Retrieves a file out of cache or opens and caches it.
        """
        return '\n'.join(self._get_file_lines(filename))

    def _get_file_lines(self, filename):
        """
        Retrieves the file from the file cache as a list of lines.
        If the file does not exist in the cache, it is cached from
        disk.
        """
        canonic_name = self.canonic(filename)
        try:
            return self._file_cache[canonic_name]
        except KeyError:
            if not self.cache_file(canonic_name):
                return []
            return self._file_cache.get(canonic_name)

    def cache_file(self, filename, contents=None):
        """
        Caches filename from disk into memory.
        This overrides whatever was cached for filename previously.
        If contents is provided, it allows the user to cache a filename to a
        string.
        Returns True if the file caching succeeded, otherwise returns false.
        """
        canonic_name = self.canonic(filename)
        if contents:
            self._file_cache[canonic_name] = contents.splitlines()
            return True
        try:
            with open(canonic_name, 'r') as f:
                self._file_cache[canonic_name] = map(
                    lambda l: l[:-1] if l.endswith('\n') else l,
                    f.readlines()
                )
                return True
        except IOError:
            # The caching operation failed.
            return False

    def set_break(self, filename, lineno, temporary=False, cond=None,
                  funcname=None, **kwargs):
        """
        Sets a breakpoint. This is overridden to account for the filecache
        and for unreachable lines.
        **kwargs are ignored. This is to work with payloads that pass extra
        fields to the set_break payload.
        """
        filename = self.canonic(filename) if filename else self.default_file
        try:
            self.get_line(filename, lineno)
        except IndexError:
            raise QdbUnreachableBreakpoint({
                'file': filename,
                'line': lineno,
                'temp': temporary,
                'cond': cond,
                'func': funcname,
            })

        blist = self.breaks.setdefault(filename, [])
        if lineno not in blist:
            blist.append(lineno)
        Breakpoint(filename, lineno, temporary, cond, funcname)

    def clear_break(self, filename, lineno, *args, **kwargs):
        """
        Wrapper to make the breakpoint json standardized for setting
        and removing of breakpoints.
        This means that the same json data that was used to set a break point
        may be fed into this function with the extra values ignored.
        """
        super(Qdb, self).clear_break(filename, lineno)

    def canonic(self, filename):
        canonic_filename = super(Qdb, self).canonic(filename)
        if canonic_filename.endswith('pyc'):
            return canonic_filename[:-1]
        return canonic_filename

    def reset(self):
        self.botframe = None
        self._set_stopinfo(None, None)
        self.forget()

    def forget(self):
        self.lineno = None
        self.stack = []
        self.curindex = 0
        self.curframe = None

    def setup_stack(self, stackframe, traceback):
        """
        Sets up the state of the debugger object for this frame.
        """
        self.forget()
        self.stack, self.curindex = self.get_stack(stackframe, traceback)
        self.curframe = self.stack[self.curindex][0]
        self.curframe_locals = self.curframe.f_locals
        self.update_watchlist()

    def extend_watchlist(self, *args):
        """
        Adds every arg to the watchlist and updates.
        """
        for expr in args:
            self.watchlist[expr] = (False, '')

        self.update_watchlist()

    def update_watchlist(self):
        """
        Updates the watchlist by evaluating all the watched expressions in
        our current frame.
        """
        for expr in self.watchlist:
            try:
                self.watchlist[expr] = (False,
                                        self.eval_fn(expr, self.curframe))
            except Exception as e:
                self.watchlist[expr] = (True,
                                        self.exception_serializer(e))

    def effective(self, file, line, stackframe):
        """
        Finds the effective breakpoint for this line; called only
        when we know that there is a breakpoint here.

        returns the breakpoint paired with a flag denoting if we should
        remove this breakpoint or not.
        """
        for breakpoint in Breakpoint.bplist[file, line]:
            if breakpoint.enabled == 0:
                continue
            if not checkfuncname(breakpoint, stackframe):
                continue
            # Count every hit when breakpoint is enabled
            breakpoint.hits = breakpoint.hits + 1
            if not breakpoint.cond:
                # If unconditional, and ignoring go on to next, else break
                if breakpoint.ignore > 0:
                    breakpoint.ignore = breakpoint.ignore - 1
                    continue
                else:
                    return breakpoint, True
            else:
                # Conditional breakpoint
                # Ignore count applies only to those bpt hits where the
                # condition evaluates to true.
                try:
                    val = self.eval_fn(breakpoint.cond, stackframe, 'eval')
                    if val:
                        if breakpoint.ignore > 0:
                            breakpoint.ignore = breakpoint.ignore - 1
                        else:
                            return breakpoint, True
                except Exception as e:
                    # Send back a message to let the user know there was an
                    # issue with their breakpoint.
                    self.cmd_manager.send_error(
                        'condition', {
                            'cond': breakpoint.cond,
                            'exc': self.debugger.exception_serializer(e),
                        }
                    )
                    # Return this breakpoint to be safe. The user will be
                    # stopped here so that they can fix the breakpoint.
                    return breakpoint, False
        return None, False

    def break_here(self, stackframe):
        """
        Checks if we should break execution in this stackframe.
        This function handles the cleanup and ignore counts for breakpoints.
        Returns True iff we should stop in the stackframe, False otherwise.
        """
        filename = self.canonic(stackframe.f_code.co_filename)
        if filename not in self.breaks:
            return False
        lineno = stackframe.f_lineno
        if lineno not in self.breaks[filename]:
            # The line itself has no breakpoint, but maybe the line is the
            # first line of a function with breakpoint set by function name.
            lineno = stackframe.f_code.co_firstlineno
            if lineno not in self.breaks[filename]:
                return False

        # flag says ok to delete temporary breakpoints.
        breakpoint, flag = self.effective(filename, lineno, stackframe)
        if breakpoint:
            self.currentbp = breakpoint.number
            if flag and breakpoint.temporary:
                self.do_clear(breakpoint.number)
            return True
        else:
            return False

    def trace_dispatch(self, stackframe, event, arg):
        """
        Trace function that does some preliminary checks and then defers to
        the event handler for each type of event.
        """
        if self.quitting:
            # We were told to quit by the user, bubble this up to their code.
            return

        if self.skip_fn(self.canonic(stackframe.f_code.co_filename)):
            # We want to skip this, don't stop but keep tracing.
            return self.trace_dispatch

        try:
            return super(Qdb, self).trace_dispatch(stackframe, event, arg)
        except BdbQuit:
            raise QdbQuit()  # Rewrap as a QdbError object.

    def user_call(self, stackframe, arg):
        if self.break_here(stackframe):
            self.user_line(stackframe)

    def user_line(self, stackframe):
        self.setup_stack(stackframe, None)
        self.cmd_manager.send_watchlist()
        self.cmd_manager.send_output()
        self.cmd_manager.send_stack()
        self.cmd_manager.next_command()

    def user_return(self, stackframe, return_value):
        stackframe.f_locals['__return__'] = return_value
        self.setup_stack(stackframe, None)
        self.cmd_manager.send_watchlist()
        self.cmd_manager.send_output()
        self.cmd_manager.send_stack()
        msg = fmt_msg('return', str(return_value), serial=pickle.dumps)
        self.cmd_manager.next_command(msg)

    def user_exception(self, stackframe, exc_info):
        exc_type, exc_value, exc_traceback = exc_info
        stackframe.f_locals['__exception__'] = exc_type, exc_value
        self.setup_stack(stackframe, exc_traceback)
        self.cmd_manager.send_watchlist()
        self.cmd_manager.send_output()
        self.cmd_manager.send_stack()
        msg = fmt_msg(
            'exception', {
                'type': str(exc_type),
                'value': str(exc_value),
                'traceback': traceback.format_tb(exc_traceback)
            },
            serial=pickle.dumps,
        )
        self.cmd_manager.next_command(msg)

    def do_clear(self, bpnum):
        """
        Handles deletion of temporary breakpoints.
        """
        if not (0 <= bpnum < len(Breakpoint.bpbynumber)):
            return
        self.clear_bpbynumber(bpnum)

    def set_quit(self):
        """
        Sets the quitting state and restores the program state.
        """
        self.quitting = True
        # Restore stdout to the true stdout.
        sys.stdout = sys.__stdout__

    def disable(self, mode='soft'):
        """
        Stops tracing.
        """
        try:
            if mode == 'soft':
                self.clear_all_breaks()
                self.set_continue()
                sys.stdout = sys.__stdout__
                # Remove this instance so that new ones may be created.
                self.__class__._instance = None
            elif mode == 'hard':
                sys.exit(1)
            else:
                raise ValueError("mode must be 'hard' or 'soft'")
        finally:
            if self.log_handler:
                self.log_handler.pop_application()
            self.cmd_manager.stop()

    def __enter__(self):
        self.set_trace(sys._getframe().f_back)
        return self

    def __exit__(self, type, value, traceback):
        if isinstance(value, QdbQuit) or value is None:
            self.disable('soft')

    def set_trace(self, stackframe=None, stop=True):
        """
        Starts debugging in stackframe or in the callers frame.
        If stop is True, begin stepping from here, otherwise, wait for
        the first breakpoint or exception.
        """
        # We need to look back 1 frame to get our caller.
        stackframe = stackframe or sys._getframe().f_back
        self.reset()
        while stackframe:
            stackframe.f_trace = self.trace_dispatch
            self.botframe = stackframe
            stackframe = stackframe.f_back
        if stop:
            self.set_step()
        else:
            self.set_continue()
        sys.settrace(self.trace_dispatch)
