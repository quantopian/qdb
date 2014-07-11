from bdb import Bdb, Breakpoint, checkfuncname, BdbQuit
from itertools import imap
import signal
import sys
from uuid import uuid4

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

from logbook import Logger

from qdb.comm import CommandManager, fmt_msg
from qdb.errors import QdbUnreachableBreakpoint, QdbQuit

log = Logger('Qdb')


def default_eval_fn(src, stackframe, mode='eval'):
    """
    Wrapper around vanilla eval with no safety.
    """
    code = compile(src, '<string>', mode)
    return eval(code, stackframe.f_globals, stackframe.f_locals)


def default_eval_exception_packager(exception):
    """
    The default exception handler for user exceptions in eval.
    """
    return str(exception)


class Qdb(Bdb, object):
    """
    The Quantopian Remote Debugger.
    """
    def __init__(self,
                 host='localhost',
                 port=8001,
                 eval_fn=None,
                 skip_fn=None,
                 topfile=None,
                 file_cache={},
                 pause_signal=None,
                 retry_attepts=10,
                 uuid_fn=None,
                 auth_fn=None):
        """
        Host and port define the address to connect to.
        eval_fn is the function to eval code where the user may provide it,
        for example in a conditional breakpoint, or in the repl.
        skip_fn is simmilar to the skip list feature of Bdb, except that
        it should be a function that takes a filename and returns True iff
        the debugger should skip this file. These files will be suppressed from
        stack traces with a '...' in its place.
        topfile defines a file where anything that does not have that in the
        stack will be skipped.
        file_cache will be used to pre-populate the internal filecache used for
        looking up files and lines.
        retry_attempts is the number of times to attempt to connect to the
        server before raising a QdbFailedToConnect error.
        The uuid_fn is a function that will be used to generate unique session
        identifiers, this defaults to uuid4.
        """
        self.address = host, port
        self.cmd_manager = None
        self.eval_exception_packager = default_eval_exception_packager
        self.eval_fn = default_eval_fn
        self.file_cache = file_cache
        self.retry_attepts = retry_attepts
        self.skip_fn = lambda _: False
        self.pause_signal = pause_signal if pause_signal else signal.SIGUSR2
        self.topfile = topfile
        self.uuid = str((uuid_fn if uuid_fn else uuid4)())
        self.watchlist = {}
        # We need to be able to send stdout back to the user debugging the
        # program. We hold a handle to this in case the program resets stdout.
        self.stdout = StringIO()
        self.stdout_ptr = self.stdout.tell()
        sys.stdout = self.stdout
        self.forget()
        super(Qdb, self).__init__()
        self.connect()

    def connect(self):
        """
        Attempts to connect to the server.
        On success, returns None, raises a QdbFailedToConnect error otherwise.
        """
        self.cmd_manager = CommandManager(self)

    def get_line(self, filename, line):
        """
        Checks for any user cached files before deferring to the linecache.
        """
        if filename in self.file_cache:
            return self.file_cache[filename][line - 1]
        self.cache_file(filename)
        return self.get_line(filename, line)

    def get_file(self, filename):
        """
        Retrieves a file out of cache or opens and caches it.
        """
        if filename in self.file_cache:
            return ''.join(self.file_cache[filename])
        self.cache_file(filename)
        return self.get_file(filename)

    def is_executable(self, filename, line):
        """
        Cannot execute blank lines or comments.
        """
        code = self.get_line(filename, line).strip()
        return code and not code.startswith(('#', '"""', "'''"))

    def cache_file(self, filename, contents=None):
        """
        Caches filename from disk into memory.
        This overrides whatever was cached for filename previously.
        If contents is provided, it allows the user to cache a filename to a
        string.
        """
        if contents:
            self.file_cache[filename] = contents.splitlines()
            return
        with open(filename, 'r') as f:
            self.file_cache[filename] = f.readlines()

    def set_break(self, filename, lineno, temporary=0, cond=None,
                  funcname=None):
        """
        Sets a breakpoint. This is overridden to account for the filecache
        and for unreachable lines.
        """
        filename = self.canonic(filename)
        bp = Breakpoint(filename, lineno, temporary, cond, funcname)
        try:
            self.get_line(filename, lineno)
        except IndexError:
            raise QdbUnreachableBreakpoint(bp)

        Breakpoint.bpbynumber[Breakpoint.next] = bp
        Breakpoint.next += 1

        if (filename, lineno) in Breakpoint.bplist:
            Breakpoint.bplist[(filename, lineno)] = [bp]
        else:
            Breakpoint.bplist[(filename, lineno)].append(bp)

    def clear_break(self, filename, lineno, **kwargs):
        """
        Wrapper to make the breakpoint json standardized for setting
        and removing of breakpoints.
        """
        super(Qdb, self).clear_break(filename, lineno)

    def canonic(self, filename):
        canonic_filename = super(Qdb, self).canonic(filename)
        if canonic_filename.endswith('pyc'):
            return canonic_filename[:-1]
        return canonic_filename

    @staticmethod
    def stack_generator(stackframe):
        """
        Yields the stack starting at stackframe.
        """
        while stackframe:
            yield stackframe
            stackframe = stackframe.f_back

    def below_or_in_topfile(self, stackframe):
        """
        Returns True iff the topfile is in the stack above or on this frame.
        """
        if self.topfile is None:
            return True
        return any(imap(lambda f: f.f_code.co_filename == self.topfile,
                        self.stack_generator(stackframe)))

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
        self.forget()
        self.stack, self.curindex = self.get_stack(stackframe, traceback)
        self.curframe = self.stack[self.curindex][0]
        self.curframe_locals = self.curframe.f_locals

    def effective(self, file, line, stackframe):
        """
        Finds teh effective breakpoint for this line; called only
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
                            'exc': self.debugger.eval_exception_packager(e),
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
        if not filename in self.breaks:
            return False
        lineno = stackframe.f_lineno
        if not lineno in self.breaks[filename]:
            # The line itself has no breakpoint, but maybe the line is the
            # first line of a function with breakpoint set by function name.
            lineno = stackframe.f_code.co_firstlineno
            if not lineno in self.breaks[filename]:
                return False

        # flag says ok to delete temp. bp
        breakpoint, flag = self.effective(filename, lineno, stackframe)
        if breakpoint:
            self.currentbp = breakpoint.number
            if flag and breakpoint.temporary:
                self.do_clear(breakpoint)
            return True
        else:
            return False

    def trace_dispatch(self, frame, event, arg):
        """
        Trace function that does some preliminary checks and then defers to
        the event handler for each type of event.
        """
        if self.quitting:
            # We were told to quit by the user, bubble this up to their code.
            raise QdbQuit()

        if not self.below_or_in_topfile(frame):
            return None

        if self.skip_fn(frame.f_code.co_filename):
            # We want to skip this, don't stop but keep tracing.
            return self.trace_dispatch
        if event == 'line':
            return self.dispatch_line(frame)
        if event == 'call':
            return self.dispatch_call(frame, arg)
        if event == 'return':
            return self.dispatch_return(frame, arg)
        if event == 'exception':
            return self.dispatch_exception(frame, arg)
        if event == 'c_call':
            return self.trace_dispatch
        if event == 'c_exception':
            return self.trace_dispatch
        if event == 'c_return':
            return self.trace_dispatch
        try:
            super(Qdb, self).trace_dispatch(frame, event, arg)
        except BdbQuit:
            raise QdbQuit()  # Rewrap as a QdbError object.

    def user_call(self, stackframe, arg):
        pass

    def user_line(self, stackframe):
        self.setup_stack(stackframe, None)
        self.cmd_manager.send_watchlist()
        self.cmd_manager.send_stdout()
        self.cmd_manager.send_stack()
        self.cmd_manager.next_command()

    def user_return(self, stackframe, return_value):
        stackframe.f_locals['__return__'] = return_value
        self.setup_stack(stackframe, None)
        self.cmd_manager.send_watchlist()
        self.cmd_manager.send_stdout()
        self.cmd_manager.send_stack()
        msg = fmt_msg('return', str(return_value))
        self.cmd_manager.next_command(msg)

    def dispatch_exception(self, stackframe, exc_info):
        exc_type, exc_value, exc_traceback = exc_info
        stackframe.f_locals['__exception__'] = exc_type, exc_value
        self.setup_stack(stackframe, exc_traceback)
        self.cmd_manager.send_watchlist()
        self.cmd_manager.send_stdout()
        self.cmd_manager.send_stack()
        msg = fmt_msg('exception', {
            'type': exc_type,
            'value': exc_value,
            'traceback': exc_traceback
        })
        self.cmd_manager.next_command(msg)

    def do_clear(arg):
        """
        Handles deletion of temporary breakpoints.
        """
        arg.deleteMe()

    def set_quit(self):
        """
        Sets the quitting state and restores the program state.
        """
        self.quitting = True
        # Restore stdout to the true stdout.
        sys.stdout = sys.__stdout__

    def disable(self, mode):
        """
        Stops tracing.
        """
        if mode == 'soft':
            self.clear_all_breaks()
            self.set_continue()
            sys.stdout = self.real_stdout
        elif mode == 'hard':
            sys.exit(1)
        else:
            raise ValueError('mode must be \'hard\' or \'soft\'')
