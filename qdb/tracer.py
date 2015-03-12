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
from bdb import Bdb, Breakpoint, checkfuncname, BdbQuit
from contextlib import contextmanager
from functools import partial
from itertools import takewhile
import json
import signal
import sys
import traceback
from uuid import uuid4

from logbook import Logger, FileHandler

from qdb.comm import TerminalCommandManager, fmt_msg
from qdb.compat import map, items, ExitStack, StringIO
from qdb.config import QdbConfig
from qdb.errors import (
    QdbUnreachableBreakpoint,
    QdbQuit,
    QdbExecutionTimeout,
    QdbPrognEndsInStatement,
)
from qdb.output import RemoteOutput, OutputTee
from qdb.utils import (
    Timeout,
    default_eval_fn,
    default_exception_serializer,
    progn,
)


log = Logger('Qdb')


@contextmanager
def capture_output():
    """
    Captures stdout and stderr for the duration of the body.
    example
    with capture_output() as (out, err):
        print 'hello'
    """
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = StringIO()
    sys.stderr = StringIO()
    try:
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout.close()
        sys.stderr.close()
        sys.stdout = old_stdout
        sys.stderr = old_stderr


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
            cls._instance = super(Qdb, cls).__new__(cls)
            cls._instance._init(*args, **kwargs)
        return cls._instance

    def __init__(self, *args, **kwargs):
        pass

    def _init(self, config=None, merge=False, **kwargs):
        """
        See qdb.config for more information about the configuration of
        qdb.
        merge denotes how config and kwargs should be merged.
        QdbConfig.kwargs_first says config will trample kwargs,
        QdbConfig.config_first says kwargs will trample config.
        Otherwise, kwargs and config cannot both be passed.
        """
        self.super_ = super(Qdb, self)
        self.super_.__init__()
        self.reset()
        if config and kwargs:
            if merge == QdbConfig.kwargs_first:
                first = kwargs
                second = config
            elif merge == QdbConfig.config_first:
                first = config
                second = kwargs
            else:
                raise TypeError('Cannot pass config and kwargs')
            config = first.merge(second)
        else:
            config = QdbConfig.get_config(config or kwargs)

        self.address = config.host, config.port
        self.set_default_file(config.default_file)
        self.default_namespace = config.default_namespace or {}
        self.exception_serializer = config.exception_serializer or \
            default_exception_serializer
        self.eval_fn = config.eval_fn or default_eval_fn
        self._file_cache = {}
        self.retry_attepts = config.retry_attepts
        self.repr_fn = config.repr_fn
        self._skip_fn = config.skip_fn or (lambda _: False)
        self.pause_signal = config.pause_signal \
            if config.pause_signal else signal.SIGUSR2
        self.uuid = str(config.uuid or uuid4())
        self.watchlist = {}
        self.execution_timeout = config.execution_timeout
        self.reset()
        self.log_handler = None
        if config.log_file:
            self.log_handler = FileHandler(config.log_file)
            self.log_handler.push_application()

        self.bound_cmd_manager = config.cmd_manager or TerminalCommandManager()
        self.bound_cmd_manager.start(config.auth_msg)

        # We need to be able to send stdout back to the user debugging the
        # program. We hold a handle to this in case the program resets stdout.
        self._old_stdout = sys.stdout
        self._old_stderr = sys.stderr
        self.redirect_output = (
            config.redirect_output and
            not isinstance(self.cmd_manager, TerminalCommandManager)
        )
        if self.redirect_output:
            sys.stdout = OutputTee(
                sys.stdout,
                RemoteOutput(self.cmd_manager, '<stdout>'),
            )
            sys.stderr = OutputTee(
                sys.stderr,
                RemoteOutput(self.cmd_manager, '<stderr>'),
            )

    def bound_cmd_manager():
        def fget(self):
            return self.__cmd_manager

        class BoundCmdMangaer(object):
            def __init__(self, tracer, cmd_manager):
                self._tracer = tracer
                self._cmd_manager = cmd_manager

            def __getattr__(self, name):
                return partial(getattr(self._cmd_manager, name), self._tracer)

        def fset(self, value):
            self.cmd_manager = value
            self.__cmd_manager = BoundCmdMangaer(self, value)

        return fget, fset
    bound_cmd_manager = property(*bound_cmd_manager())

    def skip_fn(self, path):
        return self._skip_fn(self.canonic(path))

    def restore_output_streams(self):
        """
        Restores the original output streams.
        """
        if self.redirect_output:
            sys.stdout = self._old_stdout
            sys.stderr = self._old_stderr

    def _new_execution_timeout(self, src):
        """
        Return a new execution timeout context manager.
        If not execution timeout is in place, returns ExitStack()
        """
        # We use no_gevent=True because this could be cpu bound. This will
        # still throw to the proper greenlet if this is gevented.
        return (
            Timeout(
                self.execution_timeout,
                QdbExecutionTimeout(src, self.execution_timeout),
                no_gevent=True,
            ) if self.execution_timeout else ExitStack()
        )

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
        try:
            return self.get_file_lines(filename)[line - 1]
        except IndexError:
            return 'No source available for this line.'

    def get_file(self, filename):
        """
        Retrieves a file out of cache or opens and caches it.
        """
        return '\n'.join(self.get_file_lines(filename))

    def get_file_lines(self, filename):
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
                self._file_cache[canonic_name] = tuple(map(
                    lambda l: l[:-1] if l.endswith('\n') else l,
                    f.readlines()
                ))
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
        self.super_.clear_break(filename, lineno)

    def canonic(self, filename):
        canonic_filename = self.super_.canonic(filename)
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
        id_ = lambda n: n  # Why is this NOT a builtin?
        for expr in self.watchlist:
            try:
                with self._new_execution_timeout(expr), \
                        self.inject_default_namespace() as stackframe:
                    self.watchlist[expr] = (
                        None,
                        (self.repr_fn or id_)(
                            self.eval_fn(expr, stackframe)
                        )
                    )
            except Exception as e:
                self.watchlist[expr] = (
                    type(e).__name__,
                    self.exception_serializer(e)
                )

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
                    with self._new_execution_timeout(breakpoint.cond), \
                            self.inject_default_namespace(stackframe) as frame:
                        val = self.eval_fn(
                            breakpoint.cond,
                            frame,
                            'eval'
                        )
                except Exception as e:
                    # Send back a message to let the user know there was an
                    # issue with their breakpoint.
                    self.cmd_manager.send_error(
                        'condition', {
                            'cond': breakpoint.cond,
                            'line': line,
                            'exc': type(e).__name__,
                            'output': self.exception_serializer(e),
                        }
                    )
                    # Return this breakpoint to be safe. The user will be
                    # stopped here so that they can fix the breakpoint.
                    return breakpoint, False

                if val:
                    if breakpoint.ignore > 0:
                        breakpoint.ignore = breakpoint.ignore - 1
                    else:
                        return breakpoint, True
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

        if self.skip_fn(stackframe.f_code.co_filename):
            # We want to skip this, don't stop but keep tracing.
            return self.trace_dispatch

        try:
            return self.super_.trace_dispatch(stackframe, event, arg)
        except BdbQuit:
            raise QdbQuit()  # Rewrap as a QdbError object.

    def user_call(self, stackframe, arg):
        if self.break_here(stackframe):
            self.user_line(stackframe)

    def user_line(self, stackframe):
        self.setup_stack(stackframe, None)
        bound_cmd_manager = self.bound_cmd_manager
        bound_cmd_manager.send_watchlist()
        bound_cmd_manager.send_stack()
        bound_cmd_manager.next_command()

    def user_return(self, stackframe, return_value):
        stackframe.f_locals['__return__'] = return_value
        self.setup_stack(stackframe, None)
        bound_cmd_manager = self.bound_cmd_manager
        bound_cmd_manager.send_watchlist()
        bound_cmd_manager.send_stack()
        bound_cmd_manager.next_command(
            fmt_msg('return', str(return_value), serial=json.dumps),
        )

    def user_exception(self, stackframe, exc_info):
        exc_type, exc_value, exc_traceback = exc_info
        stackframe.f_locals['__exception__'] = exc_type, exc_value
        self.setup_stack(stackframe, exc_traceback)
        bound_cmd_manager = self.bound_cmd_manager
        bound_cmd_manager.send_watchlist()
        bound_cmd_manager.send_stack()
        msg = fmt_msg(
            'exception', {
                'type': exc_type.__name__,
                'value': str(exc_value),
                'traceback': traceback.format_tb(exc_traceback)
            },
            serial=json.dumps,
        )
        self.bound_cmd_manager.next_command(msg)

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

    def eval_(self, code):
        outexc = None
        outmsg = None
        with capture_output() as (out, err), \
                self._new_execution_timeout(code), \
                self.inject_default_namespace() as stackframe:
            try:
                if self.repr_fn:
                    # Do some some custom single mode magic that lets us call
                    # the repr function on the last expr.
                    try:
                        print(self.repr_fn(
                            progn(
                                code,
                                self.eval_fn,
                                stackframe,
                            )
                        ))
                    except QdbPrognEndsInStatement:
                        # Statements have no value to print.
                        pass
                else:
                    self.eval_fn(
                        code,
                        stackframe,
                        'single',
                    )
            except Exception as e:
                outexc = type(e).__name__
                outmsg = self.exception_serializer(e)
            else:
                outmsg = (out.getvalue()[:-1] if out.getvalue() and
                          out.getvalue()[-1] == '\n' else out.getvalue())

        if outexc is not None or outmsg is not None:
            self.cmd_manager.send_print(code, outexc, outmsg)

        self.update_watchlist()

    def _stack_jump_to(self, index):
        """
        Jumps the stack to a specific index.
        Raises an IndexError if the desired index does not exist.
        """
        # Try to jump here first. This could raise an IndexError which will
        # prevent the tracer's state from being corrupted.
        self.curframe = self.stack[index][0]

        self.curindex = index
        self.curframe_locals = self.curframe.f_locals
        self.update_watchlist()

    def stack_shift_direction(self, direction):
        """
        Shifts the stack up or down depending on dirction.
        If direction is positive, travel up, if direction is negative, travel
        down. If direction is 0, do nothing.
        If you cannot shift in the desired direction, an IndexError will be
        raised.
        """
        if direction == 0:
            return  # nop

        direction = -1 if direction > 0 else 1

        # The substack is a stack were substack[n] is n + 1 frames away from
        # curframe where we are traveling in the direction we want to shift.
        if direction < 0:
            # We are moving UP the stack:
            # substack is the stack containing all frames above curframe.
            substack = self.stack[self.curindex:0:direction]
        else:
            # We are moving DOWN the stack:
            # substack is the stack containing all the frames below curframe.
            substack = self.stack[self.curindex + 1:]

        if not substack:
            # If substack is empty, you are at the end of the stack, shifting
            # in the desired direction is impossible.
            raise IndexError('Shifted off the stack')

        # Count the number of frames that we are not allowed to stop in.
        # We add one at the end because there is an implied shift of at least
        # one stackframe.
        skip_fn = self.skip_fn
        diff = sum(1 for _ in takewhile(
            lambda fl: skip_fn(fl[0].f_code.co_filename),
            substack,
        )) + 1

        idx = self.curindex + direction * diff
        if skip_fn(self.stack[idx][0].f_code.co_filename):
            # There are no frames to shift to.
            raise IndexError('Shifted off the stack')

        self._stack_jump_to(idx)

    def disable(self, mode='soft'):
        """
        Stops tracing.
        """
        try:
            if mode == 'soft':
                self.clear_all_breaks()
                self.set_continue()
                # Remove this instance so that new ones may be created.
                self.__class__._instance = None
            elif mode == 'hard':
                sys.exit(1)
            else:
                raise ValueError("mode must be 'hard' or 'soft'")
        finally:
            self.restore_output_streams()
            if self.log_handler:
                self.log_handler.pop_application()
            self.cmd_manager.stop()
            if sys.gettrace() is self.trace_dispatch:
                sys.settrace(None)

    def __enter__(self):
        self.set_trace(sys._getframe().f_back, stop=False)
        return self

    def __exit__(self, type, value, traceback):
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

    @contextmanager
    def inject_default_namespace(self, stackframe=None):
        """
        Adds the default namespace to the frame, or if no frame is provided,
        self.curframe is used.
        """
        stackframe = stackframe or self.curframe
        to_remove = set()
        for k, v in items(self.default_namespace):
            if k not in stackframe.f_globals:
                # Only add the default things if the name is unbound.
                stackframe.f_globals[k] = v
                to_remove.add(k)

        try:
            yield stackframe
        finally:
            for k in to_remove:
                try:
                    del stackframe.f_globals[k]
                except IndexError:
                    # The body of this manager might have del'd this.
                    pass

            # Prevent exceptions from generating ref cycles.
            del stackframe
