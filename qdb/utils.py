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
import ast
import re
import signal as signal_module
import sys
import tokenize

from uuid import uuid4

from qdb.errors import QdbError, QdbPrognEndsInStatement
from qdb.compat import gevent, PY2


def default_eval_fn(src, stackframe, mode='eval', original=None):
    """
    Wrapper around vanilla eval with no safety.
    """
    code = compile(src, '<stdin>', mode)
    if mode in ['exec', 'single']:
        exec(code, stackframe.f_globals, stackframe.f_locals)
        return

    return eval(code, stackframe.f_globals, stackframe.f_locals)


def default_exception_serializer(exception):
    """
    The default exception serializer for user exceptions in eval.
    """
    return '%s: %s' % (type(exception).__name__, str(exception))


class QdbTimeout(QdbError):
    """
    A timer implemented with signals.
    Example useages:
        with QdbTimeout(timeout_in_seconds):
            time_consuming_function()

    or:

        t = QdbTimeout(timeout_in_seconds, True):
        t.start()
        try:
            time_consuming_function()
        except QdbTimeout as u:
            if t is u:
                cleanup()
    """
    def __init__(self, seconds, exception=None, green=False):
        """
        seconds is the number of seconds to run this Timeout for.
        exception is the exception to raise in the case of a timeout.
        When exception is ommited or None, the QdbTimeout itself is raised.
        """
        if not isinstance(seconds, int):
            raise ValueError('integer argument expected, got %s'
                             % type(seconds).__name__)

        self._exception = exception
        self._existing_handler = None
        self.seconds = seconds
        self._running = False

        if gevent is not None:
            self._greenlet = gevent.getcurrent()
        else:
            self._greenlet = None

    def _signal_handler(self, signum, stackframe):
        if self._running:
            # Restore the orignal handler in case it times out.
            signal_module.signal(signal_module.SIGALRM, self._existing_handler)
            exc = self._exception or self
            if gevent is None:
                raise exc
            else:
                self._greenlet.throw(exc)

    def start(self):
        """
        Starts the timer.
        """
        self._existing_handler = signal_module.signal(
            signal_module.SIGALRM,
            self._signal_handler
        )
        self._running = True
        signal_module.alarm(self.seconds)

    def cancel(self):
        """
        Cancels the timer
        """
        self._running = False
        signal_module.alarm(0)  # Cancel the alarm.
        # Restore the original handler in case the user cancels.
        signal_module.signal(signal_module.SIGALRM, self._existing_handler)

    @property
    def pending(self):
        """
        Read only access to the internal running state.
        """
        return self._running

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.cancel()
        if exc_value is self and self._exception is False:
            return True

    def __str__(self):
        return 'Timed out after %s seconds' % self.seconds

    def __repr__(self):
        return 'QdbTimeout(seconds=%s, exception=%s, timer_signal=%s)' \
            % (self.seconds, self._exception, signal_module.SIGALRM)


if gevent is not None:
    class _TimeoutMagic(tuple):
        """
        _TimeoutMagic is really just a tuple that can be called to
        get a new Timeout that is either gevented or not.
        """
        def __call__(self, seconds, exception=None, green=False):
            """
            A timeout smart constructor that returns a
            gevent.Timeout or a QdbTimeout.
            """
            if green:
                timeout = gevent.Timeout
            else:
                timeout = QdbTimeout

            return timeout(seconds, exception)

    # The way this works is that in an except block, if you pass a
    # tuple of exceptions, it will compare the exception to each of
    # the exceptions in the tuple. Therefore, if you write:
    #
    # except Timeout:
    #
    # You can think of it as expanding to:
    #
    # except (gevent.Timeout, QdbTimeout):
    #
    # Also, because the __call__ has been overridden, you can get
    # the proper timeout by calling:
    #
    # Timeout(seconds, green=is_green)
    #
    # Timeout is capitalized because in almost all use cases you
    # can think of this as a class, even though there is a little
    # more going on.
    Timeout = _TimeoutMagic((gevent.Timeout, QdbTimeout))
else:
    Timeout = QdbTimeout


# Don't register the results from these nodes.
NO_REGISTER_STATEMENTS = frozenset((
    # Classes and functions.
    ast.FunctionDef,
    ast.ClassDef,
    ast.Return,

    # Assign and delete.
    ast.Delete,
    ast.Assign,
    ast.AugAssign,

    # Imports
    ast.Import,
    ast.ImportFrom,

    ast.Raise,

    ast.Global,
    ast.Pass,

    # Python 2 only
    ast.Print if PY2 else None,
    ast.Repr if PY2 else None,
))


# Matches valid python names.
NAME_REGEX = re.compile(tokenize.Name)


def to_id_char(c, default_char='_'):
    """
    Converts a character to a valid identifier character.
    """
    return c if re.match(NAME_REGEX, c) else default_char


def isolate_namespace(name):
    """
    Isolates name from the user's namespace by prefixing it with a pseudo
    random string that is still a valid identifier.
    """
    name = ''.join(map(to_id_char, name))
    return 'a%s%s' % (uuid4().hex, name)


def register_last_expr(tree, register):
    """
    Registers the last expression as register in the context of an AST.
    tree may either be a list of nodes, or an ast node with a body.
    Returns the newly modified structure AND mutates the original.
    """
    if isinstance(tree, list):
        if not tree:
            # Empty body.
            return tree
        # Allows us to use cases like directly passing orelse bodies.
        last_node = tree[-1]
    else:
        last_node = tree.body[-1]
    if type(last_node) in NO_REGISTER_STATEMENTS:
        return tree

    def mk_register_node(final_node):
        return ast.Expr(
            value=ast.Call(
                func=ast.Name(
                    id=register,
                    ctx=ast.Load(),
                ),
                args=[
                    final_node.value,
                ],
                keywords=[],
                starargs=None,
                kwargs=None,
            )
        )

    if hasattr(last_node, 'body'):
        # Deep inspect the body of the nodes.
        register_last_expr(last_node, register)

        # Try to register in all the body types.
        try:
            register_last_expr(last_node.orelse, register)
        except AttributeError:
            pass
        try:
            for handler in last_node.handlers:
                register_last_expr(handler, register)
        except AttributeError:
            pass
        try:
            register_last_expr(last_node.finalbody, register)
        except AttributeError:
            pass
    else:
        # Nodes with no body require no recursive inspection.
        tree.body[-1] = mk_register_node(last_node)

    return ast.fix_missing_locations(tree)


def progn(src, eval_fn=None, stackframe=None):
    """
    Evaluate all expressions and statments in src, returns the result of the
    last expression or raises a QdbPrognEndsInStatement if the last thing is a
    statement.
    eval_fn is the function to evaluate the src with and should conform to the
    same standards as the Qdb class's eval_fn param.
    stackframe is the context to evaluate src in, if None, it will be the
    calling stackframe.
    """
    eval_fn = eval_fn or default_eval_fn
    register_name = isolate_namespace('register')
    code = register_last_expr(ast.parse(src), register_name)

    stackframe = stackframe or sys._getframe().f_back
    store = {}

    def register(expr):
        """
        Store the last expression's result.
        """
        store['expr'] = expr
        return expr

    # Add the register function to the namespace.
    stackframe.f_globals[register_name] = register
    try:
        eval_fn(code, stackframe, 'exec', original=src)
    finally:
        # Always remove the register function from the namespace.
        # This is to not fill the namespace after multiple calls to progn.
        del stackframe.f_globals[register_name]
    try:
        # Attempt to retrieve the last expression.
        return store['expr']
    except KeyError:
        # There was no final expression.
        raise QdbPrognEndsInStatement(src)
