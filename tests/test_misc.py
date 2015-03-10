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
import ast
import signal
import sys
import time
from unittest import TestCase

from nose_parameterized import parameterized

from qdb.compat import gevent, keys
from qdb.errors import QdbPrognEndsInStatement
from qdb.utils import (
    default_eval_fn,
    default_exception_serializer,
    Timeout,
    QdbTimeout,
    progn,
)

from tests.compat import mock, skip_py3


class FakeFrame(object):
    """
    A fake stackframe for testing.
    """
    def __init__(self, locals=None, globals=None):
        self._locals = locals or {}
        self._globals = globals or {}

    @property
    def f_locals(self):
        """
        Returns a copy of locals.
        """
        return dict(self._locals)

    @property
    def f_globals(self):
        """
        Returns the actual globals.
        """
        return self._globals


class TestException(Exception):
    """
    Custom exception that implements __str__
    """
    def __init__(self, e):
        self.e = e

    def __str__(self):
        return 'result = ' + str(self.e)


class DefaultFnTester(TestCase):
    """
    Tester for the default functions that qdb accepts as parameters.
    This is to assert that default qdb works as intended.
    """
    @parameterized.expand([
        ('name_error', NameError()),
        ('wrongLanguage :: Python -> Haskell', SyntaxError()),
        ('1 / 0', ZeroDivisionError()),
        ('{}["key"]', KeyError()),
        ('test_var', 10),
        ('test_fn(1)', 2),
        ('test_list[0]', 0),
        ('test_dict["t"]', 'test'),
    ])
    def test_default_eval_fn(self, code, result):
        """
        Test that the default_eval_fn behaves like normal eval.
        """
        # We ignore flake8 warnings here because this code is only called from
        # within the string that we are evaling.
        test_var = 10  # NOQA
        test_fn = lambda n: n + 1  # NOQA
        test_list = [0]  # NOQA
        test_dict = {'t': 'test'}  # NOQA
        if isinstance(result, Exception):
            with self.assertRaises(type(result)):
                default_eval_fn(code, sys._getframe())
        else:
            self.assertEquals(result, default_eval_fn(code, sys._getframe()))

    @parameterized.expand([
        (KeyError('key'), "KeyError: 'key'"),
        (ValueError(10), 'ValueError: 10'),
        (TestException('e'), 'TestException: result = e')
    ])
    def test_default_exception_serializer(self, exception, result):
        self.assertEquals(
            result,
            default_exception_serializer(exception),
        )


class TimeoutTester(TestCase):
    @parameterized.expand([
        ('self', None, lambda self, u, t: self.assertIs(u, t)),
        ('exc', ValueError('u'),
         lambda self, u, t: self.assertEqual(str(u), 'u')),
    ])
    def test_timeout_start(self, test_name, exc, assertion):
        """
        Tests running a timeout with the start method that will raise itself.
        """
        tsignal = signal.SIGALRM
        existing_handler = signal.getsignal(tsignal)
        t = QdbTimeout(1, exc)
        t.start()
        with self.assertRaises(Exception) as cm:
            self.assertTrue(t.pending)
            time.sleep(2)
            if exc:
                self.fail('Timeout did not stop the sleep')

        self.assertIs(cm.exception, exc or t)
        self.assertIs(signal.getsignal(tsignal), existing_handler)

    @parameterized.expand([
        ('self', None, lambda self, u, t: self.assertIs(u, t)),
        ('exc', ValueError('u'),
         lambda self, u, t: self.assertEqual(str(u), 'u')),
        ('suppress', False, None),
    ])
    def test_timeout_ctx_mgr(self, test_name, exc, assertion):
        tsignal = signal.SIGALRM
        existing_handler = signal.getsignal(tsignal)
        try:
            with QdbTimeout(1, exc) as t:
                self.assertTrue(t.pending)
                time.sleep(2)
                if exc:
                    self.fail('Timeout did not stop the sleep')
        except Exception as u:
            assertion(self, u, t)
        else:
            self.assertIs(
                exc,
                False,
                'QdbTimeout(1, False) should not raise an exception'
            )

        self.assertIs(signal.getsignal(tsignal), existing_handler)

    def test_timeout_cancel(self):
        """
        Tests that stopping will stop the timer.
        """
        tsignal = signal.SIGALRM
        existing_handler = signal.getsignal(tsignal)
        with QdbTimeout(1) as t:
            self.assertTrue(t.pending)
            t.cancel()
            self.assertFalse(t.pending)

        self.assertIs(signal.getsignal(tsignal), existing_handler)

    def test_exit_clears_timer(self):
        """
        Tests that __exit__ stops the timer.
        """
        tsignal = signal.SIGALRM
        existing_handler = signal.getsignal(tsignal)
        with QdbTimeout(1) as t:
            self.assertTrue(t.pending)
        self.assertFalse(t.pending)

        self.assertIs(signal.getsignal(tsignal), existing_handler)

    @skip_py3
    def test_timeout_smart_constructor(self):
        """
        Tests that the smart constructor returns the correct type.
        """
        green = Timeout(1)
        self.assertTrue(isinstance(green, gevent.Timeout))
        not_green = Timeout(1, no_gevent=True)
        self.assertTrue(isinstance(not_green, QdbTimeout))

    @parameterized.expand([(False,), (True,)])
    def test_smart_constructor_can_catch(self, no_gevent):
        """
        Asserts that users may use the normal try/catch syntax with
        the Timeout smart constructor.
        This test will fail if except Timeout does NOT catch the exception.
        """
        try:
            raise Timeout(1, no_gevent=no_gevent)
        except Timeout:
            pass

    @parameterized.expand([(False,), (True,)])
    def test_timout_isinstance(self, no_gevent):
        """
        Asserts that the Timeout smart constructor returns are instances of
        Timeout.
        """
        self.assertIsInstance(Timeout(1, no_gevent=no_gevent), Timeout)


class PrognTester(TestCase):
    @parameterized.expand([
        ('literal_expr', '2 + 2', 4),
        ('function_call', 'f()', 'f'),
        ('compund', 'f(2 + 2)', 'f4'),
        ('multi_line', 'f()\n2 + 2', 4),
        ('with_semicolon', 'f(2);2 + 2', 4),
        ('with_stmt', 'with c() as cv:\n    cv', 'c'),
        ('if_true', 'if True:\n    True', True),
        ('elif', 'if False:    pass\nelif True:\n    True', True),
    ])
    def test_progn_default(self, name, src, expected_value):
        """
        Asserts that progn returns the last expression is various snippets
        of code. These should all be valid progn calls and return a value.
        """
        f = lambda n='': 'f%s' % n  # NOQA

        class c(object):
            """
            Testing context manager.
            """
            def __enter__(self):
                return 'c'

            def __exit__(self, *args, **kwargs):
                pass

        self.assertEqual(progn(src), expected_value)

    @parameterized.expand([
        ('end_in_assgn', 'a = 5', QdbPrognEndsInStatement),
        ('end_in_import', '2 + 2;import qdb', QdbPrognEndsInStatement),
        ('src_raises', 'raise ValueError("v")', ValueError),
        ('raise_ends_in_expr', 'raise ValueError("v");2 + 2', ValueError),
    ])
    def test_progn_raises(self, name, src, exc):
        """
        Tests the results of progn calls that raise exceptions.
        Some are exceptions in the code, some are because they are invalid
        progn calls.
        """
        with self.assertRaises(exc):
            progn(src)

    @parameterized.expand([
        ('mutate_local', 'locals()["local"] = None;2 + 2',
         lambda t, f: t.assertEqual(f.f_locals['local'], 'lvar')),
        ('mutate_global', 'globals()["global_"] = None;2 + 2',
         lambda t, f: t.assertIs(f.f_globals['global_'], None)),
    ])
    def test_progn_in_frame(self, name, src, assertion):
        """
        Tests that passing in a stackframe causes progn to evaluate code
        in the new context.
        Also asserts that implementation details do not leak out.
        """
        stackframe = FakeFrame({'local': 'lvar'}, {'global_': 'gvar'})
        progn(src, stackframe=stackframe)
        assertion(self, stackframe)

        # Make sure the register function name didn't persist.
        self.assertEqual(
            sorted(('__builtins__', 'global_')),
            sorted(keys(stackframe.f_globals)),
        )

    def test_progn_uses_custom_eval_fn(self):
        """
        Assert that the progn function uses custom eval functions properly.
        """
        eval_fn = mock.MagicMock()

        try:
            progn('2 + 2', eval_fn=eval_fn)
        except QdbPrognEndsInStatement:
            # This is the error that we are getting because our eval function
            # is not storing any results.
            pass

        calls = eval_fn.call_args_list

        self.assertEqual(len(calls), 1)
        call_args = calls[0][0]

        # This is constructed inside the function, but should be a module.
        self.assertIsInstance(call_args[0], ast.Module)
        self.assertEqual(call_args[1], sys._getframe())
        self.assertEqual(call_args[2], 'exec')
