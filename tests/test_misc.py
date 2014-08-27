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
import signal
import sys
import time
from unittest import TestCase

import gevent
from nose_parameterized import parameterized

from qdb.tracer import (
    default_eval_fn,
    default_exception_serializer,
)
from qdb.utils import Timeout, QdbTimeout


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


class UtilsTester(TestCase):
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

    def test_timeout_smart_constructor(self):
        """
        Tests that the smart constructor returns the correct type.
        """
        green = Timeout(1, green=True)
        self.assertTrue(isinstance(green, gevent.Timeout))
        not_green = Timeout(1, green=False)
        self.assertTrue(isinstance(not_green, QdbTimeout))

    @parameterized.expand([(False,), (True,)])
    def test_smart_constructor_can_catch(self, green):
        """
        Asserts that users may use the normal try/catch syntax with
        the Timeout smart constructor.
        This test will fail if except Timeout does NOT catch the exception.
        """
        try:
            raise Timeout(1, green=green)
        except Timeout:
            pass

    @parameterized.expand([(False,), (True,)])
    def test_timout_isinstance(self, green):
        """
        Asserts that the Timeout smart constructor returns are instances of
        Timeout.
        """
        self.assertIsInstance(Timeout(1, green=green), Timeout)
