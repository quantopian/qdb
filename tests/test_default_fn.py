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
import sys
from unittest import TestCase

from nose_parameterized import parameterized

from qdb.debugger import (
    default_eval_fn,
    default_repr_fn,
    default_eval_exception_packager,
)


class TestException(Exception):
    """
    Custom exception that implements __str__
    """
    def __init__(self, e):
        self.e = e

    def  __str__(self):
        return 'result = ' + str(self.e)


class DefaultFnTester(TestCase):
    """
    Tester for the default functions that users can change.
    This asserts that their behavior is as documented.
    """
    @parameterized.expand([
        ('name_error', NameError()),
        ('wrongLanguage :: Python -> Haskell', SyntaxError()),
        ('1 / 0', ZeroDivisionError()),
        ('{}["key"]', KeyError()),
        ('test_var', 10),
        ('test_fn(1)', 2),
        ('test_list[0]', 0),
        ('test_dict["t"]', 'est'),
    ])
    def test_default_eval_fn(self, code, result):
        test_var = 10
        test_fn = lambda n: n + 1
        test_list = [0]
        test_dict = {'t': 'est'}
        if issubclass(type(result), Exception):
            with self.assertRaises(type(result)):
                default_eval_fn(code, sys._getframe())
        else:
            self.assertEquals(result, default_eval_fn(code, sys._getframe()))

    @parameterized.expand([
        ('test_1', 'repr on <class \'test_default_fn.Test1\'> raised: '
         '(AttributeError: __repr__)'),
        ('test_2', '__repr__'),
    ])
    def test_default_repr_fn(self, obj, result):
        class Test1(object):
            def __repr__(self):
                raise AttributeError('__repr__')

        class Test2(object):
            def __repr__(self):
                return '__repr__'

        test_1 = Test1()
        test_2 = Test2()

        self.assertEquals(result, default_repr_fn(eval(obj)))

    @parameterized.expand([
        (KeyError('key'), 'KeyError: \'key\''),
        (ValueError(10), 'ValueError: 10'),
        (TestException('e'), 'TestException: result = e')
    ])
    def test_default_eval_exception_packager(self, exception, result):
        self.assertEquals(
            result,
            default_eval_exception_packager(exception),
        )
