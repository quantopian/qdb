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
    default_exception_serializer,
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
        test_var = 10
        test_fn = lambda n: n + 1
        test_list = [0]
        test_dict = {'t': 'test'}
        if issubclass(type(result), Exception):
            with self.assertRaises(type(result)):
                default_eval_fn(code, sys._getframe())
        else:
            self.assertEquals(result, default_eval_fn(code, sys._getframe()))

    @parameterized.expand([
        (KeyError('key'), 'KeyError: \'key\''),
        (ValueError(10), 'ValueError: 10'),
        (TestException('e'), 'TestException: result = e')
    ])
    def test_default_exception_serializer(self, exception, result):
        self.assertEquals(
            result,
            default_exception_serializer(exception),
        )
