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
from unittest import skipIf
from qdb.compat import PY3, items

try:
    from unittest import mock
except ImportError:
    import mock


class NonLocal(object):
    def __init__(self, value):
        self.value = value


skip_py3 = skipIf(PY3, 'This test will not work with python3')


class Py2TestMeta(type):
    def __new__(mcls, name, bases, dict_):
        if PY3:
            dict_.pop('setUpClass', None)
            dict_.pop('tearDownClass', None)

        return type.__new__(
            mcls,
            name,
            bases,
            {k: skip_py3(v) if k.startswith('test_') else v
             for k, v in items(dict_)},
        )


__all__ = [
    'NonLocal',
    'Py2TestMeta',
    'mock',
    'skip_py3',
]
