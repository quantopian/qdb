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
from __future__ import print_function

from types import MethodType


__all__ = [
    'Connection',
    'ExitStack',
    'PY2',
    'PY3',
    'StringIO',
    'gevent',
    'gyield',
    'items',
    'keys',
    'range',
    'reduce',
    'str_to_bytes',
    'zip',
]


try:
    reduce = reduce
    PY2 = True
except NameError:
    from functools import reduce
    PY2 = False

PY3 = not PY2

try:
    import gevent

    def gyield():
        gevent.sleep(0.01)
except ImportError:
    gevent = None

    def gyield():
        pass

if PY2:
    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO

    from contextlib2 import ExitStack
    import itertools

    boundmethod = MethodType
    filter = itertools.ifilter
    input = raw_input  # NOQA
    items = dict.iteritems
    keys = dict.iterkeys
    map = itertools.imap
    range = xrange  # NOQA
    zip = itertools.izip

else:
    from contextlib import ExitStack
    from io import StringIO

    def boundmethod(f, instance, owner):
        return MethodType(f, instance)

    filter = filter
    input = input  # NOQA
    items = dict.items
    keys = dict.keys
    map = map
    range = range
    zip = zip

print_ = print


class Connection(object):
    """
    A wrapper for a multiprocessing connection to emulate gipc pipes.
    """
    def __init__(self, conn):
        self.__conn = conn

    def put(self, *args, **kwargs):
        return self.__conn.send(*args, **kwargs)

    def get(self, *args, **kwargs):
        return self.__conn.recv(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self.__conn, name)


def with_metaclass(metaclass, *bases):
    """
    Adds a new base in the mro for python 2 and 3 compatible
    metaclass syntax.
    """
    return metaclass('SurrogateBase', bases, {})


def str_to_bytes(s, encoding):
    """
    Convert from ``str`` to ``six.binary_type``.

    In Python 2, this is a no-op.
    In Python 3, this encodes ``s`` as bytes using ``encoding``.

    This function should be used in cases where you want to convert a value
    that's always ``str`` (in both PY2 and PY3) into a value that's always
    ``bytes``.

    Parameters
    ----------
    s : str
        Value to be converted to bytes.
    encoding : str
        Encoding to use for conversion in Python 3.

    Returns
    -------
    bytes_ : bytes
        The input string, as bytes.
    """
    if not isinstance(s, str):
        raise TypeError("Expected str, got {}".format(type(s)))
    if PY2:
        return s
    else:
        return s.encode(encoding)
