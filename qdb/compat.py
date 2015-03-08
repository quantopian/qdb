try:
    reduce = reduce
    PY2 = True
except NameError:
    from functools import reduce
    PY2 = False


PY3 = not PY2


try:
    import gevent
except ImportError:
    gevent = None


if PY2:
    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO

    import itertools

    filter = itertools.ifilter
    items = dict.iteritems
    map = itertools.imap
    range = xrange  # NOQA
    zip = itertools.izip

else:
    from io import StringIO

    filter = filter
    items = dict.items
    map = map
    range = range
    zip = zip


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


__all__ = [
    'Connection',
    'PY2',
    'PY3',
    'StringIO',
    'gevent',
    'items',
    'range',
    'reduce',
    'zip',
]
