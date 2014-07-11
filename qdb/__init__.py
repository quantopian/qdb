import sys

from qdb.debugger import Qdb
from qdb.errors import (
    QdbError,
    QdbQuit,
    QdbFailedToConnect,
    QdbCommunicationError,
)  # Populates the namespace with any potentially user facing exceptions.

_version = '0.1.0.0'


def set_trace(host='localhost',
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
    Begins tracing from this point.
    All arguments except for stackframe are passed to the constructor of the
    internal Qdb object.
    """
    Qdb(
        host=host,
        port=port,
        eval_fn=eval_fn,
        skip_fn=skip_fn,
        topfile=topfile,
        file_cache=file_cache,
        pause_signal=pause_signal,
        retry_attepts=retry_attepts,
        uuid_fn=uuid_fn,
        auth_fn=auth_fn,
    ).set_trace(sys._getframe().f_back)
    # We use f_back so that we start in the caller of this function.
