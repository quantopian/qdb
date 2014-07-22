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

from qdb.tracer import Qdb

# Populate the namespace with potentially user facing errors. This allows the
# user to more easily import them to catch.
from qdb.errors import (  # NOQA
    QdbAuthenticationError,
    QdbError,
    QdbQuit,
    QdbFailedToConnect,
    QdbCommunicationError,
)

_version = '0.1.0'


def set_trace(host='localhost',
              port=8001,
              eval_fn=None,
              skip_fn=None,
              pause_signal=None,
              redirect_stdout=True,
              retry_attepts=10,
              uuid_fn=None,
              auth_fn=None,
              cmd_manager=None):
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
        pause_signal=pause_signal,
        redirect_stdout=redirect_stdout,
        retry_attepts=retry_attepts,
        uuid_fn=uuid_fn,
        auth_fn=auth_fn,
        cmd_manager=cmd_manager,
    ).set_trace(sys._getframe().f_back)
    # We use f_back so that we start in the caller of this function.
