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
import gevent
from gevent.event import Event
from logbook import Logger

from qdb.server.client import QdbClientServer
from qdb.server.session_store import SessionStore
from qdb.server.tracer import QdbTracerServer

log = Logger('QdbServer')

# The default route.
DEFAULT_ROUTE = '/websocket/(.+)'

# The default route as a format string.
DEFAULT_ROUTE_FMT = '/websocket/{uuid}'

# The number of seconds a browser has to authenticate.
AUTH_TIMEOUT = 60  # seconds


class QdbServer(object):
    """
    The QdbServer manages starting and stopping both the client and tracer
    servers.
    """
    def __init__(self,
                 session_store=None,
                 tracer_host='localhost',
                 tracer_port=8001,
                 client_host='localhost',
                 client_port=8002,
                 route=DEFAULT_ROUTE,
                 auth_timeout=AUTH_TIMEOUT,
                 tracer_auth_fn=None,
                 client_auth_fn=None,
                 tracer_server=None,
                 client_server=None):
        """
        Sets up the qdb server.
        """
        self.session_store = session_store or SessionStore()
        client_auth_fn = client_auth_fn or (lambda _: True)  # No auth.
        tracer_auth_fn = tracer_auth_fn or (lambda _: True)
        self._running = False
        self._stop = Event()
        self.tracer_server = tracer_server or QdbTracerServer(
            session_store=self.session_store,
            tracer_auth_fn=tracer_auth_fn,
            host=tracer_host,
            port=tracer_port,
            auth_timeout=auth_timeout
        )
        self.client_server = client_server or QdbClientServer(
            session_store=self.session_store,
            host=client_host,
            port=client_port,
            route=route,
            auth_timeout=auth_timeout,
            client_auth_fn=client_auth_fn,
        )
        host = self.client_server.address[0], self.tracer_server.address[0]
        port = self.client_server.address[1], self.tracer_server.address[1]
        self.address = host, port

    def is_running(self):
        """
        Returns True iff the server is running, otherwise returns False.
        """
        return self._running

    def start(self):
        """
        Starts accepting new connections.
        """
        gevent.spawn(self.session_store.start)
        self._running = True
        self._stop.clear()
        self.tracer_server.start()
        self.client_server.start()

    def serve_forever(self):
        """
        Begins accepting new connections, blocking until the server is
        terminated.
        """
        self.start()
        self._stop.wait()

    def stop(self):
        """
        Stops the internal servers.
        """
        self.tracer_server.stop()
        self.client_server.stop()
        self.session_store.stop()
        self._stop.set()
        self._running = False
