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
import json
from unittest import TestCase

from gevent import Timeout, spawn_later
from websocket import create_connection

from qdb.server import (
    DEFAULT_ROUTE_FMT,
    QdbServer,
    QdbClientServer,
    QdbNopClientServer,
    QdbTracerServer,
    QdbNopTracerServer,
)


class ServerTester(TestCase):
    def test_start_stop(self):
        """
        Tests starting and stopping the server.
        """
        server = QdbServer()
        self.assertFalse(server.is_running())
        server.start()
        self.assertTrue(server.is_running())
        server.stop()
        self.assertFalse(server.is_running())

    def test_runforever_exit(self):
        server = QdbServer()
        with Timeout(1, False):
            spawn_later(0.3, server.stop)  # Stop the server in 0.3 seconds.
            server.serve_forever()
        self.assertFalse(server.is_running())

    def test_reject_client(self):
        server = QdbServer(
            client_host='localhost',
            client_port=8002,
            auth_fn=lambda _: False
        )
        server.start()
        with self.assertRaises(Exception):
            ws = create_connection(
                'ws://localhost:8002' + DEFAULT_ROUTE_FMT.format(uuid='test')
            )
            ws.send(json.dumps({'e': 'start', 'p': 'friendzoned-again'}))
            ws.send(json.dumps({'e': 'step'}))
        server.stop
