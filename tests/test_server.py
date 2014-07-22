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

import gevent
from gevent import Timeout, spawn_later
import socket
from struct import pack, unpack
from websocket import create_connection

from qdb.server import (
    QdbServer,
    QdbClientServer,
    QdbNopClientServer,
    QdbTracerServer,
    QdbNopTracerServer,
)
from qdb.server.server import DEFAULT_ROUTE_FMT

try:
    import cPickle as pickle
except ImportError:
    import pickle


def send_tracer_event(sck, event, payload):
    """
    Sends an event over the socket.
    """
    msg = pickle.dumps({
        'e': event,
        'p': payload,
    })
    sck.sendall(pack('>i', len(msg)))
    sck.sendall(msg)


def recv_tracer_event(sck):
    """
    Reads an event off the socket.
    """
    length = sck.recv(4)
    if len(length) != 4:
        return None
    length = unpack('>i', length)[0]
    return pickle.loads(sck.recv(length)[0])


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
        """
        Tests that stopping a server from one greenlet causes serve_forever()
        to return.
        """
        server = QdbServer()
        with Timeout(1, False):
            spawn_later(0.3, server.stop)  # Stop the server in 0.3 seconds.
            server.serve_forever()
        self.assertFalse(server.is_running())

    def test_bad_auth_client(self):
        """
        Tests a non-valid auth message for a client.
        """
        server = QdbServer(
            client_host='localhost',
            client_port=8003,
            client_auth_fn=lambda _: False,  # Fail all new clients.
            tracer_server=QdbNopTracerServer(),
        )
        server.start()

        auth_failed_dict = {
            'e': 'error',
            'p': {
                'type': 'auth',
                'data': 'Authentication failed'
            }
        }
        disable_dict = {'e': 'disable'}

        auth_failed_msg = ''
        disable_msg = ''

        try:
            ws = create_connection(
                'ws://localhost:8003' + DEFAULT_ROUTE_FMT.format(uuid='test')
            )
            ws.send(json.dumps({'e': 'start', 'p': 'friendzoned-again'}))

            with Timeout(2, False):
                # The server should time us out in 1 second and send back these
                # two messages.
                auth_failed_msg = ws.recv()
                disable_msg = ws.recv()

            self.assertEquals(auth_failed_msg, json.dumps(auth_failed_dict))
            self.assertEquals(disable_msg, json.dumps(disable_dict))
            self.assertFalse('test' in server.session_store)
        finally:
            server.stop

    def test_client_auth_timeout(self):
        server = QdbServer(
            client_host='localhost',
            client_port=8004,
            auth_timeout=1,  # Timeout after 1 second.
            tracer_server=QdbNopTracerServer(),
        )
        server.start()
        ws = create_connection(
            'ws://localhost:8004' + DEFAULT_ROUTE_FMT.format(uuid='test')
        )

        auth_failed_dict = {
            'e': 'error',
            'p': {
                'type': 'auth',
                'data': 'No start event received'
            }
        }
        disable_dict = {'e': 'disable'}

        auth_failed_msg = ''
        disable_msg = ''

        try:
            with Timeout(2, False):
                # The server should time us out in 1 second and send back these
                # two messages.
                auth_failed_msg = ws.recv()
                disable_msg = ws.recv()

            self.assertEquals(auth_failed_msg, json.dumps(auth_failed_dict))
            self.assertEquals(disable_msg, json.dumps(disable_dict))
            self.assertFalse('test' in server.session_store)
        finally:
            server.stop()

    def test_bad_auth_tracer(self):
        """
        Tests a non-valid auth message for a tracer.
        """
        server = QdbServer(
            tracer_host='localhost',
            tracer_port=8001,
            tracer_auth_fn=lambda _: False,
            client_server=QdbNopClientServer(),
        )
        server.start()
        try:
            sck = socket.create_connection(('localhost', 8001))

            send_tracer_event(sck, 'start', {
                'uuid': 'test',
                'auth': 'friendzoned-again'
            })
            with self.assertRaises(EOFError):
                # We failed auth so the socket should be closed.
                recv_tracer_event(sck)
        finally:
            if sck:
                sck.close()
            server.stop()

    def test_tracer_auth_timeout(self):
        """
        Tests the auth timeout for new connections from the client.
        """
        sck = None
        server = QdbServer(
            tracer_host='localhost',
            tracer_port=8006,
            client_server=QdbNopClientServer(),
            auth_timeout=1,  # 1 second auth timeout.
        )
        server.start()
        try:
            sck = socket.create_connection(('localhost', 8006))

            passes = False
            with Timeout(2, False):
                try:
                    recv_tracer_event(sck)
                except EOFError:
                    passes = True

            self.assertTrue(passes)
        finally:
            if sck:
                sck.close()
            server.stop()
