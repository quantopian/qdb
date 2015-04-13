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

from nose_parameterized import parameterized
from struct import pack

from qdb.comm import fmt_msg, fmt_err_msg, get_events_from_socket
from qdb.compat import gevent, PY2

from tests.compat import skip_py3

if PY2:
    # These need python 2
    from websocket import create_connection

    from qdb.server import (
        QdbServer,
        QdbNopServer,
    )
    from qdb.server.session_store import ALLOW_ORPHANS
    from qdb.server.client import DEFAULT_ROUTE_FMT


def send_tracer_event(sck, event, payload):
    """
    Sends an event over the socket.
    """
    msg = fmt_msg(event, payload, serial=json.dumps)
    sck.sendall(pack('>i', len(msg)))
    sck.sendall(msg)


def send_client_event(ws, event, payload):
    """
    Sends an event to the client.
    """
    ws.send(fmt_msg(event, payload, serial=json.dumps))


def recv_tracer_event(sck):
    """
    Reads an event off the socket.
    """
    try:
        return next(get_events_from_socket(sck))
    except StopIteration:
        return {}


def recv_client_event(ws):
    """
    Reads an event off the websocket.
    """
    return json.loads(ws.recv())


@skip_py3
class ServerTester(TestCase):
    def test_start_stop(self):
        """
        Tests starting and stopping the server.
        """
        server = QdbServer(
            client_port=0,
            tracer_port=0
        )
        self.assertFalse(server.is_running)
        server.start()
        self.assertTrue(server.is_running)
        server.stop()
        self.assertFalse(server.is_running)

    def test_runforever_exit(self):
        """
        Tests that stopping a server from one greenlet causes serve_forever()
        to return.
        """
        server = QdbServer(
            client_port=0,
            tracer_port=0
        )
        with gevent.Timeout(1, False):
            # Stop the server in 0.3 seconds.
            gevent.spawn_later(0.3, server.stop)
            server.serve_forever()
        self.assertFalse(server.is_running)

    def test_bad_auth_client(self):
        """
        Tests a non-valid auth message for a client.
        """
        with QdbServer(client_host='localhost',
                       client_port=0,
                       client_auth_fn=lambda _: False,  # Fail all new clients.
                       tracer_server=QdbNopServer()) as server:

            ws = create_connection(
                'ws://localhost:%d%s' % (server.client_server.server_port,
                                         DEFAULT_ROUTE_FMT.format(uuid='test'))
            )
            send_client_event(ws, 'start', 'friendzoned-again')

            auth_failed_event = disable_event = None

            with gevent.Timeout(2, False):
                # The server should time us out in 1 second and send back these
                # two messages.
                auth_failed_event = recv_client_event(ws)
                disable_event = recv_client_event(ws)

            auth_failed_dict = fmt_err_msg('auth', 'Authentication failed')

            self.assertEquals(auth_failed_event, auth_failed_dict)
            self.assertEquals(disable_event['e'], 'disable')
            self.assertFalse('test' in server.session_store)

    def test_client_auth_timeout(self):
        with QdbServer(client_host='localhost',
                       client_port=0,
                       auth_timeout=1,  # Timeout after 1 second.
                       tracer_server=QdbNopServer()) as server:
            ws = create_connection(
                'ws://localhost:%d%s' % (server.client_server.server_port,
                                         DEFAULT_ROUTE_FMT.format(uuid='test'))
            )

            auth_failed_dict = fmt_err_msg('auth', 'No start event received')
            disable_dict = fmt_msg('disable')

            auth_failed_msg = ''
            disable_msg = ''

            with gevent.Timeout(2, False):
                # The server should time us out in 1 second and send back these
                # two messages.
                auth_failed_msg = ws.recv()
                disable_msg = ws.recv()

            self.assertEquals(auth_failed_msg, json.dumps(auth_failed_dict))
            self.assertEquals(disable_msg, json.dumps(disable_dict))
            self.assertFalse('test' in server.session_store)

    def test_bad_auth_tracer(self):
        """
        Tests a non-valid auth message for a tracer.
        """
        with QdbServer(tracer_host='localhost',
                       tracer_port=0,
                       tracer_auth_fn=lambda _: False,
                       client_server=QdbNopServer()) as server:

            auth_failed_dict = fmt_err_msg('auth', 'Authentication failed')

            sck = gevent.socket.create_connection(
                ('localhost', server.tracer_server.server_port)
            )

            send_tracer_event(sck, 'start', {
                'uuid': 'test',
                'auth': 'friendzoned-again',
                'local': (0, 0),
            })
            # We failed auth so the socket should be closed.
            self.assertEqual(auth_failed_dict,
                             recv_tracer_event(sck))
            self.assertFalse('test' in server.session_store)

    def test_tracer_auth_timeout(self):
        """
        Tests the auth timeout for new connections from the client.
        """
        with QdbServer(tracer_host='localhost',
                       tracer_port=0,
                       client_server=QdbNopServer(),
                       auth_timeout=1) as server:

            auth_failed_dict = fmt_err_msg('auth', 'No start event received')
            sck = gevent.socket.create_connection(
                ('localhost', server.tracer_server.server_port)
            )

            self.assertEqual(auth_failed_dict, recv_tracer_event(sck))
            self.assertFalse('test' in server.session_store)

    @parameterized.expand(['hard', 'soft'])
    def test_inactivity_timeout(self, mode):
        """
        Tests that timeout sends a disable message with the proper mode..
        """
        with QdbServer(tracer_host='localhost',
                       tracer_port=0,
                       client_host='localhost',
                       client_port=0,
                       inactivity_timeout=0.01,  # minutes
                       sweep_time=0.01,  # seconds
                       timeout_disable_mode=mode) as server:

            tracer = gevent.socket.create_connection(
                ('localhost', server.tracer_server.server_port)
            )
            send_tracer_event(tracer, 'start', {
                'uuid': 'test',
                'auth': '',
                'local': (0, 0),
            })
            client = create_connection(
                'ws://localhost:%d%s' % (server.client_server.server_port,
                                         DEFAULT_ROUTE_FMT.format(uuid='test'))
            )
            send_client_event(client, 'start', '')
            self.assertEqual({'e': 'start', 'p': ''},
                             recv_tracer_event(tracer))
            self.assertEqual({'e': 'disable', 'p': mode},
                             recv_tracer_event(tracer))
            self.assertEqual('disable', recv_client_event(client)['e'])
            self.assertFalse('test' in server.session_store)

    @parameterized.expand(['hard', 'soft'])
    def test_client_attach_timeout(self, mode):
        """
        Tests the case when a client attaches but no tracer does.
        """
        with QdbServer(tracer_server=QdbNopServer(),
                       client_host='localhost',
                       client_port=0,
                       attach_timeout=0.01,
                       timeout_disable_mode=mode) as server:

            client = create_connection(
                'ws://localhost:%d%s' % (server.client_server.server_port,
                                         DEFAULT_ROUTE_FMT.format(uuid='test'))
            )
            send_client_event(client, 'start', '')
            disable_event = None
            with gevent.Timeout(0.1, False):
                error_event = recv_client_event(client)
                disable_event = recv_client_event(client)

            error_dict = fmt_err_msg('tracer', 'No tracer')

            self.assertEqual(error_dict, error_event)
            self.assertEqual(fmt_msg('disable'), disable_event)
            self.assertNotIn('test', server.session_store)

    @parameterized.expand(['hard', 'soft'])
    def test_tracer_attach_timeout(self, mode):
        """
        Tests the case where a tracer attaches but no client does.
        """
        with QdbServer(tracer_host='localhost',
                       tracer_port=0,
                       client_server=QdbNopServer(),
                       attach_timeout=0.01,
                       timeout_disable_mode=mode) as server:

            tracer = gevent.socket.create_connection(
                ('localhost', server.tracer_server.server_port)
            )
            send_tracer_event(tracer, 'start', {
                'uuid': 'test',
                'auth': '',
                'local': (0, 0),
            })
            disable_event = None
            with gevent.Timeout(0.1, False):
                error_event = recv_tracer_event(tracer)
                disable_event = recv_tracer_event(tracer)

            error_dict = fmt_err_msg('client', 'No client')

            self.assertEqual(error_dict, error_event)
            self.assertEqual(fmt_msg('disable', mode), disable_event)
            self.assertNotIn('test', server.session_store)

    def test_client_orphan_session(self):
        """
        Tests that a client makes it into the session store without a tracer
        attaching if attach_timeout is set to ALLOW_ORPHANS or 0.
        """
        with QdbServer(tracer_server=QdbNopServer(),
                       client_host='localhost',
                       client_port=0,
                       attach_timeout=ALLOW_ORPHANS) as server:
            client = create_connection(
                'ws://localhost:%d%s' % (server.client_server.server_port,
                                         DEFAULT_ROUTE_FMT.format(uuid='test'))
            )
            send_client_event(client, 'start', '')
            # yield to the session_store to let it get attached.
            gevent.sleep(0.01)
            self.assertIn('test', server.session_store)

    def test_tracer_orphan_session(self):
        """
        Tests that a tracer makes it into the session_store without a client
        attaching if attach_timeout is set to ALLOW_ORPHANS or 0.
        """
        with QdbServer(client_server=QdbNopServer(),
                       tracer_host='localhost',
                       tracer_port=0,
                       attach_timeout=ALLOW_ORPHANS) as server:
            tracer = gevent.socket.create_connection(
                ('localhost', server.tracer_server.server_port)
            )
            send_tracer_event(tracer, 'start', {
                'uuid': 'test',
                'auth': '',
                'local': (0, 0),
            })
            # yield to the session_store to let it get attached.
            gevent.sleep(0.01)
            self.assertIn('test', server.session_store)
