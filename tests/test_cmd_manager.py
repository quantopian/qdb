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
from contextlib import contextmanager
import json
import signal
from unittest import TestCase

from gevent import Timeout
from mock import Mock
from nose_parameterized import parameterized
from websocket import create_connection

from qdb.comm import RemoteCommandManager, ServerLocalCommandManager, fmt_msg
from qdb.errors import (
    QdbFailedToConnect,
    QdbAuthenticationError,
)
from qdb.server import QdbServer
from qdb.server.client import DEFAULT_ROUTE_FMT

from tests import fix_filename


class RemoteCommandManagerTester(TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Start up a tracer server for the remote command managers to connect to.
        """
        cls.bad_auth_msg = 'BAD-AUTH'
        cls.tracer_host = cls.client_host = 'localhost'
        cls.tracer_port = 7999
        cls.client_port = 7998
        cls.server = QdbServer(
            tracer_host=cls.tracer_host,
            tracer_port=cls.tracer_port,
            client_host=cls.client_host,
            client_port=cls.client_port,
            tracer_auth_fn=lambda a: a != cls.bad_auth_msg,
        )
        cls.server.start()
        cls.cmd_manager = RemoteCommandManager

    @classmethod
    def tearDownClass(cls):
        """
        Stop the test server.
        """
        cls.server.stop()

    def MockTracer(self):
        """
        Construct a mock tracer.
        """
        tracer = Mock()
        tracer.address = self.tracer_host, self.tracer_port
        tracer.pause_signal = signal.SIGUSR2
        tracer.retry_attepts = 1
        tracer.local = 0, 0
        tracer.uuid = 'mock'
        tracer.watchlist = {}
        tracer.stack = []
        return tracer

    @contextmanager
    def connect_client(self, uuid='mock'):
        """
        Connects a fake client that auths with the server. This is used to put
        the session in the session store.
        """
        ws = None
        try:
            ws = create_connection(
                ('ws://%s:%s' % (self.client_host, self.client_port))
                + DEFAULT_ROUTE_FMT.format(uuid=uuid)
            )
            ws.send(fmt_msg('start', '', serial=json.dumps))
            while uuid not in self.server.session_store:
                pass
            yield ws
        finally:
            if ws:
                ws.close()

    def test_connect(self):
        """
        Tests that the remote command manager can connect to the server.
        """
        tracer = self.MockTracer()
        # If we fail to connect, an error is raised and we fail the test.
        self.cmd_manager(tracer)

    def test_fail_to_connect(self):
        """
        Assert that the correct error is raised if we cannot connect.
        """
        tracer = self.MockTracer()
        tracer.address = 'not' + self.tracer_host, 0
        with self.assertRaises(QdbFailedToConnect):
            self.cmd_manager(tracer).start('')

    def test_fail_auth(self):
        """
        Asserts that failing auth gives us the proper error.
        """
        tracer = self.MockTracer()
        with self.assertRaises(QdbAuthenticationError):
            cmd_manager = self.cmd_manager(tracer)
            cmd_manager.start(self.bad_auth_msg)
            cmd_manager.next_command()

    @parameterized.expand([
        (lambda t: t.set_step, 'step'),
        (lambda t: t.set_next, 'next'),
        (lambda t: t.set_continue, 'continue'),
        (lambda t: t.set_return, 'return'),
        (lambda t: t.set_break, 'set_break', {
            'file': fix_filename(__file__),
            'line': 1
        }),
        (lambda t: t.clear_break, 'clear_break', {
            'file': fix_filename(__file__),
            'line': 1
        }),
        (lambda t: t.set_watch, 'set_watch', ['2 + 2']),
        (lambda t: t.clear_watch, 'clear_watch', ['2 + 2']),
        (lambda t: t.get_file, 'list'),
        (lambda t: t.eval_fn, 'eval' '2 + 2'),
        (lambda t: t.disable, 'disable', 'hard'),
        (lambda t: t.disable, 'disable', 'soft'),
    ])
    def test_commands(self, attrgetter, event, payload=None):
        """
        Tests various commands with or without payloads.
        """
        tracer = self.MockTracer()
        cmd_manager = self.cmd_manager(tracer)
        tracer.cmd_manager = cmd_manager
        cmd_manager.start('')
        with self.connect_client():
            self.server.session_store.send_to_tracer(
                uuid=tracer.uuid,
                event=fmt_msg(event, payload)
            )
            with Timeout(0.1, False):
                cmd_manager.next_command()
            tracer.start.assert_called()  # Start always gets called.
            attrgetter(tracer).assert_called()

        # Kill the session we just created
        self.server.session_store.slaughter(tracer.uuid)

    def test_pause(self):
        """
        Asserts that sending a pause to the process will pause us.
        """
        tracer = self.MockTracer()
        cmd_manager = self.cmd_manager(tracer)
        tracer.cmd_manager = cmd_manager
        cmd_manager.start('')
        with self.connect_client():
            self.server.session_store.send_to_tracer(
                uuid='mock',
                event=fmt_msg('pause')
            )
            # Pausing should call set_step internally.
            tracer.set_step.assert_called()


class ServerLocalCommandManagerTester(RemoteCommandManagerTester):
    @classmethod
    def setUpClass(cls):
        cls.bad_auth_msg = 'BAD-AUTH'
        cls.tracer_host = cls.client_host = 'localhost'
        cls.tracer_port = 6789
        cls.client_port = 6790
        cls.server = QdbServer(
            tracer_host=cls.tracer_host,
            tracer_port=cls.tracer_port,
            client_host=cls.client_host,
            client_port=cls.client_port,
            tracer_auth_fn=lambda a: a != cls.bad_auth_msg,
        )
        cls.server.start()
        cls.cmd_manager = ServerLocalCommandManager
