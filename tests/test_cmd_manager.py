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
from functools import partial
import signal
import sys
from unittest import TestCase

from gevent import Timeout, sleep
from mock import MagicMock
from nose_parameterized import parameterized

from qdb import Qdb
from qdb.comm import RemoteCommandManager, ServerLocalCommandManager, fmt_msg
from qdb.errors import (
    QdbFailedToConnect,
    QdbAuthenticationError,
)
from qdb.server import QdbServer

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
            attach_timeout=0,
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
        tracer = MagicMock()
        tracer.address = self.tracer_host, self.tracer_port
        tracer.pause_signal = signal.SIGUSR2
        tracer.retry_attepts = 1
        tracer.local = 0, 0
        tracer.uuid = 'mock'
        tracer.watchlist = {}
        tracer.curframe = sys._getframe()
        tracer.stack = [(sys._getframe(), 1)] * 3
        return tracer

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
    def test_commands(self, attrgetter_, event, payload=None):
        """
        Tests various commands with or without payloads.
        """
        tracer = self.MockTracer()
        cmd_manager = self.cmd_manager(tracer)
        tracer.cmd_manager = cmd_manager
        cmd_manager.start('')
        self.server.session_store.send_to_tracer(
            uuid=tracer.uuid,
            event=fmt_msg(event, payload)
        )
        with Timeout(0.1, False):
            cmd_manager.next_command()
        tracer.start.assert_called()  # Start always gets called.
        attrgetter_(tracer).assert_called()
        # Kill the session we just created
        self.server.session_store.slaughter(tracer.uuid)

    def test_locals(self):
        """
        Tests accessing the locals.
        """
        command_locals_called = [False]

        def test_command_locals(cmd_manager, payload):
            command_locals_called[0] = True
            self.cmd_manager.command_locals(cmd_manager, payload)

        tracer = self.MockTracer()
        tracer.curframe_locals = {'a': 'a'}
        cmd_manager = self.cmd_manager(tracer)
        cmd_manager.command_locals = partial(test_command_locals, cmd_manager)
        tracer.cmd_manager = cmd_manager
        cmd_manager.start('')
        sleep(0.01)
        self.server.session_store.send_to_tracer(
            uuid=tracer.uuid,
            event=fmt_msg('locals')
        )

        with Timeout(0.1, False):
            cmd_manager.next_command()
        self.assertTrue(command_locals_called[0])

        tracer.start.assert_called()  # Start always gets called.
        self.server.session_store.slaughter(tracer.uuid)

    def test_up(self):
        """
        Tests moving up the stack.
        """
        tracer = self.MockTracer()
        tracer.curindex = 1
        cmd_manager = self.cmd_manager(tracer)
        tracer.cmd_manager = cmd_manager
        cmd_manager.start('')
        sleep(0.01)
        self.server.session_store.send_to_tracer(
            uuid=tracer.uuid,
            event=fmt_msg('up')
        )
        with Timeout(0.1, False):
            cmd_manager.next_command()
        tracer.start.assert_called()  # Start always gets called.
        self.assertEqual(tracer.curindex, 0)  # Did we move up?
        self.server.session_store.slaughter(tracer.uuid)

    def test_down(self):
        """
        Tests moving downx the stack.
        """
        tracer = self.MockTracer()
        tracer.curindex = 1
        cmd_manager = self.cmd_manager(tracer)
        tracer.cmd_manager = cmd_manager
        cmd_manager.start('')
        sleep(0.01)
        self.server.session_store.send_to_tracer(
            uuid=tracer.uuid,
            event=fmt_msg('down')
        )
        with Timeout(0.1, False):
            cmd_manager.next_command()
        tracer.start.assert_called()  # Start always gets called.
        self.assertEqual(tracer.curindex, 2)  # Did we move up?
        self.server.session_store.slaughter(tracer.uuid)

    def test_pause(self):
        """
        Asserts that sending a pause to the process will raise the pause signal
        in the tracer process.
        """
        pause_called = [False]

        def pause_handler(signal, stackframe):
            """
            Pause handler that marks that we made it into this function.
            """
            pause_called[0] = True

        db = Qdb(
            cmd_manager=self.cmd_manager,
            host=self.tracer_host,
            port=self.tracer_port,
        )
        signal.signal(db.pause_signal, pause_handler)
        self.server.session_store.send_to_tracer(
            uuid=db.uuid,
            event=fmt_msg('pause')
        )

        self.assertTrue(pause_called)

    @parameterized.expand([
        ('2 + 2', False, '4'),
        ('print "test"', False, 'test'),
        ('ValueError("test")', False, "ValueError('test',)"),
        ('raise ValueError("test")', True, 'ValueError: test'),
        ('[][10]', True, 'IndexError: list index out of range'),
        ('{}["test"]', True, "KeyError: 'test'"),
    ])
    def test_eval_results(self, input_, exc, output):
        """
        Tests that evaling code returns the proper results.
        """
        prints = []

        class cmd_manager(self.cmd_manager):
            def send_print(self, input_, exc, output):
                prints.append({
                    'input': input_,
                    'exc': exc,
                    'output': output
                })

        db = Qdb(
            uuid='eval_test',
            cmd_manager=cmd_manager,
            host=self.tracer_host,
            port=self.tracer_port,
            redirect_output=False,
        )
        sleep(0.01)
        self.server.session_store.send_to_tracer(
            uuid=db.uuid,
            event=fmt_msg('eval', input_)
        )
        self.server.session_store.send_to_tracer(
            uuid=db.uuid,
            event=fmt_msg('continue')
        )
        db.set_trace(stop=True)
        self.server.session_store.slaughter(db.uuid)

        self.assertTrue(prints)
        print_ = prints[0]

        self.assertEqual(print_['input'], input_)
        self.assertEqual(print_['exc'], exc)
        self.assertEqual(print_['output'], output)

    def test_eval_state_update(self):
        """
        Tests that eval may update the state of the program.
        """
        # We will try to corrupt this variable with a stateful operation.
        test_var = 'pure'  # NOQA

        db = Qdb(
            uuid='eval_test',
            cmd_manager=self.cmd_manager,
            host=self.tracer_host,
            port=self.tracer_port,
            redirect_output=False,
        )
        sleep(0.01)
        self.server.session_store.send_to_tracer(
            uuid=db.uuid,
            event=fmt_msg('eval', "test_var = 'mutated'")
        )
        self.server.session_store.send_to_tracer(
            uuid=db.uuid,
            event=fmt_msg('continue')
        )
        db.set_trace(stop=True)
        self.server.session_store.slaughter(db.uuid)

        self.assertEqual(test_var, 'mutated')


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
            attach_timeout=0,
        )
        cls.server.start()
        cls.cmd_manager = ServerLocalCommandManager
