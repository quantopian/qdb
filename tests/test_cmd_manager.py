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
from pprint import pformat
import signal
import sys
from time import sleep
from unittest import TestCase

from nose_parameterized import parameterized

from qdb import Qdb
from qdb.comm import RemoteCommandManager, ServerLocalCommandManager, fmt_msg
from qdb.compat import with_metaclass, PY2, gevent
from qdb.errors import (
    QdbFailedToConnect,
    QdbAuthenticationError,
    QdbExecutionTimeout,
)

if PY2:
    from qdb.server import QdbServer

from tests import fix_filename
from tests.compat import Py2TestMeta, mock

patch = mock.patch
MagicMock = mock.MagicMock


def set_break_params(tracer, filename, lineno, temporary=False, cond=None,
                     funcname=None, **kwargs):
    """
    Formats the parameters for set_break.
    """
    filename = filename or tracer.default_file
    return {
        'filename': filename,
        'lineno': lineno,
        'temporary': temporary,
        'cond': cond,
        'funcname': funcname
    }


class RemoteCommandManagerTester(with_metaclass(Py2TestMeta, TestCase)):
    """
    Tests the various behaviors that the RemoteCommandManager should conform
    to. Some tests rely on how the command manager affects the tracer that it
    is managing.
    """
    @classmethod
    def setUpClass(cls):
        """
        Start up a tracer server for the remote command managers to connect to.
        """
        cls.setup_server()
        cls.cmd_manager = RemoteCommandManager

    @classmethod
    def setup_server(cls):
        """
        Sets up the server to run on a random yet valid port.
        """
        cls.bad_auth_msg = 'BAD-AUTH'
        cls.tracer_host = cls.client_host = 'localhost'
        cls.server = QdbServer(
            tracer_host=cls.tracer_host,
            tracer_port=0,
            client_host=cls.client_host,
            client_port=0,
            tracer_auth_fn=lambda a: a != cls.bad_auth_msg,
            attach_timeout=0,
        )
        cls.server.start()
        cls.tracer_port = cls.server.tracer_server.server_port

    @classmethod
    def tearDownClass(cls):
        """
        Stop the test server.
        """
        cls.server.stop()

    def tearDown(self):
        if Qdb._instance:
            Qdb._instance.disable()

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
        tracer.skip_fn = lambda _: False
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
        tracer.address = 'not' + self.tracer_host, self.tracer_port
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
        ({'file': 'test.py', 'line': 2},),
        ({'line': 2},),
        ({'line': 2, 'cond': '2 + 2 == 4'},),
        ({'line': 2, 'func': 'f'},),
        ({'line': 2, 'file': 't.py', 'cond': 'f()', 'func': 'g'},)
    ])
    def test_fmt_breakpoint_dict(self, arg_dict):
        tracer = self.MockTracer()
        tracer.default_file = 'd.py'
        cmd_manager = self.cmd_manager(tracer)
        cpy = dict(arg_dict)
        self.assertEqual(
            cmd_manager.fmt_breakpoint_dict(cpy),
            set_break_params(tracer, **cpy)
        )

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
        with gevent.Timeout(0.1, False):
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

        with gevent.Timeout(0.1, False):
            cmd_manager.next_command()
        self.assertTrue(command_locals_called[0])

        tracer.start.assert_called()  # Start always gets called.
        self.server.session_store.slaughter(tracer.uuid)

    @parameterized.expand([('up',), ('down',)])
    def test_stack_transpose_no_skip(self, direction):
        """
        Tests moving up the stack.
        """
        events = []

        def capture_event(self, event, payload):
            events.append(fmt_msg(event, payload))

        class cmd_manager(self.cmd_manager):
            """
            Wrap send_stack by just capturing the output to make assertions on
            it.
            """
            def send_stack(self):
                with patch.object(cmd_manager, 'send_event', capture_event):
                    super(cmd_manager, self).send_stack()

        db = Qdb(
            uuid='test_' + direction,
            cmd_manager=cmd_manager,
            host=self.tracer_host,
            port=self.tracer_port,
            redirect_output=False,
            green=True,
        )
        sleep(0.01)
        if direction == 'down':
            # We are already located in the bottom frame, let's go up one
            # so that we may try going down.
            self.server.session_store.send_to_tracer(
                uuid=db.uuid,
                event=fmt_msg('up')
            )

        self.server.session_store.send_to_tracer(
            uuid=db.uuid,
            event=fmt_msg(direction)
        )
        self.server.session_store.send_to_tracer(
            uuid=db.uuid,
            event=fmt_msg('disable', 'soft')
        )
        sleep(0.01)
        db.set_trace()

        start_ind = events[-2]['p']['index']
        shift_ind = events[-1]['p']['index']

        if direction == 'up':
            self.assertEqual(start_ind - shift_ind, 1)
        elif direction == 'down':
            self.assertEqual(shift_ind - start_ind, 1)
        else:
            self.fail("direction is not 'up' or 'down'")  # wut did u do?

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
            green=True,
        )
        signal.signal(db.pause_signal, pause_handler)
        self.server.session_store.send_to_tracer(
            uuid=db.uuid,
            event=fmt_msg('pause')
        )

        self.assertTrue(pause_called)

    @parameterized.expand([
        ('2 + 2', None, '4'),
        ('print "test"', None, 'test'),
        ('ValueError("test")', None, "ValueError('test',)"),
        ('raise ValueError("test")', 'ValueError', 'ValueError: test'),
        ('[][10]', 'IndexError', 'IndexError: list index out of range'),
        ('{}["test"]', 'KeyError', "KeyError: 'test'"),
    ])
    def test_eval_results(self, input_, exc, output):
        """
        Tests that evaling code returns the proper results.
        """
        prints = []

        class cmd_manager(self.cmd_manager):
            """
            Captures print commands to make assertions on them.
            """
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
            green=True,
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

    @parameterized.expand([
        ('2 + 2', None, '4'),
        ('print "test"', None, 'test'),
        ('ValueError("test")', None, "ValueError('test',)"),
        ('raise ValueError("test")', 'ValueError', 'ValueError: test'),
        ('[][10]', 'IndexError', 'IndexError: list index out of range'),
        ('{}["test"]', 'KeyError', "KeyError: 'test'"),
        ('(1,) * 30', None, pformat((1,) * 30)),
        ('set(range(30))', None, pformat(set(range(30)))),
    ])
    def test_eval_pprint(self, input_, exc, output):
        """
        Tests that evaling code returns the proper results.
        """
        prints = []

        class cmd_manager(self.cmd_manager):
            """
            Captures print commands to make assertions on them.
            """
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
            event=fmt_msg('pprint', input_)
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
            green=True,
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

    def test_eval_timeout(self):
        """
        Tests that evaluating user repl commands will raise Timeouts.
        """
        def g():
            while True:
                pass

        prints = []

        class cmd_manager(self.cmd_manager):
            """
            Captures print commands to make assertions on them.
            """
            def send_print(self, input_, exc, output):
                prints.append({
                    'input': input_,
                    'exc': exc,
                    'output': output
                })

        to_eval = 'g()'

        db = Qdb(
            uuid='timeout_test',
            cmd_manager=cmd_manager,
            host=self.tracer_host,
            port=self.tracer_port,
            redirect_output=False,
            execution_timeout=1,
            green=True,
        )
        sleep(0.01)
        self.server.session_store.send_to_tracer(
            uuid=db.uuid,
            event=fmt_msg('eval', to_eval)
        )
        self.server.session_store.send_to_tracer(
            uuid=db.uuid,
            event=fmt_msg('continue')
        )
        db.set_trace(stop=True)
        self.server.session_store.slaughter(db.uuid)

        self.assertTrue(prints)
        print_ = prints[0]

        self.assertEqual(print_['input'], to_eval)
        self.assertTrue(print_['exc'])
        self.assertEqual(
            print_['output'],
            db.exception_serializer(QdbExecutionTimeout(to_eval, 1))
        )

    def test_send_disabled(self):
        """
        Tests that disabling sends a 'disabled' message back to the server.
        """
        class cmd_manager(self.cmd_manager):
            disabled = False

            def send_disabled(self):
                self.disabled = True

        db = Qdb(
            uuid='send_disabled_test',
            cmd_manager=cmd_manager,
            host=self.tracer_host,
            port=self.tracer_port,
            redirect_output=False,
            green=True,
        )
        sleep(0.01)
        db.set_trace(stop=False)
        db.disable()

        self.assertTrue(db.cmd_manager.disabled)
        self.server.session_store.slaughter(db.uuid)

    @parameterized.expand([(False,), (True,)])
    def test_send_stack_results(self, use_skip_fn):
        """
        Tests that the results from sending the stack are accurate.
        WARNING: This test uses lines of it's own source as string literals,
        be sure to edit the source and the string if you make any changes.
        """
        def skip_fn(filename):
            return not fix_filename(__file__) in filename

        events = []

        def capture_event(self, event, payload):
            events.append(fmt_msg(event, payload))

        class cmd_manager(self.cmd_manager):
            """
            Wrap send_stack by just capturing the output to make assertions on
            it.
            """
            def send_stack(self):
                with patch.object(cmd_manager, 'send_event', capture_event):
                    super(cmd_manager, self).send_stack()

        db = Qdb(
            uuid='send_stack_test',
            cmd_manager=cmd_manager,
            host=self.tracer_host,
            port=self.tracer_port,
            redirect_output=False,
            skip_fn=skip_fn if use_skip_fn else None,
            green=True,
        )
        sleep(0.01)
        self.server.session_store.send_to_tracer(
            uuid=db.uuid,
            event=fmt_msg('continue')
        )
        db.set_trace(stop=True)
        self.assertTrue(events)  # EDIT IN BOTH PLACES

        event = events[0]
        if use_skip_fn:
            # Assert that we actually suppressed some frames.
            self.assertTrue(len(event['p']['stack']) < len(db.stack))

        self.assertEqual(
            # I love dictionaries so much!
            event['p']['stack'][event['p']['index']]['code'],
            '        self.assertTrue(events)  # EDIT IN BOTH PLACES',
        )

        self.server.session_store.slaughter(db.uuid)


class ServerLocalCommandManagerTester(RemoteCommandManagerTester):
    """
    Subclass of RemoteCommandManagerTester that runs the same tests with
    the ServerLocalCommandManager. This makes sure that the same behavior holds
    for the two types of command managers.
    """
    @classmethod
    def setUpClass(cls):
        cls.setup_server()
        cls.cmd_manager = ServerLocalCommandManager
