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
from __future__ import print_function

import sys
from unittest import TestCase

from qdb import Qdb
from qdb.comm import NopCommandManager
from qdb.compat import StringIO
from qdb.errors import QdbExecutionTimeout
from qdb.utils import Timeout

from tests import fix_filename
from tests.utils import QueueCommandManager, OutputCatchingNopCommandManager
from tests.compat import mock, NonLocal, skip_py3

patch = mock.patch


def global_fn():
    """
    A test global function.
    """
    return 'global_fn'

# A global variable used in the watchlist.
global_var = 'global_var'


class TracerTester(TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Saves the filename of this source file.
        """
        cls.filename = fix_filename(__file__)

    def tearDown(self):
        # Stop tracing after each test.
        sys.settrace(None)
        if Qdb._instance:
            Qdb._instance.disable()

    def test_config_and_kwargs_no_merge(self):
        with self.assertRaises(TypeError):
            Qdb(config=True, merge=False, keyword=True)

        Qdb._instance = None

    def test_as_ctx_mgr(self):
        """
        Tests the debugger as a context manager.
        """
        line_1 = False
        cmd_stop = None
        with patch.object(NopCommandManager, 'start') as cmd_start, \
                patch.object(NopCommandManager, 'stop') as cmd_stop, \
                Qdb(cmd_manager=NopCommandManager()) as db:
            db.set_trace()
            cmd_start.assert_called_once_with(db, '')
            line_1 = True
            self.assertTrue(line_1)
            self.assertIs(Qdb._instance, db)
            self.assertEqual(
                db.get_line(
                    self.filename,
                    db.curframe.f_lineno),
                '                    db.curframe.f_lineno),'
            )

        # Assert the __exit__ clears the singleton so a new one can be used.
        self.assertIs(Qdb._instance, None)
        # Assert that __exit__ stopped the command manager.
        cmd_stop.assert_called_once_with()

    def test_is_singleton(self):
        """
        Tests that two newly created Qdb objects are the same.
        """
        self.assertIs(
            Qdb(cmd_manager=NopCommandManager()),
            Qdb(cmd_manager=NopCommandManager())
        )

    def test_set_step(self):
        """
        Tests the functionality of set_step by asserting that it only executes
        the next line and no more.
        """
        cmd_manager = QueueCommandManager()
        db = Qdb(cmd_manager=cmd_manager)

        # Queue up a step command.
        cmd_manager.enqueue(lambda t: t.set_step())

        stepped = False
        with Timeout(0.1, False):
            db.set_trace()
            stepped = True

        self.assertTrue(stepped)

        db.disable()

        cmd_manager = QueueCommandManager()
        db = Qdb(cmd_manager=cmd_manager)

        cmd_manager.enqueue(lambda t: t.set_step())
        cmd_manager.user_wait(0.2)

        stepped = over_stepped = False
        with Timeout(0.1, False):
            db.set_trace()
            stepped = True
            over_stepped = True

        self.assertTrue(stepped)
        self.assertFalse(over_stepped)

    def test_function_call_next_step(self):
        """
        Tests the functionality of next and step when calling functions.
        This checks to make sure the function is stepped into and can be
        stepped over.
        """
        cmd_manager = QueueCommandManager()
        db = Qdb(cmd_manager=cmd_manager)

        # Queue up a next command to next over the function call.
        cmd_manager.enqueue(lambda t: t.set_next(t.curframe))
        # Queue up a sleep so that we block after calling next.
        # This would cause us to NOT execute the f_called[0] = True line of f
        # had we only called set_step. This is asserted afterwards.
        cmd_manager.user_wait(0.2)

        # A mutable structure to check if f is called.
        f_called = NonLocal(False)

        def f():
            f_called.value = True

        with Timeout(0.1, False):
            db.set_trace()
            f()

        # We hit that line in f, so it should now be True.
        self.assertTrue(f_called.value)

        # Assert that we are currently executing the line we think we should
        # be executing. Since we are just stepping, this should be setting
        # curframe each time.
        self.assertEqual(
            db.get_line(self.filename, db.curframe.f_lineno),
            '            db.get_line(self.filename, db.curframe.f_lineno),'
        )

        db.disable()
        cmd_manager = QueueCommandManager()
        db = Qdb(cmd_manager=cmd_manager)

        f_called = NonLocal(False)

        # This time we will be only stepping, so we should not execute the
        # entire call to f.
        cmd_manager.enqueue(lambda t: t.set_step())
        cmd_manager.user_wait(1.2)

        with Timeout(0.1, False):
            db.set_trace()
            f()

        # We should not have hit this line in f.
        self.assertFalse(f_called.value)
        # Since we only stepped once, this is the last time we set the frame.
        self.assertEqual(
            db.get_line(self.filename, db.curframe.f_lineno),
            '            f_called.value = True'
        )

    def test_set_continue_no_breaks(self):
        """
        Asserts that set_continue works with no breakpoints.
        """
        cmd_manager = QueueCommandManager()
        db = Qdb(cmd_manager=cmd_manager)

        cmd_manager.enqueue(lambda t: t.set_continue())
        cmd_manager.user_wait(0.2)

        line_1 = line_2 = line_3 = False
        with Timeout(0.1, False):
            db.set_trace()
            line_1 = True  # EDIT IN BOTH PLACES
            line_2 = True
            line_3 = True

        # Assert that we hit all three lines event though interaction is
        # blocked.
        self.assertTrue(line_1 and line_2 and line_3)
        # As this was the last time we were supposed to stop, this should be
        # the curframe data.
        self.assertEqual(
            db.get_line(self.filename, db.curframe.f_lineno),
            '            line_1 = True  # EDIT IN BOTH PLACES'
        )

    def test_set_continue_with_breaks(self):
        """
        Tests the behavior of continue when there are breakpoints in the mix.
        WARNING: This test relies on the relative line numbers inside the test.
        """
        cmd_manager = QueueCommandManager()
        db = Qdb(cmd_manager=cmd_manager)
        line_offset = 8  # The difference in the set_break call and line_2.
        db.set_break(
            self.filename,
            sys._getframe().f_lineno + line_offset,
        )
        cmd_manager.enqueue(lambda t: t.set_continue())
        cmd_manager.user_wait(0.2)
        line_1 = line_2 = line_3 = False
        with Timeout(0.1, False):
            db.set_trace()
            line_1 = True
            line_2 = True
            line_3 = True

        # Assert we only got to line_1 because of the breakpoint.
        # These are split up to give more helpful messages if the test fails.
        self.assertTrue(line_1)
        self.assertFalse(line_2)
        self.assertFalse(line_3)

        # We are still in stepping mode so we should be reporting the stack.
        self.assertEqual(
            db.get_line(self.filename, db.curframe.f_lineno),
            '            db.get_line(self.filename, db.curframe.f_lineno),'
        )

        sys.settrace(None)
        db.disable()
        cmd_manager = QueueCommandManager()
        db = Qdb(cmd_manager=cmd_manager)
        line_2_offset = 13  # The difference in the set_break call and line_2.
        line_3_offset = 10   # THe difference in the set_break call and line_3.
        db.set_break(
            self.filename,
            sys._getframe().f_lineno + line_2_offset,
        )
        db.set_break(
            self.filename,
            sys._getframe().f_lineno + line_3_offset,
        )
        cmd_manager.enqueue(lambda t: t.set_continue())
        cmd_manager.enqueue(lambda t: t.set_continue())
        cmd_manager.user_wait(0.2)
        line_1 = line_2 = line_3 = False
        with Timeout(0.1, False):
            db.set_trace()
            line_1 = True
            line_2 = True
            line_3 = True

        self.assertTrue(line_1)
        self.assertTrue(line_2)
        self.assertFalse(line_3)

        self.assertEqual(
            db.get_line(self.filename, db.curframe.f_lineno),
            '            db.get_line(self.filename, db.curframe.f_lineno),'
        )

    def test_set_trace_with_stop(self):
        """
        Asserts that calling set_trace will put us into stepping mode.
        """
        cmd_manager = QueueCommandManager()
        db = Qdb(cmd_manager=cmd_manager)
        cmd_manager.user_wait(0.2)
        line_1 = False
        with Timeout(0.1, False):
            db.set_trace()
            line_1 = True  # EDIT IN BOTH PLACES

        # Since we are stepping, we should not hit this line.
        self.assertFalse(line_1)

    def test_set_trace_without_stop(self):
        """
        Asserts that calling set_trace with stop=False will start tracing
        but not stop.
        WARNING: This test relies on the relative line numbers inside the test.
        """
        cmd_manager = QueueCommandManager()
        db = Qdb(cmd_manager=cmd_manager)
        line_offset = 8  # The difference in the set_break call and line_3.
        db.set_break(
            self.filename,
            sys._getframe().f_lineno + line_offset,
        )
        cmd_manager.user_wait(0.2)
        line_1 = line_2 = line_3 = False
        with Timeout(0.1, False):
            db.set_trace(stop=False)  # Should not stop us here.
            line_1 = True
            line_2 = True
            line_3 = True

        # Since we are stepping, we should not hit this line.
        self.assertTrue(line_1)
        self.assertTrue(line_2)
        # We should have still stopped at this breakpoint if we are tracing.
        self.assertFalse(line_3)

        db.disable()

        db = Qdb(cmd_manager=NopCommandManager())
        line_1 = False
        with Timeout(0.1, False):
            db.set_trace(stop=False)
            line_1 = True

        self.assertTrue(line_1)

    @skip_py3
    def test_watchlist(self):
        """
        Tests the watchlist by evaluating a constant, local function, local
        variable, global function, and global variable.
        """
        db = Qdb(cmd_manager=NopCommandManager(), execution_timeout=1)

        too_long_msg = db.exception_serializer(
            QdbExecutionTimeout('too_long()', 1)
        )
        db.extend_watchlist(
            '2 + 2',
            'local_var',
            'local_fn()',
            'global_var',
            'global_fn()',
            'too_long()',
        )

        def new_curframe():
            """
            Test function for checking for NameErrors on the watchlist.
            This changes the curframe of the tracer to eval the watchlist with
            a new set of locals.
            """
            self.assertEqual(db.watchlist['2 + 2'], (None, 4))
            self.assertEqual(
                db.watchlist['local_var'],
                ('NameError', "NameError: name 'local_var' is not defined")
            )
            self.assertEqual(
                db.watchlist['local_fn()'],
                ('NameError', "NameError: name 'local_fn' is not defined")
            )
            self.assertEqual(db.watchlist['global_var'], (None, 'global_var'))
            self.assertEqual(db.watchlist['global_fn()'], (None, 'global_fn'))

        local_var = 'local_var'  # NOQA
        local_fn = lambda: 'local_fn'  # NOQA

        def too_long():
            while True:
                pass

        # Set trace and check innitial assertions.
        db.set_trace()
        self.assertEqual(db.watchlist['2 + 2'], (None, 4))
        self.assertEqual(db.watchlist['local_var'], (None, 'local_var'))
        self.assertEqual(db.watchlist['local_fn()'], (None, 'local_fn'))
        self.assertEqual(db.watchlist['global_var'], (None, 'global_var'))
        self.assertEqual(db.watchlist['global_fn()'], (None, 'global_fn'))

        # Testing this as a tuple causes strange behavior.
        self.assertEqual(db.watchlist['too_long()'][0], 'QdbExecutionTimeout')
        self.assertEqual(db.watchlist['too_long()'][1], too_long_msg)

        local_var = 'updated_local_var'  # NOQA
        local_fn = lambda: 'updated_local_fn'  # NOQA

        self.assertEqual(db.watchlist['2 + 2'], (None, 4))
        self.assertEqual(db.watchlist['local_var'], (None,
                                                     'updated_local_var'))
        self.assertEqual(db.watchlist['local_fn()'], (None,
                                                      'updated_local_fn'))
        self.assertEqual(db.watchlist['global_var'], (None, 'global_var'))
        self.assertEqual(db.watchlist['global_fn()'], (None, 'global_fn'))

        new_curframe()

    def test_conditional_breakpoint(self):
        """
        Tests valid conditional breakpoints.
        WARNING: This test relies on the relative line numbers inside the test.
        """
        cmd_manager = QueueCommandManager()
        db = Qdb(cmd_manager=cmd_manager)
        loop_counter = 0
        cmd_manager.enqueue(lambda t: self.assertEqual(loop_counter, 5))
        line_offset = 5
        db.set_break(
            self.filename,
            sys._getframe().f_lineno + line_offset,
            cond='loop_counter == 5'
        )
        db.set_trace(stop=False)
        while loop_counter < 10:
            loop_counter += 1

    def test_conditional_breakpoint_raises(self):
        """
        Tests conditional breakpoints that raise an exception.
        WARNING: This test relies on the relative line numbers inside the test.
        """
        line = None
        exc = ValueError('lol wut r u doing?')
        cond = 'raiser()'

        stopped = [False]

        def stop():
            stopped[0] = True
            return True  # Execute the assertion.

        cmd_manager = QueueCommandManager()
        db = Qdb(cmd_manager=cmd_manager)
        cmd_manager.enqueue(lambda t: stop() and self.assertEqual(line, 1))
        line_offset = 9
        # Set a condition that will raise a ValueError.
        db.set_break(
            self.filename,
            sys._getframe().f_lineno + line_offset,
            cond=cond,
        )
        db.set_trace(stop=False)

        def raiser():
            raise exc

        line = 1
        line = 2  # This line number is used in the data assertion.
        line = 3

        db.disable()
        errors = [e['p'] for e in cmd_manager.sent if e['e'] == 'error']
        self.assertEqual(len(errors), 1)

        error = errors[0]
        self.assertEqual(error['type'], 'condition')

        negative_line_offset = 13
        self.assertEqual(
            error['data'], {
                'line': sys._getframe().f_lineno - negative_line_offset,
                'cond': cond,
                'exc': type(exc).__name__,
                'output': db.exception_serializer(exc),
            }
        )
        # Make sure we stopped when we raised the exception.
        self.assertTrue(stopped[0])

    def test_conditional_breakpoint_timeout(self):
        """
        Tests conditional breakpoints that cause timeouts.
        WARNING: This test relies on the relative line numbers inside the test.
        """
        stopped = [False]

        def stop():
            stopped[0] = True
            return True  # Execute the assertion.

        line = None
        cond = 'g()'

        cmd_manager = QueueCommandManager()
        db = Qdb(cmd_manager=cmd_manager, execution_timeout=1)
        cmd_manager.enqueue(lambda t: stop() and self.assertEqual(line, 1))
        line_offset = 10
        # Set a condition that will time out.
        db.set_break(
            self.filename,
            sys._getframe().f_lineno + line_offset,
            cond='g()',
        )
        db.set_trace(stop=False)

        def g():
            while True:
                pass

        line = 1
        line = 2
        line = 3

        db.disable()
        errors = [e['p'] for e in cmd_manager.sent if e['e'] == 'error']
        self.assertEqual(len(errors), 1)

        error = errors[0]
        self.assertEqual(error['type'], 'condition')

        negative_line_offset = 14
        exc = QdbExecutionTimeout(cond, db.execution_timeout)
        self.assertEqual(
            error['data'], {
                'line': sys._getframe().f_lineno - negative_line_offset,
                'cond': cond,
                'exc': type(exc).__name__,
                'output': db.exception_serializer(exc),
            }
        )
        # Make sure we stopped when we raised the exception.
        self.assertTrue(stopped[0])

    def test_temporary_breakpoint(self):
        """
        Tests conditional breakpoints.
        WARNING: This test relies on the relative line numbers inside the test.
        """
        cmd_manager = QueueCommandManager()
        db = Qdb(cmd_manager=cmd_manager)
        cmd_manager.enqueue(lambda t: t.set_continue())
        cmd_manager.user_wait(0.2)
        loop_counter = 0
        line_offset = 6
        db.set_break(
            self.filename,
            sys._getframe().f_lineno + line_offset,
            temporary=True,
        )
        with Timeout(0.1, False):
            db.set_trace(stop=False)
            while loop_counter < 10:
                loop_counter += 1

        # By hitting it the first time, we cleared the breakpoint and did not
        # stop there again.
        self.assertEqual(loop_counter, 10)

    def test_clear_break(self):
        """
        Tests clearing a breakpoint.
        WARNING: This test relies on the relative line numbers inside the test.
        """
        cmd_manager = QueueCommandManager()
        db = Qdb(cmd_manager=cmd_manager)
        clear_break_offset = 14
        set_break_offset = 8
        cmd_manager.enqueue(lambda t: t.clear_break(
            self.filename,
            sys._getframe().f_lineno + clear_break_offset
        ))
        cmd_manager.enqueue(lambda t: t.set_continue())
        cmd_manager.user_wait(0.2)
        db.set_break(
            self.filename,
            sys._getframe().f_lineno + set_break_offset
        )
        db.set_trace(stop=False)

        continued = False
        with Timeout(0.1):
            db.set_trace(stop=False)
            for n in range(2):
                pass
            continued = True

        self.assertTrue(continued)

    def test_redirect_stdout(self):
        """
        Tests that stdout is stored on the tracer.
        """
        sys.stdout = stdout = StringIO()
        cmd_manager = OutputCatchingNopCommandManager()
        db = Qdb(cmd_manager=cmd_manager)

        data_to_write = 'stdout'
        db.set_trace(stop=False)

        # Write some data to stdout.
        print(data_to_write, end='')

        db.disable()
        msg = cmd_manager.msgs[0]
        self.assertEqual(msg.input_, '<stdout>')
        self.assertFalse(msg.exc)
        self.assertEqual(msg.output, data_to_write)
        self.assertEqual(stdout.getvalue(), data_to_write)

        # Assert that the stream was restored.
        self.assertIs(sys.stdout, stdout)

    def test_redirect_stderr(self):
        """
        Tests that stderr is stored on the tracer.
        """
        sys.stderr = stderr = StringIO()
        cmd_manager = OutputCatchingNopCommandManager()
        db = Qdb(cmd_manager=cmd_manager)

        data_to_write = 'stderr'
        db.set_trace(stop=False)

        # Write some data to stderr.
        print(data_to_write, end='', file=sys.stderr)

        db.disable()

        msg = cmd_manager.msgs[0]
        self.assertEqual(msg.input_, '<stderr>')
        self.assertFalse(msg.exc)
        self.assertEqual(msg.output, data_to_write)
        self.assertEqual(stderr.getvalue(), data_to_write)

        # Assert that the stream was restored.
        self.assertIs(sys.stderr, stderr)

    def test_inject_default_ns(self):
        """
        Tests adding a default namespace to a frame.
        """
        ns = {'a': 1, 'b': 2}

        # rip pyflakes
        with Qdb(cmd_manager=NopCommandManager(), default_namespace=ns) as db,\
                db.inject_default_namespace(sys._getframe()):
            self.assertEqual(a, 1)  # NOQA
            self.assertEqual(b, 2)  # NOQA

        # Assert that the namespace was cleaned.
        with self.assertRaises(NameError):
            a  # NOQA

        with self.assertRaises(NameError):
            b  # NOQA

    def test_inject_default_ns_curframe(self):
        """
        Tests adding a default namespace to the curframe.
        """
        ns = {'a': 1, 'b': 2}

        # rip pyflakes
        with Qdb(cmd_manager=NopCommandManager(), default_namespace=ns) as db:
            db.curframe = sys._getframe()
            with db.inject_default_namespace():
                self.assertEqual(a, 1)  # NOQA
                self.assertEqual(b, 2)  # NOQA

            with self.assertRaises(NameError):
                a  # NOQA

            with self.assertRaises(NameError):
                b  # NOQA

    def test_inject_default_ns_no_trample(self):
        """
        Tests adding the default namespace does not override a defined name.
        """
        ns = {'a': 1, 'b': 2}

        with Qdb(cmd_manager=NopCommandManager(), default_namespace=ns) as db,\
                db.inject_default_namespace(sys._getframe()):
            a = 'a'
            b = 'b'
            self.assertEqual(a, 'a')
            self.assertEqual(b, 'b')
