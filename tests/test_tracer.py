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
from unittest import TestCase

import gevent
from gevent import Timeout
from gevent.queue import Queue, Empty
from mock import patch

from qdb import Qdb
from qdb.comm import CommandManager, NopCommandManager

from tests import fix_filename


def global_fn():
    """
    A test global function.
    """
    return 'global_fn'

# A global variable used in the watchlist.
global_var = 'global_var'


class QueueCommandManager(CommandManager):
    """
    A command manager that takes a queue of functions that act on
    the tracer and apply them one at a time with each call to next_command().
    """
    def __init__(self, tracer):
        super(QueueCommandManager, self).__init__(tracer)
        self.queue = Queue()
        self.sent = []

    def enqueue(self, fn):
        """
        Enqueues a new message to be consumed.
        """
        self.queue.put(fn)

    def user_wait(self, duration):
        """
        Simulates waiting on the user to feed us input for duration seconds.
        """
        self.enqueue(lambda t: gevent.sleep(duration))

    def clear(self):
        """
        Clears the internal list of functions.
        """
        self.queue = Queue()

    def user_next_command(self):
        """
        Removes one message from the internal queue and apply it to the
        debugger.
        """
        try:
            self.queue.get_nowait()(self.tracer)
        except Empty:
            return

    def send(self, msg):
        # Collect the output so that we can make assertions about it.
        self.sent.append(msg)

    stop = clear

    def start(self, auth_msg=''):
        pass


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

    def test_as_ctx_mgr(self):
        """
        Tests the debugger as a context manager.
        """
        line_1 = False
        cmd_stop = None
        with patch.object(NopCommandManager, 'start') as cmd_start, \
                patch.object(NopCommandManager, 'stop') as cmd_stop_scoped, \
                Qdb(cmd_manager=NopCommandManager) as db:
            cmd_stop = cmd_stop_scoped
            cmd_start.assert_called_once_with('')
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

    def test_set_step(self):
        """
        Tests the functionality of set_step by asserting that it only executes
        the next line and no more.
        """
        db = Qdb(cmd_manager=QueueCommandManager)

        # Queue up a step command.
        db.cmd_manager.enqueue(lambda t: t.set_step())

        stepped = False
        with Timeout(0.1, False):
            db.set_trace()
            stepped = True

        self.assertTrue(stepped)

        db.disable()

        db = Qdb(cmd_manager=QueueCommandManager)

        db.cmd_manager.enqueue(lambda t: t.set_step())
        db.cmd_manager.user_wait(0.2)

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
        db = Qdb(cmd_manager=QueueCommandManager)

        # Queue up a next command to next over the function call.
        db.cmd_manager.enqueue(lambda t: t.set_next(t.curframe))
        # Queue up a sleep so that we block after calling next.
        # This would cause us to NOT execute the f_called[0] = True line of f
        # had we only called set_step. This is asserted afterwards.
        db.cmd_manager.user_wait(0.2)

        # A mutable structure to check if f is called.
        f_called = [False]

        def f():
            f_called[0] = True

        with Timeout(0.1, False):
            db.set_trace()
            f()

        # We hit that line in f, so it should now be True.
        self.assertTrue(f_called[0])

        # Assert that we are currently executing the line we think we should
        # be executing. Since we are just stepping, this should be setting
        # curframe each time.
        self.assertEqual(
            db.get_line(self.filename, db.curframe.f_lineno),
            '            db.get_line(self.filename, db.curframe.f_lineno),'
        )

        db.disable()
        db = Qdb(cmd_manager=QueueCommandManager)

        f_called[0] = False

        # This time we will be only stepping, so we should not execute the
        # entire call to f.
        db.cmd_manager.enqueue(lambda t: t.set_step())
        db.cmd_manager.user_wait(0.2)

        with Timeout(0.1, False):
            db.set_trace()
            f()

        # We should not have hit this line in f.
        self.assertFalse(f_called[0])
        # Since we only stepped once, this is the last time we set the frame.
        self.assertEqual(
            db.get_line(self.filename, db.curframe.f_lineno),
            '            f_called[0] = True'
        )

    def test_set_continue_no_breaks(self):
        """
        Asserts that set_continue works with no breakpoints.
        """
        db = Qdb(cmd_manager=QueueCommandManager)

        db.cmd_manager.enqueue(lambda t: t.set_continue())
        db.cmd_manager.user_wait(0.2)

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
        db = Qdb(cmd_manager=QueueCommandManager)
        line_offset = 8  # The difference in the set_break call and line_2.
        db.set_break(
            self.filename,
            sys._getframe().f_lineno + line_offset,
        )
        db.cmd_manager.enqueue(lambda t: t.set_continue())
        db.cmd_manager.user_wait(0.2)
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
        db = Qdb(cmd_manager=QueueCommandManager)
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
        db.cmd_manager.enqueue(lambda t: t.set_continue())
        db.cmd_manager.enqueue(lambda t: t.set_continue())
        db.cmd_manager.user_wait(0.2)
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
        db = Qdb(cmd_manager=QueueCommandManager)
        db.cmd_manager.user_wait(0.2)
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
        db = Qdb(cmd_manager=QueueCommandManager)
        line_offset = 8  # The difference in the set_break call and line_3.
        db.set_break(
            self.filename,
            sys._getframe().f_lineno + line_offset,
        )
        db.cmd_manager.user_wait(0.2)
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

        db = Qdb(cmd_manager=NopCommandManager)
        line_1 = False
        with Timeout(0.1, False):
            db.set_trace(stop=False)
            line_1 = True

        self.assertTrue(line_1)

    def test_watchlist(self):
        """
        Tests the watchlist by evaluating a constant, local function, local
        variable, global function, and global variable.
        """
        db = Qdb(cmd_manager=NopCommandManager)
        db.extend_watchlist(
            '2 + 2',
            'local_var',
            'local_fn()',
            'global_var',
            'global_fn()'
        )

        def new_curframe():
            """
            Test function for checking for NameErrors on the watchlist.
            This changes the curframe of the tracer to eval the watchlist with
            a new set of locals.
            """
            self.assertEqual(db.watchlist['2 + 2'], (False, 4))
            self.assertEqual(
                db.watchlist['local_var'],
                (True, "NameError: name 'local_var' is not defined")
            )
            self.assertEqual(
                db.watchlist['local_fn()'],
                (True, "NameError: name 'local_fn' is not defined")
            )
            self.assertEqual(db.watchlist['global_var'], (False, 'global_var'))
            self.assertEqual(db.watchlist['global_fn()'], (False, 'global_fn'))

        local_var = 'local_var'  # NOQA
        local_fn = lambda: 'local_fn'  # NOQA

        # Set trace and check innitial assertions.
        db.set_trace()
        self.assertEqual(db.watchlist['2 + 2'], (False, 4))
        self.assertEqual(db.watchlist['local_var'], (False, 'local_var'))
        self.assertEqual(db.watchlist['local_fn()'], (False, 'local_fn'))
        self.assertEqual(db.watchlist['global_var'], (False, 'global_var'))
        self.assertEqual(db.watchlist['global_fn()'], (False, 'global_fn'))

        local_var = 'updated_local_var'  # NOQA
        local_fn = lambda: 'updated_local_fn'  # NOQA

        self.assertEqual(db.watchlist['2 + 2'], (False, 4))
        self.assertEqual(db.watchlist['local_var'], (False,
                                                     'updated_local_var'))
        self.assertEqual(db.watchlist['local_fn()'], (False,
                                                      'updated_local_fn'))
        self.assertEqual(db.watchlist['global_var'], (False, 'global_var'))
        self.assertEqual(db.watchlist['global_fn()'], (False, 'global_fn'))

        new_curframe()

    def test_conditional_breakpoint(self):
        """
        Tests conditional breakpoints.
        WARNING: This test relies on the relative line numbers inside the test.
        """
        db = Qdb(cmd_manager=QueueCommandManager)
        loop_counter = 0
        db.cmd_manager.enqueue(lambda t: self.assertEqual(loop_counter, 5))
        line_offset = 5
        db.set_break(
            self.filename,
            sys._getframe().f_lineno + line_offset,
            cond='loop_counter == 5'
        )
        db.set_trace(stop=False)
        while loop_counter < 10:
            loop_counter += 1

    def test_temporary_breakpoint(self):
        """
        Tests conditional breakpoints.
        WARNING: This test relies on the relative line numbers inside the test.
        """
        db = Qdb(cmd_manager=QueueCommandManager)
        db.cmd_manager.enqueue(lambda t: t.set_continue())
        db.cmd_manager.user_wait(0.2)
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
        db = Qdb(cmd_manager=QueueCommandManager)
        clear_break_offset = 14
        set_break_offset = 8
        db.cmd_manager.enqueue(lambda t: t.clear_break(
            self.filename,
            sys._getframe().f_lineno + clear_break_offset
        ))
        db.cmd_manager.enqueue(lambda t: t.set_continue())
        db.cmd_manager.user_wait(0.2)
        db.set_break(
            self.filename,
            sys._getframe().f_lineno + set_break_offset
        )
        db.set_trace(stop=False)

        continued = False
        with Timeout(0.1):
            db.set_trace(stop=False)
            for n in xrange(2):
                pass
            continued = True

        self.assertTrue(continued)

    def test_redirect_stdout(self):
        """
        Tests that stdout is stored on the tracer.
        """
        db = Qdb(cmd_manager=NopCommandManager)

        data_to_write = 'stdout'
        db.set_trace(stop=False)

        print data_to_write,  # Write some data to stdout.

        db.disable()
        self.assertEqual(db.stdout.getvalue(), data_to_write)

    def test_redirect_stderr(self):
        """
        Tests that stderr is stored on the tracer.
        """
        db = Qdb(cmd_manager=NopCommandManager)

        data_to_write = 'stderr'
        db.set_trace(stop=False)

        print >> sys.stderr, data_to_write,  # Write some data to stderr.

        db.disable()
        self.assertEqual(db.stderr.getvalue(), data_to_write)

    def test_clear_output_buffers(self):
        """
        Tests that we can clear the output buffers to free up some memory.
        """

        db = Qdb(cmd_manager=NopCommandManager)
        stdout_data, stderr_data = 'stdout', 'stderr'
        db.set_trace(stop=False)

        print stdout_data,
        print >> sys.stderr, stderr_data,

        db.disable()

        # Assert that the data actually got written.
        self.assertEqual(db.stdout.getvalue(), stdout_data)
        self.assertEqual(db.stderr.getvalue(), stderr_data)

        db.clear_output_buffers()

        # Assert that the data actually got cleared.
        self.assertEqual(db.stdout.getvalue(), '')
        self.assertEqual(db.stderr.getvalue(), '')
