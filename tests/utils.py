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
from collections import namedtuple
import json
from time import sleep

from qdb.comm import CommandManager, NopCommandManager
from qdb.compat import PY3

if PY3:
    from queue import Queue, Empty
else:
    from Queue import Queue, Empty


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
        self.enqueue(lambda t: sleep(duration + 1))

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
        self.sent.append(json.loads(msg))

    user_stop = clear

    def start(self, auth_msg=''):
        pass


OutputMessage = namedtuple('OutputMessage', ['input_', 'exc', 'output'])


class OutputCatchingNopCommandManager(NopCommandManager):
    def __init__(self, tracer):
        super(OutputCatchingNopCommandManager, self).__init__(tracer)
        self.msgs = []

    def send_print(self, input_, exc, output):
        self.msgs.append(OutputMessage(input_, exc, output))
