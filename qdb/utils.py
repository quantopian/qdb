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
import signal

from qdb.errors import QdbError


class QdbTimeout(QdbError):
    """
    A timer implemented with signals.
    Example useages:
        with QdbTimeout(timeout_in_seconds):
            time_consuming_function()

    or:

        t = QdbTimeout(timeout_in_seconds, True):
        t.start()
        try:
            time_consuming_function()
        except QdbTimeout as u:
            if t is u:
                cleanup()
    """
    def __init__(self, seconds, exception=None, timer_signal=None):
        """
        seconds is the number of seconds to run this Timeout for.
        exception is the exception to raise in the case of a timeout.
        If exception is None, no exception is raised, if exception is True,
        raise this object. Otherwise, raise the exception given.
        timer_signal is the signal to raise to signal a timeout.
        If timer_signal is None, raise a SIGALRM.
        """
        self._exception = exception
        self.seconds = seconds
        self.signal = timer_signal or signal.SIGALRM
        self._running = False

    def _signal_handler(self, signum, stackframe):
        """
        The signal handler that will be used to raise the timeout excpetion.
        """
        if signum == self.signal and self._running:
            if self._exception is True or self._exception is None:
                raise self
            raise self._exception

    def start(self):
        """
        Starts the timer.
        """
        self._running = True
        signal.signal(self.signal, self._signal_handler)
        signal.alarm(self.seconds)

    def stop(self):
        """
        Stops the timer
        """
        self._running = False
        signal.alarm(0)  # Cancel the alarm.

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.stop()
        if exc_value is self and self._exception is None:
            return True

    def __str__(self):
        return 'Timed out after %s seconds' % self.seconds

    def __repr__(self):
        return 'QdbTimeout(seconds=%s, exception=%s, timer_signal=%)' \
            % (self.seconds, self.exception, self.signal)
