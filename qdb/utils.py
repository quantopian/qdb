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

import gevent

from qdb.errors import QdbError


def Timeout(seconds, exception=None, green=False, timer_signal=None):
    """
    A timeout smart constructor that returns a gevent.Timeout or a QdbTimeout.
    """
    if green:
        return gevent.Timeout(seconds, exception)
    return QdbTimeout(seconds, exception, timer_signal)


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
        When exception is ommited or None, the QdbTimeout itself is raised.
        timer_signal is the signal to raise in the case of a timeout, this
        defaults to SIGALRM.
        """
        if not isinstance(seconds, int):
            raise ValueError('integer argument expected, got %s'
                             % type(seconds).__name__)

        self._exception = exception
        self.seconds = seconds
        self.signal = timer_signal or signal.SIGALRM
        self._running = False

    def _signal_handler(self, signum, stackframe):
        """
        The signal handler that will be used to raise the timeout excpetion.
        """
        if signum == self.signal and self._running:
            if not self._exception:
                raise self
            raise self._exception

    def start(self):
        """
        Starts the timer.
        """
        signal.signal(self.signal, self._signal_handler)
        self._running = True
        signal.alarm(self.seconds)

    def cancel(self):
        """
        Cancels the timer
        """
        self._running = False
        signal.alarm(0)  # Cancel the alarm.

    @property
    def pending(self):
        """
        Read only access to the internal running state.
        """
        return self._running

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.cancel()
        if exc_value is self and self._exception is False:
            return True

    def __str__(self):
        return 'Timed out after %s seconds' % self.seconds

    def __repr__(self):
        return 'QdbTimeout(seconds=%s, exception=%s, timer_signal=%)' \
            % (self.seconds, self.exception, self.signal)
