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
import signal as signal_module

import gevent

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
    def __init__(self, seconds, exception=None, signal=None):
        """
        seconds is the number of seconds to run this Timeout for.
        exception is the exception to raise in the case of a timeout.
        When exception is ommited or None, the QdbTimeout itself is raised.
        signal is the signal to raise in the case of a timeout, this defaults
        to SIGALRM.
        """
        if not isinstance(seconds, int):
            raise ValueError('integer argument expected, got %s'
                             % type(seconds).__name__)

        self._exception = exception
        self._existing_handler = None
        self.seconds = seconds
        self.signal = signal or signal_module.SIGALRM
        self._running = False

    def _signal_handler(self, signum, stackframe):
        """
        The signal handler that will be used to raise the timeout excpetion.
        """
        if self._running:
            # Restore the orignal handler in case it times out.
            signal_module.signal(self.signal, self._existing_handler)
            if not self._exception:
                raise self
            raise self._exception

    def start(self):
        """
        Starts the timer.
        """
        self._existing_handler = signal_module.getsignal(self.signal)
        signal_module.signal(self.signal, self._signal_handler)
        self._running = True
        signal_module.alarm(self.seconds)

    def cancel(self):
        """
        Cancels the timer
        """
        self._running = False
        signal_module.alarm(0)  # Cancel the alarm.
        # Restore the original handler in case the user cancels.
        signal_module.signal(self.signal, self._existing_handler)

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


class _TimeoutMagic(tuple):
    """
    _TimeoutMagic is really just a tuple that can be called to get a new
    Timeout that is either gevented or not.
    """
    def __call__(self, seconds, exception=None, green=False, signal=None):
        """
        A timeout smart constructor that returns a gevent.Timeout or a
        QdbTimeout.
        """
        if green and signal:
            raise ValueError(
                'Timeout cannnot both be green=True and have a signal'
            )

        if green:
            timeout = gevent.Timeout(seconds, exception)
        else:
            timeout = QdbTimeout(seconds, exception, signal)

        return timeout


# The way this works is that in an except block, if you pass a tuple of
# exceptions, it will compare the exception to each of the exceptions in the
# tuple. Therefore, if you write:
#
# except Timeout:
#
# You can think of it as expanding to:
#
# except (gevent.Timeout, QdbTimeout):
#
# Also, because the __call__ has been overridden, you can get the proper
# timeout by calling:
#
# Timeout(seconds, green=is_green)
#
# Timeout is capitalized because in almost all use cases you can think of
# this as a class, even though there is a little more going on.
Timeout = _TimeoutMagic([gevent.Timeout, QdbTimeout])
