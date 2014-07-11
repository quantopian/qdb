from bdb import BdbQuit
from StringIO import StringIO


class QdbError(Exception):
    """
    Base Qdb error class.
    """
    def __str__(self):
        return 'QdbError'

    def __repr__(self):
        return 'QdbError()'


class QdbQuit(QdbError, BdbQuit):
    """
    Signals that qdb was told to kill the process.
    """
    def __str__(self):
        return 'Quitting'

    def __repr__(self):
        return 'QdbQuit()'


class QdbFailedToConnect(QdbError):
    """
    Error signaling that qdb was unable to connect for some reason.
    """
    def __init__(self, address, retry_attepts):
        self.address = address
        self.retry_attepts = retry_attepts

    def __str__(self):
        return 'Failed to connect to %s after %d retries.' \
            % (self.address, self.retry_attepts)

    def __repr__(self):
        return 'QdbFailedToConnect(%s, %d)'\
            % (self.address, self.retry_attepts)


class QdbUnreachableBreakpoint(QdbError):
    """
    Error signaling that the user attempted to set a breakpoint on a non
    executable line.
    """
    def __init__(self, breakpoint):
        self.breakpoint = breakpoint

    def __str__(self):
        pp = StringIO()
        self.breakpoint.bpprint(pp)
        string = 'Failed to set ' + pp.getvalue()
        pp.close()
        return string

    def __repr__(self):
        return 'QdbUnreachableBreakpoint(%s)' % repr(self.breakpoint)


class QdbTopFrame(QdbError):
    """
    Signals that we tried to step up when we were in the top frame.
    """
    def __str__(self):
        return 'Already in the top frame'

    def __repr__(self):
        return 'QdbTopFrame()'


class QdbBreakpointReadError(QdbError):
    """
    Signals that we failed to read a breakpoint for some reason.
    """
    def __init__(self, serial_data):
        self.serial_data = serial_data

    def __str__(self):
        return 'Could not read Breakpoint from %s' % self.serial_data

    def __repr__(self):
        return 'QdbBreakpointReadError(%s)' % self.serial_data


class QdbReceivedInvalidLength(QdbError):
    """
    Signals that the length data is invalid.
    """
    def __init__(self, length):
        self.length = length

    def __str__(self):
        return str(self.length)

    def __repr__(self):
        return 'QdbReceivedInvalidLength(%s)' % self.length


class QdbCommunicationError(QdbError):
    """
    Signals that we have lost communication with the server.
    """
    def __init__(self, exception):
        self.exception = exception

    def __str__(self):
        return str(self.exception)

    def __repr__(self):
        return 'QdbCommunicationError(%s)' % repr(self.exception)


class QdbInvalidRoute(QdbError):
    """
    Signals that the route does not match the route format.
    """
    def __init__(self, route):
        self.route = route

    def __str__(self):
        return self.route

    def __repr__(self):
        return 'QdbInvalidRoute(%s)' % self.route
