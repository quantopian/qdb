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
from abc import ABCMeta, abstractmethod

from qdb.compat import with_metaclass


class WriteOnlyFileLike(with_metaclass(ABCMeta)):
    def read(self, size=None):
        # completeness of file-like object
        raise IOError('%s object is write only' % self.__class__.__name__)
    readline = read
    readlines = read

    def seek(self, offset, whence=None):
        # completeness of file-like object
        raise IOError('%s object cannot seek' % self.__class__.__name__)

    @property
    def mode(self):
        return 'w'

    def isatty(self):
        return False

    @abstractmethod
    def write(self, msg):
        raise NotImplementedError('write')

    def writelines(self, msgs):
        for msg in msgs:
            self.write(msg)


class RemoteOutput(WriteOnlyFileLike):
    """
    An object that reprents an output stream to the server.
    This object implements a write only file-like object protocol.
    """
    def __init__(self, cmd_manager, name='<stdout>'):
        self._cmd_manager = cmd_manager
        self._name = name
        self._closed = False

    @property
    def name(self):
        return self._name

    def write(self, msg):
        if self._closed:
            raise ValueError('%s object was closed' % self.__class__.__name__)

        self._cmd_manager.send_print(self._name, False, msg)

    def flush(self):
        pass

    def close(self):
        self._closed = True

    @property
    def closed(self):
        return self._closed

    def tell(self):
        # completeness of file-like object
        raise IOError('%s object cannot tell' % self.__class__.__name__)


class OutputTee(WriteOnlyFileLike):
    def __init__(self, first, second):
        self._first = first
        self._second = second

    def close(self):
        self._first.close()
        self._second.close()

    def flush(self):
        self._first.flush()
        self._second.flush()

    def write(self, msg):
        """
        In order to send output to both sys.stdout and the client, we must
        use our custom OutputTee object.

        Note to users:
          You might have been put here by stepping into a print statement
          which will call sys.stdout.write internally. You may feel free
          to return from this function as it is qdb code.
        """
        self._first.write(msg)
        self._second.write(msg)

    def writelines(self, msgs):
        self._first.writelines(msgs)
        self._second.writelines(msgs)

    def __getattr__(self, name):
        """
        Other than the methods we have explicitly overridden, all other methods
        should get sent to the first stream.
        """
        return getattr(self._first, name)
