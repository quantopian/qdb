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


class QdbServerBase(object):
    """
    Base class for QdbServers.
    """
    NO_AUTH = staticmethod(lambda _: True)

    @property
    def _extra_repr_args(self):
        return ()

    def __repr__(self):
        if self.auth_fn is self.NO_AUTH:
            # This is what the argument would have been, and is more useful
            # than seeing a lambda here.
            auth = repr(None)
        else:
            fself = getattr(self.auth_fn, '__self__', None)
            if fself is self:
                auth = '<bound method %s.auth_fn of self>' % \
                       self.__class__.__name__
            else:
                auth = repr(self.auth_fn)

        host, port = self.address
        extra = self._extra_repr_args
        if extra:
            extra = ', ' + ', '.join(extra)
        else:
            extra = ''

        return '%s(session_store=%s, host=%s, port=%d, auth_fn=%s,' \
            ' auth_timeout=%d%s)' % (
                self.__class__.__name__,
                repr(self.session_store),
                repr(host),
                port,
                auth,
                self.auth_timeout,
                extra,
            )

    __str__ = __repr__
