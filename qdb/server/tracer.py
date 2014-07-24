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
import os
import socket
from struct import pack, unpack

from gevent import Timeout
from gevent.server import StreamServer
from logbook import Logger

try:
    import cPickle as pickle
except ImportError:
    import pickle

log = Logger('QdbTracerServer')


class AuthenticationFailed(Exception):
    """
    Signals that the authentication failed for some reason.
    """
    def __init__(self, message):
        self.message = message


class QdbTracerServer(StreamServer):
    """
    Listens for qdb tracer connections on a socket, spinning up new client
    connections.
    """
    def __init__(self,
                 session_store,
                 host,
                 port,
                 tracer_auth_fn,
                 auth_timeout):
        self.auth_timeout = auth_timeout
        self.session_store = session_store
        self.tracer_auth_fn = tracer_auth_fn
        super(QdbTracerServer, self).__init__(
            (host, port),
            handle=self.handle_tracer,
        )

    def start(self):
        log.info('Starting qdb.server.tracer')
        super(QdbTracerServer, self).start()

    def stop(self):
        log.info('Stopping qdb.server.tracer')
        super(QdbTracerServer, self).stop()

    def read_events(self, conn):
        """
        Generator that yields the events off the socket while we are running
        and the client is alive.
        """
        while True:
            try:
                rlen = conn.recv(4)
                if len(rlen) != 4:
                    # We did not get a valid length, the stream is corrupt.
                    return
                rlen = unpack('>i', rlen)[0]
                bytes_received = 0
                resp = ''
                with Timeout(1, False):
                    while bytes_received < rlen:
                        resp += conn.recv(rlen - bytes_received)
                        bytes_received = len(resp)

                if bytes_received != rlen:
                    return  # We are not getting bytes anymore.

                resp = pickle.loads(resp)
                resp['e']
            except (socket.error, pickle.UnpicklingError, KeyError):
                return  # It appears something died, kill this now.

            yield resp

    def read_event(self, conn):
        """
        Reads a single message.
        """
        try:
            return next(self.read_events(conn))
        except StopIteration:
            return {}

    def validate_start_event(self, start_event, addr):
        """
        Validates a start_event.
        Returns a tuple with (uuid, local) or raises an exception
        describing the error.
        """
        uuid = None
        local = (0, 0)
        try:
            if start_event['e'] == 'start':
                local = start_event['p']['local']
                uuid = start_event['p']['uuid']
                if not self.tracer_auth_fn(start_event['p'].get('auth', '')):
                    # We failed the authentication check.
                    log.warn('Bad authentication message from (%s, %d)' % addr)
                    raise AuthenticationFailed('Authentication failed')
            else:
                raise AuthenticationFailed(
                    "First event must be of type: 'start'"
                )
        except KeyError as k:
            raise AuthenticationFailed("Missing %s field" % str(k))
        return uuid, local

    def handle_tracer(self, conn, addr):
        """
        Handles new connections from the tracers.
        """
        auth_failed_dict = {
            'e': 'error',
            'p': {
                'type': 'auth',
                'data': '',
                }
        }

        uuid = None
        local_pid, pause_signal = 0, 0
        message = ''

        try:
            start_event = None
            with Timeout(self.auth_timeout, False):
                start_event = self.read_event(conn)
            if not start_event:
                # No start_event was ever recieved because we timed out.
                log.info('No start message was sent from (%s, %d)' % addr)
                message = 'No start event received'
            else:
                try:
                    uuid, local = self.validate_start_event(start_event, addr)
                    local_pid, pause_signal = local
                except AuthenticationFailed as a:
                    message = a.message

            if message:
                # If we have an error, we need to report that back to the
                # trace so that it may raise a QdbAuthenticationError in the
                # user's code.
                auth_failed_dict['p']['data'] = message
                err_msg = pickle.dumps(auth_failed_dict)
                conn.sendall(pack('>i', len(err_msg)))
                conn.sendall(err_msg)
                return

            log.info('Assigning stream from %s to session %s' % (addr, uuid))

            if not self.session_store.attach_tracer(uuid, conn):
                return  # No browser so the attach failed.

            for event in self.read_events(conn):
                # If the tracer is running local to the server, we can avoid
                # starting a reader process to raise the pause signal in the
                # tracer, This event should not get passed along.
                if local_pid and event['e'] == 'pause':
                    os.kill(local_pid, pause_signal)
                    continue
                # Send the serialized event back to the browser.
                self.session_store.send_to_clients(uuid, event=event)
        finally:
            log.info('Closing stream from %s to session %s' % (addr, uuid))
            # The session_store should close this, but closing it again here
            # assures that it is closed even if it never makes it to the
            # session_store.
            conn.close()
