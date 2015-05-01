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
import json
import socket
from struct import pack

from gevent import Timeout
from gevent.server import StreamServer
from logbook import Logger

from qdb.comm import get_events_from_socket
from qdb.server.serverbase import QdbServerBase

log = Logger('QdbTracerServer')


class AuthenticationFailed(Exception):
    """
    Signals that the authentication failed for some reason.
    """
    def __init__(self, message='Authentication failed'):
        self.message = message


class QdbTracerServer(QdbServerBase, StreamServer):
    """
    Listens for qdb tracer connections on a socket, spinning up new client
    connections.
    """
    def __init__(self,
                 session_store,
                 host='localhost',
                 port=8001,
                 auth_fn=None,
                 auth_timeout=60):  # seconds
        self.auth_timeout = auth_timeout
        self.session_store = session_store
        self.auth_fn = auth_fn or self.NO_AUTH
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

    def read_event(self, conn):
        """
        Reads a single message.
        """
        try:
            return next(get_events_from_socket(conn))
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
                if not self.auth_fn(start_event['p'].get('auth', '')):
                    # We failed the authentication check.
                    log.warn('Bad authentication message from (%s, %d)' % addr)
                    raise AuthenticationFailed()
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
        uuid = None
        local_pid, pause_signal = 0, 0
        message = ''

        log.info('New tracer request from (%s, %d)' % addr)
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
                    uuid, (local_pid, pause_signal) \
                        = self.validate_start_event(start_event, addr)
                except AuthenticationFailed as a:
                    message = a.message

            if message:
                # If we have an error, we need to report that back to the
                # trace so that it may raise a QdbAuthenticationError in the
                # user's code.
                auth_failed_dict = {
                    'e': 'error',
                    'p': {
                        'type': 'auth',
                        'data': '',
                    }
                }

                auth_failed_dict['p']['data'] = message
                err_msg = json.dumps(auth_failed_dict)
                conn.sendall(pack('>i', len(err_msg)))
                conn.sendall(err_msg)
                log.warn('Invalid start message from (%s, %d)' % addr)
                return

            log.info('Assigning stream from (%s, %d) to session %s'
                     % (addr[0], addr[1], uuid))

            if not self.session_store.attach_tracer(
                    uuid,
                    conn,
                    local_pid,
                    pause_signal
            ):
                return  # No browser so the attach failed.

            for event in get_events_from_socket(conn):
                # Send the serialized event back to the browser.
                self.session_store.send_to_clients(uuid, event=event)

            # When this is done, we should kill off the client connections too.
            self.session_store.slaughter(uuid)
        except socket.error:
            log.info('Stream from %s to session %s closed unexpectedly'
                     % (addr, uuid))
            return
        finally:
            log.info('Closing stream from %s to session %s' % (addr, uuid))
            # The session_store should close this, but closing it again here
            # assures that it is closed even if it never makes it to the
            # session_store.
            conn.close()
