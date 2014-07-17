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
import socket
from struct import unpack

from gevent import Timeout
from gevent.server import StreamServer
from logbook import Logger

try:
    import cPickle as pickle
except ImportError:
    import pickle

log = Logger('QdbTracerServer')


class QdbTracerServer(StreamServer):
    """
    Listens for qdb tracer connections on a socket, spinning up new client
    connections.
    """
    def __init__(self, session_store, host, port, tracer_auth_fn, auth_timeout):
        self.auth_timeout = auth_timeout
        self.session_store = session_store
        self.tracer_auth_fn = tracer_auth_fn
        super(QdbTracerServer, self).__init__(
            (host, port),
            handle=self.handle_tracer,
        )

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
                resp = conn.recv(rlen)
                resp = pickle.loads(resp)
                resp['e']
            except (socket.error, EOFError):
                return  # It appears something died, kill this now.
            except (pickle.UnpicklingError, KeyError):
                continue  # ignore bad messages.

            yield resp

    def read_event(self, conn):
        """
        Reads a single message.
        """
        try:
            return next(self.read_events(conn))
        except StopIteration:
            return {}

    def handle_tracer(self, conn, addr):
        """
        Handles new connections from the tracers.
        """
        uuid = None
        try:
            start_event = None
            uuid = None
            with Timeout(self.auth_timeout, False):
                try:
                    start_event = self.read_event(conn)
                    uuid = start_event['p']['uuid']
                    if not self.tracer_auth_fn(start_event['p']['auth']):
                        return
                except KeyError:
                    return
            if not start_event:
                log.info('No start message was sent from %s' % addr)
                return

            log.info('Assigning stream from %s to session %s' % (addr, uuid))

            if not self.session_store.attach_tracer(uuid, conn):
                return  # No browser so the attach failed.

            for event in self.read_events(conn):
                # Send the serialized event back to the browser.
                self.session_store.send_to_clients(uuid, event=event)
        finally:
            log.info('Closing stream from %s to session %s' % (addr, uuid))
