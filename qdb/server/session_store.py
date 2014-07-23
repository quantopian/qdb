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
from gevent.monkey import patch_all
patch_all()

from collections import namedtuple
import errno
import json
from struct import pack
from time import time

import gevent
from gevent import socket
from gevent.event import Event
from geventwebsocket import WebSocketError
from logbook import Logger

try:
    import cPickle as pickle
except ImportError:
    import pickle

# The number of minutes that a session can go without sending a message before
# it is cleaned by the gc.
SESSION_INACTIVITY_TIMEOUT = 10  # minutes

# The time that a socket will wait for the other side to connect.
ATTACH_TIMEOUT = 60  # seconds

# The number of seconds to have the session gc sleep for in between passes.
SESSION_GC_SLEEP_TIME = 60  # seconds

log = Logger('QdbSessionStore')


class DebuggingSession(namedtuple('DebuggingSessionBase', ['tracer',
                                                           'clients',
                                                           'both_sides_event',
                                                           'timestamp'])):
    """
    A DebuggingSession stores all the information about a task that is being
    debugged, including the socket to the client, the websockets to the
    client, and the timers that manage new connections.
    """
    def __new__(cls, tracer=None, clients=None,
                both_sides_event=None, timestamp=None):
        clients = clients or set()
        both_sides_event = both_sides_event or Event()
        timestamp = timestamp or time()
        self = super(DebuggingSession, cls).__new__(
            cls, tracer, clients, both_sides_event, timestamp
        )
        return self

    def update_timestamp(self):
        """
        Updates the timestamp of the session.
        This will delay it from being slaughtered in a gc pass by a minimum of
        SESSION_INACTIVITY_TIMEOUT minutes from the time of this being called.
        """
        return self._replace(timestamp=time())

    def attach_tracer(self, tracer):
        """
        Attaches a tracer to this session.
        Also internally checks if any clients are waiting on this tracer and
        will mark self.both_sides_event accordingly.
        """
        if self.clients:
            self.both_sides_event.set()
        return self._replace(tracer=tracer)

    def attach_client(self, client):
        """
        Attaches a client to this session.
        Also internally checks if the client is waiting on this client and
        will mark self.both_sides_event accordingly.
        """
        if self.tracer:
            self.both_sides_event.set()
        self.clients.add(client)
        return self


class SessionStore(object):
    """
    Stores the set of tracer and client sockets as sessions.
    Allows for easily sending messages to multiple client that are
    connected to a single session, and lets them all pass their data through
    to the underlying tracer.
    """
    def __init__(self,
                 inactivity_timeout=SESSION_INACTIVITY_TIMEOUT,
                 sweep_time=SESSION_GC_SLEEP_TIME,
                 attach_timeout=ATTACH_TIMEOUT,
                 timeout_disable_mode='soft'):
        if timeout_disable_mode not in ['soft', 'hard']:
            raise ValueError("timeout_disable_mode must be 'hard' or 'soft'")
        self.inactivity_timeout = inactivity_timeout
        self.sweep_time = sweep_time
        self.attach_timeout = attach_timeout
        self.timeout_disable_mode = timeout_disable_mode
        self._sessions = {}
        self.gc_glet = None

    def __contains__(self, uuid):
        """
        Allows for:
        `if uuid in session_store: ...`
        """
        return uuid in self._sessions

    def has_client(self, uuid):
        """
        Checks if any clients exist for this session.
        """
        return uuid in self._sessions and self._sessions[uuid].has_client()

    def has_tracer(self, uuid):
        """
        Checks if a tracer is connected for this session.
        """
        return uuid in self._sessions and self._sessions[uuid].tracer()

    def _run_gc(self):
        """
        Runs the gc over the session store, clearing any sessions that appear
        inactive. This does not clear algos as soon as timeout, but instead
        will only clear them if they are inactive at the time of a pass.
        This means that it is possible for a session to go inactive for longer
        than SESSION_INACTIVITY_TIMEOUT minutes as long as the session becomes
        active again before the gc passes over it.
        """
        def gc_pass():
            """
            Performs a pass over the sessions removing any that have not
            passed any messages in over SESSION_INACTIVITY_TIMEOUT minutes.
            """
            now = time()
            for uuid in self._sessions.keys():
                last_message = self._sessions[uuid].timestamp
                if (now - last_message) / 60 > self.inactivity_timeout:
                    log.info('Session %s was marked inactive, killing' % uuid)
                    self.slaughter(uuid, self.timeout_disable_mode)

        while True:
            gc_pass()
            gevent.sleep(self.sweep_time)

    def start(self):
        """
        Starts the session store service.
        """
        self._gc_glet = gevent.spawn(self._run_gc)

    def stop(self):
        """
        Stops the session store service that is running.
        """
        self._gc_glet.kill(timeout=5)
        self.slaughter_all()

    def attach_tracer(self, uuid, socket):
        """
        Attaches the tracer for uuid at the socket.
        This call waits for at least one client to come.
        Returns True iff a client came and the session is ready to begin,
        otherwise, returns false and does not add the session to the store.
        """
        log.info('Attaching a tracer for session %s' % uuid)
        if uuid in self._sessions:
            session = self._sessions[uuid].update_timestamp()
        else:
            session = DebuggingSession()

        self._sessions[uuid] = session.attach_tracer(socket)
        # Wait for the client.
        if not self._sessions[uuid].both_sides_event.wait(self.attach_timeout):
            self.slaughter(uuid)
            log.warn('No client came to debug %s' % uuid)
            return False
        log.info('Session %s has started' % uuid)
        return True

    def attach_client(self, uuid, socket):
        """
        Attaches a tracer for uuid at the socket.
        This call waits for the client to come.
        Returns True iff the client came and the session is ready to begin,
        otherwise returns False and does not add the session to the store.
        """
        log.info('Attaching a client for session %s' % uuid)
        if uuid in self._sessions:
            session = self._sessions[uuid].update_timestamp()
        else:
            session = DebuggingSession()

        self._sessions[uuid] = session.attach_client(socket)
        # Wait for the client.
        if not self._sessions[uuid].both_sides_event.wait(self.attach_timeout):
            self.slaughter(uuid)
            log.warn('No tracer attached for %s' % uuid)
            return False
        return True

    def _update_timestamp(self, uuid):
        self._sessions[uuid] = self._sessions[uuid].update_timestamp()

    def send_to_tracer(self, uuid, msg=None, event=None):
        """
        Sends a pre-packed message or event the tracer uuid.
        """
        if event:
            try:
                msg_dict = {
                    'e': event['e'],
                    'p': event.pop('p', None)
                }
                msg = pickle.dumps(msg_dict)
            except pickle.PicklingError as p:
                log.warn('send_to_tracer(%s, event=%s) failed: %s'
                         % (uuid, event, p))
                return
        if not msg:
            return  # No message to send.
        if uuid not in self._sessions:
            log.warn('send_to_tracer failed: session %s does not exist'
                     % uuid)
            return  # Session doesn't exist.

        sck = self._sessions[uuid].tracer
        if sck:
            # Pack the length and then send the data.
            sck.sendall(pack('>i', len(msg)))
            sck.sendall(msg)
        else:
            log.warn('No client session is alive for %s' % uuid)
        self._update_timestamp(uuid)

    def send_to_clients(self, uuid, msg=None, event=None):
        """
        Routes a message to all of the clients taking the same arguments as
        send_to_client.
        """
        if event:
            try:
                msg_dict = {'e': event['e']}
                if 'p' in event:
                    msg_dict['p'] = event['p']
                msg = json.dumps(msg_dict)
            except ValueError as v:
                log.warn('send_to_clients(%s, event=%s) failed: %s'
                         % (uuid, event, v))
                return
        if not msg:
            return  # No message to send.
        if uuid not in self._sessions:
            log.warn('send_to_clients failed: session %s does not exist'
                     % uuid)
            return  # Session doesn't exist.
        clients = self._sessions[uuid].clients
        for client in set(clients):
            try:
                client.send(msg)
            except:
                log.info('Client was closed for debug session: %s' % uuid)
                clients.remove(client)
        self._update_timestamp(uuid)

    def slaughter(self, uuid, mode='soft'):
        """
        Slaughters a session, closing all clients and the tracer.
        This also removes the session from the list of sessions.
        If mode is 'soft', the tracer clears all breakpoints and continues
        execution. If it is 'hard', it raises a QdbQuit in the tracer process.
        """
        session = self._sessions.get(uuid)
        if not session:
            return  # Slaughtering a session that does not exits.
        # Close all the clients.
        disable_event = {'e': 'disable'}
        self.send_to_clients(uuid, event=disable_event)
        for client in session.clients:
            try:
                client.close()
            except WebSocketError as e:
                if str(e) != 'Socket is dead':
                    log.exception(
                        'Exception caught while killing client for '
                        'session %s:' % uuid
                    )
        # Close the tracer if we had one.
        if session.tracer:
            try:
                disable_event['p'] = mode
                self.send_to_tracer(uuid, event=disable_event)
                session.tracer.close()
            except socket.error as e:
                # EPIPE means it is already closed.
                if e.errno != errno.EPIPE:
                    log.exception(
                        'Exception caught while killing tracer for session %s:'
                        % uuid
                    )
        del self._sessions[uuid]
        log.info('Debugging session %s has been terminated' % uuid)

    def slaughter_all(self, mode='soft'):
        """
        Slaughters all the sessions that are in progress.
        """
        for uuid in self._sessions.keys():
            self.slaughter(uuid, mode)
