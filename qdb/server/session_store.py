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
import os
from struct import pack
from time import time

import gevent
from gevent.lock import RLock
from gevent import socket
from gevent.event import Event
from geventwebsocket import WebSocketError
from logbook import Logger

from qdb.comm import fmt_msg, fmt_err_msg


# errno's that are safe to ignore when killing a session.
safe_errnos = (
    errno.EBADF,
    errno.ECONNRESET,
    errno.EPIPE,
)

# Symbolic constant for the attach_timeout case.
ALLOW_ORPHANS = 0


log = Logger('QdbSessionStore')


class DebuggingSession(namedtuple('DebuggingSessionBase', ['tracer',
                                                           'local_pid',
                                                           'pause_signal',
                                                           'clients',
                                                           'both_sides_event',
                                                           'timestamp'])):
    """
    A DebuggingSession stores all the information about a task that is being
    debugged, including the socket to the client, the websockets to the
    client, and the timers that manage new connections.
    """
    def __new__(cls,
                tracer=None,
                local_pid=None,
                pause_signal=None,
                clients=None,
                both_sides_event=None,
                timestamp=None):
        clients = clients or set()
        both_sides_event = both_sides_event or Event()
        timestamp = timestamp or time()
        self = super(DebuggingSession, cls).__new__(
            cls,
            tracer,
            local_pid,
            pause_signal,
            clients,
            both_sides_event,
            timestamp,
        )
        return self

    def update_timestamp(self):
        """
        Updates the timestamp of the session.
        This will delay it from being slaughtered in a gc pass by a minimum of
        SESSION_INACTIVITY_TIMEOUT minutes from the time of this being called.
        """
        return self._replace(timestamp=time())

    def attach_tracer(self, tracer, local_pid, pause_signal):
        """
        Attaches a tracer to this session.
        Also internally checks if any clients are waiting on this tracer and
        will mark self.both_sides_event accordingly.
        """
        if self.clients:
            self.both_sides_event.set()
        return self._replace(
            tracer=tracer,
            local_pid=local_pid,
            pause_signal=pause_signal,
        )

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
                 inactivity_timeout=10,  # minutes
                 sweep_time=1,  # minute
                 attach_timeout=60,  # seconds
                 timeout_disable_mode='soft'):
        """
        inactivity_timeout is the amount of time in minutes that a session may
        go without any messages being sent before it is killed. If
        inactivity_timeout is None, then sessions may sit innactive forever.
        sweep_time is the amount of time in minutes between checks to kill
        inactive sessions.
        attach_timeout is the amount of time in secondsto wait for both sides
        of a session to attach before killing one off. If attach_timeout is
        None, then it will wait forever. If attach_timeout is 0, then it will
        allow for orphaned sessions, meaning a clients with no tracer, or a
        tracer with no clients. These may be attached later.
        timeout_disable_mode is the mode to kill the sessions with in the event
        of a timeout. This mode may be 'hard' or 'soft'.
        """
        if timeout_disable_mode not in ['soft', 'hard']:
            raise ValueError("timeout_disable_mode must be 'hard' or 'soft'")
        self.inactivity_timeout = inactivity_timeout
        self.sweep_time = sweep_time
        self.attach_timeout = attach_timeout
        self.timeout_disable_mode = timeout_disable_mode
        self._sessions = {}
        self.gc_glet = None
        self._lock = RLock()

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
        log.info('Starting qdb.server.session_store')
        if self.inactivity_timeout:
            self._gc_glet = gevent.spawn(self._run_gc)

    def stop(self):
        """
        Stops the session store service that is running.
        """
        log.info('Stopping qdb.server.session_store')
        if self._gc_glet:
            self._gc_glet.kill(timeout=5)
        self.slaughter_all(self.timeout_disable_mode)

    def attach_tracer(self, uuid, socket, local_pid, pause_signal):
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

        self._sessions[uuid] = session.attach_tracer(
            socket,
            local_pid,
            pause_signal
        )
        # Wait for the client if needed.
        if self.attach_timeout == 0:
            log.info('Attached %s%stracer for session %s'
                     % ('local ' if local_pid else '',
                        '' if self._sessions[uuid].clients else 'orphaned ',
                        uuid))
            return True
        if not self._sessions[uuid].both_sides_event.wait(self.attach_timeout):
            # Signal to the tracer that no client attached.
            self._send_to_socket(socket, fmt_err_msg(
                'client', 'No client',
                serial=json.dumps
            ))
            self.slaughter(uuid, self.timeout_disable_mode)
            log.warn('No client came to debug %s' % uuid)
            return False
        log.info('Session %s has started' % uuid)
        return True

    def attach_client(self, uuid, ws):
        """
        Attaches a client for uuid at the ws.
        This call waits for the client to come.
        Returns True iff the client came and the session is ready to begin,
        otherwise returns False and does not add the session to the store.
        """
        log.info('Attaching a client for session %s' % uuid)
        if uuid in self._sessions:
            session = self._sessions[uuid].update_timestamp()
        else:
            session = DebuggingSession()

        self._sessions[uuid] = session.attach_client(ws)
        # Wait for the tracer if needed.
        if self.attach_timeout == ALLOW_ORPHANS:
            log.info('Attached %sclient for session %s'
                     % ('' if self._sessions[uuid].tracer else 'orphaned ',
                        uuid))
            return True
        if not self._sessions[uuid].both_sides_event.wait(self.attach_timeout):
            # Signal to the client that no tracer attached.
            ws.send(fmt_err_msg('tracer', 'No tracer', serial=json.dumps))
            self.slaughter(uuid)
            log.warn('No tracer attached for %s' % uuid)
            return False
        return True

    def _update_timestamp(self, uuid):
        self._sessions[uuid] = self._sessions[uuid].update_timestamp()

    @staticmethod
    def _send_to_socket(sck, msg):
        """
        Sends a message to a socket, prefixed with the length.
        The preferred method of sending a message to a socket is through the
        send_to_tracer method.
        """
        sck.sendall(pack('>i', len(msg)))
        sck.sendall(msg)

    def is_local(self, uuid):
        """
        Returns True iff session uuid is local.
        """
        return uuid in self._sessions and self._sessions[uuid].local_pid

    def pause_tracer(self, uuid):
        """
        Raises the pause_signal in the tracer marked by uuid.
        Returns True iff pausing was successful.
        """
        session = self._sessions.get(uuid)
        if not session:
            log.warn('Attempted to pause non-existing session %s' % uuid)
            return False

        if not session.local_pid:
            log.warn('Attempted to pause non-local session %s' % uuid)
            return False

        try:
            os.kill(session.local_pid, session.pause_signal)
            return True
        except OSError:
            return False

    def send_to_tracer(self, uuid, event):
        """
        Sends an event the tracer uuid.
        """
        if uuid not in self._sessions:
            log.warn('send_to_tracer failed: session %s does not exist'
                     % uuid)
            return  # Session doesn't exist.

        try:
            if event['e'] == 'pause' and self.is_local(uuid):
                self.pause_tracer(uuid)
                log.info('Raising pause signal (%d) in server local session %s'
                         % (self._sessions[uuid].pause_signal, uuid))
                self._update_timestamp(uuid)
                return  # We 'sent' this event.
            msg = fmt_msg(event['e'], event.get('p'), serial=json.dumps)
        except (ValueError, KeyError) as e:
            log.warn('send_to_tracer(uuid=%s, event=%s) failed: %s'
                     % (uuid, event, e))
            raise  # The event is just wrong, reraise this to the user.

        sck = self._sessions[uuid].tracer
        if sck:
            self._send_to_socket(sck, msg)
        else:
            log.warn('No client session is alive for %s' % uuid)
        self._update_timestamp(uuid)

    def send_to_clients(self, uuid, event):
        """
        Routes an event to all clients connected to a session.
        """
        if uuid not in self._sessions:
            log.warn('send_to_clients failed: session %s does not exist'
                     % uuid)
            return  # Session doesn't exist.

        try:
            msg = fmt_msg(event['e'], event.get('p'), serial=json.dumps)
        except (KeyError, ValueError) as e:
            log.warn('send_to_clients(uuid=%s, event=%s) failed: %s'
                     % (uuid, event, e))
            raise

        clients = self._sessions[uuid].clients

        with self._lock:
            for client in set(clients):
                try:
                    client.send(msg)
                except Exception:
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
        disable_event = fmt_msg('disable')
        self.send_to_clients(uuid, event=disable_event)
        for client in session.clients:
            try:
                client.close()
            except WebSocketError as e:
                if str(e) != 'Socket is dead' or e.errno not in safe_errnos:
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
                if e.errno not in safe_errnos:
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
