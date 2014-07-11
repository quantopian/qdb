from collections import namedtuple
import errno
import json

try:
    import cPickle as pickle
except ImportError:
    import pickle

import re
from struct import pack, unpack
import socket
from time import time

import gevent
from gevent import pywsgi, Timeout
from gevent.event import Event
from gevent.server import StreamServer
from geventwebsocket import WebSocketError
from geventwebsocket.handler import WebSocketHandler
from logbook import Logger

from qdb.errors import QdbInvalidRoute


log = Logger('QdbServer')


# The number of minutes that a session can go without sending a message before
# it is cleaned by the gc.
SESSION_INACTIVITY_TIMEOUT = 10  # minutes

# The time that a socket will wait for the other side to connect.
ATTACH_TIMEOUT = 60  # seconds

# The number of seconds to have the session gc sleep for in between passes.
SESSION_GC_SLEEP_TIME = 60  # seconds

# The number of seconds a browser has to authenticate.
BROWSER_AUTH_TIMEOUT = 60  # seconds

# The default route.
DEFAULT_ROUTE = '/debug_session/(.+)'


class QdbServer(object):
    def __init__(self,
                 session_store=None,
                 tracer_host='localhost',
                 tracer_port=8001,
                 client_host='localhost',
                 client_port=8002,
                 route=None,
                 auth_timeout=None,
                 auth_fn=None,
                 tracer_server=None,
                 client_server=None):
        """
        Sets up the qdb server.
        """
        session_store = session_store if session_store else SessionStore()
        gevent.spawn(session_store.start)
        route = route if route else DEFAULT_ROUTE
        auth_timeout = auth_timeout if auth_timeout else BROWSER_AUTH_TIMEOUT
        auth_fn = auth_fn if auth_fn else lambda _: True  # No auth.
        self._stop = gevent.event.Event()
        self.tracer_server = QdbTracerServer(
            session_store=session_store,
            host=tracer_host,
            port=tracer_port,
        ) if not tracer_server else tracer_server
        self.client_server = QdbClientServer(
            session_store=session_store,
            host=client_host,
            port=client_port,
            route=route,
            auth_timeout=auth_timeout,
            auth_fn=auth_fn,
        ) if not client_server else client_server

    def serve_forever(self):
        """
        Begins accepting new connections, blocking until the server is
        terminated.
        """
        self._running = True
        self.tracer_server.start()
        self.client_server.start()
        self._stop.wait()

    def stop(self):
        """
        Stops the internal servers.
        """
        self.tracer_server.stop()
        self.client_server.stop()
        self._stop.set()


class QdbTracerServer(StreamServer):
    """
    Listens for qdb tracer connections on a socket, spinning up new client
    connections.
    """
    def __init__(self, session_store, host, port):
        self.session_store = session_store
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
            except socket.error:
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
        open_event = self.read_event(conn)
        if open_event.get('e') != 'new_tracer' or 'p' not in open_event:
            # This is not a new client for some reason.
            return
        uuid = open_event['p']
        log.info('Assigning stream from %s to session %s' % (addr, uuid))

        if not self.session_store.attach_tracer(uuid, conn):
            return  # No browser so the attach failed.

        for event in self.read_events(conn):
            # Send the serialized event back to the browser.
            self.session_store.send_to_clients(uuid, event=event)


class QdbNopTracerServer(object):
    """
    Nop server (do not serve tracer connections or open a socket).
    Use this server if you wish to manage qdb connections elsewhere.
    """
    def __init__(self, *args, **kwargs):
        pass

    def start(self, *args, **kwargs):
        pass

    def stop(self, *args, **kwargs):
        pass


class QdbClientServer(object):
    def __init__(self,
                 session_store,
                 host,
                 port,
                 route,
                 auth_fn,
                 auth_timeout):
        """
        The parameters here are the same  for the client server except for
        route, where route is a regular expression (as a string or regex
        object) that defines where to look for connections.
        For example:
            `/debug_sessions/(.+)`
        There should be exactly one group in the route, this will be the uuid
        match.
        The auth_timeout is the amount of time to leave a socket open awaiting
        the auth_event or first message. This is measured in seconds.
        """
        self.address = host, port
        self.auth_fn = auth_fn
        self.auth_timeout = auth_timeout
        self.route = re.compile(route, re.IGNORECASE)
        self.session_store = session_store
        if self.route.groups != 1:
            # We need exactly one regex group.
            raise QdbInvalidRoute(self.route)
        self._server = pywsgi.WSGIServer(
            self.address,
            self.handle_client,
            handler_class=WebSocketHandler,
        )

    def send_error(self, ws, error_type, error_data):
        """
        Sends an error event back to the client.
        """
        event = {
            'e': 'error',
            'p': {
                'type': error_type,
                'data': error_data,
            },
        }
        try:
            ws.send(json.dumps(event))
        except WebSocketError:
            return

    def get_events(self, ws):
        """
        Yields valid messages from the websocket. Only yields well formed
        messages. In the case of an illformed message, an error event is sent
        to the client.
        """
        while True:
            try:
                raw = ws.receive()
            except WebSocketError:
                return
            try:
                event = json.loads(raw)
                event['e']
            except (ValueError, TypeError) as v:
                self.send_error(ws, 'event', str(v))
                continue
            except KeyError:
                self.send_error(ws, 'event', 'No \'e\' field sent')
                continue

            yield event

    def get_event(self, ws):
        """
        Returns a single (valid) event.
        """
        return next(self.get_events(ws))

    def handle_client(self, environ, start_response):
        path = environ['PATH_INFO']
        ws = environ['wsgi.websocket']
        match = self.route.match(path)
        if not match:
            # This did not match our route.
            ws.close()
            return
        uuid = match.group(1)
        auth_event = None
        with Timeout(self.auth_timeout, False):
            auth_event = self.get_event(ws)
        if not auth_event or auth_event['e'] != 'start' \
           or not self.auth_fn(auth_event.get('p', '')):
            # This is not a valid opening packet, or we never got one.
            ws.close()
            return

        if not self.session_store.attach_client(uuid, ws):
            # We are attaching to a client that does not exist.
            ws.close()
            return

        self.session_store.send_to_tracer(uuid, event=auth_event)
        for event in self.get_events(ws):
            self.session_store.send_to_tracer(uuid, event=event)

    def start(self, *args, **kwargs):
        """
        Starts up this server.
        """
        self._server.start()

    def stop(self, *args, **kwargs):
        """
        Stops the server.
        """
        self._server.stop()


class QdbNopClientServer(object):
    """
    A nop client server (does not serve client connections or open a
    websocket).
    This can be used if you wish to manage the client connections elsewhere,
    for example, in a larger flask project.
    """
    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        pass

    def stop(self):
        pass


class DebuggingSession(namedtuple('DebuggingSessionBase', ['tracer',
                                                           'clients',
                                                           'both_sides_event',
                                                           'timestamp'])):
    """
    A DebuggingSession stores all the information about a task that is being
    debugged, including the socket to the client, the websockets to the
    client, and the timers that manage new connections.
    """
    slots = ()  # No other attrs on this object.

    def __new__(cls, tracer=None, clients=None,
                both_sides_event=None, timestamp=None):
        clients = clients or set()
        both_sides_event = both_sides_event or Event()
        timestamp = timestamp or time()
        self = super(DebuggingSession, cls).__new__(
            cls, tracer, clients, both_sides_event, timestamp
        )
        return self

    def has_client(self):
        """
        Checks if at least one client has connected.
        """
        return self.clients

    def has_tracer(self):
        """
        Checks if the tracer has connected.
        """
        return self.tracer

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
        if self.has_client():
            self.both_sides_event.set()
        return self._replace(tracer=tracer)

    def attach_client(self, client):
        """
        Attaches a client to this session.
        Also internally checks if the client is waiting on this client and
        will mark self.both_sides_event accordingly.
        """
        if self.has_tracer():
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
    def __init__(self, inactivity_timeout=None, sweep_time=None,
                 attach_timeout=None):
        self._sessions = {}
        self.inactivity_timeout = inactivity_timeout if inactivity_timeout \
            else SESSION_INACTIVITY_TIMEOUT
        self.sweep_time = sweep_time if sweep_time else SESSION_GC_SLEEP_TIME
        self.attach_timeout = attach_timeout if attach_timeout \
            else ATTACH_TIMEOUT
        self._running_gc = False

    def __contains__(self, uuid):
        """
        Allows for:
        `if uuid in session_store: ...`
        """
        return uuid in self._session

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

    def start(self):
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
            for uuid in dict(self._sessions):
                last_message = self._sessions[uuid].timestamp
                if (now - last_message) / 60 > self.inactivity_timeout:
                    log.info('Session %s was marked inactive, killing' % uuid)
                    self.slaughter(uuid)

        self._running_gc = True
        while self._running_gc:
            gc_pass()
            gevent.sleep(self.sweep_time)

    def shutdown(self):
        """
        Stops the session store service that is running.
        """
        self._running_gc = False
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
                msg_dict = {'e': event['e']}
                if 'p' in event:
                    msg_dict['p'] = event['p']
                msg = pickle.dumps(msg_dict)
            except pickle.PicklingError:
                return
        if not msg:
            return  # No message to send.
        if uuid not in self._sessions:
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
            except ValueError:
                return
        if not msg:
            return  # No message to send.
        if uuid not in self._sessions:
            return  # Session doesn't exist.
        clients = self._sessions[uuid].clients
        for client in set(clients):
            try:
                client.send(msg)
            except:
                log.info('Client was closed for debug session: %s' % uuid)
                clients.remove(client)
        self._update_timestamp(uuid)

    def slaughter(self, uuid):
        """
        Slaughters a session, closing all clients and the tracer.
        This also removes the session from the list of sessions.
        """
        log.info('Debugging session %s has been terminated' % uuid)
        session = self._sessions.pop(uuid, None)
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
                self.send_to_tracer(uuid, event=disable_event)
                session.tracer.close()
            except socket.error as e:
                # EPIPE means it is already closed.
                if e.errno != errno.EPIPE:
                    log.exception(
                        'Exception caught while killing tracer for session %s:'
                        % uuid
                    )

    def slaughter_all(self):
        """
        Slaughters all the sessions that are in progress.
        """
        for uuid in dict(self._sessions):
            self.slaughter(uuid)


if __name__ == '__main__':
    server = QdbServer()
    server.serve_forever()
