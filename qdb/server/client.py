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
import gevent.monkey
gevent.monkey.patch_all()

import json
import re

from gevent import pywsgi, Timeout
from geventwebsocket import WebSocketError
from geventwebsocket.handler import WebSocketHandler
from logbook import Logger

from qdb.errors import QdbInvalidRoute

log = Logger('QdbClientServer')


class QdbClientServer(object):
    def __init__(self,
                 session_store,
                 host,
                 port,
                 route,
                 client_auth_fn,
                 auth_timeout):
        """
        The parameters here are the same  for the client server except for
        route, where route is a regular expression (as a string or regex
        object) that defines where to look for connections.
        For example:
            `/(.+)`
        There should be exactly one group in the route, this will be the uuid
        match.
        The auth_timeout is the amount of time to leave a socket open awaiting
        the start_event or first message. This is measured in seconds.
        """
        self.address = host, port
        self.client_auth_fn = client_auth_fn
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
                return
            except KeyError:
                self.send_error(ws, 'event', "No 'e' field sent")
                return

            yield event

    def get_event(self, ws):
        """
        Returns a single (valid) event.
        """
        try:
            return next(self.get_events(ws))
        except StopIteration:
            return None

    def handle_client(self, environ, start_response):
        path = environ['PATH_INFO']
        ws = environ['wsgi.websocket']
        addr = environ['REMOTE_ADDR']
        try:
            match = self.route.match(path)
            if not match:
                # This did not match our route.
                return
            log.info('Client request from %s' % addr)
            uuid = match.group(1)
            start_event = None
            with Timeout(self.auth_timeout, False):
                start_event = self.get_event(ws)

            failed = False
            message = ''

            # Fall through the various ways to fail to generate a more helpful
            # error message.
            if not start_event:
                message = 'No start event received'
                failed = True
            elif start_event['e'] != 'start':
                message = "First event must be of type: 'start'"
                failed = True
            elif not self.client_auth_fn(start_event.get('p', '')):
                log.warn('Client %s failed to authenticate' % addr)
                message = 'Authentication failed'
                failed = True

            if failed:
                try:
                    self.send_error(ws, 'auth', message)
                    ws.send(json.dumps({'e': 'disable'}))
                except WebSocketError:
                    # We are unable to send the disable message for some
                    # reason; however, they already failed auth so suppress
                    # it and close.
                    pass
                return

            if not self.session_store.attach_client(uuid, ws):
                # We are attaching to a client that does not exist.
                ws.send(json.dumps({'e': 'disable'}))
                return

            self.session_store.send_to_tracer(uuid, event=start_event)
            for event in self.get_events(ws):
                self.session_store.send_to_tracer(uuid, event=event)

        finally:
            log.info('Closing websocket to client %s' % addr)
            ws.close()

    def start(self, *args, **kwargs):
        """
        Starts up this server.
        """
        log.info('Starting qdb.server.client')
        self._server.start()

    def stop(self, *args, **kwargs):
        """
        Stops the server.
        """
        log.info('Stopping qdb.server.client')
        self._server.stop()
