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
import argparse
from contextlib2 import ExitStack

from logbook import FileHandler

from qdb.server.server import QdbServer

if __name__ == '__main__':
    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        '--tracer-host',
        type=str,
        metavar='TRACER-HOST',
        help='The host the tracer server will serve.',
        default='localhost',
    )
    argparser.add_argument(
        '--tracer-port',
        type=int,
        metavar='TRACER-PORT',
        help='The port the tracer traffic will be served on.',
        default=8001,
        )
    argparser.add_argument(
        '--client-host',
        type=str,
        metavar='CLIENT-HOST',
        help='The host the client server will serve.',
        default='localhost',
    )
    argparser.add_argument(
        '--client-port',
        type=int,
        metavar='CLIENT-PORT',
        help='The port the client traffic will be served on.',
        default=8002,
    )
    argparser.add_argument(
        '--route',
        type=str,
        metavar='ROUTE-REGEX',
        help='The regular expression defining the route the client server will'
        'listen on.',
        default=None,
    )
    argparser.add_argument(
        '--auth-timeout',
        type=int,
        metavar='AUTH-TIMEOUT-SECS',
        help='The amount of seconds that a client or tracer has to '
        'authenticate',
        default=60,
    )
    argparser.add_argument(
        '--inactivity-timeout',
        type=int,
        metavar='INACTIVITY-TIMOUT-MINS',
        help='The amount of minutes a session may be inactive before it is '
        'killed',
        default=None,
    )
    argparser.add_argument(
        '--attach-timeout',
        type=int,
        metavar='ATTACH-TIMEOUT-SECS',
        help='The amount of seconds a session will wait for both sides to '
        'attach. None means wait forever, zero means allow orphan sessions.',
        default=None,
    )
    argparser.add_argument(
        '--sweep-time',
        type=int,
        metavar='SWEEP-TIME-MINS',
        help='The amount of minutes in between sweeps of innactivity checks.',
        default=60,
    )
    argparser.add_argument(
        '--timeout-disable-mode',
        type=str,
        metavar='TIMEOUT-DISABLE-MODE',
        help='The disable mode to use when a session times out.',
        default='soft',
    )
    argparser.add_argument(
        '--log',
        type=str,
        metavar='LOG-FILE',
        help='The path to the logging output file. If omitted, logging goes to'
        'stderr.'
    )
    args = vars(argparser.parse_args())
    log = args.pop('log', None)
    with FileHandler(log) if log else ExitStack():
        QdbServer(**args).serve_forever()
