#
# Copyright 2015 Quantopian, Inc.
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
from collections import namedtuple
from itertools import chain, repeat
import os

from logbook import Logger

from qdb.compat import reduce, zip


def _coerce_dict(dict_like):
    if isinstance(dict_like, QdbConfig):
        return dict_like._asdict()
    return dict_like


log = Logger('qdb_config')


DEFAULT_OPTIONS = {
    'host': 'localhost',
    'port': 8001,
    'auth_msg': '',
    'default_file': None,
    'default_namespace': None,
    'eval_fn': None,
    'exception_serializer': None,
    'skip_fn': None,
    'pause_signal': None,
    'redirect_output': True,
    'retry_attepts': 10,
    'uuid': 'qdb',
    'cmd_manager': None,
    'green': False,
    'repr_fn': None,
    'log_file': None,
    'execution_timeout': None,
}


class QdbConfig(namedtuple('QdbConfig', DEFAULT_OPTIONS)):
    """
    Qdb configuration.
    """
    filename = '.qdb'
    DEFAULT_OPTIONS = DEFAULT_OPTIONS

    kwargs_first = 1
    config_first = -1

    def __new__(cls, **kwargs):
        """
        A structure to hold the arguments to pass to Qdb.

        Args:
          host (str): The `host` of the server.
          port (int): The `port` to connect on.
          auth_msg (str): A message that will be sent with the start event
            to the server. This can be used to do server/tracer authentication.
          default_file (str): a file to use if the file field is omitted from
            payloads.
          eval_fn (function): The function to eval code where the user may
            provide evaluate anything. For example in a conditional breakpoint
            or in the repl.
          exception_serializer (function): The function to convert exceptions
            into strings to send back to the user.
          skip_fn (function): Simmilar to the skip List feature of Bdb, except
            that it should be a function that takes a filename and returns True
            iff the debugger should skip this file. These files will be
            suppressed from stack traces.
          pause_signal (int): Signal to raise in this program to trigger a
            pause command. If this is none, this will default to SIGUSR2.
          retry_attempts (int): The number of times to attempt to connect to
            the server before raising a QdbFailedToConnect error.
          uuid (str): The identifier on the server for this session. If none is
            provided, it will generate a uuid4.
          cmd_manager (subclass of CommandManager): A callable that takes a Qdb
            instance and manages commands by implementing a next_command
            method. If none, a new, default manager will be created that reads
            commands from the server at (`host`, `port`).
          green (bool): If True, this will use gevent safe timeouts, otherwise
            this will use signal based timeouts.
          repr_fn (function): A function to use to convert objects to strings
            to send then back to the server. By default, this wraps repr by
            catching exceptions and reporting them to the user.
          log_file (str): The file to log to, if None, log to stderr.
          execution_timeout (int): The amount of time user code has to execute
            before being cut short. This is applied to the repl, watchlist and
            conditional breakpoints. If None, no timeout is applied.
        """
        extra = [k for k in kwargs if k not in cls.DEFAULT_OPTIONS]
        if extra:
            raise TypeError('QdbConfig received extra args: %s' % extra)

        options = dict(cls.DEFAULT_OPTIONS)
        options.update(kwargs)
        return super(QdbConfig, cls).__new__(cls, **options)

    @classmethod
    def read_from_file(cls, filepath):
        namespace = {}
        try:
            with open(filepath, 'r') as f:
                exec(f.read(), {cls.__name__: cls}, namespace)
        except IOError:
            # Ignore missing files
            log.debug('Skipping loading config from: %s' % filepath)

        return namespace.get('config')

    @classmethod
    def get_config(cls,
                   config=None,
                   files=None,
                   use_local=True,
                   use_profile=True):
        """
        Gets a config, checking the project local config, the
        user-set profile, and any addition files.
        """
        if isinstance(config, cls):
            return config

        if isinstance(config, dict):
            return cls(**config)

        files = files or ()
        return cls().merge(
            cls.read_from_file(filename)
            for use, filename in chain(
                ((use_profile, cls.get_profile()),
                 (use_local, cls.get_local())),
                zip(repeat(True), files),
            )
            if use
        )

    @classmethod
    def get_profile(cls):
        return os.path.join(os.path.expanduser('~'), cls.filename)

    @classmethod
    def get_local(cls):
        return os.path.join(os.getcwd(), cls.filename)

    def merge(self, configs):
        return self._replace(**reduce(
            lambda a, b: (b and a.update(_coerce_dict(b))) or a,
            configs,
            self._asdict(),
        ))


# This lives as a class level attribute on QdbConfig.
del DEFAULT_OPTIONS
