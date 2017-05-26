# qdb #
[![build status](https://travis-ci.org/quantopian/qdb.png?branch=master)](https://travis-ci.org/quantopian/qdb)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/quantopian/qdb?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)


Remote Debugger for Python

qdb powers the in-browser debugger at [Quantopian](https://www.quantopian.com/posts/new-feature-debugging-in-the-ide)

### Overview ###

qdb is a debugger for python that allows users to debug code executing
on remote machine. qdb is split into three main components that may all be
running on separate hardware:

- The client
- The tracer
- The server

The client is the user's interface to the debugger. All communication here is
through a websocket connected to the server. This client could be any type
of application. qdb provides a terminal client and emacs mode for this.


The tracer is the main debugging process. This is the actual code that the user
wishes to debug. Communication here is through a socket sending json
objects representing only the valid messages sent to the server from
the client. A single tracer may have multiple clients connected to it.


The server is the main routing station for messages between the clients and the
tracer. The server is responsible for validating that the messages from the
clients are well formed and routing them to the tracer. A single server may
manage multiple tracers, so it is responsible for making sure that connections
are routed to the proper place. The server can clean up tracer processes whose
clients have become inactive if the server manager decides. The server may also
impose authentication rules to allow or disallow some connections.


### Getting started ###

To debug a process with qdb locally, first you must start the server process.

The easiest way to do this is to execute:

    $ python -m qdb.server

which will start up a server that accepts tracer connections on port 8001, and
client connections on port 8002. There are a few options that may be passed to
the server from the command line, to see a full list, run:

    $ python -m qdb.server --help


Now that you have a server running, you may run a process under qdb.
As an example, try saving the following as qdb_test.py:

```python
from qdb import set_trace, RemoteCommandManager


def f():
    in_f = True
    return 'getting out of f'


def main():
    set_trace(
        uuid='qdb',
        host='localhost',
        port=8001,
        cmd_manager=RemoteCommandManager(),
    )
    mutable_object = {}
    print 'Hello world!'
    f()
    print mutable_object


if __name__ == '__main__':
    main()
```

Then, invoke the program as you normally would with:

    $ python qdb_test.py

Finally, you will need to connect your client to the server so that you can
actually debug the program. To connect, run the provided client found in the
client directory with:

    $ qdb-cli

Before you are finished, you will need to get the output from the program, in a
seperate terminal, run:

    $ tail -f /tmp/qdb/.qdb

This will be the realtime output from the debugger.


You are now ready to debug your process, issue the `help` command in the repl
to see a list of available commands and functions, or begin evaluating python
code in the context of the other process.


## Contributions ##

If you would like to contribute, please see our
[Contribution Requests](https://github.com/quantopian/qdb/wiki/Contribution-Requests).


### Requirements ###

To download the requirements, you can simply issue:

    $ make requirements

assuming you have pip installed. You will most likely want to install into a
virtualenv.

To view the development and normal requirements, see etc/requirements_dev.txt
and etc/requirements.txt.


### Style ##
To ensure that changes and patches are focused on behavior changes, the qdb
codebase adheres to both PEP-8, http://www.python.org/dev/peps/pep-0008/, and
pyflakes, https://launchpad.net/pyflakes/.

The maintainers check the code using
the flake8 script, https://bitbucket.org/tarek/flake8/wiki/Home, which is
included in the etc/requirements_dev.txt.

Before submitting patches or pull requests, please ensure that running
`make style` and `make test` both pass.


## Source ##

The source for qdb is hosted at: https://github.com/quantopian/qdb


### Contact ###

For other questions, please contact opensource@quantopian.com.
