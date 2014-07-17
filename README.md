# qdb #

Quantopian Remote Debugger for Python


### Overview ###

qdb is a debugger for python that allows users to debug code executing
on remote machine. qdb is split into three main components that may all be
running on seperate hardware:

- The client
- The tracer
- The server

The client is the user's interface to the debugger. All communication here is
through a websocket connected to the server. This client could be any type
of application. qdb provides a terminal client and emacs mode for this.


The tracer is the main debugging process. This is the actual code that the user
wishes to debug. Communication here is through a socket sending pickle'd
dictionaries representing only the valid json messages sent to the server from
the client. A single tracer may have multiple clients connected to it.


The server is the main routing station for messages between the clients and the
tracer. The server is responsible for validating that the messages from the
clients are well formed and routing them to the tracer. A single server may
manage multiple tracers, so it is responsible for making sure that connections
are routed to the proper place. The server can clean up tracer processes whose
clients have become inactive if the server manager decides.



### json protocol ###

All communication to the server is through a structured protocol of the form:

    {
        "e": event,
        "p": payload
    }

The event is the type of the message, and the payload is any parameter or data
that is associated with this packet. Not all messages require a payload.
For example, the client can send the command:

    {
        "e": "step"
    }

Which steps into the next expression on the tracer. The client may also send:

    {
        "e": "eval"
        "p": "a + b"
    }

This command is equivalent to evaluating the code `a + b` in the current stack
frame.

The server will always send back data that is formatted in this way.


### Modularity ###

qdb is designed with modularity in mind. For this reason, many components of the
qdb system may be swapped out with user defined alternatives to help blend qdb
into larger projects. For example, the qdb server can have the websocket server
swapped out to make it work as a route point in a larger flask project.

While qdb provides a minimal client, the beauty in the websocket / json
combination is that it allows users to plug in their own client, so long as
it can make the connection and interpret the commands.



### Security ###

qdb provides multiple features that are security oriented. Because it is a
remote debugger, the owner of the hardware running the tracer or server may
not want the user to do things. For example, the the server may define an
authentication function that reads the authentication message out of the
start command and either accepts or denies that websocket. Also, the tracer
may define their own eval function to use when evaluating repl code or the
condition of conditional breakpoints. This lets the tracer deny potentially
dangerous code if it so wishes.
