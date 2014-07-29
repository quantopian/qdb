qdb interaction
===============

An overview of the communication protocol for qdb.


### Message Structure ###

All messages follow the format of:


    {
        'e': EVENT,
        'p': PAYLOAD,
    }


where `PAYLOAD` may be a nested structure itself, and omitting a payload is
the same as setting it to `None`.

An example of this would be the command `eval`. The full message would look
like:



    {
        'e': 'eval',
        'p': 'my_function()'
    }


These frames are all encoded as json, and all messages will be receiving as
json.

Messages must be receiving asynchronously, as there is no easy association
between sending and receiving messages. This is due to the fact that messages
will be receiving for commands sent by other users attached to the same session
(collab), and because some messages send variable amounts of response frames.


### Command Appendix ###

This is a complete list of all event types that qdb understands paired with the
payload that this command requires.

- `step, None`
- `return, None`
- `next, None`
- `until, None`
- `continue, None`
- `eval, String`
- `set_watch, [String]`<sup>`0`</sup>
- `clear_watch, [String]`
- `set_break, BreakpointDict`<sup>`1`</sup>
- `clear_break, BreakpointDict`
- `list, ListDict`<sup>`2`</sup>
- `start, None`
- `disable, String`<sup>`3`</sup>



`0`: `[String]` is an array of strings to watch. These will be evaluated in the
current frame everytime control is given back to the user.

`1`: `BreakpointDict`s as formatted as such:


    {
        'file': String or None,  # This is the filename, None = ALGO_FILENAME
        'line': Int,  # The line number
        'temp': Bool or None,  # Is this temporary (defaults to False)
        'cond': String or None,  # The string to evaluate for this breakpoint
        'func': String or None,  # The function name to break on.
    }


Just like the frames, omitting a field is the same as setting it to `None`.


`2`: `ListDict`s are formatted as such:


    {
        'file': String or None,  # The file to list
        'start': Int or None,  # The first line to show
        'end': Int or None,  # The last line to show
    }

This will return back a `list` message that returns a slice of the file
named in the `file` field or ALGO_FILENAME if that field is `None`.
`None` for start means `start` at line 1, and `None` for `end` means to go until
the end of the file.


`3`: `disable`: Disable accepts the strings `soft` and `hard` where `soft` means
to stop tracing and continue execution and `hard` means to raise a `QdbQuit`
exception in the tracer process, killing the process if this is uncaught.


### Response Appendix ###

This is a complete list of all the responses that the server may send back at
any time.


- `error, ErrorDict`<sup>`0`</sup>
- `breakpoints, [BreakpointDict]`<sup>`1`</sup>
- `stack, [Stackframe]`<sup>`2`</sup>
- `watchlist, [WatchedExpr]`<sup>`3`</sup>
- `print, PrintDict`<sup>`4`</sup>
- `list, String` - The response to the `list` command.
- `disable, None`

`0`: `ErrorDict`s are formatted as such:

    {
        'type': String,  # The type of the error.
        'data': String,  # More information about the error.
    }

There are a lot of types of errors that can occur:

- `auth`  The user failed to authenticate for some reason.
- `payload`  The payload for the command is not correct.
- `event`  There was no event, or the command does not exist.
- `condition`  There was an error in a conditional breakpoint, execution will
stop here and this message will be sent.
- `set_break` The breakpoint could not be set for some reason.


`1`: This is an array of the same `BreakpointDict` as before.

`2`: This is an array of `StackFrame`s that are formatted as such:

    {
        'file': String,  # The filename.
        'line': Int,  # The line number.
        'func': String,  # The function we are in.
        'code': String,  # The code on that line.
    }

The stack is ordered in the array where `stack[0]` is the top frame, and
`stack[-1]` is the frame we are currently in. To retrieve the current line
number you are on, use `stack[-1]['line']`


`3`: This is an array of `WatchedExpr`s that are formatted as such:

    {
        'expr': String,
        'value': String,
    }

where `expr` is the expression you set to watch, and `value` is the result
from evaluating the expression in the current frame. Exceptions will be
converted into a string representation.


`4`: This format of the `PrintDict` is as such:

    {
        'input': String,
        'output': String,
    }

Where `input` is the input that prompted this print statement, and `output` is
the result. If the tracer is set to forward stdout, frames will be sent with an
input of `<stdout>`. The reason that `input` is reported is that it allows users
to show eachother the output of repl commands.
