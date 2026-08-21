## Websocket Protocol

FreeCORE uses DDP: https://github.com/meteor/meteor/blob/devel/packages/ddp/DDP.md .

DDP (Distributed Data Protocol) is the stateful websocket protocol to communicate between the client and the server.

Websocket endpoint: `/websocket`

e.g. `ws://freecore.domain/websocket`

### Example of connection

#### Client connects to websocket endpoint and sends a `connect` message.

    :::javascript
    {
      "msg": "connect",
      "version": "1",
      "support": ["1"]
    }

#### Server answers with either `connected` or `failed`.

    :::javascript
    {
      "msg": "connected",
      "session": "b4a4d164-6bc7-11e6-8a93-00e04d680384"
    }

### Authentication

Authentication happens by calling the `auth.login` method.

Request:

    :::javascript
    {
      "id": "d8e715be-6bc7-11e6-8c28-00e04d680384",
      "msg": "method",
      "method": "auth.login",
      "params": ["username", "password"]
    }

Response:

    :::javascript
    {
      "id": "d8e715be-6bc7-11e6-8c28-00e04d680384",
      "msg": "result",
      "result": true,
    }

## JSON-RPC 2.0

Clients written against the modern documented TrueNAS API speak JSON-RPC 2.0
rather than DDP. FreeCORE accepts both. DDP stays the default and nothing about
it changed; JSON-RPC is offered so third-party tooling that has no DDP fallback
can talk to a FreeCORE box at all.

Websocket endpoint: `/api/current`

e.g. `ws://freecore.domain/api/current`

There is no `connect` handshake: the first frame can be a call. A JSON-RPC frame
sent to `/websocket` before any DDP handshake is also understood, so a client
that only knows the one endpoint still works.

Request:

    :::javascript
    {
      "jsonrpc": "2.0",
      "id": 1,
      "method": "auth.login_with_api_key",
      "params": ["1-abcdef..."]
    }

Response:

    :::javascript
    {
      "jsonrpc": "2.0",
      "id": 1,
      "result": true
    }

Errors carry the errno the DDP protocol would have sent, in `data`:

    :::javascript
    {
      "jsonrpc": "2.0",
      "id": 2,
      "error": {
        "code": -32001,
        "message": "method call error",
        "data": {
          "error": 13,
          "errname": "EACCES",
          "reason": "Not authenticated",
          "trace": null,
          "extra": null
        }
      }
    }

`code` is `-32000` when the connection has too many calls in flight, `-32001`
for anything the method itself raised, and otherwise one of the codes the
JSON-RPC 2.0 specification defines (`-32700` invalid JSON, `-32600` invalid
request, `-32601` unknown method, `-32602` invalid parameters).

### Events

`core.subscribe` takes an event name and returns a subscription id;
`core.unsubscribe` takes that id back. Events arrive as JSON-RPC notifications:

    :::javascript
    {
      "jsonrpc": "2.0",
      "method": "collection_update",
      "params": {
        "msg": "changed",
        "collection": "core.get_jobs",
        "id": 42,
        "fields": {"id": 42, "state": "RUNNING"}
      }
    }

A subscription the server ends by itself -- an event source that ran out, say --
is announced with a `notify_unsubscribed` notification naming the collection.

### What is not supported

Batch requests, named (object) parameters, and `auth.login_ex`. Authentication
is `auth.login`, `auth.login_with_api_key` or `auth.token`, and the method
surface is FreeCORE's own: this is compatibility with the JSON-RPC protocol,
not with another product's API.
