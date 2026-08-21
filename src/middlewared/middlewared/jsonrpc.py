"""
JSON-RPC 2.0 over WebSocket, as documented for TrueNAS SCALE 25.04+
(https://api.truenas.com/v25.04.0/jsonrpc.html).

FreeCORE inherits the legacy DDP-style ``msg``/``result`` protocol from TrueNAS
CORE 13.3, and that protocol stays the default: the WebUI, ``midclt`` and every
existing client keep speaking it at ``/websocket``, unchanged.  Third-party
tooling written against the modern documented API speaks JSON-RPC 2.0 instead
and sends frames that carry no ``msg`` key at all.  Those frames used to reach
``Application.on_message()`` and raise ``KeyError: 'msg'``, which closed the
connection before the client could do anything (freecore/freecore#23).

This module is only the wire format.  Dispatch stays where it was --
``Middleware._method_lookup`` and ``Application.call_method`` are used as-is --
so a method behaves identically no matter which protocol asked for it, and
there is one place to audit for protocol-specific behaviour.

Scope is compatibility with what FreeCORE supports, not SCALE API parity: the
method surface stays FreeCORE's own.  Notably absent, because this lineage does
not have it, is ``auth.login_ex``; JSON-RPC clients authenticate with
``auth.login``, ``auth.login_with_api_key`` or ``auth.token``.
"""
import binascii
import errno
import pickle

from .service_exception import CallError, get_errname

__all__ = ['JSONRPC_VERSION', 'JSONRPCHandler', 'is_jsonrpc_request']

JSONRPC_VERSION = '2.0'

# Errors defined by the JSON-RPC 2.0 specification.
INVALID_JSON = (-32700, 'Invalid JSON was received by the server.')
INVALID_REQUEST = (-32600, 'The JSON sent is not a valid Request object.')
METHOD_NOT_FOUND = (-32601, 'The method does not exist / is not available.')
INVALID_PARAMS = (-32602, 'Invalid method parameter(s).')
INTERNAL_ERROR = (-32603, 'Internal server error.')

# The two implementation-defined codes the TrueNAS API documents.  Everything a
# method itself raises is reported as `method call error`, with the errno the
# legacy protocol would have sent carried in `data`.
TOO_MANY_CONCURRENT_CALLS = (-32000, 'too many concurrent calls')
METHOD_CALL_ERROR = (-32001, 'method call error')


def is_jsonrpc_request(message):
    """
    Whether `message` is a frame that identifies itself as JSON-RPC 2.0.

    Deliberately narrow: it takes a positive `jsonrpc` marker, not merely the
    absence of `msg`, so a legacy client that sends one malformed frame is not
    switched onto another protocol behind its back.
    """
    return (
        isinstance(message, dict) and
        message.get('jsonrpc') == JSONRPC_VERSION and
        'msg' not in message
    )


class JSONRPCHandler:
    """
    Encodes one `Application`'s traffic as JSON-RPC 2.0.

    An `Application` holds one of these in `self.rpc` when the connection
    speaks JSON-RPC, and `None` when it speaks the legacy protocol; that
    attribute is the only switch between the two.
    """

    def __init__(self, app):
        self.app = app
        self.middleware = app.middleware

    #
    # Outgoing frames
    #

    def send_result(self, message, result):
        self.app._send({
            'jsonrpc': JSONRPC_VERSION,
            'id': message.get('id'),
            'result': result,
        })

    def send_error(self, message, errno_, reason=None, exc_info=None, etype=None, extra=None):
        """
        Report a failed method call.

        Signature mirrors `Application.send_error` so `Application.call_method`
        can stay protocol-agnostic.  `etype` has no JSON-RPC counterpart -- the
        documented error object has no field for it -- and validation detail
        travels in `extra` exactly as it does on the legacy protocol.
        """
        if errno_ == errno.ETOOMANYREFS:
            code, message_ = TOO_MANY_CONCURRENT_CALLS
        else:
            code, message_ = METHOD_CALL_ERROR

        self._send_error_frame(message.get('id'), code, message_, errno_, reason, exc_info, extra)

    def send_protocol_error(self, id_, error, reason=None, errno_=errno.EINVAL):
        """Report a malformed frame, i.e. one that never became a method call."""
        code, message_ = error
        self._send_error_frame(id_, code, message_, errno_, reason, None, None)

    def send_parse_error(self, reason):
        self.send_protocol_error(None, INVALID_JSON, reason)

    def _send_error_frame(self, id_, code, message_, errno_, reason, exc_info, extra):
        data = {
            'error': errno_,
            'errname': get_errname(errno_),
            'reason': reason if reason is not None else message_,
            'trace': self.app._tb_error(exc_info) if exc_info else None,
            'extra': extra,
        }
        if self.app._py_exceptions and exc_info:
            data['py_exception'] = binascii.b2a_base64(pickle.dumps(exc_info[1])).decode()

        self.app._send({
            'jsonrpc': JSONRPC_VERSION,
            'id': id_,
            'error': {
                'code': code,
                'message': message_,
                'data': data,
            },
        })

    def send_event(self, event):
        """
        Wrap an event in a `collection_update` notification.

        `event` is the payload the legacy protocol sends as a bare frame, and
        the documented `params` object has the same shape (`msg`, `collection`,
        `id`, `fields`, `extra`), so it is passed through untouched.
        """
        self.app._send({
            'jsonrpc': JSONRPC_VERSION,
            'method': 'collection_update',
            'params': event,
        })

    def notify_unsubscribed(self, collection, error=None):
        """Tell the client a subscription it did not cancel has ended."""
        self.app._send({
            'jsonrpc': JSONRPC_VERSION,
            'method': 'notify_unsubscribed',
            'params': {
                'collection': collection,
                'error': error,
            },
        })

    #
    # Incoming frames
    #

    async def on_message(self, message):
        if isinstance(message, list):
            # Documented limitation of the TrueNAS API, kept deliberately: a
            # batch would have to share this connection's concurrency budget
            # with no way to report per-request back-pressure.
            self.send_protocol_error(None, INVALID_REQUEST, 'Batch requests are not supported.')
            return

        if not isinstance(message, dict):
            self.send_protocol_error(None, INVALID_REQUEST, 'Request must be an object.')
            return

        id_ = message.get('id')

        if message.get('jsonrpc') != JSONRPC_VERSION:
            self.send_protocol_error(id_, INVALID_REQUEST, f'"jsonrpc" must be "{JSONRPC_VERSION}".')
            return

        method = message.get('method')
        if not isinstance(method, str):
            self.send_protocol_error(id_, INVALID_REQUEST, '"method" must be a string.')
            return

        params = message.get('params')
        if params is None:
            params = []
        if not isinstance(params, list):
            self.send_protocol_error(id_, INVALID_PARAMS, 'Only positional parameters are supported.')
            return

        try:
            serviceobj, methodobj = self.middleware._method_lookup(method)
        except CallError as e:
            self.send_protocol_error(id_, METHOD_NOT_FOUND, str(e), e.errno)
            return

        if not self.app.authenticated and not hasattr(methodobj, '_no_auth_required'):
            self.send_error({'id': id_}, errno.EACCES, 'Not authenticated')
            return

        # Normalised to the keys `call_method` reads, so the dispatch path is
        # the same one the legacy protocol takes.
        call = {'id': id_, 'method': method, 'params': params}
        self.middleware.create_task(self.app.call_method(call, serviceobj, methodobj))
