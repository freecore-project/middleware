"""Export the installed API reference as a static page.

zfs/freecore-docs#13. The reference is only readable today by owning a running box and logging into
it, which excludes everyone deciding whether to adopt FreeCORE, anyone writing a client against a
release they are not running, and anyone answering a question with a link.

The work is split in two because only the first half needs a machine running FreeCORE:

``capture``  asks a running middleware what it registered -- the same three introspection calls the
             on-box page makes -- and returns a payload. This must run on the release it describes.
``render``   renders the page from a captured payload using the templates the box itself serves, so
             the published page is the page, not a re-implementation of it. This is pure, runs
             anywhere, and is unit tested.

Keeping the payload as the artefact is what stops the published reference from drifting: it is
captured *from* a release, so it cannot claim a call that release does not have. Rendering from a
source tree instead was tried and does not work -- middlewared's plugins need the runtime's full
dependency set to import, and a partial load would silently publish a partial API.
"""

import json
from unittest.mock import patch

from . import app

# What templates/websocket.html reads off every method. Capture and render can run on different
# machines and different releases, so a payload that cannot fill the page has to say which field is
# missing rather than surface as a Jinja error at publish time.
METHOD_FIELDS = ('accepts', 'description', 'downloadable', 'examples', 'job', 'uploadable')


def validate_payload(payload):
    """Raise unless the payload can fill the reference page."""
    if not isinstance(payload, dict):
        raise ValueError('The captured API payload must be an object.')
    for field in ('version', 'services', 'events'):
        if field not in payload:
            raise ValueError(f'The captured API payload is missing {field!r}.')
    if not isinstance(payload['services'], dict) or not isinstance(payload['events'], dict):
        raise ValueError('The captured API payload must map service names to methods and event names to attributes.')
    for service, methods in payload['services'].items():
        if not isinstance(methods, dict):
            raise ValueError(f'Captured service {service!r} does not map method names to attributes.')
        for name, attributes in methods.items():
            if not isinstance(attributes, dict):
                raise ValueError(f'Captured method {name!r} does not describe itself.')
            missing = [field for field in METHOD_FIELDS if field not in attributes]
            if missing:
                raise ValueError(
                    f'Captured method {name!r} is missing {", ".join(missing)}, which the reference '
                    f'page renders.'
                )
    return payload


def capture(client, version):
    """Collect what a running middleware reports about itself.

    ``client`` is a connected ``middlewared.client.Client``. ``version`` is the release the payload
    describes, and is recorded so a published page can state what it was generated from.
    """
    services = {}
    for name in sorted(client.call('core.get_services')):
        services[name] = client.call('core.get_methods', name)
    return validate_payload({
        'version': version,
        'services': services,
        'events': client.call('core.get_events'),
    })


def _payload_client(payload):
    """Return a stand-in for middlewared.client.Client that answers from a captured payload."""
    answers = {
        'core.get_services': lambda: {name: {} for name in payload['services']},
        'core.get_methods': lambda name=None: payload['services'].get(name, []),
        'core.get_events': lambda: payload['events'],
    }

    class _Client:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def call(self, method, *args):
            try:
                answer = answers[method]
            except KeyError:
                raise AssertionError(f'The API reference asked for {method}, which is not captured.')
            return answer(*args)

    return _Client


def render(payload, route='/websocket/', script_name=''):
    """Render one reference page from a captured payload, exactly as the box would serve it."""
    validate_payload(payload)
    with patch('middlewared.apidocs.Client', _payload_client(payload)):
        with app.test_client() as client:
            response = client.get(
                route,
                headers={'X-Script-Name': script_name} if script_name else {},
                follow_redirects=True,
            )
            if response.status_code != 200:
                raise RuntimeError(f'The API reference route {route} returned {response.status_code}.')
            return response.get_data(as_text=True)


def main(argv=None):
    """``capture <version> <out.json>`` on a box, then ``render <in.json> <out.html>`` anywhere."""
    import sys

    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) == 3 and argv[0] == 'capture':
        from middlewared.client import Client
        with Client() as client:
            payload = capture(client, argv[1])
        with open(argv[2], 'w') as handle:
            json.dump(payload, handle, indent=1, sort_keys=True)
        return 0
    if len(argv) == 3 and argv[0] == 'render':
        with open(argv[1]) as handle:
            payload = json.load(handle)
        with open(argv[2], 'w') as handle:
            handle.write(render(payload))
        return 0
    print(main.__doc__)
    return 2
