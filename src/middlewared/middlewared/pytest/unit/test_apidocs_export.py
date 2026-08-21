"""zfs/freecore-docs#13: the published reference must be the page the box serves."""
import pytest

from middlewared.apidocs.export import METHOD_FIELDS, capture, render, validate_payload


class FakeClient:
    """Stands in for a connected middlewared client on a running release."""

    def __init__(self, services, events):
        self.services = services
        self.events = events
        self.calls = []

    def call(self, method, *args):
        self.calls.append((method, args))
        if method == 'core.get_services':
            return {name: {'type': 'config'} for name in self.services}
        if method == 'core.get_methods':
            return self.services[args[0]]
        if method == 'core.get_events':
            return self.events
        raise AssertionError(method)


def method(description):
    """A method shaped the way core.get_methods reports one."""
    return {
        'accepts': [], 'description': description, 'downloadable': False,
        'examples': {}, 'job': False, 'uploadable': False,
    }


SERVICES = {
    'bastille': {'bastille.query': method('List jails')},
    'pool': {'pool.query': method('List pools')},
}
EVENTS = {'pool.query': {'description': 'Pool changes', 'wildcard_subscription': False}}


def test_capture_records_the_release_it_describes():
    payload = capture(FakeClient(SERVICES, EVENTS), 'FreeCORE-15.1-RC2')
    assert payload['version'] == 'FreeCORE-15.1-RC2'
    assert payload['events'] == EVENTS
    assert set(payload['services']) == {'bastille', 'pool'}


def test_capture_asks_every_service_for_its_methods():
    client = FakeClient(SERVICES, EVENTS)
    capture(client, 'FreeCORE-15.1-RC2')
    assert ('core.get_methods', ('bastille',)) in client.calls
    assert ('core.get_methods', ('pool',)) in client.calls


def test_capture_is_ordered_so_two_captures_of_one_release_match():
    payload = capture(FakeClient(SERVICES, EVENTS), 'v')
    assert list(payload['services']) == sorted(payload['services'])


def test_render_produces_the_reference_from_a_payload_alone():
    payload = capture(FakeClient(SERVICES, EVENTS), 'FreeCORE-15.1-RC2')
    html = render(payload)
    assert 'bastille' in html
    assert 'pool' in html


def test_render_needs_no_running_middleware():
    """The whole point: rendering must not reach for a box or a plugin import."""
    payload = {'version': 'v', 'services': {}, 'events': {}}
    assert render(payload)


@pytest.mark.parametrize('missing', ['version', 'services', 'events'])
def test_render_refuses_an_incomplete_payload(missing):
    payload = {'version': 'v', 'services': {}, 'events': {}}
    payload.pop(missing)
    with pytest.raises(ValueError):
        render(payload)


@pytest.mark.parametrize('services', [None, [], 'x', {'pool': None}, {'pool': ['pool.query']}])
def test_render_refuses_a_payload_shaped_by_a_different_tool(services):
    """A payload that cannot fill the page must fail loudly, not publish a blank one."""
    with pytest.raises(ValueError):
        render({'version': 'v', 'services': services, 'events': {}})


@pytest.mark.parametrize('field', METHOD_FIELDS)
def test_a_method_missing_a_rendered_field_names_that_field(field):
    """capture and render run on different machines; a mismatch must say which field is missing."""
    attributes = method('List pools')
    attributes.pop(field)
    with pytest.raises(ValueError, match=field):
        validate_payload({'version': 'v', 'services': {'pool': {'pool.query': attributes}}, 'events': {}})


def test_capture_refuses_to_produce_a_payload_it_could_not_render():
    class Broken(FakeClient):
        def call(self, name, *args):
            if name == 'core.get_methods':
                return {'pool.query': {'description': 'no other fields'}}
            return super().call(name, *args)

    with pytest.raises(ValueError):
        capture(Broken(SERVICES, EVENTS), 'v')
