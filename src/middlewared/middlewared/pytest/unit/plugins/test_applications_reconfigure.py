"""Changing an installed application in place, and the app-owned datasets it
keeps, reattaches or leaves behind (the internal development record)."""
import copy
from unittest.mock import AsyncMock, Mock

import pytest

from middlewared.plugins.applications_.reconfigure import (
    ReconfigureError,
    anything_changed,
    bind_reconfigure,
)
from middlewared.plugins.applications_freebsd import ApplicationsService
from middlewared.service_exception import CallError, ValidationErrors


def record(**overrides):
    # sabnzbd as crpb had it: config and downloads both app-owned.
    result = {
        'schema': 3, 'image_os': 'freebsd', 'origin': None,
        'name': 'sab', 'container_name': 'freecore-app-sab', 'container_id': '1' * 64,
        'image': 'ghcr.io/daemonless/sabnzbd:latest', 'image_id': 'sha256:' + '2' * 64,
        'digest': 'sha256:' + '3' * 64,
        'ports': [{'host_port': 18080, 'container_port': 8080, 'protocol': 'tcp'}],
        'environment': [{'name': 'PUID', 'value': '1000'}, {'name': 'API_KEY', 'value': 's3cret'}],
        'volumes': [
            {'name': 'config', 'target': '/config', 'dataset': 'tank/applications/data/sab/config',
             'source': '/mnt/tank/applications/data/sab/config', 'owned': True, 'read_only': False},
            {'name': 'downloads', 'target': '/downloads', 'dataset': 'tank/applications/data/sab/downloads',
             'source': '/mnt/tank/applications/data/sab/downloads', 'owned': True, 'read_only': False},
        ],
        'annotations': [], 'restart_policy': 'always',
        'portal': {'scheme': 'http', 'port': 18080, 'path': '/'},
        'healthcheck': {'type': 'HTTP', 'scheme': 'http', 'container_port': 8080, 'host_port': 18080, 'path': '/'},
        'created_at': '2026-09-15T00:00:00+00:00', 'updated_at': '2026-09-15T00:00:00+00:00',
        'catalog': {
            'id': 'daemonless:sabnzbd', 'version': '5.1.3', 'variant': 'latest', 'compose_sha256': 'a' * 64,
            'repository': 'https://github.com/daemonless/sabnzbd', 'image_tag': 'ghcr.io/daemonless/sabnzbd:latest',
        },
    }
    result.update(overrides)
    return result


def request(**overrides):
    result = {
        'name': 'sab', 'compose_sha256': 'a' * 64,
        'ports': [{'host_port': 18080, 'container_port': 8080, 'protocol': 'tcp'}],
        'environment': [{'name': 'PUID', 'value': None}, {'name': 'API_KEY', 'value': None}],
        'volumes': [{'name': 'config', 'dataset': None}, {'name': 'downloads', 'dataset': None}],
        'restart_policy': 'always', 'health_timeout': 60,
    }
    result.update(overrides)
    return result


# -- binding ---------------------------------------------------------------

def test_no_change_binds_to_the_record_and_keeps_every_value():
    pinned = record(schema=4, network={'mode': 'managed', 'bridge_address': '10.88.255.254'})
    prepare, fields, changes = bind_reconfigure(pinned, request())
    assert not anything_changed(changes)
    assert fields['ports'] == record()['ports']
    assert fields['environment'] == [{'name': 'API_KEY', 'value': 's3cret'}, {'name': 'PUID', 'value': '1000'}]
    assert fields['portal']['port'] == 18080 and fields['healthcheck']['host_port'] == 18080
    assert prepare['volumes'] == [
        {'name': 'config', 'target': '/config', 'read_only': False, 'dataset': None},
        {'name': 'downloads', 'target': '/downloads', 'read_only': False, 'dataset': None},
    ]


def test_the_shared_downloads_dataset_is_bound_and_the_owned_one_named_as_kept():
    data = request(volumes=[
        {'name': 'config', 'dataset': None}, {'name': 'downloads', 'dataset': 'tank/media/downloads'},
    ])
    prepare, fields, changes = bind_reconfigure(record(), data)
    assert anything_changed(changes)
    assert changes['volumes'] == [{
        'name': 'downloads', 'target': '/downloads', 'from': None, 'to': 'tank/media/downloads',
        'kept_dataset': 'tank/applications/data/sab/downloads',
    }]
    assert prepare['volumes'][1]['dataset'] == 'tank/media/downloads'
    assert changes['ports'] == [] and changes['environment'] == [] and changes['restart_policy'] is False


def test_ports_rebind_the_portal_and_health_check_and_values_can_be_kept_or_replaced():
    data = request(
        ports=[{'host_port': 28080, 'container_port': 8080, 'protocol': 'tcp'}],
        environment=[{'name': 'PUID', 'value': None}, {'name': 'API_KEY', 'value': 'new'}],
        restart_policy='no',
    )
    prepare, fields, changes = bind_reconfigure(record(), data)
    assert fields['ports'][0]['host_port'] == 28080
    assert fields['portal']['port'] == 28080 and fields['healthcheck']['host_port'] == 28080
    assert fields['environment'] == [{'name': 'API_KEY', 'value': 'new'}, {'name': 'PUID', 'value': '1000'}]
    assert prepare['environment'] == fields['environment']
    assert changes['ports'] == [{'container_port': 8080, 'protocol': 'tcp', 'from': 18080, 'to': 28080}]
    assert changes['environment'] == ['API_KEY']
    assert changes['restart_policy'] is True
    assert fields['restart_policy'] == 'no'


def test_external_to_owned_is_a_change_without_a_kept_dataset():
    current = record()
    current['volumes'][1].update({
        'dataset': 'tank/media/downloads', 'source': '/mnt/tank/media/downloads', 'owned': False,
    })
    _, _, changes = bind_reconfigure(current, request())
    assert changes['volumes'] == [{
        'name': 'downloads', 'target': '/downloads', 'from': 'tank/media/downloads', 'to': None, 'kept_dataset': None,
    }]


@pytest.mark.parametrize('data, message', [
    (request(compose_sha256='b' * 64), 'changed since this form was opened'),
    (request(name='other'), 'installed application changed'),
    (request(ports=[]), 'Port declarations'),
    (request(ports=[{'host_port': 18080, 'container_port': 9090, 'protocol': 'tcp'}]), 'Port identity'),
    (request(environment=[{'name': 'PUID', 'value': None}]), 'Environment declarations'),
    (request(volumes=[{'name': 'config', 'dataset': None}, {'name': 'tv', 'dataset': None}]), 'Volume declarations'),
    (request(restart_policy='sometimes'), 'Restart policy'),
])
def test_choices_that_do_not_fit_the_installed_contract_are_refused(data, message):
    with pytest.raises(ReconfigureError, match=message):
        bind_reconfigure(record(), data)


def test_network_binds_to_the_installed_attachment_and_flags_a_switch():
    attachment = {'mode': 'lan', 'interface': 'em0', 'address': '192.0.2.201/24', 'gateway': '192.0.2.1'}
    installed = record(schema=4, network=dict(attachment))

    _, fields, changes = bind_reconfigure(installed, request())
    assert fields['network'] == attachment and changes['network'] is False
    assert not anything_changed(changes)

    _, fields, changes = bind_reconfigure(installed, request(network={'mode': 'managed'}))
    assert fields['network'] == {'mode': 'managed'}
    assert changes['network'] is True and anything_changed(changes)

    _, fields, changes = bind_reconfigure(record(), request(network=dict(attachment)))
    assert fields['network'] == attachment and changes['network'] is True


def test_managed_access_binds_on_off_and_preserves_the_assigned_address():
    attachment = {'mode': 'lan', 'interface': 'em0', 'address': '192.0.2.201/24', 'gateway': '192.0.2.1'}
    dual = {**attachment, 'managed_access': True, 'managed_address': '10.88.255.254'}

    # turning the leg on: the flag binds, the address is left to the job
    _, fields, changes = bind_reconfigure(
        record(schema=4, network=dict(attachment)),
        request(network={**attachment, 'managed_access': True}),
    )
    assert fields['network'] == {**attachment, 'managed_access': True}
    assert changes['network'] is True

    # keeping it: the assigned address is preserved and nothing changed
    _, fields, changes = bind_reconfigure(
        record(schema=4, network=dict(dual)),
        request(network={**attachment, 'managed_access': True}),
    )
    assert fields['network'] == dual
    assert changes['network'] is False

    # turning it off: the pair leaves the record
    _, fields, changes = bind_reconfigure(
        record(schema=4, network=dict(dual)),
        request(network={**attachment, 'managed_access': False}),
    )
    assert fields['network'] == attachment
    assert changes['network'] is True


def test_managed_pin_is_preserved_and_an_unpinned_app_is_pinned_by_any_edit():
    pinned = record(schema=4, network={'mode': 'managed', 'bridge_address': '10.88.255.254'})
    _, fields, changes = bind_reconfigure(pinned, request(network={'mode': 'managed'}))
    assert fields['network'] == {'mode': 'managed', 'bridge_address': '10.88.255.254'}
    assert changes['network'] is False and not anything_changed(changes)

    # installed before #484: an edit that changes nothing else still pins it
    _, fields, changes = bind_reconfigure(record(), request())
    assert fields['network'] == {'mode': 'managed'}
    assert changes['network'] is True and anything_changed(changes)


def test_a_record_without_catalog_provenance_binds_with_no_hash():
    byo = record(catalog=None, origin={'kind': 'byo'})
    _, fields, _ = bind_reconfigure(byo, request(compose_sha256=None))
    assert fields['ports'] == byo['ports']
    with pytest.raises(ReconfigureError, match='changed since'):
        bind_reconfigure(byo, request())


# -- the job -----------------------------------------------------------------

def service():
    middleware = Mock()
    middleware.call = AsyncMock(return_value={'name': 'sab', 'status': 'RUNNING'})
    middleware.run_in_thread = AsyncMock(return_value=True)
    svc = ApplicationsService(middleware)
    svc._require_config = AsyncMock(return_value={'pool': 'tank', 'runtime_ready': True})
    svc._get_record = Mock(return_value=record())
    svc._read_records = Mock(return_value=([record(), {'name': 'radarr', 'ports': [
        {'host_port': 17878, 'container_port': 7878, 'protocol': 'tcp'},
    ]}], []))
    svc._reserved_management_ports = AsyncMock(return_value={(80, 'tcp'), (443, 'tcp'), (22, 'tcp')})
    svc._validate_record = Mock(side_effect=lambda config, rec, name, **kw: rec)
    svc._replace_container = AsyncMock()
    svc._delete_attempted_owned_datasets = AsyncMock(return_value=[])
    return svc, middleware


@pytest.mark.asyncio
async def test_reconfigure_replaces_the_container_with_the_new_mapping_and_names_the_kept_dataset():
    svc, middleware = service()

    async def prepare_volumes(config, data, created):
        assert data['name'] == 'sab'
        assert [item['dataset'] for item in data['volumes']] == [None, 'tank/media/downloads']
        return [
            {**record()['volumes'][0]},
            {'name': 'downloads', 'target': '/downloads', 'dataset': 'tank/media/downloads',
             'source': '/mnt/tank/media/downloads', 'owned': False, 'read_only': False},
        ]
    svc._prepare_volumes = AsyncMock(side_effect=prepare_volumes)
    job = Mock()

    result = await ApplicationsService.reconfigure.wraps(svc, job, request(
        volumes=[{'name': 'config', 'dataset': None}, {'name': 'downloads', 'dataset': 'tank/media/downloads'}],
    ))

    _, config, current, new_record, health_timeout, operation = svc._replace_container.await_args.args
    assert operation == 'reconfigure' and health_timeout == 60
    assert current == record()
    assert new_record['image'] == current['image'] and new_record['image_id'] == current['image_id']
    assert new_record['container_id'] is None
    assert new_record['volumes'][1]['dataset'] == 'tank/media/downloads'
    assert new_record['environment'] == [{'name': 'API_KEY', 'value': 's3cret'}, {'name': 'PUID', 'value': '1000'}]
    assert new_record['updated_at'] != current['updated_at']
    assert result['kept_datasets'] == ['tank/applications/data/sab/downloads']
    assert result['reattached_datasets'] == [] and result['created_datasets'] == []
    assert result['application'] == {'name': 'sab', 'status': 'RUNNING'}
    # The installed image is never pulled or inspected again.
    assert not any('pull' in str(invocation) for invocation in middleware.call.await_args_list)


@pytest.mark.asyncio
async def test_reconfigure_without_a_change_touches_nothing():
    svc, middleware = service()
    # a pinned record (the internal development record): an unpinned one is pinned by any edit
    svc._get_record = Mock(return_value=record(
        schema=4, network={'mode': 'managed', 'bridge_address': '10.88.255.254'},
    ))
    svc._prepare_volumes = AsyncMock()
    result = await ApplicationsService.reconfigure.wraps(svc, Mock(), request())
    assert not anything_changed(result['changes'])
    svc._prepare_volumes.assert_not_awaited()
    svc._replace_container.assert_not_awaited()
    assert result['application'] == {'name': 'sab', 'status': 'RUNNING'}


@pytest.mark.asyncio
async def test_reconfigure_reports_a_reattached_owned_dataset_and_removes_what_it_created_on_failure():
    svc, _ = service()
    current = record()
    current['volumes'][1].update({
        'dataset': 'tank/media/downloads', 'source': '/mnt/tank/media/downloads', 'owned': False,
    })
    svc._get_record = Mock(return_value=current)

    async def prepare_volumes(config, data, created):
        # config exists already (reattached); downloads is new.
        created.append('tank/applications/data/sab/downloads')
        return [
            {**record()['volumes'][0]},
            {**record()['volumes'][1]},
        ]
    svc._prepare_volumes = AsyncMock(side_effect=prepare_volumes)

    result = await ApplicationsService.reconfigure.wraps(svc, Mock(), request())
    assert result['created_datasets'] == ['tank/applications/data/sab/downloads']
    assert result['reattached_datasets'] == []
    assert result['kept_datasets'] == []

    # A second time, with the owned dataset already there: reattached.
    svc._prepare_volumes = AsyncMock(side_effect=lambda config, data, created: [
        {**record()['volumes'][0]}, {**record()['volumes'][1]},
    ])
    result = await ApplicationsService.reconfigure.wraps(svc, Mock(), request())
    assert result['reattached_datasets'] == ['tank/applications/data/sab/downloads']
    assert result['created_datasets'] == []

    # And a replacement failure removes only what this run created (nothing here).
    svc._replace_container = AsyncMock(side_effect=CallError('health check failed'))
    with pytest.raises(CallError, match='health check failed'):
        await ApplicationsService.reconfigure.wraps(svc, Mock(), request())
    svc._delete_attempted_owned_datasets.assert_awaited_with([], {})


@pytest.mark.asyncio
async def test_reconfigure_port_rules_skip_the_ports_the_application_already_holds():
    svc, middleware = service()
    svc._prepare_volumes = AsyncMock(return_value=copy.deepcopy(record()['volumes']))
    middleware.run_in_thread = AsyncMock(return_value=False)  # every probe says "in use"

    # The held port is not probed; a new one is, and it is in use.
    await ApplicationsService.reconfigure.wraps(svc, Mock(), request(restart_policy='no'))
    middleware.run_in_thread.assert_not_awaited()
    with pytest.raises(ValidationErrors, match='already in use'):
        await ApplicationsService.reconfigure.wraps(svc, Mock(), request(
            ports=[{'host_port': 28080, 'container_port': 8080, 'protocol': 'tcp'}],
        ))
    with pytest.raises(ValidationErrors, match='assigned to a managed application'):
        await ApplicationsService.reconfigure.wraps(svc, Mock(), request(
            ports=[{'host_port': 17878, 'container_port': 8080, 'protocol': 'tcp'}],
        ))
    with pytest.raises(ValidationErrors, match='reserved'):
        await ApplicationsService.reconfigure.wraps(svc, Mock(), request(
            ports=[{'host_port': 443, 'container_port': 8080, 'protocol': 'tcp'}],
        ))


@pytest.mark.asyncio
async def test_reconfigure_refuses_a_stale_form_before_touching_anything():
    svc, _ = service()
    svc._prepare_volumes = AsyncMock()
    with pytest.raises(CallError, match='changed since this form was opened'):
        await ApplicationsService.reconfigure.wraps(svc, Mock(), request(compose_sha256='b' * 64))
    svc._prepare_volumes.assert_not_awaited()


# -- owned datasets -------------------------------------------------------------

ROWS = [
    ('tank/applications/data/sab', 1000, '/mnt/tank/applications/data/sab', 'applications:sab'),
    ('tank/applications/data/sab/config', 400, '/mnt/tank/applications/data/sab/config', 'applications:sab'),
    ('tank/applications/data/sab/downloads', 600, '/mnt/tank/applications/data/sab/downloads', 'applications:sab'),
    ('tank/applications/data/gone', 50, '/mnt/tank/applications/data/gone', 'applications:gone'),
    ('tank/applications/data/gone/config', 50, '/mnt/tank/applications/data/gone/config', 'applications:gone'),
]


def data_service(current=None):
    svc, middleware = service()
    current = current or record()
    svc._read_records = Mock(return_value=([current], []))
    svc._list_owned_datasets = AsyncMock(return_value=ROWS)
    return svc, middleware


@pytest.mark.asyncio
async def test_owned_datasets_say_what_maps_them_and_what_is_nobodys():
    current = record()
    current['volumes'][1].update({
        'dataset': 'tank/media/downloads', 'source': '/mnt/tank/media/downloads', 'owned': False,
    })
    svc, _ = data_service(current)

    sab = await ApplicationsService.owned_datasets.wraps(svc, 'sab')
    assert [(item['dataset'], item['volume'], item['parent'], item['orphan'], item['used']) for item in sab] == [
        ('tank/applications/data/sab', None, True, False, 1000),
        ('tank/applications/data/sab/config', 'config', False, False, 400),
        # The owned downloads dataset a shared mapping left behind.
        ('tank/applications/data/sab/downloads', None, False, True, 600),
    ]
    # A name without a record: what a Remove kept and a reinstall would reattach.
    gone = await ApplicationsService.owned_datasets.wraps(svc, 'gone')
    assert [(item['dataset'], item['orphan']) for item in gone] == [
        ('tank/applications/data/gone', True), ('tank/applications/data/gone/config', True),
    ]
    assert await ApplicationsService.owned_datasets.wraps(svc, 'never') == []
    orphans = await ApplicationsService.orphaned_data.wraps(svc)
    assert [item['dataset'] for item in orphans] == [
        'tank/applications/data/sab/downloads', 'tank/applications/data/gone', 'tank/applications/data/gone/config',
    ]


@pytest.mark.asyncio
async def test_prune_destroys_orphaned_data_only_when_asked_and_children_first():
    current = record()
    current['volumes'][1].update({
        'dataset': 'tank/media/downloads', 'source': '/mnt/tank/media/downloads', 'owned': False,
    })
    svc, middleware = data_service(current)
    svc._referenced_images = Mock(return_value=(set(), set()))
    svc._podman = AsyncMock(return_value=Mock(stdout='[]', returncode=0))
    svc._dataset_exists = AsyncMock(return_value=False)

    plain = await ApplicationsService.prune.wraps(svc, Mock(), {'dry_run': False, 'data': False})
    assert plain['datasets'] == [] and plain['removed'] == 0
    svc._delete_attempted_owned_datasets.assert_not_awaited()

    dry = await ApplicationsService.prune.wraps(svc, Mock(), {'dry_run': True, 'data': True})
    assert [item['dataset'] for item in dry['datasets']] == [
        'tank/applications/data/sab/downloads', 'tank/applications/data/gone', 'tank/applications/data/gone/config',
    ]
    # gone's parent (50) already includes gone/config (50): 600 + 50, not 700.
    assert dry['reclaimable'] == 650 and dry['removed'] == 0
    svc._delete_attempted_owned_datasets.assert_not_awaited()

    real = await ApplicationsService.prune.wraps(svc, Mock(), {'dry_run': False, 'data': True})
    datasets, owners = svc._delete_attempted_owned_datasets.await_args.args
    # Parents first in the list: the helper deletes in reverse, so children go first.
    assert datasets == [
        'tank/applications/data/gone', 'tank/applications/data/gone/config', 'tank/applications/data/sab/downloads',
    ]
    assert owners['tank/applications/data/gone/config'] == 'applications:gone'
    assert owners['tank/applications/data/sab/downloads'] == 'applications:sab'
    assert all(item['removed'] for item in real['datasets']) and real['removed'] == 650


# -- labels (the internal development record) --------------------------------------------------------

LABELS = [{'name': 'traefik.enable', 'value': 'true'}, {'name': 'com.example/role', 'value': 'edge'}]


def page_edit_payload(**overrides):
    """Exactly what the WebUI edit form submits (applications.component.ts submitEdit)."""
    result = request(
        labels=[{'name': 'traefik.enable', 'value': 'true'}],
        network={'mode': 'managed', 'interface': None, 'address': None, 'gateway': None,
                 'managed_access': False},
    )
    result.update(overrides)
    return result


def accepted(payload):
    """Run a payload through the public method's schema, as a real API call does.

    The job tests above call `.wraps()` and so never meet the schema -- which is how a form
    that sent `labels` to a method that did not declare it passed every test."""
    schema = ApplicationsService.reconfigure.accepts[0]
    value = schema.clean(copy.deepcopy(payload))
    schema.validate(value)
    return value


def test_the_edit_form_payload_is_accepted_by_the_public_schema():
    value = accepted(page_edit_payload())
    assert value['labels'] == [{'name': 'traefik.enable', 'value': 'true'}]
    # Every field the form sends is one the method declares: an undeclared one is refused
    # with "Field was not expected" and the whole edit fails.
    assert set(page_edit_payload()) <= set(ApplicationsService.reconfigure.accepts[0].attrs)


def test_a_caller_that_does_not_mention_labels_is_still_accepted_and_keeps_them():
    value = accepted(request())
    assert value['labels'] is None
    _, fields, changes = bind_reconfigure(record(labels=copy.deepcopy(LABELS)), value)
    assert fields['labels'] == LABELS and changes['labels'] == []


@pytest.mark.parametrize('label', [
    {'name': '-leading-dash', 'value': 'x'},
    {'name': 'has space', 'value': 'x'},
    {'name': 'a', 'value': 'line\nbreak'},
    {'name': 'a'},
])
def test_the_schema_refuses_a_malformed_label(label):
    with pytest.raises(Exception):
        accepted(page_edit_payload(labels=[label]))


def test_a_label_list_replaces_the_installed_set_and_names_what_changed():
    installed = record(labels=copy.deepcopy(LABELS))
    _, fields, changes = bind_reconfigure(installed, request(labels=[
        {'name': 'traefik.enable', 'value': 'false'},      # changed
        {'name': 'homepage.group', 'value': 'media'},      # added
    ]))                                                    # com.example/role removed
    assert fields['labels'] == [
        {'name': 'traefik.enable', 'value': 'false'}, {'name': 'homepage.group', 'value': 'media'},
    ]
    assert changes['labels'] == ['com.example/role', 'homepage.group', 'traefik.enable']
    assert anything_changed(changes)


def test_an_empty_list_removes_every_label_and_the_same_set_is_no_change():
    pinned = dict(schema=4, network={'mode': 'managed', 'bridge_address': '10.88.255.254'})
    installed = record(labels=copy.deepcopy(LABELS), **pinned)
    _, fields, changes = bind_reconfigure(installed, request(labels=[]))
    assert fields['labels'] == [] and changes['labels'] == ['com.example/role', 'traefik.enable']
    assert anything_changed(changes)

    # the same labels in another order are the same set
    _, fields, changes = bind_reconfigure(installed, request(labels=list(reversed(copy.deepcopy(LABELS)))))
    assert changes['labels'] == [] and not anything_changed(changes)


def test_a_record_from_before_labels_existed_can_be_given_some():
    old = record()
    assert 'labels' not in old
    _, fields, changes = bind_reconfigure(old, request(labels=copy.deepcopy(LABELS)))
    assert fields['labels'] == LABELS
    assert changes['labels'] == ['com.example/role', 'traefik.enable']


@pytest.mark.parametrize('labels,message', [
    ([{'name': 'io.freecore.managed', 'value': 'false'}], 'reserved'),
    ([{'name': 'io.freecore.application', 'value': 'other'}], 'reserved'),
    ([{'name': 'a', 'value': '1'}, {'name': 'a', 'value': '2'}], 'unique'),
    ([{'name': 'a', 'value': 'x' * 4097}], '4096 bytes'),
    ([{'name': f'key{index}', 'value': 'x'} for index in range(129)], 'at most 128'),
])
def test_an_edit_cannot_set_a_reserved_duplicate_or_oversized_label(labels, message):
    with pytest.raises(ReconfigureError, match=message):
        bind_reconfigure(record(), request(labels=labels))


@pytest.mark.asyncio
async def test_a_label_only_edit_replaces_the_container_with_the_new_labels():
    svc, middleware = service()
    # pinned, so the label is the ONLY change
    svc._get_record = Mock(return_value=record(
        schema=4, network={'mode': 'managed', 'bridge_address': '10.88.255.254'},
    ))
    svc._prepare_volumes = AsyncMock(return_value=copy.deepcopy(record()['volumes']))

    result = await ApplicationsService.reconfigure.wraps(svc, Mock(), accepted(page_edit_payload()))

    svc._replace_container.assert_awaited_once()
    _, _, current, new_record, _, operation = svc._replace_container.await_args.args
    assert operation == 'reconfigure'
    assert new_record['labels'] == [{'name': 'traefik.enable', 'value': 'true'}]
    assert new_record['image_id'] == current['image_id']
    assert result['changes']['labels'] == ['traefik.enable']


@pytest.mark.asyncio
async def test_an_edit_that_does_not_mention_labels_carries_the_installed_ones_over():
    svc, middleware = service()
    svc._get_record = Mock(return_value=record(labels=copy.deepcopy(LABELS)))
    svc._prepare_volumes = AsyncMock(return_value=copy.deepcopy(record()['volumes']))

    await ApplicationsService.reconfigure.wraps(svc, Mock(), accepted(request(
        ports=[{'host_port': 18081, 'container_port': 8080, 'protocol': 'tcp'}],
    )))

    new_record = svc._replace_container.await_args.args[3]
    assert new_record['labels'] == LABELS and new_record['ports'][0]['host_port'] == 18081


# -- ports kept on the managed bridge (the internal development record) ---------------------------------

def test_a_port_can_be_kept_on_the_bridge_and_published_again():
    bridge_only = [{'host_port': None, 'container_port': 8080, 'protocol': 'tcp'}]
    _, fields, changes = bind_reconfigure(record(portal=None), request(ports=bridge_only))
    assert fields['ports'] == bridge_only
    assert fields['healthcheck']['host_port'] is None
    assert changes['ports'] == [{'container_port': 8080, 'protocol': 'tcp', 'from': 18080, 'to': None}]
    assert anything_changed(changes)

    unpublished = record(portal=None, ports=bridge_only, healthcheck={
        **record()['healthcheck'], 'host_port': None,
    })
    _, fields, changes = bind_reconfigure(unpublished, request())
    assert fields['healthcheck']['host_port'] == 18080
    assert changes['ports'] == [{'container_port': 8080, 'protocol': 'tcp', 'from': None, 'to': 18080}]


def test_the_portal_port_stays_published():
    with pytest.raises(ReconfigureError, match='8080/tcp opens the application.*must stay published'):
        bind_reconfigure(record(), request(ports=[
            {'host_port': None, 'container_port': 8080, 'protocol': 'tcp'},
        ]))


def test_the_public_schema_accepts_a_null_host_port_and_still_requires_the_key():
    value = accepted(request(ports=[{'host_port': None, 'container_port': 8080, 'protocol': 'tcp'}]))
    assert value['ports'][0]['host_port'] is None
    with pytest.raises(Exception):
        accepted(request(ports=[{'container_port': 8080, 'protocol': 'tcp'}]))
