"""the internal development record: applications.unconfigure and the cascading pool deletion.

The refusal an administrator met before this change — "Applications storage or
dataset references must be removed explicitly" — pointed at a removal that did
not exist. These tests pin the removal that now does: what it refuses, the order
in which it takes things apart, what a partial failure leaves behind, and the
row it writes so a later configure starts like a fresh install.
"""
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call, patch

import pytest

from middlewared.plugins.applications_.utils import application_paths
from middlewared.plugins.applications_freebsd import (
    UNCONFIGURED_SETTINGS,
    ApplicationsFSAttachmentDelegate,
    ApplicationsService,
)
from middlewared.service_exception import CallError


PATHS = application_paths('tank')
CONFIGURED = {
    'id': 1, 'pool': 'tank', 'subnet': '10.89.0.0/16', 'restart_on_boot': True,
    'runtime_ready': True, 'pf_owned': True, 'filter_local_original': 0,
    'ipv4_forwarding_original': 0, 'bridge_pfil_member_original': 0,
    'linux_compat_enabled': True, 'convert_enabled': True,
}
UNCONFIGURED = {**CONFIGURED, **UNCONFIGURED_SETTINGS, 'runtime_ready': False}


def record(name):
    return {'name': name, 'container_id': name[0] * 64, 'restart_policy': 'always', 'volumes': []}


@pytest.fixture
def configured():
    """A configured, ready appliance with two applications and the seams the
    lifecycle touches recorded in one event list."""
    middleware = Mock(call=AsyncMock())
    service = ApplicationsService(middleware)
    state = {'config': dict(CONFIGURED), 'records': [record('second'), record('first')]}
    events = []

    async def get_config():
        return dict(state['config'])

    async def datastore_update(method, *args):
        if method == 'datastore.update':
            state['config'].update(args[2])
            events.append(('settings', args[2]))
        elif method == 'etc.generate':
            events.append(('etc', args[0]))
        elif method == 'zfs.dataset.delete':
            events.append(('destroy', args[0], args[1]))
        return None

    async def remove_impl(config, item, app_dataset, remove_dataset):
        events.append(('remove', item['name'], remove_dataset))
        state['records'] = [r for r in state['records'] if r['name'] != item['name']]

    async def teardown(config, *, stop=True):
        events.append(('teardown', stop))
        state['config']['runtime_ready'] = False
        return True

    middleware.call.side_effect = datastore_update
    service.config = AsyncMock(side_effect=get_config)
    service._validate_application_store = AsyncMock()
    service._read_records = Mock(side_effect=lambda config: (list(state['records']), []))
    service._remove_impl = AsyncMock(side_effect=remove_impl)
    service._runtime_teardown_impl = AsyncMock(side_effect=teardown)
    service._dataset_exists = AsyncMock(return_value=True)
    service._dataset_owner = AsyncMock(side_effect=lambda dataset: dict(
        service._application_dataset_specs('tank')).get(dataset, f'applications:{dataset.rsplit("/", 1)[-1]}'))
    service._owned_tree = AsyncMock(side_effect=lambda dataset, owner: [dataset])
    # the internal development record: what the store still holds under data/ with no record
    # mapping it; [] unless a test plants orphans.
    service._list_owned_datasets = AsyncMock(return_value=[])
    state['bridge'] = None  # ifconfig output of cni-podman0, None = absent

    async def ifconfig(arguments, check=True, encoding=None):
        if arguments[:2] == ['ifconfig', 'cni-podman0'] and len(arguments) == 2:
            if state['bridge'] is None:
                return SimpleNamespace(returncode=1, stdout='', stderr='ifconfig: interface cni-podman0 does not exist')
            return SimpleNamespace(returncode=0, stdout=state['bridge'], stderr='')
        if arguments == ['ifconfig', 'cni-podman0', 'destroy']:
            events.append(('bridge', 'destroy'))
            state['bridge'] = None
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        raise AssertionError(f'unexpected command {arguments}')

    run_patch = patch('middlewared.plugins.applications_freebsd.run', AsyncMock(side_effect=ifconfig))
    run_patch.start()
    yield service, middleware, state, events
    run_patch.stop()


@pytest.mark.asyncio
async def test_unconfigure_is_inert_when_applications_was_never_configured(configured):
    service, middleware, state, events = configured
    state['config'].update(UNCONFIGURED_SETTINGS)
    with patch('middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()) as pf:
        result = await service.unconfigure(Mock(), {})
    assert result['pool'] is None
    assert events == []
    middleware.call.assert_not_awaited()
    pf.assert_not_awaited()


@pytest.mark.asyncio
async def test_unconfigure_refuses_installed_applications_unless_asked_and_touches_nothing(configured):
    service, middleware, state, events = configured
    with pytest.raises(CallError, match=r'remove_applications: first, second\.'):
        await service.unconfigure(Mock(), {})
    assert events == []
    middleware.call.assert_not_awaited()
    assert state['config'] == CONFIGURED


@pytest.mark.asyncio
async def test_unconfigure_refuses_invalid_records_and_an_unready_runtime_before_removing(configured):
    service, middleware, state, events = configured
    service._read_records.side_effect = lambda config: ([], [{'name': 'broken', 'error': 'invalid'}])
    with pytest.raises(CallError, match='unsafe'):
        await service.unconfigure(Mock(), {'remove_applications': True})
    service._read_records.side_effect = lambda config: (list(state['records']), [])
    state['config']['runtime_ready'] = False
    with pytest.raises(CallError, match='runtime is not ready'):
        await service.unconfigure(Mock(), {'remove_applications': True})
    assert events == []
    middleware.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_unconfigure_removes_applications_then_runtime_then_settings_then_the_store(configured):
    service, middleware, state, events = configured
    state['bridge'] = 'cni-podman0: flags=1008843<UP,BROADCAST,RUNNING> mtu 1500\n\tinet 10.88.0.1 netmask 0xffff0000\n'
    with patch('middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()) as pf:
        result = await service.unconfigure(Mock(), {'remove_applications': True})

    specs = service._application_dataset_specs('tank')
    assert events == [
        # applications first, by name, with their data, as applications.remove would
        ('remove', 'first', True),
        ('remove', 'second', True),
        # then the runtime, fail-closed, before anything is forgotten
        ('teardown', True),
        # then podman's empty bridge, whose route would otherwise claim the subnet
        ('bridge', 'destroy'),
        # then the never-configured row, and the rc/PF state that follows from it
        ('settings', UNCONFIGURED_SETTINGS),
        ('etc', 'rc'),
        # then the store: podman's layer tree under storage recursively, the rest one by
        # one and children first, the parent last
        ('destroy', PATHS['storage_dataset'], {'force': True, 'recursive': True}),
        ('destroy', PATHS['data_dataset'], {'force': True, 'recursive': False}),
        ('destroy', PATHS['records_dataset'], {'force': True, 'recursive': False}),
        ('destroy', PATHS['config_dataset'], {'force': True, 'recursive': False}),
        ('destroy', PATHS['dataset'], {'force': True, 'recursive': False}),
    ]
    assert [dataset for dataset, _ in specs] == [
        PATHS['dataset'], PATHS['storage_dataset'], PATHS['config_dataset'],
        PATHS['records_dataset'], PATHS['data_dataset'],
    ]
    pf.assert_awaited_once()
    service._owned_tree.assert_has_awaits([
        call(f'{PATHS["data_dataset"]}/first', 'applications:first'),
        call(f'{PATHS["data_dataset"]}/second', 'applications:second'),
    ])
    assert result == UNCONFIGURED
    assert result['pool'] is None and result['runtime_ready'] is False
    assert service._pool_transition() is None


@pytest.mark.asyncio
async def test_unconfigure_with_keep_data_leaves_the_store_and_application_datasets(configured):
    service, middleware, state, events = configured
    with patch('middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()):
        result = await service.unconfigure(Mock(), {'remove_applications': True, 'keep_data': True})
    assert events == [
        ('remove', 'first', False), ('remove', 'second', False),
        ('teardown', True), ('settings', UNCONFIGURED_SETTINGS), ('etc', 'rc'),
    ]
    service._owned_tree.assert_not_awaited()
    assert result['pool'] is None


@pytest.mark.asyncio
async def test_unconfigure_without_applications_needs_no_ready_runtime(configured):
    service, middleware, state, events = configured
    state['records'] = []
    state['config']['runtime_ready'] = False
    with patch('middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()):
        result = await service.unconfigure(Mock(), {})
    assert events[:3] == [('teardown', True), ('settings', UNCONFIGURED_SETTINGS), ('etc', 'rc')]
    assert [event for event in events if event[0] == 'destroy']
    assert result['pool'] is None


@pytest.mark.asyncio
async def test_failed_runtime_teardown_keeps_the_pool_selected(configured):
    service, middleware, state, events = configured
    state['records'] = []
    service._runtime_teardown_impl.side_effect = CallError('Applications teardown was incomplete')
    with patch('middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()) as pf:
        with pytest.raises(CallError, match='incomplete'):
            await service.unconfigure(Mock(), {})
    assert state['config']['pool'] == 'tank'
    assert not [event for event in events if event[0] in ('settings', 'destroy')]
    pf.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_store_that_cannot_go_completely_is_reported_after_the_settings_are_forgotten(configured):
    service, middleware, state, events = configured
    state['records'] = []
    service._dataset_owner = AsyncMock(side_effect=lambda dataset: (
        'someone-else' if dataset == PATHS['records_dataset']
        else dict(service._application_dataset_specs('tank'))[dataset]))
    with patch('middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()):
        with pytest.raises(CallError, match=r"unconfigured, but its store was not fully removed.*records.*someone-else"):
            await service.unconfigure(Mock(), {})
    assert state['config']['pool'] is None
    destroyed = [event[1] for event in events if event[0] == 'destroy']
    assert PATHS['records_dataset'] not in destroyed
    assert PATHS['data_dataset'] in destroyed and PATHS['storage_dataset'] in destroyed


def orphan_rows(*specs):
    """``_list_owned_datasets`` rows for orphan trees: ``(application, [volumes])``."""
    rows = []
    for application, volumes in specs:
        parent = f'{PATHS["data_dataset"]}/{application}'
        rows.append((parent, 1024, f'/mnt/{parent}', f'applications:{application}'))
        rows.extend(
            (f'{parent}/{volume}', 512, f'/mnt/{parent}/{volume}', f'applications:{application}')
            for volume in volumes
        )
    return rows


# the internal development record: the data an earlier keep-data unconfigure (or a Remove
# without its data) left under the store is what keep_data: false is asked to
# delete; without this step the store's parent could never go.
@pytest.mark.asyncio
async def test_unconfigure_without_keep_data_removes_orphaned_application_data_before_the_store(configured):
    service, middleware, state, events = configured
    state['records'] = []
    state['config']['runtime_ready'] = False
    service._list_owned_datasets.return_value = orphan_rows(('gone', ['config', 'data']), ('other', []))
    trees = {
        f'{PATHS["data_dataset"]}/gone': [
            f'{PATHS["data_dataset"]}/gone', f'{PATHS["data_dataset"]}/gone/config',
            f'{PATHS["data_dataset"]}/gone/data',
        ],
        f'{PATHS["data_dataset"]}/other': [f'{PATHS["data_dataset"]}/other'],
    }
    service._owned_tree = AsyncMock(side_effect=lambda dataset, owner: list(trees[dataset]))
    specs = dict(service._application_dataset_specs('tank'))
    prefix = PATHS['data_dataset'] + '/'
    # every dataset of a tree carries its application's ownership, volumes included
    service._dataset_owner = AsyncMock(side_effect=lambda dataset: specs.get(
        dataset, f"applications:{dataset[len(prefix):].split('/')[0]}"))
    with patch('middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()):
        result = await service.unconfigure(Mock(), {})

    service._list_owned_datasets.assert_awaited_once_with(PATHS['data_dataset'])
    # every orphan tree is re-verified as owned by its application right before deletion
    service._owned_tree.assert_has_awaits([
        call(f'{PATHS["data_dataset"]}/gone', 'applications:gone'),
        call(f'{PATHS["data_dataset"]}/other', 'applications:other'),
    ])
    destroyed = [event[1:] for event in events if event[0] == 'destroy']
    assert destroyed[:4] == [
        # each tree one dataset at a time, children first, never recursively
        (f'{PATHS["data_dataset"]}/gone/data', {'force': True, 'recursive': False}),
        (f'{PATHS["data_dataset"]}/gone/config', {'force': True, 'recursive': False}),
        (f'{PATHS["data_dataset"]}/gone', {'force': True, 'recursive': False}),
        (f'{PATHS["data_dataset"]}/other', {'force': True, 'recursive': False}),
    ]
    # and only then the store itself, exactly as before
    assert [dataset for dataset, _ in destroyed[4:]] == [
        PATHS['storage_dataset'], PATHS['data_dataset'], PATHS['records_dataset'],
        PATHS['config_dataset'], PATHS['dataset'],
    ]
    assert result['pool'] is None


@pytest.mark.asyncio
async def test_an_orphan_tree_with_an_unowned_member_is_refused_and_reported(configured):
    service, middleware, state, events = configured
    state['records'] = []
    state['config']['runtime_ready'] = False
    service._list_owned_datasets.return_value = orphan_rows(('gone', []), ('foreign', ['keep']))

    async def owned_tree(dataset, owner):
        if dataset.endswith('/foreign'):
            raise CallError(f"Refusing to remove {dataset!r}; {dataset + '/keep'!r} is not owned by this application.")
        return [dataset]
    service._owned_tree = AsyncMock(side_effect=owned_tree)
    # the parent of a tree that could not go is refused by ZFS, as in life
    original_call = middleware.call.side_effect

    async def zfs(method, *args):
        if method == 'zfs.dataset.delete' and args[0] == PATHS['data_dataset']:
            raise CallError(f"cannot destroy '{args[0]}': filesystem has children")
        return await original_call(method, *args)
    middleware.call.side_effect = zfs
    with patch('middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()):
        with pytest.raises(CallError) as excinfo:
            await service.unconfigure(Mock(), {})

    message = str(excinfo.value)
    assert 'unconfigured, but its store was not fully removed' in message
    assert 'not owned by this application' in message and 'foreign/keep' in message
    assert 'filesystem has children' in message
    destroyed = [event[1] for event in events if event[0] == 'destroy']
    assert f'{PATHS["data_dataset"]}/gone' in destroyed
    assert not any(dataset.endswith('/foreign') for dataset in destroyed)
    # settings are forgotten regardless, as before: the refusal is about the store only
    assert state['config']['pool'] is None


@pytest.mark.asyncio
async def test_keep_data_never_looks_at_orphaned_application_data(configured):
    service, middleware, state, events = configured
    with patch('middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()):
        await service.unconfigure(Mock(), {'remove_applications': True, 'keep_data': True})
    service._list_owned_datasets.assert_not_awaited()


@pytest.mark.asyncio
async def test_deactivate_pool_is_inert_for_another_pool_and_refuses_during_a_transition(configured):
    service, middleware, state, events = configured
    assert await service.deactivate_pool('backup') is False
    service._export_state = {'config': {}, 'records': [], 'running': {}, 'guid': '1'}
    with pytest.raises(CallError, match='transition'):
        await service.deactivate_pool('tank')
    assert events == []
    middleware.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_deactivate_pool_stops_the_runtime_and_forgets_the_settings_but_keeps_the_datasets(configured):
    service, middleware, state, events = configured
    with patch('middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()) as pf:
        assert await service.deactivate_pool('tank') is True
    # the records stay: a cascading export leaves the store for a later configure
    assert events == [('teardown', True), ('settings', UNCONFIGURED_SETTINGS), ('etc', 'rc')]
    service._remove_impl.assert_not_awaited()
    pf.assert_awaited_once()
    assert state['config']['pool'] is None


@pytest.mark.asyncio
async def test_cascading_deletion_of_the_store_deactivates_and_children_or_references_still_refuse():
    middleware = Mock(call=AsyncMock())
    delegate = ApplicationsFSAttachmentDelegate(middleware)
    store = [{'id': 'applications:store', 'name': 'Applications', 'pool': 'tank'}]
    child = [{'id': 'applications:store-child', 'name': 'Applications storage', 'pool': 'tank',
              'protected': True}]
    external = [{'id': 'applications:first:data', 'name': 'first: tank/data', 'pool': 'tank',
                 'protected': True}]
    with pytest.raises(CallError, match='Unconfigure Applications'):
        await delegate.delete(child)
    with pytest.raises(CallError, match='referenced by installed applications'):
        await delegate.delete(external)
    await delegate.delete([])
    middleware.call.assert_not_awaited()
    await delegate.delete(store)
    middleware.call.assert_awaited_once_with('applications.deactivate_pool', 'tank')


@pytest.mark.asyncio
async def test_a_bridge_that_still_carries_members_keeps_the_pool_selected(configured):
    service, middleware, state, events = configured
    state['records'] = []
    state['bridge'] = ('cni-podman0: flags=1008843<UP,BROADCAST,RUNNING> mtu 1500\n'
                       '\tinet 10.88.0.1 netmask 0xffff0000\n\tmember: veth1a flags=143<LEARNING>\n')
    with patch('middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()):
        with pytest.raises(CallError, match='still has member interfaces'):
            await service.unconfigure(Mock(), {})
    assert events == [('teardown', True)]
    assert state['config']['pool'] == 'tank'
    assert state['bridge'] is not None


@pytest.mark.asyncio
async def test_deactivate_pool_removes_an_empty_bridge_before_forgetting(configured):
    service, middleware, state, events = configured
    state['bridge'] = 'cni-podman0: flags=1008843<UP,BROADCAST,RUNNING> mtu 1500\n'
    with patch('middlewared.plugins.applications_freebsd._generate_pf_checked', AsyncMock()):
        assert await service.deactivate_pool('tank') is True
    assert events == [('teardown', True), ('bridge', 'destroy'), ('settings', UNCONFIGURED_SETTINGS), ('etc', 'rc')]
