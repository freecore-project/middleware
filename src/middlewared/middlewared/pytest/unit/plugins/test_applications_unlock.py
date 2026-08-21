# the internal development record: an always-restart application whose external dataset was locked at boot starts once the
# dataset is unlocked, and a start against a locked or unmounted dataset says so instead of the OCI runtime's advice.
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from middlewared.plugins import applications_freebsd
from middlewared.plugins.applications_freebsd import ApplicationsService
from middlewared.service_exception import CallError


def external(dataset, source=None):
    return {'name': 'data', 'dataset': dataset, 'source': source or f'/mnt/{dataset}', 'owned': False}


OWNED = {'name': 'config', 'dataset': 'tank/applications/data/x/config',
         'source': '/mnt/tank/applications/data/x/config', 'owned': True}


@pytest.fixture
def unlocked():
    records = [
        {'name': 'vaultweb', 'restart_policy': 'always',
         'volumes': [OWNED, external('vault/appdata', '/mnt/vault/appdata/html')]},
        {'name': 'manual', 'restart_policy': 'no', 'volumes': [external('vault/appdata')]},
        {'name': 'running', 'restart_policy': 'always', 'volumes': [external('vault')]},
        {'name': 'elsewhere', 'restart_policy': 'always', 'volumes': [external('tank/media')]},
        {'name': 'parent', 'restart_policy': 'always', 'volumes': [external('vault')]},
    ]
    running = {'vaultweb': False, 'manual': False, 'running': True, 'elsewhere': False, 'parent': False}
    started = []

    async def call(method, *args):
        assert method == 'applications.start', method
        started.append(args[0])
        return SimpleNamespace(wait=AsyncMock())

    service = ApplicationsService(Mock(call=AsyncMock(side_effect=call)))
    service.config = AsyncMock(return_value={'pool': 'tank', 'runtime_ready': True})
    service._read_records = Mock(return_value=(records, []))
    service._pool_transition = Mock(return_value=None)

    async def inspect(config, wanted, bounded=True):
        return {
            record['name']: ({'State': {'Running': running[record['name']]}}, record['name'] * 4) for record in wanted
        }

    service._inspect_managed_containers = AsyncMock(side_effect=inspect)
    return service, started


@pytest.mark.asyncio
async def test_unlock_starts_only_stopped_always_apps_on_the_unlocked_datasets(unlocked):
    service, started = unlocked

    assert await service.start_after_unlock(['vault/appdata']) == ['vaultweb', 'parent']
    # 'manual' is not restart-always, 'running' already runs, 'elsewhere' mounts another pool's dataset;
    # 'parent' mounts vault itself, so the child that came back is under its mount.
    assert started == ['vaultweb', 'parent']
    # the internal development record: a start that nothing replays waits for podman instead of taking the busy answer
    assert service._inspect_managed_containers.await_args.kwargs == {'bounded': False}


@pytest.mark.asyncio
@pytest.mark.parametrize('config,transition', [
    ({'pool': None, 'runtime_ready': False}, None),
    ({'pool': 'tank', 'runtime_ready': False}, None),
    ({'pool': 'tank', 'runtime_ready': True}, {'records': []}),
])
async def test_unlock_does_nothing_without_a_ready_store(unlocked, config, transition):
    service, started = unlocked
    service.config.return_value = config
    service._pool_transition.return_value = transition

    assert await service.start_after_unlock(['vault/appdata']) == []
    assert started == []


@pytest.mark.asyncio
async def test_a_start_that_fails_is_logged_and_the_rest_still_start(unlocked):
    service, started = unlocked

    async def call(method, name):
        started.append(name)
        return SimpleNamespace(wait=AsyncMock(side_effect=CallError('boom') if name == 'vaultweb' else None))

    service.middleware.call.side_effect = call
    service.logger = Mock()
    assert await service.start_after_unlock(['vault/appdata']) == ['parent']
    service.logger.warning.assert_called_once()


@pytest.mark.asyncio
async def test_the_hook_waits_for_system_ready():
    middleware = Mock()
    middleware.call = AsyncMock(return_value=False)
    await applications_freebsd._datasets_post_unlock(middleware, [{'name': 'vault/appdata'}])
    middleware.call.assert_awaited_once_with('system.ready')

    middleware.call = AsyncMock(return_value=True)
    await applications_freebsd._datasets_post_unlock(middleware, [{'name': 'vault/appdata'}, {'name': None}])
    middleware.call.assert_awaited_with('applications.start_after_unlock', ['vault/appdata'])


@pytest.mark.asyncio
@pytest.mark.parametrize('zfs_out,message', [
    ('vault/appdata\tkeystatus\tavailable\nvault/appdata\tmounted\tyes\n', None),
    ('vault/appdata\tkeystatus\t-\nvault/appdata\tmounted\tyes\n', None),
    ('vault/appdata\tkeystatus\tunavailable\nvault/appdata\tmounted\tno\n', 'Dataset vault/appdata is locked'),
    ('vault/appdata\tkeystatus\t-\nvault/appdata\tmounted\tno\n', 'Dataset vault/appdata is not mounted'),
    ('', 'Dataset vault/appdata used by application .vaultweb. does not exist'),
])
async def test_a_start_names_a_locked_or_missing_external_dataset(zfs_out, message):
    service = ApplicationsService(Mock())
    record = {'name': 'vaultweb', 'volumes': [OWNED, external('vault/appdata')]}
    zfs = AsyncMock(return_value=SimpleNamespace(stdout=zfs_out, returncode=0 if zfs_out else 1))
    with patch.object(applications_freebsd, 'run', zfs):
        if message is None:
            await service._require_external_datasets(record)
        else:
            with pytest.raises(CallError, match=message):
                await service._require_external_datasets(record)
    # Only the external dataset is asked about, never the owned ones.
    assert zfs.await_args.args[0][-1] == 'vault/appdata'
    assert 'tank/applications/data/x/config' not in zfs.await_args.args[0]


@pytest.mark.asyncio
async def test_an_app_without_external_datasets_asks_zfs_nothing():
    service = ApplicationsService(Mock())
    zfs = AsyncMock()
    with patch.object(applications_freebsd, 'run', zfs):
        await service._require_external_datasets({'name': 'x', 'volumes': [OWNED]})
    zfs.assert_not_awaited()
