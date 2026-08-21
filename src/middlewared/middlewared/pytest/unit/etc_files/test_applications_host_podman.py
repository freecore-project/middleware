"""the internal development record: the host's podman finds the Applications store as root.

The two files under /usr/local/etc/containers follow the Applications runtime state
exactly as the rc.conf podman lines do, through the same `rc` etc group: the pool's
storage.conf and containers.conf, byte for byte, while the runtime marker is set;
the package sample (storage) and no file (the drop-in) otherwise.
"""
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from middlewared.plugins.applications_ import utils
from middlewared.plugins.applications_.utils import render_containers_conf, render_storage_conf
from middlewared.plugins.etc import EtcService, FileShouldNotExist, PyRenderer

FILES_DIR = Path(__file__).parents[3] / 'etc_files'
STORAGE_CONF = 'local/containers/storage.conf'
DROPIN = 'local/containers/containers.conf.d/50-freecore-applications.conf'
SAMPLE = '# containers-common sample\n[storage]\ndriver = "zfs"\ngraphroot = "/var/db/containers/storage"\n'


class HostPodmanMiddleware:

    def __init__(self, pool='tank', subnet='10.88.0.0/16', runtime_ready=True):
        self.config = {'pool': pool, 'subnet': subnet, 'runtime_ready': runtime_ready}
        self.calls = []

    def call_sync(self, name, *args):
        self.calls.append((name, args))
        assert name == 'applications.config'
        assert not args
        return self.config

    async def run_in_thread(self, method, *args):
        return method(*args)


class HostPodmanService:

    def __init__(self, middleware):
        self.middleware = middleware


async def render(path, middleware):
    return await PyRenderer(HostPodmanService(middleware)).render(str(FILES_DIR / path), None)


@pytest.fixture
def runtime(tmp_path):
    """The marker and the package sample live under tmp_path; both start present."""
    marker = tmp_path / 'ready'
    marker.write_text('ready\n')
    sample = tmp_path / 'storage.conf.sample'
    sample.write_text(SAMPLE)
    with patch.object(utils, 'RUNTIME_READY', str(marker)), \
            patch.object(utils, 'HOST_STORAGE_CONF_SAMPLE', str(sample)):
        yield {'marker': marker, 'sample': sample}


def test_rc_group_renders_the_host_podman_configuration_beside_rc_conf():
    entries = EtcService.GROUPS['rc']
    paths = [entry['path'] for entry in entries]

    assert paths.index('rc.conf') < paths.index(STORAGE_CONF) < paths.index(DROPIN)
    for path in (STORAGE_CONF, DROPIN):
        entry = entries[paths.index(path)]
        assert entry['type'] == 'py'
        assert entry['platform'] == 'FreeBSD'
        assert os.path.isfile(FILES_DIR / f'{path}.py'), f'{path}.py is missing from etc_files'


async def test_host_storage_conf_is_the_pool_store_while_the_runtime_is_ready(runtime):
    middleware = HostPodmanMiddleware()

    rendered = await render(STORAGE_CONF, middleware)

    assert rendered == render_storage_conf('tank')
    assert 'graphroot = "/mnt/tank/applications/storage"' in rendered
    assert middleware.calls == [('applications.config', ())]


async def test_host_containers_dropin_is_the_pool_network_while_the_runtime_is_ready(runtime):
    rendered = await render(DROPIN, HostPodmanMiddleware(subnet='10.99.0.0/16'))

    assert rendered == render_containers_conf('tank', '10.99.0.0/16')
    assert 'network_config_dir = "/mnt/tank/applications/config/cni/net.d"' in rendered
    assert 'events_logfile_path = "/mnt/tank/applications/records/events.log"' in rendered


@pytest.mark.parametrize('middleware', [
    pytest.param(HostPodmanMiddleware(pool=None, runtime_ready=False), id='no-pool'),
    pytest.param(HostPodmanMiddleware(runtime_ready=False), id='pool-without-marker'),
])
async def test_host_storage_conf_returns_to_the_package_sample_when_not_ready(runtime, middleware):
    runtime['marker'].unlink()

    assert await render(STORAGE_CONF, middleware) == SAMPLE


async def test_host_storage_conf_is_absent_without_a_package_sample(runtime):
    runtime['marker'].unlink()
    runtime['sample'].unlink()

    with pytest.raises(FileShouldNotExist):
        await render(STORAGE_CONF, HostPodmanMiddleware(pool=None, runtime_ready=False))


@pytest.mark.parametrize('middleware', [
    pytest.param(HostPodmanMiddleware(pool=None, runtime_ready=False), id='no-pool'),
    pytest.param(HostPodmanMiddleware(runtime_ready=False), id='pool-without-marker'),
])
async def test_host_containers_dropin_is_removed_when_not_ready(runtime, middleware):
    runtime['marker'].unlink()

    with pytest.raises(FileShouldNotExist):
        await render(DROPIN, middleware)


async def test_a_pool_transition_does_not_hide_a_ready_runtime(runtime):
    """pool_available regenerates rc from inside the transition, when config['runtime_ready']
    is still False although the marker is set; the host configuration follows the marker."""
    middleware = HostPodmanMiddleware(runtime_ready=False)

    assert await render(STORAGE_CONF, middleware) == render_storage_conf('tank')
    assert await render(DROPIN, middleware) == render_containers_conf('tank', '10.88.0.0/16')


async def test_host_files_match_what_middleware_writes_on_the_pool(runtime):
    """Byte identity with the pool files is the contract: with both the environment and the
    system configuration in effect, middleware's podman and the host's read the same values."""
    middleware = HostPodmanMiddleware(pool='data', subnet='10.90.0.0/16')

    assert await render(STORAGE_CONF, middleware) == render_storage_conf('data')
    assert await render(DROPIN, middleware) == render_containers_conf('data', '10.90.0.0/16')
    assert utils.podman_environment('data') == {
        'CONTAINERS_STORAGE_CONF': '/mnt/data/applications/config/storage.conf',
        'CONTAINERS_CONF_OVERRIDE': '/mnt/data/applications/config/containers.conf',
    }
