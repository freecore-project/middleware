"""The experimental flags, the Linux image tier and the second install tier
(the internal development record, #444, #434)."""
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call, patch

import pytest

from middlewared.plugins.applications_.registry import image_refusals
from middlewared.plugins.applications_freebsd import ApplicationsService
from middlewared.service_exception import CallError, ValidationErrors


def service_with_middleware():
    middleware = Mock()
    middleware.call = AsyncMock()
    middleware.run_in_thread = AsyncMock()
    service = ApplicationsService(middleware)
    return service, middleware


def config(**overrides):
    result = {
        'id': 1, 'pool': 'tank', 'subnet': '10.88.0.0/16', 'restart_on_boot': False,
        'runtime_ready': True, 'pf_owned': False, 'linux_compat_enabled': False,
        'convert_enabled': False,
    }
    result.update(overrides)
    return result


def completed(returncode=0, stdout='', stderr=''):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def record(**overrides):
    result = {
        'schema': 3,
        'image_os': 'freebsd',
        'origin': None,
        'name': 'demo',
        'container_name': 'freecore-app-demo',
        'container_id': '1' * 64,
        'image': 'registry.example/demo:1',
        'image_id': 'sha256:abcdef',
        'digest': 'sha256:' + 'a' * 64,
        'ports': [],
        'environment': [],
        'volumes': [],
        'annotations': [],
        'restart_policy': 'always',
        'portal': None,
        'healthcheck': None,
        'created_at': '2026-09-13T00:00:00+00:00',
        'updated_at': '2026-09-13T00:00:00+00:00',
    }
    result.update(overrides)
    return result


# -- flags --------------------------------------------------------------------

@pytest.mark.asyncio
async def test_flags_off_leave_configure_without_side_effects():
    service, middleware = service_with_middleware()
    await service._apply_experimental_flags(Mock(), config(), {'pool': 'tank', 'subnet': '10.88.0.0/16'})
    middleware.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_enabling_linux_compat_owns_rc_runs_the_service_and_proves_the_module():
    service, middleware = service_with_middleware()
    service._sysctl = AsyncMock(return_value='5.15.0')
    job = Mock()
    with patch('middlewared.plugins.applications_freebsd.run', AsyncMock(return_value=completed())) as run:
        await service._apply_experimental_flags(job, config(), {
            'pool': 'tank', 'subnet': '10.88.0.0/16', 'linux_compat_enabled': True, 'convert_enabled': True,
        })

    middleware.call.assert_has_awaits([
        call('datastore.update', 'services.applications', 1,
             {'convert_enabled': True, 'linux_compat_enabled': True}, {'prefix': 'app_'}),
        call('etc.generate', 'rc'),
    ])
    run.assert_has_awaits([
        call(['service', 'linux', 'start'], check=False, encoding='utf8'),
        call(['kldstat', '-q', '-m', 'linux64elf'], check=False, encoding='utf8'),
    ])
    service._sysctl.assert_awaited_with('compat.linux.osrelease')


@pytest.mark.asyncio
async def test_enabling_linux_compat_reverts_when_the_elf_module_does_not_load():
    """15.1-RC2 as shipped: linux_common loads (so the osrelease sysctl answers) but
    linux64.ko refuses ("depends on mqueuefs"), and the flag must not be kept."""
    service, middleware = service_with_middleware()
    service._sysctl = AsyncMock(return_value='5.15.0')

    async def run(arguments, **kwargs):
        if arguments[0] == 'kldstat':
            return completed(returncode=1)
        if arguments[0] == 'dmesg':
            return completed(stdout='KLD linux64.ko: depends on mqueuefs - not available or version mismatch\n')
        return completed()

    with patch('middlewared.plugins.applications_freebsd.run', AsyncMock(side_effect=run)):
        with pytest.raises(CallError, match='linux64elf.*depends on mqueuefs'):
            await service._apply_experimental_flags(Mock(), config(), {
                'pool': 'tank', 'subnet': '10.88.0.0/16', 'linux_compat_enabled': True,
            })
    middleware.call.assert_any_await(
        'datastore.update', 'services.applications', 1, {'linux_compat_enabled': False}, {'prefix': 'app_'},
    )
    assert middleware.call.await_args_list[-1] == call('etc.generate', 'rc')


@pytest.mark.asyncio
async def test_disabling_linux_compat_refuses_while_linux_applications_exist():
    service, middleware = service_with_middleware()
    service._read_records = Mock(return_value=([record(name='alpine', image_os='linux')], []))
    with pytest.raises(CallError, match='Remove the Linux applications.*alpine'):
        await service._apply_experimental_flags(Mock(), config(linux_compat_enabled=True), {
            'pool': 'tank', 'subnet': '10.88.0.0/16', 'linux_compat_enabled': False,
        })
    middleware.call.assert_not_awaited()

    service._read_records = Mock(return_value=([record()], []))
    job = Mock()
    await service._apply_experimental_flags(job, config(linux_compat_enabled=True), {
        'pool': 'tank', 'subnet': '10.88.0.0/16', 'linux_compat_enabled': False,
    })
    middleware.call.assert_has_awaits([
        call('datastore.update', 'services.applications', 1, {'linux_compat_enabled': False}, {'prefix': 'app_'}),
        call('etc.generate', 'rc'),
    ])
    assert 'remain until reboot' in job.set_progress.call_args.args[1]


@pytest.mark.asyncio
async def test_linux_compat_status_proves_the_elf_brand_not_just_the_sysctl():
    service, _ = service_with_middleware()
    service._sysctl = AsyncMock(return_value='5.15.0')
    with patch('middlewared.plugins.applications_freebsd.run', AsyncMock(return_value=completed(returncode=0))):
        assert await service.linux_compat_status(False) == {'enabled': False, 'loaded': True, 'osrelease': '5.15.0'}
    with patch('middlewared.plugins.applications_freebsd.run', AsyncMock(return_value=completed(returncode=1))):
        assert await service.linux_compat_status(True) == {'enabled': True, 'loaded': False, 'osrelease': '5.15.0'}
    service._sysctl = AsyncMock(side_effect=CallError('unknown oid'))
    with patch('middlewared.plugins.applications_freebsd.run', AsyncMock(return_value=completed(returncode=1))):
        assert await service.linux_compat_status(True) == {'enabled': True, 'loaded': False, 'osrelease': None}


# -- the Linux tier ----------------------------------------------------------

@pytest.mark.asyncio
async def test_a_linux_image_is_refused_before_any_pull_while_the_tier_is_off():
    service, _ = service_with_middleware()
    service._require_config = AsyncMock(return_value=config())
    service._validate_install = AsyncMock()
    service._image_exists = AsyncMock(side_effect=AssertionError('no podman before the gate'))
    with pytest.raises(CallError, match='Linux binary compatibility setting'):
        await service._install_impl(Mock(), {
            'name': 'alpine', 'image': 'docker.io/library/alpine:3.20', 'image_os': 'linux',
            'ports': [], 'environment': [], 'volumes': [], 'annotations': [],
            'restart_policy': 'always', 'portal': None, 'healthcheck': None, 'health_timeout': 0,
        }, None)


@pytest.mark.asyncio
async def test_a_linux_image_that_starts_an_init_system_is_refused_statically():
    service, _ = service_with_middleware()
    service._require_config = AsyncMock(return_value=config(linux_compat_enabled=True))
    service._validate_install = AsyncMock()
    service.linux_compat_status = AsyncMock(return_value={'enabled': True, 'loaded': True, 'osrelease': '5.15.0'})
    inspection = {
        'reference': 'x', 'digest': 'sha256:' + 'b' * 64, 'os': 'linux', 'architecture': 'amd64',
        'labels': {}, 'environment': {}, 'entrypoint': ['/sbin/init'], 'cmd': [], 'user': '',
        'volumes': [], 'exposed_ports': [],
    }
    with patch('middlewared.plugins.applications_freebsd.inspect_remote_image', AsyncMock(return_value=inspection)):
        with pytest.raises(CallError, match='init system'):
            await service._install_impl(Mock(), {
                'name': 'systemd', 'image': 'docker.io/library/systemd:1', 'image_os': 'linux',
                'ports': [], 'environment': [], 'volumes': [], 'annotations': [],
                'restart_policy': 'always', 'portal': None, 'healthcheck': None, 'health_timeout': 0,
            }, None)


def test_image_refusals_are_static_and_conservative():
    base = {
        'reference': 'x', 'digest': 'sha256:' + 'b' * 64, 'os': 'linux', 'architecture': 'amd64',
        'labels': {}, 'environment': {}, 'entrypoint': ['/run.sh'], 'cmd': [], 'user': '',
        'volumes': [], 'exposed_ports': [],
    }
    assert image_refusals(base) == []
    assert image_refusals(None) == []
    assert any('operating system' in item for item in image_refusals({**base, 'os': 'freebsd'}))
    assert any('architecture' in item for item in image_refusals({**base, 'architecture': 'arm64'}))
    assert any('init system' in item for item in image_refusals({**base, 'entrypoint': [], 'cmd': ['/lib/systemd/systemd']}))
    assert image_refusals({**base, 'architecture': 'x86_64'}) == []


@pytest.mark.asyncio
async def test_a_linux_install_pulls_the_linux_platform_and_records_the_tier():
    service, middleware = service_with_middleware()
    cfg = config(linux_compat_enabled=True)
    service._require_config = AsyncMock(return_value=cfg)
    service._validate_install = AsyncMock()
    service._require_linux_compat = AsyncMock()
    service._image_exists = AsyncMock(return_value=False)
    service._prepare_volumes = AsyncMock(return_value=[])
    service._podman = AsyncMock(return_value=completed())
    service._inspect_image = AsyncMock(return_value={
        'id': 'sha256:1234', 'digest': 'sha256:' + 'c' * 64, 'os': 'linux', 'labels': {},
    })
    service._inspect_owned_container = AsyncMock(return_value=({'State': {'Running': True}}, '2' * 64))
    service._wait_healthy = AsyncMock()
    written = {}
    service._write_record = Mock(side_effect=lambda config_, rec: written.update(rec))
    service._refresh_restart_on_boot = AsyncMock()
    middleware.call.return_value = {'name': 'alpine'}
    job = Mock()

    await service._install_impl(job, {
        'name': 'alpine', 'image': 'docker.io/library/alpine:3.20', 'image_os': 'linux',
        'ports': [], 'environment': [], 'volumes': [], 'annotations': [],
        'restart_policy': 'always', 'portal': None, 'healthcheck': None, 'health_timeout': 0,
    }, None, {'kind': 'byo', 'reference': 'docker.io/library/alpine:3.20'})

    service._podman.assert_any_await(
        cfg, 'pull', '--quiet', '--os', 'linux', '--arch', 'amd64', '--', 'docker.io/library/alpine:3.20',
    )
    service._inspect_image.assert_awaited_once_with(cfg, 'docker.io/library/alpine:3.20', allow_linux=True)
    assert written['schema'] == 4 and written['image_os'] == 'linux'  # #484 pins every install
    assert written['origin'] == {'kind': 'byo', 'reference': 'docker.io/library/alpine:3.20'}
    assert any('compatibility tier' in c.args[1] for c in job.set_progress.call_args_list)


@pytest.mark.asyncio
async def test_a_native_install_pulls_exactly_as_before_and_records_the_tier():
    service, middleware = service_with_middleware()
    cfg = config()
    service._require_config = AsyncMock(return_value=cfg)
    service._validate_install = AsyncMock()
    service._image_exists = AsyncMock(return_value=False)
    service._prepare_volumes = AsyncMock(return_value=[])
    service._podman = AsyncMock(return_value=completed())
    service._inspect_image = AsyncMock(return_value={
        'id': 'sha256:1234', 'digest': 'sha256:' + 'c' * 64, 'os': 'freebsd', 'labels': {},
    })
    service._inspect_owned_container = AsyncMock(return_value=({'State': {'Running': True}}, '2' * 64))
    service._wait_healthy = AsyncMock()
    written = {}
    service._write_record = Mock(side_effect=lambda config_, rec: written.update(rec))
    service._refresh_restart_on_boot = AsyncMock()
    middleware.call.return_value = {'name': 'demo'}

    await service._install_impl(Mock(), {
        'name': 'demo', 'image': 'ghcr.io/daemonless/demo:pkg',
        'ports': [], 'environment': [], 'volumes': [], 'annotations': [],
        'restart_policy': 'always', 'portal': None, 'healthcheck': None, 'health_timeout': 0,
    }, {'id': 'daemonless:demo', 'version': '1', 'compose_sha256': 'a' * 64,
        'repository': 'https://github.com/daemonless/demo', 'image_tag': 'ghcr.io/daemonless/demo:pkg'})

    service._podman.assert_any_await(cfg, 'pull', '--quiet', '--', 'ghcr.io/daemonless/demo:pkg')
    assert written['image_os'] == 'freebsd' and written['origin'] is None
    assert written['catalog']['image_tag'] == 'ghcr.io/daemonless/demo:pkg'


@pytest.mark.asyncio
async def test_inspect_image_accepts_linux_only_when_asked():
    service, _ = service_with_middleware()
    service._podman = AsyncMock(return_value=completed(stdout='[{"Id": "sha256:1", "Os": "linux", "RepoDigests": ["a/b@sha256:' + 'd' * 64 + '"], "Config": {"Labels": {"k": "v"}}}]'))
    with pytest.raises(CallError, match='native FreeBSD images'):
        await service._inspect_image(config(), 'a/b:1')
    info = await service._inspect_image(config(), 'a/b:1', allow_linux=True)
    assert info == {
        'id': 'sha256:1', 'digest': 'sha256:' + 'd' * 64, 'os': 'linux', 'labels': {'k': 'v'},
        'env': [],  # the internal development record
    }


# -- the second install tier -------------------------------------------------

@pytest.mark.asyncio
async def test_bring_your_own_install_requires_the_acknowledgement():
    service, _ = service_with_middleware()
    service._install_impl = AsyncMock(return_value={'name': 'demo'})
    payload = {
        'name': 'demo', 'image': 'registry.example/demo:1', 'image_os': 'freebsd', 'ports': [],
        'environment': [], 'volumes': [], 'annotations': [], 'restart_policy': 'always',
        'portal': None, 'healthcheck': None, 'health_timeout': 60, 'acknowledge_unreviewed': False,
    }
    with pytest.raises(ValidationErrors, match='supply chain'):
        await ApplicationsService.install.wraps(service, Mock(), dict(payload))
    service._install_impl.assert_not_awaited()

    result = await ApplicationsService.install.wraps(service, Mock(), {**payload, 'acknowledge_unreviewed': True})
    assert result == {'name': 'demo'}
    job, data, catalog, origin = service._install_impl.await_args.args
    assert catalog is None
    assert origin['kind'] == 'byo' and origin['reference'] == 'registry.example/demo:1'
    assert 'acknowledge_unreviewed' not in data


# -- records ------------------------------------------------------------------

def test_record_validation_accepts_schema_two_and_three_and_both_catalog_shapes():
    cfg = config()
    legacy = record(schema=2)
    legacy.pop('image_os')
    legacy.pop('origin')
    legacy['catalog'] = {
        'compose_sha256': 'a' * 64, 'entry_revision': 1, 'id': 'daemonless:demo', 'object_sha256': 'b' * 64,
        'repository': 'https://github.com/daemonless/demo', 'snapshot_sequence': 1,
        'source_commit': 'c' * 40, 'version': '1.0.0',
    }
    assert ApplicationsService._validate_record(cfg, legacy, 'demo') == legacy

    current = record(catalog={
        'id': 'daemonless:demo', 'version': '1.2.3', 'compose_sha256': 'a' * 64,
        'repository': 'https://github.com/daemonless/demo', 'image_tag': 'ghcr.io/daemonless/demo:latest',
    })
    assert ApplicationsService._validate_record(cfg, current, 'demo') == current

    converted = record(image_os='linux', origin={
        'kind': 'convert', 'reference': 'grafana', 'plan_id': 'f' * 64, 'mode': 'compat',
    })
    assert ApplicationsService._validate_record(cfg, converted, 'demo') == converted

    for broken in (
        record(schema=4),
        record(image_os='plan9'),
        record(origin={'kind': 'stolen', 'reference': 'x'}),
        record(origin={'kind': 'byo'}),
        record(origin={'kind': 'byo', 'reference': 'x', 'nested': {'a': 1}}),
        record(catalog={'id': 'daemonless:demo', 'version': '1', 'compose_sha256': 'a' * 64,
                        'repository': 'https://github.com/daemonless/demo'}),
        {**legacy, 'image_os': 'freebsd'},
    ):
        with pytest.raises(ValueError):
            ApplicationsService._validate_record(cfg, broken, 'demo')
