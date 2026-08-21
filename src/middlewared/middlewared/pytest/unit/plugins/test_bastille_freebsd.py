import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call, patch

import pytest
from middlewared.plugins import bastille_freebsd
from middlewared.plugins.bastille_.utils import (
    MANAGED_PROPERTY,
    bastille_dataset_specs,
    bastille_paths,
    render_bastille_config,
    render_config_pointer,
)
from middlewared.plugins.bastille_freebsd import (
    BASTILLE_CAPABILITY,
    BastilleFSAttachmentDelegate,
    BastilleService,
    _bastille_datasets_available,
)
from middlewared.plugins.service import ServiceService
from middlewared.plugins.service_.services.bastille import (
    BastilleService as BastilleRcService,
)
from middlewared.service_exception import CallError, ValidationErrors

PACKAGE_CAPABILITY_VALIDATOR = BastilleService._package_capability_valid


@pytest.fixture(autouse=True)
def cli_config_off_the_host(tmp_path_factory, monkeypatch):
    """Keep the internal development record's managed /usr/local/etc/bastille/bastille.conf out of it.

    configure() and deactivate_pool() write that file for real. Redirect it into a
    temporary directory so these tests exercise the real code without touching the
    machine running them; its own behaviour is covered in test_bastille_cli_config.
    """
    directory = tmp_path_factory.mktemp('bastille-etc')
    monkeypatch.setattr(
        bastille_freebsd, 'BASTILLE_DEFAULT_CONFIG', str(directory / 'bastille.conf'),
    )
    monkeypatch.setattr(
        bastille_freebsd, 'BASTILLE_SAMPLE_CONFIG', str(directory / 'bastille.conf.sample'),
    )
    # the internal development record mirrors the live file into the boot seed when its directory
    # exists; point it at one that does not, so these tests see the pre-#451 write pattern.
    # The seed behaviour itself is covered in test_bastille_cli_config.
    monkeypatch.setattr(
        bastille_freebsd, 'BASTILLE_BASE_CONFIG', str(directory / 'no-seed' / 'bastille.conf'),
    )


def service_with_middleware():
    middleware = Mock()
    middleware.call = AsyncMock()
    return BastilleService(middleware), middleware


def raw_config(**overrides):
    config = {
        'id': 1,
        'pool': None,
        'startup_delay': 0,
        'parallel_limit': 1,
    }
    config.update(overrides)
    return config


def vnet_jail(name='web', boot=True):
    return {
        'name': name,
        'interface': 'em0',
        'bridge': 'bridge0',
        'ip4_addr': '192.0.2.50/24',
        'gateway': '192.0.2.1',
        'host_mac': '58:9c:fc:12:34:5a',
        'jail_mac': '58:9c:fc:12:34:5b',
        'host_epair': f'e0a_{name}',
        'jail_epair': f'e0b_{name}',
        'boot': boot,
    }


@pytest.fixture(autouse=True)
def patched_bastille_package_capability(monkeypatch):
    monkeypatch.setattr(
        BastilleService, '_package_capability_valid', staticmethod(lambda: True)
    )


def owned_jail_tree(tmp_path, auxiliary=None, auxiliary_content=''):
    root = tmp_path / 'bastille'
    paths = {
        'jails': str(root / 'jails'),
        'logs': str(root / 'logs'),
        'releases': str(root / 'releases'),
        'jails_dataset': 'tank/bastille/jails',
        'cache_dataset': 'tank/bastille/cache',
        'releases_dataset': 'tank/bastille/releases',
    }
    jail = root / 'jails/web'
    jail_root = jail / 'root'
    release = root / 'releases/15.0-STABLE'
    (release / 'bin').mkdir(parents=True)
    jail_root.mkdir(parents=True)
    (jail_root / '.bastille').mkdir()
    (root / 'logs').mkdir(parents=True)
    (root / 'logs/web_console.log').write_text('')
    (release / 'COPYRIGHT').write_text('FreeBSD')
    version = release / 'bin/freebsd-version'
    version.write_text('#!/bin/sh\n')
    version.chmod(0o755)
    (jail / 'jail.conf').write_text(
        'web {\n'
        '  enforce_statfs = 2;\n'
        '  devfs_ruleset = 4;\n'
        '  exec.clean;\n'
        f'  exec.consolelog = {root / "logs/web_console.log"};\n'
        "  exec.start = '/bin/sh /etc/rc';\n"
        "  exec.stop = '/bin/sh /etc/rc.shutdown';\n"
        '  host.hostname = web;\n'
        '  mount.devfs;\n'
        f'  mount.fstab = {jail / "fstab"};\n'
        f'  path = {jail_root};\n'
        '  securelevel = 2;\n'
        '  osrelease = 15.0-STABLE;\n'
        '  vnet;\n'
        '  vnet.interface = e0b_web;\n'
        "  exec.prestart += \"trap '' HUP INT TERM; ifconfig epair create name e0a_web "
        "&& epair_driver=\\$(ifconfig -D e0a_web | sed -n "
        "'s/^[[:space:]]*drivername: //p') && test -n \\\"\\${epair_driver}\\\" "
        "&& ifconfig \\\"\\${epair_driver}b\\\" up name e0b_web && ifconfig e0a_web up; "
        "epair_status=\\$?; trap - HUP INT TERM; exit \\${epair_status}\";\n"
        '  exec.prestart += "ifconfig bridge0 addm e0a_web";\n'
        '  exec.prestart += "ifconfig e0a_web ether 58:9c:fc:12:34:5a";\n'
        '  exec.prestart += "ifconfig e0b_web ether 58:9c:fc:12:34:5b";\n'
        '  exec.prestart += "ifconfig e0a_web description '
        '\\"vnet0 host interface for Bastille jail web\\"";\n'
        '  exec.poststop += "ifconfig e0a_web destroy";\n'
        '}\n'
    )
    (jail_root / 'etc').mkdir()
    (jail_root / 'etc/rc.conf').write_text(
        'syslogd_flags="-ss"\n'
        'ifconfig_e0b_web_name="vnet0"\n'
        'ifconfig_vnet0="inet 192.0.2.50/24 -txcsum -txcsum6"\n'
        'ifconfig_vnet0_descr="jail interface for bridge0"\n'
        'ifconfig_vnet0_ipv6=""\n'
        'defaultrouter="192.0.2.1"\n'
        'ipv6_defaultrouter="NO"\n'
    )
    (jail / 'fstab').write_text(
        f'{release} {jail_root / ".bastille"} nullfs ro 0 0\n'
    )
    (jail / 'settings.conf').write_text('boot="on"\ndepend=""\npriority="99"\n')
    metadata = jail / '.freecore-vnet.json'
    metadata.write_text(json.dumps({
        'schema': 'freecore-bastille-vnet-v1',
        'name': 'web',
        'release': '15.0-STABLE',
        'interface': 'em0',
        'bridge': 'bridge0',
        'ip4_addr': '192.0.2.50/24',
        'gateway': '192.0.2.1',
        'host_mac': '58:9c:fc:12:34:5a',
        'jail_mac': '58:9c:fc:12:34:5b',
        'boot': True,
    }, sort_keys=True, separators=(',', ':')) + '\n')
    metadata.chmod(0o600)
    if auxiliary:
        (jail / auxiliary).write_text(auxiliary_content)
    return paths


def test_paths_keep_zfs_identity_separate_from_live_altroot_path():
    paths = bastille_paths('tank')

    assert paths['dataset'] == 'tank/bastille'
    assert paths['logical_prefix'] == '/tank/bastille'
    assert paths['config_file'] == '/mnt/tank/bastille/config/bastille.conf'
    assert [dataset for dataset, _ in bastille_dataset_specs('tank')] == [
        'tank/bastille',
        'tank/bastille/backups',
        'tank/bastille/cache',
        'tank/bastille/config',
        'tank/bastille/jails',
        'tank/bastille/logs',
        'tank/bastille/releases',
        'tank/bastille/templates',
    ]


def test_generated_config_is_zfs_scoped_and_network_inert():
    config = render_bastille_config('tank')

    assert 'bastille_prefix="/tank/bastille"' in config
    assert 'bastille_zfs_zpool="tank"' in config
    assert 'bastille_zfs_prefix="bastille"' in config
    assert 'bastille_pf_conf="/mnt/tank/bastille/config/pf.conf"' in config
    assert 'bastille_network_loopback=""' in config
    assert 'bastille_network_shared=""' in config
    for forbidden in ('bastille setup', 'pf_enable', 'cloned_interfaces', 'iocage'):
        assert forbidden not in config


@pytest.mark.asyncio
async def test_fresh_config_is_disabled_unconfigured_and_inert():
    service, middleware = service_with_middleware()

    async def dispatch(name, *args):
        if name == 'datastore.config':
            return raw_config()
        if name == 'datastore.query':
            return [{'id': 7, 'srv_service': 'bastille', 'srv_enable': False}]
        raise AssertionError(name)

    middleware.call.side_effect = dispatch
    with patch('middlewared.plugins.bastille_freebsd.os.access', return_value=True):
        result = await service.config()

    assert result['installed'] is True
    assert result['configured'] is False
    assert result['configuration_valid'] is False
    assert result['configuration_error'] is None
    assert result['enabled'] is False
    assert result['running_jail_count'] == 0
    assert result['running_jails_error'] is None
    assert result['paths'] is None


def test_package_capability_requires_the_exact_regular_immutable_contract(tmp_path):
    assert BASTILLE_CAPABILITY == (
        'freecore-bastille-lifecycle-v3\n'
        'upstream=1.4.0.260219\n'
        'portrevision=5\n'
    )

    marker = tmp_path / 'freecore-lifecycle-v3'
    marker.write_text(BASTILLE_CAPABILITY)
    marker.chmod(0o644)

    with patch(
        'middlewared.plugins.bastille_freebsd.BASTILLE_CAPABILITY_PATH', str(marker)
    ):
        assert PACKAGE_CAPABILITY_VALIDATOR() is True

        marker.write_text(f'{BASTILLE_CAPABILITY}unexpected=true\n')
        assert PACKAGE_CAPABILITY_VALIDATOR() is False

        marker.write_text(BASTILLE_CAPABILITY)
        marker.chmod(0o666)
        assert PACKAGE_CAPABILITY_VALIDATOR() is False

        marker.unlink()
        marker.symlink_to(tmp_path / 'missing')
        assert PACKAGE_CAPABILITY_VALIDATOR() is False


@pytest.mark.asyncio
async def test_configuration_refuses_a_package_without_the_lifecycle_contract(monkeypatch):
    service, middleware = service_with_middleware()
    monkeypatch.setattr(
        BastilleService, '_package_capability_valid', staticmethod(lambda: False)
    )

    with pytest.raises(CallError, match='required FreeCORE lifecycle capability'):
        await service.configure(Mock(), {
            'pool': 'tank', 'startup_delay': 0, 'parallel_limit': 1,
        })

    middleware.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_pool_validation_rejects_boot_pool_without_touching_iocage_or_networking():
    service, middleware = service_with_middleware()

    async def dispatch(name, *args):
        if name == 'failover.status':
            return 'SINGLE'
        if name == 'pool.query':
            return [{
                'name': 'boot-pool', 'status': 'ONLINE', 'healthy': True,
                'is_decrypted': True,
            }]
        if name == 'boot.pool_name':
            return 'boot-pool'
        if name == 'zfs.dataset.query':
            return []
        raise AssertionError(name)

    middleware.call.side_effect = dispatch
    with (
        patch('middlewared.plugins.bastille_freebsd.os.access', return_value=True),
        pytest.raises(ValidationErrors, match='boot pool'),
    ):
        await service._validate_pool('boot-pool', True)

    assert all(
        not invocation.args[0].startswith(('jail.', 'iocage.', 'interface.', 'route.'))
        for invocation in middleware.call.await_args_list
    )


@pytest.mark.asyncio
async def test_managed_hierarchy_requires_local_ownership_for_every_core_dataset():
    service, _ = service_with_middleware()
    owners = {
        dataset: (owner, 'local')
        for dataset, owner in bastille_dataset_specs('tank')
    }
    service._managed_dataset_owners = AsyncMock(return_value=owners)
    await service._validate_managed_tree('tank')

    owners['tank/bastille/jails'] = ('bastille:jails', 'inherited from tank/bastille')
    with pytest.raises(CallError, match='local'):
        await service._validate_managed_tree('tank')


@pytest.mark.asyncio
async def test_mounted_hierarchy_requires_every_dataset_at_its_live_path():
    service, _ = service_with_middleware()
    lines = []
    for dataset, _ in bastille_dataset_specs('tank'):
        lines.extend([
            f'{dataset}\tmounted\tyes',
            f'{dataset}\tmountpoint\t/{dataset}',
        ])
    zfs_get = SimpleNamespace(returncode=0, stdout='\n'.join(lines), stderr='')

    with (
        patch('middlewared.plugins.bastille_freebsd.run', AsyncMock(return_value=zfs_get)),
        patch('middlewared.plugins.bastille_freebsd.os.path.ismount', return_value=True),
    ):
        await service._validate_mounted_tree('tank')

    zfs_get.stdout = zfs_get.stdout.replace(
        'tank/bastille/config\tmounted\tyes',
        'tank/bastille/config\tmounted\tno',
    )
    with (
        patch('middlewared.plugins.bastille_freebsd.run', AsyncMock(return_value=zfs_get)),
        patch('middlewared.plugins.bastille_freebsd.os.path.ismount', return_value=True),
        pytest.raises(CallError, match='tank/bastille/config.*not mounted'),
    ):
        await service._validate_mounted_tree('tank')


def test_generated_rc_postcondition_rejects_stale_or_duplicate_pool_state(tmp_path):
    config = raw_config(pool='tank', startup_delay=2, parallel_limit=4)
    rc_config = tmp_path / 'rc.conf.freenas'
    rc_config.write_text(
        'bastille_enable="NO"\n'
        'bastille_conf="/mnt/tank/bastille/config/bastille.conf"\n'
        'bastille_env="BASTILLE_CONFIG=/mnt/tank/bastille/config/bastille.conf"\n'
        'bastille_jailsdir="/mnt/tank/bastille/jails"\n'
        'bastille_startup_delay="2"\n'
        'bastille_parallel_limit="4"\n'
    )

    with patch('middlewared.plugins.bastille_freebsd.RC_CONFIG_PATH', str(rc_config)):
        BastilleService._validate_generated_rc(config, False)

        rc_config.write_text(rc_config.read_text() + 'bastille_enable="YES"\n')
        with pytest.raises(CallError, match='bastille_enable'):
            BastilleService._validate_generated_rc(config, False)

        rc_config.write_text('bastille_enable="NO"\n')
        BastilleService._validate_generated_rc(raw_config(), False)


@pytest.mark.asyncio
async def test_dataset_creation_is_bounded_to_the_dedicated_bastille_hierarchy():
    service, middleware = service_with_middleware()
    created = []

    with patch('middlewared.plugins.bastille_freebsd.os.chmod') as chmod:
        await service._create_datasets('tank', created)

    assert created == [dataset for dataset, _ in bastille_dataset_specs('tank')]
    expected_calls = []
    for dataset, owner in bastille_dataset_specs('tank'):
        expected_calls.extend([
            call('zfs.dataset.create', {
                'name': dataset,
                'properties': {
                    'atime': 'off',
                    'compression': 'lz4',
                    MANAGED_PROPERTY: owner,
                },
            }),
            call('zfs.dataset.mount', dataset),
        ])
    assert middleware.call.await_args_list == expected_calls
    assert chmod.call_count == len(created)
    assert all('/iocage' not in dataset for dataset in created)


@pytest.mark.asyncio
async def test_dataset_is_registered_for_rollback_before_mounting():
    service, middleware = service_with_middleware()
    created = []

    async def fail_mount(name, *args):
        if name == 'zfs.dataset.mount':
            raise CallError('injected mount failure')

    middleware.call.side_effect = fail_mount

    with pytest.raises(CallError, match='injected mount failure'):
        await service._create_datasets('tank', created)

    assert created == ['tank/bastille']


@pytest.mark.asyncio
async def test_running_state_accepts_only_live_roots_inside_the_bastille_tree():
    service, _ = service_with_middleware()
    jls = SimpleNamespace(
        returncode=0,
        stdout=(
            'name=same-name path=/mnt/tank/iocage/jails/same-name/root\n'
            'name=bastilleone path=/mnt/tank/bastille/jails/bastilleone/root\n'
            'name=orphan path=/mnt/tank/bastille/jails/orphan/root\n'
            'name=foreign path=/other/bastille/jails/foreign/root\n'
        ),
        stderr='',
    )

    with (
        patch('middlewared.plugins.bastille_freebsd.run', AsyncMock(return_value=jls)),
        patch(
            'middlewared.plugins.bastille_freebsd.os.path.isfile',
            side_effect=lambda path: path.endswith('/bastilleone/jail.conf'),
        ),
    ):
        assert await service._running_jails(raw_config(pool='tank')) == ['bastilleone']
        assert await service._running_jails(
            raw_config(pool='tank'), strict=True
        ) == ['bastilleone', 'orphan']


@pytest.mark.asyncio
async def test_strict_running_state_blocks_nameless_mismatched_and_unparseable_records():
    service, _ = service_with_middleware()
    nameless = SimpleNamespace(
        returncode=0,
        stdout='path=/mnt/tank/bastille/jails/orphan/root\n',
        stderr='',
    )

    with (
        patch('middlewared.plugins.bastille_freebsd.run', AsyncMock(return_value=nameless)),
        pytest.raises(CallError, match='reported jail name does not match'),
    ):
        await service._running_jails(raw_config(pool='tank'), strict=True)

    mismatched = SimpleNamespace(
        returncode=0,
        stdout='name=other path=/mnt/tank/bastille/jails/orphan/root\n',
        stderr='',
    )
    with (
        patch('middlewared.plugins.bastille_freebsd.run', AsyncMock(return_value=mismatched)),
        pytest.raises(CallError, match='reported jail name does not match'),
    ):
        await service._running_jails(raw_config(pool='tank'), strict=True)

    nested = SimpleNamespace(
        returncode=0,
        stdout='name=orphan path=/mnt/tank/bastille/jails/orphan/root/subdir\n',
        stderr='',
    )
    with (
        patch('middlewared.plugins.bastille_freebsd.run', AsyncMock(return_value=nested)),
        pytest.raises(CallError, match='not an exact managed jail root'),
    ):
        await service._running_jails(raw_config(pool='tank'), strict=True)

    unparseable = SimpleNamespace(
        returncode=0,
        stdout='name=broken path="unterminated\n',
        stderr='',
    )
    with (
        patch('middlewared.plugins.bastille_freebsd.run', AsyncMock(return_value=unparseable)),
        pytest.raises(CallError, match='classify running jail state safely'),
    ):
        await service._running_jails(raw_config(pool='tank'), strict=True)


def test_query_address_parser_preserves_static_subnets_without_running_bastille():
    jail_config = '''
bastille-one {
    ip4.addr = "em0|192.0.2.10/24,em1|198.51.100.8/32";
    ip6.addr += "em0|2001:db8::10/64";
}
'''
    rc_config = '''
ifconfig_vnet0="inet 203.0.113.8 netmask 255.255.255.0"
ifconfig_vnet0_alias0="inet 203.0.114.8/24"
ifconfig_vnet0_ipv6="inet6 2001:db8:1::8 prefixlen 64"
ifconfig_vnet1="SYNCDHCP"
'''

    assert BastilleService._extract_jail_addresses(jail_config, rc_config) == {
        4: [
            'em0|192.0.2.10/24',
            'em1|198.51.100.8/32',
            '203.0.113.8/24',
            '203.0.114.8/24',
            'DHCP',
        ],
        6: ['em0|2001:db8::10/64', '2001:db8:1::8/64'],
    }


def test_query_address_parser_fails_closed_on_unreadable_static_address():
    with pytest.raises(CallError, match='Unable to interpret'):
        BastilleService._extract_jail_addresses(
            'one {\n  ip4.addr = "em0|not-an-address";\n}\n', ''
        )


@pytest.mark.asyncio
async def test_query_rejects_symlinked_jail_paths(tmp_path):
    service, _ = service_with_middleware()
    service._raw_config = AsyncMock(return_value=raw_config(pool='tank'))
    service._validate_configured_row = AsyncMock(return_value=True)
    service._running_jails = AsyncMock(return_value=[])
    service._jail_disk_usage = AsyncMock(return_value={})
    service._managed_dataset_owners = AsyncMock(return_value={})
    jails_path = tmp_path / 'jails'
    jails_path.mkdir()
    (jails_path / 'outside').mkdir()
    (jails_path / 'bastilleone').symlink_to(jails_path / 'outside', target_is_directory=True)

    with patch(
        'middlewared.plugins.bastille_freebsd.bastille_paths',
        return_value={'jails': str(jails_path), 'releases': str(tmp_path / 'releases')},
    ):
        assert await service.query.wraps(service, [], {}) == []


def test_managed_jail_rejects_a_symlinked_console_log(tmp_path):
    paths = owned_jail_tree(tmp_path)
    log = tmp_path / 'bastille/logs/web_console.log'
    log.unlink()
    outside = tmp_path / 'outside.log'
    outside.write_text('do not touch')
    log.symlink_to(outside)

    with pytest.raises(CallError, match='console log.*unsafe'):
        BastilleService._validate_console_log(paths, 'web')


@pytest.mark.asyncio
async def test_managed_lifecycle_refuses_an_explicit_bastille_pf_file():
    service, _ = service_with_middleware()
    config = raw_config(pool='tank')
    service._raw_config = AsyncMock(return_value=config)
    service._validate_configured_row = AsyncMock(return_value=True)

    with (
        patch('middlewared.plugins.bastille_freebsd.os.path.lexists', return_value=True),
        pytest.raises(CallError, match='PF configuration path to remain absent'),
    ):
        await service._lifecycle_config()

    service._validate_configured_row.assert_awaited_once_with(config)


@pytest.mark.asyncio
async def test_partial_configuration_failure_removes_only_new_bastille_tree():
    service, middleware = service_with_middleware()
    service._raw_config = AsyncMock(return_value=raw_config())
    service._validate_pool = AsyncMock()
    service._disable_service_row = AsyncMock()
    service._service_row = AsyncMock(return_value={'id': 9, 'srv_enable': False})
    service._generate_and_validate_rc = AsyncMock()

    async def fail_after_partial_create(pool, created):
        created.extend([f'{pool}/bastille', f'{pool}/bastille/backups'])
        raise CallError('injected create failure')

    service._prepare_switch_target = fail_after_partial_create

    with (
        patch('middlewared.plugins.bastille_freebsd.os.path.lexists', return_value=False),
        pytest.raises(CallError, match='injected create failure'),
    ):
        await service.configure(Mock(), {
            'pool': 'tank', 'startup_delay': 0, 'parallel_limit': 1,
        })

    middleware.call.assert_any_await(
        'zfs.dataset.delete', 'tank/bastille', {'force': True, 'recursive': True}
    )
    assert not any(
        invocation.args[:2] == ('datastore.update', 'services.bastille')
        for invocation in middleware.call.await_args_list
    )
    service._disable_service_row.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_initial_configuration_verifies_both_rc_barriers_before_success():
    service, middleware = service_with_middleware()
    old = raw_config()
    new = {'pool': 'tank', 'startup_delay': 2, 'parallel_limit': 4}
    service._raw_config = AsyncMock(return_value=old)
    service._service_row = AsyncMock(return_value={'id': 9, 'srv_enable': False})
    service._validate_pool = AsyncMock()
    service._validate_configured_row = AsyncMock(return_value=True)
    service._prepare_switch_target = AsyncMock()
    service._validate_generated_rc = Mock()
    service.config = AsyncMock(return_value={'pool': 'tank', 'configured': True})

    with (
        patch('middlewared.plugins.bastille_freebsd.os.path.lexists', return_value=False),
        patch('middlewared.plugins.bastille_freebsd.atomic_write'),
    ):
        result = await service.configure(Mock(), new)

    assert result == {'pool': 'tank', 'configured': True}
    service._prepare_switch_target.assert_awaited_once_with('tank', [])
    assert middleware.call.await_args_list.count(call('etc.generate', 'rc')) == 3
    assert service._validate_generated_rc.call_args_list == [
        call(old, False),
        call(new, False),
        call(new, False),
    ]


@pytest.mark.asyncio
async def test_configuration_cannot_select_pool_during_storage_transition():
    service, middleware = service_with_middleware()
    service._raw_config = AsyncMock(return_value=raw_config(pool='other'))
    service._unavailable_pool_names().add('tank')

    with pytest.raises(CallError, match='being locked, exported, or recovered'):
        await service.configure(Mock(), {
            'pool': 'tank', 'startup_delay': 0, 'parallel_limit': 1,
        })

    middleware.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_pool_switch_rejects_running_jails_in_existing_target_tree():
    service, middleware = service_with_middleware()
    middleware.call.return_value = [{'id': 'backup/bastille'}]
    service._validate_managed_tree = AsyncMock()
    service._validate_mounted_tree = AsyncMock()
    service._running_jails = AsyncMock(return_value=['target-web'])
    service._create_datasets = AsyncMock()

    with pytest.raises(CallError, match='target pool.*target-web'):
        await service._prepare_switch_target('backup', [])

    service._validate_managed_tree.assert_awaited_once_with('backup')
    service._validate_mounted_tree.assert_awaited_once_with('backup')
    service._create_datasets.assert_not_awaited()


@pytest.mark.asyncio
async def test_rc_generation_failure_restores_database_and_removes_new_tree():
    service, middleware = service_with_middleware()
    old = raw_config()
    service._raw_config = AsyncMock(return_value=old)
    service._validate_pool = AsyncMock()
    service._validate_configured_row = AsyncMock(return_value=True)
    service._disable_service_row = AsyncMock()
    service._service_row = AsyncMock(return_value={'id': 9, 'srv_enable': False})
    service._validate_generated_rc = Mock()

    async def create(pool, created):
        created.append(f'{pool}/bastille')

    service._prepare_switch_target = create
    generation = 0

    async def dispatch(name, *args):
        nonlocal generation
        if name == 'datastore.update':
            return 1
        if name == 'zfs.dataset.delete':
            return True
        if name == 'etc.generate':
            generation += 1
            if generation == 2:
                raise CallError('injected rc failure')
            return None
        raise AssertionError(name)

    middleware.call.side_effect = dispatch
    with (
        patch('middlewared.plugins.bastille_freebsd.os.path.lexists', return_value=False),
        patch('middlewared.plugins.bastille_freebsd.atomic_write'),
        pytest.raises(CallError, match='injected rc failure'),
    ):
        await service.configure(Mock(), {
            'pool': 'tank', 'startup_delay': 2, 'parallel_limit': 4,
        })

    middleware.call.assert_any_await(
        'datastore.update', 'services.bastille', 1, {
            'pool': 'tank', 'startup_delay': 2, 'parallel_limit': 4,
        }, {'prefix': 'bastille_'}
    )
    middleware.call.assert_any_await(
        'datastore.update', 'services.bastille', 1, {
            'pool': None, 'startup_delay': 0, 'parallel_limit': 1,
        }, {'prefix': 'bastille_'}
    )
    middleware.call.assert_any_await(
        'zfs.dataset.delete', 'tank/bastille', {'force': True, 'recursive': True}
    )
    service._disable_service_row.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_repeat_configuration_is_idempotent_and_verifies_fail_closed_rc_cutover():
    service, middleware = service_with_middleware()
    old = raw_config(pool='tank', startup_delay=3, parallel_limit=4)
    service._raw_config = AsyncMock(return_value=old)
    service._validate_pool = AsyncMock()
    service._validate_managed_tree = AsyncMock()
    service._validate_mounted_tree = AsyncMock()
    service._validate_configured_row = AsyncMock(return_value=True)
    service._create_datasets = AsyncMock()
    service._service_row = AsyncMock(return_value={'id': 9, 'srv_enable': False})
    service._validate_generated_rc = Mock()
    service.config = AsyncMock(return_value={'configured': True})

    with (
        patch('middlewared.plugins.bastille_freebsd.os.path.lexists', return_value=False),
        patch('middlewared.plugins.bastille_freebsd.atomic_write') as write,
    ):
        result = await service.configure(Mock(), {
            'pool': 'tank', 'startup_delay': 3, 'parallel_limit': 4,
        })

    assert result == {'configured': True}
    service._create_datasets.assert_not_awaited()
    write.assert_any_call(
        '/mnt/tank/bastille/config/bastille.conf', render_bastille_config('tank')
    )
    assert write.call_args_list[-1].args[1] == render_config_pointer('tank')
    assert len(write.call_args_list) == 2
    assert middleware.call.await_args_list == [call('etc.generate', 'rc')] * 3
    assert service._validate_generated_rc.call_args_list == [
        call(old, False),
        call({'pool': 'tank', 'startup_delay': 3, 'parallel_limit': 4}, False),
        call({'pool': 'tank', 'startup_delay': 3, 'parallel_limit': 4}, False),
    ]


@pytest.mark.asyncio
async def test_pool_transition_stop_marks_store_unavailable_and_verifies_strict_zero():
    service, _ = service_with_middleware()
    config = raw_config(pool='tank')
    service._raw_config = AsyncMock(return_value=config)
    service.rc_preflight = AsyncMock()
    service._running_jails = AsyncMock(return_value=[])
    service._generate_and_validate_rc = AsyncMock()

    with patch(
        'middlewared.plugins.bastille_freebsd.freebsd_service',
        new=AsyncMock(return_value=SimpleNamespace(returncode=0)),
    ) as stop:
        assert await service.stop_for_pool('tank') is True

    service._generate_and_validate_rc.assert_awaited_once_with(config, False)
    stop.assert_awaited_once_with('bastille', 'forcestop')
    service._running_jails.assert_awaited_once_with(config, strict=True)
    assert service._pool_is_unavailable('tank') is True
    service.rc_preflight.assert_awaited_once_with('stop')


@pytest.mark.asyncio
async def test_pool_transition_stop_failure_restores_boot_rc_and_clears_start_block():
    service, _ = service_with_middleware()
    config = raw_config(pool='tank')
    service._raw_config = AsyncMock(return_value=config)
    service.rc_preflight = AsyncMock()
    service._service_row = AsyncMock(return_value={'id': 9, 'srv_enable': True})
    service._generate_and_validate_rc = AsyncMock()

    with (
        patch(
            'middlewared.plugins.bastille_freebsd.freebsd_service',
            new=AsyncMock(return_value=SimpleNamespace(returncode=1)),
        ),
        pytest.raises(CallError, match='failed to stop'),
    ):
        await service.stop_for_pool('tank')

    assert service._generate_and_validate_rc.await_args_list == [
        call(config, False),
        call(config, True),
    ]
    assert service._pool_is_unavailable('tank') is False
    service.rc_preflight.assert_awaited_once_with('stop')


@pytest.mark.asyncio
async def test_pool_transition_stop_cancellation_restores_boot_rc_and_clears_start_block():
    service, _ = service_with_middleware()
    config = raw_config(pool='tank')
    service._raw_config = AsyncMock(return_value=config)
    service.rc_preflight = AsyncMock()
    service._service_row = AsyncMock(return_value={'id': 9, 'srv_enable': True})
    service._generate_and_validate_rc = AsyncMock()
    stop_started = asyncio.Event()

    async def blocked_stop(*args):
        stop_started.set()
        await asyncio.Event().wait()

    with patch(
        'middlewared.plugins.bastille_freebsd.freebsd_service',
        new=AsyncMock(side_effect=blocked_stop),
    ):
        transition = asyncio.create_task(service.stop_for_pool('tank'))
        await stop_started.wait()
        transition.cancel()
        with pytest.raises(asyncio.CancelledError):
            await transition

    assert service._pool_is_unavailable('tank') is False
    assert service._generate_and_validate_rc.await_args_list == [
        call(config, False),
        call(config, True),
    ]
    service.rc_preflight.assert_awaited_once_with('stop')


@pytest.mark.asyncio
async def test_pool_transition_stop_keeps_start_block_when_rc_restore_fails():
    service, _ = service_with_middleware()
    config = raw_config(pool='tank')
    service._raw_config = AsyncMock(return_value=config)
    service.rc_preflight = AsyncMock()
    service._service_row = AsyncMock(return_value={'id': 9, 'srv_enable': True})
    service._generate_and_validate_rc = AsyncMock(side_effect=[
        None,
        CallError('restore failed'),
        None,
    ])

    with (
        patch(
            'middlewared.plugins.bastille_freebsd.freebsd_service',
            new=AsyncMock(return_value=SimpleNamespace(returncode=1)),
        ),
        pytest.raises(CallError, match='could not be restored safely'),
    ):
        await service.stop_for_pool('tank')

    assert service._pool_is_unavailable('tank') is True
    assert service._generate_and_validate_rc.await_args_list == [
        call(config, False),
        call(config, True),
        call(config, False),
    ]
    service.rc_preflight.assert_awaited_once_with('stop')


@pytest.mark.asyncio
async def test_pool_available_revalidates_rc_before_clearing_start_block():
    service, _ = service_with_middleware()
    config = raw_config(pool='tank', startup_delay=2, parallel_limit=4)
    service._raw_config = AsyncMock(return_value=config)
    service._validate_configured_row = AsyncMock(return_value=True)
    service._service_row = AsyncMock(return_value={'id': 9, 'srv_enable': True})
    service._generate_and_validate_rc = AsyncMock()
    service._unavailable_pool_names().add('tank')

    state = await service.pool_available('tank')

    assert state == {'matched': True, 'enabled': True}
    assert service._pool_is_unavailable('tank') is False
    assert service._generate_and_validate_rc.await_args_list == [
        call(config, False),
        call(config, True),
    ]


@pytest.mark.asyncio
async def test_attachment_delegate_skips_recovery_while_native_dataset_remains_locked():
    middleware = Mock()
    middleware.call = AsyncMock(return_value={
        **raw_config(pool='tank'),
        'enabled': True,
        'configuration_valid': False,
    })
    delegate = BastilleFSAttachmentDelegate(middleware)

    assert await delegate.query('/mnt/tank', True, {'locked': False}) == []

    middleware.call.return_value = {
        **raw_config(pool='tank'),
        'enabled': True,
        'configuration_valid': True,
    }
    assert await delegate.query('/mnt/tank', True, {'locked': False}) == [{
        'id': 'bastille:boot-enabled',
        'name': 'Bastille',
        'pool': 'tank',
        'boot_enabled': True,
    }]


@pytest.mark.asyncio
async def test_attachment_delegate_does_not_promote_runtime_only_store_to_boot_enabled():
    middleware = Mock()
    middleware.call = AsyncMock(return_value={'matched': True, 'enabled': False})
    delegate = BastilleFSAttachmentDelegate(middleware)
    attachment = {
        'id': 'bastille:runtime-only',
        'name': 'Bastille',
        'pool': 'tank',
        'boot_enabled': False,
    }

    await delegate.toggle([attachment], False)
    await delegate.toggle([attachment], True)

    assert middleware.call.await_args_list == [
        call('bastille.stop_for_pool', 'tank', True),
        call('bastille.pool_available', 'tank'),
    ]


@pytest.mark.asyncio
async def test_dataset_post_unlock_unblocks_store_without_starting_disabled_attachments():
    middleware = Mock()
    middleware.call = AsyncMock(side_effect=[
        {
            **raw_config(pool='tank'),
            'switching_pool': True,
        },
        {'matched': True, 'enabled': True},
    ])

    await _bastille_datasets_available(
        middleware,
        [{'name': 'tank/bastille/config'}],
    )

    assert middleware.call.await_args_list == [
        call('bastille.rc_config'),
        call('bastille.pool_available', 'tank'),
    ]


@pytest.mark.asyncio
async def test_dataset_post_unlock_clears_marker_for_retained_inactive_store():
    middleware = Mock()
    middleware.call = AsyncMock(side_effect=[
        {
            **raw_config(pool='backup'),
            'switching_pool': False,
        },
        {'matched': False, 'enabled': False},
    ])

    await _bastille_datasets_available(
        middleware,
        [{'name': 'tank/bastille'}],
    )

    assert middleware.call.await_args_list == [
        call('bastille.rc_config'),
        call('bastille.pool_available', 'tank'),
    ]


@pytest.mark.asyncio
async def test_service_enable_validates_first_and_rolls_back_rc_generation_failure():
    middleware = Mock()
    middleware.call = AsyncMock()
    service = ServiceService(middleware)
    service_object = Mock()
    service_object.before_enable = AsyncMock()
    generation = 0

    async def dispatch(name, *args):
        nonlocal generation
        if name == 'datastore.query':
            return [{'id': 9, 'srv_service': 'bastille', 'srv_enable': False}]
        if name == 'service.object':
            return service_object
        if name == 'datastore.update':
            return 9
        if name == 'etc.generate':
            generation += 1
            if generation == 1:
                raise CallError('injected rc failure')
            return None
        if name == 'bastille.verify_current_rc':
            return True
        raise AssertionError(name)

    middleware.call.side_effect = dispatch
    with pytest.raises(CallError, match='injected rc failure'):
        await service.do_update('bastille', {'enable': True})

    service_object.before_enable.assert_awaited_once_with()
    assert middleware.call.await_args_list.count(call(
        'datastore.update', 'services.services', 9, {'srv_enable': True}
    )) == 1
    assert middleware.call.await_args_list.count(call(
        'datastore.update', 'services.services', 9, {'srv_enable': False}
    )) == 1


@pytest.mark.asyncio
async def test_service_enable_verifies_generated_bastille_rc_before_success():
    middleware = Mock()
    middleware.call = AsyncMock()
    service = ServiceService(middleware)
    service_object = Mock()
    service_object.before_enable = AsyncMock()

    async def dispatch(name, *args):
        if name == 'datastore.query':
            return [{'id': 9, 'srv_service': 'bastille', 'srv_enable': False}]
        if name == 'service.object':
            return service_object
        if name == 'datastore.update':
            return 9
        if name == 'etc.generate':
            return None
        if name == 'bastille.verify_current_rc':
            return True
        raise AssertionError(name)

    middleware.call.side_effect = dispatch
    assert await service.do_update('bastille', {'enable': True}) == 9

    service_object.before_enable.assert_awaited_once_with()
    middleware.call.assert_any_await('bastille.verify_current_rc')


@pytest.mark.asyncio
async def test_rc_service_uses_jail_state_not_a_daemon_process():
    middleware = Mock()
    middleware.call = AsyncMock(return_value=['one'])
    service = BastilleRcService(middleware)

    state = await service._get_state_freebsd()

    assert state.running is True
    assert state.pids == []
    assert await service._identify_freebsd('bastille') is False
    middleware.call.assert_awaited_once_with('bastille.running_jails')


@pytest.mark.asyncio
async def test_rc_service_requires_completed_configuration_before_enable_and_start():
    middleware = Mock()
    middleware.call = AsyncMock(side_effect=[True, {'pool': 'tank', 'enabled': True}, True])
    service = BastilleRcService(middleware)

    await service.before_enable()
    await service.before_start()

    assert middleware.call.await_args_list == [
        call('bastille.validate_startable'),
        call('bastille.rc_config'),
        call('bastille.validate_startable'),
    ]


@pytest.mark.asyncio
async def test_rc_service_start_waits_for_pool_switch_lifecycle_lock():
    from middlewared.service import LOCKS

    middleware = Mock()
    middleware.call = AsyncMock()
    service = BastilleRcService(middleware)
    service._freebsd_service = AsyncMock(return_value=SimpleNamespace(returncode=0))
    lifecycle_lock = LOCKS['bastille_lifecycle_internal']

    await lifecycle_lock.acquire()
    try:
        start = asyncio.create_task(service._start_freebsd())
        await asyncio.sleep(0)
        service._freebsd_service.assert_not_awaited()
    finally:
        lifecycle_lock.release()

    await start
    assert middleware.call.await_args_list == [
        call('bastille.validate_startable'),
        call('bastille.rc_postflight', 'start'),
    ]
    service._freebsd_service.assert_awaited_once_with('bastille', 'start')


@pytest.mark.asyncio
async def test_rc_service_stop_fails_if_any_structural_bastille_root_remains_live():
    middleware = Mock()
    middleware.call = AsyncMock(side_effect=[
        {'pool': 'tank'},
        True,
        ['orphan'],
    ])
    service = BastilleRcService(middleware)
    service._freebsd_service = AsyncMock(return_value=SimpleNamespace(returncode=0))

    with pytest.raises(CallError, match='orphan'):
        await service._stop_freebsd()

    service._freebsd_service.assert_awaited_once_with('bastille', 'stop', force=True)
    assert middleware.call.await_args_list == [
        call('bastille.rc_config'),
        call('bastille.rc_preflight', 'stop'),
        call('bastille.running_jails_strict'),
    ]


@pytest.mark.asyncio
async def test_rc_service_restart_uses_guarded_stop_and_start_paths():
    middleware = Mock()
    middleware.call = AsyncMock(side_effect=[
        True,
        {'pool': 'tank'},
        True,
        [],
        True,
        True,
        True,
    ])
    service = BastilleRcService(middleware)
    assert service.restartable is True
    service._freebsd_service = AsyncMock(return_value=SimpleNamespace(returncode=0))

    await service._restart_freebsd()

    assert middleware.call.await_args_list == [
        call('bastille.validate_startable'),
        call('bastille.rc_config'),
        call('bastille.rc_preflight', 'stop'),
        call('bastille.running_jails_strict'),
        call('bastille.rc_postflight', 'stop'),
        call('bastille.validate_startable'),
        call('bastille.rc_postflight', 'start'),
    ]
    assert service._freebsd_service.await_args_list == [
        call('bastille', 'stop', force=True),
        call('bastille', 'start'),
    ]


@pytest.mark.asyncio
async def test_startability_check_blocks_rc_start_during_unverified_recovery():
    service, _ = service_with_middleware()
    service._raw_config = AsyncMock(return_value=raw_config(pool='tank'))
    service._pool_switch_in_progress = True
    service._validate_configured_row = AsyncMock()

    with pytest.raises(CallError, match='changing or recovering'):
        await service.validate_startable()

    service._validate_configured_row.assert_not_awaited()


@pytest.mark.asyncio
async def test_rc_service_disables_autostart_after_postflight_failure():
    middleware = Mock()

    async def dispatch(name, *args):
        if name == 'bastille.validate_startable':
            return True
        if name == 'bastille.rc_postflight':
            raise CallError('injected topology failure')
        if name == 'bastille.disable_service':
            return True
        raise AssertionError(name)

    middleware.call = AsyncMock(side_effect=dispatch)
    service = BastilleRcService(middleware)
    service._freebsd_service = AsyncMock(return_value=SimpleNamespace(returncode=0))

    with pytest.raises(CallError, match='injected topology failure'):
        await service._start_freebsd()

    middleware.call.assert_any_await('bastille.disable_service')


@pytest.mark.asyncio
async def test_failed_start_validation_disables_the_service():
    middleware = Mock()
    middleware.call = AsyncMock()
    service = BastilleRcService(middleware)

    async def dispatch(name, *args):
        if name == 'bastille.rc_config':
            return {'pool': 'tank', 'enabled': True}
        if name == 'bastille.validate_startable':
            raise CallError('configuration damaged')
        if name == 'bastille.disable_service':
            return 9
        raise AssertionError(name)

    middleware.call.side_effect = dispatch
    with pytest.raises(CallError, match='configuration damaged'):
        await service.before_start()

    middleware.call.assert_any_await('bastille.disable_service')


@pytest.mark.asyncio
async def test_failed_rc_start_disables_the_service():
    middleware = Mock()
    middleware.call = AsyncMock(return_value=9)
    service = BastilleRcService(middleware)
    service._freebsd_service = AsyncMock(return_value=SimpleNamespace(returncode=1))

    with pytest.raises(CallError, match='failed to start'):
        await service._start_freebsd()

    assert middleware.call.await_args_list == [
        call('bastille.validate_startable'),
        call('bastille.disable_service'),
    ]


MIRROR_INDEX = """<html><head><title>Index of /ftp/releases/amd64/</title></head><body>
<a href="../">../</a>
<a href="12.4-RELEASE/">12.4-RELEASE/</a>
<a href="13.5-RELEASE/">13.5-RELEASE/</a>
<a href="14.2-RELEASE/">14.2-RELEASE/</a>
<a href="14.3-RELEASE/">14.3-RELEASE/</a>
<a href="15.1-RELEASE/">15.1-RELEASE/</a>
<a href="ISO-IMAGES/">ISO-IMAGES/</a>
</body></html>"""


def test_query_address_parser_reports_dhcp_and_slaac_instead_of_nothing():
    rc_config = (
        'ifconfig_vnet0="SYNCDHCP"\n'
        'ifconfig_vnet0_ipv6="inet6 -ifdisabled accept_rtadv"\n'
    )
    assert BastilleService._extract_jail_addresses('', rc_config) == {4: ['DHCP'], 6: ['SLAAC']}
    # Bastille also accepts the bare keyword.
    assert BastilleService._extract_jail_addresses('', 'ifconfig_vnet0="DHCP"\n') == {4: ['DHCP'], 6: []}


def test_parse_live_addresses_reads_ifconfig_and_drops_loopback_link_local_and_garbage():
    output = (
        'lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> metric 0 mtu 16384\n'
        '\tinet 127.0.0.1 netmask 0xff000000\n'
        '\tinet6 ::1 prefixlen 128\n'
        'vnet0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500\n'
        '\tinet 198.51.100.240 netmask 0xffffff00 broadcast 198.51.100.255\n'
        '\tinet6 fe80::a8bb:ccff:fedd:eeff%vnet0 prefixlen 64 scopeid 0x2\n'
        '\tinet6 2001:db8::240 prefixlen 64\n'
        '\tinet 198.51.100.240/24\n'
        '\tinet not-an-address netmask 0xffffff00\n'
        '\tinet 192.0.2.9 netmask 255.255.255.0\n'
    )
    assert BastilleService._parse_live_addresses(output) == {
        4: ['vnet0|198.51.100.240/24', 'vnet0|192.0.2.9/24'],
        6: ['vnet0|2001:db8::240/64'],
    }
    assert BastilleService._parse_live_addresses('') == {4: [], 6: []}


@pytest.mark.asyncio
async def test_running_jail_ids_and_disk_usage_tolerate_unreadable_commands():
    service, _ = service_with_middleware()
    config = raw_config(pool='tank')
    paths = {'jails': '/mnt/tank/bastille/jails', 'jails_dataset': 'tank/bastille/jails'}

    jls = SimpleNamespace(returncode=0, stdout=(
        'jid=12 name=dhcpjail path=/mnt/tank/bastille/jails/dhcpjail/root\n'
        'jid=13 name=ioc-web path=/mnt/tank/iocage/jails/web/root\n'
        'jid=x name=broken path=/mnt/tank/bastille/jails/broken/root\n'
        'jid=14 name=other path=/mnt/tank/bastille/jails/dhcpjail/root\n'
    ), stderr='')
    zfs = SimpleNamespace(returncode=0, stdout=(
        'tank/bastille/jails\t258000000\n'
        'tank/bastille/jails/dhcpjail\t79691776\n'
        'tank/bastille/jails/dhcpjail/root\t79000000\n'
        'tank/bastille/jails/weird\tnotanumber\n'
    ), stderr='')
    with patch('middlewared.plugins.bastille_freebsd.bastille_paths', return_value=paths), \
            patch('middlewared.plugins.bastille_freebsd.run', AsyncMock(side_effect=[jls, zfs])):
        assert await service._running_jail_ids(config) == {'dhcpjail': 12}
        assert await service._jail_disk_usage(config) == {'dhcpjail': 79691776}

    failing = SimpleNamespace(returncode=1, stdout='', stderr='nope')
    with patch('middlewared.plugins.bastille_freebsd.bastille_paths', return_value=paths), \
            patch('middlewared.plugins.bastille_freebsd.run', AsyncMock(side_effect=[failing, failing])):
        assert await service._running_jail_ids(config) == {}
        assert await service._jail_disk_usage(config) == {}

    with patch('middlewared.plugins.bastille_freebsd.bastille_paths', return_value=paths), \
            patch('middlewared.plugins.bastille_freebsd.run', AsyncMock(side_effect=FileNotFoundError())):
        assert await service._running_jail_ids(config) == {}
        assert await service._jail_disk_usage(config) == {}
    assert await service._running_jail_ids(raw_config()) == {}
    assert await service._jail_disk_usage(raw_config()) == {}


@pytest.mark.asyncio
async def test_live_jail_addresses_fall_back_to_none_on_failure_or_timeout():
    service, _ = service_with_middleware()
    good = SimpleNamespace(returncode=0, stdout='vnet0: flags=1 mtu 1500\n\tinet 203.0.113.5/24\n', stderr='')
    with patch('middlewared.plugins.bastille_freebsd.run', AsyncMock(return_value=good)) as run_mock:
        assert await service._live_jail_addresses('dhcpjail') == {4: ['vnet0|203.0.113.5/24'], 6: []}
    assert run_mock.await_args.args[:4] == ('/usr/sbin/jexec', '-l', 'dhcpjail', '/sbin/ifconfig')

    failed = SimpleNamespace(returncode=1, stdout='', stderr='jexec: jail "dhcpjail" not found')
    with patch('middlewared.plugins.bastille_freebsd.run', AsyncMock(return_value=failed)):
        assert await service._live_jail_addresses('dhcpjail') is None
    with patch('middlewared.plugins.bastille_freebsd.run', AsyncMock(side_effect=asyncio.TimeoutError())):
        assert await service._live_jail_addresses('dhcpjail') is None
    with patch('middlewared.plugins.bastille_freebsd.run', AsyncMock(side_effect=FileNotFoundError())):
        assert await service._live_jail_addresses('dhcpjail') is None


def _dhcp_jail(tmp_path, name='dhcpjail'):
    jails_path = tmp_path / 'jails'
    jail = jails_path / name
    (jail / 'root/etc').mkdir(parents=True)
    (jail / 'jail.conf').write_text(
        f'{name} {{\n  vnet;\n  vnet.interface = e0b_{name};\n  path = {jail / "root"};\n}}\n'
    )
    (jail / 'root/etc/rc.conf').write_text('ifconfig_vnet0="SYNCDHCP"\n')
    return jails_path


@pytest.mark.asyncio
async def test_query_reports_jid_disk_and_live_addresses_for_a_running_dhcp_vnet_jail(tmp_path):
    service, _ = service_with_middleware()
    service._raw_config = AsyncMock(return_value=raw_config(pool='tank'))
    service._validate_configured_row = AsyncMock(return_value=True)
    service._managed_dataset_owners = AsyncMock(return_value={})
    service._running_jails = AsyncMock(return_value=['dhcpjail'])
    service._running_jail_ids = AsyncMock(return_value={'dhcpjail': 12})
    service._jail_disk_usage = AsyncMock(return_value={'dhcpjail': 79691776})
    service._live_jail_addresses = AsyncMock(return_value={4: ['vnet0|198.51.100.240/24'], 6: []})
    jails_path = _dhcp_jail(tmp_path)

    with patch(
        'middlewared.plugins.bastille_freebsd.bastille_paths',
        return_value={'jails': str(jails_path), 'jails_dataset': 'tank/bastille/jails',
                      'releases': str(tmp_path / 'releases'), 'logs': str(tmp_path / 'logs')},
    ):
        [row] = await service.query.wraps(service, [], {})

    assert row['state'] == 'up'
    assert row['jid'] == 12
    assert row['disk_used'] == 79691776
    assert row['ip4_addr'] == 'vnet0|198.51.100.240/24'
    assert row['address_source'] == 'live'
    assert row['operable'] is True
    service._live_jail_addresses.assert_awaited_once_with('dhcpjail')


@pytest.mark.asyncio
async def test_query_reports_dhcp_for_a_stopped_vnet_jail_without_reading_inside_it(tmp_path):
    service, _ = service_with_middleware()
    service._raw_config = AsyncMock(return_value=raw_config(pool='tank'))
    service._validate_configured_row = AsyncMock(return_value=True)
    service._managed_dataset_owners = AsyncMock(return_value={})
    service._running_jails = AsyncMock(return_value=[])
    service._running_jail_ids = AsyncMock(return_value={})
    service._jail_disk_usage = AsyncMock(return_value={})
    service._live_jail_addresses = AsyncMock()
    jails_path = _dhcp_jail(tmp_path)

    with patch(
        'middlewared.plugins.bastille_freebsd.bastille_paths',
        return_value={'jails': str(jails_path), 'jails_dataset': 'tank/bastille/jails',
                      'releases': str(tmp_path / 'releases'), 'logs': str(tmp_path / 'logs')},
    ):
        [row] = await service.query.wraps(service, [], {})

    assert row['state'] == 'down'
    assert row['jid'] is None
    assert row['disk_used'] is None
    assert row['ip4_addr'] == 'DHCP'
    assert row['address_source'] == 'config'
    service._live_jail_addresses.assert_not_awaited()
    service._running_jail_ids.assert_not_awaited()


@pytest.mark.asyncio
async def test_query_keeps_the_configured_address_when_the_live_read_fails(tmp_path):
    service, _ = service_with_middleware()
    service._raw_config = AsyncMock(return_value=raw_config(pool='tank'))
    service._validate_configured_row = AsyncMock(return_value=True)
    service._managed_dataset_owners = AsyncMock(return_value={})
    service._running_jails = AsyncMock(return_value=['dhcpjail'])
    service._running_jail_ids = AsyncMock(return_value={})
    service._jail_disk_usage = AsyncMock(return_value={})
    service._live_jail_addresses = AsyncMock(return_value=None)
    jails_path = _dhcp_jail(tmp_path)

    with patch(
        'middlewared.plugins.bastille_freebsd.bastille_paths',
        return_value={'jails': str(jails_path), 'jails_dataset': 'tank/bastille/jails',
                      'releases': str(tmp_path / 'releases'), 'logs': str(tmp_path / 'logs')},
    ):
        [row] = await service.query.wraps(service, [], {})

    assert row['state'] == 'up'
    assert row['jid'] is None
    assert row['ip4_addr'] == 'DHCP'
    assert row['address_source'] == 'config'


# ---------------------------------------------------------------------------
# the internal development record: middleware observes jails; the bastille CLI manages them.

from types import SimpleNamespace as _SimpleNamespace  # noqa: E402
from unittest.mock import AsyncMock as _AsyncMock, Mock as _Mock, patch as _patch  # noqa: E402
from middlewared.plugins.bastille_.utils import BASTILLE_PATH as _BASTILLE_PATH  # noqa: E402
from middlewared.plugins.bastille_freebsd import BastilleFSAttachmentDelegate as _Delegate  # noqa: E402


def test_the_management_api_is_gone():
    for name in (
        'create', 'delete', 'set_boot', 'edit', 'edit_config', 'export', 'update', 'release_update',
        'console_target', 'mount_add', 'mount_remove', 'mount_edit', 'mounts',
        'mount_source_choices', 'mount_destination_rules', 'mount_attachments', 'bootstrap', 'release_delete',
        'release_choices', 'remote_release_choices', 'interface_choices', 'templates', 'template_details',
        'template_import', 'template_apply', 'template_sources', 'template_bootstrap',
        'template_source_delete', 'template_apply_imported', '_validate_owned_jail', '_run_bastille',
    ):
        assert not hasattr(BastilleService, name), name
    # the internal development record brought start, stop and restart back as the one kind of
    # management the page offers: the lifecycle the iocage rows have.
    for name in ('query', 'releases', 'logs', 'config', 'configure', 'rc_preflight', 'rc_postflight',
                 'validate_startable', 'stop_for_pool', 'start_after_export', 'start', 'stop', 'restart'):
        assert hasattr(BastilleService, name), name


@pytest.mark.asyncio
async def test_query_marks_a_jail_whose_root_escapes_its_directory_not_operable(tmp_path):
    service, _ = service_with_middleware()
    service._raw_config = _AsyncMock(return_value=raw_config(pool='tank'))
    service._validate_configured_row = _AsyncMock(return_value=True)
    service._running_jails = _AsyncMock(return_value=[])
    service._running_jail_ids = _AsyncMock(return_value={})
    service._jail_disk_usage = _AsyncMock(return_value={})
    jails_path = tmp_path / 'jails'
    for name, root in (('good', None), ('escapee', tmp_path / 'elsewhere')):
        jail = jails_path / name
        (jail / 'root/etc').mkdir(parents=True)
        path = root or (jail / 'root')
        (jail / 'jail.conf').write_text(f'{name} {{\n  path = {path};\n  ip4.addr = "em0|192.0.2.9/24";\n}}\n')
    with _patch('middlewared.plugins.bastille_freebsd.bastille_paths', return_value={
        'jails': str(jails_path), 'jails_dataset': 'tank/bastille/jails',
        'releases': str(tmp_path / 'releases'), 'logs': str(tmp_path / 'logs'),
    }):
        rows = {row['name']: row for row in await service.query.wraps(service, [], {})}
    assert rows['good']['operable'] is True and rows['good']['validation_error'] is None
    assert rows['escapee']['operable'] is False
    assert 'root inside its own storage' in rows['escapee']['validation_error']
    assert set(rows['good']) == {
        'id', 'name', 'engine', 'state', 'jid', 'ip4_addr', 'ip6_addr', 'address_source', 'path',
        'release', 'interface', 'boot', 'disk_used', 'operable', 'validation_error', 'running_error',
    }


@pytest.mark.asyncio
async def test_releases_are_read_only_and_list_every_release_on_disk(tmp_path):
    service, _ = service_with_middleware()
    service._lifecycle_config = _AsyncMock(return_value=raw_config(pool='tank'))
    service.query = _AsyncMock(return_value=[
        {'name': 'web', 'release': '15.0-RELEASE'}, {'name': 'db', 'release': '15.0-RELEASE'},
    ])
    sizes = {
        'tank/bastille/releases/15.1-RELEASE': 390070272, 'tank/bastille/cache/15.1-RELEASE': 164626432,
        'tank/bastille/releases/15.0-RELEASE': 576557056, 'tank/bastille/cache/15.0-RELEASE': 165371904,
    }
    service._dataset_used_bytes = _AsyncMock(side_effect=lambda dataset: sizes[dataset])
    releases_path = tmp_path / 'releases'
    for name in ('15.0-RELEASE', '15.1-RELEASE', 'not-a-release'):
        (releases_path / name).mkdir(parents=True)
    (releases_path / '14.3-RELEASE').symlink_to(releases_path / '15.0-RELEASE', target_is_directory=True)
    with _patch('middlewared.plugins.bastille_freebsd.bastille_paths', return_value={
        'releases': str(releases_path), 'releases_dataset': 'tank/bastille/releases',
        'cache_dataset': 'tank/bastille/cache',
    }):
        result = await service.releases()
    assert result == [
        {'name': '15.1-RELEASE', 'consumers': [], 'used_bytes': 390070272, 'cache_bytes': 164626432},
        {'name': '15.0-RELEASE', 'consumers': ['db', 'web'], 'used_bytes': 576557056, 'cache_bytes': 165371904},
    ]


@pytest.mark.asyncio
async def test_logs_read_any_identified_jail_and_report_an_empty_log_before_first_start(tmp_path):
    service, middleware = service_with_middleware()
    service._lifecycle_config = _AsyncMock(return_value=raw_config(pool='tank'))
    middleware.run_in_thread = _AsyncMock(side_effect=lambda fn, *args: fn(*args))
    jails_path = tmp_path / 'jails'
    logs_path = tmp_path / 'logs'
    logs_path.mkdir()
    jail = jails_path / 'my-cli.jail'
    (jail / 'root').mkdir(parents=True)
    (jail / 'jail.conf').write_text(f'my-cli.jail {{\n  path = {jail / "root"};\n}}\n')
    with _patch('middlewared.plugins.bastille_freebsd.bastille_paths', return_value={
        'jails': str(jails_path), 'logs': str(logs_path),
    }):
        assert await service.logs('my-cli.jail', 1024) == {'name': 'my-cli.jail', 'content': '', 'truncated': False}
        (logs_path / 'my-cli.jail_console.log').write_text('booted\n')
        assert await service.logs('my-cli.jail', 1024) == {
            'name': 'my-cli.jail', 'content': 'booted\n', 'truncated': False,
        }
        with pytest.raises(CallError, match='does not exist'):
            await service.logs('missing', 1024)


@pytest.mark.asyncio
async def test_rc_postflight_reports_a_boot_jail_that_did_not_come_up():
    service, _ = service_with_middleware()
    service._raw_config = _AsyncMock(return_value=raw_config(pool='tank'))
    service.query = _AsyncMock(return_value=[
        {'name': 'web', 'boot': True, 'state': 'up'},
        {'name': 'db', 'boot': True, 'state': 'down'},
        {'name': 'lab', 'boot': False, 'state': 'down'},
    ])
    with pytest.raises(CallError, match=r'left boot-enabled jail\(s\) stopped: db'):
        await service.rc_postflight('start')
    service.query = _AsyncMock(return_value=[{'name': 'web', 'boot': True, 'state': 'up'}])
    assert await service.rc_postflight('restart') is True
    assert await service.rc_postflight('stop') is True
    service.query.assert_awaited_once()
    with pytest.raises(CallError):
        await service.rc_postflight('reload')


@pytest.mark.asyncio
async def test_validate_startable_only_vouches_for_the_configuration():
    service, _ = service_with_middleware()
    service._lifecycle_config = _AsyncMock(return_value=raw_config(pool='tank'))
    assert await service.validate_startable() is True
    service._lifecycle_config.assert_awaited_once()


@pytest.mark.asyncio
async def test_pool_delegate_claims_nothing_outside_the_store_and_restarts_after_a_failed_export():
    middleware = _Mock()
    calls = {
        'bastille.rc_config': {'pool': 'tank', 'configuration_valid': True, 'enabled': True},
        'bastille.pool_stop_running': ['web', 'db'],
        'bastille.pool_available': {'matched': True},
        'bastille.running_jails_strict': ['web'],
    }
    middleware.call = _AsyncMock(side_effect=lambda method, *args: calls.get(method, True))
    delegate = _Delegate(middleware)
    assert await delegate.query('/mnt/tank/data', True) == []
    assert await delegate.query('/mnt/tank/bastille/jails', True) == [
        {'id': 'bastille:boot-enabled', 'name': 'Bastille', 'pool': 'tank', 'boot_enabled': True},
    ]
    attachments = [{
        'id': 'bastille:boot-enabled', 'name': 'Bastille', 'pool': 'tank', 'boot_enabled': True,
        'export_stop_attempted': True,
    }]
    assert await delegate.rollback_export(attachments) is True
    awaited = [call.args for call in middleware.call.await_args_list]
    assert ('bastille.start_after_export', 'db') in awaited
    assert ('bastille.start_after_export', 'web') not in awaited
    assert not hasattr(delegate, '_require_mounts_detached')


@pytest.mark.asyncio
async def test_start_after_export_runs_bastille_start_and_reports_failure():
    service, _ = service_with_middleware()
    ok = _SimpleNamespace(returncode=0, stdout='', stderr='')
    with _patch('middlewared.plugins.bastille_freebsd.run', _AsyncMock(return_value=ok)) as run_mock:
        assert await service.start_after_export('web') is True
    assert run_mock.await_args.args[:3] == (_BASTILLE_PATH, 'start', 'web')
    failed = _SimpleNamespace(returncode=1, stdout='', stderr='[ERROR]: no such jail')
    with _patch('middlewared.plugins.bastille_freebsd.run', _AsyncMock(return_value=failed)):
        with pytest.raises(CallError, match='no such jail'):
            await service.start_after_export('web')
    with pytest.raises(CallError):
        await service.start_after_export('all')


# ---------------------------------------------------------------------------
# the internal development record: start, stop and restart one jail -- identity, the CLI, and
# a check from jls that the CLI did it. No ownership, nothing written to the jail.

def _lifecycle_service(running_after, config=None):
    service, middleware = service_with_middleware()
    service._lifecycle_config = _AsyncMock(return_value=config or raw_config(pool='tank'))
    service._validate_jail_identity = _AsyncMock(
        return_value={'name': 'web', 'path': '/mnt/tank/bastille/jails/web',
                      'root': '/mnt/tank/bastille/jails/web/root'}
    )
    service._running_jails = _AsyncMock(return_value=running_after)
    return service, middleware


@pytest.mark.parametrize('action,running_after', [
    ('start', ['web']),
    ('stop', []),
    ('restart', ['web']),
])
@pytest.mark.asyncio
async def test_a_lifecycle_action_runs_the_cli_for_that_jail_and_confirms_it_from_jls(action, running_after):
    service, _ = _lifecycle_service(running_after)
    ok = _SimpleNamespace(returncode=0, stdout='', stderr='')
    with _patch('middlewared.plugins.bastille_freebsd.run', _AsyncMock(return_value=ok)) as run_mock:
        assert await getattr(service, action).wraps(service, _Mock(), 'web') is True
    assert run_mock.await_args.args[:3] == (_BASTILLE_PATH, action, 'web')
    # Identity is checked before the CLI runs, on the configured store.
    service._validate_jail_identity.assert_awaited_once()
    assert service._validate_jail_identity.await_args.args[1] == 'web'
    # The outcome is read strictly, the way stop_for_pool reads it.
    service._running_jails.assert_awaited_once()
    assert service._running_jails.await_args.kwargs == {'strict': True}


@pytest.mark.parametrize('action,running_after,expected', [
    ('start', [], 'running'),
    ('restart', [], 'running'),
    ('stop', ['web'], 'stopped'),
])
@pytest.mark.asyncio
async def test_a_cli_that_exits_zero_but_did_not_change_the_state_is_reported(action, running_after, expected):
    service, _ = _lifecycle_service(running_after)
    ok = _SimpleNamespace(returncode=0, stdout='', stderr='')
    with _patch('middlewared.plugins.bastille_freebsd.run', _AsyncMock(return_value=ok)):
        with pytest.raises(CallError, match=f"Bastille {action} did not leave jail 'web' {expected}"):
            await getattr(service, action).wraps(service, _Mock(), 'web')


@pytest.mark.asyncio
async def test_the_cli_failure_text_is_the_error_and_jls_is_not_consulted():
    service, _ = _lifecycle_service(['web'])
    failed = _SimpleNamespace(returncode=1, stdout='', stderr='[ERROR]: web is not running.')
    with _patch('middlewared.plugins.bastille_freebsd.run', _AsyncMock(return_value=failed)):
        with pytest.raises(CallError, match='bastille stop web failed: .*web is not running'):
            await service.stop.wraps(service, _Mock(), 'web')
    service._running_jails.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_jail_that_fails_identity_is_refused_before_the_cli_runs():
    service, _ = _lifecycle_service(['web'])
    service._validate_jail_identity = _AsyncMock(
        side_effect=CallError("Bastille jail 'web' is not configured with a root inside its own storage.")
    )
    with _patch('middlewared.plugins.bastille_freebsd.run', _AsyncMock()) as run_mock:
        with pytest.raises(CallError, match='root inside its own storage'):
            await service.start.wraps(service, _Mock(), 'web')
    run_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_an_unconfigured_store_refuses_before_identity_or_the_cli():
    service, _ = _lifecycle_service(['web'])
    service._lifecycle_config = _AsyncMock(
        side_effect=CallError('Bastille storage configuration is changing or recovering.')
    )
    with _patch('middlewared.plugins.bastille_freebsd.run', _AsyncMock()) as run_mock:
        with pytest.raises(CallError, match='changing or recovering'):
            await service.restart.wraps(service, _Mock(), 'web')
    run_mock.assert_not_awaited()
    service._validate_jail_identity.assert_not_awaited()


def test_lifecycle_jobs_share_the_pool_transition_lock_and_one_job_lock():
    # The internal lock is the one stop_for_pool holds, so a pool export cannot race a
    # start; the job lock serialises the three actions with each other.
    for name in ('start', 'stop', 'restart'):
        method = getattr(BastilleService, name)
        assert getattr(method, '_job', None), name
        assert method._job['lock'] == 'bastille_jail_lifecycle', name
