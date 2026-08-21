import json
from pathlib import Path

import pytest

from middlewared.plugins.applications_.utils import (
    APPLICATION_LABEL,
    MANAGED_LABEL,
    TRANSACTION_LABEL,
    application_paths,
    lan_conflist_path,
    lan_managed_conflist_path,
    lan_managed_network_name,
    lan_network_name,
    render_lan_conflist,
    render_managed_leg_conflist,
    podman_create_args,
    podman_environment,
    public_record,
    render_containers_conf,
    render_storage_conf,
    temporary_environment_file,
    validate_image_reference,
    validate_mount_target,
)


def application_record():
    return {
        'name': 'demo',
        'container_name': 'freecore-app-demo',
        'image': 'registry.example/demo:1',
        'restart_policy': 'always',
        'annotations': [
            {'name': 'org.freebsd.jail.allow.mlock', 'value': 'true'},
        ],
        'environment': [
            {'name': 'TOKEN', 'value': 'secret-value'},
            {'name': 'MODE', 'value': 'production'},
        ],
        'ports': [
            {'host_port': 8443, 'container_port': 443, 'protocol': 'tcp'},
        ],
        'volumes': [
            {
                'name': 'config',
                'source': '/mnt/tank/applications/data/demo/config',
                'target': '/config',
                'read_only': True,
            },
        ],
    }


def test_application_paths_are_confined_to_one_pool_hierarchy():
    paths = application_paths('tank')

    assert paths['dataset'] == 'tank/applications'
    assert paths['storage'] == '/mnt/tank/applications/storage'
    assert paths['records'] == '/mnt/tank/applications/records'
    assert all(
        not path.startswith('/mnt/') or
        path == '/mnt/tank/applications' or
        path.startswith('/mnt/tank/applications/')
        for path in paths.values()
    )


def test_rendered_runtime_configuration_uses_zfs_and_managed_paths():
    storage = render_storage_conf('tank')
    containers = render_containers_conf('tank', '10.88.0.0/16')

    assert 'driver = "zfs"' in storage
    assert 'graphroot = "/mnt/tank/applications/storage"' in storage
    assert 'runroot = "/var/run/freecore-applications/storage"' in storage
    assert 'network_backend = "cni"' in containers
    assert 'default_subnet = "10.88.0.0/16"' in containers
    assert 'network_config_dir = "/mnt/tank/applications/config/cni/net.d"' in containers
    assert podman_environment('tank') == {
        'CONTAINERS_STORAGE_CONF': '/mnt/tank/applications/config/storage.conf',
        'CONTAINERS_CONF_OVERRIDE': '/mnt/tank/applications/config/containers.conf',
    }


def test_podman_create_arguments_are_argv_safe_and_deterministic(tmp_path):
    record = application_record()
    with temporary_environment_file(record, str(tmp_path)) as environment_file:
        args = podman_create_args(record, '/test/podman', environment_file)

        assert environment_file not in ('', None)
        assert Path(environment_file).read_text() == 'MODE=production\nTOKEN=secret-value\n'
        assert '--env-file' in args
        assert args[args.index('--env-file') + 1] == environment_file
        assert 'secret-value' not in repr(args)

    assert args[0:2] == ['/test/podman', 'create']
    assert args[-2:] == ['--', 'registry.example/demo:1']
    assert '8443:443/tcp' in args
    assert '/mnt/tank/applications/data/demo/config:/config:ro' in args
    assert 'org.freebsd.jail.allow.mlock=true' in args
    assert not Path(environment_file).exists()


def test_podman_create_arguments_bind_container_to_one_install_transaction():
    transaction_id = 'a' * 32

    args = podman_create_args(
        application_record(), '/test/podman', '/tmp/application-env', transaction_id,
    )

    labels = [
        args[index + 1]
        for index, argument in enumerate(args[:-1])
        if argument == '--label'
    ]
    assert labels == [
        f'{TRANSACTION_LABEL}={transaction_id}',
        f'{MANAGED_LABEL}=true',
        f'{APPLICATION_LABEL}=demo',
    ]


def test_environment_file_rejects_multiline_values(tmp_path):
    record = application_record()
    record['environment'][0]['value'] = 'line-one\nline-two'

    with (
        pytest.raises(ValueError, match='newline'),
        temporary_environment_file(record, str(tmp_path)),
    ):
        pass


def test_public_record_never_returns_environment_values():
    private = application_record()
    public = public_record(private)

    assert public['environment'] == [
        {'name': 'TOKEN', 'set': True},
        {'name': 'MODE', 'set': True},
    ]
    assert private['environment'][0]['value'] == 'secret-value'
    assert 'secret-value' not in repr(public)


@pytest.mark.parametrize('target', ['relative', '/', '/not/../normalized', '/path:mode', '/bad\x00path'])
def test_invalid_mount_targets_are_rejected(target):
    with pytest.raises(ValueError):
        validate_mount_target(target)


@pytest.mark.parametrize(
    'image',
    ['--root=/tmp image', '-malicious', 'registry/image with-space', 'registry/image\x00tag'],
)
def test_ambiguous_image_references_are_rejected(image):
    with pytest.raises(ValueError):
        validate_image_reference(image)


# -- LAN-attached network mode (the internal development record) ----------------------


def test_lan_attached_create_arguments_join_the_application_network_and_publish_nothing():
    managed = application_record()
    defaulted = application_record()
    defaulted['network'] = {'mode': 'managed'}
    assert podman_create_args(managed, '/test/podman', '/tmp/application-env') == \
        podman_create_args(defaulted, '/test/podman', '/tmp/application-env')

    lan = application_record()
    lan['network'] = {
        'mode': 'lan', 'interface': 'em0', 'address': '192.0.2.201/24', 'gateway': '192.0.2.1',
    }
    args = podman_create_args(lan, '/test/podman', '/tmp/application-env')
    assert args[args.index('--network') + 1] == 'freecore-lan-demo'
    assert '--publish' not in args
    assert '8443:443/tcp' not in args
    # the declared ports stay on the record; only the publishing is gone
    assert lan['ports']


def test_lan_conflist_attaches_the_bridge_without_nat_or_addressing():
    rendered = render_lan_conflist('demo', 'bridge7', '192.0.2.201/24', '192.0.2.1')
    parsed = json.loads(rendered)
    assert parsed['name'] == lan_network_name('demo') == 'freecore-lan-demo'
    (plugin,) = parsed['plugins']
    assert plugin['type'] == 'bridge'
    assert plugin['bridge'] == 'bridge7'
    assert plugin['isGateway'] is False and plugin['ipMasq'] is False
    assert plugin['ipam'] == {
        'type': 'static',
        'addresses': [{'address': '192.0.2.201/24', 'gateway': '192.0.2.1'}],
        'routes': [{'dst': '0.0.0.0/0', 'gw': '192.0.2.1'}],
    }
    assert lan_conflist_path('tank', 'demo') == \
        '/mnt/tank/applications/config/cni/net.d/90-freecore-lan-demo.conflist'
    # deterministic: a re-render is byte-identical, so prepare is idempotent
    assert rendered == render_lan_conflist('demo', 'bridge7', '192.0.2.201/24', '192.0.2.1')


def test_public_record_presents_pre_481_records_as_managed():
    assert public_record(application_record())['network'] == {'mode': 'managed'}


def test_dual_attached_create_arguments_join_both_networks_in_order():
    lan = application_record()
    lan['network'] = {
        'mode': 'lan', 'interface': 'em0', 'address': '192.0.2.201/24', 'gateway': '192.0.2.1',
    }
    single = podman_create_args(lan, '/test/podman', '/tmp/application-env')
    assert single.count('--network') == 1

    lan['network'].update({'managed_access': True, 'managed_address': '10.88.255.254'})
    dual = podman_create_args(lan, '/test/podman', '/tmp/application-env')
    networks = [dual[i + 1] for i, a in enumerate(dual[:-1]) if a == '--network']
    assert networks == ['freecore-lan-demo', 'freecore-managed-demo']
    assert '--publish' not in dual


def test_managed_leg_conflist_is_an_onlink_presence_and_nothing_more():
    rendered = render_managed_leg_conflist('demo', 'cni-podman0', '10.88.255.254/16')
    parsed = json.loads(rendered)
    assert parsed['name'] == lan_managed_network_name('demo') == 'freecore-managed-demo'
    (plugin,) = parsed['plugins']
    assert plugin['bridge'] == 'cni-podman0'
    assert plugin['isGateway'] is False and plugin['ipMasq'] is False
    assert plugin['ipam'] == {'type': 'static', 'addresses': [{'address': '10.88.255.254/16'}]}
    # the LAN leg owns the only default route; this leg must carry none
    assert 'routes' not in plugin['ipam']
    assert lan_managed_conflist_path('tank', 'demo') == \
        '/mnt/tank/applications/config/cni/net.d/91-freecore-managed-demo.conflist'


def test_pinned_managed_application_requests_its_address_and_nothing_else_does():
    legacy = application_record()
    assert '--ip' not in podman_create_args(legacy, '/test/podman', '/tmp/application-env')

    pinned = application_record()
    pinned['network'] = {'mode': 'managed', 'bridge_address': '10.88.255.254'}
    args = podman_create_args(pinned, '/test/podman', '/tmp/application-env')
    assert args[args.index('--ip') + 1] == '10.88.255.254'
    assert '--network' not in args and '8443:443/tcp' in args

    lan = application_record()
    lan['network'] = {
        'mode': 'lan', 'interface': 'em0', 'address': '192.0.2.201/24', 'gateway': '192.0.2.1',
        'managed_access': True, 'managed_address': '10.88.255.253',
    }
    # the dual leg's address lives in its own static conflist, never in --ip
    assert '--ip' not in podman_create_args(lan, '/test/podman', '/tmp/application-env')


def test_unpublished_port_stays_on_the_managed_bridge():
    # the internal development record: a declared port without a host port is not published.
    record = application_record()
    record['network'] = {'mode': 'managed', 'bridge_address': '10.88.255.254'}
    record['ports'] = [
        {'host_port': None, 'container_port': 6379, 'protocol': 'tcp'},
        {'host_port': 8443, 'container_port': 443, 'protocol': 'tcp'},
        {'host_port': None, 'container_port': 5353, 'protocol': 'udp'},
    ]
    args = podman_create_args(record, '/test/podman', '/tmp/application-env')
    published = [args[index + 1] for index, value in enumerate(args) if value == '--publish']
    assert published == ['8443:443/tcp']
    assert args[args.index('--ip') + 1] == '10.88.255.254'
    assert public_record(record)['ports'] == record['ports']
