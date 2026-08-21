"""Convert & Import: the pure parts (the internal development record, #415, #445)."""
import json
import os
import shutil
import sqlite3
import tarfile
from unittest.mock import AsyncMock, Mock

import pytest

from middlewared.plugins.applications_.catalog import CatalogContractError
from middlewared.plugins.applications_.convert import (
    bundle,
    compose as compose_reader,
    export as export_tool,
    ini as ini_carry,
    jails as jail_sources,
    lift as lift_tool,
    plan as plan_doc,
    probes,
    recipe as recipe_store,
)
from middlewared.plugins.applications_convert_freebsd import ApplicationsConvertService
from middlewared.service_exception import CallError


GRAFANA_INI = """\
app_mode = production

[paths]
data = /var/db/grafana
logs = /var/log/grafana

[server]
http_port = 3000
root_url = https://grafana.example.org/
domain = grafana.example.org

[security]
secret_key = correct-horse-battery-staple
admin_password = hunter2

[alerting]
enabled = true

[smtp]
enabled = true
host = mail.example.org:587

[log]
mode = console
"""

COMPOSE = """\
services:
  grafana:
    image: grafana/grafana-oss:8.5.27
    container_name: grafana
    restart: unless-stopped
    user: "472"
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SERVER_ROOT_URL=https://grafana.example.org/
      - GF_PATHS_DATA=/var/lib/grafana
    ports:
      - "3000:3000"
    volumes:
      - ./grafana-data:/var/lib/grafana
      - grafana-etc:/etc/grafana
    healthcheck:
      test: ["CMD-SHELL", "wget -q -O - http://localhost:3000/api/health || exit 1"]
volumes:
  grafana-etc: {}
"""


def make_grafana_db(path, legacy_alerts=0, angular=False):
    connection = sqlite3.connect(path)
    connection.execute('CREATE TABLE alert (id INTEGER PRIMARY KEY, name TEXT)')
    for index in range(legacy_alerts):
        connection.execute('INSERT INTO alert (name) VALUES (?)', (f'alert-{index}',))
    connection.execute('CREATE TABLE dashboard (id INTEGER PRIMARY KEY, title TEXT, is_folder INTEGER, data TEXT)')
    panel_type = 'graph' if angular else 'timeseries'
    connection.execute(
        'INSERT INTO dashboard (title, is_folder, data) VALUES (?, 0, ?)',
        ('Overview', json.dumps({'panels': [{'type': panel_type, 'title': 'CPU'}]})),
    )
    connection.execute(
        'CREATE TABLE migration_log (id INTEGER PRIMARY KEY, migration_id TEXT)'
    )
    connection.execute("INSERT INTO migration_log (migration_id) VALUES ('add unified alerting')")
    connection.commit()
    connection.close()


def make_jail_root(root, version='8.5.27', legacy_alerts=0, angular=False, plugins=()):
    root.joinpath('usr/local/etc/grafana').mkdir(parents=True)
    root.joinpath('usr/local/etc/grafana/grafana.ini').write_text(GRAFANA_INI)
    data = root.joinpath('var/db/grafana')
    data.mkdir(parents=True)
    make_grafana_db(str(data / 'grafana.db'), legacy_alerts=legacy_alerts, angular=angular)
    (data / 'png').mkdir()
    (data / 'png' / 'render.png').write_bytes(b'png')
    for name, backend in plugins:
        plugin = data / 'plugins' / name
        plugin.mkdir(parents=True)
        plugin.joinpath('plugin.json').write_text(json.dumps({'id': name, 'backend': backend}))
    pkgdb = root.joinpath('var/db/pkg')
    pkgdb.mkdir(parents=True)
    connection = sqlite3.connect(str(pkgdb / 'local.sqlite'))
    connection.execute('CREATE TABLE packages (id INTEGER PRIMARY KEY, name TEXT, version TEXT)')
    connection.execute("INSERT INTO packages (name, version) VALUES ('grafana', ?)", (version,))
    connection.commit()
    connection.close()
    return root


def make_bundle(root, legacy_alerts=0):
    root.mkdir(parents=True, exist_ok=True)
    root.joinpath('compose.yaml').write_text(COMPOSE)
    data = root.joinpath('grafana-data')
    data.mkdir()
    make_grafana_db(str(data / 'grafana.db'), legacy_alerts=legacy_alerts)
    etc = root.joinpath('etc-staging')
    etc.mkdir()
    etc.joinpath('grafana.ini').write_text(GRAFANA_INI)
    with tarfile.open(root / 'grafana-etc.tar', 'w') as archive:
        archive.add(etc / 'grafana.ini', arcname='grafana.ini')
    return root


# -- recipes and equivalences -------------------------------------------------

def test_shipped_recipes_and_equivalences_validate():
    recipes = recipe_store.load_recipes()
    assert 'grafana' in recipes
    grafana = recipes['grafana']
    assert grafana['target']['catalog_id'] == 'daemonless:grafana'
    assert 'unified_alerting.*' in grafana['config']['deny']
    assert 'paths.*' in grafana['config']['deny']
    assert grafana['hops'][0]['when'] == 'legacy_alerts_present'
    equivalences = recipe_store.load_equivalences()
    assert any(entry['app'] == 'grafana' for entry in equivalences['entries'])


@pytest.mark.parametrize('reference, repository, tag', [
    ('grafana/grafana-oss:8.5.27', 'docker.io/grafana/grafana-oss', '8.5.27'),
    ('nginx', 'docker.io/library/nginx', 'latest'),
    ('lscr.io/linuxserver/jellyfin:latest', 'lscr.io/linuxserver/jellyfin', 'latest'),
    ('ghcr.io/daemonless/grafana:pkg', 'ghcr.io/daemonless/grafana', 'pkg'),
    ('localhost:5000/demo:1', 'localhost:5000/demo', '1'),
])
def test_image_references_normalize(reference, repository, tag):
    normalized = recipe_store.normalize_reference(reference)
    assert normalized['repository'] == repository
    assert normalized['tag'] == tag


def test_equivalence_lookup_orders_table_family_name_and_refusal():
    equivalences = recipe_store.load_equivalences()
    names = {'grafana', 'jellyfin', 'radarr'}
    assert recipe_store.equivalence_lookup('grafana/grafana:9.0', equivalences, names)['kind'] == 'table'
    family = recipe_store.equivalence_lookup('lscr.io/linuxserver/radarr', equivalences, names)
    assert family['kind'] == 'family' and family['app'] == 'radarr'
    suggestion = recipe_store.equivalence_lookup('docker.io/someone/jellyfin', equivalences, names)
    assert suggestion['kind'] == 'name' and suggestion['confidence'] == 'suggestion'
    refused = recipe_store.equivalence_lookup('grafana/grafana-enterprise', equivalences, names)
    assert refused['app'] is None and 'Enterprise' in refused['refuse']
    assert recipe_store.equivalence_lookup('example.org/x/y', equivalences, names)['kind'] == 'none'


def test_recipe_for_linux_image_and_jail_detection(tmp_path):
    recipes = recipe_store.load_recipes()
    recipe, refusal = recipe_store.recipe_for_linux_image('docker.io/grafana/grafana-oss:8.5', recipes)
    assert recipe['app'] == 'grafana' and refusal is None
    recipe, refusal = recipe_store.recipe_for_linux_image('grafana/grafana-enterprise:9', recipes)
    assert recipe['app'] == 'grafana' and 'Enterprise' in refusal
    assert recipe_store.recipe_for_linux_image('docker.io/library/nginx', recipes) == (None, None)
    # the internal development record: only the official Jellyfin image shares the Daemonless layout; the
    # LinuxServer image keeps its database under /config/data and must not match the recipe.
    for reference in ('jellyfin/jellyfin:10.10.7', 'docker.io/jellyfin/jellyfin'):
        recipe, refusal = recipe_store.recipe_for_linux_image(reference, recipes)
        assert recipe['app'] == 'jellyfin' and refusal is None
    for reference in ('lscr.io/linuxserver/jellyfin:latest', 'ghcr.io/linuxserver/jellyfin',
                      'docker.io/linuxserver/jellyfin', 'linuxserver/jellyfin'):
        assert recipe_store.recipe_for_linux_image(reference, recipes) == (None, None)
    # the internal development record: neither LinuxServer nor hotio qBittorrent shares the --profile=/config layout.
    for reference in ('lscr.io/linuxserver/qbittorrent', 'ghcr.io/linuxserver/qbittorrent:5.1.2',
                      'docker.io/linuxserver/qbittorrent', 'ghcr.io/hotio/qbittorrent:release'):
        assert recipe_store.recipe_for_linux_image(reference, recipes) == (None, None)
    # the internal development record: only the official image, whose profile layout matches Daemonless, is listed.
    assert recipes['qbittorrent']['sources']['linux']['images'] == [
        'docker.io/qbittorrentofficial/qbittorrent-nox', 'qbittorrentofficial/qbittorrent-nox']
    assert 'jail' in recipes['qbittorrent']['sources']
    assert recipe_store.match_jail(str(tmp_path), recipes) is None
    make_jail_root(tmp_path)
    assert recipe_store.match_jail(str(tmp_path), recipes)['app'] == 'grafana'


# -- compose reader -------------------------------------------------------------

def test_compose_reader_normalizes_a_single_service():
    result = compose_reader.read_export_compose(COMPOSE)
    assert result['image'] == 'grafana/grafana-oss:8.5.27'
    assert result['refusals'] == []
    assert {item['name'] for item in result['environment']} == {
        'GF_SECURITY_ADMIN_USER', 'GF_SERVER_ROOT_URL', 'GF_PATHS_DATA',
    }
    assert result['ports'] == [{'host_port': 3000, 'container_port': 3000, 'protocol': 'tcp'}]
    assert result['volumes'] == [
        {'kind': 'bind', 'source': './grafana-data', 'target': '/var/lib/grafana', 'read_only': False},
        {'kind': 'volume', 'source': 'grafana-etc', 'target': '/etc/grafana', 'read_only': False},
    ]
    assert result['healthcheck'] == {'container_port': 3000, 'path': '/api/health'}
    assert result['restart'] == 'always'
    assert any(item.startswith('container_name') for item in result['drops'])
    assert any(item.startswith('healthcheck') for item in result['drops'])


@pytest.mark.parametrize('addition, expected', [
    ('    privileged: true\n', 'privileged'),
    ('    cap_add: [NET_ADMIN]\n', 'cap_add'),
    ('    network_mode: host\n', 'host networking'),
    ('    pid: host\n', 'PID namespace'),
    ('    devices: ["/dev/dri:/dev/dri"]\n', 'device'),
    ('    env_file: .env\n', 'env_file'),
    ('    depends_on: [db]\n', 'multi-service'),
])
def test_compose_reader_refuses_by_key(addition, expected):
    text = COMPOSE.replace('    container_name: grafana\n', '    container_name: grafana\n' + addition)
    result = compose_reader.read_export_compose(text)
    assert any(expected in item for item in result['refusals']), result['refusals']


def test_compose_reader_refuses_several_services_and_interpolation():
    multi = COMPOSE.replace('volumes:\n  grafana-etc: {}\n', '  db:\n    image: postgres:16\nvolumes:\n  grafana-etc: {}\n')
    result = compose_reader.read_export_compose(multi)
    assert any('several services' in item for item in result['refusals'])
    with pytest.raises(CatalogContractError, match='interpolation'):
        compose_reader.read_export_compose(COMPOSE.replace('=admin', '=${ADMIN}'))
    with pytest.raises(CatalogContractError, match='not declared'):
        compose_reader.read_export_compose(COMPOSE.replace('volumes:\n  grafana-etc: {}\n', ''))


@pytest.mark.parametrize('declaration, expected, note', [
    ('8080:80', {'host_port': 8080, 'container_port': 80, 'protocol': 'tcp'}, False),
    ('3000:3000', {'host_port': 3000, 'container_port': 3000, 'protocol': 'tcp'}, False),
    ('22000:22000/udp', {'host_port': 22000, 'container_port': 22000, 'protocol': 'udp'}, False),
    ('8443', {'host_port': 8443, 'container_port': 8443, 'protocol': 'tcp'}, False),
    ('127.0.0.1:3000:3000', {'host_port': 3000, 'container_port': 3000, 'protocol': 'tcp'}, True),
    ('[::1]:8080:80', {'host_port': 8080, 'container_port': 80, 'protocol': 'tcp'}, True),
    ('8000-8001:8000-8001', {'host_port': 8000, 'container_port': 8000, 'protocol': 'tcp'}, False),
])
def test_compose_port_declarations_read_from_the_right(declaration, expected, note):
    text = COMPOSE.replace('      - "3000:3000"\n', f'      - "{declaration}"\n')
    result = compose_reader.read_export_compose(text)
    assert result['ports'] == [expected]
    assert any('host address binding' in item for item in result['drops']) is note


def test_compose_reader_drops_host_address_bindings_with_a_note():
    text = COMPOSE.replace('      - "3000:3000"\n', '      - "127.0.0.1:3000:3000"\n')
    result = compose_reader.read_export_compose(text)
    assert result['ports'][0]['host_port'] == 3000
    assert any('127.0.0.1' in item for item in result['drops'])


# -- bundle -------------------------------------------------------------------

def test_bundle_discovery_fingerprint_and_named_volumes(tmp_path, monkeypatch):
    root = tmp_path / 'mnt' / 'tank' / 'export'
    make_bundle(root)
    monkeypatch.setattr(bundle, 'os', bundle.os)
    with pytest.raises(CatalogContractError, match='below /mnt'):
        bundle.discover(str(root).replace('/mnt/', '/tmp/', 1) if str(root).startswith('/mnt/') else '/tmp/nope')
    real = os.path
    original_normpath = real.normpath
    monkeypatch.setattr(bundle.os.path, 'normpath', original_normpath)
    found = bundle.discover(str(root)) if str(root).startswith('/mnt/') else None
    if found is None:
        # The harness cannot create /mnt on a workstation; exercise the reader on the real path
        # through the fingerprint and archive helpers instead.
        found = {'root': str(root), 'compose_text': root.joinpath('compose.yaml').read_text()}
    first = bundle.fingerprint(found['root'], found['compose_text'])
    assert first == bundle.fingerprint(found['root'], found['compose_text'])
    root.joinpath('grafana-data', 'extra.txt').write_text('changed')
    assert bundle.fingerprint(found['root'], found['compose_text']) != first
    assert bundle.resolve_bind(str(root), './grafana-data') == str(root / 'grafana-data')
    assert bundle.resolve_bind(str(root), '/srv/grafana/grafana-data') == str(root / 'grafana-data')
    with pytest.raises(CatalogContractError, match='escapes'):
        bundle.resolve_bind(str(root), '../outside')
    assert bundle.volume_tar(str(root), 'grafana-etc') == str(root / 'grafana-etc.tar')
    destination = tmp_path / 'extracted'
    bundle.extract_volume(str(root / 'grafana-etc.tar'), str(destination))
    assert (destination / 'grafana.ini').read_text() == GRAFANA_INI


def test_volume_archives_that_escape_are_refused(tmp_path):
    archive = tmp_path / 'evil.tar'
    payload = tmp_path / 'payload'
    payload.write_text('x')
    with tarfile.open(archive, 'w') as tar:
        tar.add(payload, arcname='../escape')
    with pytest.raises(CatalogContractError, match='escapes'):
        bundle.extract_volume(str(archive), str(tmp_path / 'out'))


# -- ini carry ----------------------------------------------------------------

def test_ini_translation_denies_paths_alerting_and_carries_secret_key():
    recipe = recipe_store.load_recipes()['grafana']
    sections = ini_carry.parse_ini(GRAFANA_INI)
    assert sections['security']['secret_key'] == 'correct-horse-battery-staple'
    env = ini_carry.env_overrides({
        'GF_SERVER_ROOT_URL': 'https://new.example.org/',
        'GF_UNIFIED_ALERTING_ENABLED': 'true',
        'GF_AUTH_GENERIC_OAUTH_ENABLED': 'true',
        'UNRELATED': 'x',
    }, known_sections=tuple(sections))
    assert env['server']['root_url'] == 'https://new.example.org/'
    assert env['unified_alerting']['enabled'] == 'true'
    assert env['auth.generic_oauth']['enabled'] == 'true'
    merged = ini_carry.merged(sections, env)
    assert merged['server']['root_url'] == 'https://new.example.org/'
    carried, denied, dropped = ini_carry.translate(merged, recipe['config']['allow'], recipe['config']['deny'])
    assert carried['security'] == {'secret_key': 'correct-horse-battery-staple'}
    assert carried['server'] == {'root_url': 'https://new.example.org/', 'domain': 'grafana.example.org'}
    assert carried['smtp'] == {'enabled': 'true', 'host': 'mail.example.org:587'}
    assert 'paths.data' in denied and 'alerting.enabled' in denied and 'unified_alerting.enabled' in denied
    assert 'security.admin_password' in denied and 'log.mode' in denied
    assert 'DEFAULT.app_mode' in dropped
    rendered = ini_carry.render(carried, header='test')
    assert '[security]\nsecret_key = correct-horse-battery-staple' in rendered
    assert 'paths' not in rendered


# -- probes and plan helpers --------------------------------------------------

def test_probes_read_state_without_writing(tmp_path):
    root = make_jail_root(tmp_path, legacy_alerts=2, angular=True, plugins=[('piechart', False), ('clickhouse', True)])
    db = str(root / 'var/db/grafana/grafana.db')
    assert probes.pkg_version(str(root), 'grafana') == '8.5.27'
    assert probes.pkg_version(str(root), 'nginx') is None
    assert probes.legacy_alerts_present(db) == 2
    assert probes.angular_panels(db) == [('Overview', 'graph')]
    assert probes.grafana_version_from_db(db) == 'add unified alerting'
    assert probes.classify_plugins(str(root / 'var/db/grafana/plugins')) == (['piechart'], ['clickhouse'])
    assert probes.legacy_alerts_present(str(tmp_path / 'missing.db')) == 0
    assert probes.database_type({'database': {'type': 'postgres'}}) == 'postgres'
    assert probes.database_type({}) == 'sqlite3'


@pytest.mark.parametrize('target, source, expected', [
    ('13.1.1_2', '8.5.27', True),
    ('10.4.19', '10.4.19', True),
    ('10.4.19', '13.2.0', False),
    ('v11.0.0', '10.4', True),
    (None, '8.5', True),
    ('13.1.1', 'latest', True),
    ('4.0.15', '4.0.15.2941', True),
    ('4.0.14', '4.0.15.2941', False),
    ('4.0.15', '4.1', False),
])
def test_version_comparison_never_downgrades(target, source, expected):
    assert plan_doc.not_older(target, source) is expected


def test_plan_ids_are_content_addressed():
    plan = {'schema': 1, 'entries': [plan_doc.entry('carry', 'x', **{'from': 'a', 'to': 'b'})]}
    first = plan_doc.plan_id(plan)
    plan['plan_id'] = first
    assert plan_doc.plan_id(plan) == first
    plan['entries'].append(plan_doc.entry('drop', 'y', what='y'))
    assert plan_doc.plan_id(plan) != first
    with pytest.raises(ValueError):
        plan_doc.entry('bogus', 'x')


# -- service: planning against real fixtures -----------------------------------

def patch_jail_seams(monkeypatch, origin=None, guid='1234567890123', listening=None):
    """The describer reads ZFS properties and sockstat through subprocesses; answer them here."""
    async def zfs_property(dataset, name):
        if name == 'origin':
            return origin if dataset and not dataset.endswith('/15.1-RELEASE/root') else None
        if name == 'guid':
            return guid
        if name == 'mountpoint':
            return '/mnt/' + dataset.split('@', 1)[0]
        if name in ('used', 'referenced'):
            return '123456789'
        return None

    async def listening_ports(jid):
        return list(listening or [])

    monkeypatch.setattr(jail_sources, 'zfs_property', zfs_property)
    monkeypatch.setattr(jail_sources, 'listening_ports', listening_ports)


def service_with_middleware(tmp_path, config=None):
    middleware = Mock()
    middleware.call = AsyncMock()

    async def run_in_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    middleware.run_in_thread = AsyncMock(side_effect=run_in_thread)
    service = ApplicationsConvertService(middleware)
    config = config or {
        'pool': 'tank', 'convert_enabled': True, 'linux_compat_enabled': True, 'runtime_ready': True,
    }
    service._applications_config = AsyncMock(return_value=config)
    service._plans_dir = Mock(return_value=str(tmp_path / 'plans'))
    return service, middleware


def grafana_detail(version='13.1.1_2'):
    return {
        'id': 'daemonless:grafana', 'available': True,
        'catalog': {'version': version, 'compose_sha256': 'c' * 64},
        'install': {
            'image': 'ghcr.io/daemonless/grafana:pkg',
            'ports': [{'host_port': 3000, 'container_port': 3000, 'protocol': 'tcp'}],
            'environment': [{'name': 'PUID', 'value': '1000'}, {'name': 'PGID', 'value': '1000'}, {'name': 'TZ', 'value': 'UTC'}],
            'volumes': [{'name': 'config', 'target': '/config', 'dataset': None, 'read_only': False}],
        },
        'provenance': {'upstream_url': 'https://github.com/grafana/grafana'},
    }


@pytest.mark.asyncio
async def test_jail_plan_carries_state_denies_config_and_snapshots_the_source(tmp_path, monkeypatch):
    root = make_jail_root(tmp_path / 'root', plugins=[('piechart', False), ('clickhouse', True)])
    service, middleware = service_with_middleware(tmp_path)
    jail = {'name': 'grafana', 'state': 'down', 'release': '13.1-RELEASE-p9'}
    snapshots = []

    async def call(method, *args):
        if method == 'jail.iocage_set_up':
            return True
        if method == 'jail.query':
            return [jail]
        if method == 'jail.get_iocroot':
            return str(tmp_path)
        if method == 'zfs.dataset.query':
            return [{'id': 'tank/iocage/jails/grafana/root'}]
        if method == 'zfs.snapshot.create':
            snapshots.append(args[0])
            return True
        if method == 'applications.catalog.details':
            return grafana_detail()
        if method == 'applications.catalog.query':
            return [{'name': 'grafana'}]
        if method == 'applications.host_port_free':
            return True
        if method == 'pool.dataset.query':
            return []
        raise AssertionError(f'unexpected call {method}')

    middleware.call.side_effect = call
    monkeypatch.setattr(
        'middlewared.plugins.applications_convert_freebsd.inspect_remote_image', AsyncMock(return_value=None),
    )
    # The jail root lives at <iocroot>/jails/<name>/root.
    (tmp_path / 'jails' / 'grafana').mkdir(parents=True)
    os.rename(root, tmp_path / 'jails' / 'grafana' / 'root')

    patch_jail_seams(monkeypatch, origin=None)
    plan = await service.plan(
        {'kind': 'jail', 'jail': 'grafana', 'engine': 'iocage', 'path': None, 'image': None}, {'mode': 'native'},
    )

    # the internal development record: the lift is the default for a jail; the recipe's migration is offered.
    assert plan['mode'] == 'native' and plan['recommended'] == 'lift'
    assert plan['app'] == {'name': 'grafana', 'title': 'Grafana', 'version': '8.5.27', 'recipe': 'grafana@1', 'recipe_status': 'proven'}
    assert plan['modes']['native']['available'] is True
    assert plan['modes']['compat']['available'] is False
    assert plan['modes']['lift']['available'] is True
    types = [item['type'] for item in plan['entries']]
    assert 'refuse' not in types
    carries = {item['to'] for item in plan['entries'] if item['type'] == 'carry' and 'to' in item}
    assert 'data/grafana.db' in carries and 'plugins/piechart' in carries and 'data/png' in carries
    assert any(item.get('what') == 'plugin:clickhouse' for item in plan['entries'] if item['type'] == 'drop')
    config_entry = next(item for item in plan['entries'] if item.get('what') == 'config')
    assert 'security.secret_key' in config_entry['carried']
    assert 'paths.data' in config_entry['denied'] and 'alerting.enabled' in config_entry['denied']
    assert plan['source']['snapshot'].startswith('freecore-convert-')
    assert snapshots == [{'dataset': 'tank/iocage/jails/grafana/root', 'name': plan['source']['snapshot'], 'recursive': False}]
    assert plan['plan_id'] == plan_doc.plan_id(plan)
    assert plan['hop'] is None
    stored = json.loads((tmp_path / 'plans' / f'{plan["plan_id"]}.json').read_text())
    assert stored == plan


@pytest.mark.asyncio
async def test_jail_plan_refuses_a_running_jail_a_downgrade_and_unmigratable_alerts(tmp_path, monkeypatch):
    service, middleware = service_with_middleware(tmp_path, config={
        'pool': 'tank', 'convert_enabled': True, 'linux_compat_enabled': False, 'runtime_ready': True,
    })
    root = make_jail_root(tmp_path / 'jails' / 'grafana' / 'root', version='13.2.0', legacy_alerts=3)
    jail = {'name': 'grafana', 'state': 'up', 'release': '13.1-RELEASE-p9'}

    async def call(method, *args):
        return {
            'jail.iocage_set_up': True, 'jail.query': [jail], 'jail.get_iocroot': str(tmp_path),
            'zfs.dataset.query': [{'id': 'tank/iocage/jails/grafana/root'}],
            'applications.catalog.details': grafana_detail('13.1.1_2'),
            'applications.catalog.query': [{'name': 'grafana'}],
            'applications.host_port_free': True,
            'pool.dataset.query': [],
        }[method]

    middleware.call.side_effect = call
    monkeypatch.setattr(
        'middlewared.plugins.applications_convert_freebsd.inspect_remote_image', AsyncMock(return_value=None),
    )
    patch_jail_seams(monkeypatch)
    with pytest.raises(CallError) as excinfo:
        await service.plan({'kind': 'jail', 'jail': 'grafana', 'path': None, 'image': None}, {'mode': 'native'})
    message = str(excinfo.value)
    assert 'must be stopped' in message
    assert 'downgrade is never performed' in message
    assert 'legacy dashboard alerts' in message and 'Linux binary compatibility' in message
    assert not (tmp_path / 'plans').exists() or not list((tmp_path / 'plans').glob('*.json'))
    assert not any(c.args and c.args[0] == 'zfs.snapshot.create' for c in middleware.call.call_args_list)


@pytest.mark.asyncio
async def test_export_plan_offers_native_with_a_hop_and_compat(tmp_path, monkeypatch):
    root = make_bundle(tmp_path / 'export', legacy_alerts=1)
    service, middleware = service_with_middleware(tmp_path)

    async def call(method, *args):
        if method == 'applications.catalog.details':
            return grafana_detail()
        if method == 'applications.catalog.query':
            return [{'name': 'grafana'}]
        if method == 'applications.config':
            return {'linux_compat_enabled': True}
        raise AssertionError(method)

    middleware.call.side_effect = call
    monkeypatch.setattr(bundle, 'discover', lambda path: {
        'root': str(root), 'compose_path': str(root / 'compose.yaml'),
        'compose_text': root.joinpath('compose.yaml').read_text(),
    })
    inspection = {
        'reference': 'x', 'digest': 'sha256:' + 'd' * 64, 'os': 'linux', 'architecture': 'amd64',
        'labels': {'org.opencontainers.image.source': 'https://github.com/grafana/grafana'},
        'environment': {}, 'entrypoint': ['/run.sh'], 'cmd': [], 'user': '472', 'volumes': [], 'exposed_ports': ['3000/tcp'],
    }
    monkeypatch.setattr(
        'middlewared.plugins.applications_convert_freebsd.inspect_remote_image', AsyncMock(return_value=inspection),
    )

    plan = await service.plan({'kind': 'linux-export', 'jail': None, 'path': str(root), 'image': None}, {})
    assert plan['mode'] == 'native'
    assert plan['modes']['compat']['available'] is True
    assert plan['modes']['compat']['digest'] == 'sha256:' + 'd' * 64
    hop = plan['hop']
    assert hop['image'].startswith('docker.io/grafana/grafana-oss:10.4') and hop['count'] == 1
    assert any(item['type'] == 'hop' for item in plan['entries'])
    assert plan['source']['fingerprint'] == bundle.fingerprint(str(root), root.joinpath('compose.yaml').read_text())
    assert plan['app']['version'] == '8.5.27'
    config_entry = next(item for item in plan['entries'] if item.get('what') == 'config')
    assert 'server.root_url' in config_entry['carried']
    assert 'paths.data' in config_entry['denied']
    assert plan['environment']['GF_SERVER_ROOT_URL'] == 'https://grafana.example.org/'
    # The staged ini carries the environment-expressed settings of a Linux export.
    recipe = recipe_store.load_recipes()['grafana']
    staged = tmp_path / 'staged'
    staged.mkdir()
    service._stage_native(plan, recipe, str(root), str(staged))
    ini = (staged / 'grafana.ini').read_text()
    assert 'root_url = https://grafana.example.org/' in ini
    assert '[paths]' not in ini and 'admin_password' not in ini
    assert (staged / 'data' / 'grafana.db').is_file()

    compat = await service.plan(
        {'kind': 'linux-export', 'jail': None, 'path': str(root), 'image': None}, {'mode': 'compat'},
    )
    assert compat['mode'] == 'compat'
    volumes = [item for item in compat['entries'] if item['type'] == 'carry' and 'volume' in item]
    assert {item['volume'] for item in volumes} == {'var-lib-grafana', 'etc-grafana'}
    assert any(item.get('archive') for item in volumes)


@pytest.mark.asyncio
async def test_linuxserver_jellyfin_export_gets_no_native_carry_but_keeps_compat(tmp_path, monkeypatch):
    # the internal development record: the LinuxServer image keeps its database in /config/data and its settings in
    # /config; carrying that tree into the Daemonless /config would start an empty server that passes health.
    root = tmp_path / 'export'
    root.mkdir()
    root.joinpath('compose.yaml').write_text(
        'services:\n'
        '  jellyfin:\n'
        '    image: lscr.io/linuxserver/jellyfin:10.10.7\n'
        '    environment:\n'
        '      - PUID=1000\n'
        '      - PGID=1000\n'
        '    volumes:\n'
        '      - ./config:/config\n'
        '    ports:\n'
        '      - "8096:8096"\n'
    )
    root.joinpath('config', 'data', 'data').mkdir(parents=True)
    root.joinpath('config', 'data', 'data', 'library.db').write_bytes(b'')
    root.joinpath('config', 'system.xml').write_text('<ServerConfiguration/>')
    service, middleware = service_with_middleware(tmp_path)

    async def call(method, *args):
        if method == 'applications.catalog.query':
            return [{'name': 'jellyfin'}]
        if method == 'applications.config':
            return {'linux_compat_enabled': True}
        raise AssertionError(method)

    middleware.call.side_effect = call
    monkeypatch.setattr(bundle, 'discover', lambda path: {
        'root': str(root), 'compose_path': str(root / 'compose.yaml'),
        'compose_text': root.joinpath('compose.yaml').read_text(),
    })
    inspection = {
        'reference': 'x', 'digest': 'sha256:' + 'e' * 64, 'os': 'linux', 'architecture': 'amd64', 'labels': {},
        'environment': {}, 'entrypoint': ['/init'], 'cmd': [], 'user': '', 'volumes': ['/config'],
        'exposed_ports': ['8096/tcp'],
    }
    monkeypatch.setattr(
        'middlewared.plugins.applications_convert_freebsd.inspect_remote_image', AsyncMock(return_value=inspection),
    )

    plan = await service.plan({'kind': 'linux-export', 'jail': None, 'path': str(root), 'image': None}, {})
    assert plan['modes']['native']['available'] is False
    assert plan['modes']['native']['reasons'] == ['no recipe recognises this source']
    assert plan['modes']['compat']['available'] is True
    assert plan['mode'] == 'compat'
    assert not any(item['type'] == 'carry' and item.get('to') == '' for item in plan['entries'])


@pytest.mark.asyncio
async def test_plan_requires_the_flag_and_apply_requires_confirmation(tmp_path):
    service, middleware = service_with_middleware(tmp_path, config={
        'pool': 'tank', 'convert_enabled': False, 'linux_compat_enabled': False, 'runtime_ready': True,
    })
    with pytest.raises(CallError, match='experimental and off'):
        await service.plan({'kind': 'jail', 'jail': 'x', 'path': None, 'image': None}, {})
    service._applications_config = AsyncMock(return_value={
        'pool': 'tank', 'convert_enabled': True, 'linux_compat_enabled': False, 'runtime_ready': True,
    })
    with pytest.raises(CallError, match='Confirm the plan'):
        await ApplicationsConvertService.apply.wraps(service, Mock(), 'a' * 64, {'confirm': False})
    with pytest.raises(CallError, match='does not exist'):
        await ApplicationsConvertService.apply.wraps(service, Mock(), 'a' * 64, {'confirm': True})


@pytest.mark.asyncio
async def test_discard_destroys_the_snapshot_and_forgets_the_plan(tmp_path):
    service, middleware = service_with_middleware(tmp_path)
    plan = {'schema': 1, 'source': {'kind': 'jail', 'dataset': 'tank/iocage/jails/g/root', 'snapshot': 'freecore-convert-abc'}}
    plan['plan_id'] = plan_doc.plan_id(plan)
    (tmp_path / 'plans').mkdir()
    (tmp_path / 'plans' / f'{plan["plan_id"]}.json').write_text(json.dumps(plan))
    middleware.call.return_value = True

    assert await service.discard(plan['plan_id']) is True
    middleware.call.assert_awaited_once_with(
        'zfs.snapshot.delete', 'tank/iocage/jails/g/root@freecore-convert-abc', {'defer': False},
    )
    assert not (tmp_path / 'plans' / f'{plan["plan_id"]}.json').exists()


@pytest.mark.asyncio
async def test_native_apply_stages_from_the_snapshot_and_installs_through_the_catalog(tmp_path, monkeypatch):
    service, middleware = service_with_middleware(tmp_path)
    jail_root = make_jail_root(tmp_path / 'jails' / 'grafana' / 'root', plugins=[('piechart', False)])
    snapshot_root = tmp_path / 'jails' / 'grafana' / 'root' / '.zfs' / 'snapshot' / 'freecore-convert-abc'
    snapshot_root.mkdir(parents=True)
    for relative in ('usr/local/etc/grafana', 'var/db/grafana'):
        os.makedirs(snapshot_root / relative, exist_ok=True)
    import shutil
    shutil.copytree(jail_root / 'var/db/grafana', snapshot_root / 'var/db/grafana', dirs_exist_ok=True)
    shutil.copy2(jail_root / 'usr/local/etc/grafana/grafana.ini', snapshot_root / 'usr/local/etc/grafana/grafana.ini')
    mountpoint = tmp_path / 'mnt' / 'tank' / 'applications' / 'data' / 'grafana' / 'config'
    mountpoint.mkdir(parents=True)

    jail = {'name': 'grafana', 'state': 'down', 'release': '13.1-RELEASE-p9'}
    calls = []

    async def call(method, *args):
        calls.append((method, args))
        if method == 'jail.iocage_set_up':
            return True
        if method == 'jail.query':
            return [jail]
        if method == 'jail.get_iocroot':
            return str(tmp_path)
        if method == 'zfs.dataset.query':
            return [{'id': 'tank/iocage/jails/grafana/root'}]
        if method == 'zfs.snapshot.create':
            return True
        if method == 'zfs.snapshot.query':
            return [{'id': args[0][0][2]}]
        if method == 'zfs.snapshot.delete':
            return True
        if method == 'applications.catalog.details':
            return grafana_detail()
        if method == 'applications.query':
            return []
        if method == 'applications.prepare_owned_volume':
            return {
                'dataset': 'tank/applications/data/grafana/config', 'mountpoint': str(mountpoint),
                'created': ['tank/applications/data/grafana', 'tank/applications/data/grafana/config'],
            }
        if method == 'filesystem.chown':
            job = Mock()
            job.wait = AsyncMock()
            job.error = None
            return job
        if method == 'applications.catalog.bind_install':
            return ({'name': 'grafana', 'image': 'ghcr.io/daemonless/grafana:pkg'}, {'id': 'daemonless:grafana'})
        if method == 'applications.install_catalog':
            return 'subjob'
        if method == 'applications.catalog.query':
            return [{'name': 'grafana'}]
        if method == 'applications.host_port_free':
            return True
        if method == 'pool.dataset.query':
            return []
        raise AssertionError(f'unexpected call {method}')

    middleware.call.side_effect = call
    monkeypatch.setattr(
        'middlewared.plugins.applications_convert_freebsd.inspect_remote_image', AsyncMock(return_value=None),
    )
    monkeypatch.setattr('middlewared.plugins.applications_convert_freebsd.uuid.uuid4', lambda: Mock(hex='abc' * 11))
    patch_jail_seams(monkeypatch)

    plan = await service.plan(
        {'kind': 'jail', 'jail': 'grafana', 'path': None, 'image': None}, {'host_port': 3100, 'mode': 'native'},
    )
    plan_file = tmp_path / 'plans' / f'{plan["plan_id"]}.json'
    # The snapshot name is derived from the mocked uuid; point the fixture at it.
    os.rename(snapshot_root, snapshot_root.parent / plan['source']['snapshot'])

    job = Mock()
    job.wrap = AsyncMock(return_value={'name': 'grafana'})
    result = await ApplicationsConvertService.apply.wraps(service, job, plan['plan_id'], {'confirm': True})

    assert result == {'name': 'grafana'}
    assert (mountpoint / 'data' / 'grafana.db').is_file()
    assert (mountpoint / 'data' / 'png' / 'render.png').is_file()
    assert (mountpoint / 'plugins' / 'piechart' / 'plugin.json').is_file()
    ini = (mountpoint / 'grafana.ini').read_text()
    assert 'secret_key = correct-horse-battery-staple' in ini
    assert '[paths]' not in ini and '[alerting]' not in ini and '[unified_alerting]' not in ini
    assert 'admin_password' not in ini and '[log]' not in ini
    bind = next(args for method, args in calls if method == 'applications.catalog.bind_install')[0]
    assert bind['ports'] == [{'host_port': 3100, 'container_port': 3000, 'protocol': 'tcp'}]
    assert bind['volumes'] == [{'name': 'config', 'dataset': None}]
    install = next(args for method, args in calls if method == 'applications.install_catalog')
    assert install[2]['kind'] == 'convert' and install[2]['plan_id'] == plan['plan_id']
    assert install[2]['mode'] == 'native' and install[2]['source_kind'] == 'jail'
    assert ('zfs.snapshot.delete', (f'tank/iocage/jails/grafana/root@{plan["source"]["snapshot"]}', {'defer': False})) in calls
    assert not plan_file.exists()
    chowns = [args[0] for method, args in calls if method == 'filesystem.chown']
    assert chowns and chowns[-1]['uid'] == 1000 and chowns[-1]['options']['recursive'] is True


# -- compose import (the internal development record): the "point at your own GitHub" path ---

@pytest.mark.asyncio
async def test_read_compose_fills_an_import_form_from_text_or_an_allowlisted_url(tmp_path, monkeypatch):
    service, middleware = service_with_middleware(tmp_path)

    async def call(method, *args):
        if method == 'applications.catalog.query':
            return [{'name': 'grafana'}]
        if method == 'applications.config':
            return {'linux_compat_enabled': True}
        raise AssertionError(method)

    middleware.call.side_effect = call
    inspection = {
        'reference': 'x', 'digest': 'sha256:' + 'd' * 64, 'os': 'linux', 'architecture': 'amd64',
        'labels': {}, 'environment': {}, 'entrypoint': [], 'cmd': [], 'user': None, 'volumes': [], 'exposed_ports': [],
    }
    monkeypatch.setattr(
        'middlewared.plugins.applications_convert_freebsd.inspect_remote_image', AsyncMock(return_value=inspection),
    )

    result = await service.read_compose({'url': None, 'text': COMPOSE})
    install = result['install']
    assert install['name'] == 'grafana' and install['image'] == 'grafana/grafana-oss:8.5.27'
    assert install['image_os'] == 'linux'
    assert install['ports'] == [{'host_port': 3000, 'container_port': 3000, 'protocol': 'tcp'}]
    assert {item['name'] for item in install['environment']} == {'GF_SECURITY_ADMIN_USER', 'GF_SERVER_ROOT_URL', 'GF_PATHS_DATA'}
    assert install['volumes'] == [
        {'name': 'var-lib-grafana', 'target': '/var/lib/grafana', 'dataset': None, 'read_only': False},
        {'name': 'etc-grafana', 'target': '/etc/grafana', 'dataset': None, 'read_only': False},
    ]
    assert install['healthcheck'] == {'type': 'HTTP', 'scheme': 'http', 'container_port': 3000, 'host_port': 3000, 'path': '/api/health'}
    assert install['restart_policy'] == 'always' and 'acknowledge_unreviewed' not in install
    assert result['catalog_app'] == 'grafana'
    assert any(item.startswith('container_name') for item in result['ignored'])

    with pytest.raises(CallError, match='either a compose file URL or its text'):
        await service.read_compose({'url': None, 'text': None})
    with pytest.raises(CallError, match='raw.githubusercontent.com'):
        await service.read_compose({'url': 'https://example.org/compose.yaml', 'text': None})

    fetched = []

    async def get(self, url, maximum, accept='application/json'):
        fetched.append((url, maximum, accept))
        return COMPOSE.encode('utf-8')

    monkeypatch.setattr('middlewared.plugins.applications_convert_freebsd.ProviderClient.get', get)
    result = await service.read_compose({'url': 'https://raw.githubusercontent.com/me/apps/main/compose.yaml', 'text': None})
    assert result['install']['image'] == 'grafana/grafana-oss:8.5.27'
    assert fetched == [('https://raw.githubusercontent.com/me/apps/main/compose.yaml', 256 * 1024, 'text/plain')]

    with pytest.raises(CallError, match='declares no services'):
        await service.read_compose({'url': None, 'text': 'version: "3"\n'})


# -- generic (pattern S) recipes: one data directory into /config (the internal development record) --

def test_every_shipped_recipe_validates_and_the_drafts_say_so():
    recipes = recipe_store.load_recipes()
    assert len(recipes) >= 30
    for app in ('plex', 'tautulli', 'homepage', 'adguardhome', 'audiobookshelf',
                'n8n', 'mealie', 'nocodb', 'heimdall', 'code-server',
                'redis', 'haproxy', 'caddy'):
        assert app in recipes
    for app, recipe in recipes.items():
        assert recipe['target']['catalog_id'] == f'daemonless:{app}'
        assert recipe_store.recipe_kind(recipe) in ('generic', 'grafana')
        if recipe_store.recipe_kind(recipe) == 'generic':
            # sonarr proven on the box 2026-09-13; syncthing, vaultwarden
            # and plex 2026-09-29.
            proven = ('sonarr', 'syncthing', 'vaultwarden', 'plex')
            assert recipe['status'] == ('proven' if app in proven else 'draft'), app
            # The first carry is the required state and always a template
            # (named paths since the internal development record, {data} before it).
            assert recipe['carry'][0]['from'].startswith('{')
            assert recipe['carry'][0]['required'] is True
            assert not recipe['config']['allow'] and not recipe['config']['deny']
            # the internal development record: no listed Linux image shares qBittorrent's --profile=/config layout.
            assert 'linux' in recipe['sources'], app
            if 'jail' in recipe['sources']:
                jail = recipe['sources']['jail']
                assert jail['rc_script'] and jail['pkg'] and jail['detect']
                # rc_data_var is optional: tautulli's rc script hardcodes the
                # datadir, and plexmediaserver_support_path names the PARENT of
                # the data directory, so an override would carry the wrong tree.
                if 'rc_data_var' in jail:
                    assert jail['rc_data_var']
                assert not jail['data'].startswith('/')
    assert recipes['grafana']['status'] == 'proven' and recipe_store.recipe_kind(recipes['grafana']) == 'grafana'
    # Distinct jail detection: no two recipes claim the same rc.d script.
    scripts = [r['sources']['jail']['detect'][0] for r in recipes.values() if 'jail' in r['sources']]
    assert len(scripts) == len(set(scripts))
    with pytest.raises(CatalogContractError, match='kind is unknown'):
        recipe_store.validate_recipe({**recipes['sonarr'], 'kind': 'magic'})
    with pytest.raises(CatalogContractError, match='names none'):
        recipe_store.validate_recipe({**recipes['sonarr'], 'kind': 'grafana'})
    with pytest.raises(CatalogContractError, match='status is unknown'):
        recipe_store.validate_recipe({**recipes['sonarr'], 'status': 'verified'})


def test_rc_settings_and_script_defaults_are_read_in_their_common_shapes(tmp_path):
    root = tmp_path
    (root / 'usr/local/etc/rc.d').mkdir(parents=True)
    (root / 'usr/local/etc/rc.d/sonarr').write_text(
        '#!/bin/sh\n. /etc/rc.subr\nname=sonarr\nload_rc_config $name\n'
        ': ${sonarr_enable:="NO"}\n: ${sonarr_data_dir:="/usr/local/sonarr"}\n: ${sonarr_pid_dir="/var/run/sonarr"}\n'
    )
    (root / 'usr/local/etc/rc.d/qbittorrent').write_text(
        'qbittorrent_conf_dir=${qbittorrent_conf_dir:-"/var/db/qbittorrent/conf"}\n'
    )
    assert probes.rc_script_default(str(root), 'sonarr', 'sonarr_data_dir') == '/usr/local/sonarr'
    assert probes.rc_script_default(str(root), 'sonarr', 'sonarr_pid_dir') == '/var/run/sonarr'
    assert probes.rc_script_default(str(root), 'qbittorrent', 'qbittorrent_conf_dir') == '/var/db/qbittorrent/conf'
    assert probes.rc_script_default(str(root), 'sonarr', 'nope') is None
    assert probes.rc_script_default(str(root), 'missing', 'x') is None
    rc = 'sonarr_enable="YES"\nsonarr_data_dir="/mnt/apps/sonarr"  # moved\nsonarr_data_dir=/mnt/apps/sonarr2\n'
    assert probes.rc_setting(rc, 'sonarr_data_dir') == '/mnt/apps/sonarr2'
    assert probes.rc_setting(rc, 'sonarr_enable') == 'YES'
    assert probes.rc_setting(rc, 'other') is None


def make_sonarr_jail(root, data='usr/local/sonarr', rc_conf=''):
    os.makedirs(os.path.join(root, 'usr/local/etc/rc.d'), exist_ok=True)
    with open(os.path.join(root, 'usr/local/etc/rc.d/sonarr'), 'w') as file:
        file.write(': ${sonarr_data_dir:="/usr/local/sonarr"}\n')
    os.makedirs(os.path.join(root, 'etc'), exist_ok=True)
    with open(os.path.join(root, 'etc/rc.conf'), 'w') as file:
        file.write('sonarr_enable="YES"\n' + rc_conf)
    os.makedirs(os.path.join(root, data, 'Backups'), exist_ok=True)
    with open(os.path.join(root, data, 'sonarr.db'), 'wb') as file:
        file.write(b'db')
    with open(os.path.join(root, data, 'config.xml'), 'w') as file:
        file.write('<Config><Port>8989</Port></Config>')
    pkgdb = os.path.join(root, 'var/db/pkg')
    os.makedirs(pkgdb, exist_ok=True)
    connection = sqlite3.connect(os.path.join(pkgdb, 'local.sqlite'))
    connection.execute('CREATE TABLE packages (id INTEGER PRIMARY KEY, name TEXT, version TEXT)')
    connection.execute("INSERT INTO packages (name, version) VALUES ('sonarr', '4.0.15.2941')")
    connection.commit()
    connection.close()
    return root


@pytest.mark.asyncio
async def test_generic_recipe_plans_from_the_jails_own_rc_conf_and_stages_the_tree(tmp_path, monkeypatch):
    root = make_sonarr_jail(str(tmp_path / 'jails' / 'tv' / 'root'), data='mnt/apps/sonarr',
                            rc_conf='sonarr_data_dir="/mnt/apps/sonarr"\n')
    service, middleware = service_with_middleware(tmp_path)
    jail = {'name': 'tv', 'id': 'tv', 'state': 'down', 'release': '15.1-RELEASE'}
    detail = {
        'id': 'daemonless:sonarr', 'available': True,
        'catalog': {'version': '4.0.15', 'compose_sha256': 'c' * 64},
        'install': {'image': 'ghcr.io/daemonless/sonarr:latest',
                    'ports': [{'host_port': 8989, 'container_port': 8989, 'protocol': 'tcp'}],
                    'environment': [], 'volumes': [{'name': 'config', 'target': '/config', 'dataset': None, 'read_only': False}]},
    }

    async def call(method, *args):
        return {
            'jail.iocage_set_up': True, 'jail.query': [jail], 'jail.get_iocroot': str(tmp_path),
            'zfs.dataset.query': [{'id': 'tank/iocage/jails/tv/root'}], 'zfs.snapshot.create': True,
            'applications.catalog.details': detail, 'applications.catalog.query': [{'name': 'sonarr'}],
            'applications.host_port_free': True, 'pool.dataset.query': [],
        }[method]

    middleware.call.side_effect = call
    monkeypatch.setattr(
        'middlewared.plugins.applications_convert_freebsd.inspect_remote_image', AsyncMock(return_value=None),
    )
    patch_jail_seams(monkeypatch, origin=None)

    detect = await service.detect({'kind': 'jail', 'jail': 'tv', 'engine': 'iocage', 'path': None, 'image': None})
    assert detect['recipe'] == 'sonarr@1' and detect['recipe_status'] == 'proven'
    assert detect['paths']['data'] == os.path.join(root, 'mnt/apps/sonarr')
    assert detect['version'] == '4.0.15.2941'

    plan = await service.plan({'kind': 'jail', 'jail': 'tv', 'engine': 'iocage', 'path': None, 'image': None}, {'mode': 'native'})
    assert plan['mode'] == 'native' and plan['app']['recipe_status'] == 'proven'
    carries = [item for item in plan['entries'] if item['type'] == 'carry']
    assert carries == [{'type': 'carry', 'human': f'{root}/mnt/apps/sonarr -> /config', 'from': f'{root}/mnt/apps/sonarr', 'to': ''}]
    whats = {item.get('what') for item in plan['entries']}
    assert 'draft' not in whats and 'config' not in whats and 'secret_key' not in whats
    # A draft recipe says so in its plan and in detection.
    service._recipes['sonarr']['status'] = 'draft'
    draft_plan = await service.plan(
        {'kind': 'jail', 'jail': 'tv', 'engine': 'iocage', 'path': None, 'image': None}, {'mode': 'native'},
    )
    assert draft_plan['app']['recipe_status'] == 'draft'
    assert any(item.get('what') == 'draft' for item in draft_plan['entries'])
    service._recipes['sonarr']['status'] = 'proven'
    assert [item['id'] for item in plan['preflights']] == ['target_not_older']
    assert plan['modes']['native']['available'] is True and plan['recommended'] == 'lift'

    recipe = recipe_store.load_recipes()['sonarr']
    staged = tmp_path / 'staged'
    staged.mkdir()
    service._stage_native(plan, recipe, root, str(staged))
    assert (staged / 'sonarr.db').is_file() and (staged / 'config.xml').is_file() and (staged / 'Backups').is_dir()
    assert not list(staged.glob('*.ini'))

    # A jail whose data directory is the package default, with a version newer than the image: refused.
    make_sonarr_jail(str(tmp_path / 'jails' / 'tv2' / 'root'))
    jail.update({'name': 'tv2', 'id': 'tv2'})
    detail['catalog']['version'] = '3.0.10'
    with pytest.raises(CallError, match='downgrade is never performed'):
        await service.plan({'kind': 'jail', 'jail': 'tv2', 'engine': 'iocage', 'path': None, 'image': None}, {'mode': 'native'})


def test_recipe_v11_named_paths_and_carry_volumes_validate():
    # the internal development record
    import copy
    base = recipe_store.load_recipes()['sonarr']
    bad = copy.deepcopy(base)
    bad['sources']['jail']['paths'] = {'data': 'somewhere'}
    with pytest.raises(CatalogContractError, match='reserved or invalid'):
        recipe_store.validate_recipe(bad)
    bad = copy.deepcopy(base)
    bad['carry'] = base['carry'] + [{'from': '{data}/x', 'to': 'x', 'volume': 'other'}]
    with pytest.raises(CatalogContractError, match='undeclared volume'):
        recipe_store.validate_recipe(bad)
    good = copy.deepcopy(base)
    good['target']['volumes'] = {'other': {'uid': 0, 'gid': 0}}
    good['carry'] = base['carry'] + [{'from': '{data}/x', 'to': 'x', 'volume': 'other'}]
    # the internal development record: a carry into a second volume cannot be reversed for export.
    with pytest.raises(CatalogContractError, match='explicit volumes'):
        recipe_store.validate_recipe(copy.deepcopy(good))
    del good['sources']['linux']['export']
    recipe_store.validate_recipe(good)
    bad = copy.deepcopy(good)
    bad['target']['volumes'] = {'other': {'uid': 'root'}}
    with pytest.raises(CatalogContractError, match='needs uid and gid'):
        recipe_store.validate_recipe(bad)


def test_stage_native_routes_carry_entries_to_their_volumes(tmp_path):
    # the internal development record: a carry naming a volume lands in that volume's
    # mountpoint; everything else lands in the primary one.
    service, _ = service_with_middleware(tmp_path)
    source_dir = tmp_path / 'source'
    (source_dir / 'conf').mkdir(parents=True)
    (source_dir / 'work').mkdir()
    (source_dir / 'conf' / 'app.yaml').write_text('setting: true\n')
    (source_dir / 'work' / 'stats.db').write_text('x')
    primary = tmp_path / 'vol-conf'
    secondary = tmp_path / 'vol-work'
    primary.mkdir(); secondary.mkdir()
    recipe = {
        'app': 'routing', 'recipe_version': 1, 'kind': 'generic',
        'target': {'catalog_id': 'daemonless:routing', 'volume': 'conf', 'layout': {'data': ''},
                   'uid': 1000, 'gid': 1000, 'volumes': {'work': {'uid': 1000, 'gid': 1000}}},
        'sources': {'linux': {'images': ['docker.io/x/routing'], 'data': '/conf', 'uid': 0,
                              'paths': {'work': '/work'}}},
        'config': {'allow': [], 'deny': []},
        'carry': [{'from': '{data}', 'to': '', 'required': True},
                  {'from': '{work}', 'to': '', 'volume': 'work', 'optional': True}],
    }
    recipe_store.validate_recipe(recipe)
    plan = {
        'source': {'kind': 'linux-export', 'root': str(source_dir), 'ref': str(source_dir)},
        'entries': [
            {'type': 'carry', 'from': str(source_dir / 'conf'), 'to': ''},
            {'type': 'carry', 'from': str(source_dir / 'work'), 'to': '', 'volume': 'work'},
        ],
    }
    service._stage_native(plan, recipe, str(source_dir), str(primary), {'work': str(secondary)})
    assert (primary / 'app.yaml').is_file()
    assert (secondary / 'stats.db').is_file()
    assert not (primary / 'stats.db').exists()


# -- export to a Linux host (the internal development record) ----------------------------

def test_shipped_export_targets_map_the_daemonless_volume():
    recipes = recipe_store.load_recipes()
    assert recipe_store.export_mapping(recipes['sonarr']) == [{'from': '', 'target': '/config', 'optional': False}]
    assert recipe_store.export_mapping(recipes['syncthing']) == [{'from': '', 'target': '/config', 'optional': False}]
    assert recipe_store.export_mapping(recipes['vaultwarden']) == [{'from': '', 'target': '/data', 'optional': False}]
    assert recipe_store.export_mapping(recipes['plex']) == [{'from': '', 'target': '/config', 'optional': False}]
    assert recipe_store.export_mapping(recipes['grafana']) == [
        {'from': 'data', 'target': '/var/lib/grafana', 'optional': False},
        {'from': 'grafana.ini', 'target': '/etc/grafana/grafana.ini', 'optional': False},
        {'from': 'provisioning', 'target': '/etc/grafana/provisioning', 'optional': True},
    ]
    # Every recipe has an export target (the operator's best-effort pass of 2026-09-30); qbittorrent's
    # is the official image, the one Linux image whose profile layout matches Daemonless (#489).
    assert recipe_store.export_mapping(recipes['qbittorrent']) == [{'from': '', 'target': '/config', 'optional': False}]
    assert {app for app in recipes if recipe_store.export_mapping(recipes[app])} == set(recipes)
    # Two whose carries do not all start at {data} map explicitly: one bind, the image's own paths.
    assert recipe_store.export_mapping(recipes['audiobookshelf']) == [{'from': '', 'target': '/config', 'optional': False}]
    assert recipe_store.export_mapping(recipes['adguardhome']) == [
        {'from': '', 'target': '/opt/adguardhome/work', 'optional': False},
        {'from': 'AdGuardHome.yaml', 'target': '/opt/adguardhome/conf/AdGuardHome.yaml', 'optional': False},
    ]
    # Every target names one of the recipe's own Linux images, and the ownership mode fits the family.
    for app, recipe in recipes.items():
        export = (recipe['sources'].get('linux') or {}).get('export')
        if not export:
            continue
        assert export['image'] in recipe['sources']['linux']['images'], app
        if export['image'].startswith('lscr.io/linuxserver/'):
            assert export['user'] == 'puid', app


@pytest.mark.parametrize('change, expected', [
    ({'image': 'lscr.io/linuxserver/sonarr:latest'}, 'without a tag'),
    ({'user': 'root'}, 'export user'),
    ({'user': 'image'}, 'image_uid'),
    ({'tag_template': 'v1'}, 'tag_template'),
    ({'environment': {'BAD NAME': 'x'}}, 'environment'),
    ({'volumes': [{'from': '../etc', 'target': '/config'}]}, 'escapes'),
    ({'volumes': [{'from': '', 'target': 'config'}]}, 'clean absolute path'),
])
def test_export_targets_are_validated(change, expected):
    recipe = json.loads(json.dumps(recipe_store.load_recipes()['sonarr']))
    recipe['sources']['linux']['export'].update(change)
    with pytest.raises(CatalogContractError, match=expected):
        recipe_store.validate_recipe(recipe)
    # Carries that do not start at {data} cannot be reversed without explicit volumes.
    grafana = json.loads(json.dumps(recipe_store.load_recipes()['grafana']))
    del grafana['sources']['linux']['export']['volumes']
    with pytest.raises(CatalogContractError, match='explicit volumes'):
        recipe_store.validate_recipe(grafana)


def test_export_helpers_choose_tags_versions_owners_and_environment():
    export = {'image': 'lscr.io/linuxserver/sonarr', 'tag_template': 'version-{version}', 'user': 'puid'}
    assert export_tool.package_version('1.34.3_1') == '1.34.3'
    assert export_tool.package_version('v2.1.5,1') == '2.1.5'
    assert export_tool.candidate_tags(export, '4.0.15.2941_2') == ['version-4.0.15.2941', 'latest']
    assert export_tool.candidate_tags({'image': 'x', 'user': 'puid'}, '1.0') == ['latest']
    labels = {'org.opencontainers.image.version': '4.0.16.2944-ls291'}
    assert export_tool.target_version('latest', None, '4.0.15', labels) == '4.0.16.2944-ls291'
    assert export_tool.target_version('version-4.0.15', 'version-{version}', '4.0.15_1', {}) == '4.0.15'
    assert export_tool.target_version('latest', 'version-{version}', '4.0.15', {}) is None
    environment = [('PUID', '1001'), ('PGID', '1002'), ('TZ', 'UTC'), ('VERSION', 'container'), ('PLEX_CLAIM', 'x')]
    assert export_tool.ownership(environment) == (1001, 1002)
    assert export_tool.ownership([]) == (1000, 1000)
    result, changes = export_tool.export_environment(
        environment, {'user': 'puid', 'environment': {'VERSION': 'docker'}, 'drop_environment': ['PLEX_CLAIM']},
    )
    assert result == [('PUID', '1001'), ('PGID', '1002'), ('TZ', 'UTC'), ('VERSION', 'docker')]
    assert changes == ['VERSION=docker (was container)', 'PLEX_CLAIM dropped']
    result, _changes = export_tool.export_environment(environment[:3], {'user': 'user'})
    assert result == [('TZ', 'UTC')]
    taken = set()
    assert export_tool.bundle_directory('/config', taken) == 'config'
    assert export_tool.bundle_directory('/config', taken) == 'config-2'
    assert export_tool.bundle_directory('/etc/grafana/grafana.ini', taken) == 'etc-grafana-grafana.ini'
    for bad in ('/tmp/x', '/mnt/tank', '/mnt/tank/applications/x', '/mnt/tank/iocage', '/mnt/tank/../etc'):
        with pytest.raises(CatalogContractError):
            export_tool.check_destination(bad)


def test_an_exported_compose_reads_back_through_the_import_reader():
    text = export_tool.compose_text(
        'sonarr', 'lscr.io/linuxserver/sonarr:latest',
        [('PUID', '1000'), ('TZ', 'Europe/Stockholm'), ('API_NOTE', 'a "quoted" value: yes')],
        [{'host_port': 8989, 'container_port': 8989, 'protocol': 'tcp'}],
        [{'source': './config', 'target': '/config', 'read_only': False},
         {'source': '/mnt/tank/media/tv', 'target': '/tv', 'read_only': True}],
        '1000:1000', ['exported'],
    )
    result = compose_reader.read_export_compose(text)
    assert result['refusals'] == [] and result['drops'] == []
    assert result['image'] == 'lscr.io/linuxserver/sonarr:latest'
    assert result['user'] == '1000:1000' and result['restart'] == 'always'
    assert {item['name']: item['value'] for item in result['environment']}['API_NOTE'] == 'a "quoted" value: yes'
    assert result['ports'] == [{'host_port': 8989, 'container_port': 8989, 'protocol': 'tcp'}]
    assert result['volumes'] == [
        {'kind': 'bind', 'source': './config', 'target': '/config', 'read_only': False},
        {'kind': 'bind', 'source': '/mnt/tank/media/tv', 'target': '/tv', 'read_only': True},
    ]


def test_a_port_kept_on_the_bridge_is_exported_as_expose_not_published():
    # the internal development record: the Linux host gets the declaration, not a host listener.
    text = export_tool.compose_text(
        'redis', 'docker.io/library/redis:7', [],
        [{'host_port': None, 'container_port': 6379, 'protocol': 'tcp'},
         {'host_port': 16380, 'container_port': 6380, 'protocol': 'tcp'}],
        [], None, ['exported'],
    )
    assert '    ports:\n      - "16380:6380/tcp"\n' in text
    assert '    expose:\n      - "6379/tcp"\n' in text
    assert 'None' not in text
    result = compose_reader.read_export_compose(text)
    assert result['refusals'] == []
    assert result['ports'] == [{'host_port': 16380, 'container_port': 6380, 'protocol': 'tcp'}]
    # the internal development record: and it reads back as kept on the bridge, not as nothing.
    assert result['exposed'] == [{'container_port': 6379, 'protocol': 'tcp'}]


def test_expose_reads_single_ports_published_wins_and_ranges_are_dropped():
    # the internal development record
    result = compose_reader.read_export_compose(
        'services:\n  app:\n    image: docker.io/library/redis:7\n'
        '    ports:\n      - "8080:80"\n'
        '    expose:\n      - "6379"\n      - 80\n      - "53/udp"\n      - "3000-3005"\n      - "6379/tcp"\n'
    )
    assert result['refusals'] == []
    assert result['ports'] == [{'host_port': 8080, 'container_port': 80, 'protocol': 'tcp'}]
    assert result['exposed'] == [
        {'container_port': 6379, 'protocol': 'tcp'}, {'container_port': 53, 'protocol': 'udp'},
    ]
    assert "expose: '3000-3005' is not a single port, ignored" in result['drops']


def test_export_port_decisions_follow_the_bundle_and_keep_the_portal_on_the_host():
    # the internal development record: chosen > the bundle's ports: > its expose: > the catalog; the portal stays published.
    detail = {'install': {
        'ports': [
            {'host_port': 8096, 'container_port': 8096, 'protocol': 'tcp'},
            {'host_port': 8920, 'container_port': 8920, 'protocol': 'tcp'},
            {'host_port': 6379, 'container_port': 6379, 'protocol': 'tcp'},
            {'host_port': 1900, 'container_port': 1900, 'protocol': 'udp'},
        ],
        'portal': {'port': 8096, 'path': '/'},
    }}
    compose = {
        'ports': [{'host_port': 18920, 'container_port': 8920, 'protocol': 'tcp'}],
        'exposed': [{'container_port': 8096, 'protocol': 'tcp'}, {'container_port': 6379, 'protocol': 'tcp'}],
    }
    decide = ApplicationsConvertService._export_port_decisions
    decisions, entries = decide(detail, compose, None, 8096)
    assert decisions == [
        {'container_port': 8096, 'protocol': 'tcp', 'host_port': 8096},
        {'container_port': 8920, 'protocol': 'tcp', 'host_port': 18920},
        {'container_port': 6379, 'protocol': 'tcp', 'host_port': None},
        {'container_port': 1900, 'protocol': 'udp', 'host_port': 1900},
    ]
    assert [entry['what'] for entry in entries] == ['port'] * 4
    assert entries[0].get('warning') is True and "web page" in entries[0]['human']
    assert 'as the bundle published it' in entries[1]['human']
    assert entries[2]['human'] == 'port 6379/tcp stays on the managed network, not published on the host (as in the bundle)'
    assert 'does not mention it' in entries[3]['human']
    assert not any(entry.get('warning') for entry in entries[1:])
    chosen, _ = decide(detail, compose, 9000, 8096)
    assert chosen[0]['host_port'] == 9000 and chosen[1:] == decisions[1:]


def export_record(tmp_path, name='sonarr', catalog_id='daemonless:sonarr', version='4.0.15.2941',
                  image='ghcr.io/daemonless/sonarr:latest'):
    config = tmp_path / 'apps' / name / 'config'
    config.mkdir(parents=True)
    (config / 'sonarr.db').write_bytes(b'db')
    (config / 'config.xml').write_text('<Config><ApiKey>k</ApiKey></Config>')
    (config / 'Backups').mkdir()
    cache = tmp_path / 'apps' / name / 'cache'
    cache.mkdir()
    return {
        'schema': 4, 'name': name, 'image_os': 'freebsd', 'origin': None,
        'image': image, 'digest': 'sha256:' + 'a' * 64, 'updated_at': '2026-09-30T00:00:00+00:00',
        'environment': [
            {'name': 'PUID', 'value': '1000'}, {'name': 'PGID', 'value': '1000'},
            {'name': 'TZ', 'value': 'Europe/Stockholm'},
        ],
        'ports': [{'host_port': 8989, 'container_port': 8989, 'protocol': 'tcp'}],
        'volumes': [
            {'name': 'config', 'target': '/config', 'dataset': f'tank/applications/data/{name}/config',
             'source': str(config), 'owned': True, 'read_only': False},
            {'name': 'tv', 'target': '/tv', 'dataset': 'tank/media/tv', 'source': '/mnt/tank/media/tv',
             'owned': False, 'read_only': False},
            {'name': 'cache', 'target': '/cache', 'dataset': f'tank/applications/data/{name}/cache',
             'source': str(cache), 'owned': True, 'read_only': False},
        ],
        # The record shape _validate_record accepts: a list of {name, value}, never a mapping.
        'annotations': [{'name': 'org.freebsd.jail.allow.mlock', 'value': 'true'}],
        'network': {'mode': 'managed'},
        'catalog': {'id': catalog_id, 'version': version},
    }


def export_middleware(middleware, record, calls, running=True):
    def finished_job():
        job = Mock()
        job.wait = AsyncMock()
        job.error = None
        return job

    def mountpoint(dataset):
        return next(volume['source'] for volume in record['volumes'] if volume['dataset'] == dataset)

    async def call(method, *args):
        calls.append((method, args))
        if method == 'applications.catalog_record':
            return json.loads(json.dumps(record))
        if method == 'applications.query':
            return [{'name': record['name'], 'running': running}]
        if method in ('applications.stop', 'applications.start'):
            return finished_job()
        if method == 'zfs.snapshot.create':
            root = mountpoint(args[0]['dataset'])
            shutil.copytree(root, os.path.join(root, '.zfs', 'snapshot', args[0]['name']),
                            ignore=shutil.ignore_patterns('.zfs'), symlinks=True)
            return True
        if method == 'zfs.snapshot.delete':
            dataset, snapshot = args[0].split('@')
            shutil.rmtree(os.path.join(mountpoint(dataset), '.zfs', 'snapshot', snapshot))
            return True
        raise AssertionError(f'unexpected call {method}')

    middleware.call.side_effect = call


def export_inspections(monkeypatch, known):
    async def inspect(reference, os_name, architecture):
        if reference in known:
            return {'reference': reference, 'os': 'linux', 'architecture': 'amd64', 'environment': {},
                    'entrypoint': ['/init'], 'cmd': [], 'user': '', 'volumes': [], 'exposed_ports': [],
                    **known[reference]}
        raise CallError('manifest unknown')

    monkeypatch.setattr('middlewared.plugins.applications_convert_freebsd.inspect_remote_image', inspect)


@pytest.mark.asyncio
async def test_export_drops_a_mounted_system_certificate_and_says_what_to_do(tmp_path, monkeypatch):
    """the internal development record: the files are rendered from this system's certificate store into
    memory; nothing of them belongs in a bundle, and the plan tells the operator so."""
    record = export_record(tmp_path)
    record['certificates'] = [{
        'id': 7, 'name': 'wildcard.example', 'fingerprint': 'AA:BB', 'target': '/certs',
        'restart_on_change': True, 'uid': None, 'gid': None, 'public_key_sha256': 'e' * 64,
    }]
    service, middleware = service_with_middleware(tmp_path)
    export_middleware(middleware, record, [])
    export_inspections(monkeypatch, {'lscr.io/linuxserver/sonarr:version-4.0.15.2941': {
        'digest': 'sha256:' + 'f' * 64, 'labels': {'org.opencontainers.image.version': '4.0.15.2941-ls290'},
    }})

    plan = await service.export_plan('sonarr')

    dropped = [item for item in plan['entries'] if item.get('what') == 'certificate']
    assert [(item['type'], item['target']) for item in dropped] == [('drop', '/certs')]
    assert "'wildcard.example'" in dropped[0]['human']
    assert 'attach the certificate on the Linux host' in dropped[0]['human']
    # The rendered copy is not a volume of the application: it is carried nowhere.
    assert '/var/run/freecore-applications' not in json.dumps(plan)
    assert not any(item.get('target') == '/certs' for item in plan['entries'] if item['type'] == 'carry')


@pytest.mark.asyncio
async def test_export_writes_a_linux_bundle_that_reads_back_as_the_same_app(tmp_path, monkeypatch):
    record = export_record(tmp_path)
    service, middleware = service_with_middleware(tmp_path)
    calls = []
    export_middleware(middleware, record, calls)
    export_inspections(monkeypatch, {'lscr.io/linuxserver/sonarr:version-4.0.15.2941': {
        'digest': 'sha256:' + 'f' * 64, 'labels': {'org.opencontainers.image.version': '4.0.15.2941-ls290'},
    }})

    plan = await service.export_plan('sonarr')
    assert plan['direction'] == 'export' and plan['kind'] == 'state'
    assert plan['target'] == {
        'image': 'lscr.io/linuxserver/sonarr:version-4.0.15.2941', 'digest': 'sha256:' + 'f' * 64,
        'version': '4.0.15.2941-ls290',
    }
    assert plan['app']['recipe'] == 'sonarr@1' and plan['app']['version'] == '4.0.15.2941'
    carries = [item for item in plan['entries'] if item['type'] == 'carry']
    assert [(item['from'], item['to'], item['directory']) for item in carries] == [('', '/config', 'config')]
    drops = {item.get('what') for item in plan['entries'] if item['type'] == 'drop'}
    assert {'cache', 'annotations', 'healthcheck'} <= drops
    # The plan names the annotation; the record stores {name, value} pairs (a jellyfin install crashed here).
    assert any(
        item.get('what') == 'annotations' and 'org.freebsd.jail.allow.mlock' in item['human']
        for item in plan['entries']
    )
    assert any(item.get('what') == 'host_volume' and item['target'] == '/tv' for item in plan['entries'])
    assert any(item.get('what') == 'ownership' and 'PUID/PGID' in item['human'] for item in plan['entries'])
    assert all(item['human'] for item in plan['entries'])
    assert (tmp_path / 'plans' / 'export' / f'{plan["plan_id"]}.json').is_file()
    # An export plan never shows up among conversion plans, and apply cannot find it.
    config = await service._applications_config()
    assert service._read_plans(config) == []
    assert [item['plan_id'] for item in service._read_plans(config, service._export_plans_dir(config))] == [
        plan['plan_id']
    ]
    with pytest.raises(CallError, match='does not exist'):
        await ApplicationsConvertService.apply.wraps(service, Mock(), plan['plan_id'], {'confirm': True})

    destination = tmp_path / 'exports'
    destination.mkdir()
    monkeypatch.setattr(export_tool, 'check_destination', lambda path: None)
    with pytest.raises(CallError, match='Confirm'):
        await ApplicationsConvertService.export.wraps(
            service, Mock(), plan['plan_id'], {'destination': str(destination), 'mode': 'bundle', 'live': False,
                                               'confirm': False},
        )
    result = await ApplicationsConvertService.export.wraps(
        service, Mock(), plan['plan_id'],
        {'destination': str(destination), 'mode': 'bundle', 'live': False, 'confirm': True},
    )
    root = destination / 'sonarr'
    assert result['path'] == str(root) and result['image'] == 'lscr.io/linuxserver/sonarr:version-4.0.15.2941'
    assert (root / 'config' / 'sonarr.db').read_bytes() == b'db'
    assert (root / 'config' / 'config.xml').is_file() and (root / 'config' / 'Backups').is_dir()
    assert not (root / 'cache').exists() and not (root / 'config' / '.zfs').exists()
    assert result['fingerprint'] == bundle.fingerprint(str(root), (root / 'compose.yaml').read_text())
    methods = [method for method, _args in calls]
    # Stopped for the snapshot only, started again before the copy; the snapshot is gone afterwards.
    assert methods.index('applications.stop') < methods.index('zfs.snapshot.create') < \
        methods.index('applications.start')
    assert methods.count('zfs.snapshot.delete') == 1
    assert not os.listdir(os.path.join(record['volumes'][0]['source'], '.zfs', 'snapshot'))
    assert not (tmp_path / 'plans' / 'export' / f'{plan["plan_id"]}.json').exists()
    compose = compose_reader.read_export_compose((root / 'compose.yaml').read_text())
    assert compose['refusals'] == [] and compose['image'] == 'lscr.io/linuxserver/sonarr:version-4.0.15.2941'
    assert {item['name'] for item in compose['environment']} == {'PUID', 'PGID', 'TZ'}
    assert compose['volumes'] == [
        {'kind': 'bind', 'source': './config', 'target': '/config', 'read_only': False},
        {'kind': 'bind', 'source': '/mnt/tank/media/tv', 'target': '/tv', 'read_only': False},
    ]
    readme = (root / 'README.export').read_text()
    assert 'lscr.io/linuxserver/sonarr:version-4.0.15.2941' in readme and '[carry]' in readme
    # the internal development record: the way back names the path that exists (the API; the web interface converts jails
    # only) and no tracker reference reaches the user's bundle.
    assert '"kind": "linux-export"' in readme and 'applications.convert.apply' in readme
    assert 'Convert -> Import' not in readme and 'freecore/' not in readme
    with pytest.raises(CallError, match='already exists'):
        plan_again = await service.export_plan('sonarr')
        await ApplicationsConvertService.export.wraps(
            service, Mock(), plan_again['plan_id'],
            {'destination': str(destination), 'mode': 'bundle', 'live': False, 'confirm': True},
        )

    # Round trip: the #445 reader recognises the bundle as sonarr and carries ./config back into /config.
    detail = {
        'id': 'daemonless:sonarr', 'available': True,
        'catalog': {'version': '4.0.15', 'compose_sha256': 'c' * 64},
        'install': {'image': 'ghcr.io/daemonless/sonarr:latest',
                    'ports': [{'host_port': 8989, 'container_port': 8989, 'protocol': 'tcp'}],
                    'environment': [], 'volumes': [{'name': 'config', 'target': '/config', 'dataset': None,
                                                    'read_only': False}]},
    }

    async def import_call(method, *args):
        return {
            'applications.catalog.details': detail, 'applications.catalog.query': [{'name': 'sonarr'}],
            'applications.config': {'linux_compat_enabled': True}, 'applications.host_port_free': True,
            'pool.dataset.query': [],
        }[method]

    middleware.call.side_effect = import_call
    monkeypatch.setattr(bundle, 'discover', lambda path: {
        'root': str(root), 'compose_path': str(root / 'compose.yaml'),
        'compose_text': (root / 'compose.yaml').read_text(),
    })
    back = await service.plan(
        {'kind': 'linux-export', 'jail': None, 'path': str(root), 'image': None}, {'mode': 'native'},
    )
    assert back['mode'] == 'native' and back['app']['recipe'] == 'sonarr@1'
    carries = [(item['from'], item['to']) for item in back['entries'] if item['type'] == 'carry']
    assert carries == [(str(root / 'config'), '')]


@pytest.mark.asyncio
async def test_export_refuses_lifts_downgrades_missing_state_and_a_changed_application(tmp_path, monkeypatch):
    service, middleware = service_with_middleware(tmp_path)
    calls = []
    lifted = export_record(tmp_path / 'lift', name='oldjail', image='localhost/freecore-lift-oldjail:1')
    lifted['origin'] = {'kind': 'convert', 'reference': 'oldjail', 'mode': 'lift'}
    export_middleware(middleware, lifted, calls)
    with pytest.raises(CallError, match='lifted jail'):
        await service.export_plan('oldjail')

    record = export_record(tmp_path / 'older')
    export_middleware(middleware, record, calls)
    export_inspections(monkeypatch, {'lscr.io/linuxserver/sonarr:latest': {
        'digest': 'sha256:' + 'b' * 64, 'labels': {'org.opencontainers.image.version': '4.0.10.2544-ls200'},
    }})
    with pytest.raises(CallError, match='never moves to an older version'):
        await service.export_plan('sonarr')

    export_inspections(monkeypatch, {})
    plan = await service.export_plan('sonarr')
    assert plan['target']['image'] == 'lscr.io/linuxserver/sonarr:latest' and plan['target']['version'] is None
    assert {item.get('what') for item in plan['entries']} >= {'registry', 'version'}
    record['updated_at'] = '2026-10-01T00:00:00+00:00'
    monkeypatch.setattr(export_tool, 'check_destination', lambda path: None)
    with pytest.raises(CallError, match='changed since this plan'):
        await ApplicationsConvertService.export.wraps(
            service, Mock(), plan['plan_id'], {'destination': str(tmp_path), 'mode': 'bundle', 'live': False,
                                               'confirm': True},
        )

    grafana = export_record(tmp_path / 'grafana', name='grafana', catalog_id='daemonless:grafana',
                            version='13.1.1_2', image='ghcr.io/daemonless/grafana:pkg')
    config = grafana['volumes'][0]['source']
    os.makedirs(os.path.join(config, 'data'))
    export_middleware(middleware, grafana, calls)
    with pytest.raises(CallError, match='required state .*grafana.ini is missing'):
        await service.export_plan('grafana')
    with open(os.path.join(config, 'grafana.ini'), 'w') as file:
        file.write('[server]\nroot_url = https://grafana.example.org/\n')
    export_inspections(monkeypatch, {
        'docker.io/grafana/grafana:13.1.1': {'digest': 'sha256:' + 'c' * 64, 'labels': {}},
    })
    plan = await service.export_plan('grafana')
    assert plan['target']['image'] == 'docker.io/grafana/grafana:13.1.1' and plan['target']['version'] == '13.1.1'
    assert plan['compose']['user'] == '1000:1000'
    assert [name for name, _value in plan['compose']['environment']] == ['TZ']
    assert [(item['from'], item['to']) for item in plan['entries'] if item['type'] == 'carry'] == [
        ('data', '/var/lib/grafana'), ('grafana.ini', '/etc/grafana/grafana.ini'),
    ]
    assert any(item.get('what') == 'optional' for item in plan['entries'])
    assert any(item['type'] == 'drop' and item['human'].startswith('plugins:') for item in plan['entries'])


@pytest.mark.asyncio
async def test_export_of_compat_and_recipe_less_applications(tmp_path, monkeypatch):
    service, middleware = service_with_middleware(tmp_path)
    calls = []
    compat = export_record(tmp_path / 'compat', name='kuma', catalog_id=None, image='docker.io/louislam/uptime-kuma:1')
    compat['image_os'] = 'linux'
    compat['catalog'] = None
    compat['annotations'] = {}
    export_middleware(middleware, compat, calls)
    export_inspections(monkeypatch, {})
    plan = await service.export_plan('kuma')
    assert plan['kind'] == 'identity' and plan['target']['image'] == 'docker.io/louislam/uptime-kuma:1'
    assert [(item['from'], item['to']) for item in plan['entries'] if item['type'] == 'carry'] == [
        ('', '/config'), ('', '/cache'),
    ]
    assert plan['compose']['environment'] == [['PUID', '1000'], ['PGID', '1000'], ['TZ', 'Europe/Stockholm']]

    fresh = export_record(tmp_path / 'fresh', name='gitea', catalog_id='daemonless:gitea',
                          image='ghcr.io/daemonless/gitea:latest')
    export_middleware(middleware, fresh, calls)
    plan = await service.export_plan('gitea')
    assert plan['kind'] == 'fresh' and plan['target']['image'] == 'docker.io/gitea/gitea:latest'
    assert plan['copies'] == [] and not any(item['type'] == 'carry' for item in plan['entries'])
    assert any(item.get('what') == 'fresh' for item in plan['entries'])

    nothing = export_record(tmp_path / 'none', name='obscure', catalog_id='daemonless:obscure',
                            image='ghcr.io/daemonless/obscure:latest')
    export_middleware(middleware, nothing, calls)
    with pytest.raises(CallError, match='No Linux image is known'):
        await service.export_plan('obscure')


def plex_bundle(root, with_data=True, named_volume=False):
    root.mkdir(parents=True)
    volume = '      - plex-config:/config\n' if named_volume else '      - ./config:/config\n'
    root.joinpath('compose.yaml').write_text(
        'services:\n'
        '  plex:\n'
        '    image: lscr.io/linuxserver/plex:latest\n'
        '    environment:\n'
        '      - PUID=1000\n'
        '      - PGID=1000\n'
        '      - VERSION=docker\n'
        '    volumes:\n' + volume +
        '      - /srv/media/movies:/movies\n'
        '    ports:\n'
        '      - "32400:32400"\n'
        + ('volumes:\n  plex-config: {}\n' if named_volume else '')
    )
    config = root / 'config'
    config.mkdir()
    if with_data:
        data = config / 'Library' / 'Application Support' / 'Plex Media Server'
        data.mkdir(parents=True)
        (data / 'Preferences.xml').write_text('<Preferences ProcessedMachineIdentifier="abc"/>')
    return root


@pytest.mark.asyncio
async def test_a_linux_plex_bundle_finds_its_data_inside_the_config_mount(tmp_path, monkeypatch):
    # the internal development record: every Plex image mounts /config; the data directory is below it.
    service, middleware = service_with_middleware(tmp_path)
    detail = {
        'id': 'daemonless:plex', 'available': True,
        'catalog': {'version': '1.43.3.10896', 'compose_sha256': 'c' * 64},
        'install': {'image': 'ghcr.io/daemonless/plex:latest',
                    'ports': [{'host_port': 32400, 'container_port': 32400, 'protocol': 'tcp'}],
                    'environment': [], 'volumes': [{'name': 'config', 'target': '/config', 'dataset': None,
                                                    'read_only': False}]},
    }

    async def call(method, *args):
        return {
            'applications.catalog.details': detail, 'applications.catalog.query': [{'name': 'plex'}],
            'applications.config': {'linux_compat_enabled': True}, 'applications.host_port_free': True,
            'pool.dataset.query': [],
        }[method]

    middleware.call.side_effect = call
    monkeypatch.setattr(
        'middlewared.plugins.applications_convert_freebsd.inspect_remote_image', AsyncMock(return_value=None),
    )

    def discover_at(root):
        monkeypatch.setattr(bundle, 'discover', lambda path: {
            'root': str(root), 'compose_path': str(root / 'compose.yaml'),
            'compose_text': (root / 'compose.yaml').read_text(),
        })

    root = plex_bundle(tmp_path / 'good')
    discover_at(root)
    source = {'kind': 'linux-export', 'jail': None, 'path': str(root), 'image': None}
    plan = await service.plan(source, {'mode': 'native'})
    assert plan['mode'] == 'native' and plan['app']['recipe'] == 'plex@1'
    data = str(root / 'config' / 'Library' / 'Application Support' / 'Plex Media Server')
    assert [(item['from'], item['to']) for item in plan['entries'] if item['type'] == 'carry'] == [
        (data, 'Library/Application Support/Plex Media Server'),
    ]

    root = plex_bundle(tmp_path / 'empty', with_data=False)
    discover_at(root)
    # No data below the mount: native says which path is missing (compat is refused too: the media
    # bind is not in the bundle), so nothing is offered.
    with pytest.raises(CallError, match='holds no Library/Application Support/Plex Media Server inside it'):
        await service.plan({**source, 'path': str(root)}, {})

    root = plex_bundle(tmp_path / 'named', named_volume=True)
    discover_at(root)
    with pytest.raises(CallError, match='inside the named volume'):
        await service.plan({**source, 'path': str(root)}, {})
    # hotio keeps Plex's data at the volume root; it is not claimed by the recipe.
    recipes = recipe_store.load_recipes()
    assert recipe_store.recipe_for_linux_image('ghcr.io/hotio/plex:release', recipes) == (None, None)


@pytest.mark.asyncio
async def test_a_latest_tagged_source_takes_its_version_from_the_image_label(tmp_path, monkeypatch):
    # the internal development record: Daemonless emby is 4.9.3.0; a 4.10 programdata must not be carried into it.
    service, middleware = service_with_middleware(tmp_path)
    root = tmp_path / 'emby'
    (root / 'config' / 'data').mkdir(parents=True)
    (root / 'config' / 'data' / 'library.db').write_bytes(b'db')
    root.joinpath('compose.yaml').write_text(
        'services:\n  emby:\n    image: lscr.io/linuxserver/emby:latest\n'
        '    volumes:\n      - ./config:/config\n    ports:\n      - "8096:8096"\n'
    )
    detail = {
        'id': 'daemonless:emby', 'available': True,
        'catalog': {'version': '4.9.3.0', 'compose_sha256': 'c' * 64},
        'install': {'image': 'ghcr.io/daemonless/emby:latest',
                    'ports': [{'host_port': 8096, 'container_port': 8096, 'protocol': 'tcp'}],
                    'environment': [], 'volumes': [{'name': 'config', 'target': '/config', 'dataset': None,
                                                    'read_only': False}]},
    }

    async def call(method, *args):
        return {
            'applications.catalog.details': detail, 'applications.catalog.query': [{'name': 'emby'}],
            'applications.config': {'linux_compat_enabled': False}, 'applications.host_port_free': True,
            'pool.dataset.query': [],
        }[method]

    middleware.call.side_effect = call
    monkeypatch.setattr(bundle, 'discover', lambda path: {
        'root': str(root), 'compose_path': str(root / 'compose.yaml'),
        'compose_text': root.joinpath('compose.yaml').read_text(),
    })
    labelled = {
        'reference': 'x', 'digest': 'sha256:' + 'e' * 64, 'os': 'linux', 'architecture': 'amd64',
        'labels': {'org.opencontainers.image.version': '4.10.1.0-ls42'}, 'environment': {},
        'entrypoint': ['/init'], 'cmd': [], 'user': '', 'volumes': ['/config'], 'exposed_ports': ['8096/tcp'],
    }
    inspect = AsyncMock(return_value=labelled)
    monkeypatch.setattr('middlewared.plugins.applications_convert_freebsd.inspect_remote_image', inspect)
    source = {'kind': 'linux-export', 'jail': None, 'path': str(root), 'image': None}

    detected = await service.detect(source)
    assert detected['version'] == '4.10.1.0-ls42'
    with pytest.raises(CallError, match='older than the source 4.10.1.0-ls42'):
        await service.plan(source, {'mode': 'native'})

    # No label either: the plan carries it but says the version is unknown.
    inspect.return_value = {**labelled, 'labels': {}}
    plan = await service.plan(source, {'mode': 'native'})
    assert plan['mode'] == 'native'
    assert any(item.get('what') == 'source_version' for item in plan['entries'])


@pytest.mark.asyncio
async def test_export_with_host_root_writes_absolute_binds_scale_can_install(tmp_path, monkeypatch):
    # the internal development record Stage 0: TrueNAS SCALE's Install via YAML does not resolve ./ binds.
    record = export_record(tmp_path)
    service, middleware = service_with_middleware(tmp_path)
    export_middleware(middleware, record, [])
    export_inspections(monkeypatch, {})
    monkeypatch.setattr(export_tool, 'check_destination', lambda path: None)
    destination = tmp_path / 'exports'
    destination.mkdir()
    options = {'destination': str(destination), 'mode': 'bundle', 'live': True, 'confirm': True}

    plan = await service.export_plan('sonarr')
    for bad, reason in (('relative/path', 'normalized absolute'), ('/mnt/a:b', 'normalized absolute'),
                        ('/mnt/apps/', 'normalized absolute')):
        with pytest.raises(CallError, match=reason):
            await ApplicationsConvertService.export.wraps(
                service, Mock(), plan['plan_id'], {**options, 'host_root': bad})
    with pytest.raises(CallError, match='applies to a bundle'):
        await ApplicationsConvertService.export.wraps(
            service, Mock(), plan['plan_id'], {**options, 'mode': 'in-place', 'host_root': '/mnt/apps/bundles'})

    await ApplicationsConvertService.export.wraps(
        service, Mock(), plan['plan_id'], {**options, 'host_root': '/mnt/apps/bundles'})
    root = destination / 'sonarr'
    compose = compose_reader.read_export_compose((root / 'compose.yaml').read_text())
    assert compose['volumes'][0] == {
        'kind': 'bind', 'source': '/mnt/apps/bundles/sonarr/config', 'target': '/config', 'read_only': False,
    }
    assert compose['volumes'][1]['source'] == '/mnt/tank/media/tv'
    readme = (root / 'README.export').read_text()
    assert 'copy this directory to /mnt/apps/bundles/sonarr' in readme
    # An absolute bind still reads back: the #445 reader finds it beside the compose file by name.
    assert bundle.resolve_bind(str(root), '/mnt/apps/bundles/sonarr/config') == str(root / 'config')


@pytest.mark.asyncio
async def test_export_notes_the_pools_scale_would_meet_and_refuses_a_full_destination(tmp_path, monkeypatch):
    from middlewared.plugins.config_ import scale as scale_config
    record = export_record(tmp_path)
    service, middleware = service_with_middleware(tmp_path)
    calls = []
    export_middleware(middleware, record, calls)
    export_inspections(monkeypatch, {})
    reports = {
        'tank': {'pool': 'tank', 'reference': 'TrueNAS SCALE 24.10.0', 'refused': ['longname'],
                 'read_only': [], 'dormant': ['physical_rewrite']},
    }
    monkeypatch.setattr(scale_config, 'pool_feature_report', lambda pool: reports.get(pool))
    plan = await service.export_plan('sonarr')
    notes = [item for item in plan['entries'] if item.get('what') == 'pool_features']
    assert [item['pool'] for item in notes] == ['tank']
    assert 'longname (in use), physical_rewrite (enabled)' in notes[0]['human']
    assert 'import the pool only on OpenZFS 2.4 (TrueNAS 27 or later)' in notes[0]['human']
    assert 'in-place export' in notes[0]['human']

    monkeypatch.setattr(export_tool, 'check_destination', lambda path: None)
    monkeypatch.setattr(export_tool, 'logical_size', lambda target: 50 * 2 ** 30)
    monkeypatch.setattr(export_tool, 'free_bytes', lambda path: 2 ** 30)
    destination = tmp_path / 'exports'
    destination.mkdir()
    with pytest.raises(CallError, match=r'needs about 50\.0 GiB and .* has 1\.0 GiB free'):
        await ApplicationsConvertService.export.wraps(
            service, Mock(), plan['plan_id'],
            {'destination': str(destination), 'mode': 'bundle', 'live': False, 'confirm': True})
    # Refused before anything was copied: no half bundle, the application is running, no snapshot left.
    assert not (destination / 'sonarr').exists()
    methods = [method for method, _args in calls]
    assert methods.count('applications.start') == 1 and methods.count('zfs.snapshot.delete') == 1
    assert export_tool.human_size(1536) == '1.5 KiB' and export_tool.human_size(10) == '10 B'


def test_copy_state_streams_trees_and_files_without_cp(tmp_path, monkeypatch):
    # the internal development record: cp would ask ZFS for block cloning and activate block_cloning_endian.
    real_popen, real_run = export_tool.subprocess.Popen, export_tool.subprocess.run
    seen = []

    def spy_popen(argv, *args, **kwargs):
        seen.append(argv[0])
        return real_popen(argv, *args, **kwargs)

    def spy_run(argv, *args, **kwargs):
        seen.append(argv[0])
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(export_tool.subprocess, 'Popen', spy_popen)
    monkeypatch.setattr(export_tool.subprocess, 'run', spy_run)
    source = tmp_path / 'snapshot'
    (source / 'Library' / 'deep').mkdir(parents=True)
    (source / 'Library' / 'deep' / 'db.sqlite').write_bytes(b'x' * 4096)
    (source / 'private.key').write_text('k')
    os.chmod(source / 'private.key', 0o600)
    os.symlink('Library/deep/db.sqlite', source / 'link')
    os.utime(source / 'private.key', ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_000))

    export_tool.copy_state(str(source), str(tmp_path / 'bundle' / 'config'))
    copied = tmp_path / 'bundle' / 'config'
    assert (copied / 'Library' / 'deep' / 'db.sqlite').read_bytes() == b'x' * 4096
    assert oct(os.stat(copied / 'private.key').st_mode & 0o777) == '0o600'
    assert os.stat(copied / 'private.key').st_mtime_ns == 1_700_000_000_000_000_000
    assert os.readlink(copied / 'link') == 'Library/deep/db.sqlite'

    export_tool.copy_state(str(source / 'private.key'), str(tmp_path / 'bundle' / 'etc-app-private.key'))
    single = tmp_path / 'bundle' / 'etc-app-private.key'
    assert single.read_text() == 'k' and oct(os.stat(single).st_mode & 0o777) == '0o600'
    assert os.stat(single).st_mtime_ns == 1_700_000_000_000_000_000
    assert 'cp' not in seen and set(seen) == {'tar'}
    with pytest.raises(CatalogContractError, match='never overwrites'):
        export_tool.copy_state(str(source), str(copied))


EXPOSED_COMPOSE = COMPOSE.replace('    ports:\n      - "3000:3000"\n', '    expose:\n      - "3000/tcp"\n')


@pytest.mark.asyncio
@pytest.mark.parametrize('compose, options, host_port', [
    (EXPOSED_COMPOSE, {}, None),                       # kept on the bridge in the bundle: stays off the host
    (COMPOSE.replace('"3000:3000"', '"13000:3000"'), {}, 13000),   # the bundle's own host port
    (EXPOSED_COMPOSE, {'host_port': 3100}, 3100),      # a host port chosen for the conversion wins
], ids=['exposed-stays-on-the-bridge', 'bundle-host-port', 'chosen-host-port'])
async def test_recipe_conversion_of_an_export_keeps_its_port_choices(tmp_path, monkeypatch, compose, options, host_port):
    # the internal development record: an export brought back through a recipe published the port it kept on
    # the managed network, on the catalog's host port, and the reviewed plan showed no port at all.
    root = make_bundle(tmp_path / 'export')
    root.joinpath('compose.yaml').write_text(compose)
    assert EXPOSED_COMPOSE != COMPOSE  # the fixture really swapped ports: for expose:
    service, middleware = service_with_middleware(tmp_path)
    mountpoint = tmp_path / 'mnt' / 'tank' / 'applications' / 'data' / 'grafana' / 'config'
    mountpoint.mkdir(parents=True)
    calls = []

    async def call(method, *args):
        calls.append((method, args))
        if method == 'applications.catalog.details':
            return grafana_detail()
        if method == 'applications.catalog.query':
            return [{'name': 'grafana'}]
        if method == 'applications.config':
            return {'linux_compat_enabled': True}
        if method == 'applications.query':
            return []
        if method == 'applications.prepare_owned_volume':
            return {'dataset': 'tank/applications/data/grafana/config', 'mountpoint': str(mountpoint),
                    'created': ['tank/applications/data/grafana', 'tank/applications/data/grafana/config']}
        if method == 'filesystem.chown':
            job = Mock()
            job.wait = AsyncMock()
            job.error = None
            return job
        if method == 'applications.catalog.bind_install':
            return ({'name': 'grafana', 'image': 'ghcr.io/daemonless/grafana:pkg'}, {'id': 'daemonless:grafana'})
        if method == 'applications.install_catalog':
            return 'subjob'
        raise AssertionError(f'unexpected call {method}')

    middleware.call.side_effect = call
    monkeypatch.setattr(bundle, 'discover', lambda path: {
        'root': str(root), 'compose_path': str(root / 'compose.yaml'),
        'compose_text': root.joinpath('compose.yaml').read_text(),
    })
    monkeypatch.setattr(
        'middlewared.plugins.applications_convert_freebsd.inspect_remote_image', AsyncMock(return_value=None),
    )

    plan = await service.plan({'kind': 'linux-export', 'jail': None, 'path': str(root), 'image': None}, options)
    assert plan['mode'] == 'native'
    assert plan['application']['ports'] == [{'container_port': 3000, 'protocol': 'tcp', 'host_port': host_port}]
    lines = [item for item in plan['entries'] if item.get('what') == 'port']
    assert len(lines) == 1 and lines[0]['host_port'] == host_port
    if host_port is None:
        assert 'stays on the managed network' in lines[0]['human']
    else:
        assert f'published as host port {host_port}' in lines[0]['human']

    job = Mock()
    job.wrap = AsyncMock(return_value={'name': 'grafana'})
    result = await ApplicationsConvertService.apply.wraps(service, job, plan['plan_id'], {'confirm': True})
    assert result == {'name': 'grafana'}
    bind = next(args for method, args in calls if method == 'applications.catalog.bind_install')[0]
    assert bind['ports'] == [{'host_port': host_port, 'container_port': 3000, 'protocol': 'tcp'}]

