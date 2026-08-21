"""the internal development record: provider runtime options, first the stop grace period.

ClickHouse's compose asks for `stop_grace_period: 60s` so a stop gives it a minute to flush before
podman kills it; the contract refused the field and the entry was never offered. It is read as whole
seconds, carried in the record as `runtime.stop_timeout`, and becomes `podman create --stop-timeout`,
which `podman stop` and restart then honour.
"""
from pathlib import Path

import pytest

from middlewared.plugins.applications_.catalog import (
    CatalogContractError,
    compose_duration_seconds,
    normalize_daemonless_contract,
    normalize_catalog_index,
)
from middlewared.plugins.applications_.convert import compose as compose_reader
from middlewared.plugins.applications_.convert import export as export_tool
from middlewared.plugins.applications_.utils import podman_create_args, public_record
from middlewared.plugins.applications_freebsd import ApplicationsService

FIXTURES = Path(__file__).parent / 'fixtures' / 'applications_catalog'


def entry():
    import json
    index = json.loads((FIXTURES / 'index.json').read_text())
    repositories = json.loads((FIXTURES / 'repositories.json').read_text())
    catalog = normalize_catalog_index(index, [repositories], 'amd64')
    return next(item for item in catalog['entries'] if item['name'] == 'demo')


def compose_with(line):
    return (FIXTURES / 'compose.yaml').read_text().replace(
        '    restart: unless-stopped\n', f'    restart: unless-stopped\n    {line}\n',
    )


@pytest.mark.parametrize('value,seconds', [
    ('60s', 60), ('1m30s', 90), ('1h', 3600), ('500ms', 1), ('1.5s', 2), ('0s', 0), ('2m', 120),
])
def test_a_compose_duration_is_whole_seconds_rounded_up(value, seconds):
    assert compose_duration_seconds(value) == seconds


@pytest.mark.parametrize('value', ['60', 'soon', '1d', '60 s', '', '-5s', 60, None, 's60'])
def test_what_is_not_a_compose_duration_reads_as_none(value):
    assert compose_duration_seconds(value) is None


def test_the_stop_grace_period_reaches_the_contract_and_its_install_block():
    contract = normalize_daemonless_contract(entry(), compose_with('stop_grace_period: 60s'))
    assert contract['runtime'] == {'stop_timeout': 60}
    plain = normalize_daemonless_contract(entry(), (FIXTURES / 'compose.yaml').read_text())
    assert plain['runtime'] == {}


@pytest.mark.parametrize('line', ['stop_grace_period: soon', 'stop_grace_period: 2h'])
def test_an_unreadable_or_unbounded_grace_period_is_refused(line):
    with pytest.raises(CatalogContractError, match='stop_grace_period'):
        normalize_daemonless_contract(entry(), compose_with(line))


def record(**overrides):
    base = {
        'name': 'demo', 'container_name': 'freecore-app-demo', 'image': 'registry.example/demo:1',
        'restart_policy': 'always', 'annotations': [], 'environment': [], 'ports': [], 'volumes': [],
        'labels': [],
    }
    base.update(overrides)
    return base


def test_the_container_is_created_with_the_stop_timeout():
    args = podman_create_args(record(runtime={'stop_timeout': 60}))
    assert args[args.index('--stop-timeout') + 1] == '60'
    assert args.index('--stop-timeout') < args.index('--')


def test_a_record_without_runtime_options_creates_the_container_as_before():
    assert '--stop-timeout' not in podman_create_args(record())
    assert '--stop-timeout' not in podman_create_args(record(runtime={}))


def test_query_presents_runtime_options_even_for_a_record_written_before_them():
    assert public_record(record())['runtime'] == {}


def test_the_linux_export_carries_the_grace_period_and_reads_it_back():
    text = export_tool.compose_text(
        'clickhouse', 'docker.io/clickhouse/clickhouse-server:25', [], [], [], None, ['exported'],
        runtime={'stop_timeout': 60},
    )
    assert '    stop_grace_period: "60s"\n' in text
    result = compose_reader.read_export_compose(text)
    assert result['stop_timeout'] == 60 and result['drops'] == []


def test_an_import_keeps_a_grace_period_and_notes_one_it_cannot_read():
    good = compose_reader.read_export_compose(
        'services:\n  db:\n    image: docker.io/library/postgres:17\n    stop_grace_period: 1m30s\n'
    )
    assert good['stop_timeout'] == 90
    bad = compose_reader.read_export_compose(
        'services:\n  db:\n    image: docker.io/library/postgres:17\n    stop_grace_period: forever\n'
    )
    assert bad['stop_timeout'] is None
    assert any(item.startswith('stop_grace_period:') for item in bad['drops'])


def test_a_record_carries_only_known_bounded_runtime_options():
    from middlewared.pytest.unit.plugins.test_applications_experimental import config, record as stored
    cfg = config()
    assert ApplicationsService._validate_record(cfg, stored(runtime={'stop_timeout': 60}), 'demo')['runtime'] == {'stop_timeout': 60}
    assert 'runtime' not in ApplicationsService._validate_record(cfg, stored(), 'demo')
    for broken in (
        {'stop_timeout': 3601}, {'stop_timeout': -1}, {'stop_timeout': '60'}, {'stop_timeout': True},
        {'grace': 60}, ['stop_timeout'],
    ):
        with pytest.raises(ValueError):
            ApplicationsService._validate_record(cfg, stored(runtime=broken), 'demo')


# -- the internal development record: extra_hosts -----------------------------------------------------
# OpenCloud's compose maps its own placeholder host name to the loopback address so the URL it is told
# to serve (OC_URL=https://hostname:9200) resolves inside the container.

from middlewared.plugins.applications_.catalog import compose_extra_hosts  # noqa: E402
from middlewared.plugins.applications_freebsd import runtime_options  # noqa: E402
from middlewared.service_exception import CallError  # noqa: E402


@pytest.mark.parametrize('value', [
    ['hostname:127.0.0.1', 'db.internal=192.0.2.5'],
    {'hostname': '127.0.0.1', 'db.internal': '192.0.2.5'},
])
def test_extra_hosts_read_as_name_sorted_pairs_from_a_list_or_a_mapping(value):
    assert compose_extra_hosts(value) == [
        {'host': 'db.internal', 'address': '192.0.2.5'},
        {'host': 'hostname', 'address': '127.0.0.1'},
    ]


def test_an_ipv6_extra_host_uses_equals_or_brackets_and_is_normalised():
    assert compose_extra_hosts(['v6host=2001:db8::0001']) == [{'host': 'v6host', 'address': '2001:db8::1'}]
    assert compose_extra_hosts(['v6host:[::1]']) == [{'host': 'v6host', 'address': '::1'}]


@pytest.mark.parametrize('value', [
    ['nocolon'], ['bad_host:127.0.0.1'], ['host:not-an-ip'], ['a:127.0.0.1', 'a:127.0.0.2'],
    'hostname:127.0.0.1', [1], [f'h{i}:127.0.0.1' for i in range(65)],
])
def test_an_extra_host_that_is_not_a_name_and_an_address_is_refused(value):
    with pytest.raises(ValueError):
        compose_extra_hosts(value)


def test_extra_hosts_reach_the_contract_and_the_container():
    contract = normalize_daemonless_contract(entry(), compose_with('extra_hosts:\n      - "hostname:127.0.0.1"'))
    assert contract['runtime'] == {'extra_hosts': [{'host': 'hostname', 'address': '127.0.0.1'}]}
    args = podman_create_args(record(runtime=contract['runtime']))
    assert args[args.index('--add-host') + 1] == 'hostname:127.0.0.1'
    assert args.index('--add-host') < args.index('--')


def test_a_contract_with_an_unusable_extra_host_is_refused():
    with pytest.raises(CatalogContractError, match='extra_hosts'):
        normalize_daemonless_contract(entry(), compose_with('extra_hosts:\n      - "hostname:localhost"'))


def test_install_writes_canonical_runtime_options_and_refuses_a_repeated_host():
    assert runtime_options({'stop_timeout': None, 'extra_hosts': [
        {'host': 'b', 'address': '192.0.2.2'}, {'host': 'a', 'address': '192.0.2.1'},
    ]}) == {'extra_hosts': [{'host': 'a', 'address': '192.0.2.1'}, {'host': 'b', 'address': '192.0.2.2'}]}
    assert runtime_options(None) == {} and runtime_options({'extra_hosts': []}) == {}
    with pytest.raises(CallError, match='unique'):
        runtime_options({'extra_hosts': [{'host': 'a', 'address': '192.0.2.1'}, {'host': 'a', 'address': '192.0.2.2'}]})


def test_a_record_carries_only_canonical_extra_hosts():
    from middlewared.pytest.unit.plugins.test_applications_experimental import config, record as stored
    cfg = config()
    good = stored(runtime={'extra_hosts': [{'host': 'hostname', 'address': '127.0.0.1'}]})
    assert ApplicationsService._validate_record(cfg, good, 'demo') == good
    for broken in (
        [{'host': 'b', 'address': '192.0.2.2'}, {'host': 'a', 'address': '192.0.2.1'}],  # unsorted
        [{'host': 'bad host', 'address': '127.0.0.1'}],
        [{'host': 'a', 'address': '127.0.0.1', 'extra': 1}],
        'hostname:127.0.0.1',
    ):
        with pytest.raises(ValueError):
            ApplicationsService._validate_record(cfg, stored(runtime={'extra_hosts': broken}), 'demo')


def test_the_linux_export_carries_extra_hosts_and_the_import_reads_them_back():
    text = export_tool.compose_text(
        'opencloud', 'docker.io/opencloudeu/opencloud-rolling:latest', [], [], [], None, ['exported'],
        runtime={'extra_hosts': [{'host': 'hostname', 'address': '127.0.0.1'}, {'host': 'v6', 'address': '::1'}]},
    )
    assert '    extra_hosts:\n      - "hostname=127.0.0.1"\n      - "v6=::1"\n' in text
    result = compose_reader.read_export_compose(text)
    assert result['extra_hosts'] == [{'host': 'hostname', 'address': '127.0.0.1'}, {'host': 'v6', 'address': '::1'}]
    assert result['drops'] == []
