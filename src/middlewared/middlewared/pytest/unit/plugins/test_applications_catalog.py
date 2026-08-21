"""The Applications catalog reads the Daemonless organisation directly (the internal development record)."""
import copy
import json
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from middlewared.plugins.applications_.catalog import (
    CatalogContractError,
    entry_version,
    finalize_daemonless_contract,
    finalize_tag_contract,
    image_tag,
    image_version,
    installed_catalog_provenance,
    normalize_catalog_index,
    normalize_daemonless_contract,
    parse_catalog_yaml,
    version_key,
)
from middlewared.plugins.applications_.provider import (
    CACHE_SCHEMA,
    PROVIDER_INDEX_URL,
    ProviderClient,
    ProviderNotFound,
    empty_cache,
    is_stale,
    read_cache,
    repositories_due,
    sha256_hex,
    store_compose,
    validate_cache,
    write_cache,
)
from middlewared.plugins.applications_catalog_freebsd import (
    ApplicationsCatalogService,
    bind_catalog_install,
    bind_catalog_update,
    catalog_entries,
    catalog_install_state,
    catalog_provenance,
)
from middlewared.plugins.applications_freebsd import ApplicationsService
from middlewared.service_exception import CallError


FIXTURES = Path(__file__).parent / 'fixtures' / 'applications_catalog'


def fixtures():
    index = json.loads((FIXTURES / 'index.json').read_text())
    repositories = json.loads((FIXTURES / 'repositories.json').read_text())
    return index, [repositories]


def entry(name='demo', architecture='amd64'):
    index, repositories = fixtures()
    catalog = normalize_catalog_index(index, repositories, architecture)
    return next(item for item in catalog['entries'] if item['name'] == name)


def image_info(**overrides):
    result = {
        'digest': 'sha256:' + 'a' * 64,
        'os': 'freebsd',
        'architecture': 'amd64',
    }
    result.update(overrides)
    return result


def live_cache(with_compose=True):
    index, repositories = fixtures()
    cache = empty_cache()
    cache.update({
        'source': 'live', 'fetched_at': 1_800_000_000, 'repositories_fetched_at': 1_800_000_000,
        'index': index, 'repositories': repositories,
    })
    if with_compose:
        store_compose(cache, 'demo', (FIXTURES / 'compose.yaml').read_text(), now=1_800_000_000)
    return cache


def service_with_middleware(cache=None):
    middleware = Mock()
    middleware.call = AsyncMock()
    service = ApplicationsCatalogService(middleware)
    service._catalog_cache = cache if cache is not None else live_cache()
    service._save_cache = Mock(side_effect=lambda value: setattr(service, '_catalog_cache', value))
    service._architecture = Mock(return_value='amd64')
    service._resolve_image = AsyncMock(return_value=(None, False))
    return service, middleware


# -- surface ------------------------------------------------------------------

def test_the_two_install_tiers_exist_and_nothing_signed_remains():
    # The catalog tier binds to the reviewed contract; the second tier is the
    # acknowledged bring-your-own install (the internal development record, #443).
    assert hasattr(ApplicationsCatalogService, 'install')
    assert hasattr(ApplicationsCatalogService, 'update')
    assert hasattr(ApplicationsService, 'install')
    assert not hasattr(ApplicationsCatalogService, 'custom')
    assert not hasattr(ApplicationsCatalogService, '_root_certificate')
    assert not hasattr(ApplicationsCatalogService, '_operation_catalog')


# -- normalisation (unchanged contract) ---------------------------------------

def test_schema_v2_index_is_deterministic_and_marks_preflight_boundaries():
    index, repositories = fixtures()
    catalog = normalize_catalog_index(index, repositories, 'x86_64')

    assert [item['name'] for item in catalog['entries']] == ['base-demo', 'demo', 'x86-demo']
    by_name = {item['name']: item for item in catalog['entries']}
    assert by_name['demo']['status'] == 'UNRESOLVED'
    assert by_name['demo']['architectures'] == ['aarch64', 'amd64']
    assert by_name['demo']['attribution']['license'] == 'BSD-2-Clause'
    assert by_name['base-demo']['status'] == 'UNAVAILABLE'
    assert 'Base images' in by_name['base-demo']['reason']


# the internal development record: the index lists one version per published flavour.
# Observed 2026-09-15: ``:latest`` == ``:1.37.3`` (upstream), ``:pkg`` ==
# ``:1.36.0_1-pkg`` (quarterly), ``:pkg-latest`` == ``:1.37.2_1-pkg-latest``.
VAULTWARDEN = {'versions': {
    'pkg': {'amd64': '1.36.0_1', 'aarch64': '1.36.0_1'},
    'pkg-latest': {'amd64': '1.37.2_1', 'aarch64': '1.37.2_1'},
    'upstream': '1.37.3',
}}
POSTGRES = {'versions': {
    'type': 'multi-version', 'default': '18',
    'variants': {
        '14': {'pkg': {'amd64': '14.24'}, 'pkg-latest': {'amd64': '14.24'}},
        '18': {'pkg': {'amd64': '18.6'}, 'pkg-latest': {'amd64': '18.7'}},
    },
}}
HAPROXY = {'versions': {
    'type': 'multi-version', 'default': '3.4',
    'variants': {'3.0': {'lua-pkg-latest': {'amd64': '3.0.24_1'}, 'pkg-latest': {'amd64': '3.0.27'}}},
}}


def test_entry_version_reads_the_field_of_the_flavour_the_image_was_built_as():
    # The tag the compose pins is only an assumption; the image's variant label
    # decides.  No variant means the ``latest`` assumption.
    assert entry_version(VAULTWARDEN, 'amd64') == '1.37.3'
    assert entry_version(VAULTWARDEN, 'amd64', 'latest') == '1.37.3'
    assert entry_version(VAULTWARDEN, 'x86_64', 'pkg') == '1.36.0_1'
    assert entry_version(VAULTWARDEN, 'aarch64', 'pkg-latest') == '1.37.2_1'
    assert entry_version(VAULTWARDEN, 'amd64', 'lts') is None
    # Package-only services: ``latest`` is one of the package builds.
    assert entry_version(entry('x86-demo'), 'amd64') == '2.0.0'
    assert entry_version(entry('x86-demo'), 'aarch64') is None
    assert entry_version(entry('demo'), 'aarch64', 'pkg') == '1.2.2'
    assert entry_version({'versions': {'upstream': 'v9'}}, 'amd64', 'pkg') is None
    assert entry_version({'versions': {}}, 'amd64') is None
    # Multi-version: the default variant, or the one the label names.
    assert entry_version(POSTGRES, 'amd64') == '18.7'
    assert entry_version(POSTGRES, 'amd64', 'pkg') == '18.6'
    assert entry_version(POSTGRES, 'amd64', '14') == '14.24'
    assert entry_version(POSTGRES, 'amd64', '18-pkg-latest') == '18.7'
    assert entry_version(POSTGRES, 'amd64', '14-pkg') == '14.24'
    assert entry_version(POSTGRES, 'amd64', '16-pkg') is None
    assert entry_version(HAPROXY, 'amd64', '3.0-lua-pkg-latest') == '3.0.24_1'
    assert entry_version(entry('base-demo'), 'x86_64') == '18.6'


def test_image_labels_are_the_only_statement_of_what_a_tag_contains():
    labels = {'org.opencontainers.image.version': '1.37.3', 'io.daemonless.variant': 'latest'}
    assert image_version(labels) == ('1.37.3', 'latest')
    assert image_version({'org.opencontainers.image.version': '0.163.3_3,1'}) == ('0.163.3_3,1', None)
    assert image_version({'org.opencontainers.image.version': 'v2.3.0', 'io.daemonless.variant': '14-pkg'}) \
        == ('v2.3.0', '14-pkg')
    assert image_version({'org.opencontainers.image.version': 'not a version'}) == (None, None)
    assert image_version({'org.opencontainers.image.version': 7, 'io.daemonless.variant': ['pkg']}) == (None, None)
    assert image_version(None) == (None, None)
    assert image_tag('ghcr.io/daemonless/vaultwarden:latest') == 'latest'
    assert image_tag('ghcr.io/daemonless/postgres:18') == '18'
    assert image_tag('ghcr.io/daemonless/demo') == 'latest'
    # homepage: label ``2.3.0``, index upstream ``v2.3.0``.
    assert version_key('v2.3.0') == version_key('2.3.0') == '2.3.0'
    assert version_key('vaultwarden') == 'vaultwarden'
    assert version_key(None) is None


def test_installed_provenance_is_what_was_pulled():
    reviewed = {
        'id': 'daemonless:vaultwarden', 'version': '1.36.0_1', 'variant': 'latest',
        'compose_sha256': 'a' * 64, 'repository': 'https://github.com/daemonless/vaultwarden',
        'image_tag': 'ghcr.io/daemonless/vaultwarden:latest',
    }
    pulled = {'id': 'sha256:' + '1' * 64, 'digest': 'sha256:' + '2' * 64, 'os': 'freebsd', 'labels': {
        'org.opencontainers.image.version': '1.37.3', 'io.daemonless.variant': 'latest',
    }}
    assert installed_catalog_provenance(reviewed, pulled) == {**reviewed, 'version': '1.37.3'}
    # navidrome: the compose pins ``latest`` and the image says it is the quarterly package.
    navidrome = {**reviewed, 'id': 'daemonless:navidrome', 'version': '0.63.2_3'}
    assert installed_catalog_provenance(navidrome, {'labels': {
        'org.opencontainers.image.version': '0.62.0_3', 'io.daemonless.variant': 'pkg',
    }}) == {**navidrome, 'version': '0.62.0_3', 'variant': 'pkg'}
    # An image without labels keeps the reviewed answer; legacy shapes and BYO
    # installs pass through untouched.
    unlabeled = {k: v for k, v in reviewed.items() if k != 'variant'}
    assert installed_catalog_provenance(unlabeled, {'labels': {}}) == {**reviewed, 'variant': None}
    assert installed_catalog_provenance(reviewed, {}) == reviewed
    legacy = {'id': 'daemonless:demo', 'version': '1.2.3', 'compose_sha256': 'a' * 64,
              'repository': 'https://github.com/daemonless/demo', 'object_sha256': 'b' * 64,
              'entry_revision': 3, 'snapshot_sequence': 3, 'source_commit': 'c' * 40}
    assert installed_catalog_provenance(legacy, pulled) == legacy
    assert installed_catalog_provenance(None, pulled) is None


def test_safe_contract_normalizes_review_and_install_without_provider_host_paths():
    contract = normalize_daemonless_contract(entry(), (FIXTURES / 'compose.yaml').read_text())
    result = finalize_daemonless_contract(contract, image_info())

    assert result['available'] is True
    assert result['image']['immutable_reference'] == f'ghcr.io/daemonless/demo@sha256:{"a" * 64}'
    assert result['portal'] == {'scheme': 'http', 'port': 18080, 'path': '/health'}
    assert all(volume['dataset'] is None for volume in result['install']['volumes'])
    assert '/provider/host' not in repr(result)


def test_tag_contract_follows_the_tag_and_only_uses_a_resolution_for_display():
    contract = normalize_daemonless_contract(entry(), (FIXTURES / 'compose.yaml').read_text())
    unresolved = finalize_tag_contract(copy.deepcopy(contract))
    assert unresolved['available'] is True
    assert unresolved['install']['image'] == 'ghcr.io/daemonless/demo:latest'
    assert unresolved['image'] == {
        'reference': 'ghcr.io/daemonless/demo:latest', 'immutable_reference': None, 'digest': None,
        'os': 'freebsd', 'architecture': 'amd64',
    }

    resolved = finalize_tag_contract(copy.deepcopy(contract), image_info())
    assert resolved['install']['image'] == 'ghcr.io/daemonless/demo:latest'
    assert resolved['image']['digest'] == 'sha256:' + 'a' * 64
    assert resolved['image']['immutable_reference'] == f'ghcr.io/daemonless/demo@sha256:{"a" * 64}'

    wrong_os = finalize_tag_contract(copy.deepcopy(contract), image_info(os='linux'))
    assert wrong_os['available'] is False and 'linux' in wrong_os['reason']
    wrong_arch = finalize_tag_contract(copy.deepcopy(contract), image_info(architecture='aarch64'))
    assert wrong_arch['available'] is False and 'aarch64' in wrong_arch['reason']


def test_multi_service_and_executable_compose_fields_are_unavailable():
    with pytest.raises(CatalogContractError, match='Exactly one service'):
        normalize_daemonless_contract(
            entry(), (FIXTURES / 'compose_multi_service.yaml').read_text()
        )

    unsafe = (FIXTURES / 'compose.yaml').read_text().replace(
        '    container_name: demo\n', '    container_name: demo\n    command: ["sh", "-c", "id"]\n'
    )
    with pytest.raises(CatalogContractError, match='command'):
        normalize_daemonless_contract(entry(), unsafe)


def with_named_volume(declaration):
    """The fixture with MariaDB's shape: a named volume used by the service and declared at the top."""
    return (FIXTURES / 'compose.yaml').read_text().replace(
        '      - /provider/host/config:/config\n', '      - demo-config:/config\n',
    ) + f'\nvolumes:\n  demo-config:{declaration}\n'


@pytest.mark.parametrize('declaration', ['', ' {}'])
def test_a_plain_named_volume_declaration_is_accepted_and_owned_like_any_other(declaration):
    # the internal development record: daemonless/mariadb declares `volumes: {mariadb-config: }`.
    plain = normalize_daemonless_contract(entry(), (FIXTURES / 'compose.yaml').read_text())
    named = normalize_daemonless_contract(entry(), with_named_volume(declaration))
    assert named['volumes'] == plain['volumes']
    assert {volume['storage'] for volume in named['volumes']} == {'MIDDLEWARE_MANAGED_DATASET'}


@pytest.mark.parametrize('declaration,message', [
    ('\n    driver: local', 'sets options'),
    ('\n    external: true', 'sets options'),
    ('\n    driver_opts:\n      type: nfs', 'sets options'),
    ('\n    name: shared', 'sets options'),
])
def test_a_named_volume_that_asks_for_storage_options_is_still_refused(declaration, message):
    with pytest.raises(CatalogContractError, match=message):
        normalize_daemonless_contract(entry(), with_named_volume(declaration))


def test_declared_health_must_use_a_reviewed_published_tcp_port():
    compose = (FIXTURES / 'compose.yaml').read_text().replace(
        '    port: 8080\n', '    port: 9999\n'
    )

    with pytest.raises(CatalogContractError, match='must be published'):
        normalize_daemonless_contract(entry(), compose)


def test_network_owned_jail_privileges_are_rejected():
    unsafe = (FIXTURES / 'compose.yaml').read_text().replace(
        '      org.freebsd.jail.allow.mlock: "true"',
        '      org.freebsd.jail.vnet: "new"',
    )
    with pytest.raises(CatalogContractError):
        normalize_daemonless_contract(entry(), unsafe)


def test_yaml_aliases_duplicate_keys_and_oversized_documents_are_rejected():
    with pytest.raises(CatalogContractError, match='aliases'):
        parse_catalog_yaml('a: &x 1\nb: *x\n')
    with pytest.raises(CatalogContractError, match='Duplicate'):
        parse_catalog_yaml('a: 1\na: 2\n')
    with pytest.raises(CatalogContractError, match='maximum supported size'):
        parse_catalog_yaml('a: ' + 'x' * (1024 * 1024 + 1))


# -- cache and seed -------------------------------------------------------------

def test_cache_round_trip_and_seed_fallback(tmp_path):
    cache_path = tmp_path / 'cache.json'
    seed_path = tmp_path / 'seed.json'
    assert read_cache(str(cache_path), str(seed_path)) == empty_cache()

    seed = live_cache()
    seed['source'] = 'seed'
    write_cache(seed, str(seed_path))
    loaded = read_cache(str(cache_path), str(seed_path))
    assert loaded['source'] == 'seed' and loaded['index'] is not None
    assert is_stale(loaded) is True

    live = live_cache()
    write_cache(live, str(cache_path))
    loaded = read_cache(str(cache_path), str(seed_path))
    assert loaded['source'] == 'live' and loaded['composes']['demo']['sha256'] == sha256_hex(
        (FIXTURES / 'compose.yaml').read_text()
    )
    assert is_stale(loaded, now=1_800_000_000 + 3600) is False
    assert is_stale(loaded, now=1_800_000_000 + 2 * 86400) is True
    assert repositories_due(loaded, now=1_800_000_000 + 60) is False
    assert repositories_due(loaded, now=1_800_000_000 + 7 * 3600) is True

    # A cache from the retired signed client is superseded, not fatal.
    cache_path.write_text(json.dumps({'schema': 2, 'snapshot': {}, 'signature': {}}))
    assert read_cache(str(cache_path), str(seed_path))['source'] == 'seed'
    cache_path.write_text('{corrupt')
    assert read_cache(str(cache_path), str(seed_path))['source'] == 'seed'


def test_cache_structure_and_compose_hashes_are_validated():
    cache = live_cache()
    validate_cache(cache)
    broken = copy.deepcopy(cache)
    broken['composes']['demo']['sha256'] = 'f' * 64
    with pytest.raises(CatalogContractError, match='compose cache'):
        validate_cache(broken)
    broken = copy.deepcopy(cache)
    broken['schema'] = CACHE_SCHEMA + 1
    with pytest.raises(CatalogContractError, match='structure'):
        validate_cache(broken)
    broken = copy.deepcopy(cache)
    broken['extra'] = 1
    with pytest.raises(CatalogContractError, match='structure'):
        validate_cache(broken)


# -- provider client -----------------------------------------------------------

class FakeContent:

    def __init__(self, chunks):
        self.chunks = chunks

    async def iter_chunked(self, size):
        assert size > 0
        for chunk in self.chunks:
            yield chunk


class FakeResponse:

    def __init__(self, chunks, status=200, headers=None):
        self.status = status
        self.headers = headers or {}
        self.content = FakeContent(chunks)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


class FakeSession:

    def __init__(self, response, **kwargs):
        self.response = response
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    def get(self, url, **kwargs):
        self.url = url
        return self.response


@pytest.mark.asyncio
async def test_provider_reader_consumes_every_bounded_http_chunk():
    response = FakeResponse([b'{"schema_version"', b': 2, "arches": ["amd64"], "services": {}}'])
    with patch('middlewared.plugins.applications_.provider.aiohttp.ClientSession',
               lambda **kwargs: FakeSession(response, **kwargs)):
        index = await ProviderClient().fetch_index()
    assert index == {'schema_version': 2, 'arches': ['amd64'], 'services': {}}

    oversized = FakeResponse([b'x' * (1024 * 1024 + 1)])
    with patch('middlewared.plugins.applications_.provider.aiohttp.ClientSession',
               lambda **kwargs: FakeSession(oversized, **kwargs)):
        with pytest.raises(CatalogContractError, match='maximum supported size'):
            await ProviderClient().fetch_index()


@pytest.mark.asyncio
async def test_provider_rate_limit_is_reported_as_such():
    response = FakeResponse([b''], status=403, headers={'x-ratelimit-remaining': '0'})
    with patch('middlewared.plugins.applications_.provider.aiohttp.ClientSession',
               lambda **kwargs: FakeSession(response, **kwargs)):
        with pytest.raises(CallError, match='rate limit'):
            await ProviderClient().fetch_repositories()


@pytest.mark.parametrize('url', [
    'http://raw.githubusercontent.com/daemonless/demo/main/compose.yaml',
    'https://example.org/daemonless-versions.json',
    'https://user:pw@raw.githubusercontent.com/x',
    'https://raw.githubusercontent.com:8443/x',
])
def test_provider_reader_rejects_noncanonical_origins(url):
    with pytest.raises(CatalogContractError, match='HTTPS identity'):
        ProviderClient.check_url(url)


def test_provider_urls_are_the_documented_ones():
    assert PROVIDER_INDEX_URL == (
        'https://raw.githubusercontent.com/daemonless/daemonless/main/daemonless-versions.json'
    )


# -- service ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_query_lists_entries_from_the_cache_with_version_and_staleness():
    service, _ = service_with_middleware()
    with patch('middlewared.plugins.applications_catalog_freebsd.is_stale', return_value=False):
        result = await ApplicationsCatalogService.query.wraps(service)
    by_name = {item['name']: item for item in result}
    assert by_name['demo']['catalog'] == {'version': 'v1.2.4', 'version_source': 'index', 'source': 'live'}
    assert by_name['demo']['provenance']['sbom_url'] == 'https://github.com/daemonless/demo/blob/main/sbom.json'
    assert by_name['demo']['catalog_stale'] is False
    assert by_name['demo']['catalog_source'] == 'live'
    assert by_name['base-demo']['status'] == 'UNAVAILABLE'


@pytest.mark.asyncio
async def test_details_reviews_the_cached_contract_and_fetches_lazily():
    service, _ = service_with_middleware(live_cache(with_compose=False))
    client = Mock()
    client.fetch_compose = AsyncMock(return_value=(FIXTURES / 'compose.yaml').read_text())
    service._client = Mock(return_value=client)

    detail = await service.details('daemonless:demo', {'refresh': False})

    client.fetch_compose.assert_awaited_once_with('demo')
    assert detail['available'] is True
    assert detail['install']['image'] == 'ghcr.io/daemonless/demo:latest'
    assert detail['catalog']['compose_sha256'] == sha256_hex((FIXTURES / 'compose.yaml').read_text())
    # No registry answer in this test: the index's answer for the pinned tag, said so.
    assert detail['catalog']['version'] == 'v1.2.4'
    assert detail['catalog']['variant'] == 'latest'
    assert detail['catalog']['version_source'] == 'index'
    assert detail['provenance']['repository'] == 'https://github.com/daemonless/demo'
    assert detail['provenance']['upstream_url'] == 'https://github.com/example/demo'
    service._save_cache.assert_called_once()
    assert 'demo' in service._catalog_cache['composes']

    # Cached now: no second fetch.
    client.fetch_compose.reset_mock()
    await service.details('daemonless:demo', {'refresh': False})
    client.fetch_compose.assert_not_awaited()

    with pytest.raises(CallError, match='does not exist'):
        await service.details('daemonless:missing', {'refresh': False})


@pytest.mark.asyncio
async def test_refresh_replaces_the_index_and_keeps_repositories_on_api_failure():
    cache = live_cache()
    cache['repositories_fetched_at'] = 0
    service, _ = service_with_middleware(cache)
    index, _ = fixtures()
    client = Mock()
    client.fetch_index = AsyncMock(return_value=index)
    client.fetch_repositories = AsyncMock(side_effect=CallError('rate limit'))
    # the internal development record: the fjord catalog is optional too.
    client.fetch_fjord_catalog = AsyncMock(side_effect=CallError('offline'))
    service._client = Mock(return_value=client)

    result = await service.refresh()

    assert {item['name'] for item in result} == {'base-demo', 'demo', 'x86-demo'}
    assert service._catalog_cache['source'] == 'live'
    assert service._catalog_cache['repositories'] == cache['repositories']
    assert service._catalog_cache['composes'] == cache['composes']


@pytest.mark.asyncio
async def test_refresh_failure_keeps_the_last_known_good_catalog():
    cache = live_cache()
    service, _ = service_with_middleware(cache)
    client = Mock()
    client.fetch_index = AsyncMock(side_effect=CallError('offline'))
    service._client = Mock(return_value=client)

    with pytest.raises(CallError, match='catalog update failed: .*offline'):
        await service.refresh()
    assert service._catalog_cache is cache


@pytest.mark.asyncio
async def test_install_binds_the_reviewed_contract_without_a_network_round_trip():
    service, middleware = service_with_middleware()
    client = Mock()
    client.fetch_compose = AsyncMock(side_effect=AssertionError('no network at install time'))
    service._client = Mock(return_value=client)
    detail = await service.details('daemonless:demo', {'refresh': False})
    middleware.call.return_value = 'subjob'
    job = Mock()
    job.wrap = AsyncMock(return_value={'name': 'demo'})

    result = await ApplicationsCatalogService.install.wraps(service, job, {
        'id': 'daemonless:demo',
        'compose_sha256': detail['catalog']['compose_sha256'],
        'name': 'demo',
        'ports': [
            {'host_port': 28080, 'container_port': 8080, 'protocol': 'tcp'},
            {'host_port': 28443, 'container_port': 8443, 'protocol': 'tcp'},
        ],
        'environment': [{'name': 'MODE', 'value': 'production'}, {'name': 'API_TOKEN', 'value': 'x'}],
        'volumes': [{'name': 'config', 'dataset': None}, {'name': 'media', 'dataset': 'tank/media'}],
        'restart_policy': 'always',
        'health_timeout': 30,
    })

    assert result == {'name': 'demo'}
    method, install, provenance = middleware.call.await_args.args
    assert method == 'applications.install_catalog'
    assert install['image'] == 'ghcr.io/daemonless/demo:latest'
    assert install['ports'][0]['host_port'] == 28080 and install['portal']['port'] == 28080
    assert install['healthcheck']['host_port'] == 28080
    assert [volume['dataset'] for volume in install['volumes']] == [None, 'tank/media']
    assert provenance == {
        'id': 'daemonless:demo', 'version': 'v1.2.4', 'variant': 'latest',
        'compose_sha256': detail['catalog']['compose_sha256'],
        'repository': 'https://github.com/daemonless/demo',
        'image_tag': 'ghcr.io/daemonless/demo:latest',
    }

    with pytest.raises(CallError, match='review it again'):
        await ApplicationsCatalogService.install.wraps(service, job, {
            'id': 'daemonless:demo', 'compose_sha256': 'e' * 64, 'name': 'demo',
            'ports': [], 'environment': [], 'volumes': [], 'restart_policy': 'always', 'health_timeout': 30,
        })


@pytest.mark.asyncio
async def test_a_refused_install_returns_the_inner_field_errors_not_a_traceback():
    """the internal development record: job.wrap turns the inner job's failure into a
    CallError carrying its traceback; install hands on a validation refusal as
    the ValidationErrors it was, and leaves any other failure as it was."""
    from middlewared.job import Job
    from middlewared.service_exception import ValidationErrors

    service, middleware = service_with_middleware()
    service._client = Mock(return_value=Mock(fetch_compose=AsyncMock(side_effect=AssertionError)))
    detail = await service.details('daemonless:demo', {'refresh': False})
    request = {
        'id': 'daemonless:demo', 'compose_sha256': detail['catalog']['compose_sha256'], 'name': 'demo',
        'ports': [
            {'host_port': 28080, 'container_port': 8080, 'protocol': 'tcp'},
            {'host_port': 28443, 'container_port': 8443, 'protocol': 'tcp'},
        ],
        'environment': [{'name': 'MODE', 'value': 'production'}, {'name': 'API_TOKEN', 'value': 'x'}],
        'volumes': [{'name': 'config', 'dataset': None}, {'name': 'media', 'dataset': 'tank/media'}],
        'restart_policy': 'always', 'health_timeout': 30,
    }
    refusal = ValidationErrors()
    refusal.add('application_install.ports.0.host_port', 'Host port is already assigned to a managed application.')
    subjob = Mock(time_finished=1, progress={}, result=None,
                  exception='Traceback (most recent call last):\n...\nValidationErrors: ...',
                  exc_info=(ValidationErrors, refusal, None))
    middleware.call.return_value = subjob
    outer = Mock()
    outer.wrap = lambda inner: Job.wrap(outer, inner)    # the real wrap

    with pytest.raises(ValidationErrors) as raised:
        await ApplicationsCatalogService.install.wraps(service, outer, request)
    assert raised.value is refusal
    assert str(raised.value).startswith('[EINVAL] application_install.ports.0.host_port:')
    assert 'Traceback' not in str(raised.value)

    crash = RuntimeError('podman exploded')
    subjob.exc_info = (RuntimeError, crash, None)
    with pytest.raises(CallError, match='Traceback'):
        await ApplicationsCatalogService.install.wraps(service, outer, request)


@pytest.mark.asyncio
async def test_install_requires_a_reviewed_entry_on_this_system():
    service, middleware = service_with_middleware(live_cache(with_compose=False))
    service._client = Mock(return_value=Mock(fetch_compose=AsyncMock(side_effect=AssertionError)))
    with pytest.raises(CallError, match='review it before installing'):
        await ApplicationsCatalogService.install.wraps(service, Mock(), {
            'id': 'daemonless:demo', 'compose_sha256': 'e' * 64, 'name': 'demo',
            'ports': [], 'environment': [], 'volumes': [], 'restart_policy': 'always', 'health_timeout': 30,
        })


def _labelled_detail_and_request():
    contract = normalize_daemonless_contract(entry(), (FIXTURES / 'compose.yaml').read_text())
    detail = finalize_tag_contract(contract)
    detail['catalog'] = {'version': '1.2.3', 'compose_sha256': 'a' * 64}
    detail['provenance'] = {'repository': 'https://github.com/daemonless/demo'}
    # the provider's own labels, as the contract's install block carries them
    detail['install']['labels'] = [{'name': 'provider.tier', 'value': 'web'}]
    request = {
        'id': 'daemonless:demo', 'compose_sha256': 'a' * 64, 'name': 'demo',
        'ports': [
            {'host_port': 1, 'container_port': 8080, 'protocol': 'tcp'},
            {'host_port': 2, 'container_port': 8443, 'protocol': 'tcp'},
        ],
        'environment': [{'name': 'MODE', 'value': 'x'}, {'name': 'API_TOKEN', 'value': 'y'}],
        'volumes': [{'name': 'config', 'dataset': None}, {'name': 'media', 'dataset': None}],
        'restart_policy': 'no', 'health_timeout': 5,
    }
    return detail, request


def test_catalog_install_labels_are_the_operators_once_stated():
    """the internal development record: the form prefills the provider's labels and the operator owns
    the list from there -- so a list is authoritative, the EMPTY one included. Only a request
    that does not state labels at all falls back to the provider's set."""
    detail, request = _labelled_detail_and_request()
    provider = [{'name': 'provider.tier', 'value': 'web'}]

    install, _ = bind_catalog_install(detail, request)
    assert install['labels'] == provider
    install, _ = bind_catalog_install(detail, {**request, 'labels': None})
    assert install['labels'] == provider

    # the operator removed the prefilled label: it must stay removed
    install, _ = bind_catalog_install(detail, {**request, 'labels': []})
    assert install['labels'] == []

    mine = [{'name': 'traefik.enable', 'value': 'true'}]
    install, _ = bind_catalog_install(detail, {**request, 'labels': mine})
    assert install['labels'] == mine


def test_catalog_install_schema_tells_unstated_labels_from_an_empty_list():
    from middlewared.plugins.applications_catalog_freebsd import CATALOG_INSTALL_SCHEMA
    _, request = _labelled_detail_and_request()
    for payload, expected in (
        (request, None),
        ({**request, 'labels': None}, None),
        ({**request, 'labels': []}, []),
        ({**request, 'labels': [{'name': 'a', 'value': 'b'}]}, [{'name': 'a', 'value': 'b'}]),
    ):
        value = CATALOG_INSTALL_SCHEMA.clean(copy.deepcopy(payload))
        CATALOG_INSTALL_SCHEMA.validate(value)
        assert value['labels'] == expected


def test_bind_functions_compare_the_reviewed_contract_hash():
    contract = normalize_daemonless_contract(entry(), (FIXTURES / 'compose.yaml').read_text())
    detail = finalize_tag_contract(contract)
    detail['catalog'] = {'version': '1.2.3', 'compose_sha256': 'a' * 64}
    detail['provenance'] = {'repository': 'https://github.com/daemonless/demo'}
    request = {
        'id': 'daemonless:demo', 'compose_sha256': 'a' * 64, 'name': 'demo',
        'ports': [
            {'host_port': 1, 'container_port': 8080, 'protocol': 'tcp'},
            {'host_port': 2, 'container_port': 8443, 'protocol': 'tcp'},
        ],
        'environment': [{'name': 'MODE', 'value': 'x'}, {'name': 'API_TOKEN', 'value': 'y'}],
        'volumes': [{'name': 'config', 'dataset': None}, {'name': 'media', 'dataset': None}],
        'restart_policy': 'no', 'health_timeout': 5,
    }
    install, provenance = bind_catalog_install(detail, request)
    assert install['restart_policy'] == 'no' and provenance['version'] == '1.2.3'
    with pytest.raises(CatalogContractError, match='changed'):
        bind_catalog_install(detail, {**request, 'compose_sha256': 'b' * 64})
    with pytest.raises(CatalogContractError, match='port identity'):
        bind_catalog_install(detail, {**request, 'ports': [
            {'host_port': 1, 'container_port': 9999, 'protocol': 'tcp'},
            {'host_port': 2, 'container_port': 8443, 'protocol': 'tcp'},
        ]})

    record = {
        'name': 'demo', 'restart_policy': 'always',
        'ports': install['ports'], 'environment': install['environment'], 'volumes': [
            {**volume, 'source': f'/mnt/tank/{volume["name"]}', 'owned': True} for volume in install['volumes']
        ],
        'catalog': {**provenance, 'version': '1.0.0'},
    }
    replacement, new_provenance, changed = bind_catalog_update(detail, record, request)
    assert changed is True and new_provenance['version'] == '1.2.3'
    assert replacement['image'] == 'ghcr.io/daemonless/demo:latest'
    assert replacement['ports'][0]['host_port'] == 1
    record['catalog']['version'] = '1.2.3'
    assert bind_catalog_update(detail, record, request)[2] is False
    record['environment'] = []
    with pytest.raises(CatalogContractError, match='incompatible'):
        bind_catalog_update(detail, record, request)


def test_installed_state_answers_new_and_legacy_records_the_same_way():
    _, entries = catalog_entries(live_cache(), 'amd64')
    new = {'id': 'daemonless:demo', 'version': '1.0.0', 'compose_sha256': 'a' * 64,
           'repository': 'https://github.com/daemonless/demo', 'image_tag': 'ghcr.io/daemonless/demo:latest'}
    legacy = {'id': 'daemonless:demo', 'version': '1.2.4', 'compose_sha256': 'a' * 64,
              'repository': 'https://github.com/daemonless/demo', 'object_sha256': 'b' * 64,
              'entry_revision': 3, 'snapshot_sequence': 3, 'source_commit': 'c' * 40}
    assert catalog_install_state(entries, new, 'amd64')['update_available'] is True
    # A snapshot-era record followed ``latest``; the leading v is the index's, not the image's.
    assert catalog_install_state(entries, legacy, 'amd64')['update_available'] is False
    absent = catalog_install_state(entries, {**new, 'id': 'daemonless:gone'}, 'amd64')
    assert absent['catalog_error'] and absent['update_available'] is False
    assert catalog_install_state({}, new, 'amd64')['catalog_error']
    assert catalog_install_state(entries, None, 'amd64') == {
        'update_available': False, 'revoked': False, 'revocation_reason': None, 'catalog_error': None,
    }
    with pytest.raises(CatalogContractError):
        catalog_install_state(entries, {'id': 'bogus'}, 'amd64')


def test_installed_state_compares_the_flavour_the_image_was_built_as():
    # the internal development record: crpb's vaultwarden.  The index moved quarterly
    # to 1.36.0_1 while the ``latest`` image is the upstream 1.37.x build.
    index, repositories = fixtures()
    index['services']['vaultwarden'] = copy.deepcopy(VAULTWARDEN['versions'])
    index['services']['navidrome'] = {
        'pkg': {'amd64': '0.62.0_3'}, 'pkg-latest': {'amd64': '0.63.2_3'},
    }
    cache = live_cache()
    cache['index'] = index
    _, entries = catalog_entries(cache, 'amd64')
    record = {
        'id': 'daemonless:vaultwarden', 'compose_sha256': 'a' * 64,
        'repository': 'https://github.com/daemonless/vaultwarden',
        'image_tag': 'ghcr.io/daemonless/vaultwarden:latest',
    }
    # What RC2 wrote after crpb's update: the quarterly number for an upstream image.
    rc2 = {**record, 'version': '1.36.0_1'}
    assert catalog_install_state(entries, rc2, 'amd64')['update_available'] is True
    # What the fixed install records: the pulled image's own labels.
    current = {**record, 'version': '1.37.3', 'variant': 'latest'}
    assert catalog_install_state(entries, current, 'amd64')['update_available'] is False
    older = {**record, 'version': '1.37.2', 'variant': 'latest'}
    assert catalog_install_state(entries, older, 'amd64')['update_available'] is True
    # An image built as the quarterly package is compared with the quarterly field.
    quarterly = {**record, 'version': '1.36.0_1', 'variant': 'pkg'}
    assert catalog_install_state(entries, quarterly, 'amd64')['update_available'] is False
    # navidrome pins ``latest`` and its ``latest`` is the quarterly build.
    navidrome = {
        **record, 'id': 'daemonless:navidrome', 'repository': 'https://github.com/daemonless/navidrome',
        'image_tag': 'ghcr.io/daemonless/navidrome:latest', 'version': '0.62.0_3', 'variant': 'pkg',
    }
    assert catalog_install_state(entries, navidrome, 'amd64')['update_available'] is False
    # A flavour the index does not track makes no claim.
    unknown = {**record, 'version': '1.37.3', 'variant': 'lts'}
    assert catalog_install_state(entries, unknown, 'amd64')['update_available'] is False
    # What the running image says outranks the record on both counts: the RC2
    # record above is current once its image reports 1.37.3, and navidrome's
    # ``latest`` reports itself as the quarterly build.
    assert catalog_install_state(entries, rc2, 'amd64', ('1.37.3', 'latest'))['update_available'] is False
    assert catalog_install_state(entries, rc2, 'amd64', ('1.37.2', 'latest'))['update_available'] is True
    legacy_navidrome = {k: v for k, v in navidrome.items() if k != 'variant'}
    assert catalog_install_state(entries, legacy_navidrome, 'amd64')['update_available'] is True
    assert catalog_install_state(entries, legacy_navidrome, 'amd64', ('0.62.0_3', 'pkg'))['update_available'] is False
    assert catalog_install_state(entries, legacy_navidrome, 'amd64', ('0.62.0_3', None))['update_available'] is True


def test_catalog_provenance_records_what_an_update_needs():
    detail = {
        'id': 'daemonless:demo',
        'catalog': {'version': '1.2.3', 'variant': 'latest', 'compose_sha256': 'a' * 64},
        'provenance': {'repository': 'https://github.com/daemonless/demo'},
        'image': {'reference': 'ghcr.io/daemonless/demo:latest'},
    }
    assert set(catalog_provenance(detail)) == {
        'id', 'version', 'variant', 'compose_sha256', 'repository', 'image_tag',
    }


# -- the internal development record / #456: what the review says when the provider is short ----

@pytest.mark.asyncio
async def test_a_tag_the_registry_does_not_publish_makes_the_entry_unavailable_before_the_form():
    service, _ = service_with_middleware()
    service._resolve_image = AsyncMock(return_value=(None, True))

    detail = await service.details('daemonless:demo', {'refresh': False})

    assert detail['status'] == 'UNAVAILABLE'
    assert detail['available'] is False
    assert "pins image tag 'latest'" in detail['reason']
    assert 'ghcr.io/daemonless/demo:latest' in detail['reason']
    assert detail['install'] is None


@pytest.mark.asyncio
async def test_an_unreachable_registry_keeps_the_entry_available_without_a_digest():
    service, _ = service_with_middleware()
    service._resolve_image = AsyncMock(return_value=(None, False))

    detail = await service.details('daemonless:demo', {'refresh': False})

    assert detail['status'] == 'AVAILABLE'
    assert detail['image']['digest'] is None
    assert detail['install']['image'] == 'ghcr.io/daemonless/demo:latest'
    assert detail['catalog']['version_source'] == 'index'


@pytest.mark.asyncio
async def test_the_review_shows_the_version_the_tag_resolves_to():
    # the internal development record: the registry answered; the image's labels win over
    # the index (demo's index says pkg 1.2.3 / upstream v1.2.4).
    service, _ = service_with_middleware()
    service._resolve_image = AsyncMock(return_value=(image_info(labels={
        'org.opencontainers.image.version': '1.2.4', 'io.daemonless.variant': 'latest',
    }), False))

    detail = await service.details('daemonless:demo', {'refresh': False})

    assert detail['status'] == 'AVAILABLE'
    assert detail['image']['digest'] == 'sha256:' + 'a' * 64
    assert detail['catalog']['version'] == '1.2.4'
    assert detail['catalog']['variant'] == 'latest'
    assert detail['catalog']['version_source'] == 'image'

    # A resolution without labels falls back to the index for the pinned tag.
    service._resolve_image = AsyncMock(return_value=(image_info(), False))
    detail = await service.details('daemonless:demo', {'refresh': False})
    assert detail['catalog'] == {
        **detail['catalog'], 'version': 'v1.2.4', 'variant': 'latest', 'version_source': 'index',
    }


@pytest.mark.asyncio
async def test_update_decides_changed_against_the_registry_not_the_index():
    service, middleware = service_with_middleware()
    detail = await service.details('daemonless:demo', {'refresh': False})
    installed = {
        'name': 'demo', 'restart_policy': 'always',
        'ports': detail['install']['ports'], 'environment': detail['install']['environment'],
        'volumes': detail['install']['volumes'],
        'catalog': {
            'id': 'daemonless:demo', 'version': '1.2.4', 'variant': 'latest',
            'compose_sha256': detail['catalog']['compose_sha256'],
            'repository': 'https://github.com/daemonless/demo',
            'image_tag': 'ghcr.io/daemonless/demo:latest',
        },
    }
    request = {
        'id': 'daemonless:demo', 'compose_sha256': detail['catalog']['compose_sha256'],
        'name': 'demo', 'recreate': False, 'health_timeout': 30,
    }
    job = Mock()
    job.wrap = AsyncMock(return_value={'name': 'demo'})

    # The registry still serves the installed version: nothing to do, no pull.
    service._resolve_image = AsyncMock(return_value=(image_info(labels={
        'org.opencontainers.image.version': '1.2.4', 'io.daemonless.variant': 'latest',
    }), False))
    middleware.call.side_effect = [copy.deepcopy(installed), {'name': 'demo', 'status': 'RUNNING'}]
    assert await ApplicationsCatalogService.update.wraps(service, job, request) == {
        'name': 'demo', 'status': 'RUNNING',
    }
    service._resolve_image.assert_awaited_once_with('ghcr.io/daemonless/demo:latest')
    assert [invocation.args[0] for invocation in middleware.call.await_args_list] == [
        'applications.catalog_record', 'applications.query',
    ]

    # The tag moved on: the replacement carries what the registry said.
    service._resolve_image = AsyncMock(return_value=(image_info(labels={
        'org.opencontainers.image.version': '1.2.5', 'io.daemonless.variant': 'latest',
    }), False))
    middleware.call.reset_mock()
    middleware.call.side_effect = [copy.deepcopy(installed), 'subjob']
    await ApplicationsCatalogService.update.wraps(service, job, request)
    method, _, replacement, provenance, _ = middleware.call.await_args.args
    assert method == 'applications.update_catalog'
    assert replacement['image'] == 'ghcr.io/daemonless/demo:latest'
    assert provenance['version'] == '1.2.5' and provenance['variant'] == 'latest'


@pytest.mark.asyncio
async def test_resolve_image_turns_the_registry_verdict_into_a_missing_flag():
    service, _ = service_with_middleware()
    service._resolve_image = ApplicationsCatalogService._resolve_image.__get__(service)
    with patch(
        'middlewared.plugins.applications_catalog_freebsd.probe_remote_image',
        AsyncMock(return_value=(None, 'missing')),
    ):
        assert await service._resolve_image('ghcr.io/daemonless/demo:latest') == (None, True)
    with patch(
        'middlewared.plugins.applications_catalog_freebsd.probe_remote_image',
        AsyncMock(return_value=(None, 'unknown')),
    ):
        assert await service._resolve_image('ghcr.io/daemonless/demo:latest') == (None, False)
    with patch(
        'middlewared.plugins.applications_catalog_freebsd.probe_remote_image',
        AsyncMock(side_effect=OSError('skopeo exploded')),
    ):
        assert await service._resolve_image('ghcr.io/daemonless/demo:latest') == (None, False)


@pytest.mark.asyncio
async def test_a_provider_404_on_one_compose_is_that_entrys_condition_not_the_catalogs():
    service, _ = service_with_middleware(live_cache(with_compose=False))
    client = Mock()
    client.fetch_compose = AsyncMock(
        side_effect=ProviderNotFound('https://raw.githubusercontent.com/daemonless/demo/main/compose.yaml'),
    )
    service._client = Mock(return_value=client)

    detail = await service.details('daemonless:demo', {'refresh': False})

    assert detail['status'] == 'UNAVAILABLE'
    assert detail['reason'] == 'The provider publishes no compose contract for this application.'
    assert detail['name'] == 'demo'

    # Any other provider failure is still the catalog's problem, said the old way.
    client.fetch_compose = AsyncMock(side_effect=CallError('Applications provider returned HTTP status 503.'))
    with pytest.raises(CallError, match='catalog is unavailable.*503'):
        await service.details('daemonless:demo', {'refresh': False})


def test_documentation_metadata_from_newer_providers_is_ignored():
    # the internal development record: the 2026-09-29 Daemonless format added `level`
    # (and `optional`) to env documentation. Documentation metadata is
    # presentation, not execution -- an unknown doc key must never make the
    # entry unavailable, while the known keys keep their strict shapes.
    compose = (FIXTURES / 'compose.yaml').read_text().replace(
        '      API_TOKEN:\n        desc: API credential\n        default: ""\n',
        '      API_TOKEN:\n        desc: API credential\n        default: ""\n'
        '        optional: true\n        level: primary\n',
    )
    contract = normalize_daemonless_contract(entry(), compose)
    documented = {item['name']: item for item in contract['environment']}
    token = documented['API_TOKEN']
    assert token.get('description') == 'API credential'
    assert 'level' not in repr(contract)

    # A known key with the wrong shape is still refused.
    broken = (FIXTURES / 'compose.yaml').read_text().replace(
        '        default: ""\n', '        default: ""\n        optional: "yes"\n',
    )
    with pytest.raises(CatalogContractError, match='optional flag must be boolean'):
        normalize_daemonless_contract(entry(), broken)


def test_a_reviewed_port_can_stay_on_the_managed_bridge():
    """the internal development record: a catalog install may leave a reviewed port unpublished; it is
    still declared, so its identity binds as before, and the portal -- a link on the host --
    has to stay published."""
    from middlewared.plugins.applications_catalog_freebsd import CATALOG_INSTALL_SCHEMA
    detail, request = _labelled_detail_and_request()
    bridge_only = {**request, 'ports': [
        {'host_port': 1, 'container_port': 8080, 'protocol': 'tcp'},
        {'host_port': None, 'container_port': 8443, 'protocol': 'tcp'},
    ]}
    value = CATALOG_INSTALL_SCHEMA.clean(copy.deepcopy(bridge_only))
    CATALOG_INSTALL_SCHEMA.validate(value)
    install, provenance = bind_catalog_install(detail, value)
    assert install['ports'][1] == {'host_port': None, 'container_port': 8443, 'protocol': 'tcp'}
    assert install['portal']['port'] == 1 and install['healthcheck']['host_port'] == 1

    with pytest.raises(CatalogContractError, match='port identity'):
        bind_catalog_install(detail, {**request, 'ports': [
            {'host_port': 1, 'container_port': 8080, 'protocol': 'tcp'},
            {'host_port': None, 'container_port': 9999, 'protocol': 'tcp'},
        ]})
    portal_unpublished = {**request, 'ports': [
        {'host_port': None, 'container_port': 8080, 'protocol': 'tcp'},
        {'host_port': 2, 'container_port': 8443, 'protocol': 'tcp'},
    ]}
    with pytest.raises(CatalogContractError, match='8080/tcp opens the application.*must stay published'):
        bind_catalog_install(detail, portal_unpublished)

    # without a portal, the health check follows its port onto the bridge
    no_portal = copy.deepcopy(detail)
    no_portal['install']['portal'] = None
    install_without_portal, _ = bind_catalog_install(no_portal, portal_unpublished)
    assert install_without_portal['healthcheck']['host_port'] is None
    assert install_without_portal['healthcheck']['container_port'] == 8080

    # an update keeps the choice ...
    record = {
        'name': 'demo', 'restart_policy': 'always',
        'ports': install['ports'], 'environment': install['environment'], 'volumes': [
            {**volume, 'source': f'/mnt/tank/{volume["name"]}', 'owned': True} for volume in install['volumes']
        ],
        'catalog': {**provenance, 'version': '1.0.0'},
    }
    replacement, _, _ = bind_catalog_update(detail, record, request)
    assert [port['host_port'] for port in replacement['ports']] == [1, None]
    # ... and refuses a new portal on a port the administrator kept on the bridge
    record['ports'] = install_without_portal['ports']
    with pytest.raises(CatalogContractError, match='8080/tcp.*publish that port'):
        bind_catalog_update(detail, record, request)
