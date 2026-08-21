"""The Daemonless fjord catalog (the internal development record) and current review contracts (#485)."""
import asyncio
import base64
import copy
import json
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from middlewared.plugins.applications_.catalog import (
    CatalogContractError,
    apply_fjord_presentation,
    icon_data_uri,
    normalize_catalog_index,
    normalize_daemonless_contract,
    normalize_fjord_catalog,
    normalize_fjord_contract,
    render_fjord_manifest,
    repository_metadata,
)
from middlewared.plugins.applications_.provider import (
    CACHE_SCHEMA,
    FJORD_CATALOG_URL,
    ProviderClient,
    current_document,
    empty_cache,
    read_cache,
    sha256_hex,
    store_compose,
    store_document,
    store_icon,
    validate_cache,
    write_cache,
)
from middlewared.plugins.applications_catalog_freebsd import ApplicationsCatalogService
from middlewared.service_exception import CallError


FIXTURES = Path(__file__).parent / 'fixtures' / 'applications_catalog'
NOW = 1_800_000_000
SVG = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8"><rect width="8" height="8" fill="url(#g)"/></svg>'
PNG = b'\x89PNG\r\n\x1a\n' + b'\x00' * 32


def fixtures():
    index = json.loads((FIXTURES / 'index.json').read_text())
    repositories = json.loads((FIXTURES / 'repositories.json').read_text())
    return index, [repositories]


def fjord_catalog():
    return json.loads((FIXTURES / 'fjord_catalog.json').read_text())


def manifest():
    return (FIXTURES / 'fjord_manifest.yaml').read_text()


def compose():
    return (FIXTURES / 'compose.yaml').read_text()


def entry(name='demo'):
    index, repositories = fixtures()
    catalog = normalize_catalog_index(index, repositories, 'amd64')
    return next(item for item in catalog['entries'] if item['name'] == name)


def live_cache(fjord=True, composes=(), manifests=(), document_age=0):
    index, repositories = fixtures()
    cache = empty_cache()
    cache.update({
        'source': 'live', 'fetched_at': NOW, 'repositories_fetched_at': NOW,
        'index': index, 'repositories': repositories,
    })
    if fjord:
        cache.update({'fjord': fjord_catalog(), 'fjord_fetched_at': NOW})
    for name in composes:
        store_compose(cache, name, compose(), now=NOW - document_age)
    for name in manifests:
        store_document(cache, 'manifests', name, manifest(), now=NOW - document_age)
    return cache


def service_with(cache):
    middleware = Mock()
    middleware.call = AsyncMock()
    service = ApplicationsCatalogService(middleware)
    service._catalog_cache = cache
    service._save_cache = Mock(side_effect=lambda value: setattr(service, '_catalog_cache', value))
    service._architecture = Mock(return_value='amd64')
    service._resolve_image = AsyncMock(return_value=(None, False))
    return service


def client(**methods):
    result = Mock()
    for name, value in methods.items():
        setattr(result, name, value if isinstance(value, (AsyncMock, Mock)) else AsyncMock(return_value=value))
    return result


# -- rendering a manifest ------------------------------------------------------

def test_a_manifest_renders_to_the_same_contract_as_the_repository_compose():
    fjord = normalize_fjord_contract(entry(), manifest())
    repository = normalize_daemonless_contract(entry(), compose())

    for field in ('image_reference', 'annotations', 'restart_policy', 'service_name'):
        assert fjord[field] == repository[field], field
    assert [
        (item['name'], item['default'], item['required'], item['sensitive']) for item in fjord['environment']
    ] == [
        (item['name'], item['default'], item['required'], item['sensitive']) for item in repository['environment']
    ]
    assert [
        {key: item[key] for key in ('name', 'target', 'read_only', 'optional', 'description')}
        for item in fjord['volumes']
    ] == [
        {key: item[key] for key in ('name', 'target', 'read_only', 'optional', 'description')}
        for item in repository['volumes']
    ]
    assert fjord['ports'] == repository['ports']
    # Presentation comes from fjord; the compose's health check has no fjord
    # counterpart, so the portal is the manifest's declared web port.
    assert fjord['title'] == 'Demo Service Pro'
    assert fjord['health'] is None and repository['health'] is not None
    assert fjord['portal'] == {'scheme': 'http', 'port': 18080, 'path': '/'}
    assert '/provider/host' not in json.dumps(fjord)

    # Read together with the repository compose, the health check carries over.
    together = normalize_fjord_contract(entry(), manifest(), repository_metadata(compose()))
    assert together['health'] == repository['health']
    assert together['portal'] == repository['portal']
    # ... unless it does not fit the manifest's ports; then the manifest stands alone.
    misfit = compose().replace('    port: 8080\n    path: /health', '    port: 9999\n    path: /health')
    assert normalize_fjord_contract(entry(), manifest(), repository_metadata(misfit))['health'] is None


def test_references_render_defaults_and_compose_fallbacks():
    text = manifest().replace(
        '      - API_TOKEN=${API_TOKEN}\n',
        '      - API_TOKEN=${API_TOKEN}\n'
        '      - TZ=${TZ:-UTC}\n'
        '      - LANG=${LANG-C}\n'
        '      - HOST=${UNDECLARED:-localhost}\n'
        '      - URL=http://${MODE}.example:${WEB_PORT}/\n'
        '      - LITERAL=$HOME and $$\n',
    ).replace(
        '    - name: MODE\n',
        '    - name: TZ\n      type: string\n      default: ""\n'
        '    - name: LANG\n      type: string\n      default: ""\n'
        '    - name: MODE\n',
    )
    environment = {item['name']: item['default'] for item in normalize_fjord_contract(entry(), text)['environment']}
    assert environment['TZ'] == 'UTC'
    assert environment['LANG'] == ''
    assert environment['HOST'] == 'localhost'
    assert environment['URL'] == 'http://production.example:18080/'
    assert environment['LITERAL'] == '$HOME and $$'


@pytest.mark.parametrize('replacement,message', [
    (('- MODE=${MODE}', '- MODE=${NOPE}'), 'undeclared variable'),
    (('- MODE=${MODE}', '- MODE=${MODE:?required}'), 'unsupported variable reference'),
    (('- MODE=${MODE}', '- MODE=${A:-${MODE}}'), 'unsupported variable reference'),
    (('      type: string\n', '      type: color\n'), 'unsupported type'),
    (('      default: "18080"\n', '      default: "80a"\n'), 'valid default port'),
    (('      default: latest\n', '      default: "bad tag!"\n'), 'image tag variable'),
    # the internal development record: a public URL default must be an http(s) address, as fjord itself checks.
    (('      type: string\n      default: production\n', '      type: public_url\n      default: f/\n'), 'not an http'),
    (('    - name: HTTPS_PORT\n', '    - name: MODE\n'), 'valid and unique'),
    (('  version: "0.1"\n', '  version: "0.2"\n'), 'version is not supported'),
    (('    id: demo\n', '    id: other\n'), 'identity does not match'),
    (('name: demo\n', 'name: demo\nx-daemonless: {}\n'), 'must not carry x-daemonless'),
    (('      default: production\n', '      default: "${OTHER}"\n'), 'default is invalid'),
])
def test_a_manifest_the_renderer_cannot_read_is_refused(replacement, message):
    with pytest.raises(CatalogContractError, match=message):
        normalize_fjord_contract(entry(), manifest().replace(*replacement, 1))


def test_manifest_policy_is_the_compose_policy():
    # Rendering widens nothing: host networking and extra services are refused
    # by the same strict parser, with the same words.
    host = manifest().replace('    restart: unless-stopped\n', '    restart: unless-stopped\n    network_mode: host\n')
    with pytest.raises(CatalogContractError, match='Unsupported Compose service fields: network_mode'):
        normalize_fjord_contract(entry(), host)
    stack = manifest().replace('x-fjord:\n', '  redis:\n    image: ghcr.io/daemonless/redis:latest\nx-fjord:\n')
    with pytest.raises(CatalogContractError, match='Exactly one service is supported; provider contract declares 2'):
        normalize_fjord_contract(entry(), stack)


@pytest.mark.parametrize('default,expected', [
    ('http://demo.example:18080', 'http://demo.example:18080'),
    ('https://demo.example/app/', 'https://demo.example/app/'),
    ('""', ''),
])
def test_a_public_url_variable_is_an_environment_value(default, expected):
    # the internal development record: Vikunja's VIKUNJA_SERVICE_PUBLICURL and Woodpecker's WOODPECKER_HOST.
    text = manifest().replace(
        '      type: string\n      default: production\n',
        f'      type: public_url\n      default: {default}\n      optional: true\n',
    )
    environment = {item['name']: item for item in normalize_fjord_contract(entry(), text)['environment']}
    assert environment['MODE']['default'] == expected
    assert environment['MODE']['sensitive'] is False
    assert environment['MODE']['description'] == 'Runtime mode'


@pytest.mark.parametrize('default,expected', [
    # the internal development record: navidrome's ND_SCANNER_SCHEDULE, written for a .env file.
    ("'\"@every 1h\"'", '@every 1h'),
    ('"''single quoted''"', 'single quoted'),
    ("'\"say \\\"hi\\\" \\\\ok\"'", 'say "hi" \\ok'),
    ("'say \"hi\"'", 'say "hi"'),
    ("'\"unbalanced'", '"unbalanced'),
    ('production', 'production'),
])
def test_a_variable_default_reads_as_its_dotenv_value(default, expected):
    text = manifest().replace('      default: production\n', f'      default: {default}\n')
    environment = {item['name']: item for item in normalize_fjord_contract(entry(), text)['environment']}
    assert environment['MODE']['default'] == expected


def test_a_secret_variable_marks_its_environment_entry_sensitive():
    text = manifest().replace('API_TOKEN', 'ENCRYPTION_KEY')
    environment = {item['name']: item for item in normalize_fjord_contract(entry(), text)['environment']}
    assert environment['ENCRYPTION_KEY']['sensitive'] is True
    assert environment['ENCRYPTION_KEY']['description'] == 'API credential'
    assert environment['MODE']['sensitive'] is False


def test_storage_variables_are_placeholders_and_labels_become_documentation():
    rendered = render_fjord_manifest(entry(), manifest())
    service = rendered['services']['demo']
    assert service['volumes'] == ['config_data:/config', 'media_path:/media:ro']
    assert service['ports'] == ['18080:8080', '18443:8443']
    assert service['image'] == 'ghcr.io/daemonless/demo:latest'
    docs = rendered['x-daemonless']['docs']
    assert docs['volumes']['/media'] == {'desc': 'Optional media', 'optional': True}
    assert docs['ports'] == {'8080': {'desc': 'Web UI'}, '8443': {'desc': 'HTTPS Web UI'}}
    assert docs['env']['API_TOKEN'] == {'desc': 'API credential', 'optional': True, 'sensitive': True}
    assert 'x-fjord' not in rendered and 'appjail' not in json.dumps(rendered)


def test_web_https_selects_an_https_portal():
    text = manifest().replace('    web_port: ${WEB_PORT}\n', '    web_port: ${HTTPS_PORT}\n    web_https: true\n')
    assert normalize_fjord_contract(entry(), text)['portal'] == {'scheme': 'https', 'port': 18443, 'path': '/'}


# -- the fjord catalog ---------------------------------------------------------

def test_fjord_catalog_is_read_per_application_and_only_in_known_versions():
    apps = normalize_fjord_catalog(fjord_catalog())
    assert set(apps) == {'demo', 'x86-demo'}
    assert apps['demo'] == {
        'name': 'demo',
        'title': 'Demo Service Pro',
        'description': 'The fjord description of the demo.',
        'category': 'Monitoring',
        'class': 'service',
        'manifest_path': 'manifests/demo.yaml',
        'icon_path': 'icons/demo.svg',
    }
    assert apps['x86-demo']['category'] == 'Other'

    for broken in ({**fjord_catalog(), 'fjord_version': '0.2'}, {'apps': []}, None, [], {'fjord_version': '0.1'}):
        assert normalize_fjord_catalog(broken) is None

    duplicated = fjord_catalog()
    duplicated['apps'].append(copy.deepcopy(duplicated['apps'][0]))
    assert 'demo' not in normalize_fjord_catalog(duplicated)

    absolute_icon = fjord_catalog()
    absolute_icon['apps'][0]['icon'] = 'https://example.org/icon.svg'
    assert normalize_fjord_catalog(absolute_icon)['demo']['icon_path'] is None


def test_presentation_overlays_index_entries_and_stacks_are_unavailable_up_front():
    index, repositories = fixtures()
    catalog = normalize_catalog_index(index, repositories, 'amd64')
    apply_fjord_presentation(catalog, normalize_fjord_catalog(fjord_catalog()), {'demo': 'data:image/png;base64,AA=='})
    by_name = {item['name']: item for item in catalog['entries']}
    assert by_name['demo']['title'] == 'Demo Service Pro'
    assert by_name['demo']['category'] == 'Monitoring'
    assert by_name['demo']['icon'] == 'data:image/png;base64,AA=='
    assert by_name['demo']['status'] == 'UNRESOLVED'
    assert by_name['x86-demo']['status'] == 'UNAVAILABLE'
    assert 'multi-service stack' in by_name['x86-demo']['reason']
    # Not in fjord: untouched (the base image keeps its own reason).
    assert by_name['base-demo']['reason'] == 'Base images are not installable Applications.'
    assert by_name['base-demo']['icon'] is None


def test_icons_are_typed_by_their_bytes_and_unsafe_svg_falls_back():
    assert icon_data_uri(SVG) == 'data:image/svg+xml;base64,' + base64.b64encode(SVG).decode()
    assert icon_data_uri(b'\xef\xbb\xbf<?xml version="1.0"?>\n' + SVG).startswith('data:image/svg+xml;base64,')
    assert icon_data_uri(PNG).startswith('data:image/png;base64,')
    assert icon_data_uri(b'\xff\xd8\xff\xe0' + b'\x00' * 8).startswith('data:image/jpeg;base64,')
    assert icon_data_uri(b'GIF89a' + b'\x00' * 8).startswith('data:image/gif;base64,')
    assert icon_data_uri(b'RIFF\x00\x00\x00\x00WEBPVP8 ').startswith('data:image/webp;base64,')
    embedded = b'<svg xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="data:image/png;base64,AAAA"/></svg>'
    assert icon_data_uri(embedded).startswith('data:image/svg+xml;base64,')
    for unsafe in (
        b'<svg><script>alert(1)</script></svg>',
        b'<svg onload="alert(1)"></svg>',
        b'<svg><a href="https://example.org/"><rect/></a></svg>',
        b'<svg><image xlink:href="http://example.org/x.png"/></svg>',
        b'<!DOCTYPE svg [<!ENTITY x "y">]><svg>&x;</svg>',
        b'<svg><foreignObject><div/></foreignObject></svg>',
        b'<svg style="background:url(https://example.org/t.png)"></svg>',
        b'<html><body>not an icon</body></html>',
        b'\x00\x01binary',
        b'',
        SVG + b' ' * (64 * 1024),
    ):
        assert icon_data_uri(unsafe) is None, unsafe[:40]


# -- cache ---------------------------------------------------------------------

def test_cache_schema_4_carries_fjord_documents_and_icons():
    cache = live_cache(manifests=['demo'])
    store_icon(cache, 'demo', 'icons/demo.svg', SVG, now=NOW)
    assert validate_cache(cache)['schema'] == CACHE_SCHEMA == 4

    broken = copy.deepcopy(cache)
    broken['icons']['demo']['sha256'] = 'f' * 64
    with pytest.raises(CatalogContractError, match='icon cache'):
        validate_cache(broken)
    broken = copy.deepcopy(cache)
    broken['icons']['demo']['data'] = 'not base64!'
    with pytest.raises(CatalogContractError, match='icon cache'):
        validate_cache(broken)
    broken = copy.deepcopy(cache)
    broken['icons']['demo']['path'] = 'https://example.org/demo.svg'
    with pytest.raises(CatalogContractError, match='icon cache'):
        validate_cache(broken)
    broken = copy.deepcopy(cache)
    broken['manifests']['demo']['content'] += '\n'
    with pytest.raises(CatalogContractError, match='manifest cache'):
        validate_cache(broken)
    with pytest.raises(CatalogContractError, match='maximum supported size'):
        store_icon(cache, 'demo', 'icons/demo.svg', b'x' * (64 * 1024 + 1))
    with pytest.raises(CatalogContractError, match='identity'):
        store_icon(cache, 'demo', '../demo.svg', SVG)


def test_schema_3_caches_and_seeds_are_read_and_an_upgraded_box_adopts_the_seed_fjord(tmp_path):
    cache_path, seed_path = tmp_path / 'cache.json', tmp_path / 'seed.json'
    legacy = live_cache(fjord=False, composes=['demo'])
    for field in ('fjord', 'fjord_fetched_at', 'manifests', 'icons'):
        legacy.pop(field)
    legacy['schema'] = 3
    cache_path.write_text(json.dumps(legacy))

    loaded = read_cache(str(cache_path), str(seed_path))
    assert loaded['schema'] == 4 and loaded['source'] == 'live' and loaded['fjord'] is None
    assert loaded['composes']['demo']['content'] == compose()

    seed = live_cache(manifests=['demo', 'x86-demo'], document_age=86400)
    seed.update({'source': 'seed', 'fetched_at': NOW - 86400})
    store_icon(seed, 'demo', 'icons/demo.svg', SVG, now=NOW - 86400)
    write_cache(seed, str(seed_path))
    loaded = read_cache(str(cache_path), str(seed_path))
    # The box keeps its own index and composes and gains the seed's fjord data.
    assert loaded['source'] == 'live' and loaded['fetched_at'] == NOW
    assert loaded['fjord'] == fjord_catalog() and set(loaded['icons']) == {'demo'}
    assert set(loaded['manifests']) == {'demo', 'x86-demo'}
    # ... whose documents are older than the box's index, so a review re-reads them.
    assert current_document(loaded, 'manifests', 'demo') is None

    legacy_seed = copy.deepcopy(legacy)
    legacy_seed['source'] = 'seed'
    cache_path.unlink()
    seed_path.write_text(json.dumps(legacy_seed))
    assert read_cache(str(cache_path), str(seed_path))['source'] == 'seed'


def test_a_document_is_current_only_if_fetched_after_the_index_it_is_read_with():
    cache = live_cache(composes=['demo'], document_age=60)
    assert current_document(cache, 'composes', 'demo') is None
    cache = live_cache(composes=['demo'])
    assert current_document(cache, 'composes', 'demo') == compose()


# -- service -------------------------------------------------------------------

@pytest.mark.asyncio
async def test_review_prefers_the_fjord_manifest_and_shows_the_provider_icon():
    cache = live_cache()
    store_icon(cache, 'demo', 'icons/demo.svg', SVG, now=NOW)
    service = service_with(cache)
    provider = client(fetch_fjord_manifest=manifest(), fetch_compose=compose())
    service._client = Mock(return_value=provider)

    detail = await service.details('daemonless:demo', {'refresh': False})

    provider.fetch_fjord_manifest.assert_awaited_once_with('manifests/demo.yaml')
    # The compose is read only for what fjord 0.1 does not say (the class).
    provider.fetch_compose.assert_awaited_once_with('demo')
    assert detail['available'] is True
    assert detail['title'] == 'Demo Service Pro'
    assert detail['icon'].startswith('data:image/svg+xml;base64,')
    assert detail['catalog']['compose_sha256'] == sha256_hex(manifest())
    assert detail['provenance']['source_path'] == 'manifests/demo.yaml'
    assert detail['provenance']['source_url'] == 'https://catalog.daemonless.io/v1/daemonless/manifests/demo.yaml'
    assert detail['provenance']['repository'] == 'https://github.com/daemonless/demo'
    assert service._catalog_cache['manifests']['demo']['content'] == manifest()


@pytest.mark.asyncio
async def test_review_falls_back_to_the_repository_compose_per_entry():
    # Unreachable manifest: the compose is reviewed.
    service = service_with(live_cache())
    provider = client(fetch_fjord_manifest=AsyncMock(side_effect=CallError('offline')), fetch_compose=compose())
    service._client = Mock(return_value=provider)
    detail = await service.details('daemonless:demo', {'refresh': False})
    assert detail['available'] is True
    assert detail['catalog']['compose_sha256'] == sha256_hex(compose())
    assert detail['provenance']['source_path'] == 'compose.yaml'

    # A manifest this release cannot read: the compose is reviewed.
    service = service_with(live_cache())
    unreadable = manifest().replace('  version: "0.1"\n', '  version: "0.9"\n')
    provider = client(fetch_fjord_manifest=unreadable, fetch_compose=compose())
    service._client = Mock(return_value=provider)
    detail = await service.details('daemonless:demo', {'refresh': False})
    assert detail['available'] is True and detail['provenance']['source_path'] == 'compose.yaml'

    # Both refused: the manifest's reason is the one shown.
    service = service_with(live_cache())
    provider = client(
        fetch_fjord_manifest=unreadable,
        fetch_compose=compose().replace('    container_name: demo\n', '    container_name: demo\n    privileged: true\n'),
    )
    service._client = Mock(return_value=provider)
    detail = await service.details('daemonless:demo', {'refresh': False})
    assert detail['status'] == 'UNAVAILABLE' and 'version is not supported' in detail['reason']

    # Refused manifest and no compose at all: still the manifest's reason, not an error.
    service = service_with(live_cache())
    provider = client(fetch_fjord_manifest=unreadable, fetch_compose=AsyncMock(side_effect=CallError('HTTP 503')))
    service._client = Mock(return_value=provider)
    detail = await service.details('daemonless:demo', {'refresh': False})
    assert detail['status'] == 'UNAVAILABLE' and 'version is not supported' in detail['reason']

    # No fjord catalog at all: exactly the pre-fjord behaviour.
    service = service_with(live_cache(fjord=False))
    provider = client(fetch_fjord_manifest=manifest(), fetch_compose=compose())
    service._client = Mock(return_value=provider)
    detail = await service.details('daemonless:demo', {'refresh': False})
    provider.fetch_fjord_manifest.assert_not_awaited()
    assert detail['provenance']['source_path'] == 'compose.yaml'


@pytest.mark.asyncio
async def test_the_repository_compose_still_says_what_is_not_an_application():
    # fjord 0.1 labels the provider's CLI images `service`; their composes say `cli`.
    cli = compose().replace('  title: Demo Service\n', '  title: Demo Service\n  class: cli\n')
    service = service_with(live_cache())
    service._client = Mock(return_value=client(fetch_fjord_manifest=manifest(), fetch_compose=cli))
    detail = await service.details('daemonless:demo', {'refresh': False})
    assert detail['status'] == 'UNAVAILABLE'
    assert detail['reason'] == 'CLI images are not installable Applications.'

    # The same holds when an install is bound straight to the cached manifest.
    cache = live_cache(manifests=['demo'])
    store_compose(cache, 'demo', cli, now=NOW)
    service = service_with(cache)
    with pytest.raises(CallError, match='not installable: CLI images'):
        await service.bind_install({
            'id': 'daemonless:demo', 'name': 'demo', 'compose_sha256': sha256_hex(manifest()),
            'ports': [], 'environment': [], 'volumes': [], 'restart_policy': 'always', 'health_timeout': 60,
        })

    # No compose to ask: the manifest decides alone.
    service = service_with(live_cache())
    service._client = Mock(return_value=client(
        fetch_fjord_manifest=manifest(), fetch_compose=AsyncMock(side_effect=CallError('HTTP 503')),
    ))
    assert (await service.details('daemonless:demo', {'refresh': False}))['available'] is True


@pytest.mark.asyncio
async def test_a_stack_is_unavailable_without_any_fetch():
    service = service_with(live_cache())
    provider = client(fetch_fjord_manifest=manifest(), fetch_compose=compose())
    service._client = Mock(return_value=provider)
    detail = await service.details('daemonless:x86-demo', {'refresh': False})
    assert detail['status'] == 'UNAVAILABLE' and 'multi-service stack' in detail['reason']
    provider.fetch_fjord_manifest.assert_not_awaited()
    provider.fetch_compose.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_contract_older_than_the_index_is_fetched_again_once():
    # the internal development record: the upgraded-box shape -- an old compose under a
    # newer index -- reviews the provider's current contract.
    service = service_with(live_cache(fjord=False, composes=['demo'], document_age=86400))
    current = compose().replace('MODE=production', 'MODE=current')
    provider = client(fetch_compose=current)
    service._client = Mock(return_value=provider)

    detail = await service.details('daemonless:demo', {'refresh': False})
    provider.fetch_compose.assert_awaited_once_with('demo')
    assert {item['name']: item['default'] for item in detail['environment']}['MODE'] == 'current'
    assert service._catalog_cache['composes']['demo']['fetched_at'] >= NOW

    provider.fetch_compose.reset_mock()
    await service.details('daemonless:demo', {'refresh': False})
    provider.fetch_compose.assert_not_awaited()

    # Offline: the stale copy still reviews.
    service = service_with(live_cache(fjord=False, composes=['demo'], document_age=86400))
    service._client = Mock(return_value=client(fetch_compose=AsyncMock(side_effect=CallError('offline'))))
    detail = await service.details('daemonless:demo', {'refresh': False})
    assert detail['available'] is True
    assert detail['catalog']['compose_sha256'] == sha256_hex(compose())


@pytest.mark.asyncio
async def test_install_binds_the_document_that_was_reviewed():
    cache = live_cache(composes=['demo'], manifests=['demo'])
    service = service_with(cache)
    service.middleware.call = AsyncMock(return_value=Mock())
    base = {
        'id': 'daemonless:demo', 'name': 'demo',
        'ports': [
            {'host_port': 28080, 'container_port': 8080, 'protocol': 'tcp'},
            {'host_port': 28443, 'container_port': 8443, 'protocol': 'tcp'},
        ],
        'environment': [{'name': 'API_TOKEN', 'value': 't'}, {'name': 'MODE', 'value': 'production'}],
        'volumes': [{'name': 'config', 'dataset': None}, {'name': 'media', 'dataset': None}],
        'restart_policy': 'always', 'network': {'mode': 'managed'}, 'health_timeout': 60,
    }

    install, provenance = await service.bind_install({**base, 'compose_sha256': sha256_hex(manifest())})
    assert provenance['compose_sha256'] == sha256_hex(manifest())
    assert install['portal']['port'] == 28080

    install, provenance = await service.bind_install({**base, 'compose_sha256': sha256_hex(compose())})
    assert provenance['compose_sha256'] == sha256_hex(compose())
    assert install['healthcheck']['host_port'] == 28080

    with pytest.raises(CallError, match='changed; review it again'):
        await service.bind_install({**base, 'compose_sha256': 'e' * 64})


@pytest.mark.asyncio
async def test_refresh_reads_fjord_and_icons_without_letting_either_fail_it():
    cache = live_cache(fjord=False)
    cache['repositories_fetched_at'] = NOW
    service = service_with(cache)
    index, _ = fixtures()

    async def icon(path):
        if path == 'icons/x86-demo.png':
            raise CallError('HTTP 404')
        return SVG

    provider = client(
        fetch_index=index,
        fetch_fjord_catalog=fjord_catalog(),
        fetch_fjord_icon=AsyncMock(side_effect=icon),
    )
    service._client = Mock(return_value=provider)
    result = await service.refresh()

    assert service._catalog_cache['fjord'] == fjord_catalog()
    assert set(service._catalog_cache['icons']) == {'demo'}
    by_name = {item['name']: item for item in result}
    assert by_name['demo']['icon'].startswith('data:image/svg+xml;base64,')
    assert by_name['demo']['title'] == 'Demo Service Pro'
    assert by_name['x86-demo']['status'] == 'UNAVAILABLE'
    # Only applications the index lists get icons fetched.
    assert {call.args[0] for call in provider.fetch_fjord_icon.await_args_list} == {
        'icons/demo.svg', 'icons/x86-demo.png',
    }

    # Unreachable fjord: the last copy stays; recent icons are not fetched again.
    provider = client(
        fetch_index=index, fetch_fjord_catalog=AsyncMock(side_effect=CallError('offline')),
        fetch_fjord_icon=AsyncMock(return_value=SVG),
    )
    service._client = Mock(return_value=provider)
    await service.refresh()
    assert service._catalog_cache['fjord'] == fjord_catalog()
    assert {call.args[0] for call in provider.fetch_fjord_icon.await_args_list} == {'icons/x86-demo.png'}

    # A format this release does not read: fjord is dropped, icons stay.
    provider = client(fetch_index=index, fetch_fjord_catalog={**fjord_catalog(), 'fjord_version': '1.0'})
    service._client = Mock(return_value=provider)
    result = await service.refresh()
    assert service._catalog_cache['fjord'] is None
    by_name = {item['name']: item for item in result}
    assert by_name['demo']['title'] == 'Demo' and by_name['demo']['icon'].startswith('data:image/svg+xml')


@pytest.mark.asyncio
async def test_slow_icons_cost_icons_not_the_refresh():
    service = service_with(live_cache(fjord=False))
    index, _ = fixtures()

    async def icon(path):
        if path == 'icons/demo.svg':
            await asyncio.sleep(30)
        return SVG

    service._client = Mock(return_value=client(
        fetch_index=index, fetch_fjord_catalog=fjord_catalog(), fetch_fjord_icon=AsyncMock(side_effect=icon),
    ))
    with patch('middlewared.plugins.applications_catalog_freebsd.ICON_FETCH_BUDGET', 0.05):
        await service.refresh()
    assert set(service._catalog_cache['icons']) == {'x86-demo'}


def test_the_fjord_catalog_is_a_documented_provider_url():
    assert FJORD_CATALOG_URL == 'https://catalog.daemonless.io/v1/daemonless/catalog.json'
    ProviderClient.check_url(FJORD_CATALOG_URL)
    with pytest.raises(CatalogContractError, match='HTTPS identity'):
        ProviderClient.check_url('https://catalog.daemonless.io.example.org/v1/daemonless/catalog.json')


@pytest.mark.asyncio
async def test_fjord_documents_are_fetched_only_from_pinned_paths():
    provider = ProviderClient()
    provider.get = AsyncMock(return_value=b'name: demo\n')
    assert await provider.fetch_fjord_manifest('manifests/demo.yaml') == 'name: demo\n'
    provider.get.assert_awaited_once_with(
        'https://catalog.daemonless.io/v1/daemonless/manifests/demo.yaml', 1024 * 1024, accept='text/plain',
    )
    for path in ('https://example.org/x.yaml', 'manifests/../x.yaml', 'manifests/demo.yml', '/manifests/demo.yaml'):
        with pytest.raises(CatalogContractError, match='path is invalid'):
            await provider.fetch_fjord_manifest(path)
    for path in ('icons/demo.gif', 'icons/../demo.svg', 'https://example.org/i.svg'):
        with pytest.raises(CatalogContractError, match='path is invalid'):
            await provider.fetch_fjord_icon(path)


@pytest.mark.asyncio
async def test_providers_name_the_fjord_catalog():
    service = service_with(live_cache())
    assert (await service.providers())[0]['catalog_url'] == FJORD_CATALOG_URL
