"""Read the Daemonless organisation directly (the internal development record).

The catalog used to be a FreeCORE-signed snapshot with a digest-pinned object
per application.  It now reads what the provider itself publishes:

- the version index ``daemonless-versions.json`` in the ``daemonless/daemonless``
  repository (one request, from the raw content CDN);
- the organisation's repository list from the GitHub API (two requests for the
  current organisation size, subject to the unauthenticated 60/hour budget, so it
  is refreshed on a slow schedule and its absence only degrades categories); and
- each application's ``compose.yaml``, fetched lazily from the raw content CDN
  when the application is reviewed, and cached by content hash; and
- the provider's fjord catalog (the internal development record): one listing with
  presentation and icons, and per application a manifest with typed variables,
  preferred over the compose when it can be read, never required.

Nothing is signed and nothing expires.  The cache is a last-known-good copy that
keeps the page working offline; the image build ships a seed with the same shape
so a box with no egress still lists applications.  What FreeCORE authors (the
normalised contract it installs from) is hashed by content so that a reviewed
entry cannot change between review and install; what upstream authors (the
image) is followed by tag and recorded by the digest actually pulled.
"""
import asyncio
import base64
import binascii
import hashlib
import json
import os
import re
import time
from urllib.parse import urlsplit

import aiohttp

from middlewared.plugins.applications_.catalog import (
    CatalogContractError,
    FJORD_ICON_PATH,
    FJORD_MANIFEST_PATH,
    MAX_ICON_SIZE,
    PROVIDER_ID,
    PROVIDER_ORGANIZATION,
    SERVICE_NAME,
)
from middlewared.plugins.applications_.utils import atomic_write
from middlewared.service_exception import CallError
from middlewared.utils.network import INTERNET_TIMEOUT

PROVIDER_INDEX_URL = (
    f'https://raw.githubusercontent.com/{PROVIDER_ORGANIZATION}/{PROVIDER_ORGANIZATION}'
    '/main/daemonless-versions.json'
)
PROVIDER_REPOSITORIES_URL = f'https://api.github.com/orgs/{PROVIDER_ORGANIZATION}/repos'
PROVIDER_COMPOSE_URL = (
    f'https://raw.githubusercontent.com/{PROVIDER_ORGANIZATION}/{{name}}/main/compose.yaml'
)
PROVIDER_REPOSITORY_URL = f'https://github.com/{PROVIDER_ORGANIZATION}/{{name}}'
PROVIDER_SBOM_URL = f'https://github.com/{PROVIDER_ORGANIZATION}/{{name}}/blob/main/sbom.json'
PROVIDER_IMAGE = f'ghcr.io/{PROVIDER_ORGANIZATION}/{{name}}'
FJORD_BASE_URL = f'https://catalog.daemonless.io/v1/{PROVIDER_ORGANIZATION}/'
FJORD_CATALOG_URL = f'{FJORD_BASE_URL}catalog.json'
EXPECTED_PROVIDER_HOSTS = {'raw.githubusercontent.com', 'api.github.com', 'catalog.daemonless.io'}

CACHE_PATH = '/data/applications-catalog-cache.json'
SEED_PATH = '/usr/local/share/freecore/applications/catalog-seed.json'
CACHE_SCHEMA = 4
# the internal development record: schema 3 is schema 4 without the fjord fields; such a
# cache (or an older image's seed) is read by adding them empty.
MIGRATABLE_CACHE_SCHEMA = 3
FJORD_CACHE_FIELDS = ('fjord', 'fjord_fetched_at', 'manifests', 'icons')
CACHE_LIMIT = 64 * 1024 * 1024
MAX_INDEX_SIZE = 1024 * 1024
MAX_REPOSITORY_PAGE_SIZE = 4 * 1024 * 1024
MAX_REPOSITORY_PAGES = 8
MAX_COMPOSE_SIZE = 1024 * 1024
MAX_COMPOSES = 512
MAX_FJORD_CATALOG_SIZE = 1024 * 1024
MAX_ICONS = 512
# Icons change rarely; a refresh re-reads one older than this.
ICON_REFRESH_INTERVAL = 7 * 24 * 60 * 60
# GitHub allows 60 unauthenticated API requests per hour per source address.
# Two requests enumerate the organisation; keep them rare.
REPOSITORY_METADATA_INTERVAL = 6 * 60 * 60
# A catalog older than this is shown, but the page says it is stale.
STALE_AFTER = 24 * 60 * 60
HEX_SHA256 = re.compile(r'^[0-9a-f]{64}$')


class ProviderNotFound(CallError):
    """The provider answered 404 for one resource (the internal development record).

    A CallError so every existing handler still treats it as a provider
    failure; callers that can attribute it to a single entry catch it first.
    """

    def __init__(self, url):
        super().__init__(f'Applications provider has no such resource ({url}).')


def sha256_hex(content):
    if isinstance(content, str):
        content = content.encode('utf-8')
    return hashlib.sha256(content).hexdigest()


def empty_cache():
    return {
        'schema': CACHE_SCHEMA,
        'provider': PROVIDER_ID,
        'source': 'empty',
        'fetched_at': 0,
        'repositories_fetched_at': 0,
        'index': None,
        'repositories': None,
        'composes': {},
        'fjord': None,
        'fjord_fetched_at': 0,
        'manifests': {},
        'icons': {},
    }


def _validate_documents(documents, label):
    if not isinstance(documents, dict) or len(documents) > MAX_COMPOSES:
        raise CatalogContractError(f'Applications catalog {label} cache is invalid.')
    for name, item in documents.items():
        if (
            not isinstance(name, str) or not SERVICE_NAME.fullmatch(name) or
            not isinstance(item, dict) or set(item) != {'sha256', 'content', 'fetched_at'} or
            not isinstance(item['sha256'], str) or not HEX_SHA256.fullmatch(item['sha256']) or
            not isinstance(item['content'], str) or
            len(item['content'].encode('utf-8')) > MAX_COMPOSE_SIZE or
            sha256_hex(item['content']) != item['sha256'] or
            type(item['fetched_at']) is not int or item['fetched_at'] < 0
        ):
            raise CatalogContractError(f'Applications catalog {label} cache is invalid.')


def _icon_bytes(item):
    try:
        return base64.b64decode(item['data'], validate=True)
    except (binascii.Error, TypeError, ValueError) as error:
        raise CatalogContractError('Applications catalog icon cache is invalid.') from error


def _validate_icons(icons):
    if not isinstance(icons, dict) or len(icons) > MAX_ICONS:
        raise CatalogContractError('Applications catalog icon cache is invalid.')
    for name, item in icons.items():
        if (
            not isinstance(name, str) or not SERVICE_NAME.fullmatch(name) or
            not isinstance(item, dict) or set(item) != {'sha256', 'data', 'fetched_at', 'path'} or
            not isinstance(item['sha256'], str) or not HEX_SHA256.fullmatch(item['sha256']) or
            not isinstance(item['data'], str) or
            not isinstance(item['path'], str) or not FJORD_ICON_PATH.fullmatch(item['path']) or
            type(item['fetched_at']) is not int or item['fetched_at'] < 0
        ):
            raise CatalogContractError('Applications catalog icon cache is invalid.')
        content = _icon_bytes(item)
        if len(content) > MAX_ICON_SIZE or sha256_hex(content) != item['sha256']:
            raise CatalogContractError('Applications catalog icon cache is invalid.')


def validate_cache(data):
    expected = {
        'schema', 'provider', 'source', 'fetched_at', 'repositories_fetched_at',
        'index', 'repositories', 'composes', *FJORD_CACHE_FIELDS,
    }
    if (
        not isinstance(data, dict) or set(data) != expected or
        data['schema'] != CACHE_SCHEMA or data['provider'] != PROVIDER_ID or
        data['source'] not in {'empty', 'seed', 'live'} or
        type(data['fetched_at']) is not int or data['fetched_at'] < 0 or
        type(data['repositories_fetched_at']) is not int or data['repositories_fetched_at'] < 0 or
        not (data['index'] is None or isinstance(data['index'], dict)) or
        not (data['repositories'] is None or isinstance(data['repositories'], list)) or
        not isinstance(data['composes'], dict) or len(data['composes']) > MAX_COMPOSES or
        not (data['fjord'] is None or isinstance(data['fjord'], dict)) or
        type(data['fjord_fetched_at']) is not int or data['fjord_fetched_at'] < 0
    ):
        raise CatalogContractError('Applications catalog cache structure is invalid.')
    if data['source'] == 'empty' and data['index'] is not None:
        raise CatalogContractError('Applications catalog empty cache carries an index.')
    if data['repositories'] is not None and (
        len(data['repositories']) > MAX_REPOSITORY_PAGES or
        any(not isinstance(page, list) for page in data['repositories'])
    ):
        raise CatalogContractError('Applications catalog repository cache is invalid.')
    _validate_documents(data['composes'], 'compose')
    _validate_documents(data['manifests'], 'manifest')
    _validate_icons(data['icons'])
    return data


def _migrate(data):
    """A schema-3 cache or seed as schema 4: the same data, no fjord fields yet."""
    if isinstance(data, dict) and data.get('schema') == MIGRATABLE_CACHE_SCHEMA and not (
        set(data) & set(FJORD_CACHE_FIELDS)
    ):
        data = dict(data, schema=CACHE_SCHEMA, fjord=None, fjord_fetched_at=0, manifests={}, icons={})
    return data


def _read_json_file(path, label):
    try:
        if os.path.getsize(path) > CACHE_LIMIT:
            raise CatalogContractError(f'{label} is oversized.')
        with open(path, 'rb') as file:
            content = file.read(CACHE_LIMIT + 1)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise CatalogContractError(f'{label} is unreadable.') from error
    try:
        return json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as error:
        raise CatalogContractError(f'{label} is corrupt.') from error


def read_seed(path=None):
    """The image-shipped last-known-good copy, or None."""
    data = _read_json_file(path or SEED_PATH, 'Applications catalog seed')
    if data is None:
        return None
    data = validate_cache(_migrate(data))
    data['source'] = 'seed'
    return data


def read_cache(path=None, seed_path=None):
    """Runtime cache first, then the image seed, then nothing.

    A cache written by the retired signed-snapshot client (schema 1 or 2) is not
    an error: it is simply superseded, and the seed or the next refresh replaces
    it.  A structurally invalid schema-3 cache also falls back rather than taking
    the page down; refresh rewrites it.
    """
    data = None
    try:
        data = _migrate(_read_json_file(path or CACHE_PATH, 'Applications catalog cache'))
        if isinstance(data, dict) and data.get('schema') == CACHE_SCHEMA:
            data = validate_cache(data)
        else:
            data = None
    except CatalogContractError:
        data = None
    seed = None
    try:
        seed = read_seed(seed_path)
    except CatalogContractError:
        seed = None
    if data is not None and data['index'] is not None:
        return adopt_seed_fjord(data, seed)
    if seed is not None and seed['index'] is not None:
        return seed
    return data or empty_cache()


def adopt_seed_fjord(cache, seed):
    """An upgraded box's cache takes the image seed's fjord data when it has none.

    Its own index, repositories and composes stay; the seed's fjord catalog,
    manifests and icons keep their build-time timestamps, so the next refresh
    replaces them like any other copy.
    """
    if cache['fjord'] is not None or seed is None or seed['fjord'] is None:
        return cache
    result = dict(cache)
    result.update({
        'fjord': seed['fjord'],
        'fjord_fetched_at': seed['fjord_fetched_at'],
        'manifests': {**seed['manifests'], **cache['manifests']},
        'icons': {**seed['icons'], **cache['icons']},
    })
    return result


def write_cache(cache, path=None):
    validate_cache(cache)
    content = json.dumps(cache, indent=2, sort_keys=True) + '\n'
    if len(content.encode()) > CACHE_LIMIT:
        raise ValueError('Applications catalog cache exceeds the maximum supported size.')
    atomic_write(path or CACHE_PATH, content, mode=0o600)


def is_stale(cache, now=None):
    if cache.get('index') is None:
        return True
    if cache.get('source') != 'live':
        return True
    current = int(time.time()) if now is None else int(now)
    return current - int(cache.get('fetched_at') or 0) > STALE_AFTER


def repositories_due(cache, now=None):
    current = int(time.time()) if now is None else int(now)
    fetched = int(cache.get('repositories_fetched_at') or 0)
    return cache.get('repositories') is None or current - fetched >= REPOSITORY_METADATA_INTERVAL


def cached_document(cache, store, name):
    """A cached contract document (``composes`` or ``manifests``), whatever its age."""
    item = cache[store].get(name)
    return None if item is None else item['content']


def current_document(cache, store, name):
    """A cached contract document that is not older than the index it is read with.

    the internal development record: an Update Catalog makes every cached contract stale;
    the next review of an entry fetches it again once.  The seed's documents carry
    the seed's own timestamp, so a box reviews from its seed until it refreshes.
    """
    item = cache[store].get(name)
    if item is None or item['fetched_at'] < int(cache.get('fetched_at') or 0):
        return None
    return item['content']


def store_document(cache, store, name, content, now=None):
    if not SERVICE_NAME.fullmatch(name or ''):
        raise CatalogContractError('Application name is invalid.')
    if len(cache[store]) >= MAX_COMPOSES and name not in cache[store]:
        raise CatalogContractError(f'Applications catalog {store} cache is full.')
    cache[store][name] = {
        'sha256': sha256_hex(content),
        'content': content,
        'fetched_at': int(time.time()) if now is None else int(now),
    }
    return cache[store][name]


def cached_compose(cache, name):
    return cached_document(cache, 'composes', name)


def store_compose(cache, name, content, now=None):
    return store_document(cache, 'composes', name, content, now)


def document_by_hash(cache, name, sha256):
    """``(store, content)`` of the cached document with this hash, or ``(None, None)``."""
    for store in ('manifests', 'composes'):
        item = cache[store].get(name)
        if item is not None and item['sha256'] == sha256:
            return store, item['content']
    return None, None


def icon_due(cache, name, path, now=None):
    current = int(time.time()) if now is None else int(now)
    item = cache['icons'].get(name)
    return item is None or item['path'] != path or current - item['fetched_at'] >= ICON_REFRESH_INTERVAL


def store_icon(cache, name, path, content, now=None):
    if not SERVICE_NAME.fullmatch(name or '') or not FJORD_ICON_PATH.fullmatch(path or ''):
        raise CatalogContractError('Application icon identity is invalid.')
    if not isinstance(content, bytes) or len(content) > MAX_ICON_SIZE:
        raise CatalogContractError('Application icon exceeds the maximum supported size.')
    if len(cache['icons']) >= MAX_ICONS and name not in cache['icons']:
        raise CatalogContractError('Applications catalog icon cache is full.')
    cache['icons'][name] = {
        'sha256': sha256_hex(content),
        'data': base64.b64encode(content).decode('ascii'),
        'fetched_at': int(time.time()) if now is None else int(now),
        'path': path,
    }
    return cache['icons'][name]


def cached_icon(cache, name):
    """The raw bytes of a cached icon, or None."""
    item = cache['icons'].get(name)
    return None if item is None else _icon_bytes(item)


class ProviderClient:
    """Bounded HTTPS reads from the provider's hosts, nothing else.

    No redirects are followed, every response is capped at a declared size, and
    only the raw content CDN, the GitHub API and the provider's fjord catalog host
    are allowed as origins.  The API is the budgeted one; the caller decides how
    rarely to touch it.
    """

    def __init__(self, timeout=None, user_agent='FreeCORE-Applications-catalog/3'):
        self.timeout = INTERNET_TIMEOUT if timeout is None else timeout
        self.user_agent = user_agent

    @staticmethod
    def check_url(url):
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError as error:
            raise CatalogContractError('Provider request URL is malformed.') from error
        if (
            parsed.scheme != 'https' or parsed.hostname not in EXPECTED_PROVIDER_HOSTS or
            parsed.username or parsed.password or port not in {None, 443} or parsed.fragment
        ):
            raise CatalogContractError('Provider request URL is outside the expected HTTPS identity.')

    async def get(self, url, maximum, accept='application/json'):
        self.check_url(url)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        headers = {'Accept': accept, 'User-Agent': self.user_agent}
        if urlsplit(url).hostname == 'api.github.com':
            headers['X-GitHub-Api-Version'] = '2022-11-28'
        try:
            async with (
                aiohttp.ClientSession(timeout=timeout, trust_env=True, headers=headers) as session,
                session.get(url, allow_redirects=False) as response,
            ):
                if response.status == 403 and response.headers.get('x-ratelimit-remaining') == '0':
                    raise CallError(
                        'The provider API rate limit for this address is exhausted; '
                        'the cached catalog stays in use until it resets.'
                    )
                if response.status == 404:
                    raise ProviderNotFound(url)
                if response.status != 200:
                    raise CallError(f'Applications provider returned HTTP status {response.status}.')
                chunks = []
                size = 0
                async for chunk in response.content.iter_chunked(64 * 1024):
                    size += len(chunk)
                    if size > maximum:
                        raise CatalogContractError(
                            'Applications provider response exceeds the maximum supported size.'
                        )
                    chunks.append(chunk)
                return b''.join(chunks)
        except (CallError, CatalogContractError):
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError) as error:
            raise CallError('Unable to contact the Applications provider.') from error

    @staticmethod
    def _decode_json(content, label):
        try:
            return json.loads(content.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
            raise CatalogContractError(f'{label} is not valid JSON.') from error

    async def fetch_index(self):
        content = await self.get(PROVIDER_INDEX_URL, MAX_INDEX_SIZE)
        index = self._decode_json(content, 'Provider version index')
        if not isinstance(index, dict):
            raise CatalogContractError('Provider version index must be an object.')
        return index

    async def fetch_repositories(self):
        pages = []
        for page in range(1, MAX_REPOSITORY_PAGES + 1):
            content = await self.get(
                f'{PROVIDER_REPOSITORIES_URL}?per_page=100&page={page}&type=public',
                MAX_REPOSITORY_PAGE_SIZE,
                accept='application/vnd.github+json',
            )
            data = self._decode_json(content, 'Provider repository page')
            if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
                raise CatalogContractError('Provider repository page is malformed.')
            if not data:
                break
            pages.append(data)
            if len(data) < 100:
                break
        if not pages:
            raise CatalogContractError('Provider organisation lists no repositories.')
        return pages

    async def fetch_fjord_catalog(self):
        content = await self.get(FJORD_CATALOG_URL, MAX_FJORD_CATALOG_SIZE)
        catalog = self._decode_json(content, 'Provider fjord catalog')
        if not isinstance(catalog, dict):
            raise CatalogContractError('Provider fjord catalog must be an object.')
        return catalog

    async def fetch_fjord_manifest(self, path):
        if not isinstance(path, str) or not FJORD_MANIFEST_PATH.fullmatch(path):
            raise CatalogContractError('fjord manifest path is invalid.')
        content = await self.get(f'{FJORD_BASE_URL}{path}', MAX_COMPOSE_SIZE, accept='text/plain')
        try:
            text = content.decode('utf-8')
        except UnicodeDecodeError as error:
            raise CatalogContractError('fjord manifest is not valid UTF-8.') from error
        if '\x00' in text:
            raise CatalogContractError('fjord manifest contains a NUL character.')
        return text

    async def fetch_fjord_icon(self, path):
        if not isinstance(path, str) or not FJORD_ICON_PATH.fullmatch(path):
            raise CatalogContractError('fjord icon path is invalid.')
        return await self.get(f'{FJORD_BASE_URL}{path}', MAX_ICON_SIZE, accept='image/*')

    async def fetch_compose(self, name):
        if not SERVICE_NAME.fullmatch(name or ''):
            raise CatalogContractError('Application name is invalid.')
        content = await self.get(
            PROVIDER_COMPOSE_URL.format(name=name), MAX_COMPOSE_SIZE, accept='text/plain',
        )
        try:
            text = content.decode('utf-8')
        except UnicodeDecodeError as error:
            raise CatalogContractError('Application compose contract is not valid UTF-8.') from error
        if '\x00' in text:
            raise CatalogContractError('Application compose contract contains a NUL character.')
        return text
