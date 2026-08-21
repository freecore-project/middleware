import asyncio
import copy
import errno
import platform
import time

from middlewared.plugins.applications_.catalog import (
    CATALOG_ID,
    PROVIDER_ID,
    PROVIDER_NAME,
    PROVIDER_RELATIONSHIP,
    PROVIDER_SOURCE_URL,
    CatalogContractError,
    apply_fjord_presentation,
    entry_version,
    finalize_tag_contract,
    icon_data_uri,
    image_tag,
    image_version,
    normalize_catalog_index,
    normalize_daemonless_contract,
    normalize_fjord_catalog,
    normalize_fjord_contract,
    repository_metadata,
    unavailable_detail,
    version_key,
)
from middlewared.plugins.applications_.provider import (
    FJORD_BASE_URL,
    FJORD_CATALOG_URL,
    PROVIDER_COMPOSE_URL,
    PROVIDER_INDEX_URL,
    PROVIDER_REPOSITORY_URL,
    PROVIDER_SBOM_URL,
    ProviderClient,
    cached_document,
    cached_icon,
    current_document,
    document_by_hash,
    icon_due,
    is_stale,
    read_cache,
    repositories_due,
    sha256_hex,
    store_document,
    store_icon,
    write_cache,
)
from middlewared.plugins.applications_.provider import ProviderNotFound
from middlewared.plugins.applications_.registry import VERDICT_MISSING, probe_remote_image
from middlewared.schema import Bool, Dict, Int, List, Str, accepts
from middlewared.service import Service, filterable, job, private
from middlewared.service_exception import CallError, ValidationErrors
from middlewared.utils import filter_list
from middlewared.validators import Match, Range


# How long a review-time registry observation may take before the page gives up
# on showing a digest.  It is informational: the install pulls by tag anyway.
IMAGE_RESOLUTION_TIMEOUT = 8
# the internal development record: icons are fetched on refresh, a few at a time, inside a
# total budget -- a slow icon host costs icons, never the refresh.
ICON_FETCH_CONCURRENCY = 8
ICON_FETCH_BUDGET = 20
SUMMARY_FIELDS = {
    'title',
    'category',
    'description',
    'icon',
    'resolved',
    'available',
    'status',
    'reason',
    'catalog',
    'provenance',
}

APPLICATION_NAME = r'^[a-z0-9][a-z0-9_.-]{0,62}$'
ENVIRONMENT_NAME = r'^[A-Za-z_][A-Za-z0-9_]*$'
ENVIRONMENT_VALUE = r'^[^\x00\r\n]*$'
# the internal development record: kept in step with applications_freebsd.py's definitions.
LABEL_NAME = r'^[A-Za-z0-9][A-Za-z0-9._/-]{0,253}$'
LABEL_VALUE = r'^[^\x00\r\n]*$'
DATASET_NAME = r'^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+$'
HEX_SHA256 = r'^[0-9a-f]{64}$'

CATALOG_INSTALL_SCHEMA = Dict(
    'applications_catalog_install',
    Str('id', required=True, validators=[Match(CATALOG_ID.pattern)]),
    Str('compose_sha256', required=True, validators=[Match(HEX_SHA256)]),
    Str('name', required=True, validators=[Match(APPLICATION_NAME)]),
    List('ports', items=[Dict(
        'port',
        # the internal development record: null keeps the port on the managed bridge.
        Int('host_port', required=True, null=True, validators=[Range(min=1, max=65535)]),
        Int('container_port', required=True, validators=[Range(min=1, max=65535)]),
        Str('protocol', required=True, enum=['tcp', 'udp']),
    )], default=[]),
    List('environment', items=[Dict(
        'environment',
        Str('name', required=True, validators=[Match(ENVIRONMENT_NAME)]),
        Str(
            'value', required=True, private=True,
            max_length=65536,
            validators=[Match(ENVIRONMENT_VALUE), Range(max=65536)],
        ),
    )], default=[]),
    List('volumes', items=[Dict(
        'volume',
        Str('name', required=True, validators=[Match(APPLICATION_NAME)]),
        Str('dataset', default=None, null=True, validators=[Match(DATASET_NAME)]),
    )], default=[]),
    # the internal development record: user-defined container labels, prefilled from the contract.
    # null = "not stated" (the provider's set applies); a list, the empty one included, is
    # the operator's own and is installed as given.
    List('labels', items=[Dict(
        'label',
        Str('name', required=True, validators=[Match(LABEL_NAME)]),
        Str('value', required=True, max_length=4096, validators=[Match(LABEL_VALUE)]),
    )], default=None, null=True),
    # the internal development record: system certificates mounted into the application. A catalog
    # entry never declares one, so this is the operator's list alone.
    List('certificates', items=[Dict(
        'certificate',
        Int('id', required=True),
        Str('name', required=True, empty=False),
        Str('fingerprint', required=True, empty=False),
        Str('target', required=True, empty=False),
        Bool('restart_on_change', default=True),
        Int('uid', default=None, null=True, validators=[Range(min=0)]),
        Int('gid', default=None, null=True, validators=[Range(min=0)]),
    )], default=[]),
    Str('restart_policy', enum=['no', 'on-failure', 'always'], default='always'),
    Dict(
        'network',
        Str('mode', enum=['managed', 'lan'], default='managed'),
        Str('interface', default=None, null=True),
        Str('address', default=None, null=True),
        Str('gateway', default=None, null=True),
        Bool('managed_access', default=False),
        default={'mode': 'managed'},
    ),
    Int('health_timeout', default=60, validators=[Range(min=0, max=300)]),
)

CATALOG_UPDATE_SCHEMA = Dict(
    'applications_catalog_update',
    Str('id', required=True, validators=[Match(CATALOG_ID.pattern)]),
    Str('compose_sha256', required=True, validators=[Match(HEX_SHA256)]),
    Str('name', required=True, validators=[Match(APPLICATION_NAME)]),
    Bool('recreate', default=False),
    Int('health_timeout', default=60, validators=[Range(min=0, max=300)]),
)


_ICON_URIS = {}


def catalog_icons(cache):
    """``{name: data URI}`` for every cached icon the page may show."""
    result = {}
    for name, item in (cache.get('icons') or {}).items():
        uri = _ICON_URIS.get(item['sha256'], False)
        if uri is False:
            try:
                uri = icon_data_uri(cached_icon(cache, name))
            except CatalogContractError:
                uri = None
            if len(_ICON_URIS) >= 1024:
                _ICON_URIS.clear()
            _ICON_URIS[item['sha256']] = uri
        if uri:
            result[name] = uri
    return result


def catalog_entries(cache, architecture):
    """Entries by name from a cache, or an empty map when nothing is cached."""
    if not cache.get('index'):
        return None, {}
    catalog = normalize_catalog_index(cache['index'], cache.get('repositories'), architecture)
    apply_fjord_presentation(catalog, normalize_fjord_catalog(cache.get('fjord')), catalog_icons(cache))
    return catalog, {entry['name']: entry for entry in catalog['entries']}


def catalog_provenance(detail):
    """What an installed record remembers about the catalog entry it came from.

    ``version`` and ``variant`` are what the review could see; the install and
    update jobs replace them with the pulled image's own labels
    (``installed_catalog_provenance``, the internal development record).
    """
    catalog = detail['catalog']
    return {
        'id': detail['id'],
        'version': catalog['version'],
        'variant': catalog.get('variant'),
        'compose_sha256': catalog['compose_sha256'],
        'repository': detail['provenance']['repository'],
        'image_tag': detail['image']['reference'],
    }


def bind_catalog_install(detail, data):
    """Rebuild an install request from a reviewed contract and safe overrides."""
    catalog = detail.get('catalog') or {}
    if (
        detail.get('id') != data['id'] or not detail.get('catalog_app') or
        catalog.get('compose_sha256') != data['compose_sha256']
    ):
        raise CatalogContractError(
            'The reviewed catalog entry changed; review it again before installing.'
        )
    base = detail.get('install')
    if not isinstance(base, dict):
        raise CatalogContractError('Catalog entry does not contain an installable contract.')

    expected_environment = {item['name']: item for item in detail['environment']}
    requested_environment = {item['name']: item['value'] for item in data['environment']}
    if (
        len(requested_environment) != len(data['environment']) or
        set(requested_environment) != set(expected_environment)
    ):
        raise CatalogContractError('Catalog environment declarations do not match the reviewed entry.')
    for name, definition in expected_environment.items():
        if definition.get('required') and not requested_environment[name]:
            raise CatalogContractError(f'Catalog environment value {name!r} is required.')

    base_ports = base['ports']
    if len(data['ports']) != len(base_ports):
        raise CatalogContractError('Catalog port declarations do not match the reviewed entry.')
    ports = []
    # the internal development record: a reviewed port may stay on the managed bridge (no host
    # port); it is still declared, so its identity has to match the entry all the same.
    for expected, requested in zip(base_ports, data['ports']):
        if any(requested[field] != expected[field] for field in ('container_port', 'protocol')):
            raise CatalogContractError('Catalog port identity does not match the reviewed entry.')
        ports.append({
            'host_port': requested['host_port'],
            'container_port': expected['container_port'],
            'protocol': expected['protocol'],
        })

    expected_volumes = {item['name']: item for item in base['volumes']}
    requested_volumes = {item['name']: item['dataset'] for item in data['volumes']}
    if (
        len(requested_volumes) != len(data['volumes']) or
        set(requested_volumes) != set(expected_volumes)
    ):
        raise CatalogContractError('Catalog volume declarations do not match the reviewed entry.')
    volumes = []
    for expected in base['volumes']:
        volume = copy.deepcopy(expected)
        volume['dataset'] = requested_volumes[expected['name']]
        volumes.append(volume)

    portal = copy.deepcopy(base['portal'])
    if portal is not None:
        portal_index = next((
            index for index, declared in enumerate(base_ports)
            if declared['protocol'] == 'tcp' and declared['host_port'] == portal['port']
        ), None)
        if portal_index is None:
            raise CatalogContractError('Catalog portal is not bound to a reviewed TCP port.')
        # the internal development record: the portal is a link on the host, so its port stays published.
        if ports[portal_index]['host_port'] is None:
            raise CatalogContractError(
                f'Container port {ports[portal_index]["container_port"]}/tcp opens the application\'s '
                'web page and must stay published on the host.'
            )
        portal['port'] = ports[portal_index]['host_port']

    healthcheck = copy.deepcopy(base['healthcheck'])
    if healthcheck is not None:
        health_index = next((
            index for index, declared in enumerate(base_ports)
            if (
                declared['protocol'] == 'tcp' and
                declared['container_port'] == healthcheck['container_port'] and
                declared['host_port'] == healthcheck['host_port']
            )
        ), None)
        if health_index is None:
            raise CatalogContractError(
                'Catalog health check is not bound to a reviewed TCP port.'
            )
        healthcheck['host_port'] = ports[health_index]['host_port']

    install = copy.deepcopy(base)
    install.update({
        'name': data['name'],
        'ports': ports,
        'environment': [
            {'name': name, 'value': requested_environment[name]}
            for name in sorted(expected_environment)
        ],
        'volumes': volumes,
        # the internal development record: labels are the operator's, not part of the reviewed contract --
        # the contract only declares the provider's set, which the form prefills. A request that
        # does not state labels keeps that provider set, so an API caller still gets what the
        # entry intends; a stated list wins even when empty, or a label the operator removed in
        # the form would come back.
        'labels': copy.deepcopy(
            (base.get('labels') or []) if data.get('labels') is None else data['labels']
        ),
        # the internal development record: the contract declares no certificate, so there is nothing
        # to prefill and nothing to keep: the request's list is the whole truth.
        'certificates': copy.deepcopy(data.get('certificates') or []),
        'restart_policy': data['restart_policy'],
        'portal': portal,
        'healthcheck': healthcheck,
        'health_timeout': data['health_timeout'],
        # the internal development record: the attachment is the administrator's choice,
        # not part of the reviewed contract.
        'network': data.get('network') or {'mode': 'managed'},
    })
    return install, catalog_provenance(detail)


def catalog_install_state(entries, provenance, architecture, observed=None):
    """What the current catalog says about an installed record's origin entry.

    Under tag-following an update means the provider's index lists a newer
    version for the flavour the installed image was built as than the one the
    record carries (the internal development record: the index tracks three flavours per
    application, and the record's ``variant`` -- the pulled image's own label --
    says which one to read; the tag is the fallback, and ``latest`` for records
    the retired signed-snapshot client wrote).  ``observed`` -- the running
    image's own ``(version, variant)`` -- outranks the record on both counts.
    The index runs ahead of the provider's images, so this is a hint: the
    review reads the registry before anything is pulled.  There are no
    revocations any more; the fields stay so that the page keeps its shape.
    """
    result = {
        'update_available': False,
        'revoked': False,
        'revocation_reason': None,
        'catalog_error': None,
    }
    if provenance is None:
        return result
    if not isinstance(provenance, dict) or not isinstance(provenance.get('id'), str):
        raise CatalogContractError('Installed Applications catalog provenance is invalid.')
    match = CATALOG_ID.fullmatch(provenance['id'])
    if match is None:
        raise CatalogContractError('Installed Applications catalog identity is invalid.')
    if not entries:
        result['catalog_error'] = 'Applications catalog has not been fetched.'
        return result
    entry = entries.get(match.group(1))
    if entry is None:
        result['catalog_error'] = 'Installed application is absent from the provider catalog.'
        return result
    observed_version, observed_variant = observed if isinstance(observed, (tuple, list)) else (None, None)
    variant = observed_variant or provenance.get('variant')
    if not isinstance(variant, str) or not variant:
        tag = provenance.get('image_tag')
        variant = image_tag(tag) if isinstance(tag, str) and tag else 'latest'
    current = entry_version(entry, architecture, variant)
    installed = observed_version or provenance.get('version')
    result['update_available'] = bool(current) and version_key(current) != version_key(installed)
    return result


def bind_catalog_update(detail, record, data):
    """Bind a replacement to the current contract and preserved administrator choices."""
    installed = record.get('catalog')
    catalog = detail.get('catalog') or {}
    if (
        not isinstance(installed, dict) or installed.get('id') != data['id'] or
        detail.get('id') != data['id'] or not detail.get('catalog_app') or
        catalog.get('compose_sha256') != data['compose_sha256']
    ):
        raise CatalogContractError(
            'The installed application or reviewed catalog entry changed; review it again.'
        )

    base = detail.get('install')
    if not isinstance(base, dict):
        raise CatalogContractError('Catalog entry does not contain an installable contract.')

    current_ports = record['ports']
    base_ports = base['ports']
    if len(current_ports) != len(base_ports) or any(
        current[field] != expected[field]
        for current, expected in zip(current_ports, base_ports)
        for field in ('container_port', 'protocol')
    ):
        raise CatalogContractError(
            'Updated catalog port declarations are incompatible with the installed application.'
        )
    ports = [
        {**copy.deepcopy(expected), 'host_port': current['host_port']}
        for current, expected in zip(current_ports, base_ports)
    ]

    current_environment = {item['name']: item['value'] for item in record['environment']}
    base_environment = {item['name'] for item in base['environment']}
    if (
        len(current_environment) != len(record['environment']) or
        set(current_environment) != base_environment
    ):
        raise CatalogContractError(
            'Updated catalog environment declarations are incompatible with the installed application.'
        )

    current_volumes = {item['name']: item for item in record['volumes']}
    base_volumes = {item['name']: item for item in base['volumes']}
    if (
        len(current_volumes) != len(record['volumes']) or
        set(current_volumes) != set(base_volumes)
    ):
        raise CatalogContractError(
            'Updated catalog volume declarations are incompatible with the installed application.'
        )
    volumes = []
    for expected in base['volumes']:
        current = copy.deepcopy(current_volumes[expected['name']])
        current.update({
            'target': expected['target'],
            'read_only': expected['read_only'],
        })
        volumes.append(current)

    portal = copy.deepcopy(base['portal'])
    if portal is not None:
        portal_index = next((
            index for index, declared in enumerate(base_ports)
            if declared['protocol'] == 'tcp' and declared['host_port'] == portal['port']
        ), None)
        if portal_index is None:
            raise CatalogContractError('Updated catalog portal is not bound to a reviewed TCP port.')
        if ports[portal_index]['host_port'] is None:
            raise CatalogContractError(
                f'The updated entry opens its web page on container port '
                f'{ports[portal_index]["container_port"]}/tcp, which this application keeps on the '
                'managed bridge; publish that port (Edit) before updating.'
            )
        portal['port'] = ports[portal_index]['host_port']

    healthcheck = copy.deepcopy(base['healthcheck'])
    if healthcheck is not None:
        health_index = next((
            index for index, declared in enumerate(base_ports)
            if (
                declared['protocol'] == 'tcp' and
                declared['container_port'] == healthcheck['container_port'] and
                declared['host_port'] == healthcheck['host_port']
            )
        ), None)
        if health_index is None:
            raise CatalogContractError(
                'Updated catalog health check is not bound to a reviewed TCP port.'
            )
        healthcheck['host_port'] = ports[health_index]['host_port']

    replacement = {
        'name': record['name'],
        'image': base['image'],
        'ports': ports,
        'environment': [
            {'name': name, 'value': current_environment[name]}
            for name in sorted(current_environment)
        ],
        'volumes': volumes,
        'annotations': copy.deepcopy(base['annotations']),
        # the internal development record: labels are the operator's set once installed -- a catalog
        # update keeps them, as it keeps environment values. The contract only prefills them.
        'labels': copy.deepcopy(record.get('labels') or []),
        # the internal development record: runtime options are the provider's, so an update takes the new ones.
        'runtime': copy.deepcopy(base.get('runtime') or {}),
        # the internal development record: the mounted certificates are the operator's too.
        'certificates': copy.deepcopy(record.get('certificates') or []),
        'restart_policy': record['restart_policy'],
        'portal': portal,
        'healthcheck': healthcheck,
    }
    provenance = catalog_provenance(detail)
    changed = (
        version_key(provenance['version']) != version_key(installed.get('version')) or
        provenance['compose_sha256'] != installed.get('compose_sha256')
    )
    return replacement, provenance, changed


class ApplicationsCatalogService(Service):

    class Config:
        namespace = 'applications.catalog'

    def __init__(self, middleware):
        super().__init__(middleware)
        self._catalog_cache = None
        self._catalog_lock = asyncio.Lock()

    @accepts()
    async def providers(self):
        return [{
            'id': PROVIDER_ID,
            'name': PROVIDER_NAME,
            'default': True,
            'type': 'OCI_ORGANIZATION',
            'source_url': PROVIDER_SOURCE_URL,
            'index_url': PROVIDER_INDEX_URL,
            'catalog_url': FJORD_CATALOG_URL,
            'support_owner': 'Daemonless project and image repository maintainers',
            'relationship': PROVIDER_RELATIONSHIP,
        }]

    def _client(self):
        return ProviderClient()

    @staticmethod
    def _architecture():
        return platform.machine()

    def _load_cache(self):
        if self._catalog_cache is None:
            self._catalog_cache = read_cache()
        return self._catalog_cache

    def _save_cache(self, cache):
        try:
            write_cache(cache)
        except (OSError, ValueError, CatalogContractError) as error:
            raise CallError('Unable to persist the Applications catalog cache.') from error
        self._catalog_cache = cache

    @staticmethod
    def _provider_error(error):
        if isinstance(error, (CallError, CatalogContractError)):
            return str(error)
        return f'Applications catalog is temporarily unavailable ({type(error).__name__}).'

    def _entries(self, cache):
        try:
            return catalog_entries(cache, self._architecture())
        except CatalogContractError as error:
            raise CallError(f'Applications catalog is unavailable: {error}') from error

    def _summaries(self, cache, entries):
        stale = is_stale(cache)
        result = []
        for entry in entries.values():
            item = {
                key: copy.deepcopy(value)
                for key, value in entry.items()
                if key in {
                    'architectures',
                    'attribution',
                    'catalog_app',
                    'host_architecture',
                    'id',
                    'name',
                    'provider',
                    'provider_name',
                    'versions',
                    *SUMMARY_FIELDS,
                }
            }
            item.update({
                'catalog': {
                    # The index's ``latest`` assumption; a review reads the image.
                    'version': entry_version(entry, self._architecture()),
                    'version_source': 'index',
                    'source': cache['source'],
                },
                'provenance': {
                    'repository': PROVIDER_REPOSITORY_URL.format(name=entry['name']),
                    'sbom_url': PROVIDER_SBOM_URL.format(name=entry['name']),
                },
                'catalog_stale': stale,
                'catalog_refreshed_at': cache['fetched_at'],
                'catalog_source': cache['source'],
                'provider_error': None,
            })
            result.append(item)
        return sorted(result, key=lambda entry: (entry['title'].casefold(), entry['id']))

    @filterable
    async def query(self, filters=None, options=None):
        async with self._catalog_lock:
            cache = self._load_cache()
            _, entries = self._entries(cache)
            result = self._summaries(cache, entries)
        return filter_list(result, filters, options)

    async def _refresh_impl(self, previous, force_repositories=False):
        client = self._client()
        index = await client.fetch_index()
        now = int(time.time())
        cache = copy.deepcopy(previous)
        cache.update({'source': 'live', 'fetched_at': now, 'index': index})
        if force_repositories or repositories_due(previous, now):
            try:
                cache['repositories'] = await client.fetch_repositories()
                cache['repositories_fetched_at'] = now
            except (CallError, CatalogContractError):
                # Categories and licences come from the budgeted API; keep the
                # last copy and the index still lists every application.
                self.logger.warning('Provider repository metadata is unavailable', exc_info=True)
        # the internal development record: the fjord catalog is optional.  Unreachable keeps
        # the last copy; a format this release does not read drops it, and the
        # repository compose path carries on alone.
        try:
            fjord = await client.fetch_fjord_catalog()
        except (CallError, CatalogContractError) as error:
            self.logger.warning('Provider fjord catalog is unavailable; keeping the last copy: %s', error)
        else:
            if normalize_fjord_catalog(fjord) is None:
                self.logger.warning('Provider fjord catalog is in a format this release does not read.')
                fjord = None
            cache.update({'fjord': fjord, 'fjord_fetched_at': now})
        await self._refresh_icons(client, cache, now)
        # The index must normalise before it replaces the last-known-good copy.
        catalog_entries(cache, self._architecture())
        self._save_cache(cache)
        return cache

    async def _refresh_icons(self, client, cache, now):
        listed = set((cache.get('index') or {}).get('services') or {})
        apps = normalize_fjord_catalog(cache['fjord']) or {}
        due = [
            (name, app['icon_path']) for name, app in sorted(apps.items())
            if name in listed and app['icon_path'] and icon_due(cache, name, app['icon_path'], now)
        ]
        if not due:
            return
        semaphore = asyncio.Semaphore(ICON_FETCH_CONCURRENCY)

        async def fetch(name, path):
            async with semaphore:
                try:
                    store_icon(cache, name, path, await client.fetch_fjord_icon(path), now)
                except (CallError, CatalogContractError) as error:
                    self.logger.debug('Icon for %r is unavailable: %s', name, error)

        tasks = [asyncio.ensure_future(fetch(name, path)) for name, path in due]
        _, pending = await asyncio.wait(tasks, timeout=ICON_FETCH_BUDGET)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
            self.logger.warning('%d provider icons were not fetched within the refresh budget.', len(pending))

    @accepts()
    async def refresh(self):
        async with self._catalog_lock:
            try:
                previous = self._load_cache()
                cache = await self._refresh_impl(previous)
                _, entries = self._entries(cache)
            except (CallError, CatalogContractError) as error:
                raise CallError(f'Applications catalog update failed: {self._provider_error(error)}') from error
            return self._summaries(cache, entries)

    async def _ensure_document(self, cache, store, name, refresh, fetch):
        """A contract document for review: the cached copy while it is current
        (the internal development record), else a fetch, else the cached copy anyway."""
        content = None if refresh else current_document(cache, store, name)
        if content is not None:
            return content
        try:
            fetched = await fetch()
        except (CallError, CatalogContractError) as error:
            cached = cached_document(cache, store, name)
            if cached is not None:
                self.logger.warning('Using the cached contract for %r: %s', name, error)
                return cached
            raise
        # Never older than the index it was fetched for, whatever the clock did.
        now = max(int(time.time()), int(cache.get('fetched_at') or 0))
        store_document(cache, store, name, fetched, now)
        self._save_cache(cache)
        return fetched

    async def _contract(self, cache, entry, refresh):
        """``(store, content, contract or refusal)`` for a review.

        the internal development record: the fjord manifest when the provider's catalog
        lists the application and it can be fetched and rendered; the repository
        compose otherwise.  A refusal of both reports the manifest's reason.
        """
        name = entry['name']
        app = (normalize_fjord_catalog(cache.get('fjord')) or {}).get(name)
        refusal = manifest = None
        if app is not None:
            try:
                manifest = await self._ensure_document(
                    cache, 'manifests', name, refresh,
                    lambda: self._client().fetch_fjord_manifest(app['manifest_path']),
                )
            except (CallError, CatalogContractError) as error:
                self.logger.warning('fjord manifest for %r is unavailable; using the repository compose: %s', name, error)
            if manifest is not None:
                # The repository compose still says what fjord 0.1 does not (CLI
                # images, health checks); its absence only loses that.
                try:
                    await self._ensure_document(
                        cache, 'composes', name, refresh, lambda: self._client().fetch_compose(name),
                    )
                except (CallError, CatalogContractError) as error:
                    self.logger.debug('Repository compose for %r is unavailable: %s', name, error)
                try:
                    return 'manifests', manifest, self._fjord_contract(cache, entry, manifest)
                except CatalogContractError as error:
                    refusal = error
                    self.logger.debug('fjord manifest for %r is refused; trying the repository compose: %s', name, error)
        try:
            content = await self._ensure_document(
                cache, 'composes', name, refresh, lambda: self._client().fetch_compose(name),
            )
        except (CallError, CatalogContractError):
            if refusal is None:
                raise
            return 'manifests', manifest, refusal
        try:
            return 'composes', content, normalize_daemonless_contract(entry, content)
        except CatalogContractError as error:
            return 'composes', content, refusal or error

    @staticmethod
    def _fjord_contract(cache, entry, manifest):
        return normalize_fjord_contract(
            entry, manifest, repository_metadata(cached_document(cache, 'composes', entry['name'])),
        )

    def _preferred_document(self, cache, name):
        """``(store, content)`` a review would read from the cache, or ``(None, None)``."""
        stores = ('manifests', 'composes')
        if name not in (normalize_fjord_catalog(cache.get('fjord')) or {}):
            stores = ('composes', 'manifests')
        for store in stores:
            content = cached_document(cache, store, name)
            if content is not None:
                return store, content
        return None, None

    async def _resolve_image(self, reference):
        """``(inspection, missing)``: the review-time registry observation, and whether
        the registry said the tag does not exist (the internal development record)."""
        try:
            inspection, verdict = await probe_remote_image(
                reference, 'freebsd', self._architecture(), timeout=IMAGE_RESOLUTION_TIMEOUT,
            )
        except Exception:  # noqa: BLE001
            self.logger.debug('Unable to resolve %r at review time', reference, exc_info=True)
            return None, False
        return inspection, verdict == VERDICT_MISSING

    async def _detail(self, cache, entry, content, resolve=True, store='composes', contract=None):
        if entry['status'] == 'UNAVAILABLE':
            return unavailable_detail(entry, entry['reason'])
        if contract is None:
            try:
                if store == 'manifests':
                    contract = self._fjord_contract(cache, entry, content)
                else:
                    contract = normalize_daemonless_contract(entry, content)
            except CatalogContractError as error:
                return unavailable_detail(entry, str(error))
        elif isinstance(contract, CatalogContractError):
            return unavailable_detail(entry, str(contract))
        if entry.get('icon'):
            # The provider's own icon outranks the compose's icon-font shortcode.
            contract['icon'] = entry['icon']
        resolved = None
        if resolve:
            resolved, missing = await self._resolve_image(contract['image_reference'])
            if missing:
                # The provider's compose names a tag its registry does not publish
                # (forgejo and wagtail pin `latest`; ghcr.io has `pkg`, `15`, ...).
                # The pull would fail after the form was filled in; say so now.
                reference = contract['image_reference']
                tag = reference.rsplit(':', 1)[1] if ':' in reference.rsplit('/', 1)[-1] else 'latest'
                contract['image_reference'] = reference
                return unavailable_detail(
                    contract,
                    f"The provider's compose pins image tag {tag!r}, which the registry does not "
                    f'publish ({reference}).',
                )
        tag = image_tag(contract['image_reference'])
        detail = finalize_tag_contract(contract, resolved)
        # the internal development record: the version the page shows is the one the tag
        # resolves to right now, as the image itself states it.  Only an
        # unreachable registry falls back to the index, which tracks the pinned
        # flavour at best and says so.
        version, variant = image_version((resolved or {}).get('labels'))
        version_source = 'image'
        if version is None:
            version = entry_version(entry, self._architecture(), tag)
            version_source = 'index'
        detail['catalog'] = {
            'version': version,
            'variant': variant if variant is not None else tag,
            'version_source': version_source,
            'compose_sha256': sha256_hex(content),
            'source': cache['source'],
            'fetched_at': cache[store].get(entry['name'], {}).get('fetched_at', 0),
        }
        source_path = 'compose.yaml' if store == 'composes' else f'manifests/{entry["name"]}.yaml'
        detail['provenance'] = {
            'repository': PROVIDER_REPOSITORY_URL.format(name=entry['name']),
            'source_path': source_path,
            'source_url': (
                PROVIDER_COMPOSE_URL.format(name=entry['name']) if store == 'composes'
                else f'{FJORD_BASE_URL}{source_path}'
            ),
            'compose_sha256': detail['catalog']['compose_sha256'],
            'sbom_url': PROVIDER_SBOM_URL.format(name=entry['name']),
            'upstream_url': (detail.get('links') or {}).get('upstream'),
            'index_updated_at': (cache.get('index') or {}).get('last_check'),
        }
        detail.update({
            'catalog_stale': is_stale(cache),
            'catalog_refreshed_at': cache['fetched_at'],
            'catalog_source': cache['source'],
            'provider_error': None,
        })
        return detail

    def _entry(self, entries, id_):
        name = CATALOG_ID.fullmatch(id_).group(1)
        entry = entries.get(name)
        if entry is None:
            raise CallError(f'Catalog entry {id_!r} does not exist.', errno.ENOENT)
        return entry

    @accepts(
        Str('id', validators=[Match(CATALOG_ID.pattern)]),
        Dict('options', Bool('refresh', default=False), default={}),
    )
    async def details(self, id_, options):
        async with self._catalog_lock:
            try:
                cache = self._load_cache()
                if options['refresh']:
                    cache = await self._refresh_impl(cache)
                _, entries = self._entries(cache)
                entry = self._entry(entries, id_)
                if entry['status'] == 'UNAVAILABLE':
                    return await self._detail(cache, entry, None, resolve=False)
                try:
                    store, content, contract = await self._contract(cache, entry, options['refresh'])
                except ProviderNotFound:
                    # the internal development record: one entry without a compose file upstream
                    # (immich-cli) is that entry's condition, not the catalog's.
                    return unavailable_detail(
                        entry, 'The provider publishes no compose contract for this application.',
                    )
                return await self._detail(cache, entry, content, store=store, contract=contract)
            except (CallError, CatalogContractError) as error:
                if isinstance(error, CallError) and error.errno == errno.ENOENT:
                    raise
                raise CallError(f'Applications catalog is unavailable: {self._provider_error(error)}') from error

    async def _reviewed_detail(self, id_, resolve=False, compose_sha256=None):
        """The contract exactly as it is cached; never a provider fetch.

        ``compose_sha256`` picks the document that was reviewed -- a fjord manifest
        or a repository compose (the internal development record); without a match the
        document a review would read is bound, and its hash then refuses.
        ``resolve`` asks the registry what the tag is right now (the same
        observation a review makes) without touching the cached contract.
        """
        cache = self._load_cache()
        _, entries = self._entries(cache)
        entry = self._entry(entries, id_)
        store, content = document_by_hash(cache, entry['name'], compose_sha256)
        if content is None:
            store, content = self._preferred_document(cache, entry['name'])
        if content is None:
            raise CallError(
                f'Catalog entry {id_!r} has not been reviewed on this system; review it before installing.'
            )
        return await self._detail(cache, entry, content, resolve=resolve, store=store)

    @private
    async def bind_install(self, data):
        """Bind an install request to the reviewed contract (used by the converter too)."""
        async with self._catalog_lock:
            detail = await self._reviewed_detail(data['id'], compose_sha256=data['compose_sha256'])
            if not detail.get('available'):
                raise CallError(
                    f'Catalog entry {data["id"]!r} is not installable: {detail.get("reason")}'
                )
            try:
                return bind_catalog_install(detail, data)
            except CatalogContractError as error:
                raise CallError(str(error)) from error

    @accepts(CATALOG_INSTALL_SCHEMA)
    @job()
    async def install(self, job, data):
        install, provenance = await self.bind_install(data)
        subjob = await self.middleware.call(
            'applications.install_catalog', install, provenance
        )
        try:
            return await job.wrap(subjob)
        except CallError:
            # job.wrap reports any failure of the inner job as a CallError whose
            # text is the inner traceback. A refusal by install validation is a
            # ValidationErrors naming the fields; hand it on as it was raised so
            # the caller gets those field errors (the internal development record).
            error = (getattr(subjob, 'exc_info', None) or (None, None))[1]
            if isinstance(error, ValidationErrors):
                raise error
            raise

    @accepts(CATALOG_UPDATE_SCHEMA)
    @job()
    async def update(self, job, data):
        expected_record = await self.middleware.call(
            'applications.catalog_record', data['name']
        )
        async with self._catalog_lock:
            # the internal development record: whether anything changed is decided against
            # the image the tag resolves to, not the index; the pull that follows
            # needs the registry anyway.
            detail = await self._reviewed_detail(
                data['id'], resolve=True, compose_sha256=data['compose_sha256'],
            )
            if not detail.get('available'):
                raise CallError(
                    f'Catalog entry {data["id"]!r} is not installable: {detail.get("reason")}'
                )
            try:
                replacement, provenance, changed = bind_catalog_update(
                    detail, expected_record, data
                )
            except CatalogContractError as error:
                raise CallError(str(error)) from error

        if not changed and not data['recreate']:
            return await self.middleware.call(
                'applications.query', [('name', '=', data['name'])], {'get': True}
            )
        subjob = await self.middleware.call(
            'applications.update_catalog',
            expected_record,
            replacement,
            provenance,
            data['health_timeout'],
        )
        return await job.wrap(subjob)

    @private
    async def installed_state(self, provenances, observed=None):
        if observed is None:
            observed = [None for _ in provenances]
        async with self._catalog_lock:
            cache = self._load_cache()
            try:
                _, entries = catalog_entries(cache, self._architecture())
                return [
                    catalog_install_state(entries, provenance, self._architecture(), seen)
                    for provenance, seen in zip(provenances, observed)
                ]
            except CatalogContractError as error:
                raise CallError(f'Applications catalog is unavailable: {error}') from error
