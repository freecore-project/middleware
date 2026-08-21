import base64
import copy
import math
import hashlib
import ipaddress
import re
from urllib.parse import urlsplit

import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode

from middlewared.plugins.applications_.utils import (
    CATALOG_RUNTIME_ANNOTATIONS,
    NETWORK_OWNED_ANNOTATIONS,
    validate_image_reference,
    validate_mount_target,
)

PROVIDER_ID = 'daemonless'
PROVIDER_NAME = 'Daemonless'
PROVIDER_ORGANIZATION = 'daemonless'
PROVIDER_SOURCE_URL = 'https://github.com/daemonless'
PROVIDER_RELATIONSHIP = (
    'Independent upstream catalog provider; no FreeCORE or iXsystems partnership is implied.'
)
CATALOG_ID = re.compile(r'^daemonless:([a-z0-9][a-z0-9._-]{0,62})$')
SERVICE_NAME = re.compile(r'^[a-z0-9][a-z0-9._-]{0,62}$')
ENVIRONMENT_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
ANNOTATION_NAME = re.compile(r'^org\.freebsd\.jail\.[a-z0-9_.-]+$')
# the internal development record: container labels declared by a catalog Compose service.
LABEL_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._/-]{0,253}$')
RESERVED_LABEL_PREFIX = 'io.freecore.'
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
TAG = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$')
# the internal development record: what an image says about itself.  The version label is
# the only statement of what a tag contains; the variant label names the
# provider's flavour it was built as (``latest``, ``pkg``, ``pkg-latest``, or a
# multi-version key such as ``18`` / ``14-pkg``).
IMAGE_VERSION_LABEL = 'org.opencontainers.image.version'
IMAGE_VARIANT_LABEL = 'io.daemonless.variant'
IMAGE_VERSION = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+,:~-]{0,127}$')
# The provider's published flavours and the version-index field that tracks each
# (their README: ``:latest`` upstream binaries, ``:pkg`` quarterly packages,
# ``:pkg-latest`` rolling packages).
FLAVOUR_FIELDS = {'latest': 'upstream', 'pkg': 'pkg', 'pkg-latest': 'pkg-latest'}
# Which index field to read for an image whose flavour is not known -- the
# provider's default tag is ``latest`` and most of its ``latest`` images are the
# upstream build.
DEFAULT_FLAVOUR_ORDER = ('upstream', 'pkg-latest', 'pkg')
# What an installed record remembers about the catalog entry it came from, and
# the field records written before #463 do not carry.
CATALOG_FIELDS = {'id', 'version', 'compose_sha256', 'repository', 'image_tag'}
OPTIONAL_CATALOG_FIELDS = {'variant'}
ICON = re.compile(r'^:[a-z0-9-]+:$')
PORTAL_PATH = re.compile(r'^/(?!/)[^\x00\r\n]*$')
MAX_COMPOSE_SIZE = 1024 * 1024
MAX_YAML_NODES = 20_000
MAX_YAML_DEPTH = 16

# the internal development record: the provider's fjord catalog (catalog.daemonless.io) --
# one listing with icons and presentation, and per application a manifest: the
# compose written with ``${VAR}`` references plus typed install variables.  Only
# the versions below are read; anything else leaves the repository compose path
# in charge, exactly as before fjord existed.
FJORD_VERSIONS = {'0.1'}
# the internal development record: 'public_url' (fjord 0.1, daemonless/fjord#103) is the address the app is opened at:
# an environment value, http(s)://host[:port][/path] when set.
FJORD_VARIABLE_TYPES = {'string', 'secret', 'port', 'path', 'zfs_dataset', 'image_tag', 'public_url'}
FJORD_STORAGE_TYPES = {'path', 'zfs_dataset'}
FJORD_MANIFEST_PATH = re.compile(r'^manifests/([a-z0-9][a-z0-9._-]{0,62})\.yaml$')
FJORD_ICON_PATH = re.compile(r'^icons/[a-z0-9][a-z0-9._-]{0,62}\.(?:svg|png)$')
FJORD_REFERENCE = re.compile(r'\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?-)([^${}]*))?\}')
MAX_FJORD_VARIABLES = 256
# Icons are presentation.  They reach the page as data URIs inside <img>, where an
# SVG can neither run script nor load anything; the checks below are defence in
# depth, and anything they refuse falls back to the placeholder tile.
MAX_ICON_SIZE = 64 * 1024
ICON_MAGIC = (
    (b'\x89PNG\r\n\x1a\n', 'image/png'),
    (b'\xff\xd8\xff', 'image/jpeg'),
    (b'GIF87a', 'image/gif'),
    (b'GIF89a', 'image/gif'),
)
UNSAFE_SVG = re.compile(
    r'<!DOCTYPE|<!ENTITY|<script|<foreignObject|javascript:|@import|'
    r'\son[a-z]+\s*=|'
    r'''(?:xlink:)?href\s*=\s*["'](?!#|data:image/(?:png|jpeg|gif|webp);base64,)|'''
    r'''url\(\s*["']?(?!#|data:image/(?:png|jpeg|gif|webp);base64,)''',
    re.IGNORECASE,
)

UPSTREAM_CATALOG_ANNOTATIONS = {
    'org.freebsd.jail.allow.mlock': {'true'},
    'org.freebsd.jail.allow.raw_sockets': {'true'},
    'org.freebsd.jail.allow.sysvipc': {'true'},
}
SYSVIPC_ANNOTATION = 'org.freebsd.jail.allow.sysvipc'

CATEGORIES = {
    'Base',
    'Databases',
    'Development',
    'Downloaders',
    'Entertainment',
    'Health & Fitness',
    'Infrastructure',
    'Media Management',
    'Media Servers',
    'Monitoring',
    'Network',
    'Photos & Media',
    'Productivity',
    'Utilities',
}
CATEGORY_TOPICS = {
    'base': 'Base',
    'databases': 'Databases',
    'development': 'Development',
    'downloaders': 'Downloaders',
    'entertainment': 'Entertainment',
    'health-fitness': 'Health & Fitness',
    'infrastructure': 'Infrastructure',
    'media-management': 'Media Management',
    'media-servers': 'Media Servers',
    'network': 'Network',
    'photos-media': 'Photos & Media',
    'productivity': 'Productivity',
    'utilities': 'Utilities',
}
SUPPORTED_SERVICE_KEYS = {
    'annotations',
    'container_name',
    'environment',
    'image',
    'labels',
    'ports',
    'restart',
    # the internal development record: names the container resolves to fixed addresses (OpenCloud's own host name).
    'extra_hosts',
    # the internal development record: how long a stop waits before it kills (ClickHouse asks for 60 s).
    'stop_grace_period',
    'volumes',
}
# the internal development record: a host name extra_hosts may pin, and how many.
HOST_ALIAS = re.compile(r'^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')
MAX_EXTRA_HOSTS = 64
# the internal development record: a Compose duration ("60s", "1m30s", "500ms"), Go time.ParseDuration's units.
COMPOSE_DURATION = re.compile(r'(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)')
DURATION_UNITS = {'ns': 1e-9, 'us': 1e-6, 'µs': 1e-6, 'ms': 1e-3, 's': 1, 'm': 60, 'h': 3600}
MAX_STOP_TIMEOUT = 3600
SUPPORTED_ROOT_KEYS = {'name', 'services', 'volumes', 'x-daemonless'}


class CatalogContractError(ValueError):
    pass


class StrictCatalogLoader(yaml.SafeLoader):

    def compose_node(self, parent, index):
        if self.check_event(AliasEvent):
            raise CatalogContractError('YAML aliases are not supported in catalog contracts.')
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, MappingNode):
            raise CatalogContractError('Catalog mapping is malformed.')
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as error:
                raise CatalogContractError('Catalog mapping keys must be scalar.') from error
            if duplicate:
                raise CatalogContractError(f'Duplicate YAML mapping key {key!r}.')
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _validate_yaml_tree(value, depth=0, budget=None):
    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > MAX_YAML_NODES:
        raise CatalogContractError('Catalog contract contains too many YAML nodes.')
    if depth > MAX_YAML_DEPTH:
        raise CatalogContractError('Catalog contract is nested too deeply.')

    if value is None or type(value) in {bool, int, float, str}:
        if isinstance(value, str) and len(value) > 65536:
            raise CatalogContractError('Catalog contract contains an oversized string.')
        return
    if isinstance(value, list):
        for item in value:
            _validate_yaml_tree(item, depth + 1, budget)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if type(key) not in {bool, int, float, str}:
                raise CatalogContractError('Catalog mapping keys must be scalar.')
            _validate_yaml_tree(item, depth + 1, budget)
        return
    raise CatalogContractError(f'Unsupported YAML object type {type(value).__name__!r}.')


def parse_catalog_yaml(content):
    if not isinstance(content, str):
        raise CatalogContractError('Catalog contract must be UTF-8 text.')
    if '\x00' in content:
        raise CatalogContractError('Catalog contract contains a NUL character.')
    if len(content.encode('utf-8')) > MAX_COMPOSE_SIZE:
        raise CatalogContractError('Catalog contract exceeds the maximum supported size.')

    try:
        data = yaml.load(content, Loader=StrictCatalogLoader)
    except CatalogContractError:
        raise
    except yaml.YAMLError as error:
        raise CatalogContractError(f'Catalog contract is not valid YAML: {error}.') from error

    _validate_yaml_tree(data)
    if not isinstance(data, dict):
        raise CatalogContractError('Catalog contract root must be a mapping.')
    return data


def normalize_architecture(machine):
    architecture = str(machine or '').lower()
    if architecture in {'amd64', 'x86_64'}:
        return 'amd64'
    if architecture in {'aarch64', 'arm64'}:
        return 'aarch64'
    return architecture


def _clean_text(value, field, maximum, required=True):
    if value is None and not required:
        return None
    if not isinstance(value, str):
        raise CatalogContractError(f'{field} must be text.')
    result = re.sub(r'\s+', ' ', value).strip()
    if required and not result:
        raise CatalogContractError(f'{field} must not be empty.')
    if len(result) > maximum:
        raise CatalogContractError(f'{field} exceeds {maximum} characters.')
    return result


def _https_url(value, field, expected=None, required=True):
    if value is None and not required:
        return None
    value = _clean_text(value, field, 2048, required=required)
    if value in {None, ''} and not required:
        return None
    parsed = urlsplit(value)
    if (
        parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or
        parsed.hostname != parsed.hostname.lower()
    ):
        raise CatalogContractError(f'{field} must be an HTTPS URL without embedded credentials.')
    if expected is not None and value.rstrip('/') != expected.rstrip('/'):
        raise CatalogContractError(f'{field} does not match the expected provider identity.')
    return value


def _humanize(name):
    return ' '.join(component.capitalize() for component in re.split(r'[-_.]+', name) if component)


def _normalize_versions(data, arches):
    if not isinstance(data, dict):
        raise CatalogContractError('Version index service entry must be a mapping.')

    def arch_map(value, field):
        if not isinstance(value, dict) or not value:
            raise CatalogContractError(f'{field} must be a non-empty architecture mapping.')
        result = {}
        for arch, version in value.items():
            if arch not in arches:
                raise CatalogContractError(f'{field} contains unsupported architecture {arch!r}.')
            result[arch] = _clean_text(version, f'{field}.{arch}', 128)
        return dict(sorted(result.items()))

    result = {}
    for field in ('pkg', 'pkg-latest'):
        if field in data:
            result[field] = arch_map(data[field], field)
    if 'upstream' in data:
        result['upstream'] = _clean_text(data['upstream'], 'upstream version', 128)

    if 'type' in data:
        if data['type'] != 'multi-version':
            raise CatalogContractError('Version index contains an unsupported service type.')
        result['type'] = data['type']
    if 'default' in data:
        result['default'] = _clean_text(data['default'], 'default version', 128)
    if 'variants' in data:
        variants = data['variants']
        if not isinstance(variants, dict) or len(variants) > 128:
            raise CatalogContractError('Version variants must be a bounded mapping.')
        result['variants'] = {}
        for variant, variant_data in sorted(variants.items()):
            variant = _clean_text(variant, 'version variant', 128)
            if not isinstance(variant_data, dict):
                raise CatalogContractError('Version variant must be a mapping.')
            normalized = {}
            for field, versions in variant_data.items():
                if not isinstance(field, str) or not re.fullmatch(r'[a-z0-9-]{1,64}', field):
                    raise CatalogContractError('Version variant type is invalid.')
                normalized[field] = arch_map(versions, f'variants.{variant}.{field}')
            result['variants'][variant] = normalized
    return result


def _architecture_maps(data, allowed):
    found = []
    if isinstance(data, dict):
        keys = set(data)
        if keys and keys <= allowed and all(isinstance(value, str) for value in data.values()):
            found.append(keys)
        else:
            for value in data.values():
                found.extend(_architecture_maps(value, allowed))
    return found


def _service_architectures(versions, global_arches):
    allowed = set(global_arches)
    source = versions
    if versions.get('type') == 'multi-version' and versions.get('default'):
        source = versions.get('variants', {}).get(versions['default'], versions)
    mappings = _architecture_maps(source, allowed)
    if not mappings:
        return sorted(allowed)
    return sorted(set().union(*mappings))


def _normalize_repo(repo, expected_name):
    expected_url = f'https://github.com/{PROVIDER_ORGANIZATION}/{expected_name}'
    if not isinstance(repo, dict):
        raise CatalogContractError('Repository metadata must be a mapping.')
    if repo.get('name') != expected_name:
        raise CatalogContractError('Repository metadata name does not match the version index.')
    owner = repo.get('owner')
    if not isinstance(owner, dict) or owner.get('login') != PROVIDER_ORGANIZATION:
        raise CatalogContractError('Repository owner does not match the expected provider identity.')
    source_url = _https_url(repo.get('html_url'), 'repository URL', expected=expected_url)
    if repo.get('visibility') != 'public' or repo.get('private') is True:
        raise CatalogContractError('Catalog repository is not public.')
    if repo.get('default_branch') != 'main':
        raise CatalogContractError('Catalog repository does not use the expected main branch.')

    topics = repo.get('topics') or []
    if not isinstance(topics, list) or len(topics) > 128:
        raise CatalogContractError('Repository topics are malformed.')
    topics = sorted({
        _clean_text(topic, 'repository topic', 128)
        for topic in topics
        if isinstance(topic, str)
    })
    category = next((CATEGORY_TOPICS[topic] for topic in topics if topic in CATEGORY_TOPICS), 'Other')

    license_data = repo.get('license')
    license_id = None
    if isinstance(license_data, dict) and license_data.get('spdx_id') not in {None, 'NOASSERTION'}:
        candidate = _clean_text(license_data['spdx_id'], 'repository license', 128)
        if re.fullmatch(r'[A-Za-z0-9.+-]+', candidate):
            license_id = candidate

    return {
        'source_url': source_url,
        'support_url': f'{expected_url}/issues',
        'description': _clean_text(repo.get('description') or '', 'repository description', 2048, False),
        'category': category,
        'topics': topics,
        'license': license_id,
        'archived': repo.get('archived') is True,
        'disabled': repo.get('disabled') is True,
    }


def normalize_catalog_index(index, repository_pages, architecture):
    architecture = normalize_architecture(architecture)
    if not isinstance(index, dict) or index.get('schema_version') != 2:
        raise CatalogContractError('Daemonless version index must use schema version 2.')
    arches = index.get('arches')
    if (
        not isinstance(arches, list) or not arches or len(arches) > 16 or
        any(arch not in {'amd64', 'aarch64'} for arch in arches) or
        len(set(arches)) != len(arches)
    ):
        raise CatalogContractError('Daemonless version index architectures are invalid.')
    services = index.get('services')
    if not isinstance(services, dict) or not services or len(services) > 512:
        raise CatalogContractError('Daemonless version index service set is invalid.')

    repository_metadata_available = repository_pages is not None
    if repository_metadata_available and (
        not isinstance(repository_pages, list) or not repository_pages
    ):
        raise CatalogContractError('Repository metadata pages are missing.')
    repositories = {}
    for page in repository_pages or []:
        if not isinstance(page, list) or len(page) > 100:
            raise CatalogContractError('Repository metadata page is malformed.')
        for repo in page:
            if not isinstance(repo, dict) or not isinstance(repo.get('name'), str):
                raise CatalogContractError('Repository metadata entry is malformed.')
            if repo['name'] in repositories:
                raise CatalogContractError(f'Duplicate repository metadata for {repo["name"]!r}.')
            repositories[repo['name']] = repo

    entries = []
    for name, version_data in sorted(services.items()):
        if not isinstance(name, str) or not SERVICE_NAME.fullmatch(name):
            raise CatalogContractError(f'Version index service name {name!r} is invalid.')
        versions = _normalize_versions(version_data, set(arches))
        service_arches = _service_architectures(versions, arches)
        unavailable_reason = None
        try:
            if repository_metadata_available:
                repo = _normalize_repo(repositories.get(name), name)
            else:
                raise LookupError
        except (CatalogContractError, LookupError) as error:
            repo = {
                'source_url': f'https://github.com/{PROVIDER_ORGANIZATION}/{name}',
                'support_url': f'https://github.com/{PROVIDER_ORGANIZATION}/{name}/issues',
                'description': '',
                'category': 'Other',
                'topics': [],
                'license': None,
                'archived': False,
                'disabled': False,
            }
            if repository_metadata_available:
                unavailable_reason = str(error)

        if repo['archived'] or repo['disabled']:
            unavailable_reason = 'Provider repository is archived or disabled.'
        elif 'base' in repo['topics']:
            unavailable_reason = 'Base images are not installable Applications.'
        elif architecture not in service_arches:
            unavailable_reason = f'Provider does not publish this Application for {architecture!r}.'

        status = 'UNAVAILABLE' if unavailable_reason else 'UNRESOLVED'
        entries.append({
            'id': f'{PROVIDER_ID}:{name}',
            'name': name,
            'provider': PROVIDER_ID,
            'provider_name': PROVIDER_NAME,
            'catalog_app': True,
            'title': _humanize(name),
            'category': repo['category'],
            'description': repo['description'],
            'icon': None,
            'architectures': service_arches,
            'host_architecture': architecture,
            'resolved': bool(unavailable_reason),
            'available': False,
            'status': status,
            'reason': unavailable_reason,
            'versions': versions,
            'attribution': {
                'provider': PROVIDER_NAME,
                'source_url': repo['source_url'],
                'support_url': repo['support_url'],
                'support_owner': 'Daemonless project and image repository maintainers',
                'license': repo['license'],
                'relationship': PROVIDER_RELATIONSHIP,
            },
        })

    return {
        'provider': PROVIDER_ID,
        'provider_name': PROVIDER_NAME,
        'architecture': architecture,
        'schema_version': index['schema_version'],
        'index_updated_at': _clean_text(index.get('last_check'), 'version index timestamp', 128),
        'repository_metadata_available': repository_metadata_available,
        'entries': entries,
    }


def unavailable_detail(entry, reason):
    result = copy.deepcopy(entry)
    result.update({
        'resolved': True,
        'available': False,
        'status': 'UNAVAILABLE',
        'reason': _clean_text(str(reason), 'unavailable reason', 4096),
        'image': None,
        'environment': [],
        'volumes': [],
        'ports': [],
        'annotations': [],
        'labels': [],
        'health': None,
        'portal': None,
        'install': None,
    })
    return result


def _docs_map(metadata, field):
    docs = metadata.get('docs') or {}
    if not isinstance(docs, dict):
        raise CatalogContractError('x-daemonless.docs must be a mapping.')
    values = docs.get(field) or {}
    if not isinstance(values, dict) or len(values) > 512:
        raise CatalogContractError(f'x-daemonless.docs.{field} must be a bounded mapping.')
    result = {}
    for key, description in values.items():
        key = str(key)
        if isinstance(description, str):
            result[key] = {
                'description': _clean_text(description, f'{field} description', 1024),
            }
            continue
        if not isinstance(description, dict):
            raise CatalogContractError(f'{field} description must be text or a metadata mapping.')
        allowed = {
            # the internal development record: `sensitive` is what a fjord `secret`
            # variable says about the environment entry it feeds.
            'env': {'default', 'desc', 'optional', 'sensitive'},
            'volumes': {'desc', 'optional'},
            'ports': {'desc'},
        }[field]
        # the internal development record: documentation metadata is presentation, not
        # execution. A provider adding a doc key (the 2026-09-29 Daemonless
        # format carries `level` on env entries) must not make the entry
        # unavailable; unknown keys are ignored and the known ones keep their
        # strict shapes.
        description = {key_: value for key_, value in description.items() if key_ in allowed}
        normalized = {
            'description': _clean_text(description.get('desc'), f'{field} description', 1024),
        }
        if 'default' in description:
            default = description['default']
            if type(default) not in {bool, int, float, str}:
                raise CatalogContractError(f'{field} documented default must be scalar.')
            normalized['documented_default'] = (
                str(default).lower() if isinstance(default, bool) else str(default)
            )
        if 'optional' in description:
            if type(description['optional']) is not bool:
                raise CatalogContractError(f'{field} optional flag must be boolean.')
            normalized['optional'] = description['optional']
        if 'sensitive' in description:
            if type(description['sensitive']) is not bool:
                raise CatalogContractError(f'{field} sensitive flag must be boolean.')
            normalized['sensitive'] = description['sensitive']
        result[key] = normalized
    return result


def _normalize_environment(service, metadata):
    source = service.get('environment') or []
    if not isinstance(source, (list, dict)) or len(source) > 128:
        raise CatalogContractError('Service environment must be a bounded list or mapping.')
    descriptions = _docs_map(metadata, 'env')
    values = []
    if isinstance(source, dict):
        values = list(source.items())
    else:
        for value in source:
            if not isinstance(value, str) or '=' not in value:
                raise CatalogContractError('Environment list entries must use NAME=value syntax.')
            values.append(value.split('=', 1))

    result = []
    names = set()
    for name, value in values:
        if not isinstance(name, str) or not ENVIRONMENT_NAME.fullmatch(name) or name in names:
            raise CatalogContractError('Environment variable names must be valid and unique.')
        names.add(name)
        if value is None:
            default = ''
            required = True
        elif type(value) in {bool, int, float, str}:
            default = str(value).lower() if isinstance(value, bool) else str(value)
            required = False
        else:
            raise CatalogContractError(f'Environment value for {name!r} must be scalar.')
        if '${' in default or any(character in default for character in ('\x00', '\r', '\n')):
            raise CatalogContractError('Compose environment interpolation and multiline values are unsupported.')
        if len(default) > 65536:
            raise CatalogContractError(f'Environment value for {name!r} is too large.')
        documentation = descriptions.get(name, {})
        sensitive = bool(
            re.search(r'(?:PASSWORD|PASSWD|SECRET|TOKEN|PRIVATE_KEY|CREDENTIAL)', name, re.IGNORECASE) or
            documentation.get('sensitive')
        )
        result.append({
            'name': name,
            'default': default,
            'required': required,
            'sensitive': sensitive,
            'description': documentation.get('description'),
            'documented_default': documentation.get('documented_default'),
        })
    return sorted(result, key=lambda item: item['name'])


def _volume_name(target):
    value = re.sub(r'[^a-z0-9]+', '-', target.strip('/').lower()).strip('-') or 'data'
    if len(value) > 63:
        value = f'{value[:54].rstrip("-")}-{hashlib.sha256(target.encode()).hexdigest()[:8]}'
    return value


def _normalize_volumes(service, metadata):
    source = service.get('volumes') or []
    if not isinstance(source, list) or len(source) > 128:
        raise CatalogContractError('Service volumes must be a bounded list.')
    descriptions = _docs_map(metadata, 'volumes')
    result = []
    names = set()
    targets = set()
    for value in source:
        if not isinstance(value, str) or '${' in value:
            raise CatalogContractError('Only static short-form Compose volumes are supported.')
        parts = value.split(':')
        if len(parts) not in {2, 3} or not parts[0] or not parts[1]:
            raise CatalogContractError('Compose volume must use source:target[:ro|rw] syntax.')
        target = parts[1]
        try:
            validate_mount_target(target)
        except ValueError as error:
            raise CatalogContractError(str(error)) from error
        mode = parts[2] if len(parts) == 3 else 'rw'
        if mode not in {'ro', 'rw'}:
            raise CatalogContractError('Compose volume mode must be ro or rw.')
        if target in targets:
            raise CatalogContractError('Container volume targets must be unique.')
        targets.add(target)
        name = _volume_name(target)
        if name in names:
            name = f'{name[:54].rstrip("-")}-{hashlib.sha256(target.encode()).hexdigest()[:8]}'
        names.add(name)
        documentation = descriptions.get(target, {})
        result.append({
            'name': name,
            'target': target,
            'read_only': mode == 'ro',
            'description': documentation.get('description'),
            'optional': documentation.get('optional', False),
            'storage': 'MIDDLEWARE_MANAGED_DATASET',
        })
    return sorted(result, key=lambda item: item['name'])


def _port_description(descriptions, container_port, protocol):
    documentation = descriptions.get(f'{container_port}/{protocol}') or descriptions.get(str(container_port)) or {}
    return documentation.get('description')


def _normalize_ports(service, metadata):
    source = service.get('ports') or []
    if not isinstance(source, list) or len(source) > 256:
        raise CatalogContractError('Service ports must be a bounded list.')
    descriptions = _docs_map(metadata, 'ports')
    result = []
    published = set()
    for value in source:
        protocol = 'tcp'
        if isinstance(value, str):
            if '${' in value:
                raise CatalogContractError('Compose port interpolation is unsupported.')
            port_value, separator, suffix = value.partition('/')
            if separator:
                protocol = suffix
            parts = port_value.split(':')
            if len(parts) != 2 or not all(part.isdigit() for part in parts):
                raise CatalogContractError('Compose ports must use published:target[/protocol] syntax.')
            host_port, container_port = map(int, parts)
        elif isinstance(value, dict):
            if set(value) - {'published', 'target', 'protocol'}:
                raise CatalogContractError('Long-form Compose port contains unsupported fields.')
            host_port = value.get('published')
            container_port = value.get('target')
            protocol = value.get('protocol', 'tcp')
            if type(host_port) is not int or type(container_port) is not int:
                raise CatalogContractError('Long-form Compose ports require integer published and target ports.')
        else:
            raise CatalogContractError('Compose port entry is malformed.')
        if protocol not in {'tcp', 'udp'} or not 1 <= host_port <= 65535 or not 1 <= container_port <= 65535:
            raise CatalogContractError('Compose port or protocol is invalid.')
        key = (host_port, protocol)
        if key in published:
            raise CatalogContractError('Published port/protocol pairs must be unique.')
        published.add(key)
        result.append({
            'host_port': host_port,
            'container_port': container_port,
            'protocol': protocol,
            'description': _port_description(descriptions, container_port, protocol),
        })
    return sorted(result, key=lambda item: (item['host_port'], item['protocol'], item['container_port']))


def _normalize_labels(service):
    """the internal development record: a service's `labels:`, as a mapping or NAME=value list.

    Reserved `io.freecore.` names make the entry unavailable, exactly as an unsupported key
    does today -- a provider must not be able to declare a label that impersonates one of
    FreeCORE's own management labels.
    """
    source = service.get('labels') or {}
    if isinstance(source, list):
        values = []
        for value in source:
            if not isinstance(value, str) or '=' not in value:
                raise CatalogContractError('Label list entries must use NAME=value syntax.')
            values.append(value.split('=', 1))
    elif isinstance(source, dict):
        values = list(source.items())
    else:
        raise CatalogContractError('Service labels must be a list or mapping.')
    if len(values) > 128:
        raise CatalogContractError('Service contains too many container labels.')

    result = []
    names = set()
    for name, value in values:
        if not isinstance(name, str) or not LABEL_NAME.fullmatch(name) or name in names:
            raise CatalogContractError('Container label names must be valid and unique.')
        if name.startswith(RESERVED_LABEL_PREFIX):
            raise CatalogContractError(
                f'Container label {name!r} is reserved for FreeCORE\'s own management labels.'
            )
        names.add(name)
        if type(value) not in {bool, int, float, str}:
            raise CatalogContractError(f'Container label {name!r} must have a scalar value.')
        value = str(value).lower() if isinstance(value, bool) else str(value)
        if len(value.encode()) > 4096 or any(character in value for character in ('\x00', '\r', '\n')):
            raise CatalogContractError(f'Container label {name!r} has an invalid value.')
        result.append({'name': name, 'value': value})
    return sorted(result, key=lambda item: item['name'])


def _normalize_annotations(service):
    source = service.get('annotations') or {}
    if isinstance(source, list):
        values = []
        for value in source:
            if not isinstance(value, str) or '=' not in value:
                raise CatalogContractError('Annotation list entries must use NAME=value syntax.')
            values.append(value.split('=', 1))
    elif isinstance(source, dict):
        values = list(source.items())
    else:
        raise CatalogContractError('Service annotations must be a list or mapping.')
    if len(values) > 128:
        raise CatalogContractError('Service contains too many jail annotations.')

    result = []
    names = set()
    for name, value in values:
        if not isinstance(name, str) or not ANNOTATION_NAME.fullmatch(name) or name in names:
            raise CatalogContractError('Jail annotation names must be valid and unique.')
        if name in NETWORK_OWNED_ANNOTATIONS:
            raise CatalogContractError(f'Jail annotation {name!r} is owned by the managed network.')
        names.add(name)
        if type(value) not in {bool, int, float, str}:
            raise CatalogContractError(f'Jail annotation {name!r} must have a scalar value.')
        value = str(value).lower() if isinstance(value, bool) else str(value)
        if len(value) > 4096 or any(character in value for character in ('\x00', '\r', '\n')):
            raise CatalogContractError(f'Jail annotation {name!r} has an invalid value.')
        if value not in UPSTREAM_CATALOG_ANNOTATIONS.get(name, set()):
            raise CatalogContractError(f'Jail annotation {name!r} is not permitted for catalog applications.')
        if name == SYSVIPC_ANNOTATION:
            result.extend(
                {'name': runtime_name, 'value': 'new'}
                for runtime_name in (
                    'org.freebsd.jail.sysvmsg',
                    'org.freebsd.jail.sysvsem',
                    'org.freebsd.jail.sysvshm',
                )
            )
        else:
            result.append({'name': name, 'value': value})
    if any(item['value'] not in CATALOG_RUNTIME_ANNOTATIONS.get(item['name'], set()) for item in result):
        raise CatalogContractError('Catalog jail annotation normalization produced an unsafe value.')
    return sorted(result, key=lambda item: item['name'])


def _normalize_health(metadata, ports):
    source = metadata.get('healthcheck')
    if source is None:
        return None
    if not isinstance(source, dict):
        raise CatalogContractError('x-daemonless.healthcheck must be a mapping.')
    port = source.get('port')
    path = source.get('path', '/')
    if type(port) is not int or not 1 <= port <= 65535:
        raise CatalogContractError('Catalog healthcheck port is invalid.')
    if not isinstance(path, str) or not PORTAL_PATH.fullmatch(path) or len(path) > 2048:
        raise CatalogContractError('Catalog healthcheck path is invalid.')
    published = next((
        item['host_port'] for item in ports
        if item['container_port'] == port and item['protocol'] == 'tcp'
    ), None)
    if published is None:
        raise CatalogContractError(
            'Catalog healthcheck port must be published as a reviewed TCP port.'
        )
    return {
        'type': 'HTTP',
        'scheme': 'http',
        'container_port': port,
        'host_port': published,
        'path': path,
    }


def _normalize_portal(ports, health, metadata=None):
    if health and health['host_port']:
        return {'scheme': health['scheme'], 'port': health['host_port'], 'path': health['path']}
    candidates = [item for item in ports if item['protocol'] == 'tcp']
    if not candidates:
        return None
    # the internal development record: a fjord manifest names its web port outright.
    web_port = (metadata or {}).get('web_port')
    if type(web_port) is int:
        named = next((item for item in candidates if item['host_port'] == web_port), None)
        if named is not None:
            https = (metadata or {}).get('web_https') is True or named['container_port'] == 443
            return {'scheme': 'https' if https else 'http', 'port': named['host_port'], 'path': '/'}
    preferred = next((
        item for item in candidates
        if any(word in (item.get('description') or '').lower() for word in ('web ui', 'web', 'http', 'admin'))
    ), None)
    if preferred is None:
        return None
    description = (preferred.get('description') or '').lower()
    scheme = 'https' if preferred['container_port'] == 443 or 'https' in description else 'http'
    return {'scheme': scheme, 'port': preferred['host_port'], 'path': '/'}


# the internal development record: a Compose project name for a volume (`mariadb-config:`), as the spec allows.
NAMED_VOLUME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$')


def compose_duration_seconds(value):
    """the internal development record: a Compose duration as whole seconds, rounded up; None if invalid."""
    if not isinstance(value, str) or not value or len(value) > 64:
        return None
    position, seconds = 0, 0.0
    for match in COMPOSE_DURATION.finditer(value):
        if match.start() != position:
            return None
        seconds += float(match.group(1)) * DURATION_UNITS[match.group(2)]
        position = match.end()
    if position != len(value):
        return None
    return int(math.ceil(seconds))


def compose_extra_hosts(value):
    """the internal development record: Compose ``extra_hosts`` as ``[{host, address}]``, name-sorted.

    A list of ``host:address`` or ``host=address`` (an IPv6 address needs ``=``) or a mapping.
    Raises ValueError with the reason when an entry is not a host name and an IP address.
    """
    if isinstance(value, dict):
        pairs = [(str(host), str(address)) for host, address in value.items()]
    elif isinstance(value, list):
        pairs = []
        for item in value:
            if not isinstance(item, str):
                raise ValueError('extra_hosts entries must be text')
            separator = '=' if '=' in item else ':'
            host, found, address = item.partition(separator)
            if not found:
                raise ValueError(f'extra_hosts entry {item!r} needs host:address')
            pairs.append((host, address.strip('[]')))
    else:
        raise ValueError('extra_hosts must be a list or a mapping')
    if len(pairs) > MAX_EXTRA_HOSTS:
        raise ValueError(f'at most {MAX_EXTRA_HOSTS} extra_hosts entries are supported')
    result = {}
    for host, address in pairs:
        if not HOST_ALIAS.fullmatch(host) or host in result:
            raise ValueError(f'extra_hosts host name {host!r} is invalid or repeated')
        try:
            result[host] = str(ipaddress.ip_address(address))
        except ValueError:
            raise ValueError(f'extra_hosts address {address!r} for {host!r} is not an IP address') from None
    return [{'host': host, 'address': result[host]} for host in sorted(result)]


def _normalize_runtime(service):
    """the internal development record: the provider's runtime options for the container."""
    runtime = {}
    if 'extra_hosts' in service:
        try:
            extra_hosts = compose_extra_hosts(service['extra_hosts'])
        except ValueError as error:
            raise CatalogContractError(f'Compose {error}.') from error
        if extra_hosts:
            runtime['extra_hosts'] = extra_hosts
    if 'stop_grace_period' in service:
        seconds = compose_duration_seconds(service['stop_grace_period'])
        if seconds is None or seconds > MAX_STOP_TIMEOUT:
            raise CatalogContractError(
                f'Compose stop_grace_period must be a duration of at most {MAX_STOP_TIMEOUT} seconds.'
            )
        runtime['stop_timeout'] = seconds
    return runtime


def _normalize_top_level_volumes(volumes):
    """the internal development record: a top-level ``volumes:`` that only declares plain named volumes.

    A service volume's source is never used -- every one becomes an owned dataset named by its
    target -- so a declaration like MariaDB's ``volumes: {mariadb-config: }`` changes nothing.
    A declaration that asks for anything (a driver, driver options, ``external``, a ``name``, labels)
    would mean storage this contract cannot honour, and is still refused.
    """
    if not volumes:
        return
    if not isinstance(volumes, dict) or len(volumes) > 128:
        raise CatalogContractError('Top-level Compose volumes must be a bounded mapping.')
    for name, definition in volumes.items():
        if not isinstance(name, str) or not NAMED_VOLUME.fullmatch(name):
            raise CatalogContractError('Top-level Compose volume names must be valid.')
        if definition not in (None, {}):
            raise CatalogContractError(
                f'Top-level Compose volume {name!r} sets options; only plain named volumes are supported.'
            )


def normalize_daemonless_contract(entry, content):
    if entry.get('provider') != PROVIDER_ID or not SERVICE_NAME.fullmatch(entry.get('name', '')):
        raise CatalogContractError('Catalog entry does not belong to the expected provider.')
    return _normalize_compose(entry, parse_catalog_yaml(content))


def _normalize_compose(entry, data):
    if any(not isinstance(key, str) for key in data):
        raise CatalogContractError('Compose root field names must be text.')
    unknown_root = set(data) - SUPPORTED_ROOT_KEYS
    if unknown_root:
        raise CatalogContractError(f'Unsupported Compose root fields: {", ".join(sorted(unknown_root))}.')
    if not isinstance(data.get('name'), str) or not SERVICE_NAME.fullmatch(data['name']):
        raise CatalogContractError('Compose project name is invalid.')
    _normalize_top_level_volumes(data.get('volumes'))

    metadata = data.get('x-daemonless')
    if not isinstance(metadata, dict):
        raise CatalogContractError('x-daemonless metadata must be a mapping.')
    application_class = metadata.get('class')
    if application_class in {'base', 'cli'}:
        raise CatalogContractError(f'{application_class.upper()} images are not installable Applications.')
    if application_class not in {None, 'service'}:
        raise CatalogContractError('x-daemonless class is unsupported.')

    services = data.get('services')
    if not isinstance(services, dict) or len(services) != 1:
        count = len(services) if isinstance(services, dict) else 0
        raise CatalogContractError(f'Exactly one service is supported; provider contract declares {count}.')
    service_name, service = next(iter(services.items()))
    if not isinstance(service_name, str) or not SERVICE_NAME.fullmatch(service_name) or not isinstance(service, dict):
        raise CatalogContractError('Compose service definition is malformed.')
    if any(not isinstance(key, str) for key in service):
        raise CatalogContractError('Compose service field names must be text.')
    unknown_service = set(service) - SUPPORTED_SERVICE_KEYS
    if unknown_service:
        raise CatalogContractError(f'Unsupported Compose service fields: {", ".join(sorted(unknown_service))}.')
    container_name = service.get('container_name')
    if container_name is not None and (
        not isinstance(container_name, str) or not SERVICE_NAME.fullmatch(container_name)
    ):
        raise CatalogContractError('Compose container_name is invalid.')

    image = service.get('image')
    if not isinstance(image, str):
        raise CatalogContractError('Compose service image must be text.')
    try:
        validate_image_reference(image)
    except ValueError as error:
        raise CatalogContractError(str(error)) from error
    expected_prefix = f'ghcr.io/{PROVIDER_ORGANIZATION}/{entry["name"]}:'
    if not image.startswith(expected_prefix) or not TAG.fullmatch(image[len(expected_prefix):]):
        raise CatalogContractError('Compose image does not match the expected provider repository identity.')

    title = _clean_text(metadata.get('title'), 'x-daemonless.title', 128)
    description = _clean_text(metadata.get('description'), 'x-daemonless.description', 2048)
    category = _clean_text(metadata.get('category'), 'x-daemonless.category', 128)
    if category not in CATEGORIES:
        category = 'Other'
    icon = metadata.get('icon')
    if icon is not None:
        icon = _clean_text(icon, 'x-daemonless.icon', 128)
        if not ICON.fullmatch(icon):
            icon = None

    upstream_url = _https_url(metadata.get('upstream_url'), 'x-daemonless.upstream_url')
    website_url = _https_url(metadata.get('web_url'), 'x-daemonless.web_url')
    freshports_url = _https_url(
        metadata.get('freshports_url'), 'x-daemonless.freshports_url', required=False
    )
    environment = _normalize_environment(service, metadata)
    volumes = _normalize_volumes(service, metadata)
    ports = _normalize_ports(service, metadata)
    annotations = _normalize_annotations(service)
    labels = _normalize_labels(service)
    runtime = _normalize_runtime(service)
    health = _normalize_health(metadata, ports)
    portal = _normalize_portal(ports, health, metadata)

    restart = service.get('restart', 'unless-stopped')
    restart_policy = {
        'always': 'always',
        'unless-stopped': 'always',
        'on-failure': 'on-failure',
        'no': 'no',
    }.get(restart)
    if restart_policy is None:
        raise CatalogContractError('Compose restart policy is unsupported.')

    result = copy.deepcopy(entry)
    result.update({
        'title': title,
        'category': category,
        'description': description,
        'icon': icon,
        'service_name': service_name,
        'image_reference': image,
        'environment': environment,
        'volumes': volumes,
        'ports': ports,
        'annotations': annotations,
        'labels': labels,
        'runtime': runtime,
        'health': health,
        'portal': portal,
        'restart_policy': restart_policy,
        'links': {
            'upstream': upstream_url,
            'website': website_url,
            'freshports': freshports_url,
        },
    })
    return result


def _presentation(value, maximum):
    """Provider presentation text, cleaned and bounded; never a reason to refuse."""
    if not isinstance(value, str):
        return None
    result = re.sub(r'\s+', ' ', re.sub(r'[\x00-\x1f\x7f]', ' ', value)).strip()
    if len(result) > maximum:
        result = f'{result[:maximum - 1].rstrip()}…'
    return result or None


def _normalize_fjord_app(app):
    if not isinstance(app, dict):
        raise CatalogContractError('fjord catalog application must be a mapping.')
    name = app.get('id')
    if not isinstance(name, str) or not SERVICE_NAME.fullmatch(name):
        raise CatalogContractError('fjord catalog application id is invalid.')
    manifest = app.get('manifest_url')
    match = FJORD_MANIFEST_PATH.fullmatch(manifest) if isinstance(manifest, str) else None
    if match is None or match.group(1) != name:
        raise CatalogContractError('fjord catalog manifest path is not the expected one.')
    icon = app.get('icon')
    if not isinstance(icon, str) or not FJORD_ICON_PATH.fullmatch(icon):
        icon = None
    category = _presentation(app.get('category'), 128)
    if category is not None and category not in CATEGORIES:
        category = 'Other'
    application_class = app.get('class')
    return {
        'name': name,
        'title': _presentation(app.get('name'), 128) or _humanize(name),
        'description': _presentation(app.get('description'), 2048),
        'category': category,
        'class': application_class if isinstance(application_class, str) else None,
        'manifest_path': manifest,
        'icon_path': icon,
    }


def normalize_fjord_catalog(data):
    """What the provider's fjord catalog says per application, or None.

    None -- no catalog, or a ``fjord_version`` this release does not read -- leaves
    the repository compose path in charge of everything.  A malformed application
    is skipped on its own (a duplicated id drops every copy); the rest of the
    catalog still applies.  Paths are only ever the provider's relative
    ``manifests/<id>.yaml`` and ``icons/<name>.svg|png``: no URL is taken from it.
    """
    if not isinstance(data, dict) or str(data.get('fjord_version')) not in FJORD_VERSIONS:
        return None
    apps = data.get('apps')
    if not isinstance(apps, list) or len(apps) > 512:
        return None
    result = {}
    duplicates = set()
    for app in apps:
        try:
            item = _normalize_fjord_app(app)
        except CatalogContractError:
            continue
        if item['name'] in result:
            duplicates.add(item['name'])
        result[item['name']] = item
    for name in duplicates:
        result.pop(name)
    return result


def apply_fjord_presentation(catalog, apps, icons=None):
    """Overlay the fjord catalog's presentation onto normalised index entries.

    The version index still decides which entries exist and which versions they
    track (the internal development record); fjord supplies the name, description,
    category and icon, and says up front when an application is a stack.
    """
    icons = icons or {}
    for entry in catalog['entries']:
        icon = icons.get(entry['name'])
        if icon:
            entry['icon'] = icon
        app = (apps or {}).get(entry['name'])
        if app is None:
            continue
        entry['title'] = app['title']
        if app['description']:
            entry['description'] = app['description']
        if app['category']:
            entry['category'] = app['category']
        if app['class'] == 'stack' and entry['status'] != 'UNAVAILABLE':
            entry.update({
                'resolved': True,
                'status': 'UNAVAILABLE',
                'reason': 'Exactly one service is supported; the provider publishes this application '
                          'as a multi-service stack.',
            })
    return catalog


def icon_data_uri(content):
    """A provider icon as a ``data:`` URI for an <img>, or None for the placeholder.

    The type comes from the bytes, never the file name: the provider serves PNGs
    under ``.svg`` names.
    """
    if not isinstance(content, (bytes, bytearray)) or not content or len(content) > MAX_ICON_SIZE:
        return None
    content = bytes(content)
    media_type = next((media for magic, media in ICON_MAGIC if content.startswith(magic)), None)
    if media_type is None and content[:4] == b'RIFF' and content[8:12] == b'WEBP':
        media_type = 'image/webp'
    if media_type is None:
        try:
            text = content.decode('utf-8')
        except UnicodeDecodeError:
            return None
        head = text.lstrip('﻿ \t\r\n')
        if (
            not head.startswith('<') or not re.search(r'<svg[\s>]', head[:8192], re.IGNORECASE) or
            UNSAFE_SVG.search(text)
        ):
            return None
        media_type = 'image/svg+xml'
    return f'data:{media_type};base64,{base64.b64encode(content).decode("ascii")}'


def _public_url(value):
    """fjord's own check for a public_url value: http or https, with a host."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return parsed.scheme in {'http', 'https'} and bool(parsed.hostname)


def _dotenv_value(text):
    """A fjord default as the manifest's ``.env`` gives it to Compose (the internal development record).

    Daemonless writes defaults for a dotenv file -- ``default: '"@every 1h"'`` beside
    ``ND_SCANNER_SCHEDULE="@every 1h"`` in ``env_defaults`` -- and dotenv strips the
    quotes around a whole value; inside double quotes ``\\"`` and ``\\\\`` unescape.
    Anything not wholly quoted stays as written.
    """
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ('"', "'"):
        inner = text[1:-1]
        if text[0] == "'":
            return inner
        return re.sub(r'\\(["\\])', r'\1', inner)
    return text


def _fjord_variables(value):
    if not isinstance(value, list) or len(value) > MAX_FJORD_VARIABLES:
        raise CatalogContractError('fjord variables must be a bounded list.')
    result = {}
    for item in value:
        if not isinstance(item, dict):
            raise CatalogContractError('fjord variable must be a mapping.')
        name = item.get('name')
        if not isinstance(name, str) or not ENVIRONMENT_NAME.fullmatch(name) or name in result:
            raise CatalogContractError('fjord variable names must be valid and unique.')
        kind = item.get('type')
        if kind not in FJORD_VARIABLE_TYPES:
            raise CatalogContractError(f'fjord variable {name!r} has unsupported type {kind!r}.')
        default = item.get('default', '')
        if default is None:
            default = ''
        if type(default) not in {bool, int, float, str}:
            raise CatalogContractError(f'fjord variable {name!r} default must be scalar.')
        default = _dotenv_value(str(default).lower() if isinstance(default, bool) else str(default))
        if len(default) > 65536 or '${' in default or any(character in default for character in ('\x00', '\r', '\n')):
            raise CatalogContractError(f'fjord variable {name!r} default is invalid.')
        if kind == 'port':
            if not default.isdigit() or not 1 <= int(default) <= 65535:
                raise CatalogContractError(f'fjord port variable {name!r} needs a valid default port.')
            default = str(int(default))
        if kind == 'image_tag' and not TAG.fullmatch(default):
            raise CatalogContractError(f'fjord image tag variable {name!r} default is invalid.')
        if kind == 'public_url' and default and not _public_url(default):
            raise CatalogContractError(f'fjord public URL variable {name!r} default is not an http(s) address.')
        optional = item.get('optional', False)
        if type(optional) is not bool:
            raise CatalogContractError(f'fjord variable {name!r} optional flag must be boolean.')
        result[name] = {
            'type': kind,
            'default': default,
            'label': _presentation(item.get('label'), 1024),
            'optional': optional,
        }
    return result


def _fjord_expand(text, variables):
    """``(text with every reference replaced, the variable when the text is exactly one reference)``.

    A variable renders as its declared default -- the install form edits the
    result exactly as it edits a static compose.  ``${VAR}``, ``${VAR:-x}`` and
    ``${VAR-x}`` are read; any other construct, or an undeclared variable without
    a fallback, refuses the manifest.  A bare ``$`` is left alone, as the static
    compose path leaves it.
    """
    whole = FJORD_REFERENCE.fullmatch(text)

    def replace(match):
        name, operator, fallback = match.group(1), match.group(2), match.group(3) or ''
        variable = variables.get(name)
        if variable is None:
            if operator is None:
                raise CatalogContractError(f'fjord manifest references undeclared variable {name!r}.')
            return fallback
        if operator == ':-' and variable['default'] == '':
            return fallback
        return variable['default']

    result = FJORD_REFERENCE.sub(replace, text)
    if '${' in result:
        raise CatalogContractError('fjord manifest uses an unsupported variable reference.')
    return result, (whole.group(1) if whole else None)


def _fjord_expand_tree(value, variables):
    if isinstance(value, str):
        return _fjord_expand(value, variables)[0]
    if isinstance(value, list):
        return [_fjord_expand_tree(item, variables) for item in value]
    if isinstance(value, dict):
        return {key: _fjord_expand_tree(item, variables) for key, item in value.items()}
    return value


def _fjord_document(variable, name):
    """The documentation a variable gives the compose entry it feeds, or None."""
    if variable is None:
        return None
    document = {}
    if variable['label']:
        document['desc'] = variable['label']
    if variable['optional']:
        document['optional'] = True
    if variable['type'] == 'secret':
        document['sensitive'] = True
    if not document:
        return None
    document.setdefault('desc', _humanize(name))
    return document


def _fjord_leading_reference(text):
    """``(reference, rest)`` when ``text`` starts with one reference and a colon."""
    match = FJORD_REFERENCE.match(text)
    if match is None or text[match.end():match.end() + 1] != ':':
        return None, text
    return match, text[match.end() + 1:]


def _fjord_environment(value, variables, docs):
    if isinstance(value, dict):
        result = {}
        for name, raw in value.items():
            if not isinstance(raw, str):
                result[name] = raw
                continue
            result[name], whole = _fjord_expand(raw, variables)
            document = _fjord_document(variables.get(whole), whole) if whole else None
            if document and isinstance(name, str):
                docs[name] = document
        return result
    if not isinstance(value, list):
        return _fjord_expand_tree(value, variables)
    result = []
    for item in value:
        if not isinstance(item, str) or '=' not in item:
            result.append(_fjord_expand_tree(item, variables))
            continue
        name, raw = item.split('=', 1)
        expanded, whole = _fjord_expand(raw, variables)
        result.append(f'{name}={expanded}')
        document = _fjord_document(variables.get(whole), whole) if whole else None
        if document:
            docs[name] = document
    return result


def _fjord_volumes(value, variables, docs):
    if not isinstance(value, list):
        return _fjord_expand_tree(value, variables)
    result = []
    for item in value:
        if not isinstance(item, str):
            result.append(_fjord_expand_tree(item, variables))
            continue
        reference, rest = _fjord_leading_reference(item)
        variable = variables.get(reference.group(1)) if reference else None
        if variable is None or variable['type'] not in FJORD_STORAGE_TYPES:
            result.append(_fjord_expand(item, variables)[0])
            continue
        # The host side of a catalog volume is discarded: middleware provides the
        # dataset.  Only the target is contract; the source is a placeholder.
        rest = _fjord_expand(rest, variables)[0]
        result.append(f'{reference.group(1).lower()}:{rest}')
        document = _fjord_document(variable, reference.group(1))
        if document:
            docs[rest.split(':', 1)[0]] = {key: document[key] for key in ('desc', 'optional') if key in document}
    return result


def _fjord_ports(value, variables, docs):
    if not isinstance(value, list):
        return _fjord_expand_tree(value, variables)
    result = []
    for item in value:
        if not isinstance(item, str):
            result.append(_fjord_expand_tree(item, variables))
            continue
        reference, _ = _fjord_leading_reference(item)
        expanded = _fjord_expand(item, variables)[0]
        result.append(expanded)
        variable = variables.get(reference.group(1)) if reference else None
        if variable is None or variable['type'] != 'port' or not variable['label']:
            continue
        port_value, separator, protocol = expanded.partition('/')
        container_port = port_value.rsplit(':', 1)[-1]
        docs[f'{container_port}/{protocol}' if separator else container_port] = {'desc': variable['label']}
    return result


def render_fjord_manifest(entry, content):
    """A fjord manifest rendered into the compose the contract parser reads.

    the internal development record: every typed variable renders as its default, storage
    variables become volume placeholders, and ``x-fjord.info`` plus the variable
    labels become the ``x-daemonless`` block.  The strict parser then decides
    installability exactly as it does for a repository compose, so nothing a
    manifest says widens what an Application may do.
    """
    data = parse_catalog_yaml(content)
    if 'x-daemonless' in data:
        raise CatalogContractError('fjord manifest must not carry x-daemonless metadata.')
    metadata = data.pop('x-fjord', None)
    if not isinstance(metadata, dict):
        raise CatalogContractError('fjord manifest has no x-fjord metadata.')
    if str(metadata.get('version')) not in FJORD_VERSIONS:
        raise CatalogContractError('fjord manifest version is not supported by this release.')
    info = metadata.get('info')
    if not isinstance(info, dict) or info.get('id') != entry['name']:
        raise CatalogContractError('fjord manifest identity does not match the catalog entry.')
    variables = _fjord_variables(metadata.get('variables', []))

    services = data.get('services')
    if not isinstance(services, dict) or len(services) != 1:
        count = len(services) if isinstance(services, dict) else 0
        raise CatalogContractError(f'Exactly one service is supported; provider contract declares {count}.')
    service_name, service = next(iter(services.items()))
    if not isinstance(service, dict):
        raise CatalogContractError('Compose service definition is malformed.')
    docs = {'env': {}, 'volumes': {}, 'ports': {}}
    rendered = {}
    for key, value in service.items():
        if key == 'environment':
            rendered[key] = _fjord_environment(value, variables, docs['env'])
        elif key == 'volumes':
            rendered[key] = _fjord_volumes(value, variables, docs['volumes'])
        elif key == 'ports':
            rendered[key] = _fjord_ports(value, variables, docs['ports'])
        else:
            rendered[key] = _fjord_expand_tree(value, variables)
    data['services'] = {service_name: rendered}

    title = _presentation(info.get('name'), 128) or _humanize(entry['name'])
    daemonless = {
        'title': title,
        'description': _presentation(info.get('description'), 2048) or entry.get('description') or title,
        'category': _presentation(info.get('category'), 128) or entry.get('category') or 'Other',
        'upstream_url': info.get('upstream_url'),
        'web_url': info.get('web_url'),
        'docs': docs,
    }
    if isinstance(info.get('class'), str):
        daemonless['class'] = info['class']
    web_port = info.get('web_port')
    if type(web_port) in {int, str}:
        web_port = _fjord_expand(str(web_port), variables)[0]
        if web_port.isdigit() and 1 <= int(web_port) <= 65535:
            daemonless['web_port'] = int(web_port)
    if info.get('web_https') is True:
        daemonless['web_https'] = True
    data['x-daemonless'] = daemonless
    return data


def repository_metadata(content):
    """The ``x-daemonless`` block of a repository compose, or an empty mapping.

    the internal development record: fjord 0.1 labels the provider's CLI images
    ``service`` and carries no health checks; the repository compose still says
    both, so a manifest is read together with it whenever it is at hand.
    """
    if content is None:
        return {}
    try:
        data = parse_catalog_yaml(content)
    except CatalogContractError:
        return {}
    metadata = data.get('x-daemonless')
    return metadata if isinstance(metadata, dict) else {}


def normalize_fjord_contract(entry, content, repository=None):
    if entry.get('provider') != PROVIDER_ID or not SERVICE_NAME.fullmatch(entry.get('name', '')):
        raise CatalogContractError('Catalog entry does not belong to the expected provider.')
    repository = repository or {}
    declared_class = repository.get('class')
    if declared_class in {'base', 'cli'}:
        raise CatalogContractError(f'{declared_class.upper()} images are not installable Applications.')
    data = render_fjord_manifest(entry, content)
    health = repository.get('healthcheck')
    if health is not None and 'healthcheck' not in data['x-daemonless']:
        candidate = copy.deepcopy(data)
        candidate['x-daemonless']['healthcheck'] = copy.deepcopy(health)
        try:
            return _normalize_compose(entry, candidate)
        except CatalogContractError:
            # The compose's health check does not fit the manifest; without it,
            # the manifest is judged on its own.
            pass
    return _normalize_compose(entry, data)


def _validated_image_info(image_info, expected_architecture):
    if not isinstance(image_info, dict):
        raise CatalogContractError('OCI image inspection result is malformed.')
    digest = image_info.get('digest')
    architecture = normalize_architecture(image_info.get('architecture'))
    operating_system = str(image_info.get('os') or '').lower()
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise CatalogContractError('OCI registry did not return an immutable sha256 digest.')
    if operating_system != 'freebsd':
        raise CatalogContractError(f'OCI image reports unsupported operating system {operating_system or "unknown"!r}.')
    if architecture != expected_architecture:
        raise CatalogContractError(
            f'OCI image architecture {architecture or "unknown"!r} does not match host {expected_architecture!r}.'
        )
    return digest, architecture, operating_system


def finalize_daemonless_contract(contract, image_info):
    digest, architecture, operating_system = _validated_image_info(
        image_info, contract['host_architecture']
    )
    reference = contract.pop('image_reference')
    repository = reference.rsplit(':', 1)[0]
    immutable_reference = f'{repository}@{digest}'
    contract.update({
        'resolved': True,
        'available': True,
        'status': 'AVAILABLE',
        'reason': None,
        'image': {
            'reference': reference,
            'immutable_reference': immutable_reference,
            'digest': digest,
            'os': operating_system,
            'architecture': architecture,
        },
    })
    contract['install'] = {
        'name': contract['name'],
        'image': immutable_reference,
        'ports': [
            {key: item[key] for key in ('host_port', 'container_port', 'protocol')}
            for item in contract['ports']
        ],
        'environment': [
            {'name': item['name'], 'value': item['default']}
            for item in contract['environment']
        ],
        'volumes': [
            {
                'name': item['name'],
                'target': item['target'],
                'dataset': None,
                'read_only': item['read_only'],
            }
            for item in contract['volumes']
        ],
        'annotations': copy.deepcopy(contract['annotations']),
        'labels': copy.deepcopy(contract.get('labels') or []),
        # the internal development record: provider runtime options; carried, never edited on the form.
        'runtime': copy.deepcopy(contract.get('runtime') or {}),
        'restart_policy': contract['restart_policy'],
        'portal': copy.deepcopy(contract['portal']),
        'healthcheck': copy.deepcopy(contract['health']),
        'health_timeout': 60,
    }
    return contract


def finalize_tag_contract(contract, resolved=None):
    """Bind a normalised contract to its tag (the internal development record).

    The image is followed by tag: the install pulls ``ghcr.io/daemonless/<name>:<tag>``
    and records the digest it actually received.  ``resolved`` is an optional
    registry observation made at review time (see ``registry.inspect_remote_image``);
    it fills the digest and platform for display and refuses a tag that resolves
    to the wrong operating system or architecture, but its absence never blocks
    an install -- an offline box installs from the cached contract and the pull.
    """
    reference = contract.pop('image_reference')
    repository = reference.rsplit(':', 1)[0]
    host_architecture = contract['host_architecture']
    digest = None
    operating_system = 'freebsd'
    architecture = host_architecture
    if resolved is not None:
        candidate = resolved.get('digest')
        if isinstance(candidate, str) and DIGEST.fullmatch(candidate):
            digest = candidate
        observed_os = str(resolved.get('os') or '').lower()
        observed_architecture = normalize_architecture(resolved.get('architecture'))
        if observed_os and observed_os != 'freebsd':
            contract['image_reference'] = reference
            return unavailable_detail(
                contract,
                f'OCI image reports unsupported operating system {observed_os!r}.',
            )
        if observed_architecture and observed_architecture != host_architecture:
            contract['image_reference'] = reference
            return unavailable_detail(
                contract,
                f'OCI image architecture {observed_architecture!r} does not match host '
                f'{host_architecture!r}.',
            )
        if observed_architecture:
            architecture = observed_architecture
    contract.update({
        'resolved': True,
        'available': True,
        'status': 'AVAILABLE',
        'reason': None,
        'image': {
            'reference': reference,
            'immutable_reference': f'{repository}@{digest}' if digest else None,
            'digest': digest,
            'os': operating_system,
            'architecture': architecture,
        },
    })
    contract['install'] = {
        'name': contract['name'],
        'image': reference,
        'ports': [
            {key: item[key] for key in ('host_port', 'container_port', 'protocol')}
            for item in contract['ports']
        ],
        'environment': [
            {'name': item['name'], 'value': item['default']}
            for item in contract['environment']
        ],
        'volumes': [
            {
                'name': item['name'],
                'target': item['target'],
                'dataset': None,
                'read_only': item['read_only'],
            }
            for item in contract['volumes']
        ],
        'annotations': copy.deepcopy(contract['annotations']),
        'labels': copy.deepcopy(contract.get('labels') or []),
        # the internal development record: provider runtime options; carried, never edited on the form.
        'runtime': copy.deepcopy(contract.get('runtime') or {}),
        'restart_policy': contract['restart_policy'],
        'portal': copy.deepcopy(contract['portal']),
        'healthcheck': copy.deepcopy(contract['health']),
        'health_timeout': 60,
    }
    return contract


def image_tag(reference):
    """The tag of an image reference; a catalog contract always pins one."""
    last = reference.rsplit('/', 1)[-1]
    return last.split(':', 1)[1] if ':' in last else 'latest'


def image_version(labels):
    """``(version, variant)`` as the image's own labels state them, or Nones.

    the internal development record: the provider's version index tracks three flavours per
    application and runs ahead of its images; only the image says what it is.
    """
    if not isinstance(labels, dict):
        return None, None
    version = labels.get(IMAGE_VERSION_LABEL)
    variant = labels.get(IMAGE_VARIANT_LABEL)
    if not isinstance(version, str) or not IMAGE_VERSION.fullmatch(version):
        version = None
    if not isinstance(variant, str) or not TAG.fullmatch(variant):
        variant = None
    return version, variant


def version_key(version):
    """Compare like with like: the index copies upstream tags verbatim (``v2.3.0``)
    where the image label may drop the ``v``."""
    if not isinstance(version, str):
        return None
    if version[:1] in {'v', 'V'} and version[1:2].isdigit():
        return version[1:]
    return version


def _arch_version(source, field, architecture):
    mapping = source.get(field) if isinstance(source, dict) else None
    if field == 'upstream':
        return mapping if isinstance(mapping, str) and mapping else None
    if isinstance(mapping, dict) and isinstance(mapping.get(architecture), str):
        return mapping[architecture]
    return None


def entry_version(entry, architecture, variant=None):
    """The provider's index version for the flavour ``variant`` -- an image's
    ``io.daemonless.variant`` label or a compose tag -- or None when the index does
    not track that flavour.

    Without a variant the ``latest`` assumption applies (upstream, then the rolling
    and quarterly packages): that is all a catalog list can say before a review,
    and it is marked as index-derived by every caller.
    """
    architecture = normalize_architecture(architecture)
    versions = entry.get('versions') or {}
    variants = versions.get('variants') if versions.get('type') == 'multi-version' else None
    variants = variants if isinstance(variants, dict) else None

    source = versions
    if variants is not None and versions.get('default') in variants:
        source = variants[versions['default']]
    if variant is None or variant == 'latest':
        # A ``latest`` image is the upstream build where the provider makes one
        # and one of the package builds otherwise.
        for field in DEFAULT_FLAVOUR_ORDER:
            found = _arch_version(versions if field == 'upstream' else source, field, architecture)
            if found is not None:
                return found
        return None
    if variant in FLAVOUR_FIELDS:
        return _arch_version(source, FLAVOUR_FIELDS[variant], architecture)

    if variants is None:
        return None
    # ``18`` / ``14-pkg`` / ``3.0-lua-pkg-latest``: a variant key, optionally
    # followed by the field within it.
    if variant in variants:
        for field in ('pkg', 'pkg-latest'):
            found = _arch_version(variants[variant], field, architecture)
            if found is not None:
                return found
        return None
    head = variant
    while '-' in head:
        head, _, _ = head.rpartition('-')
        if head in variants:
            return _arch_version(variants[head], variant[len(head) + 1:], architecture)
    return None


def installed_catalog_provenance(provenance, image_info):
    """The provenance a record keeps once the image is on the box: the pulled
    image's own version and variant labels replace what the review could only
    read from the index (the internal development record).  Legacy shapes pass through.
    """
    if not isinstance(provenance, dict):
        return provenance
    result = copy.deepcopy(provenance)
    if set(result) - OPTIONAL_CATALOG_FIELDS != CATALOG_FIELDS:
        return result
    labels = image_info.get('labels') if isinstance(image_info, dict) else None
    version, variant = image_version(labels)
    if version is not None:
        result['version'] = version
    if variant is not None:
        result['variant'] = variant
    else:
        result.setdefault('variant', None)
    return result
