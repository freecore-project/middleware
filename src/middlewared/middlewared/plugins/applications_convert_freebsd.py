"""Convert & Import: the experimental guided lane (the internal development record).

Sources: an iocage or Bastille jail, a Linux export bundle, or a Linux image
reference.  Sinks: an Application record on the native Daemonless image with
the workload's state carried across (a recipe knows the app); the source Linux
image under the compatibility tier (the internal development record); or, for any
jail, the jail's own software lifted into a native image with its state on
owned datasets (the internal development record, no recipe needed).

``detect`` reads.  ``plan`` writes a typed, content-addressed document and, for
a jail, takes the snapshot that *is* the plan's input.  ``apply`` re-validates
the input, stages the data into the application's own dataset, runs an
optional hop, and hands the result to the ordinary install path.  The source is
never opened for writing; a jail is never created, started or changed.
"""
import asyncio
import copy
import hashlib
import json
import os
import shutil
import uuid
from datetime import datetime, timezone

from middlewared.plugins.applications_.catalog import CatalogContractError
from middlewared.plugins.applications_.provider import ProviderClient
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
from middlewared.plugins.applications_.registry import image_refusals, inspect_remote_image
from middlewared.plugins.config_ import scale as scale_config
from middlewared.plugins.applications_.utils import application_paths, atomic_write, podman_environment
from middlewared.schema import Bool, Dict, Int, List, Str, accepts
from middlewared.service import Service, filterable, job
from middlewared.service_exception import CallError
from middlewared.utils import filter_list, run
from middlewared.validators import Match, Range

PLAN_SCHEMA = 1
PLANS_SUBDIR = 'convert'
SNAPSHOT_PREFIX = 'freecore-convert-'
# the internal development record: export plans live beside, never among, conversion plans.
EXPORT_PLANS_SUBDIR = 'export'
EXPORT_SNAPSHOT_PREFIX = 'freecore-export-'
EXPORT_MODES = ('bundle', 'in-place')
SOURCE_KINDS = ('jail', 'linux-export', 'linux-image')
ENGINES = ('iocage', 'bastille')
MODES = ('native', 'compat', 'lift')
LIFT_STANDARD_INIT = ('/bin/sh /etc/rc', '/bin/sh /etc/rc.shutdown', '/bin/sh /etc/rc.shutdown jail')
LIFT_WORK_SUBDIR = 'work'
APPLICATION_NAME = r'^[a-z0-9][a-z0-9_.-]{0,62}$'
PLAN_ID = r'^[0-9a-f]{64}$'
HOP_CONTAINER_PREFIX = 'freecore-convert-hop-'
MAX_COMPOSE_SIZE = 256 * 1024
HOP_POLL_INTERVAL = 3
MAX_PLANS = 64

SOURCE_SCHEMA = Dict(
    'source',
    Str('kind', required=True, enum=list(SOURCE_KINDS)),
    Str('jail', null=True, default=None),
    Str('engine', enum=list(ENGINES), default='iocage'),
    Str('path', null=True, default=None),
    Str('image', null=True, default=None),
)
PLAN_OPTIONS_SCHEMA = Dict(
    'options',
    Str('name', null=True, default=None, validators=[Match(APPLICATION_NAME)]),
    Str('mode', null=True, default=None, enum=[*MODES, None]),
    Int('host_port', null=True, default=None, validators=[Range(min=1, max=65535)]),
    # the internal development record: the lift publishes what the jail listens on; the
    # wizard hands back the host ports it chose, or leaves one out to drop it.
    List('ports', items=[Dict(
        'port',
        Int('container_port', required=True, validators=[Range(min=1, max=65535)]),
        Str('protocol', enum=['tcp', 'udp'], default='tcp'),
        Int('host_port', null=True, default=None, validators=[Range(min=1, max=65535)]),
    )], default=[]),
    default={},
)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _volume_name(target):
    name = target.strip('/').replace('/', '-').replace('_', '-').lower() or 'root'
    return name[:63]


class ApplicationsConvertService(Service):

    class Config:
        namespace = 'applications.convert'

    def __init__(self, middleware):
        super().__init__(middleware)
        self._recipes = None
        self._equivalences = None

    # -- recipes -----------------------------------------------------------

    def _load(self):
        if self._recipes is None:
            self._recipes = recipe_store.load_recipes()
            self._equivalences = recipe_store.load_equivalences()
        return self._recipes, self._equivalences

    @accepts()
    async def recipes(self):
        recipes, equivalences = self._load()
        return {
            'recipes': [
                {
                    'app': recipe['app'],
                    'title': recipe.get('title') or recipe['app'],
                    'version': recipe['recipe_version'],
                    'status': recipe.get('status') or 'proven',
                    'kind': recipe_store.recipe_kind(recipe),
                    'sources': sorted(recipe['sources']),
                    'catalog_id': recipe['target']['catalog_id'],
                    'hops': [hop['image'] for hop in recipe.get('hops') or []],
                }
                for recipe in recipes.values()
            ],
            'equivalences': copy.deepcopy(equivalences['entries']),
            'families': copy.deepcopy(equivalences.get('families') or []),
        }

    # -- configuration -----------------------------------------------------

    async def _applications_config(self):
        config = await self.middleware.call('applications.config')
        if not config['pool']:
            raise CallError('Configure an Applications data pool first.')
        return config

    @staticmethod
    def _require_enabled(config):
        if not config.get('convert_enabled'):
            raise CallError(
                'Convert & Import is experimental and off; enable it in Applications Settings first.'
            )

    @staticmethod
    def _plans_dir(config):
        return os.path.join(application_paths(config['pool'])['records'], PLANS_SUBDIR)

    def _read_plans(self, config, directory=None):
        directory = directory or self._plans_dir(config)
        plans = []
        if not os.path.isdir(directory):
            return plans
        for name in sorted(os.listdir(directory)):
            if not name.endswith('.json'):
                continue
            try:
                with open(os.path.join(directory, name), 'rb') as file:
                    plan = json.loads(file.read().decode('utf-8'))
            except (OSError, ValueError):
                continue
            if isinstance(plan, dict) and plan.get('schema') == PLAN_SCHEMA and \
                    plan.get('plan_id') == name[:-5]:
                plans.append(plan)
        return plans

    def _read_plan(self, config, plan_id, directory=None):
        path = os.path.join(directory or self._plans_dir(config), f'{plan_id}.json')
        try:
            with open(path, 'rb') as file:
                plan = json.loads(file.read().decode('utf-8'))
        except FileNotFoundError:
            raise CallError(f'Conversion plan {plan_id!r} does not exist.') from None
        except (OSError, ValueError) as error:
            raise CallError(f'Conversion plan {plan_id!r} is unreadable.') from error
        if plan.get('plan_id') != plan_id or plan_doc.plan_id(plan) != plan_id:
            raise CallError(f'Conversion plan {plan_id!r} does not match its content.')
        return plan

    def _write_plan(self, config, plan, directory=None):
        directory = directory or self._plans_dir(config)
        if len(self._read_plans(config, directory)) >= MAX_PLANS:
            raise CallError('Too many pending conversion plans; discard some first.')
        atomic_write(
            os.path.join(directory, f'{plan["plan_id"]}.json'),
            json.dumps(plan, indent=2, sort_keys=True) + '\n',
            mode=0o600,
        )

    def _delete_plan(self, config, plan_id, directory=None):
        try:
            os.unlink(os.path.join(directory or self._plans_dir(config), f'{plan_id}.json'))
        except FileNotFoundError:
            pass

    # -- lookup ------------------------------------------------------------

    async def _catalog_names(self):
        try:
            entries = await self.middleware.call('applications.catalog.query')
        except CallError:
            return set()
        return {entry['name'] for entry in entries}

    @accepts(Str('image', required=True, empty=False))
    async def lookup(self, image):
        """Which native application a Linux image corresponds to (the internal development record).

        Reads registry metadata only; never pulls a layer and needs no flag.
        """
        recipes, equivalences = self._load()
        try:
            normalized = recipe_store.normalize_reference(image)
        except CatalogContractError as error:
            raise CallError(str(error)) from error
        catalog_names = await self._catalog_names()
        match = recipe_store.equivalence_lookup(image, equivalences, catalog_names)
        recipe, recipe_refusal = recipe_store.recipe_for_linux_image(image, recipes)
        inspection = None
        try:
            inspection = await inspect_remote_image(image, 'linux', 'amd64')
        except Exception:  # noqa: BLE001
            self.logger.debug('Unable to inspect %r', image, exc_info=True)
        refusals = image_refusals(inspection, 'linux', 'amd64')
        if recipe_refusal:
            refusals.append(recipe_refusal)
        if match.get('refuse') and match['refuse'] not in refusals:
            refusals.append(match['refuse'])
        source_label = None
        if inspection:
            source_label = inspection['labels'].get('org.opencontainers.image.source') or \
                inspection['labels'].get('org.opencontainers.image.url')
        if match['app'] and source_label and match['kind'] != 'table':
            try:
                detail = await self.middleware.call(
                    'applications.catalog.details', f'daemonless:{match["app"]}',
                )
                upstream = (detail.get('provenance') or {}).get('upstream_url')
                if upstream and upstream.rstrip('/') == source_label.rstrip('/'):
                    match = {**match, 'kind': 'label', 'confidence': 'exact'}
            except CallError:
                pass
        config = await self.middleware.call('applications.config')
        return {
            'reference': image,
            'repository': normalized['repository'],
            'tag': normalized['tag'],
            'digest': inspection['digest'] if inspection else None,
            'os': inspection['os'] if inspection else None,
            'architecture': inspection['architecture'] if inspection else None,
            'labels': inspection['labels'] if inspection else {},
            'match': match,
            'recipe': recipe['app'] if recipe else None,
            'compat_possible': not refusals and bool(config.get('linux_compat_enabled')),
            'compat_enabled': bool(config.get('linux_compat_enabled')),
            'refusals': refusals,
        }

    # -- compose import (the internal development record) ----------------------------

    @accepts(Dict(
        'compose',
        Str('url', null=True, default=None),
        Str('text', null=True, default=None, max_length=MAX_COMPOSE_SIZE),
    ))
    async def read_compose(self, data):
        """Read a compose file into an import form: the "point at your own GitHub" path.

        The URL must be on ``raw.githubusercontent.com`` (the same allowlist the
        catalog uses); pasted text needs no network.  Nothing is pulled and no
        flag is needed -- this only fills in what the administrator then reviews
        and acknowledges on ``applications.install``.
        """
        if bool(data.get('url')) == bool(data.get('text')):
            raise CallError('Give either a compose file URL or its text.')
        text = data.get('text')
        if data.get('url'):
            client = ProviderClient()
            try:
                client.check_url(data['url'])
            except CatalogContractError:
                raise CallError(
                    'Compose files are read from https://raw.githubusercontent.com/ only; '
                    'paste the file instead.'
                ) from None
            content = await client.get(data['url'], MAX_COMPOSE_SIZE, accept='text/plain')
            text = content.decode('utf-8', 'replace')
        try:
            compose = compose_reader.read_export_compose(text)
        except CatalogContractError as error:
            raise CallError(str(error)) from error
        lookup = None
        try:
            lookup = await self.lookup(compose['image'])
        except CallError:
            lookup = None
        image_os = (lookup or {}).get('os') or 'linux'
        healthcheck = None
        if compose.get('healthcheck'):
            match = next((
                port for port in compose['ports']
                if port['container_port'] == compose['healthcheck']['container_port'] and port['protocol'] == 'tcp'
            ), None)
            if match:
                healthcheck = {
                    'type': 'HTTP', 'scheme': 'http', 'container_port': match['container_port'],
                    'host_port': match['host_port'], 'path': compose['healthcheck']['path'],
                }
        return {
            'service': compose['service'],
            'install': {
                'name': self._application_name_for(compose['service']),
                'image': compose['image'],
                'image_os': image_os if image_os in ('freebsd', 'linux') else 'linux',
                'ports': copy.deepcopy(compose['ports']),
                'environment': copy.deepcopy(compose['environment']),
                'volumes': [
                    {'name': _volume_name(volume['target']), 'target': volume['target'], 'dataset': None,
                     'read_only': bool(volume['read_only'])}
                    for volume in compose['volumes']
                ],
                'annotations': [],
                # the internal development record: an imported compose keeps its labels; reserved names are
                # left behind rather than failing the draft.
                'labels': [
                    {'name': key, 'value': value}
                    for key, value in sorted((compose.get('labels') or {}).items())
                    if not key.startswith('io.freecore.')
                ],
                # the internal development record #535: a compose stop_grace_period and extra_hosts travel with the import.
                'runtime': {
                    **({'stop_timeout': compose['stop_timeout']} if compose.get('stop_timeout') is not None else {}),
                    **({'extra_hosts': compose['extra_hosts']} if compose.get('extra_hosts') else {}),
                },
                'restart_policy': compose['restart'],
                'portal': None,
                'healthcheck': healthcheck,
                'health_timeout': 60,
            },
            'match': (lookup or {}).get('match'),
            'catalog_app': ((lookup or {}).get('match') or {}).get('app'),
            'ignored': [
                *compose['drops'],
                *[f'refused for conversion, ignored for import: {item}' for item in compose['refusals']],
            ],
            'volumes_in_compose': [
                {'source': volume['source'], 'target': volume['target'], 'kind': volume['kind']}
                for volume in compose['volumes']
            ],
        }

    # -- sources -----------------------------------------------------------

    @staticmethod
    def _application_name_for(name):
        candidate = ''.join(
            character if character.isalnum() or character in '_.-' else '-' for character in str(name).lower()
        ).strip('-.')[:63]
        return candidate if candidate and candidate[0].isalnum() else f'jail-{candidate}'.strip('-')[:63]

    async def _catalog_matches(self, packages, catalog_names):
        """Catalog entries that carry the same name as a package the jail holds."""
        return sorted({
            item['name'] for item in packages
            if not item.get('automatic') and item['name'] in catalog_names
        })

    @accepts()
    async def sources(self):
        """Every iocage and Bastille jail as a conversion candidate (read-only).

        ``lift`` says whether the generic lift can take it (the internal development record);
        ``app`` names the recipe that recognises it, when one does; ``catalog``
        lists Daemonless entries whose name matches a package the jail holds.
        """
        recipes, _ = self._load()
        catalog_names = await self._catalog_names()
        result = []
        if await self.middleware.call('jail.iocage_set_up'):
            iocroot = await self.middleware.call('jail.get_iocroot')
            for jail in await self.middleware.call('jail.query'):
                name = jail.get('name') or jail.get('id')
                root = f'{iocroot}/jails/{name}/root'
                result.append(await self._source_row('iocage', name, jail, root, recipes, catalog_names))
        try:
            bastille = await self.middleware.call('bastille.config')
        except CallError:
            bastille = {}
        if bastille.get('pool'):
            for jail in await self.middleware.call('bastille.query'):
                result.append(await self._source_row(
                    'bastille', jail['name'], jail, jail.get('path') or '', recipes, catalog_names,
                ))
        return result

    async def _source_row(self, engine, name, jail, root, recipes, catalog_names):
        recipe = await self.middleware.run_in_thread(recipe_store.match_jail, root, recipes) if root else None
        version = None
        if recipe is not None:
            version = await self.middleware.run_in_thread(
                probes.pkg_version, root, recipe['sources']['jail']['pkg'],
            )
        packages = await self.middleware.run_in_thread(probes.installed_packages, root) if root else []
        requested = [
            {'name': item[0], 'version': item[1]} for item in packages if not item[2]
        ]
        return {
            'kind': 'jail',
            'engine': engine,
            'name': name,
            'state': jail.get('state'),
            'release': jail.get('release'),
            'root': root,
            'app': recipe['app'] if recipe else None,
            'version': version,
            'packages': requested[:24],
            'catalog': await self._catalog_matches(
                [{'name': item[0], 'automatic': item[2]} for item in packages], catalog_names,
            ),
            'lift': bool(root) and bool(jail.get('operable', True)),
            'convertible': recipe is not None and jail.get('state') == 'down',
        }

    async def _describe_jail(self, name, engine='iocage'):
        recipes, _ = self._load()
        description = await jail_sources.describe(self.middleware, engine, name)
        root = description['root']
        recipe = await self.middleware.run_in_thread(recipe_store.match_jail, root, recipes)
        description.update({
            'app': None,
            'version': None,
            'recipe': None,
            'uid': None,
            'paths': {},
            'environment': {},
            'refusals': [],
            'fingerprint': None,
            'image': None,
        })
        if description['dataset'] is None:
            description['refusals'].append(f'no ZFS dataset is mounted at {root}')
        if recipe is None:
            description['refusals'].append('no recipe recognises this jail')
        elif description.get('state') != 'down':
            description['refusals'].append('the jail must be stopped; a live database copy is a corrupt copy')
        if recipe is None:
            return description
        source = recipe['sources']['jail']
        data = source['data']
        if source.get('rc_data_var'):
            # The jail's own rc.conf, then its own rc.d script, name the data directory
            # the installed version really uses; the recipe's path is the fallback.
            configured = probes.rc_setting(description.get('rc_conf') or '', source['rc_data_var'])
            if not configured:
                configured = await self.middleware.run_in_thread(
                    probes.rc_script_default, root, source.get('rc_script') or source['pkg'], source['rc_data_var'],
                )
            if configured and configured.startswith('/') and os.path.isdir(os.path.join(root, configured.lstrip('/'))):
                data = configured.lstrip('/')
        description.update({
            'app': recipe['app'],
            'recipe': f'{recipe["app"]}@{recipe["recipe_version"]}',
            'recipe_status': recipe.get('status') or 'proven',
            'version': await self.middleware.run_in_thread(probes.pkg_version, root, source['pkg']),
            'uid': source['uid'],
            'paths': {
                'data': os.path.join(root, data),
                'ini': os.path.join(root, source['ini']) if source.get('ini') else None,
                'provisioning': os.path.join(root, source['provisioning']) if source.get('provisioning') else None,
                # the internal development record: recipe-named extra paths, root-relative.
                **{key: os.path.join(root, value) for key, value in (source.get('paths') or {}).items()},
            },
        })
        return description

    async def _describe_export(self, path):
        recipes, _ = self._load()
        if not path:
            raise CallError('An export bundle path is required.')
        try:
            found = await self.middleware.run_in_thread(bundle.discover, path)
            compose = compose_reader.read_export_compose(found['compose_text'])
            fingerprint = await self.middleware.run_in_thread(
                bundle.fingerprint, found['root'], found['compose_text'],
            )
        except CatalogContractError as error:
            raise CallError(str(error)) from error
        recipe, recipe_refusal = recipe_store.recipe_for_linux_image(compose['image'], recipes)
        normalized = recipe_store.normalize_reference(compose['image'])
        description = {
            'kind': 'linux-export',
            'ref': found['root'],
            'root': found['root'],
            'dataset': None,
            'state': None,
            'release': None,
            'app': recipe['app'] if recipe else None,
            'version': normalized['tag'] if normalized['tag'] not in (None, 'latest') else None,
            'recipe': f'{recipe["app"]}@{recipe["recipe_version"]}' if recipe else None,
            'recipe_status': (recipe.get('status') or 'proven') if recipe else None,
            'uid': recipe['sources']['linux']['uid'] if recipe else None,
            'paths': {},
            'environment': {item['name']: item['value'] for item in compose['environment']},
            'refusals': list(compose['refusals']),
            'drops': list(compose['drops']),
            'fingerprint': fingerprint,
            'image': compose['image'],
            'compose': compose,
        }
        if recipe_refusal:
            description['refusals'].append(recipe_refusal)
        if recipe is not None and description['version'] is None:
            # the internal development record: a :latest (or untagged) source says nothing about the
            # version it ran; the image's own label is the only way never-downgrade can fire.
            lookup = await self.lookup(compose['image'])
            description['lookup'] = lookup
            label = (lookup.get('labels') or {}).get('org.opencontainers.image.version')
            if isinstance(label, str) and plan_doc.version_key(label):
                description['version'] = label
                description['version_source'] = 'label'
        if recipe is not None:
            source = recipe['sources']['linux']
            # the internal development record: recipe-named extra paths resolve exactly like
            # ini -- an exact volume match, or a file inside a bind volume.
            wanted_paths = {'data': source.get('data'), 'ini': source.get('ini'),
                            'provisioning': source.get('provisioning'),
                            **(source.get('paths') or {})}
            paths = {key: None for key in wanted_paths}
            for volume in compose['volumes']:
                for key, wanted in wanted_paths.items():
                    if not wanted:
                        continue
                    if volume['target'] == wanted or (
                        key != 'data' and volume['target'] == os.path.dirname(wanted)
                    ):
                        location = None
                        if volume['kind'] == 'bind':
                            location = bundle.resolve_bind(found['root'], volume['source'])
                        else:
                            tar = bundle.volume_tar(found['root'], volume['source'])
                            location = f'tar:{tar}' if tar else None
                        if location and key != 'data' and volume['target'] == os.path.dirname(wanted) \
                                and not location.startswith('tar:'):
                            location = os.path.join(location, os.path.basename(wanted))
                        paths[key] = location
            data_refusal = None
            if paths['data'] is None and source.get('data'):
                # the internal development record: the data directory may sit inside a mounted
                # directory (Plex keeps it under /config/Library/...); the deepest mount wins.
                wanted = source['data'].rstrip('/')
                enclosing = sorted(
                    (volume for volume in compose['volumes']
                     if wanted.startswith(volume['target'].rstrip('/') + '/')),
                    key=lambda volume: len(volume['target']), reverse=True,
                )
                if enclosing:
                    volume = enclosing[0]
                    inside = os.path.relpath(wanted, volume['target'])
                    if volume['kind'] != 'bind':
                        data_refusal = (
                            f'the data for {wanted} is inside the named volume {volume["source"]!r}; a path inside '
                            'a volume archive is not read -- export that volume as a bind directory'
                        )
                    else:
                        location = bundle.resolve_bind(found['root'], volume['source'])
                        candidate = os.path.join(location, inside) if location else None
                        if candidate and os.path.isdir(candidate):
                            paths['data'] = candidate
                        else:
                            data_refusal = (
                                f'the bundle mounts {volume["target"]} but holds no {inside} inside it; '
                                f'this is not the layout the recipe reads for {wanted}'
                            )
            description['paths'] = paths
            if paths['data'] is None:
                description['refusals'].append(data_refusal or (
                    f'the bundle carries no data for {source["data"]}; export the volume or bind directory'
                ))
        return description

    async def _describe_image(self, image):
        if not image:
            raise CallError('An image reference is required.')
        lookup = await self.lookup(image)
        return {
            'kind': 'linux-image',
            'ref': image,
            'root': None,
            'dataset': None,
            'state': None,
            'release': None,
            'app': lookup['recipe'] or lookup['match'].get('app'),
            'version': lookup['tag'] if lookup['tag'] not in (None, 'latest') else None,
            'recipe': None,
            'uid': None,
            'paths': {},
            'environment': {},
            'refusals': list(lookup['refusals']),
            'fingerprint': lookup['digest'],
            'image': image,
            'lookup': lookup,
        }

    async def _describe(self, source):
        if source['kind'] == 'jail':
            return await self._describe_jail(source.get('jail'), source.get('engine') or 'iocage')
        if source['kind'] == 'linux-export':
            return await self._describe_export(source.get('path'))
        return await self._describe_image(source.get('image'))

    @accepts(SOURCE_SCHEMA)
    async def detect(self, source):
        """Inspect a source read-only: what a recipe recognises, and for a jail what the lift sees.

        the internal development record: the port candidates come back here so the wizard
        can let the administrator choose host ports before a plan is written.
        """
        await self._applications_config()
        description = await self._describe(source)
        description.pop('compose', None)
        description.pop('rc_conf', None)
        if source['kind'] == 'jail':
            _detected, detected_from, candidates = await self._lift_ports(description, {})
            description['ports'] = [
                {key: port.get(key) for key in ('container_port', 'protocol', 'host_port', 'command')}
                for port in candidates
            ]
            description['ports_detected_from'] = detected_from
        return description

    # -- planning ----------------------------------------------------------

    async def _target_detail(self, recipe):
        detail = await self.middleware.call(
            'applications.catalog.details', recipe['target']['catalog_id'],
        )
        if not detail.get('available'):
            raise CallError(
                f'Target catalog entry {recipe["target"]["catalog_id"]!r} is not installable: '
                f'{detail.get("reason")}'
            )
        return detail

    @staticmethod
    def _export_port_decisions(detail, compose, chosen_host_port, target_port):
        """Each catalog port of a recipe conversion from a Linux export, decided from the bundle.

        the internal development record: the bundle says which ports were published (``ports:``) and which
        stayed on the managed network (``expose:``).  A host port chosen for this conversion wins;
        then the bundle's own choice; a port the bundle does not mention keeps the catalog's host
        port.  The portal port opens the web page and cannot stay off the host.  Every port gets a
        plan line, so the review shows what will be published.
        """
        install = detail.get('install') or {}
        declared = install.get('ports') or []
        portal = install.get('portal') or {}
        portal_key = next((
            (port['container_port'], port['protocol']) for port in declared
            if port['protocol'] == 'tcp' and portal.get('port') is not None and port['host_port'] == portal['port']
        ), None)
        published = {(port['container_port'], port['protocol']): port['host_port'] for port in compose.get('ports') or []}
        exposed = {(port['container_port'], port['protocol']) for port in compose.get('exposed') or []}
        decisions = []
        entries = []
        for port in declared:
            key = (port['container_port'], port['protocol'])
            label = f'{port["container_port"]}/{port["protocol"]}'
            warning = False
            if chosen_host_port and port['container_port'] == target_port:
                host_port, reason = chosen_host_port, 'chosen for this conversion'
            elif key in published:
                host_port, reason = published[key], 'as the bundle published it'
            elif key in exposed and key != portal_key:
                host_port, reason = None, None
            elif key in exposed:
                host_port, warning = port['host_port'], True
                reason = "it opens the application's web page; the bundle kept it on the managed network"
            else:
                host_port, reason = port['host_port'], "the bundle does not mention it; the catalog entry's host port"
            decisions.append({'container_port': port['container_port'], 'protocol': port['protocol'], 'host_port': host_port})
            if host_port is None:
                text = f'port {label} stays on the managed network, not published on the host (as in the bundle)'
            else:
                text = f'port {label} is published as host port {host_port} ({reason})'
            entries.append(plan_doc.entry(
                'note', text, what='port', container_port=port['container_port'], protocol=port['protocol'],
                host_port=host_port, **({'warning': True} if warning else {}),
            ))
        return decisions, entries

    def _native_entries(self, recipe, description, detail, config):
        """The plan entries for carrying state into the native image."""
        entries = []
        preflights = []
        refusals = []
        target = recipe['target']
        layout = target['layout']
        paths = description['paths']
        values = {key: value for key, value in (paths or {}).items() if isinstance(value, str)}
        values.setdefault('data', paths.get('data') or '')
        values.setdefault('provisioning', paths.get('provisioning') or '')
        values.update({f'layout.{key}': value for key, value in layout.items()})

        target_version = (detail.get('catalog') or {}).get('version')
        source_version = description.get('version')
        older = not plan_doc.not_older(target_version, source_version)
        preflights.append({
            'id': 'target_not_older', 'ok': not older,
            'detail': f'source {source_version or "unknown"} -> target {target_version or "unknown"}',
        })
        if older:
            refusals.append(
                f'the native image ships {target_version}, older than the source {source_version}; '
                'a downgrade is never performed'
            )
        if source_version is None and description['kind'] == 'linux-export':
            entries.append(plan_doc.entry(
                'note', f'the source version is unknown (its tag is latest and its image states no version); '
                f'confirm it is not newer than the native {target_version or "image"} before applying',
                what='source_version',
            ))

        # the internal development record: a "grafana" recipe translates an ini through its
        # allow/deny lists and probes the database; a generic recipe carries trees.
        grafana = recipe_store.recipe_kind(recipe) == 'grafana'
        merged = {}
        if grafana:
            # Configuration: file first, environment on top, then the allow/deny lists.
            sections = {}
            ini_path = paths.get('ini')
            if ini_path and not str(ini_path).startswith('tar:') and os.path.isfile(ini_path):
                try:
                    with open(ini_path, 'r', encoding='utf-8', errors='replace') as file:
                        sections = ini_carry.parse_ini(file.read())
                except (OSError, ValueError) as error:
                    refusals.append(f'the configuration file {ini_path} is unreadable: {error}')
            source_definition = recipe['sources'][
                'jail' if description['kind'] == 'jail' else 'linux'
            ]
            env_sections = ini_carry.env_overrides(
                description.get('environment') or {},
                prefix=source_definition.get('env_prefix') or 'GF_',
                known_sections=tuple(sections),
            )
            merged = ini_carry.merged(sections, env_sections)
            carried, denied, dropped = ini_carry.translate(
                merged, recipe['config']['allow'], recipe['config']['deny'],
            )
            carried_keys = sorted(f'{section}.{key}' for section, values_ in carried.items() for key in values_)
            entries.append(plan_doc.entry(
                'rewrite', f'configuration: {len(carried_keys)} settings carried, '
                f'{len(denied)} denied by the recipe, {len(dropped)} not carried',
                what='config', carried=carried_keys, denied=denied, dropped=dropped,
            ))
            if 'security.secret_key' not in carried_keys:
                entries.append(plan_doc.entry(
                    'note', "no security.secret_key is set at the source; Grafana's default key stays in "
                    'use for datasource secrets on both sides', what='secret_key',
                ))

        database = probes.database_type(merged) if grafana else 'sqlite3'
        external_db = database != 'sqlite3'
        if grafana:
            preflights.append({'id': 'external_database', 'ok': True, 'detail': database})

        data_path = paths.get('data')
        data_in_tar = bool(data_path and str(data_path).startswith('tar:'))
        db_path = None if (not data_path or data_in_tar or not grafana) else os.path.join(data_path, 'grafana.db')
        for item in recipe['carry']:
            try:
                source_path = recipe_store.expand(item['from'], values)
            except CatalogContractError:
                continue
            destination = recipe_store.expand(item['to'], values)
            if external_db and source_path.endswith('grafana.db'):
                entries.append(plan_doc.entry(
                    'drop', f'{source_path}: the database is external ({database}); settings are '
                    'carried and the data stays where it is', what=source_path,
                ))
                continue
            exists = data_in_tar or os.path.exists(source_path)
            volume_name = item.get('volume')
            extra_volume = volume_name if volume_name and volume_name != target['volume'] else None
            mount_label = f'volume {extra_volume}' if extra_volume else '/config'
            if exists:
                entries.append(plan_doc.entry(
                    'carry', f'{source_path} -> {mount_label}' + (f'/{destination}' if destination else ''),
                    **{'from': source_path, 'to': destination,
                       **({'volume': extra_volume} if extra_volume else {})},
                ))
            elif item.get('required') and not external_db:
                refusals.append(f'required state {source_path} is missing at the source')
        plugins = recipe.get('plugins')
        if plugins and data_path and not data_in_tar:
            plugin_dir = recipe_store.expand(plugins['from'], values)
            carried_plugins, dropped_plugins = probes.classify_plugins(plugin_dir)
            for name in carried_plugins:
                entries.append(plan_doc.entry(
                    'carry', f'plugin {name} (frontend only) -> /config/{layout["plugins"]}/{name}',
                    **{'from': os.path.join(plugin_dir, name),
                       'to': f'{layout["plugins"]}/{name}'},
                ))
            for name in dropped_plugins:
                entries.append(plan_doc.entry(
                    'drop', f'plugin {name}: {plugins.get("drop_because", "backend plugins are not carried")}',
                    what=f'plugin:{name}',
                ))
        entries.append(plan_doc.entry(
            'rewrite', f'ownership: {description.get("uid")}:{description.get("uid")} -> '
            f'{target["uid"]}:{target["gid"]} on every carried file',
            what='ownership', **{'from': str(description.get('uid')), 'to': f'{target["uid"]}:{target["gid"]}'},
        ))

        legacy = probes.legacy_alerts_present(db_path) if db_path else 0
        hop = None
        if not grafana:
            pass
        elif legacy:
            candidate = next((
                item for item in recipe.get('hops') or [] if item['when'] == 'legacy_alerts_present'
            ), None)
            if candidate is None:
                refusals.append(f'{legacy} legacy dashboard alerts exist and Grafana 11+ cannot migrate them')
                preflights.append({'id': 'legacy_alerts_present', 'ok': False, 'detail': str(legacy)})
            elif not config.get('linux_compat_enabled'):
                refusals.append(
                    f'{legacy} legacy dashboard alerts need a migration hop through {candidate["image"]}, '
                    'which requires the Linux binary compatibility setting'
                )
                preflights.append({'id': 'legacy_alerts_present', 'ok': False, 'detail': str(legacy)})
            else:
                hop = copy.deepcopy(candidate)
                hop['count'] = legacy
                preflights.append({
                    'id': 'legacy_alerts_present', 'ok': True, 'detail': str(legacy), 'handled_by': 'hop',
                })
        else:
            preflights.append({'id': 'legacy_alerts_present', 'ok': True, 'detail': '0'})

        angular = probes.angular_panels(db_path) if db_path else []
        if grafana and angular:
            sample = ', '.join(f'{title} ({kind})' for title, kind in angular[:10])
            entries.append(plan_doc.entry(
                'rewrite', f'{len(angular)} AngularJS panels; core panels are migrated by Grafana on '
                f'first load, third-party Angular plugins stop rendering: {sample}',
                what='angular_panels', count=len(angular),
            ))
        if grafana:
            preflights.append({'id': 'angular_panels', 'ok': True, 'detail': str(len(angular))})
        if recipe.get('status') == 'draft':
            entries.append(plan_doc.entry(
                'note', f'the {recipe["app"]} recipe is a draft: its paths were reviewed against the '
                'package and the image, the migration itself has not been verified by FreeCORE',
                what='draft',
            ))

        for item in recipe.get('drop') or []:
            entries.append(plan_doc.entry('drop', item, what=item))
        for item in description.get('drops') or []:
            entries.append(plan_doc.entry('drop', item, what=item))
        for reason in [*description.get('refusals', []), *refusals]:
            entries.append(plan_doc.entry('refuse', reason, when=reason))
        return entries, preflights, hop, [*description.get('refusals', []), *refusals]

    def _compat_entries(self, description, config):
        entries = []
        refusals = list(description.get('refusals') or [])
        if not config.get('linux_compat_enabled'):
            refusals.append('the Linux binary compatibility setting is off')
        compose = description.get('compose')
        if compose:
            for volume in compose['volumes']:
                if volume['kind'] == 'bind':
                    location = bundle.resolve_bind(description['root'], volume['source'])
                else:
                    location = bundle.volume_tar(description['root'], volume['source'])
                if location is None:
                    refusals.append(f'volume {volume["source"]!r} for {volume["target"]} is not in the bundle')
                    continue
                entries.append(plan_doc.entry(
                    'carry', f'{location} -> {volume["target"]} (owned dataset)',
                    **{'from': location, 'to': volume['target'], 'volume': _volume_name(volume['target']),
                       'read_only': volume['read_only'], 'archive': volume['kind'] == 'volume'},
                ))
            for port in compose['ports']:
                entries.append(plan_doc.entry(
                    'note', f'port {port["host_port"]} -> {port["container_port"]}/{port["protocol"]} is published',
                    what='port', **port,
                ))
            entries.append(plan_doc.entry(
                'carry', f'{len(compose["environment"])} environment settings carried as declared',
                what='environment', count=len(compose['environment']),
            ))
            for item in compose['drops']:
                entries.append(plan_doc.entry('drop', item, what=item))
        entries.append(plan_doc.entry(
            'note', 'the Linux image runs under FreeBSD Linux binary compatibility: best effort, '
            'host-wide, no compatibility promise', what='compat',
        ))
        for reason in refusals:
            entries.append(plan_doc.entry('refuse', reason, when=reason))
        return entries, refusals

    # -- lift ----------------------------------------------------------------

    async def _lift_ports(self, description, options):
        """Ports to publish: the wizard's choice, else what the jail listens on, else the catalog's."""
        detected = []
        detected_from = None
        if description.get('jid'):
            detected = await jail_sources.listening_ports(description['jid'])
            detected_from = 'listening'
        if not detected:
            catalog_names = await self._catalog_names()
            packages = [
                {'name': item['name'], 'automatic': item['automatic']} for item in description.get('packages') or []
            ]
            for match in (await self._catalog_matches(packages, catalog_names))[:3]:
                try:
                    detail = await self.middleware.call('applications.catalog.details', f'daemonless:{match}')
                except CallError:
                    continue
                for port in ((detail.get('install') or {}).get('ports') or []):
                    detected.append({
                        'container_port': port['container_port'], 'protocol': port['protocol'],
                        'command': match, 'user': None, 'address': '*',
                    })
                if detected:
                    detected_from = f'catalog:{match}'
                    break
        chosen = options.get('ports') or []
        candidates = []
        if chosen:
            for item in chosen:
                if item.get('host_port') is None:
                    continue
                known = next((
                    port for port in detected
                    if port['container_port'] == item['container_port'] and port['protocol'] == item['protocol']
                ), {})
                candidates.append({**known, **item})
        else:
            for port in detected:
                free = await self.middleware.call(
                    'applications.host_port_free', port['container_port'], port['protocol'],
                )
                candidates.append({**port, 'host_port': port['container_port'] if free else None})
        return detected, detected_from, candidates

    async def _lift_entries(self, description, config, options):
        """The plan for lifting a jail as it is (the internal development record): typed rows plus what apply needs."""
        entries = []
        refusals = []
        root = description['root']
        parameters = description.get('parameters') or {}
        if description.get('dataset') is None:
            refusals.append(f'the jail root {root} is not a ZFS dataset; the lift reads a snapshot of one')
        if 'template' in (description.get('unsupported') or []):
            refusals.append('this is an iocage template, not a jail')
        base_root = description.get('base_root')
        if description.get('root_kind') in ('basejail', 'thin') and not base_root:
            refusals.append('the release this jail borrows its base system from is not present on this system')
        if base_root and not os.path.isdir(base_root):
            refusals.append(f'the base system at {base_root} is not readable')
        if description.get('root_kind') == 'clone' and not base_root:
            refusals.append(
                'the snapshot this jail was cloned from is not mounted; the lift needs it for the base layer'
            )

        exec_start = parameters.get('exec_start')
        if exec_start and exec_start not in LIFT_STANDARD_INIT:
            entries.append(plan_doc.entry(
                'note', f'the jail starts with {exec_start!r}; the application runs /etc/rc through jail-init instead',
                what='exec_start',
            ))
        for allowance in description.get('unsupported') or []:
            if allowance == 'template':
                continue
            entries.append(plan_doc.entry(
                'drop', f'{allowance} is set on the jail; Applications never grant mount or device allowances',
                what=allowance,
            ))
        ruleset = str(parameters.get('devfs_ruleset') or '')
        if ruleset not in ('', '4', '5', 'None'):
            entries.append(plan_doc.entry(
                'note', f'devfs ruleset {ruleset} is not carried; the application gets the runtime\'s device set',
                what='devfs_ruleset',
            ))
        for annotation in description.get('annotations') or []:
            entries.append(plan_doc.entry(
                'carry',
                f'jail parameter {annotation["name"].rsplit(".", 2)[-1]} -> {annotation["name"]}={annotation["value"]}',
                what='annotation', name=annotation['name'], value=annotation['value'],
            ))
        if description.get('state') == 'up':
            entries.append(plan_doc.entry(
                'note', 'the jail is running: the snapshot is crash-consistent, like a backup; stop the jail '
                'first for a clean copy of any database', what='running',
            ))

        state = await self.middleware.run_in_thread(lift_tool.state_volumes, root)
        for volume in state:
            entries.append(plan_doc.entry(
                'carry', f'{volume["target"]} -> owned dataset {volume["name"]} (state stays out of the image)',
                **{'from': os.path.join(root, volume['path']), 'to': volume['target'], 'volume': volume['name'],
                   'state': True},
            ))
        _rewritten, dropped = lift_tool.rewrite_rc_conf(description.get('rc_conf') or '')
        entries.append(plan_doc.entry(
            'rewrite', f'/etc/rc.conf: {len(dropped)} network identity settings removed'
            + (f' ({", ".join(sorted(set(dropped)))})' if dropped else ''),
            what='rc_conf', dropped=sorted(set(dropped)),
        ))

        external = []
        if description.get('fstab'):
            by_mountpoint = {}
            for dataset in await self.middleware.call('pool.dataset.query'):
                if dataset.get('mountpoint'):
                    by_mountpoint[os.path.normpath(dataset['mountpoint'])] = dataset['id']
            for mount in description['fstab']:
                if mount.get('base') or mount['target'] == '/' + lift_tool.BASTILLE_MOUNT:
                    # The jail's own base system (basejail directories, Bastille's /.bastille):
                    # that is the base layer, never a volume.
                    continue
                if mount['fstype'] != 'nullfs':
                    refusals.append(
                        f'fstab mounts {mount["source"]} at {mount["target"]} as {mount["fstype"]}; '
                        'only nullfs mounts of datasets carry'
                    )
                    continue
                dataset = by_mountpoint.get(mount['source'])
                if dataset is None:
                    refusals.append(
                        f'{mount["source"]} is mounted at {mount["target"]} but is not a dataset mountpoint; '
                        'Applications bind datasets, not directories'
                    )
                    continue
                name = f'mount-{_volume_name(mount["target"])}'[:63]
                external.append({
                    'name': name, 'target': mount['target'], 'dataset': dataset, 'read_only': mount['read_only'],
                })
                entries.append(plan_doc.entry(
                    'carry',
                    f'{mount["source"]} -> {mount["target"]} '
                    f'({"read-only" if mount["read_only"] else "read-write"}, dataset {dataset})',
                    **{'from': mount['source'], 'to': mount['target'], 'volume': name, 'dataset': dataset,
                       'read_only': mount['read_only']},
                ))

        detected, detected_from, candidates = await self._lift_ports(description, options)
        ports = []
        for port in candidates:
            label = f'{port["container_port"]}/{port["protocol"]}'
            if port.get('command'):
                label += f' ({port["command"]})'
            if port.get('host_port') is None:
                refusals.append(
                    f'choose a host port for {label}: {port["container_port"]} is in use on this system'
                )
                continue
            if options.get('ports'):
                free = await self.middleware.call(
                    'applications.host_port_free', port['host_port'], port['protocol'],
                )
                if not free:
                    refusals.append(f'host port {port["host_port"]}/{port["protocol"]} is in use on this system')
                    continue
            ports.append({
                'host_port': port['host_port'], 'container_port': port['container_port'], 'protocol': port['protocol'],
            })
            entries.append(plan_doc.entry(
                'note', f'{label} is published as host port {port["host_port"]}',
                what='port', **{'container_port': port['container_port'], 'protocol': port['protocol'],
                                'host_port': port['host_port']},
            ))
            address = str(port.get('address') or '')
            if lift_tool.is_loopback(address):
                # the internal development record: the BastilleBSD forgejo template renders
                # HTTP_ADDR = 127.0.0.1; published, the port answered nothing.
                entries.append(plan_doc.entry(
                    'note',
                    f'{label} is bound to {address} inside the jail; host port {port["host_port"]} will not reach '
                    'it until the service listens on all addresses (the configuration travels with the state '
                    'dataset, so it can be changed after the lift)',
                    what='loopback', warning=True, container_port=port['container_port'],
                    protocol=port['protocol'], address=address,
                ))
        if not candidates:
            if description.get('jid'):
                why = 'nothing in the running jail is listening and no catalog entry matches its packages'
            else:
                why = 'the jail is stopped and no catalog entry matches its packages'
            entries.append(plan_doc.entry(
                'note', f'no listening ports were detected ({why}); the application publishes nothing '
                'until ports are added',
                what='ports',
            ))
        address = str(parameters.get('ip4_addr') or '')
        if '|' in address:
            address = address.split('|', 1)[1]
        address = address.split('/', 1)[0].strip()
        if address and address.replace('.', '').isdigit():
            mentions = await self.middleware.run_in_thread(
                lift_tool.mentions_of, os.path.join(root, 'usr/local/etc'), address,
            )
            if mentions:
                entries.append(plan_doc.entry(
                    'note', f'the jail address {address} appears in {len(mentions)} configuration files '
                    f'({", ".join(mentions[:5])}); the application answers on the host\'s address and the '
                    'published ports', what='address', address=address, files=mentions,
                ))

        size = None
        if description.get('dataset'):
            size = await jail_sources.zfs_property(
                description['dataset'], 'used' if description.get('root_kind') == 'clone' else 'referenced',
            )
        base_reference = None
        base = description.get('base_release')
        if base_root and base:
            tag = lift_tool.sanitize_tag(base)
            if description.get('base_guid'):
                tag = f'{tag}-{str(description["base_guid"])[-10:]}'
            base_reference = f'{lift_tool.BASE_REPOSITORY}:{tag}'
        delta = {'clone': 'zfs-diff', 'basejail': 'walk', 'thin': 'walk'}.get(description.get('root_kind'), 'full')
        skip = []
        if description.get('root_kind') == 'basejail':
            skip = list(lift_tool.BASEJAIL_DIRECTORIES)
        elif description.get('root_kind') == 'thin':
            skip = sorted(await self.middleware.run_in_thread(lift_tool.bastille_borrowed, root))
        entries.append(plan_doc.entry(
            'carry', f'the jail\'s software as an image layer ({delta}'
            + (f' on base {base_reference}' if base_reference else ', single layer') + ')',
            what='image', delta=delta, base=base_reference,
        ))
        for reason in refusals:
            entries.append(plan_doc.entry('refuse', reason, when=reason))
        meta = {
            'engine': description.get('engine'),
            'root_kind': description.get('root_kind'),
            'release': description.get('release'),
            'userland': description.get('userland'),
            'origin': description.get('origin'),
            'base': {
                'reference': base_reference, 'root': base_root if base_reference else None,
                'release': base, 'guid': description.get('base_guid'),
            },
            'delta': delta,
            'skip': skip,
            'image_repository': f'{lift_tool.CONVERTED_REPOSITORY}/{self._application_name_for(description["ref"])}',
            'state_volumes': state,
            'external_volumes': external,
            'ports': ports,
            'ports_detected_from': detected_from,
            'annotations': [
                {'name': item['name'], 'value': item['value']} for item in description.get('annotations') or []
            ],
            'rc_conf_dropped': sorted(set(dropped)),
            'size_bytes': int(size) if size and str(size).isdigit() else None,
            'packages': [
                item['name'] for item in description.get('packages') or [] if not item.get('automatic')
            ][:24],
        }
        return entries, refusals, meta

    async def _snapshot_jail(self, description):
        name = f'{SNAPSHOT_PREFIX}{uuid.uuid4().hex[:12]}'
        await self.middleware.call('zfs.snapshot.create', {
            'dataset': description['dataset'], 'name': name, 'recursive': False,
        })
        return name

    @accepts(SOURCE_SCHEMA, PLAN_OPTIONS_SCHEMA)
    async def plan(self, source, options):
        """Write the plan the operator confirms. Nothing runs."""
        config = await self._applications_config()
        self._require_enabled(config)
        recipes, _ = self._load()
        description = await self._describe(source)
        recipe = recipes.get(description['app']) if description.get('recipe') else None

        native = {'available': False, 'image': None, 'version': None, 'catalog_id': None, 'reasons': []}
        compat = {'available': False, 'image': None, 'digest': None, 'reasons': []}
        lifted = {'available': False, 'image': None, 'base': None, 'reasons': ['only a jail can be lifted']}
        lift_entries, lift_meta = [], None
        entries = []
        preflights = []
        hop = None
        native_refusals = []
        native_ports = None
        if recipe is not None:
            detail = await self._target_detail(recipe)
            native.update({
                'image': detail['install']['image'] if detail.get('install') else None,
                'version': (detail.get('catalog') or {}).get('version'),
                'catalog_id': recipe['target']['catalog_id'],
                'compose_sha256': (detail.get('catalog') or {}).get('compose_sha256'),
            })
            entries, preflights, hop, native_refusals = await self.middleware.run_in_thread(
                self._native_entries, recipe, description, detail, config,
            )
            if description['kind'] == 'linux-export':
                native_ports, port_entries = self._export_port_decisions(
                    detail, description.get('compose') or {}, options.get('host_port'), recipe['target']['port'],
                )
                entries = [*entries, *port_entries]
            native['available'] = not native_refusals
            native['reasons'] = native_refusals
            if hop is not None:
                resolved = None
                try:
                    resolved = await inspect_remote_image(hop['image'], 'linux', 'amd64')
                except Exception:  # noqa: BLE001
                    resolved = None
                hop['digest'] = resolved['digest'] if resolved else None
                entries.append(plan_doc.entry(
                    'hop', f'run {hop["image"]} once against the staged data: {hop["purpose"]} '
                    f'({hop["count"]} legacy alerts)',
                    image=hop['image'], digest=hop['digest'], purpose=hop['purpose'],
                ))
        else:
            native['reasons'] = ['no recipe recognises this source']
            if source['kind'] == 'jail':
                for reason in description.get('refusals', []):
                    entries.append(plan_doc.entry('refuse', reason, when=reason))

        if source['kind'] == 'jail':
            lift_entries, lift_refusals, lift_meta = await self._lift_entries(description, config, options)
            lifted = {
                'available': not lift_refusals, 'reasons': lift_refusals,
                'image': lift_meta['image_repository'], 'base': lift_meta['base']['reference'],
                'release': lift_meta['release'], 'root_kind': lift_meta['root_kind'],
            }

        compat_entries = []
        compat_refusals = ['a jail cannot run under the Linux compatibility tier']
        if source['kind'] != 'jail':
            compat_entries, compat_refusals = self._compat_entries(description, config)
            lookup = description.get('lookup')
            if lookup is None and description.get('image'):
                lookup = await self.lookup(description['image'])
            compat.update({
                'image': description.get('image'),
                'digest': lookup['digest'] if lookup else None,
                'available': not compat_refusals,
                'reasons': compat_refusals,
            })

        mode = options.get('mode')
        if mode is None:
            if source['kind'] == 'jail':
                # the internal development record: as it is by default; a recipe's migration is offered, not assumed.
                mode = 'lift' if lifted['available'] else ('native' if native['available'] else None)
            else:
                mode = 'native' if native['available'] else ('compat' if compat['available'] else None)
        if mode == 'native' and not native['available']:
            raise CallError('Native conversion is not available: ' + '; '.join(native['reasons']) + '.')
        if mode == 'compat' and not compat['available']:
            raise CallError('Compatibility import is not available: ' + '; '.join(compat['reasons']) + '.')
        if mode == 'lift' and not lifted['available']:
            raise CallError('The lift is not available: ' + '; '.join(lifted['reasons']) + '.')
        if mode is None:
            reasons = [*native['reasons'], *compat['reasons']]
            if source['kind'] == 'jail':
                reasons.extend(lifted['reasons'])
            raise CallError('No conversion is available for this source: ' + '; '.join(reasons) + '.')
        chosen_entries = {'native': entries, 'compat': compat_entries, 'lift': lift_entries}[mode]

        application_name = options.get('name') or (
            self._application_name_for(description['ref']) if mode == 'lift' else None
        ) or description.get('app') or (
            description.get('compose', {}).get('service') if description.get('compose') else None
        ) or 'imported'
        host_port = options.get('host_port') or (recipe['target']['port'] if recipe else None)

        snapshot = None
        if source['kind'] == 'jail':
            snapshot = await self._snapshot_jail(description)
        plan = {
            'schema': PLAN_SCHEMA,
            'created_at': _now(),
            'source': {
                'kind': source['kind'],
                'engine': description.get('engine') if source['kind'] == 'jail' else None,
                'ref': description['ref'],
                'root': description.get('root'),
                'dataset': description.get('dataset'),
                'snapshot': snapshot,
                'fingerprint': description.get('fingerprint') or snapshot,
            },
            'app': {
                'name': description.get('app'),
                'title': recipe.get('title') if recipe else None,
                'version': description.get('version'),
                'recipe': description.get('recipe'),
                'recipe_status': description.get('recipe_status'),
            },
            # the internal development record: a native conversion from a Linux export carries its decided ports.
            'application': {
                'name': application_name, 'host_port': host_port,
                'ports': native_ports if mode == 'native' else None,
            },
            'modes': {'native': native, 'compat': compat, 'lift': lifted},
            'mode': mode,
            'recommended': (
                ('lift' if lifted['available'] else ('native' if native['available'] else None))
                if source['kind'] == 'jail' else
                ('native' if native['available'] else ('compat' if compat['available'] else None))
            ),
            'entries': chosen_entries,
            'preflights': preflights if mode == 'native' else [],
            'hop': hop if mode == 'native' else None,
            'lift': lift_meta if mode == 'lift' else None,
            'compose': description.get('compose') if mode == 'compat' else None,
            # The source's environment feeds the configuration carry in both modes:
            # a Linux export expresses most settings as GF_* environment.
            'environment': dict(description.get('environment') or {}),
            'paths': description.get('paths') if mode == 'native' else {},
            'uid': description.get('uid'),
        }
        plan['plan_id'] = plan_doc.plan_id(plan)
        try:
            self._write_plan(config, plan)
        except BaseException:
            if snapshot:
                await self._destroy_snapshot(description['dataset'], snapshot)
            raise
        return plan

    @filterable
    async def plans(self, filters=None, options=None):
        config = await self._applications_config()
        return filter_list(self._read_plans(config), filters, options)

    async def _destroy_snapshot(self, dataset, snapshot):
        if not dataset or not snapshot:
            return
        try:
            await self.middleware.call('zfs.snapshot.delete', f'{dataset}@{snapshot}', {'defer': False})
        except CallError as error:
            self.logger.warning('Unable to destroy conversion snapshot %s@%s: %s', dataset, snapshot, error)

    @accepts(Str('plan_id', validators=[Match(PLAN_ID)]))
    async def discard(self, plan_id):
        """Forget a plan and destroy the snapshot it holds on the source."""
        config = await self._applications_config()
        directory = None
        if not os.path.exists(os.path.join(self._plans_dir(config), f'{plan_id}.json')):
            # the internal development record: an export plan holds no snapshot.
            directory = self._export_plans_dir(config)
        plan = self._read_plan(config, plan_id, directory)
        await self._destroy_snapshot(plan['source'].get('dataset'), plan['source'].get('snapshot'))
        self._delete_plan(config, plan_id, directory)
        return True

    # -- export to a Linux host (the internal development record) --------------------

    def _export_plans_dir(self, config):
        return os.path.join(self._plans_dir(config), EXPORT_PLANS_SUBDIR)

    @staticmethod
    def _record_fingerprint(record):
        """What an export plan was written against: the image, its volumes and the last record change."""
        return hashlib.sha256(plan_doc.canonical({
            'image': record.get('image'),
            'digest': record.get('digest'),
            'updated_at': record.get('updated_at'),
            'volumes': [
                [volume.get('name'), volume.get('dataset'), volume.get('target'), volume.get('read_only')]
                for volume in record.get('volumes') or []
            ],
        })).hexdigest()

    async def _resolve_export_image(self, export, installed_version):
        """The best tag of the recipe's Linux image the registry answers for, with its labels."""
        for tag in export_tool.candidate_tags(export, installed_version):
            try:
                inspection = await inspect_remote_image(f'{export["image"]}:{tag}', 'linux', 'amd64')
            except Exception:  # noqa: BLE001
                self.logger.debug('Unable to inspect %s:%s', export['image'], tag, exc_info=True)
                continue
            return tag, inspection
        return None, None

    @filterable
    async def export_plans(self, filters=None, options=None):
        config = await self._applications_config()
        return filter_list(self._read_plans(config, self._export_plans_dir(config)), filters, options)

    @accepts(Str('name', validators=[Match(APPLICATION_NAME)]))
    async def export_plan(self, name):
        """Plan an export of an installed application as a Linux compose bundle.

        the internal development record.  Reads the record, the application's volume and
        the registry; nothing runs and nothing is snapshotted until ``export``.
        """
        config = await self._applications_config()
        self._require_enabled(config)
        record = await self.middleware.call('applications.catalog_record', name)
        recipes, equivalences = self._load()
        origin = record.get('origin') or {}
        if origin.get('mode') == 'lift' or record['image'].startswith('localhost/'):
            raise CallError(
                'This application is a lifted jail: its image is a FreeBSD userland with no Linux '
                'equivalent, so there is nothing a Linux host could run.'
            )
        catalog = record.get('catalog') if isinstance(record.get('catalog'), dict) else {}
        installed_version = catalog.get('version')
        environment = [(item['name'], item['value']) for item in record.get('environment') or []]
        ports = [
            {'host_port': port['host_port'], 'container_port': port['container_port'], 'protocol': port['protocol']}
            for port in record.get('ports') or []
        ]
        volumes = record.get('volumes') or []
        entries, refusals, commands, copies, compose_volumes = [], [], [], [], []
        taken = set()
        user = None
        target = {'image': None, 'digest': None, 'version': None}
        recipe = None
        state_volume = None

        def carry(volume, source, target_path, human):
            directory = export_tool.bundle_directory(target_path, taken)
            copies.append({
                'dataset': volume['dataset'], 'mountpoint': volume['source'], 'from': source, 'directory': directory,
            })
            compose_volumes.append({
                'kind': 'bundle', 'source': f'./{directory}', 'target': target_path, 'read_only': volume['read_only'],
                'dataset': volume['dataset'], 'mountpoint': volume['source'], 'from': source,
            })
            entries.append(plan_doc.entry(
                'carry', human, **{'from': source, 'to': target_path, 'directory': directory},
            ))

        if record.get('image_os') == 'linux':
            kind = 'identity'
            target.update(image=record['image'], digest=record.get('digest'))
            entries.append(plan_doc.entry(
                'note', 'the application already runs a Linux image; the bundle names it unchanged', what='identity',
            ))
        else:
            recipe = recipe_store.recipe_for_catalog_id(catalog.get('id'), recipes)
            mapping = recipe_store.export_mapping(recipe) if recipe else None
            if mapping is None:
                app = recipe['app'] if recipe else str(catalog.get('id') or '').partition(':')[2] or None
                repository = recipe_store.linux_image_for(app, recipe, equivalences) if app else None
                if repository is None:
                    raise CallError('No Linux image is known for this application, so there is nothing to export to.')
                kind = 'fresh'
                target['image'] = f'{recipe_store.normalize_reference(repository)["repository"]}:latest'
                entries.append(plan_doc.entry(
                    'note', 'fresh install -- no state carried: no recipe knows where this image keeps its '
                    'data, so the Linux service starts empty with the same settings', what='fresh',
                ))
            else:
                kind = 'state'
                export = recipe['sources']['linux']['export']
                state_volume = next((item for item in volumes if item['name'] == recipe['target']['volume']), None)
                if state_volume is None:
                    raise CallError(
                        f'The application has no {recipe["target"]["volume"]!r} volume for the recipe to read.'
                    )
                tag, inspection = await self._resolve_export_image(export, installed_version)
                if tag is None:
                    tag, inspection = 'latest', None
                    entries.append(plan_doc.entry(
                        'note', f'the registry could not be read for {export["image"]}; the bundle names :latest '
                        'unverified', what='registry',
                    ))
                version = export_tool.target_version(
                    tag, export.get('tag_template'), installed_version, (inspection or {}).get('labels'),
                )
                target.update(
                    image=f'{export["image"]}:{tag}', digest=(inspection or {}).get('digest'), version=version,
                )
                if version and installed_version and not plan_doc.not_older(version, installed_version):
                    raise CallError(
                        f'{export["image"]}:{tag} carries {version}, older than the installed {installed_version}; '
                        'an application never moves to an older version.'
                    )
                if version is None:
                    entries.append(plan_doc.entry(
                        'note', f'{export["image"]}:{tag} does not state its version; check it is not older than '
                        f'{installed_version or "the installed one"} before the first start', what='version',
                    ))
                if (recipe.get('status') or 'proven') == 'draft':
                    entries.append(plan_doc.entry(
                        'note', f'the {recipe["app"]} recipe is a draft: its paths were reviewed against both '
                        'images, the export itself has not been verified by FreeCORE', what='draft',
                    ))
                for item in mapping:
                    path = state_volume['source']
                    if item['from']:
                        path = os.path.join(path, item['from'])
                    if not await self.middleware.run_in_thread(os.path.exists, path):
                        if item['optional']:
                            entries.append(plan_doc.entry(
                                'note', f'{item["from"]} is not present; nothing to carry for {item["target"]}',
                                what='optional',
                            ))
                        else:
                            refusals.append(f'required state {path} is missing')
                        continue
                    carry(
                        state_volume, item['from'], item['target'],
                        f'{recipe["target"]["volume"]}/{item["from"]} -> {item["target"]} in the Linux image',
                    )
                uid, gid = export_tool.ownership(environment)
                environment, changes = export_tool.export_environment(environment, export)
                if export['user'] == 'puid':
                    present = {name for name, _value in environment}
                    for variable, value in (('PUID', uid), ('PGID', gid)):
                        if variable not in present:
                            environment.append((variable, str(value)))
                    entries.append(plan_doc.entry(
                        'rewrite', f'ownership stays {uid}:{gid}, expressed as PUID/PGID', what='ownership',
                    ))
                elif export['user'] == 'user':
                    user = f'{uid}:{gid}'
                    entries.append(plan_doc.entry(
                        'rewrite', f'ownership stays {uid}:{gid}, expressed as the service user', what='ownership',
                    ))
                else:
                    image_uid = export['image_uid']
                    human = f'the image runs as uid {image_uid}'
                    if image_uid not in (0, uid):
                        commands.extend(
                            f'chown -R {image_uid} ./{item["source"][2:]}'
                            for item in compose_volumes if item['kind'] == 'bundle'
                        )
                        human += f'; the copied state is owned by {uid} -- README.export lists the chown to run'
                    entries.append(plan_doc.entry('rewrite', human, what='ownership'))
                if changes:
                    entries.append(plan_doc.entry(
                        'rewrite', 'environment: ' + ', '.join(changes), what='environment', changes=changes,
                    ))
                for item in export.get('drop') or []:
                    entries.append(plan_doc.entry('drop', item, what=item))
            entries.append(plan_doc.entry(
                'rewrite', f'image {record["image"]} -> {target["image"]}', what='image',
                **{'from': record['image'], 'to': target['image']},
            ))

        # the internal development record: the files are rendered from this system's certificate store
        # into tmpfs; nothing of them belongs in a bundle, and the Linux host has its own store.
        for entry in record.get('certificates') or []:
            entries.append(plan_doc.entry(
                'drop', f'{entry["target"]}: the system certificate {entry["name"]!r} is mounted '
                'from this system\'s certificate store; attach the certificate on the Linux host',
                what='certificate', target=entry['target'],
            ))

        for volume in volumes:
            if state_volume is not None and volume['name'] == state_volume['name']:
                continue
            if volume.get('owned') and kind == 'identity':
                carry(volume, '', volume['target'], f'{volume["name"]} -> {volume["target"]}')
            elif volume.get('owned'):
                entries.append(plan_doc.entry(
                    'drop', f'{volume["target"]} ({volume["name"]}): application-owned scratch space, not carried',
                    what=volume['name'],
                ))
            else:
                compose_volumes.append({
                    'kind': 'host', 'source': volume['source'], 'target': volume['target'],
                    'read_only': volume['read_only'],
                })
                entries.append(plan_doc.entry(
                    'note', f'{volume["source"]} stays bound at {volume["target"]}; it is not copied -- mount the '
                    f'same data at {volume["target"]} on the Linux host, the application stores paths under it',
                    what='host_volume', target=volume['target'],
                ))

        # The pools behind this application, and the release they need: a bundle is a copy and never
        # depends on them, an in-place export moves the pool with the system.
        for pool in sorted({volume['dataset'].split('/')[0] for volume in volumes if volume.get('dataset')}):
            report = await self.middleware.run_in_thread(scale_config.pool_feature_report, pool)
            for line in scale_config.describe_pool_report(report):
                entries.append(plan_doc.entry(
                    'note', f'{line} (for an in-place export, which moves the pool)', what='pool_features', pool=pool,
                ))

        network = record.get('network') or {'mode': 'managed'}
        if network.get('mode') == 'lan':
            if not ports and recipe and recipe['target'].get('port'):
                port = recipe['target']['port']
                ports = [{'host_port': port, 'container_port': port, 'protocol': 'tcp'}]
            address = f' {network["address"]}' if network.get('address') else ''
            entries.append(plan_doc.entry(
                'drop', f'the application\'s own LAN address{address} -- the Linux service publishes its ports '
                'on the host instead', what='network',
            ))
        for port in ports:
            entries.append(plan_doc.entry(
                'note', 'port {host_port} -> {container_port}/{protocol} is published'.format(**port),
                what='port', **port,
            ))
        if record.get('annotations'):
            # A record's annotations are {name, value} pairs (see _validate_record); the plan names them.
            names = sorted(item['name'] for item in record['annotations'])
            entries.append(plan_doc.entry(
                'drop', 'FreeBSD jail annotations: ' + ', '.join(names), what='annotations',
            ))
        entries.append(plan_doc.entry(
            'drop', 'the Applications health probe -- the Linux host runs its own', what='healthcheck',
        ))
        if refusals:
            raise CallError('This application cannot be exported: ' + '; '.join(refusals) + '.')

        plan = {
            'schema': PLAN_SCHEMA,
            'direction': 'export',
            'created_at': _now(),
            'source': {'kind': 'application', 'ref': name, 'fingerprint': self._record_fingerprint(record)},
            'app': {
                'name': recipe['app'] if recipe else None,
                'title': recipe.get('title') if recipe else None,
                'version': installed_version,
                'recipe': f'{recipe["app"]}@{recipe["recipe_version"]}' if recipe and kind == 'state' else None,
                'recipe_status': (recipe.get('status') or 'proven') if recipe and kind == 'state' else None,
            },
            'kind': kind,
            'target': target,
            'compose': {
                'service': name,
                'environment': [[variable, value] for variable, value in environment],
                'ports': ports,
                'volumes': compose_volumes,
                'user': user,
                # the internal development record: the application's own labels travel with it. FreeCORE's
                # management labels are not in the record, so they cannot leak into the bundle.
                'labels': [
                    [item['name'], item['value']]
                    for item in sorted(record.get('labels') or [], key=lambda entry: entry['name'])
                ],
                # the internal development record: the provider's runtime options travel with it.
                'runtime': copy.deepcopy(record.get('runtime') or {}),
            },
            'copies': copies,
            'commands': commands,
            'entries': entries,
        }
        plan['plan_id'] = plan_doc.plan_id(plan)
        self._write_plan(config, plan, self._export_plans_dir(config))
        return plan

    async def _wait_job(self, method, *args):
        running = await self.middleware.call(method, *args)
        await running.wait()
        if running.error:
            raise CallError(f'{method} failed: {running.error}')

    @accepts(
        Str('plan_id', validators=[Match(PLAN_ID)]),
        Dict(
            'options',
            Str('destination', required=True),
            Str('mode', enum=list(EXPORT_MODES), default='bundle'),
            Bool('live', default=False),
            Bool('confirm', default=False),
            # Where this bundle directory's parent will be on the Linux host: binds are then written
            # absolute, which TrueNAS SCALE's Install via YAML needs (it does not resolve ./paths).
            Str('host_root', null=True, default=None),
        ),
    )
    @job(lock='applications_convert')
    async def export(self, job, plan_id, options):
        """Write the bundle of a confirmed export plan (the internal development record).

        The application's data is only read: it is stopped for the instant of a
        snapshot (unless ``live``), started again, and copied out of the
        snapshot.  ``in-place`` copies nothing and binds the application's own
        dataset paths, for moving the whole pool to the Linux host.
        """
        config = await self._applications_config()
        self._require_enabled(config)
        if not options['confirm']:
            raise CallError('Confirm the plan you reviewed; export runs only a confirmed plan.')
        directory = self._export_plans_dir(config)
        plan = self._read_plan(config, plan_id, directory)
        name = plan['source']['ref']
        record = await self.middleware.call('applications.catalog_record', name)
        if self._record_fingerprint(record) != plan['source']['fingerprint']:
            raise CallError('The application changed since this plan was written; plan the export again.')
        try:
            await self.middleware.run_in_thread(export_tool.check_destination, options['destination'])
        except CatalogContractError as error:
            raise CallError(str(error)) from error
        root = os.path.join(options['destination'], name)
        if os.path.lexists(root):
            raise CallError(f'{root} already exists; the export never overwrites.')
        in_place = options['mode'] == 'in-place'
        host_root = options.get('host_root')
        if host_root is not None:
            try:
                export_tool.check_host_root(host_root)
            except CatalogContractError as error:
                raise CallError(str(error)) from error
            if in_place:
                raise CallError('host_root applies to a bundle; an in-place export already binds absolute paths.')
        snapshot_name = f'{EXPORT_SNAPSHOT_PREFIX}{uuid.uuid4().hex[:12]}'
        snapshotted = []
        stopped = False
        created_root = False
        try:
            await self.middleware.run_in_thread(os.makedirs, root, 0o755)
            created_root = True
            if plan['copies'] and not in_place:
                if not options['live']:
                    running = await self.middleware.call('applications.query', [('name', '=', name)])
                    if running and running[0].get('running'):
                        job.set_progress(10, f'Stopping {name} for a consistent copy')
                        await self._wait_job('applications.stop', name)
                        stopped = True
                for dataset in sorted({item['dataset'] for item in plan['copies']}):
                    await self.middleware.call('zfs.snapshot.create', {
                        'dataset': dataset, 'name': snapshot_name, 'recursive': False,
                    })
                    snapshotted.append(dataset)
                if stopped:
                    job.set_progress(20, f'Starting {name} again')
                    await self._wait_job('applications.start', name)
                    stopped = False
                sizes = [
                    await self.middleware.run_in_thread(export_tool.logical_size, f'{dataset}@{snapshot_name}')
                    for dataset in snapshotted
                ]
                if sizes and None not in sizes:
                    needed = sum(sizes)
                    free = await self.middleware.run_in_thread(export_tool.free_bytes, options['destination'])
                    if needed > free:
                        raise CallError(
                            f'The bundle needs about {export_tool.human_size(needed)} and '
                            f'{options["destination"]} has {export_tool.human_size(free)} free.'
                        )
                for index, item in enumerate(plan['copies']):
                    source = os.path.join(item['mountpoint'], '.zfs', 'snapshot', snapshot_name)
                    if item['from']:
                        source = os.path.join(source, item['from'])
                    job.set_progress(
                        25 + int(60 * index / len(plan['copies'])),
                        f'Copying {item["from"] or "/"} to {item["directory"]}',
                    )
                    await self.middleware.run_in_thread(
                        export_tool.copy_state, source, os.path.join(root, item['directory']),
                    )
            volumes = []
            for volume in plan['compose']['volumes']:
                source = volume['source']
                if volume['kind'] == 'bundle' and in_place:
                    source = volume['mountpoint']
                    if volume['from']:
                        source = os.path.join(source, volume['from'])
                elif volume['kind'] == 'bundle' and host_root:
                    source = os.path.join(host_root, name, source[2:])
                volumes.append({'source': source, 'target': volume['target'], 'read_only': volume['read_only']})
            job.set_progress(90, 'Writing the compose file')
            text = export_tool.compose_text(
                plan['compose']['service'], plan['target']['image'],
                [tuple(item) for item in plan['compose']['environment']],
                plan['compose']['ports'], volumes, plan['compose']['user'],
                [f'FreeCORE export of application {name!r}, plan {plan_id}; see README.export.'],
                labels=[tuple(item) for item in plan['compose'].get('labels') or []],
                runtime=plan['compose'].get('runtime'),
            )
            compose_path = os.path.join(root, export_tool.COMPOSE_NAME)
            atomic_write(compose_path, text, mode=0o600)
            atomic_write(
                os.path.join(root, export_tool.README_NAME),
                export_tool.readme_text(plan, options['mode'], plan['commands'], host_root), mode=0o644,
            )
            fingerprint = await self.middleware.run_in_thread(bundle.fingerprint, root, text)
        except BaseException:
            if created_root:
                await self.middleware.run_in_thread(shutil.rmtree, root, True)
            raise
        finally:
            if stopped:
                try:
                    await self._wait_job('applications.start', name)
                except CallError as error:
                    self.logger.warning('Unable to start %s again after the export failed: %s', name, error)
            for dataset in snapshotted:
                await self._destroy_snapshot(dataset, snapshot_name)
        self._delete_plan(config, plan_id, directory)
        job.set_progress(100, f'Exported {name} to {root}')
        return {
            'path': root, 'compose': compose_path, 'mode': options['mode'],
            'image': plan['target']['image'], 'fingerprint': fingerprint,
        }

    # -- apply -------------------------------------------------------------

    async def _revalidate(self, plan):
        source = plan['source']
        if source['kind'] == 'jail':
            snapshots = await self.middleware.call(
                'zfs.snapshot.query', [('id', '=', f'{source["dataset"]}@{source["snapshot"]}')],
            )
            if not snapshots:
                raise CallError('The source snapshot this plan was written against no longer exists; plan again.')
            if source.get('engine') == 'bastille':
                jails = await self.middleware.call('bastille.query', [('id', '=', source['ref'])])
            else:
                jails = await self.middleware.call('jail.query', [('id', '=', source['ref'])])
            if not jails:
                raise CallError('The source jail no longer exists.')
            # the internal development record: a lift reads the snapshot only, so the jail may keep running.
            if plan['mode'] != 'lift' and jails[0].get('state') != 'down':
                raise CallError('The source jail must exist and be stopped.')
            return os.path.join(source['root'], '.zfs', 'snapshot', source['snapshot'])
        if source['kind'] == 'linux-export':
            found = await self.middleware.run_in_thread(bundle.discover, source['root'])
            fingerprint = await self.middleware.run_in_thread(
                bundle.fingerprint, found['root'], found['compose_text'],
            )
            if fingerprint != source['fingerprint']:
                raise CallError('The export bundle changed since the plan was written; plan again.')
            return source['root']
        return None

    @staticmethod
    def _copy_into(source, destination):
        if os.path.isdir(source):
            shutil.copytree(source, destination, symlinks=True, dirs_exist_ok=True)
        else:
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            shutil.copy2(source, destination, follow_symlinks=False)

    def _stage_native(self, plan, recipe, input_root, mountpoint, extra_mountpoints=None):
        """Copy the carried state and write the translated configuration.

        the internal development record: a carry entry naming a volume lands in that
        volume's mountpoint; everything else lands in the primary one.
        """
        source = plan['source']
        rebase = None
        if source['kind'] == 'jail':
            rebase = (source['root'], input_root)
        layout = recipe['target']['layout']
        for item in plan['entries']:
            if item['type'] != 'carry' or 'from' not in item or 'to' not in item:
                continue
            destination_root = (extra_mountpoints or {}).get(item.get('volume')) or mountpoint
            origin = item['from']
            if rebase and origin.startswith(rebase[0]):
                origin = rebase[1] + origin[len(rebase[0]):]
            if origin.startswith('tar:'):
                bundle.extract_volume(origin[4:], os.path.join(destination_root, layout['data']))
                continue
            self._copy_into(origin, os.path.join(destination_root, item['to']))
        for name in layout.values():
            if name.endswith('.ini') or not name:
                continue
            os.makedirs(os.path.join(mountpoint, name), exist_ok=True)
        if recipe_store.recipe_kind(recipe) != 'grafana' or not layout.get('ini'):
            return
        config_entry = next((item for item in plan['entries'] if item.get('what') == 'config'), None)
        sections = {}
        ini_path = (plan.get('paths') or {}).get('ini')
        if ini_path and rebase and ini_path.startswith(rebase[0]):
            ini_path = rebase[1] + ini_path[len(rebase[0]):]
        if ini_path and os.path.isfile(ini_path):
            with open(ini_path, 'r', encoding='utf-8', errors='replace') as file:
                sections = ini_carry.parse_ini(file.read())
        environment = dict(plan.get('environment') or {})
        if not environment and plan.get('compose'):
            environment = {item['name']: item['value'] for item in plan['compose']['environment']}
        source_definition = recipe['sources']['jail' if source['kind'] == 'jail' else 'linux']
        merged = ini_carry.merged(sections, ini_carry.env_overrides(
            environment, prefix=source_definition.get('env_prefix') or 'GF_', known_sections=tuple(sections),
        ))
        carried, _, _ = ini_carry.translate(merged, recipe['config']['allow'], recipe['config']['deny'])
        if config_entry is not None:
            wanted = set(config_entry.get('carried') or [])
            carried = {
                section: {key: value for key, value in values.items() if f'{section}.{key}' in wanted}
                for section, values in carried.items()
            }
        with open(os.path.join(mountpoint, layout['ini']), 'w', encoding='utf-8') as file:
            file.write(ini_carry.render(
                carried,
                header=f'Written by FreeCORE Convert & Import from {source["kind"]} {source["ref"]}\n'
                       f'plan {plan["plan_id"]}\nPaths, alerting and logging settings are owned by the image.',
            ))

    def _stage_compat(self, plan, mountpoints):
        for item in plan['entries']:
            if item['type'] != 'carry' or 'volume' not in item:
                continue
            destination = mountpoints[item['volume']]
            if item.get('archive'):
                bundle.extract_volume(item['from'], destination)
            else:
                self._copy_into(item['from'], destination)

    async def _chown(self, path, uid, gid):
        chown = await self.middleware.call('filesystem.chown', {
            'path': path, 'uid': uid, 'gid': gid,
            'options': {'recursive': True, 'traverse': True},
        })
        await chown.wait()
        if chown.error:
            raise CallError(f'Unable to set ownership on {path}: {chown.error}')

    async def _run_hop(self, job, plan, recipe, mountpoint):
        """Run the migration hop once against the staged data, then stop it."""
        hop = plan['hop']
        layout = recipe['target']['layout']
        image = f'{recipe_store.normalize_reference(hop["image"])["repository"]}@{hop["digest"]}' \
            if hop.get('digest') else hop['image']
        container = f'{HOP_CONTAINER_PREFIX}{uuid.uuid4().hex[:12]}'
        data_dir = os.path.join(mountpoint, layout['data'])
        await self._chown(data_dir, hop.get('uid', 472), hop.get('gid', 0))
        job.set_progress(55, f'Pulling migration hop image {hop["image"]}')
        await self.middleware.call(
            'applications.podman', 'pull', '--quiet', '--os', 'linux', '--arch', 'amd64', '--', image,
        )
        # No published ports: the hop gets its own network stack on the managed
        # bridge and is reachable by nobody. ``--network none`` is not that on
        # FreeBSD -- ocijail then inherits the host stack, and a hop listening on
        # its default port collides with whatever the host publishes there.
        arguments = ['run', '--detach', '--name', container, '--volume',
                     f'{data_dir}:{hop["data_target"]}:rw']
        for name, value in sorted((hop.get('env') or {}).items()):
            arguments.extend(['--env', f'{name}={value}'])
        arguments.extend(['--', image])
        job.set_progress(60, 'Running the migration hop')
        await self.middleware.call('applications.podman', *arguments)
        try:
            deadline = asyncio.get_running_loop().time() + int(hop.get('timeout') or 300)
            while True:
                logs = await self.middleware.call(
                    'applications.podman', 'logs', '--tail', '200', container, False,
                )
                text = f'{logs.get("stdout") or ""}{logs.get("stderr") or ""}'
                if hop['ready_log'] in text:
                    break
                inspection = await self.middleware.call('applications.podman', 'inspect', container, False)
                state = {}
                try:
                    parsed = json.loads(inspection.get('stdout') or '[]')
                    state = (parsed[0] if parsed else {}).get('State') or {}
                except (ValueError, TypeError, IndexError):
                    state = {}
                if state and not state.get('Running'):
                    raise CallError(
                        'The migration hop exited before it was ready: ' + text.strip()[-2048:]
                    )
                if asyncio.get_running_loop().time() >= deadline:
                    raise CallError('The migration hop did not become ready in time: ' + text.strip()[-2048:])
                await asyncio.sleep(HOP_POLL_INTERVAL)
            await self.middleware.call('applications.podman', 'stop', '--time', '30', container, False)
        finally:
            await self.middleware.call('applications.podman', 'rm', '--force', container, False)
        await self._chown(data_dir, recipe['target']['uid'], recipe['target']['gid'])

    async def _lift_listing(self, plan, snapshot_root):
        """The delta of the jail against its base: added/modified and removed paths."""
        source = plan['source']
        meta = plan['lift']
        if meta['delta'] == 'zfs-diff':
            completed = await run(
                ['/sbin/zfs', 'diff', '-FH', meta['origin'], f'{source["dataset"]}@{source["snapshot"]}'],
                check=False, encoding='utf8', errors='surrogateescape',
            )
            if completed.returncode:
                raise CallError(f'zfs diff failed: {(completed.stderr or "").strip()[-2048:]}')
            return lift_tool.parse_zfs_diff(completed.stdout or '', source['root'])
        added = await self.middleware.run_in_thread(lift_tool.walk_root, snapshot_root, meta.get('skip') or [])
        return added, set()

    async def _apply_lift(self, job, plan, config, name, origin, created):
        """Build the image from the snapshot, carry the state, install (the internal development record)."""
        source = plan['source']
        meta = plan['lift']
        snapshot_root = os.path.join(source['root'], '.zfs', 'snapshot', source['snapshot'])
        if not os.path.isdir(snapshot_root):
            raise CallError(f'The source snapshot is not readable at {snapshot_root}.')
        work = os.path.join(self._plans_dir(config), LIFT_WORK_SUBDIR, plan['plan_id'])
        environment = {**os.environ, **podman_environment(config['pool'])}
        image = f'{meta["image_repository"]}:{plan["plan_id"][:12]}'
        base = meta['base']['reference']
        built = False
        try:
            shutil.rmtree(work, ignore_errors=True)
            os.makedirs(work, mode=0o700, exist_ok=True)
            if base:
                exists = await self.middleware.call('applications.podman', 'image', 'exists', base, False)
                if exists['returncode'] != 0:
                    job.set_progress(10, f'Importing the {meta["base"]["release"]} base system as {base}')
                    await self.middleware.run_in_thread(
                        lift_tool.import_base, meta['base']['root'], base, {
                            'io.freecore.jail-base': str(meta['base']['release'] or ''),
                            'io.freecore.base-source': str(meta['base']['root'] or ''),
                            'io.freecore.base-guid': str(meta['base']['guid'] or ''),
                        }, environment,
                    )
            job.set_progress(25, 'Reading the jail delta')
            added, removed = await self._lift_listing(plan, snapshot_root)
            image_paths = lift_tool.partition(added, [volume['path'] for volume in meta['state_volumes']])
            image_paths.discard('etc/rc.conf')
            listing = os.path.join(work, 'image.list')
            await self.middleware.run_in_thread(lift_tool.write_listing, image_paths, listing)
            job.set_progress(35, f'Packing {len(image_paths)} entries of the jail into a layer')
            await self.middleware.run_in_thread(
                lift_tool.create_tar, snapshot_root, listing, os.path.join(work, 'delta.tar'),
            )
            overlay_etc = os.path.join(work, 'overlay', 'etc')
            os.makedirs(overlay_etc, mode=0o755, exist_ok=True)
            rc_conf = ''
            try:
                with open(os.path.join(snapshot_root, 'etc', 'rc.conf'), 'r', encoding='utf-8', errors='replace') as file:
                    rc_conf = file.read(1024 * 1024)
            except OSError:
                pass
            rewritten, _dropped = lift_tool.rewrite_rc_conf(rc_conf)
            with open(os.path.join(overlay_etc, 'rc.conf'), 'w', encoding='utf-8') as file:
                file.write(rewritten)
            os.chmod(os.path.join(overlay_etc, 'rc.conf'), 0o644)
            lift_tool.install_init(work)
            with open(os.path.join(work, 'Containerfile'), 'w', encoding='utf-8') as file:
                file.write(lift_tool.render_containerfile(base, removed, {
                    'io.freecore.converted-from': f'{meta["engine"]}:{source["ref"]}',
                    'io.freecore.jail-release': str(meta.get('release') or ''),
                    'io.freecore.jail-userland': str(meta.get('userland') or ''),
                    'io.freecore.plan': plan['plan_id'],
                }))
            job.set_progress(45, 'Building the application image')
            await self.middleware.call(
                'applications.podman', 'build', '--pull=never', '--tag', image,
                '--file', os.path.join(work, 'Containerfile'), work,
            )
            built = True

            job.set_progress(65, 'Carrying the jail state to owned datasets')
            volumes = []
            for volume in meta['state_volumes']:
                prepared = await self.middleware.call(
                    'applications.prepare_owned_volume', name, volume['name'], None,
                )
                created.extend(prepared['created'])
                if prepared['dataset'] not in prepared['created'] and os.listdir(prepared['mountpoint']):
                    raise CallError(
                        f'Dataset {prepared["dataset"]!r} already holds data; remove it or choose another name.'
                    )
                tree = os.path.join(snapshot_root, volume['path'])
                state_list = os.path.join(work, f'{volume["name"]}.list')
                paths = await self.middleware.run_in_thread(lift_tool.state_listing, snapshot_root, volume['path'])
                await self.middleware.run_in_thread(lift_tool.write_listing, paths, state_list)
                await self.middleware.run_in_thread(lift_tool.copy_tree, tree, state_list, prepared['mountpoint'])
                volumes.append({
                    'name': volume['name'], 'target': volume['target'], 'dataset': None, 'read_only': False,
                })
            for external in meta['external_volumes']:
                volumes.append({
                    'name': external['name'], 'target': external['target'],
                    'dataset': external['dataset'], 'read_only': bool(external['read_only']),
                })

            job.set_progress(80, 'Installing the lifted application')
            subjob = await self.middleware.call('applications.install_with_origin', {
                'name': name,
                'image': image,
                'image_os': 'freebsd',
                'ports': [
                    {'host_port': port['host_port'], 'container_port': port['container_port'],
                     'protocol': port['protocol']} for port in meta['ports']
                ],
                'environment': [],
                'volumes': volumes,
                'annotations': copy.deepcopy(meta['annotations']),
                'labels': [],
                # the internal development record: a lifted jail mounts no system certificate; the
                # operator attaches one afterwards (Edit) if it needs one.
                'certificates': [],
                'restart_policy': 'always',
                'portal': None,
                'healthcheck': None,
                'health_timeout': 60,
            }, {
                **origin,
                'engine': meta['engine'],
                'release': meta.get('release'),
                'userland': meta.get('userland'),
                'root_kind': meta.get('root_kind'),
                'image': image,
                'image_owned': True,
                'base_image': base,
            })
            return await job.wrap(subjob)
        except BaseException:
            if built:
                try:
                    await self.middleware.call('applications.podman', 'rmi', '--force', image, False)
                except Exception:  # noqa: BLE001
                    self.logger.warning('Unable to remove the lifted image %s', image, exc_info=True)
            raise
        finally:
            shutil.rmtree(work, ignore_errors=True)

    @accepts(
        Str('plan_id', validators=[Match(PLAN_ID)]),
        Dict('options', Bool('confirm', default=False), default={}),
    )
    @job(lock='applications_convert')
    async def apply(self, job, plan_id, options):
        """Run a confirmed plan. The source is never written; failures leave the plan to retry."""
        config = await self._applications_config()
        self._require_enabled(config)
        if not options['confirm']:
            raise CallError('Confirm the plan you reviewed; apply runs only a confirmed plan.')
        plan = self._read_plan(config, plan_id)
        recipes, _ = self._load()
        recipe = recipes.get(plan['app']['name']) if plan['app'].get('recipe') else None
        if plan['mode'] == 'native' and recipe is None:
            raise CallError('The recipe this plan was written against is no longer shipped.')
        if any(item['type'] == 'refuse' for item in plan['entries']):
            raise CallError('This plan contains refusals and cannot be applied.')
        name = plan['application']['name']
        records = await self.middleware.call('applications.query', [('name', '=', name)])
        if records:
            raise CallError(f'An application named {name!r} already exists.')
        existing = await self.middleware.call(
            'applications.query', [('origin.plan_id', '=', plan_id)],
        )
        if existing:
            raise CallError('This plan was already applied.')

        job.set_progress(5, 'Re-validating the source')
        input_root = await self._revalidate(plan)
        origin = {
            'kind': 'convert',
            'reference': plan['source']['ref'],
            'source_kind': plan['source']['kind'],
            'plan_id': plan_id,
            'mode': plan['mode'],
            'recipe': plan['app'].get('recipe'),
            'fingerprint': plan['source'].get('fingerprint'),
            'converted_at': _now(),
        }
        created = []
        try:
            if plan['mode'] == 'lift':
                result = await self._apply_lift(job, plan, config, name, origin, created)
            elif plan['mode'] == 'native':
                target = recipe['target']
                job.set_progress(15, 'Preparing the application dataset')
                volume = await self.middleware.call(
                    'applications.prepare_owned_volume', name, target['volume'],
                    [target['uid'], target['gid']],
                )
                created.extend(volume['created'])
                if volume['dataset'] not in volume['created'] and os.listdir(volume['mountpoint']):
                    raise CallError(
                        f'Dataset {volume["dataset"]!r} already holds data; remove it or choose another name.'
                    )
                extra_specs = target.get('volumes') or {}
                extra_names = sorted({
                    carried['volume'] for carried in plan['entries']
                    if carried.get('type') == 'carry' and carried.get('volume')
                } - {target['volume']})
                extra_volumes = {}
                for extra_name in extra_names:
                    spec = extra_specs.get(extra_name) or {}
                    extra = await self.middleware.call(
                        'applications.prepare_owned_volume', name, extra_name,
                        [spec.get('uid', target['uid']), spec.get('gid', target['gid'])],
                    )
                    created.extend(extra['created'])
                    if extra['dataset'] not in extra['created'] and os.listdir(extra['mountpoint']):
                        raise CallError(
                            f'Dataset {extra["dataset"]!r} already holds data; remove it or choose another name.'
                        )
                    extra_volumes[extra_name] = extra
                job.set_progress(30, 'Carrying application state')
                await self.middleware.run_in_thread(
                    self._stage_native, plan, recipe, input_root, volume['mountpoint'],
                    {key: value['mountpoint'] for key, value in extra_volumes.items()},
                )
                await self._chown(volume['mountpoint'], target['uid'], target['gid'])
                for extra_name, extra in extra_volumes.items():
                    spec = extra_specs.get(extra_name) or {}
                    await self._chown(
                        extra['mountpoint'], spec.get('uid', target['uid']), spec.get('gid', target['gid']),
                    )
                if plan.get('hop'):
                    await self._run_hop(job, plan, recipe, volume['mountpoint'])
                job.set_progress(70, 'Installing the native application')
                detail_ports = await self.middleware.call(
                    'applications.catalog.details', target['catalog_id'],
                )
                ports = []
                decided = plan['application'].get('ports')
                for port in detail_ports['install']['ports']:
                    if decided is not None:
                        # the internal development record: the ports the reviewed plan decided, unpublished ones included.
                        match = next((
                            item for item in decided
                            if item['container_port'] == port['container_port'] and item['protocol'] == port['protocol']
                        ), None)
                        if match is None:
                            raise CallError(
                                f'The catalog entry {target["catalog_id"]} declares port '
                                f'{port["container_port"]}/{port["protocol"]}, which the plan does not; plan again.'
                            )
                        host_port = match['host_port']
                    else:
                        host_port = port['host_port']
                        if port['container_port'] == target['port'] and plan['application'].get('host_port'):
                            host_port = plan['application']['host_port']
                    ports.append({
                        'host_port': host_port, 'container_port': port['container_port'],
                        'protocol': port['protocol'],
                    })
                install, provenance = await self.middleware.call('applications.catalog.bind_install', {
                    'id': target['catalog_id'],
                    'compose_sha256': detail_ports['catalog']['compose_sha256'],
                    'name': name,
                    'ports': ports,
                    'environment': [
                        {'name': item['name'], 'value': item['value']}
                        for item in detail_ports['install']['environment']
                    ],
                    'volumes': [
                        {'name': item['name'], 'dataset': None}
                        for item in detail_ports['install']['volumes']
                    ],
                    'restart_policy': 'always',
                    'health_timeout': 180,
                })
                subjob = await self.middleware.call(
                    'applications.install_catalog', install, provenance, origin,
                )
                result = await job.wrap(subjob)
            else:
                job.set_progress(15, 'Preparing the application datasets')
                mountpoints = {}
                volumes = []
                for item in plan['entries']:
                    if item['type'] != 'carry' or 'volume' not in item:
                        continue
                    prepared = await self.middleware.call(
                        'applications.prepare_owned_volume', name, item['volume'], None,
                    )
                    created.extend(prepared['created'])
                    if prepared['dataset'] not in prepared['created'] and os.listdir(prepared['mountpoint']):
                        raise CallError(
                            f'Dataset {prepared["dataset"]!r} already holds data; remove it or choose another name.'
                        )
                    mountpoints[item['volume']] = prepared['mountpoint']
                    volumes.append({
                        'name': item['volume'], 'target': item['to'], 'dataset': None,
                        'read_only': bool(item.get('read_only')),
                    })
                job.set_progress(30, 'Carrying volumes')
                await self.middleware.run_in_thread(self._stage_compat, plan, mountpoints)
                compose = plan['compose'] or {}
                image = plan['modes']['compat']['image']
                digest = plan['modes']['compat'].get('digest')
                if digest:
                    image = f'{recipe_store.normalize_reference(image)["repository"]}@{digest}'
                healthcheck = None
                if compose.get('healthcheck'):
                    match = next((
                        port for port in compose['ports']
                        if port['container_port'] == compose['healthcheck']['container_port']
                        and port['protocol'] == 'tcp'
                    ), None)
                    if match:
                        healthcheck = {
                            'type': 'HTTP', 'scheme': 'http',
                            'container_port': match['container_port'], 'host_port': match['host_port'],
                            'path': compose['healthcheck']['path'],
                        }
                job.set_progress(70, 'Installing the Linux image under the compatibility tier')
                subjob = await self.middleware.call('applications.install_with_origin', {
                    'name': name,
                    'image': image,
                    'image_os': 'linux',
                    'ports': copy.deepcopy(compose.get('ports') or []),
                    'environment': copy.deepcopy(compose.get('environment') or []),
                    'volumes': volumes,
                    'annotations': [],
                    'labels': [
                        {'name': key, 'value': value}
                        for key, value in sorted((compose.get('labels') or {}).items())
                        if not key.startswith('io.freecore.')
                    ],
                    # the internal development record: an imported Compose service brings no system
                    # certificate; a mount is the operator's choice afterwards.
                    'certificates': [],
                    'restart_policy': compose.get('restart') or 'always',
                    'portal': None,
                    'healthcheck': healthcheck,
                    'health_timeout': 180,
                }, origin)
                result = await job.wrap(subjob)
        except BaseException:
            if created:
                try:
                    await self.middleware.call('applications.discard_owned_datasets', name, created)
                except Exception:  # noqa: BLE001
                    self.logger.warning('Unable to remove staged datasets for %r', name, exc_info=True)
            raise

        await self._destroy_snapshot(plan['source'].get('dataset'), plan['source'].get('snapshot'))
        self._delete_plan(config, plan_id)
        job.set_progress(100, 'Conversion complete; the source was not modified')
        return result
