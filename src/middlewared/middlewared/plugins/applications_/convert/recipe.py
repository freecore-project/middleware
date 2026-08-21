"""Recipes and the image equivalence table (the internal development record, #445).

A recipe is deliberately dumb JSON: where an application keeps its state in
each source, what to carry, what to deny in its configuration, what to refuse
and what to drop.  The target half is derived from the Daemonless entry and
image; only the source half and the app knowledge are hand-written.
"""
import json
import os
import re
from pathlib import Path

from middlewared.plugins.applications_.catalog import CatalogContractError

RECIPES_DIR = Path(__file__).parent / 'recipes'
APP_NAME = re.compile(r'^[a-z0-9][a-z0-9._-]{0,62}$')
PATH_KEY = re.compile(r'^[a-z][a-z0-9_]*$')
RESERVED_PATH_KEYS = {'data', 'ini', 'provisioning'}
REQUIRED_RECIPE_KEYS = {'app', 'recipe_version', 'target', 'sources', 'carry'}
REQUIRED_TARGET_KEYS = {'catalog_id', 'volume', 'layout', 'uid', 'gid'}
RECIPE_KINDS = ('generic', 'grafana')
RECIPE_STATUSES = ('proven', 'draft')
# the internal development record: how an exported compose expresses file ownership.
EXPORT_USER_MODES = ('puid', 'user', 'image')
TAG_TEMPLATE = re.compile(r'^[A-Za-z0-9_.{}-]{1,128}$')
ENVIRONMENT_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def recipe_kind(recipe):
    return recipe.get('kind') or 'generic'


def _load_json(path):
    with open(path, 'rb') as file:
        return json.loads(file.read().decode('utf-8'))


def validate_recipe(recipe):
    if not isinstance(recipe, dict) or not REQUIRED_RECIPE_KEYS <= set(recipe):
        raise CatalogContractError('Recipe is missing required fields.')
    if not isinstance(recipe['app'], str) or not APP_NAME.fullmatch(recipe['app']):
        raise CatalogContractError('Recipe application name is invalid.')
    target = recipe['target']
    if not isinstance(target, dict) or not REQUIRED_TARGET_KEYS <= set(target):
        raise CatalogContractError(f'Recipe {recipe["app"]!r} target is incomplete.')
    if not isinstance(target['layout'], dict) or not target['layout']:
        raise CatalogContractError(f'Recipe {recipe["app"]!r} target layout is invalid.')
    sources = recipe['sources']
    if not isinstance(sources, dict) or not sources:
        raise CatalogContractError(f'Recipe {recipe["app"]!r} declares no sources.')
    if 'jail' in sources and not {'detect', 'data', 'uid'} <= set(sources['jail']):
        raise CatalogContractError(f'Recipe {recipe["app"]!r} jail source is incomplete.')
    if 'linux' in sources and not {'images', 'data', 'uid'} <= set(sources['linux']):
        raise CatalogContractError(f'Recipe {recipe["app"]!r} linux source is incomplete.')
    for kind_name in ('jail', 'linux'):
        extra_paths = (sources.get(kind_name) or {}).get('paths')
        if extra_paths is None:
            continue
        if not isinstance(extra_paths, dict):
            raise CatalogContractError(f'Recipe {recipe["app"]!r} {kind_name} paths must be a map.')
        for key, value in extra_paths.items():
            if not PATH_KEY.fullmatch(key) or key in RESERVED_PATH_KEYS:
                raise CatalogContractError(f'Recipe {recipe["app"]!r} names a reserved or invalid path {key!r}.')
            if not isinstance(value, str) or not value:
                raise CatalogContractError(f'Recipe {recipe["app"]!r} path {key!r} is empty.')
    config = recipe.setdefault('config', {'allow': [], 'deny': []})
    if not isinstance(config, dict) or not isinstance(config.get('allow'), list) or \
            not isinstance(config.get('deny'), list):
        raise CatalogContractError(f'Recipe {recipe["app"]!r} config lists are invalid.')
    if recipe_kind(recipe) not in RECIPE_KINDS:
        raise CatalogContractError(f'Recipe {recipe["app"]!r} kind is unknown.')
    if recipe_kind(recipe) == 'grafana' and not target['layout'].get('ini'):
        raise CatalogContractError(f'Recipe {recipe["app"]!r} translates an ini but names none.')
    if (recipe.get('status') or 'proven') not in RECIPE_STATUSES:
        raise CatalogContractError(f'Recipe {recipe["app"]!r} status is unknown.')
    extra_volumes = recipe['target'].get('volumes')
    if extra_volumes is not None:
        if not isinstance(extra_volumes, dict):
            raise CatalogContractError(f'Recipe {recipe["app"]!r} target volumes must be a map.')
        for volume_name, spec in extra_volumes.items():
            if not isinstance(volume_name, str) or not volume_name or not isinstance(spec, dict) \
                    or not isinstance(spec.get('uid'), int) or not isinstance(spec.get('gid'), int):
                raise CatalogContractError(
                    f'Recipe {recipe["app"]!r} target volume {volume_name!r} needs uid and gid.')
    for item in recipe['carry']:
        if not isinstance(item, dict) or not {'from', 'to'} <= set(item):
            raise CatalogContractError(f'Recipe {recipe["app"]!r} carry entry is invalid.')
        volume_name = item.get('volume')
        if volume_name is not None:
            if not isinstance(volume_name, str) or not volume_name:
                raise CatalogContractError(f'Recipe {recipe["app"]!r} carry volume is invalid.')
            if volume_name != recipe['target']['volume'] and volume_name not in (extra_volumes or {}):
                raise CatalogContractError(
                    f'Recipe {recipe["app"]!r} carries into undeclared volume {volume_name!r}.')
    for hop in recipe.get('hops') or []:
        if not isinstance(hop, dict) or not {'when', 'image', 'data_target', 'ready_log'} <= set(hop):
            raise CatalogContractError(f'Recipe {recipe["app"]!r} hop is invalid.')
    if (sources.get('linux') or {}).get('export') is not None:
        _validate_export(recipe, sources['linux']['export'])
    return recipe


def _validate_export(recipe, export):
    """The Linux export target of a recipe (the internal development record)."""
    app = recipe['app']
    if not isinstance(export, dict):
        raise CatalogContractError(f'Recipe {app!r} export must be a map.')
    image = export.get('image')
    if not isinstance(image, str) or not image or '@' in image or ':' in image.rsplit('/', 1)[-1] \
            or any(character.isspace() for character in image):
        raise CatalogContractError(f'Recipe {app!r} export image must be a repository without a tag.')
    if export.get('user') not in EXPORT_USER_MODES:
        raise CatalogContractError(f'Recipe {app!r} export user must be one of {", ".join(EXPORT_USER_MODES)}.')
    if export['user'] == 'image' and not (isinstance(export.get('image_uid'), int) and export['image_uid'] >= 0):
        raise CatalogContractError(f'Recipe {app!r} export runs as the image user but names no image_uid.')
    template = export.get('tag_template')
    if template is not None and not (isinstance(template, str) and '{version}' in template and
                                     TAG_TEMPLATE.fullmatch(template)):
        raise CatalogContractError(f'Recipe {app!r} export tag_template is invalid.')
    environment = export.get('environment') or {}
    if not isinstance(environment, dict) or any(
        not isinstance(name, str) or not ENVIRONMENT_NAME.fullmatch(name) or not isinstance(value, str)
        for name, value in environment.items()
    ):
        raise CatalogContractError(f'Recipe {app!r} export environment is invalid.')
    for key in ('drop_environment', 'drop'):
        values = export.get(key) or []
        if not isinstance(values, list) or any(not isinstance(value, str) or not value for value in values):
            raise CatalogContractError(f'Recipe {app!r} export {key} is invalid.')
    volumes = export.get('volumes')
    if volumes is not None:
        if not isinstance(volumes, list) or not volumes:
            raise CatalogContractError(f'Recipe {app!r} export volumes must be a non-empty list.')
        for volume in volumes:
            if not isinstance(volume, dict) or not isinstance(volume.get('from'), str) or \
                    not isinstance(volume.get('target'), str):
                raise CatalogContractError(f'Recipe {app!r} export volume is invalid.')
            source, target = volume['from'], volume['target']
            if source.startswith('/') or '..' in source.split('/'):
                raise CatalogContractError(f'Recipe {app!r} export volume {source!r} escapes the volume.')
            if not target.startswith('/') or os.path.normpath(target) != target or ':' in target:
                raise CatalogContractError(f'Recipe {app!r} export target {target!r} is not a clean absolute path.')
    if not export_mapping(recipe):
        raise CatalogContractError(
            f'Recipe {app!r} export needs explicit volumes: its carries do not all start at {{data}}.'
        )


def export_mapping(recipe):
    """Where the recipe's Linux image expects each piece of the Daemonless volume.

    the internal development record.  ``from`` is relative to the target volume (the
    Daemonless ``/config``), ``target`` is the Linux container path.  Explicit
    ``export.volumes`` win; otherwise the import carries are run backwards,
    which works when every carry reads below ``{data}``.  None when the recipe
    has no export target or the carries cannot be reversed.
    """
    linux = recipe['sources'].get('linux') or {}
    export = linux.get('export')
    if not export:
        return None
    if export.get('volumes'):
        return [
            {'from': volume['from'].strip('/'), 'target': volume['target'], 'optional': bool(volume.get('optional'))}
            for volume in export['volumes']
        ]
    layout = {f'layout.{key}': value for key, value in recipe['target']['layout'].items()}
    mapping = []
    for item in recipe['carry']:
        if item.get('volume') not in (None, recipe['target']['volume']) or not item['from'].startswith('{data}'):
            return None
        rest = item['from'][len('{data}'):].strip('/')
        target = linux['data'].rstrip('/') + (f'/{rest}' if rest else '')
        mapping.append({
            'from': expand(item['to'], layout).strip('/'),
            'target': target or '/',
            'optional': bool(item.get('optional')),
        })
    return mapping


def recipe_for_catalog_id(catalog_id, recipes):
    """The recipe whose Daemonless target is this catalog entry, or None."""
    if not isinstance(catalog_id, str):
        return None
    for recipe in recipes.values():
        if recipe['target']['catalog_id'] == catalog_id:
            return recipe
    return None


def linux_image_for(app, recipe, equivalences):
    """The Linux repository a fresh install of ``app`` would name, or None (the internal development record).

    The recipe's export image first, then its first matched Linux image, then an
    exact equivalence-table entry; never a family guess.
    """
    linux = (recipe or {}).get('sources', {}).get('linux') or {}
    if linux.get('export'):
        return linux['export']['image']
    if linux.get('images'):
        return linux['images'][0]
    for entry in equivalences.get('entries', []):
        if entry.get('app') == app and not entry.get('refuse'):
            return entry['match']
    return None


def load_recipes(directory=None):
    directory = Path(directory or RECIPES_DIR)
    recipes = {}
    for path in sorted(directory.glob('*.json')):
        if path.name == 'equivalences.json':
            continue
        recipe = validate_recipe(_load_json(path))
        recipes[recipe['app']] = recipe
    return recipes


def load_equivalences(directory=None):
    path = Path(directory or RECIPES_DIR) / 'equivalences.json'
    data = _load_json(path)
    if not isinstance(data, dict) or data.get('schema') != 1 or not isinstance(data.get('entries'), list):
        raise CatalogContractError('Equivalence table is invalid.')
    return data


def normalize_reference(reference):
    """Canonical repository, tag and digest of an image reference.

    ``grafana/grafana:8.5`` becomes ``docker.io/grafana/grafana``; ``nginx`` becomes
    ``docker.io/library/nginx``.  The tag defaults to ``latest`` when absent.
    """
    if not isinstance(reference, str) or not reference or any(character.isspace() for character in reference):
        raise CatalogContractError('Image reference is invalid.')
    digest = None
    if '@' in reference:
        reference, digest = reference.split('@', 1)
    tag = None
    name = reference
    last_slash = reference.rfind('/')
    last_colon = reference.rfind(':')
    if last_colon > last_slash:
        name, tag = reference[:last_colon], reference[last_colon + 1:]
    components = name.split('/')
    first = components[0]
    if len(components) == 1:
        components = ['docker.io', 'library', first]
    elif '.' not in first and ':' not in first and first != 'localhost':
        components = ['docker.io', *components]
    repository = '/'.join(components)
    if repository.startswith('docker.io/') and len(components) == 2:
        repository = f'docker.io/library/{components[1]}'
    return {'repository': repository, 'tag': tag or ('latest' if digest is None else None), 'digest': digest}


def equivalence_lookup(reference, equivalences, catalog_names=None):
    """Which Daemonless application a Linux image corresponds to, and why."""
    normalized = normalize_reference(reference)
    repository = normalized['repository']
    for entry in equivalences.get('entries', []):
        if normalize_reference(entry['match'])['repository'] == repository:
            if entry.get('refuse'):
                return {'kind': 'table', 'app': None, 'refuse': entry['refuse'], 'confidence': 'exact'}
            return {'kind': 'table', 'app': entry['app'], 'refuse': None, 'confidence': 'exact'}
    for family in equivalences.get('families', []):
        for prefix in family.get('prefixes', []):
            if repository.startswith(prefix):
                name = repository[len(prefix):].split('/')[0]
                if catalog_names is None or name in catalog_names:
                    return {
                        'kind': 'family', 'app': name, 'refuse': None, 'confidence': 'family',
                        'family': family['id'],
                    }
    name = repository.rsplit('/', 1)[-1]
    if catalog_names and name in catalog_names:
        return {'kind': 'name', 'app': name, 'refuse': None, 'confidence': 'suggestion'}
    return {'kind': 'none', 'app': None, 'refuse': None, 'confidence': None}


def recipe_for_linux_image(reference, recipes):
    """The recipe whose linux source claims this image, and any explicit refusal."""
    repository = normalize_reference(reference)['repository']
    for recipe in recipes.values():
        source = recipe['sources'].get('linux')
        if not source:
            continue
        for item in source.get('refuse_images', []):
            if normalize_reference(item['match'])['repository'] == repository:
                return recipe, item.get('because') or 'refused by recipe'
        for image in source['images']:
            if normalize_reference(image)['repository'] == repository:
                return recipe, None
    return None, None


def match_jail(root, recipes):
    """The recipe whose detect paths all exist under a jail root, or None."""
    for recipe in recipes.values():
        source = recipe['sources'].get('jail')
        if not source:
            continue
        if all(os.path.exists(os.path.join(root, path)) for path in source['detect']):
            return recipe
    return None


def expand(template, values):
    """Fill ``{data}`` / ``{layout.data}`` placeholders from a values map."""
    def replace(match):
        key = match.group(1)
        if key not in values:
            raise CatalogContractError(f'Recipe placeholder {key!r} is not defined.')
        return values[key]
    return re.sub(r'\{([a-z_.]+)\}', replace, template)
