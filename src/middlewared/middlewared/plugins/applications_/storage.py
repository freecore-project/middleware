"""Recover Podman's explicit ZFS mounts after appliance pool import."""

import json
import os
import re
import stat
from pathlib import Path

from middlewared.service_exception import CallError
from middlewared.utils import run


LAYER_ID = re.compile(r'^[0-9a-f]{64}$')
MAX_LAYER_METADATA_SIZE = 16 * 1024 * 1024
OWNER_PROPERTY = 'org.freecore:managedby'
PROPERTIES = f'type,guid,mountpoint,mounted,{OWNER_PROPERTY}'


def read_layer_ids(storage):
    path = Path(storage) / 'zfs-layers' / 'layers.json'
    if os.path.realpath(path) != str(path):
        raise CallError('Podman layer metadata must not contain symbolic links.')
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_mode & 0o022 or info.st_nlink != 1
            ):
                raise ValueError('unsafe ownership or file type')
            content = stream.read(MAX_LAYER_METADATA_SIZE + 1)
        if len(content) > MAX_LAYER_METADATA_SIZE:
            raise ValueError('metadata exceeds the supported size')
        layers = json.loads(content)
        if not isinstance(layers, list):
            raise ValueError('expected a layer list')
        ids = set()
        for layer in layers:
            if not isinstance(layer, dict) or not isinstance(layer.get('id'), str):
                raise ValueError('invalid layer record')
            if not LAYER_ID.fullmatch(layer['id']) or layer['id'] in ids:
                raise ValueError('invalid or duplicate layer identity')
            ids.add(layer['id'])
        parents = {}
        for layer in layers:
            parent = layer.get('parent')
            if parent not in (None, '') and (
                not isinstance(parent, str) or parent not in ids or parent == layer['id']
            ):
                raise ValueError('invalid layer parent')
            parents[layer['id']] = parent
        visited = set()
        for identity in ids:
            chain = set()
            while identity and identity not in visited:
                if identity in chain:
                    raise ValueError('cyclic layer parents')
                chain.add(identity)
                identity = parents[identity]
            visited.update(chain)
        return ids
    except FileNotFoundError:
        # A newly configured store has no Podman metadata yet. The dataset
        # inventory below must also be empty before treating this as a no-op.
        return set()
    except (OSError, ValueError, TypeError) as error:
        raise CallError(f'Unable to read Podman layer metadata: {error}') from error


async def _zfs_state(dataset, recursive=False):
    command = ['zfs', 'get', '-H', '-p', '-t', 'filesystem,volume']
    if recursive:
        command.append('-r')
    command += ['-o', 'name,property,value,source', PROPERTIES, dataset]
    cp = await run(command, check=False, encoding='utf8')
    if cp.returncode:
        raise CallError(f'Unable to inspect Podman storage: {cp.stderr.strip()}')
    result = {}
    for line in cp.stdout.splitlines():
        fields = line.split('\t')
        if len(fields) != 4:
            raise CallError('Unable to interpret Podman dataset properties.')
        name, prop, value, source = fields
        properties = result.setdefault(name, {})
        if prop in properties:
            raise CallError('Podman dataset properties are duplicated.')
        properties[prop] = (value, source)
    if any(set(props) != set(PROPERTIES.split(',')) for props in result.values()):
        raise CallError('Podman dataset properties are incomplete.')
    return result


async def _mounts():
    cp = await run(['mount', '-p'], check=False, encoding='utf8')
    if cp.returncode:
        raise CallError(f'Unable to inspect Podman mounts: {cp.stderr.strip()}')
    result = []
    for line in cp.stdout.splitlines():
        fields = line.split()
        if len(fields) < 3:
            raise CallError('Unable to interpret host mounts.')
        result.append(tuple(fields[:3]))
    return result


def _check_mount(dataset, properties, mounts):
    canonical = f'/mnt/{dataset}'
    references = [item for item in mounts if (
        item[0] == dataset or item[1] == canonical or item[1].startswith(canonical + '/')
    )]
    expected = [(dataset, canonical, 'zfs')] if properties['mounted'][0] == 'yes' else []
    if properties['mounted'][0] not in {'yes', 'no'} or references != expected:
        raise CallError(f'Refusing to change unexpected or nested mounts for Podman layer {dataset!r}.')


async def layer_recovery_plan(paths, ids):
    root = paths['storage_dataset']
    states = await _zfs_state(root, recursive=True)
    if root not in states:
        raise CallError('Applications storage dataset is unavailable.')
    states.pop(root)
    expected = {f'{root}/{layer}' for layer in ids}
    if set(states) != expected:
        raise CallError('Podman layer metadata does not match the Applications storage datasets.')

    plan = []
    for dataset, props in sorted(states.items()):
        if (
            props['type'][0] != 'filesystem' or not props['guid'][0].isdigit() or
            props[OWNER_PROPERTY] != ('applications:storage', f'inherited from {root}')
        ):
            raise CallError(f'Podman layer {dataset!r} has unexpected identity or ownership.')
        mountpoint, source = props['mountpoint']
        if mountpoint == 'legacy':
            # Podman owns graph mounts, including live containers. Leave them
            # alone; runtime setup may also run while healthy apps are running.
            continue
        if mountpoint != f'/mnt/{dataset}' or not (
            source == 'default' or source.startswith('inherited from ')
        ):
            raise CallError(f'Podman layer {dataset!r} has a custom mountpoint; refusing to change it.')
        plan.append((dataset, props))
    if plan:
        mounts = await _mounts()
        for dataset, props in plan:
            _check_mount(dataset, props, mounts)
    return plan


async def restore_layer_mountpoints(plan):
    # The complete inventory and active-container checks precede all changes.
    # Recheck each exact dataset immediately before changing it. Partial success
    # is safe to retry: recovered layers are already-legacy no-ops next time.
    for dataset, original in plan:
        current = await _zfs_state(dataset)
        if current != {dataset: original}:
            raise CallError(f'Podman layer {dataset!r} changed during storage recovery. Retry the operation.')
        _check_mount(dataset, original, await _mounts())
        if original['mounted'][0] == 'yes':
            cp = await run(['zfs', 'unmount', dataset], check=False, encoding='utf8')
            if cp.returncode:
                raise CallError(f'Unable to unmount inactive Podman layer {dataset!r}: {cp.stderr.strip()}')
        cp = await run(['zfs', 'set', 'mountpoint=legacy', dataset], check=False, encoding='utf8')
        if cp.returncode:
            raise CallError(f'Unable to restore Podman layer {dataset!r}: {cp.stderr.strip()}')
        updated = (await _zfs_state(dataset)).get(dataset, {})
        if (
            updated.get('guid') != original['guid'] or
            updated.get('mountpoint') != ('legacy', 'local') or
            updated.get('mounted', (None,))[0] != 'no' or
            updated.get(OWNER_PROPERTY) != original[OWNER_PROPERTY]
        ):
            raise CallError(f'Podman layer {dataset!r} did not retain its expected identity and mount settings.')
