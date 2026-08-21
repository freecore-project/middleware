import copy
import json
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from middlewared.plugins.applications_ import storage
from middlewared.service_exception import CallError


ROOT = 'tank/applications/storage'
LAYER = 'a' * 64
OTHER = 'b' * 64
DATASET = f'{ROOT}/{LAYER}'
PATHS = {'storage_dataset': ROOT}


def properties(dataset=DATASET, *, legacy=False, mounted=True):
    return {
        'type': ('filesystem', '-'), 'guid': ('123', '-'),
        'mountpoint': ('legacy', 'local') if legacy else (f'/mnt/{dataset}', 'default'),
        'mounted': ('yes' if mounted else 'no', '-'),
        storage.OWNER_PROPERTY: ('applications:storage', f'inherited from {ROOT}'),
    }


def metadata(tmp_path, value):
    # FreeBSD's pytest temp paths are canonical; resolve macOS /var as well.
    root = tmp_path.resolve()
    path = root / 'zfs-layers' / 'layers.json'
    path.parent.mkdir()
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return root, path


def test_layer_inventory_reads_ids_and_parent_chain_without_writing(tmp_path):
    root, path = metadata(tmp_path, [{'id': LAYER}, {'id': OTHER, 'parent': LAYER}])
    before = path.read_bytes()
    assert storage.read_layer_ids(str(root)) == {LAYER, OTHER}
    assert path.read_bytes() == before


@pytest.mark.parametrize('value', [
    {}, [{}], [{'id': '../foreign'}], [{'id': LAYER}, {'id': LAYER}],
    [{'id': LAYER, 'parent': OTHER}], [{'id': LAYER, 'parent': []}],
    [{'id': LAYER, 'parent': OTHER}, {'id': OTHER, 'parent': LAYER}],
])
def test_malformed_layer_identity_is_rejected(tmp_path, value):
    root, _ = metadata(tmp_path, value)
    with pytest.raises(CallError):
        storage.read_layer_ids(str(root))


@pytest.mark.parametrize('kind', ['symlink', 'fifo', 'writable', 'large'])
def test_unsafe_layer_metadata_is_rejected(tmp_path, kind):
    root, path = metadata(tmp_path, [{'id': LAYER}])
    if kind == 'symlink':
        other = root / 'other.json'
        path.rename(other)
        path.symlink_to(other)
    elif kind == 'fifo':
        path.unlink()
        os.mkfifo(path, 0o600)
    elif kind == 'writable':
        path.chmod(0o666)
    else:
        path.write_bytes(b' ' * (storage.MAX_LAYER_METADATA_SIZE + 1))
    with pytest.raises(CallError):
        storage.read_layer_ids(str(root))


@pytest.mark.asyncio
async def test_new_store_is_inert_but_missing_metadata_cannot_adopt_hash_like_dataset(tmp_path):
    ids = storage.read_layer_ids(str(tmp_path.resolve()))
    assert ids == set()
    with patch.object(storage, '_zfs_state', AsyncMock(return_value={ROOT: {}})), patch.object(
        storage, '_mounts', AsyncMock(),
    ) as mounts:
        assert await storage.layer_recovery_plan(PATHS, ids) == []
        mounts.assert_not_awaited()
    with patch.object(storage, '_zfs_state', AsyncMock(return_value={ROOT: {}, DATASET: properties()})):
        with pytest.raises(CallError, match='does not match'):
            await storage.layer_recovery_plan(PATHS, ids)


@pytest.mark.asyncio
async def test_legacy_layers_are_inert_even_when_running_at_graph_mount():
    with patch.object(storage, '_zfs_state', AsyncMock(return_value={
        ROOT: {}, DATASET: properties(legacy=True),
    })), patch.object(storage, '_mounts', AsyncMock()) as mounts:
        assert await storage.layer_recovery_plan(PATHS, {LAYER}) == []
        mounts.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('fault', ['unknown', 'nested', 'owner', 'type', 'custom', 'stacked', 'graph'])
async def test_complete_plan_refuses_foreign_or_ambiguous_layers(fault):
    state = {ROOT: {}, DATASET: properties()}
    mounts = [(DATASET, f'/mnt/{DATASET}', 'zfs')]
    if fault == 'unknown':
        state[f'{ROOT}/{OTHER}'] = properties(f'{ROOT}/{OTHER}')
    elif fault == 'nested':
        state[f'{DATASET}/child'] = properties(f'{DATASET}/child')
    elif fault == 'owner':
        state[DATASET][storage.OWNER_PROPERTY] = ('foreign', 'local')
    elif fault == 'type':
        state[DATASET]['type'] = ('volume', '-')
    elif fault == 'custom':
        state[DATASET]['mountpoint'] = ('/custom', 'local')
    elif fault == 'stacked':
        mounts.append(('devfs', f'/mnt/{DATASET}/dev', 'devfs'))
    else:
        mounts = [(DATASET, f'/mnt/{ROOT}/zfs/graph/{LAYER}', 'zfs')]
    with patch.object(storage, '_zfs_state', AsyncMock(return_value=state)), patch.object(
        storage, '_mounts', AsyncMock(return_value=mounts),
    ), patch.object(storage, 'run', AsyncMock()) as run:
        with pytest.raises(CallError):
            await storage.layer_recovery_plan(PATHS, {LAYER})
        run.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('mounted', [False, True])
async def test_recovery_preserves_identity_and_sets_only_exact_layer_mountpoint(mounted):
    original = properties(mounted=mounted)
    mounts = [(DATASET, f'/mnt/{DATASET}', 'zfs')] if mounted else []
    with patch.object(storage, '_zfs_state', AsyncMock(side_effect=[
        {ROOT: {}, DATASET: original}, {DATASET: original},
        {DATASET: properties(legacy=True, mounted=False)},
    ])), patch.object(storage, '_mounts', AsyncMock(return_value=mounts)), patch.object(
        storage, 'run', AsyncMock(return_value=SimpleNamespace(returncode=0)),
    ) as run:
        plan = await storage.layer_recovery_plan(PATHS, {LAYER})
        await storage.restore_layer_mountpoints(plan)
        commands = [call.args[0] for call in run.await_args_list]
        assert commands == ([['zfs', 'unmount', DATASET]] if mounted else []) + [
            ['zfs', 'set', 'mountpoint=legacy', DATASET],
        ]


@pytest.mark.asyncio
async def test_busy_unmount_never_forces_or_changes_properties():
    original = properties()
    with patch.object(storage, '_zfs_state', AsyncMock(return_value={DATASET: original})), patch.object(
        storage, '_mounts', AsyncMock(return_value=[(DATASET, f'/mnt/{DATASET}', 'zfs')]),
    ), patch.object(storage, 'run', AsyncMock(return_value=SimpleNamespace(
        returncode=1, stderr='Device busy',
    ))) as run:
        with pytest.raises(CallError, match='Device busy'):
            await storage.restore_layer_mountpoints([(DATASET, original)])
        assert [call.args[0] for call in run.await_args_list] == [['zfs', 'unmount', DATASET]]


@pytest.mark.asyncio
async def test_dataset_replacement_between_plan_and_apply_is_refused():
    original = properties()
    changed = copy.deepcopy(original)
    changed['guid'] = ('456', '-')
    with patch.object(storage, '_zfs_state', AsyncMock(return_value={DATASET: changed})), patch.object(
        storage, 'run', AsyncMock(),
    ) as run:
        with pytest.raises(CallError, match='changed during'):
            await storage.restore_layer_mountpoints([(DATASET, original)])
        run.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('fault', ['command', 'readback'])
async def test_failed_property_restore_is_reported(fault):
    original = properties(mounted=False)
    with patch.object(storage, '_zfs_state', AsyncMock(return_value={DATASET: original})), patch.object(
        storage, '_mounts', AsyncMock(return_value=[]),
    ), patch.object(storage, 'run', AsyncMock(return_value=SimpleNamespace(
        returncode=1 if fault == 'command' else 0, stderr='readonly pool',
    ))):
        with pytest.raises(CallError):
            await storage.restore_layer_mountpoints([(DATASET, original)])
