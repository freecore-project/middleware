import contextlib
import errno
import subprocess
import sys
import types
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

try:
    import libzfs  # noqa: F401
except ModuleNotFoundError:
    # This narrow do_delete unit does not enter py-libzfs. Keep it runnable on
    # developer platforms where that FreeBSD extension is unavailable.
    sys.modules['libzfs'] = types.ModuleType('libzfs')

from middlewared.plugins import zfs as zfs_plugin
from middlewared.plugins.zfs import ZFSDatasetService, ZFSSnapshot
from middlewared.service_exception import CallError


@pytest.mark.parametrize('message', [
    "cannot unmount '/mnt/tank/busy': pool or dataset is busy",
    "cannot unmount '/mnt/tank/busy': Device busy",
])
def test_dataset_delete_reports_native_busy_errors_as_ebusy(message):
    service = ZFSDatasetService(Mock())
    with patch('middlewared.plugins.zfs.subprocess.run', side_effect=[
        SimpleNamespace(returncode=1),
        subprocess.CalledProcessError(
            1, ['zfs', 'destroy', 'tank/busy'], stderr=message,
        ),
    ]):
        with pytest.raises(CallError) as error:
            service.do_delete('tank/busy', {'force': False, 'recursive': False})

    assert error.value.errno == errno.EBUSY


def test_dataset_delete_keeps_unclassified_errors_as_efault():
    service = ZFSDatasetService(Mock())
    with patch('middlewared.plugins.zfs.subprocess.run', side_effect=[
        SimpleNamespace(returncode=1),
        subprocess.CalledProcessError(
            1, ['zfs', 'destroy', 'tank/busy'], stderr='permission denied',
        ),
    ]):
        with pytest.raises(CallError) as error:
            service.do_delete('tank/busy', {'force': False, 'recursive': False})

    assert error.value.errno == errno.EFAULT


# -- the internal development record: an opaque dataset is enumerated as a leaf ------------------


class FakeDataset:
    """Enough of libzfs.ZFSDataset for the walk: name, children, asdict(recursive=...)."""

    def __init__(self, name, children=(), user_properties=None):
        self.name = name
        self.children = list(children)
        self.calls = []
        self.user_properties = user_properties or {}

    def asdict(self, recursive=True, **_):
        self.calls.append(recursive)
        properties = {
            'used': {'value': '1'}, 'mountpoint': {'value': f'/mnt/{self.name}'},
            **{key: {'value': value} for key, value in self.user_properties.items()},
        }
        result = {'id': self.name, 'name': self.name, 'properties': properties}
        if recursive:  # like py-libzfs: no `children` key at all when not recursing
            result['children'] = [child.asdict(recursive=True) for child in self.children]
        return result


def fake_pool_tree():
    layers = [FakeDataset(f'tank/applications/storage/{index:064x}') for index in range(3)]
    storage = FakeDataset('tank/applications/storage', layers, {'org.freecore:opaque': 'on'})
    data = FakeDataset('tank/applications/data', [FakeDataset('tank/applications/data/demo')])
    applications = FakeDataset('tank/applications', [storage, data])
    iocage = FakeDataset('tank/iocage', [FakeDataset('tank/iocage/jails')])
    tank = FakeDataset('tank', [applications, iocage])
    boot = FakeDataset('boot-pool', [FakeDataset('boot-pool/ROOT')])
    return tank, boot, {'storage': storage, 'applications': applications, 'iocage': iocage, 'data': data}


def names(datasets):
    return [dataset['name'] for dataset in datasets]


def test_serialize_skipping_walks_only_the_path_to_the_opaque_dataset():
    tank, _, nodes = fake_pool_tree()
    service = ZFSDatasetService(Mock())

    result = service.serialize_skipping(tank, frozenset({'tank/applications/storage'}))

    assert names(result['children']) == ['tank/applications', 'tank/iocage']
    applications = result['children'][0]
    assert names(applications['children']) == ['tank/applications/storage', 'tank/applications/data']
    assert applications['children'][0]['children'] == []                   # the leaf
    assert names(applications['children'][1]['children']) == ['tank/applications/data/demo']
    # Python only on the path: tank and tank/applications non-recursive; every
    # other subtree one recursive C call; the layers never serialised.
    assert tank.calls == [False] and nodes['applications'].calls == [False]
    assert nodes['storage'].calls == [False] and nodes['iocage'].calls == [True] and nodes['data'].calls == [True]
    assert all(layer.calls == [] for layer in nodes['storage'].children)


def test_restrict_properties_matches_what_datasets_serialized_would_keep():
    tree = [{
        'name': 'tank', 'properties': {'used': 1, 'mountpoint': 2, 'org.freecore:opaque': 3, 'quota': 4},
        'children': [{'name': 'tank/a', 'properties': {'used': 1, 'org.x:y': 5}, 'children': []}],
    }]
    ZFSDatasetService.restrict_properties(tree, ['used'], False)
    assert tree[0]['properties'] == {'used': 1, 'mountpoint': 2}
    assert tree[0]['children'][0]['properties'] == {'used': 1}


def test_restrict_properties_keeps_user_properties_whatever_props_says():
    # the internal development record: libzfs applies `props` to native properties only and
    # returns user properties whenever user_props is set. jail.iocage_set_up asks for
    # three native properties and filters on org.freebsd.ioc:active, so the user
    # property must survive a props list, and an empty props list must keep it too.
    tree = [{
        'name': 'tank',
        'properties': {'used': 1, 'mountpoint': 2, 'org.freebsd.ioc:active': 'yes', 'quota': 4},
        'children': [{'name': 'tank/iocage', 'properties': {'used': 1, 'org.x:y': 5}, 'children': []}],
    }]
    ZFSDatasetService.restrict_properties(tree, ['encryption', 'keystatus', 'mountpoint'], True)
    assert tree[0]['properties'] == {'mountpoint': 2, 'org.freebsd.ioc:active': 'yes'}
    assert tree[0]['children'][0]['properties'] == {'org.x:y': 5}
    tree = [{'name': 'tank', 'properties': {'used': 1, 'org.freebsd.ioc:active': 'yes'}, 'children': []}]
    ZFSDatasetService.restrict_properties(tree, [], True)
    assert tree[0]['properties'] == {'org.freebsd.ioc:active': 'yes'}


def test_opaque_datasets_reads_local_on_values_and_caches():
    zfs_plugin.forget_opaque_datasets()
    output = 'tank/applications/storage\ton\ntank/other\toff\ntank/x\t-\n'
    completed = SimpleNamespace(returncode=0, stdout=output)
    with patch('middlewared.plugins.zfs.subprocess.run', return_value=completed) as run:
        assert zfs_plugin.opaque_datasets() == frozenset({'tank/applications/storage'})
        assert zfs_plugin.opaque_datasets() == frozenset({'tank/applications/storage'})
    assert run.call_count == 1
    assert run.call_args.args[0][:6] == ['zfs', 'get', '-H', '-r', '-s', 'local']
    zfs_plugin.forget_opaque_datasets()
    with patch('middlewared.plugins.zfs.subprocess.run', return_value=SimpleNamespace(returncode=1, stdout='')):
        assert zfs_plugin.opaque_datasets() == frozenset()
    zfs_plugin.forget_opaque_datasets()
    assert zfs_plugin.is_internal('tank/applications/storage/abc', {'tank/applications/storage'})
    assert not zfs_plugin.is_internal('tank/applications/storage', {'tank/applications/storage'})
    assert not zfs_plugin.is_internal('tank/applications/storage2', {'tank/applications/storage'})


def fake_libzfs(tank, boot):
    zfs = Mock()
    zfs.pools = [SimpleNamespace(root_dataset=boot), SimpleNamespace(root_dataset=tank)]
    zfs.datasets_serialized = Mock(return_value=[boot.asdict(True), tank.asdict(True)])
    module = Mock()
    module.ZFS = Mock(return_value=contextlib.nullcontext(zfs))
    return module, zfs


def test_dataset_query_hides_internals_by_default_and_shows_them_on_request():
    tank, boot, _ = fake_pool_tree()
    module, zfs = fake_libzfs(tank, boot)
    service = ZFSDatasetService(Mock())
    with patch('middlewared.plugins.zfs.libzfs', module), \
            patch('middlewared.plugins.zfs.opaque_datasets', return_value=frozenset({'tank/applications/storage'})):
        flat = ZFSDatasetService.query.wraps(service, [], {'extra': {'flat': True}})
        assert 'tank/applications/storage' in names(flat)
        assert not any(name.startswith('tank/applications/storage/') for name in names(flat))
        assert 'tank/applications/data/demo' in names(flat) and 'tank/iocage/jails' in names(flat)
        zfs.datasets_serialized.assert_not_called()

        tree = ZFSDatasetService.query.wraps(service, [], {'extra': {'flat': False}})
        assert names(tree) == ['boot-pool', 'tank']

        restricted = ZFSDatasetService.query.wraps(
            service, [], {'extra': {'flat': True, 'properties': ['used'], 'user_properties': False}},
        )
        assert all(set(item['properties']) <= {'used', 'mountpoint'} for item in restricted)

        everything = ZFSDatasetService.query.wraps(service, [], {'extra': {'flat': True, 'include_internal': True}})
        assert sum(1 for name in names(everything) if name.startswith('tank/applications/storage/')) == 3
        zfs.datasets_serialized.assert_called_once()


def test_dataset_query_without_opaque_datasets_is_the_plain_enumeration():
    tank, boot, _ = fake_pool_tree()
    module, zfs = fake_libzfs(tank, boot)
    service = ZFSDatasetService(Mock())
    with patch('middlewared.plugins.zfs.libzfs', module), \
            patch('middlewared.plugins.zfs.opaque_datasets', return_value=frozenset()):
        ZFSDatasetService.query.wraps(service, [], {'extra': {'flat': True}})
    zfs.datasets_serialized.assert_called_once_with(props=None, user_props=True)


def test_snapshot_query_hides_layer_snapshots_unless_asked():
    snapshots = [
        SimpleNamespace(asdict=lambda: {
            'name': 'tank/applications/storage/abc@layer', 'dataset': 'tank/applications/storage/abc',
        }),
        SimpleNamespace(asdict=lambda: {'name': 'tank/data@daily', 'dataset': 'tank/data'}),
        SimpleNamespace(asdict=lambda: {
            'name': 'tank/applications/storage@keep', 'dataset': 'tank/applications/storage',
        }),
    ]
    zfs = Mock(snapshots=snapshots)
    module = Mock(ZFS=Mock(return_value=contextlib.nullcontext(zfs)))
    service = ZFSSnapshot(Mock())
    with patch('middlewared.plugins.zfs.libzfs', module), \
            patch('middlewared.plugins.zfs.opaque_datasets', return_value=frozenset({'tank/applications/storage'})):
        visible = ZFSSnapshot.query.wraps(service, [], {})
        assert [item['name'] for item in visible] == ['tank/data@daily', 'tank/applications/storage@keep']
        everything = ZFSSnapshot.query.wraps(service, [], {'extra': {'include_internal': True}})
        assert len(everything) == 3


def test_the_id_fast_path_answers_an_opaque_dataset_as_a_leaf_and_internals_directly():
    tank, boot, nodes = fake_pool_tree()
    zfs = Mock()
    zfs.get_dataset = Mock(side_effect=lambda name: {
        'tank/applications/storage': nodes['storage'],
        nodes['storage'].children[0].name: nodes['storage'].children[0],
    }[name])
    module = Mock(ZFS=Mock(return_value=contextlib.nullcontext(zfs)))
    service = ZFSDatasetService(Mock())
    with patch('middlewared.plugins.zfs.libzfs', module), \
            patch('middlewared.plugins.zfs.opaque_datasets', return_value=frozenset({'tank/applications/storage'})):
        leaf = ZFSDatasetService.query.wraps(service, [['id', '=', 'tank/applications/storage']], {})
        assert leaf[0]['children'] == [] and nodes['storage'].calls == [False]
        full = ZFSDatasetService.query.wraps(
            service, [['id', '=', 'tank/applications/storage']], {'extra': {'include_internal': True}},
        )
        assert len(full[0]['children']) == 3
        layer = nodes['storage'].children[0]
        direct = ZFSDatasetService.query.wraps(service, [['id', '=', layer.name]], {'extra': {'recursive': False}})
        assert direct[0]['name'] == layer.name


def test_snapshot_name_fast_path_hides_layer_snapshots_unless_asked():
    listing = 'tank/applications/storage/abc@layer\ntank/applications/storage@keep\ntank/data@daily\n'
    service = ZFSSnapshot(Mock())
    with patch('middlewared.plugins.zfs.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=listing)), \
            patch('middlewared.plugins.zfs.opaque_datasets', return_value=frozenset({'tank/applications/storage'})):
        names_only = ZFSSnapshot.query.wraps(service, [], {'select': ['name']})
        assert [item['name'] for item in names_only] == ['tank/applications/storage@keep', 'tank/data@daily']
        everything = ZFSSnapshot.query.wraps(service, [], {'select': ['name'], 'extra': {'include_internal': True}})
        assert len(everything) == 3
