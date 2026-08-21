# the internal development record: query-options.extra.retrieve_children reads nothing below the starting point.
# The 15.0 line has no test_zfs.py, so the fakes live here.
import sys
import types
from unittest.mock import MagicMock, Mock, patch

try:
    import libzfs  # noqa: F401
except ModuleNotFoundError:
    sys.modules['libzfs'] = types.ModuleType('libzfs')

from middlewared.plugins.pool import PoolDatasetService
from middlewared.plugins.zfs import ZFSDatasetService


class FakeDataset:
    """Enough of libzfs.ZFSDataset: name, children, asdict(recursive=...) that records the flag."""

    def __init__(self, name, children=()):
        self.name = name
        self.children = list(children)
        self.calls = []

    def asdict(self, recursive=True, **_):
        self.calls.append(recursive)
        result = {'id': self.name, 'name': self.name, 'pool': self.name.split('/')[0], 'properties': {}}
        if recursive:  # like py-libzfs: no `children` key at all when not recursing
            result['children'] = [child.asdict(recursive=True) for child in self.children]
        return result


def fake_libzfs(roots):
    module = types.ModuleType('libzfs')
    module.ZFSException = type('ZFSException', (Exception,), {})
    zfs = MagicMock()
    zfs.__enter__.return_value = zfs
    module.ZFS = MagicMock(return_value=zfs)
    by_name = {}
    for root in roots:
        stack = [root]
        while stack:
            node = stack.pop()
            by_name[node.name] = node
            stack.extend(node.children)
    zfs.datasets_serialized = Mock(side_effect=lambda props=None, user_props=True, retrieve_children=True: [
        root.asdict(recursive=retrieve_children) for root in roots
    ])
    zfs.get_dataset = Mock(side_effect=lambda name: by_name[name])
    return module, zfs, by_name


def tree():
    leaf = FakeDataset('tank/apps/storage')
    apps = FakeDataset('tank/apps', [leaf])
    tank = FakeDataset('tank', [apps, FakeDataset('tank/data')])
    boot = FakeDataset('boot-pool', [FakeDataset('boot-pool/ROOT')])
    return [boot, tank]


def names(datasets):
    return [dataset['name'] for dataset in datasets]


def test_dataset_query_without_children_reads_only_the_root_datasets():
    module, zfs, _ = fake_libzfs(tree())
    with patch('middlewared.plugins.zfs.libzfs', module):
        roots = ZFSDatasetService.query.wraps(ZFSDatasetService(Mock()), [], {'extra': {'retrieve_children': False}})

    assert names(roots) == ['boot-pool', 'tank']
    assert all(root['children'] == [] for root in roots)
    zfs.datasets_serialized.assert_called_once_with(props=None, user_props=True, retrieve_children=False)


def test_dataset_query_default_still_reads_the_whole_tree():
    module, zfs, _ = fake_libzfs(tree())
    with patch('middlewared.plugins.zfs.libzfs', module):
        everything = ZFSDatasetService.query.wraps(ZFSDatasetService(Mock()), [], {'extra': {'flat': False}})

    assert names(everything) == ['boot-pool', 'tank']
    assert names(everything[1]['children']) == ['tank/apps', 'tank/data']
    zfs.datasets_serialized.assert_called_once_with(props=None, user_props=True)


def test_dataset_query_by_id_without_children_does_not_recurse():
    module, zfs, by_name = fake_libzfs(tree())
    with patch('middlewared.plugins.zfs.libzfs', module):
        one = ZFSDatasetService.query.wraps(
            ZFSDatasetService(Mock()), [['id', '=', 'tank/apps']], {'extra': {'retrieve_children': False}},
        )

    assert names(one) == ['tank/apps'] and one[0]['children'] == []
    assert by_name['tank/apps'].calls == [False]
    zfs.datasets_serialized.assert_not_called()


def pool_dataset_service(seen):
    def zfs_dataset_query(filters, options):
        seen.append((filters, options))
        return [{'id': 'tank', 'name': 'tank', 'pool': 'tank', 'properties': {}, 'children': [{'id': 'tank/data'}]}]

    methods = {
        'systemdataset.config': lambda: {'basename': ''},
        'boot.pool_name': lambda: 'boot-pool',
        'zfs.dataset.query': zfs_dataset_query,
    }
    return PoolDatasetService(Mock(call_sync=Mock(side_effect=lambda method, *args: methods[method](*args))))


def test_pool_dataset_query_forwards_retrieve_children_and_empties_children():
    seen = []
    with patch.object(PoolDatasetService, '_PoolDatasetService__transform', lambda self, datasets: datasets):
        roots = PoolDatasetService.query.wraps(pool_dataset_service(seen), [], {'extra': {'retrieve_children': False}})

    assert names(roots) == ['tank'] and roots[0]['children'] == []
    assert seen == [([], {'extra': {'flat': True, 'retrieve_children': False}})]


def test_pool_dataset_query_with_a_filter_reads_the_tree_but_still_strips_children():
    seen = []
    with patch.object(PoolDatasetService, '_PoolDatasetService__transform', lambda self, datasets: datasets):
        matches = PoolDatasetService.query.wraps(
            pool_dataset_service(seen), [['pool', '=', 'tank']], {'extra': {'retrieve_children': False}},
        )

    assert names(matches) == ['tank'] and matches[0]['children'] == []
    assert seen[0][1] == {'extra': {'flat': True, 'retrieve_children': True}}
