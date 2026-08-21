# The zfs.dataset.update cases of test_zfs.py (rust/UPSTREAM.md #52), which 15.0 does not have
import contextlib
import sys
import types
from types import SimpleNamespace
from unittest.mock import Mock, patch

try:
    import libzfs  # noqa: F401
except ModuleNotFoundError:
    # zfs.dataset.update is driven through a mocked libzfs below; keep the module importable off-box.
    sys.modules['libzfs'] = types.ModuleType('libzfs')

from middlewared.plugins.zfs import ZFSDatasetService  # noqa: E402

# -- zfs.dataset.update leaves a property alone when it already has the requested value ---------


class FakeProperty:
    """libzfs.ZFSProperty: `value` is zfs_prop_get's formatted string, `rawvalue` the literal one."""

    def __init__(self, value, rawvalue, source='LOCAL'):
        self._value = value
        self.rawvalue = rawvalue
        self.source = SimpleNamespace(name=source)
        self.sets = []

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self.sets.append(value)


def update(properties, requested):
    dataset = SimpleNamespace(properties=properties)
    zfs = Mock(get_dataset=Mock(return_value=dataset))
    module = Mock(
        ZFS=Mock(return_value=contextlib.nullcontext(zfs)), ZFSException=type('ZFSException', (Exception,), {}),
    )
    with patch('middlewared.plugins.zfs.libzfs', module):
        ZFSDatasetService.do_update.wraps(ZFSDatasetService(Mock()), 'tank/ds', {'properties': requested})
    return {name: prop.sets for name, prop in properties.items()}


def test_dataset_update_does_not_reset_unchanged_numeric_properties():
    # What pool.dataset.update sends for a dataset whose settings were not changed.
    assert update({
        'quota': FakeProperty('10G', '10737418240'),
        'refquota': FakeProperty('none', '0', 'DEFAULT'),
        'reservation': FakeProperty('1G', '1073741824'),
        'refreservation': FakeProperty('512M', '536870912'),
        'copies': FakeProperty('2', '2'),
        'special_small_blocks': FakeProperty('64K', '65536'),
        'volsize': FakeProperty('10G', '10737418240'),
        'compression': FakeProperty('lz4', 'lz4'),
        'org.freenas:description': FakeProperty('docs', 'docs'),
    }, {
        'quota': {'value': 10737418240},
        'refquota': {'value': 'none'},
        'reservation': {'value': 1073741824},
        'refreservation': {'value': 536870912},
        'copies': {'value': 2},
        'special_small_blocks': {'value': 65536},
        'volsize': {'value': '10737418240'},
        'compression': {'value': 'lz4'},
        'org.freenas:description': {'value': 'docs'},
    }) == {
        'quota': [], 'refquota': [], 'reservation': [], 'refreservation': [], 'copies': [],
        'special_small_blocks': [], 'volsize': [], 'compression': [], 'org.freenas:description': [],
    }


def test_dataset_update_sets_changed_or_inherited_properties():
    assert update({
        'quota': FakeProperty('10G', '10737418240'),
        'copies': FakeProperty('1', '1', 'INHERITED'),
        'special_small_blocks': FakeProperty('0', '0'),
        'compression': FakeProperty('lz4', 'lz4'),
    }, {
        'quota': {'value': 21474836480},
        'copies': {'value': 1},
        'special_small_blocks': {'value': 65536},
        'compression': {'value': 'zstd'},
    }) == {
        'quota': [21474836480], 'copies': [1], 'special_small_blocks': [65536], 'compression': ['zstd'],
    }
