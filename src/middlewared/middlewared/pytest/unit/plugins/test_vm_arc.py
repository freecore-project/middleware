import pytest

from middlewared.plugins.vm_.arc import (
    ZFS_ARC_MAX_MIN,
    arc_max_reject_reason,
    effective_arc_min,
    minimum_valid_arc_max,
)


GiB = 1024 * 1024 * 1024


@pytest.mark.parametrize('value,kwargs,valid', [
    (0, {}, True),
    (ZFS_ARC_MAX_MIN - 1, {}, False),
    (ZFS_ARC_MAX_MIN, {}, True),
    (2 * GiB, {'arc_min': 0, 'arc_c_min': 24 * GiB}, False),
    (24 * GiB + 1, {'arc_min': 0, 'arc_c_min': 24 * GiB}, True),
    (768 * GiB, {'all_memory': 768 * GiB}, False),
])
def test__arc_max_reject_reason(value, kwargs, valid):
    assert (arc_max_reject_reason(value, **kwargs) is None) is valid


def test__minimum_valid_arc_max_uses_effective_arc_min():
    assert minimum_valid_arc_max(
        arc_min=0,
        arc_c_min=24 * GiB,
        all_memory=768 * GiB,
    ) == 24 * GiB + 1


def test__effective_arc_min_uses_kstat_floor_when_sysctl_tunable_is_zero():
    assert effective_arc_min(0, 24 * GiB) == 24 * GiB


def test__minimum_valid_arc_max_returns_none_when_no_valid_value_exists():
    assert minimum_valid_arc_max(
        arc_min=0,
        arc_c_min=24 * GiB,
        all_memory=24 * GiB + 1,
    ) is None
