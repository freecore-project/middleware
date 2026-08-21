"""The descriptor headroom alert (the internal development record): quiet below 75% of the 1024 select() wall
(or of a lower process limit), a WARNING above it. Off-box: the count and the limit are stubs."""
import resource
from unittest.mock import patch

from middlewared.alert.source import middlewared_descriptors as source
from middlewared.alert.source.middlewared_descriptors import (
    MiddlewaredDescriptorsAlertClass, MiddlewaredDescriptorsAlertSource, descriptor_threshold,
)


def check(count, soft_limit):
    src = object.__new__(MiddlewaredDescriptorsAlertSource)
    with patch.object(source.psutil, 'Process') as proc, \
            patch.object(source.resource, 'getrlimit', return_value=(soft_limit, resource.RLIM_INFINITY)):
        proc.return_value.num_fds.return_value = count
        return src.check_sync()


def test_threshold_is_three_quarters_of_the_select_wall_or_a_lower_limit():
    assert descriptor_threshold(resource.RLIM_INFINITY) == 768
    assert descriptor_threshold(116991) == 768
    assert descriptor_threshold(512) == 384


def test_quiet_at_the_usual_size():
    assert check(59, 116991) is None
    assert check(768, 116991) is None


def test_warns_above_the_threshold():
    alert = check(1306, 116991)
    assert alert.klass is MiddlewaredDescriptorsAlertClass
    assert alert.args == {'count': 1306, 'threshold': 768, 'wall': 1024}


def test_a_low_process_limit_moves_the_wall():
    alert = check(400, 512)
    assert alert.args == {'count': 400, 'threshold': 384, 'wall': 512}
