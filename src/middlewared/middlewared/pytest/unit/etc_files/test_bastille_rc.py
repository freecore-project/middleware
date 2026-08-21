import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock, patch

import pytest

RC_CONF = Path(__file__).parents[3] / 'etc_files/rc.conf.py'


class BastilleRcMiddleware:

    def __init__(self, *, pool='tank', enabled=True, valid=True, switching=False):
        self.config = {
            'pool': pool,
            'startup_delay': 2,
            'parallel_limit': 4,
            'enabled': enabled,
            'configuration_valid': valid,
            'switching_pool': switching,
        }

    def call_sync(self, name, *args):
        assert name == 'bastille.rc_config'
        assert not args
        return self.config


@pytest.fixture(scope='module')
def rc_conf():
    spec = importlib.util.spec_from_file_location('bastille_rc_conf_test', RC_CONF)
    module = importlib.util.module_from_spec(spec)
    middlewared_utils = ModuleType('middlewared.utils')
    middlewared_utils.__path__ = []
    middlewared_utils_io = ModuleType('middlewared.utils.io')
    middlewared_utils_io.write_if_changed = Mock()
    with patch.dict(sys.modules, {
        'middlewared.utils': middlewared_utils,
        'middlewared.utils.io': middlewared_utils_io,
        'sysctl': Mock(),
    }):
        spec.loader.exec_module(module)
    return module


def test_unconfigured_bastille_is_explicitly_disabled(rc_conf):
    result = list(rc_conf.bastille_config(BastilleRcMiddleware(pool=None), {}))

    assert result == ['bastille_enable="NO"']


def test_configured_bastille_uses_packaged_rc_with_pool_config(rc_conf):
    result = list(rc_conf.bastille_config(BastilleRcMiddleware(), {}))

    assert result == [
        'bastille_enable="YES"',
        'bastille_conf="/mnt/tank/bastille/config/bastille.conf"',
        'bastille_env="BASTILLE_CONFIG=/mnt/tank/bastille/config/bastille.conf"',
        'bastille_jailsdir="/mnt/tank/bastille/jails"',
        'bastille_startup_delay="2"',
        'bastille_parallel_limit="4"',
    ]


def test_invalid_configuration_fails_closed_without_hiding_settings(rc_conf):
    result = list(rc_conf.bastille_config(BastilleRcMiddleware(valid=False), {}))

    assert result[0] == 'bastille_enable="NO"'
    assert any(line.startswith('bastille_conf=') for line in result)
    assert not any(
        token in '\n'.join(result)
        for token in ('pf_enable', 'cloned_interfaces', 'ifconfig_', 'iocage')
    )


def test_pool_switch_fails_closed_without_hiding_target_settings(rc_conf):
    result = list(rc_conf.bastille_config(BastilleRcMiddleware(switching=True), {}))

    assert result[0] == 'bastille_enable="NO"'
    assert 'bastille_conf="/mnt/tank/bastille/config/bastille.conf"' in result
    assert 'bastille_env="BASTILLE_CONFIG=/mnt/tank/bastille/config/bastille.conf"' in result
