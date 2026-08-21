import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock, patch

import pytest

RC_CONF = Path(__file__).parents[3] / 'etc_files/rc.conf.py'
NFS_RC = Path(__file__).parents[3] / 'utils/nfs_rc.py'


class HostRcMiddleware:

    def __init__(self, network):
        self.network = network

    def call_sync(self, name, *args):
        assert name == 'network.configuration.config'
        assert not args
        return self.network


@pytest.fixture(scope='module')
def rc_conf():
    spec = importlib.util.spec_from_file_location('netwait_rc_conf_test', RC_CONF)
    module = importlib.util.module_from_spec(spec)
    middlewared_utils = ModuleType('middlewared.utils')
    middlewared_utils.__path__ = []
    middlewared_utils_io = ModuleType('middlewared.utils.io')
    middlewared_utils_io.write_if_changed = Mock()
    # rc.conf.py also imports the NFS flag helper (the internal development record); it is pure, load the real one
    nfs_rc_spec = importlib.util.spec_from_file_location('middlewared.utils.nfs_rc', NFS_RC)
    middlewared_utils_nfs_rc = importlib.util.module_from_spec(nfs_rc_spec)
    nfs_rc_spec.loader.exec_module(middlewared_utils_nfs_rc)
    with patch.dict(sys.modules, {
        'middlewared.utils': middlewared_utils,
        'middlewared.utils.io': middlewared_utils_io,
        'middlewared.utils.nfs_rc': middlewared_utils_nfs_rc,
        'sysctl': Mock(),
    }):
        spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('netwait_ip,ipv4gateway,ipv6gateway,expected', [
    (['192.168.0.10', '192.168.0.11'], '192.168.0.1', '', 'netwait_ip="192.168.0.10 192.168.0.11"'),
    ([], '192.168.0.1', 'fe80::1%em0', 'netwait_ip="192.168.0.1"'),
    ([], '', 'fe80::1%em0', 'netwait_ip="fe80::1%em0"'),
    ([], '', '', 'netwait_ip=""'),
])
def test_host_config_netwait_ip(rc_conf, netwait_ip, ipv4gateway, ipv6gateway, expected):
    result = list(rc_conf.host_config(HostRcMiddleware({
        'hostname_local': 'nas',
        'domain': 'local',
        'ipv4gateway': ipv4gateway,
        'ipv6gateway': ipv6gateway,
        'netwait_enabled': True,
        'netwait_ip': netwait_ip,
    }), {}))

    assert 'netwait_enable="YES"' in result
    assert [line for line in result if line.startswith('netwait_ip=')] == [expected]


def test_host_config_netwait_disabled(rc_conf):
    result = list(rc_conf.host_config(HostRcMiddleware({
        'hostname_local': 'nas',
        'domain': 'local',
        'ipv4gateway': '',
        'ipv6gateway': '',
        'netwait_enabled': False,
        'netwait_ip': [],
    }), {}))

    assert result == ['hostname="nas.local"']
