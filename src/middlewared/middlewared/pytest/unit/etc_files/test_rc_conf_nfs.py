import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock, patch

import pytest

RC_CONF = Path(__file__).parents[3] / 'etc_files/rc.conf.py'

NFS_CONFIG = {
    'allow_nonroot': False,
    'mountd_log': False,
    'mountd_port': None,
    'rpcstatd_port': None,
    'rpclockd_port': None,
    'servers': 4,
    'statd_lockd_log': False,
    'udp': False,
    'userd_manage_gids': False,
    'v4': False,
    'v4_domain': '',
    'v4_krb_enabled': False,
    'v4_v3owner': False,
}


class NFSRcMiddleware:

    def __init__(self):
        self.calls = []

    def call_sync(self, name, *args):
        self.calls.append((name, *args))
        if name == 'etc.generate':
            return None
        if name == 'nfs.config':
            return NFS_CONFIG
        if name == 'nfs.bindip':
            return []
        if name == 'datastore.query':
            return [{'srv_service': 'nfs', 'srv_enable': True}]

        raise AssertionError(f'unexpected call {name!r}')


@pytest.fixture(scope='module')
def rc_conf():
    spec = importlib.util.spec_from_file_location('nfs_rc_conf_test', RC_CONF)
    module = importlib.util.module_from_spec(spec)
    middlewared_utils = ModuleType('middlewared.utils')
    middlewared_utils.__path__ = []
    middlewared_utils_io = ModuleType('middlewared.utils.io')
    middlewared_utils_io.write_if_changed = Mock()
    # rc.conf.py also imports the NFS flag helper (the internal development record); it is pure, load the real one
    nfs_rc_spec = importlib.util.spec_from_file_location(
        'middlewared.utils.nfs_rc', Path(__file__).parents[3] / 'utils/nfs_rc.py'
    )
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


def test_nfs_config_does_not_rebuild_the_system_keytab(rc_conf):
    # Every rc reload runs nfs_config. Rebuilding /etc/krb5.keytab from the
    # database here would undo a machine password rotation that winbindd has
    # written to it but that check_updated_keytab has not yet stored.
    middleware = NFSRcMiddleware()

    result = list(rc_conf.nfs_config(middleware, {
        'failover_licensed': False,
        'failover_status': 'SINGLE',
    }))

    assert 'nfs_server_flags="-t -n 4 -S"' in result
    assert [call for call in middleware.calls if call[0] == 'etc.generate'] == []
