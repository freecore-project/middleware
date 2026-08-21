import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock, patch

import pytest

RC_CONF = Path(__file__).parents[3] / 'etc_files/rc.conf.py'
NFS_RC = Path(__file__).parents[3] / 'utils/nfs_rc.py'
CONTEXT = {'failover_licensed': False, 'failover_status': 'SINGLE'}

pytestmark = pytest.mark.skipif(shutil.which('sh') is None, reason='needs a POSIX shell')


class RcMiddleware:

    def __init__(self, **results):
        self.results = results

    def call_sync(self, name, *args):
        if name == 'etc.generate':
            return None
        return self.results[name]


@pytest.fixture(scope='module')
def rc_conf():
    spec = importlib.util.spec_from_file_location('rc_conf_quoting_test', RC_CONF)
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


@pytest.fixture
def hostile(tmp_path):
    # Every character that is special inside a double-quoted rc.conf value or in
    # the eval rc.subr does on ${name}_flags / command_args.
    marker = tmp_path / 'executed'
    value = f'Rack "5" 19" $(touch {marker}) `touch {marker}` ${{HOME}} back\\slash \'tick\' ;x'
    return value, marker


def rc_shell(tmp_path, lines, script):
    """Source the generated lines like rc(8) does, then run `script` against them."""
    rc_file = tmp_path / 'rc.conf.freenas'
    rc_file.write_text('\n'.join(lines) + '\n')
    cp = subprocess.run(
        ['sh', '-c', f'. "$1" && {script}', 'sh', str(rc_file)],
        capture_output=True, text=True,
    )
    assert cp.returncode == 0, cp.stderr
    return cp.stdout


# rc.subr builds "$command $rc_flags $command_args" and evals it.
def rc_args(tmp_path, lines, var):
    return rc_shell(tmp_path, lines, f'eval "set -- ${var}" && printf "<%s>" "$@"')


def rc_value(tmp_path, lines, var):
    return rc_shell(tmp_path, lines, f'printf "<%s>" "${var}"')


def test_lldp_location_reaches_ladvd_as_one_literal_argument(rc_conf, tmp_path, hostile):
    location, marker = hostile
    middleware = RcMiddleware(**{'lldp.config': {'intdesc': True, 'country': 'US', 'location': location}})

    lines = list(rc_conf.lldp_config(middleware, CONTEXT))

    ladvd_flags = rc_args(tmp_path, lines, 'ladvd_flags')
    assert not marker.exists()
    assert ladvd_flags == f'<-a><-z><-c><US><-l><{location}>'


def nfs_config(rc_conf, v4_domain):
    middleware = RcMiddleware(**{
        'nfs.config': {
            'allow_nonroot': False, 'mountd_log': False, 'mountd_port': None,
            'rpcstatd_port': None, 'rpclockd_port': None, 'servers': 4,
            'statd_lockd_log': False, 'udp': False, 'userd_manage_gids': True,
            'v4': True, 'v4_domain': v4_domain, 'v4_krb_enabled': False, 'v4_v3owner': False,
        },
        'nfs.bindip': [],
        'datastore.query': [{'srv_service': 'nfs', 'srv_enable': True}],
    })
    with patch.object(rc_conf, '_load_nfsd_module'), patch.object(rc_conf, '_set_sysctl'):
        return list(rc_conf.nfs_config(middleware, CONTEXT))


def test_nfs_v4_domain_reaches_nfsuserd_as_one_literal_argument(rc_conf, tmp_path, hostile):
    domain, marker = hostile

    lines = nfs_config(rc_conf, domain)

    nfsuserd_flags = rc_args(tmp_path, lines, 'nfsuserd_flags')
    assert not marker.exists()
    assert nfsuserd_flags == f'<-manage-gids><-domain><{domain}>'


def test_nis_domain_and_servers_stay_literal(rc_conf, tmp_path, hostile):
    domain, marker = hostile
    middleware = RcMiddleware(**{'datastore.config': {
        'enable': True, 'domain': domain, 'servers': 'nis1,nis2', 'secure_mode': True, 'manycast': False,
    }})

    lines = list(rc_conf.nis_config(middleware, CONTEXT))

    nisdomainname = rc_value(tmp_path, lines, 'nisdomainname')
    nis_client_flags = rc_args(tmp_path, lines, 'nis_client_flags')
    assert not marker.exists()
    assert nisdomainname == f'<{domain}>'
    assert nis_client_flags == f'<-S><{domain},nis1,nis2><-s>'


def test_ups_remotehost_reaches_upslog_as_one_literal_argument(rc_conf, tmp_path, hostile):
    remotehost, marker = hostile
    middleware = RcMiddleware(**{
        'datastore.query': [{'srv_service': 'ups', 'srv_enable': True}],
        'ups.config': {'mode': 'SLAVE', 'identifier': 'ups', 'remotehost': remotehost, 'remoteport': 3493},
    })

    lines = list(rc_conf.nut_config(middleware, CONTEXT))

    # nut_upslog's rc script puts the value into nut_upslog_flags as "-s ${nut_upslog_ups}".
    nut_upslog_ups = rc_args(tmp_path, lines, 'nut_upslog_ups')
    assert not marker.exists()
    assert nut_upslog_ups == f'<ups@{remotehost}:3493>'


def test_hostname_stays_literal(rc_conf, tmp_path, hostile):
    domain, marker = hostile
    middleware = RcMiddleware(**{'network.configuration.config': {
        'hostname_local': 'truenas', 'domain': domain, 'ipv4gateway': '', 'ipv6gateway': '',
        'netwait_enabled': False, 'netwait_ip': [],
    }})

    lines = list(rc_conf.host_config(middleware, CONTEXT))

    hostname = rc_value(tmp_path, lines, 'hostname')
    assert not marker.exists()
    assert hostname == f'<truenas.{domain}>'


def test_keymap_stays_literal(rc_conf, tmp_path, hostile):
    kbdmap, marker = hostile
    middleware = RcMiddleware(**{'system.general.config': {'kbdmap': kbdmap}})

    lines = list(rc_conf.kbdmap_config(middleware, CONTEXT))

    keymap = rc_value(tmp_path, lines, 'keymap')
    assert not marker.exists()
    assert keymap == f'<{kbdmap}>'


def test_ordinary_values_render_as_before(rc_conf):
    lldp = RcMiddleware(**{'lldp.config': {'intdesc': True, 'country': 'US', 'location': ''}})
    nis = RcMiddleware(**{'datastore.config': {
        'enable': True, 'domain': 'corp', 'servers': '192.0.2.1', 'secure_mode': False, 'manycast': True,
    }})
    ups = RcMiddleware(**{
        'datastore.query': [{'srv_service': 'ups', 'srv_enable': True}],
        'ups.config': {'mode': 'SLAVE', 'identifier': 'ups', 'remotehost': '192.0.2.2', 'remoteport': 3493},
    })

    assert list(rc_conf.lldp_config(lldp, CONTEXT)) == ['ladvd_flags="-a -z -c US"']
    assert 'nfsuserd_flags="-manage-gids -domain example.com"' in nfs_config(rc_conf, 'example.com')
    assert list(rc_conf.nis_config(nis, CONTEXT)) == [
        'nisdomainname="corp"',
        'nis_client_enable="YES"',
        'nis_client_flags="-S corp,192.0.2.1 -m"',
    ]
    assert list(rc_conf.nut_config(ups, CONTEXT)) == [
        'nut_upslog_ups="ups@192.0.2.2:3493"',
        'nut_upslog_enable="YES"',
        'nut_upsmon_enable="YES"',
    ]
