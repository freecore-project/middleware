# the internal development record: the NFS bind IP reaches rpcbind, statd, lockd, mountd and nfsd at boot.
# /etc/rc keeps the rc.conf it read at its start, so the flags also go to /etc/rc.conf.d/<script>,
# which rc.subr re-reads for every script, and ix-nfsbind must run before each of those scripts.
import importlib.util
from pathlib import Path

import pytest

from middlewared.plugins.etc import EtcService, FileShouldNotExist
from middlewared.utils.nfs_rc import RC_CONF_D, nfs_rc_flags

MIDDLEWARED = Path(__file__).resolve().parents[3]
ETC_FILES = MIDDLEWARED / 'etc_files'
IX_NFSBIND = MIDDLEWARED.parents[1] / 'freenas' / 'etc' / 'ix.rc.d' / 'ix-nfsbind'

BASE_NFS = {
    'allow_nonroot': False,
    'mountd_log': False,
    'mountd_port': None,
    'rpcstatd_port': None,
    'rpclockd_port': None,
    'servers': 16,
    'statd_lockd_log': False,
    'udp': False,
    'v4': False,
    'v4_krb_enabled': False,
}

# A real system's configuration, whose rendered rc.conf.freenas lines are the expected values below.
BOUND_NFS = {**BASE_NFS, 'allow_nonroot': True, 'mountd_port': 755, 'rpcstatd_port': 756, 'rpclockd_port': 757, 'udp': True}


class Middleware:

    def __init__(self, nfs, bindip):
        self.nfs = nfs
        self.bindip = bindip
        self.calls = []

    def call_sync(self, name, *args):
        self.calls.append(name)
        if name == 'nfs.config':
            return dict(self.nfs)
        if name == 'nfs.bindip':
            assert args == (self.nfs,)
            return list(self.bindip)
        raise AssertionError(f'unexpected call {name!r}')


def generator(script):
    # Loaded the way PyRenderer loads every etc_files generator.
    path = ETC_FILES / 'rc.conf.d' / f'{script}.py'
    spec = importlib.util.spec_from_file_location(script, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_flags_without_a_bind_ip_are_the_rc_conf_freenas_defaults():
    flags = nfs_rc_flags(BASE_NFS, [])

    assert flags == {
        'nfs_server_flags': '-t -n 16 -S',
        'rpc_statd_flags': '',
        'rpc_lockd_flags': '',
        'mountd_flags': '-rS',
    }


def test_bind_ip_reaches_every_daemon_that_takes_one():
    flags = nfs_rc_flags(BOUND_NFS, ['192.0.2.10'])

    assert flags == {
        'rpcbind_flags': '-h 192.0.2.10',
        'nfs_server_flags': '-t -n 16 -S -u -h 192.0.2.10',
        'rpc_statd_flags': '-p 756 -h 192.0.2.10',
        'rpc_lockd_flags': '-p 757',
        'mountd_flags': '-rS -n -p 755 -h 192.0.2.10',
    }


def test_flags_keep_rc_conf_freenas_order():
    assert list(nfs_rc_flags(BOUND_NFS, ['192.0.2.10'])) == [
        'rpcbind_flags', 'nfs_server_flags', 'rpc_statd_flags', 'rpc_lockd_flags', 'mountd_flags',
    ]


@pytest.mark.parametrize('script', sorted(RC_CONF_D))
def test_rc_conf_d_file_carries_the_variables_its_script_reads(script):
    middleware = Middleware(BOUND_NFS, ['192.0.2.10'])
    expected = nfs_rc_flags(BOUND_NFS, ['192.0.2.10'])[RC_CONF_D[script][0]]

    assert generator(script).render(None, middleware) == ''.join(f'{var}="{expected}"\n' for var in RC_CONF_D[script])
    assert middleware.calls == ['nfs.config', 'nfs.bindip']


def test_statd_and_lockd_files_set_the_script_variable_too():
    # FreeBSD before d85e97c16f03 lets run_rc_command clobber the script's rc_flags=${rpc_statd_flags}; only
    # statd_flags / lockd_flags reach the daemon there. Proven on a 15.2 test VM.
    assert generator('statd').render(None, Middleware(BOUND_NFS, ['192.0.2.10'])) == (
        'rpc_statd_flags="-p 756 -h 192.0.2.10"\nstatd_flags="-p 756 -h 192.0.2.10"\n'
    )
    assert generator('lockd').render(None, Middleware(BOUND_NFS, ['192.0.2.10'])) == (
        'rpc_lockd_flags="-p 757"\nlockd_flags="-p 757"\n'
    )


def test_rpcbind_file_goes_away_without_a_bind_ip_like_its_rc_conf_line():
    with pytest.raises(FileShouldNotExist):
        generator('rpcbind').render(None, Middleware(BASE_NFS, []))

    assert generator('statd').render(None, Middleware(BASE_NFS, [])) == 'rpc_statd_flags=""\nstatd_flags=""\n'


def test_rc_group_renders_rc_conf_d_for_every_script():
    paths = [entry['path'] for entry in EtcService.GROUPS['rc']]

    assert paths.index('rc.conf') < min(paths.index(f'rc.conf.d/{script}') for script in RC_CONF_D)
    for script in RC_CONF_D:
        assert f'rc.conf.d/{script}' in paths


def test_ix_nfsbind_runs_before_every_rc_conf_d_script():
    before = next(line for line in IX_NFSBIND.read_text().splitlines() if line.startswith('# BEFORE:'))

    for script in RC_CONF_D:
        assert script in before.split()
