from unittest.mock import patch

from middlewared.etc_files.rc.conf import collectd_config, nfs_config


BASE_NFS_CONFIG = {
    'allow_nonroot': False,
    'mountd_log': False,
    'mountd_port': None,
    'rpcstatd_port': None,
    'rpclockd_port': None,
    'servers': 16,
    'statd_lockd_log': False,
    'udp': False,
    'userd_manage_gids': False,
    'v4': False,
    'v4_domain': '',
    'v4_krb_enabled': False,
    'v4_v3owner': False,
}


class NFSRcMiddleware:

    def __init__(self, nfs):
        self.nfs = nfs

    def call_sync(self, name, *args):
        if name == 'etc.generate':
            assert args == ('kerberos',)
            return None
        if name == 'nfs.config':
            return self.nfs
        if name == 'nfs.bindip':
            return []
        if name == 'datastore.query':
            return [{'srv_service': 'nfs', 'srv_enable': True}]
        if name == 'network.configuration.config':
            return {'hostname_virtual': '', 'domain': ''}

        raise AssertionError(f'unexpected call {name!r}')


class CollectdRcMiddleware:

    def __init__(self, systemdataset_pool):
        self.systemdataset_pool = systemdataset_pool

    def call_sync(self, name, *args):
        if name == 'systemdataset.config':
            return {'pool': self.systemdataset_pool}
        if name == 'boot.pool_name':
            return 'boot-pool'

        raise AssertionError(f'unexpected call {name!r}')


def test_nfs_config_uses_authsys_only_without_kerberos():
    result = list(nfs_config(NFSRcMiddleware(BASE_NFS_CONFIG.copy()), {
        'failover_licensed': False,
        'failover_status': 'SINGLE',
    }))

    assert 'nfs_server_flags="-t -n 16 -S"' in result
    assert 'gssd_enable="YES"' not in result


def test_nfs_config_uses_authsys_only_without_v4_even_with_nfs_principal():
    nfs = BASE_NFS_CONFIG.copy()
    nfs.update({
        'v4': False,
        'v4_krb_enabled': True,
    })

    result = list(nfs_config(NFSRcMiddleware(nfs), {
        'failover_licensed': False,
        'failover_status': 'SINGLE',
    }))

    assert 'nfs_server_flags="-t -n 16 -S"' in result
    assert 'gssd_enable="YES"' not in result


def test_nfs_config_keeps_gss_registration_with_kerberos():
    nfs = BASE_NFS_CONFIG.copy()
    nfs.update({
        'v4': True,
        'v4_krb_enabled': True,
    })

    with patch('middlewared.etc_files.rc.conf._load_nfsd_module'):
        result = list(nfs_config(NFSRcMiddleware(nfs), {
            'failover_licensed': False,
            'failover_status': 'SINGLE',
        }))

    assert 'nfs_server_flags="-t -n 16"' in result
    assert 'nfs_server_flags="-t -n 16 -S"' not in result
    assert 'gssd_enable="YES"' in result


def test_collectd_config_uses_rrdcached_rc_variables():
    result = list(collectd_config(CollectdRcMiddleware('boot-pool'), {
        'failover_licensed': False,
        'failover_status': 'SINGLE',
    }))

    assert 'collectd_daemon_enable="YES"' in result
    assert 'rrdcached_enable="YES"' in result
    assert 'rrdcached_group="www"' in result
    assert 'rrdcached_address="/var/run/rrdcached.sock"' in result
    assert 'rrdcached_pid="/var/run/rrdcached.pid"' in result
    assert 'rrdcached_flags="-w 3600 -f 7200"' in result

    rrdcached_flags = [line for line in result if line.startswith('rrdcached_flags=')][0]
    assert '-s www' not in rrdcached_flags
    assert '-l /var/run/rrdcached.sock' not in rrdcached_flags
    assert '-p /var/run/rrdcached.pid' not in rrdcached_flags


def test_collectd_config_omits_rrdcached_tuning_when_sysdataset_is_not_on_boot_pool():
    result = list(collectd_config(CollectdRcMiddleware('tank'), {
        'failover_licensed': False,
        'failover_status': 'SINGLE',
    }))

    assert 'rrdcached_flags=""' in result
