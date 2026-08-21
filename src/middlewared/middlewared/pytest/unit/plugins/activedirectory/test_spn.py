from middlewared.plugins.activedirectory_.spn import samba_keytab_sync_option, service_spn_targets


def test_service_spn_targets_preserve_registered_hostnames_and_aliases():
    assert service_spn_targets('NFS', [
        'HOST/NAS',
        'host/nas.example.test',
        'HOST/alias.example.test',
        'host/NAS',
        'RestrictedKrbHost/nas.example.test',
    ], 'ignored', 'ignored.test') == [
        'nfs/nas',
        'nfs/nas.example.test',
        'nfs/alias.example.test',
    ]


def test_service_spn_targets_fall_back_to_configured_names():
    assert service_spn_targets('nfs', [], 'NAS', 'EXAMPLE.TEST') == [
        'nfs/nas',
        'nfs/nas.example.test',
    ]


def test_samba_keytab_sync_option_is_complete():
    assert samba_keytab_sync_option('/tmp/machine.keytab') == (
        'sync machine password to keytab=/tmp/machine.keytab:'
        'spn_prefixes=host:account_name:sync_spns:sync_kvno:machine_password'
    )
