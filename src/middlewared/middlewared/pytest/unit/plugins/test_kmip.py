import inspect

from middlewared.plugins.kmip import KMIPService


PUBLIC_METHODS = {
    'clear_sync_pending_keys',
    'config',
    'kmip_sync_pending',
    'sync_keys',
    'update',
}

PRIVATE_METHODS = {
    'reset_sed_disk_password',
    'reset_sed_global_password',
    'reset_zfs_key',
    'retrieve_sed_disks_keys',
    'retrieve_zfs_keys',
    'sed_global_password',
    'sync_sed_keys',
    'sync_zfs_keys',
}


def test_disabled_kmip_compatibility_api_surface():
    methods = {
        name: method
        for name, method in inspect.getmembers(KMIPService, inspect.isfunction)
        if not name.startswith('_')
    }

    assert {name for name, method in methods.items() if not hasattr(method, '_private')} == PUBLIC_METHODS
    assert {name for name, method in methods.items() if hasattr(method, '_private')} == PRIVATE_METHODS
