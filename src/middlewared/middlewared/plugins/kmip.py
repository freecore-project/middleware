import errno

from middlewared.schema import accepts, Bool, Dict, Int, Str
from middlewared.service import CallError, Service, job, periodic, private

# Column set from alembic 12.0/2019-12-29_14-09_kmip; enabled has never been
# True on this fork, so the stub reports the permanent disabled state.
KMIP_CONFIG = {
    'id': 1,
    'server': None,
    'port': 5696,
    'certificate': None,
    'certificate_authority': None,
    'manage_sed_disks': False,
    'manage_zfs_keys': False,
    'enabled': False,
}


class KMIPService(Service):
    """
    Stand-in for the removed proprietary KMIP plugin (freecore/the internal development record).
    Key material is managed locally; every method behaves as the real plugin
    did with KMIP disabled.
    """

    @accepts()
    async def config(self):
        return dict(KMIP_CONFIG)

    @accepts(Dict(
        'kmip_update',
        Bool('enabled'),
        Bool('manage_sed_disks'),
        Bool('manage_zfs_keys'),
        Bool('force_clear'),
        Bool('change_server'),
        Bool('validate'),
        Int('certificate', null=True),
        Int('certificate_authority', null=True),
        Int('port'),
        Str('server', null=True),
        update=True,
    ))
    @job(lock='kmip_update')
    async def update(self, job, data):
        if data.get('enabled'):
            raise CallError('KMIP support has been removed from FreeCORE', errno.ENOTSUP)
        return dict(KMIP_CONFIG)

    @accepts()
    async def kmip_sync_pending(self):
        return False

    @periodic(86400)
    async def sync_keys(self):
        return None

    @accepts()
    async def clear_sync_pending_keys(self):
        return None

    @private
    async def sync_zfs_keys(self, ids=None):
        return None

    @private
    async def sync_sed_keys(self, ids=None):
        return None

    @private
    async def retrieve_zfs_keys(self):
        return {}

    @private
    async def retrieve_sed_disks_keys(self):
        return {}

    @private
    async def reset_zfs_key(self, dataset, kmip_uid):
        return None

    @private
    async def reset_sed_disk_password(self, disk_id, kmip_uid):
        return None

    @private
    async def reset_sed_global_password(self, kmip_uid):
        return None

    @private
    async def sed_global_password(self):
        return ''
