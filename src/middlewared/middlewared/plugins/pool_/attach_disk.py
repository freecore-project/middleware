from middlewared.schema import accepts, Bool, Dict, Int, Str
from middlewared.service import CallError, job, Service, ValidationErrors


RAIDZ_TYPES = ('RAIDZ1', 'RAIDZ2', 'RAIDZ3')
RAIDZ_EXPANSION_FEATURE = 'raidz_expansion'
ZFS_FEATURE_ENABLED_STATES = ('ENABLED', 'ACTIVE')


def raidz_expansion_feature_enabled(zpool):
    return any(
        feature['name'] == RAIDZ_EXPANSION_FEATURE and feature['state'] in ZFS_FEATURE_ENABLED_STATES
        for feature in zpool.get('features') or []
    )


def raidz_expansion_in_progress(zpool):
    expand = zpool.get('expand') or {}
    return expand.get('state') == 'SCANNING' or bool(expand.get('waiting_for_resilver'))


class PoolService(Service):

    @accepts(
        Int('oid'),
        Dict(
            'pool_attach',
            Str('target_vdev', required=True),
            Str('new_disk', required=True),
            Str('passphrase'),
            Bool('allow_duplicate_serials', default=False),
        )
    )
    @job(lock=lambda args: f'pool_attach_{args[0]}')
    async def attach(self, job, oid, options):
        """
        For TrueNAS Core/Enterprise platform, if the `oid` pool is passphrase GELI encrypted, `passphrase`
        must be specified for this operation to succeed.

        `target_vdev` is the GUID of the vdev where the disk needs to be attached. In case of STRIPED vdev, this
        is the STRIPED disk GUID which will be converted to mirror. If `target_vdev` is mirror, it will be converted
        into a n-way mirror. If `target_vdev` is RAID-Z, the RAID-Z vdev will be expanded by one disk.
        """
        pool = await self.middleware.call('pool.get_instance', oid)
        verrors = ValidationErrors()
        if not pool['is_decrypted']:
            verrors.add('oid', 'Pool must be unlocked for this action.')
            verrors.check()

        topology = pool['topology']
        topology_type = vdev = None
        for i in topology:
            for v in topology[i]:
                if v['guid'] == options['target_vdev']:
                    topology_type = i
                    vdev = v
                    break
            if topology_type:
                break
        else:
            verrors.add('pool_attach.target_vdev', 'Unable to locate VDEV')
            verrors.check()

        raidz_attach = topology_type == 'data' and vdev['type'] in RAIDZ_TYPES

        if topology_type in ('cache', 'spare'):
            verrors.add('pool_attach.target_vdev', f'Attaching disks to {topology_type} not allowed.')
        elif topology_type == 'data':
            # We would like to make sure here that we don't have inconsistent vdev types across data
            if vdev['type'] not in ('DISK', 'MIRROR', *RAIDZ_TYPES):
                verrors.add('pool_attach.target_vdev', f'Attaching disk to {vdev["type"]} vdev is not allowed.')
            elif raidz_attach:
                zpool = (await self.middleware.call('zfs.pool.query', [['id', '=', pool['name']]]))[0]
                if not raidz_expansion_feature_enabled(zpool):
                    verrors.add(
                        'pool_attach.target_vdev',
                        'RAID-Z expansion requires the raidz_expansion pool feature. '
                        'Upgrade this pool before adding a disk to a RAID-Z vdev.'
                    )
                if raidz_expansion_in_progress(zpool):
                    verrors.add(
                        'pool_attach.target_vdev',
                        'A RAID-Z expansion is already in progress for this pool.'
                    )

        if pool['encrypt'] == 2:
            if not options.get('passphrase'):
                verrors.add('pool_attach.passphrase', 'Passphrase is required for encrypted pool.')
            elif not await self.middleware.call('disk.geli_testkey', pool, options['passphrase']):
                verrors.add('pool_attach.passphrase', 'Passphrase is not valid.')

        # Let's validate new disk now
        availability_errors, _ = await self.middleware.call(
            'disk.check_disks_availability', [options['new_disk']], options['allow_duplicate_serials']
        )
        verrors.add_child('pool_attach', availability_errors)
        verrors.check()

        disks = {options['new_disk']: {'create_swap': topology_type == 'data'}}
        await self.middleware.call('pool.format_disks', job, disks)
        await self.middleware.call('geom.cache.invalidate')

        zfs_part = await self.middleware.call('disk.get_zfs_part_type')
        new_devname = await self.middleware.call('disk.gptid_from_part_type', options['new_disk'], zfs_part)
        if pool['encrypt'] > 0:
            new_devname = f'{new_devname}.eli'
            enc_disks = [{'devname': new_devname}]
            enc_options = {'enc_keypath': pool['encryptkey_path'], 'passphrase': options.get('passphrase')}
            await self.middleware.call('pool.encrypt_disks', job, enc_disks, enc_options)

        guid = vdev['guid'] if vdev['type'] == 'DISK' or raidz_attach else vdev['children'][0]['guid']
        extend_job = await self.middleware.call('zfs.pool.extend', pool['name'], None, [
            {'target': guid, 'type': 'DISK', 'path': f'/dev/{new_devname}'}
        ])
        try:
            await job.wrap(extend_job)
        except CallError:
            if pool['encrypt'] > 0:
                try:
                    # If attach has failed, detach GELI to avoid keeping the disk busy.
                    await self.middleware.call('disk.geli_detach_single', new_devname)
                except Exception:
                    self.logger.warning('Failed to geli detach %r', new_devname, exc_info=True)
            raise

        if pool['encrypt'] > 0:
            enc_disks = [{'disk': options['new_disk'], 'devname': f'{new_devname.removeprefix("/dev/")}'}]
            disk = await self.middleware.call('disk.query', [['devname', '=', options['new_disk']]], {'get': True})
            await self.middleware.call('pool.save_encrypteddisks', oid, enc_disks, {disk['devname']: disk})

        self.middleware.create_task(self.middleware.call('disk.swaps_configure'))
