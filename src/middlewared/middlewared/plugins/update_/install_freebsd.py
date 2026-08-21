# -*- coding=utf-8 -*-
import contextlib
import os
import shutil
import subprocess
import tempfile
import time

try:
    from freenasOS import Configuration, Manifest, Update
except ImportError:
    from middlewared.utils.freenasOS import Configuration, Manifest, Update

import humanfriendly
import requests

from middlewared.plugins.config_ import scale as scale_config
from middlewared.schema import accepts, Bool, Dict
from middlewared.service import CallError, job, private, Service
from middlewared.worker import FakeJob

from . import scale_sidegrade
from .download import sha256_file
from .utils import can_update
from .utils_freebsd import UpdateHandler

run_kw = dict(check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', errors='ignore')


class ScaledProgress:
    """A job seen through a progress window: `start` + `span` percent of the real job's progress."""

    def __init__(self, job, start, span):
        self.job, self.start, self.span = job, start, span

    def set_progress(self, percent, description=None, extra=None):
        self.job.set_progress(self.start + (percent or 0) * self.span / 100, description, extra)


class UpdateService(Service):
    @private
    def install_impl(self, job, location):
        if os.path.exists(os.path.join(location, 'scale')):
            return self._install_scale(job, os.path.join(location, 'update.sqsh'))

        old_manifest = Configuration.Configuration().SystemManifest()

        new_manifest = Manifest.Manifest(require_signature=True)
        try:
            new_manifest.LoadPath('{}/MANIFEST'.format(location))
        except FileNotFoundError:
            raise CallError('Uploaded file is not a manual update file')
        if not new_manifest.Signature() or not new_manifest.VerifySignature():
            raise CallError('Update manifest signature is missing or invalid')

        old_version = old_manifest.Version()
        new_version = new_manifest.Version()
        if old_version == new_version:
            raise CallError(f'You already are using {new_version}')
        if not can_update(old_version, new_version):
            raise CallError(f'Unable to downgrade from {old_version} to {new_version}')
        return self.middleware.call_sync('update.install_impl_job', job.id, location).wait_sync(raise_error=True)

    @private
    @job(process=True)
    def install_impl_job(self, job, job_id, location):
        job = FakeJob(job_id, self.middleware.client)

        handler = UpdateHandler(self, job)

        return Update.ApplyUpdate(
            location,
            install_handler=handler.install_handler,
        )

    @private
    def install_manual_impl(self, job, path, dest_extracted):
        p = subprocess.run(['file', path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, encoding='ascii',
                           errors='ignore')
        if 'Squashfs filesystem' in p.stdout:
            if self.middleware.call_sync('system.is_enterprise'):
                try:
                    allowed = self.middleware.call_sync('cache.get', 'TRUENAS_ENT_UPGRADE') == 1
                except KeyError:
                    allowed = False

                if not allowed:
                    raise CallError('Enterprise upgrade to SCALE not allowed')
            return self._install_scale(job, path)

        job.set_progress(30, 'Extracting file')
        Update.ExtractFrozenUpdate(path, dest_extracted, verbose=True)

        job.set_progress(50, 'Applying update')
        if self.install_impl(job, dest_extracted) is None:
            raise CallError('Uploaded file is not a manual update file')

    @accepts()
    def scale_move_check(self):
        """
        What moving this system to TrueNAS SCALE in place would do (the internal development record). Nothing is
        downloaded or changed.

        `target` is the TrueNAS SCALE 24.04 update the move would install and where it comes from.
        `blockers` stop the move. `pools` lists pools TrueNAS SCALE 24.04 cannot import (or imports
        read-only) until a later release runs; they never stop the move. `not_carried` lists FreeCORE-only
        settings in use that do not travel. `way_back` says how to return to FreeCORE.
        """
        blockers = []
        if self.middleware.call_sync('system.is_enterprise'):
            blockers.append('This system cannot be moved to TrueNAS SCALE in place.')
        for check in (scale_sidegrade.check_tools,
                      lambda: scale_sidegrade.check_boot_pool(self.middleware.call_sync('boot.pool_name')),
                      lambda: scale_sidegrade.check_bios_grub(scale_sidegrade.boot_method())):
            try:
                check()
            except CallError as e:
                blockers.append(e.errmsg)
        target = None
        try:
            target = self.scale_move_target()
        except CallError as e:
            blockers.append(e.errmsg)
        if target is not None:
            location = self.middleware.call_sync('update.get_update_location')
            free, needed = shutil.disk_usage(location).free, scale_sidegrade.required_space(target)
            if free < needed:
                blockers.append(
                    f'The move needs {humanfriendly.format_size(needed)} free at {location} for the update file and '
                    f'its image; {humanfriendly.format_size(free)} is free.'
                )
        pools = []
        for pool in self.middleware.call_sync('pool.query', [], {'select': ['name']}):
            warning = scale_sidegrade.pool_warning(scale_config.pool_feature_report(
                pool['name'], features=scale_sidegrade.SCALE_2404_POOL_FEATURES,
                reference=scale_sidegrade.SCALE_2404_RELEASE,
            ))
            if warning:
                pools.append(warning)
        return {
            'available': not blockers,
            'target': target,
            'blockers': blockers,
            'pools': pools,
            'not_carried': self.scale_move_not_carried(),
            'way_back': scale_sidegrade.WAY_BACK,
        }

    @accepts(Dict('scale_move', Bool('reboot', default=False)))
    @job(lock='updatemanual')
    def scale_move(self, job, options):
        """
        Move this system to TrueNAS SCALE 24.04 in place (the internal development record): fetch the update named by
        `update.scale_move_check`, verify its published SHA-256 and install it beside the FreeCORE boot
        environment, which is kept for the way back. Refuses on any blocker the check reports; pool warnings
        do not stop it. `reboot` restarts into TrueNAS SCALE when the install is done.
        """
        check = self.scale_move_check()
        if check['blockers']:
            raise CallError('\n'.join(check['blockers']))
        location = self.middleware.call_sync('update.get_update_location')
        path = self.scale_move_download(job, check['target'], location)
        try:
            self._install_scale(ScaledProgress(job, 40, 60), path)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)
        if options['reboot']:
            self.middleware.call_sync('system.reboot', {'delay': 10})
        return True

    @private
    def scale_move_target(self, get=requests.get):
        """iX's 24.04 update when iX serves it; otherwise FreeCORE's mirror of the pinned file; otherwise refuse."""
        try:
            response = get(f'{scale_sidegrade.IX_SCALE_UPDATE_SERVER}/{scale_sidegrade.MOVE_TRAIN}/manifest.json',
                           timeout=30)
            response.raise_for_status()
            target = scale_sidegrade.move_target(response.json())
        except (requests.RequestException, ValueError, CallError):
            self.logger.warning('TrueNAS SCALE 24.04 is not available from iX', exc_info=True)
        else:
            return dict(target, source='iX', url=(f'{scale_sidegrade.IX_SCALE_UPDATE_SERVER}/'
                                                  f'{scale_sidegrade.MOVE_TRAIN}/{target["filename"]}'))
        pinned = scale_sidegrade.PINNED_TARGET
        url = f'{scale_sidegrade.FREECORE_SCALE_MIRROR}/{scale_sidegrade.MOVE_TRAIN}/{pinned["filename"]}'
        try:
            response = get(url, stream=True, timeout=30)
            response.raise_for_status()
            size = int(response.headers.get('Content-Length', -1))
            response.close()
        except (requests.RequestException, ValueError):
            size = None
        if size == pinned['filesize']:
            return dict(pinned, source='FreeCORE mirror', url=url)
        raise CallError(
            f'TrueNAS SCALE 24.04 is not available from iX or from FreeCORE right now. '
            f'{scale_sidegrade.CONFIG_FILE_ADVICE}'
        )

    @private
    def scale_move_download(self, job, target, location, get=requests.get):
        """The verified update file in `location`; a file whose SHA-256 differs is removed and refused."""
        path = os.path.join(location, target['filename'])
        if os.path.exists(path) and os.path.getsize(path) == target['filesize']:
            job.set_progress(0, 'Verifying the TrueNAS SCALE update already downloaded')
            if sha256_file(path) == target['checksum']:
                return path
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
        started = time.monotonic()
        with get(target['url'], stream=True, timeout=30) as response, open(path, 'wb') as file:
            response.raise_for_status()
            for chunk in response.iter_content(chunk_size=8 * 1024 * 1024):
                file.write(chunk)
                done = file.tell()
                job.set_progress(
                    done / target['filesize'] * 35,
                    f'Downloading TrueNAS SCALE {target["version"]} from {target["source"]}: '
                    f'{humanfriendly.format_size(done)} of {humanfriendly.format_size(target["filesize"])} at '
                    f'{humanfriendly.format_size(done / max(time.monotonic() - started, 1e-3))}/s',
                )
        job.set_progress(35, 'Verifying the TrueNAS SCALE update')
        if os.path.getsize(path) != target['filesize'] or sha256_file(path) != target['checksum']:
            os.unlink(path)
            raise CallError(
                f'The downloaded TrueNAS SCALE update does not match its published SHA-256 ({target["source"]}). '
                'Nothing was installed.'
            )
        return path

    @private
    def scale_move_not_carried(self):
        """FreeCORE-only settings in use that TrueNAS SCALE has no place for."""
        def call(method, *args, default=None):
            try:
                return self.middleware.call_sync(method, *args)
            except Exception:
                return default

        items = []
        services = {service['service']: service for service in call('service.query', default=[]) or []}
        for name, label in (('wireguard', 'WireGuard server'), ('wireguard_client', 'WireGuard client'),
                            ('bastille', 'Bastille jails'), ('rar2fs', 'rar2fs')):
            service = services.get(name)
            if service and (service['enable'] or service['state'] == 'RUNNING'):
                items.append(label)
        if (call('applications.config', default={}) or {}).get('configured'):
            count = len(call('applications.query', default=[]) or [])
            items.append(f'Applications ({count} installed)')
        jails = call('jail.query', [], {'select': ['id']}, default=[]) or []
        if jails:
            items.append(f'iocage jails and plugins ({len(jails)})')
        return items

    def _install_scale(self, job, path):
        location = os.path.dirname(path)

        # the internal development record: which release this is and whether the image can install it,
        # settled before a gigabyte is extracted for nothing.
        manifest = scale_sidegrade.read_manifest(path)
        scale_sidegrade.check_target(manifest)
        scale_sidegrade.check_tools()
        scale_sidegrade.check_boot_pool(self.middleware.call_sync('boot.pool_name'))
        # the internal development record: a BIOS system needs GRUB's i386-pc platform, and the installer retypes
        # FreeBSD's boot partition before it installs GRUB. Record the partitions to put back if it fails.
        method = scale_sidegrade.boot_method()
        scale_sidegrade.check_bios_grub(method)
        bios_partitions = []
        if method == 'BIOS':
            bios_partitions = scale_sidegrade.bios_boot_partitions(self.middleware.call_sync('boot.get_disks'))

        mounted = os.path.join(location, 'squashfs-root')
        with contextlib.suppress(FileNotFoundError):
            shutil.rmtree(mounted)

        job.set_progress(0, 'Extracting update file')
        subprocess.run(['unsquashfs', os.path.basename(path)], cwd=location, **run_kw)

        # The installer copies /data from the root it is given. It gets a staged root whose
        # database is the 13.3-shaped copy SCALE accepts; the live root is never touched, so the
        # GRUB "TrueNAS CORE" entry brings this boot environment back as it is.
        staged = tempfile.mkdtemp(prefix='freecore-to-scale-', dir='/var/tmp')
        try:
            job.set_progress(45, 'Preparing the configuration TrueNAS SCALE accepts')
            self._stage_old_root(staged)
            try:
                return self.middleware.call_sync(
                    'update.install_scale',
                    mounted,
                    lambda progress, description: job.set_progress((0.5 + 0.5 * progress) * 100, description),
                    staged,
                )
            except Exception as error:
                if not bios_partitions:
                    raise
                failures = scale_sidegrade.restore_bios_boot(bios_partitions)
                self.logger.error('TrueNAS SCALE install failed on a BIOS system; boot partition restore: %s',
                                  failures or 'done')
                message = getattr(error, 'errmsg', None) or str(error)
                restored = scale_sidegrade.bios_restore_message(bios_partitions, failures)
                raise CallError(f'{message}\n{restored}') from error
        finally:
            scale_sidegrade.discard_staged_root(staged)
            shutil.rmtree(mounted)

    def _stage_old_root(self, staged):
        version = self.middleware.call_sync('system.version')
        boot_environment = scale_sidegrade.root_dataset()
        pool_lines = []
        for pool in self.middleware.call_sync('pool.query', [], {'select': ['name']}):
            pool_lines.extend(scale_config.describe_pool_report(scale_config.pool_feature_report(pool['name'])))
        scale_sidegrade.stage_old_root(
            staged, lambda undone: scale_sidegrade.readme(undone, version, boot_environment, pool_lines),
        )
