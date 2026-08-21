import os
import shutil
import subprocess
import tarfile
import time

from middlewared.service import lock, private, Service

from .utils import reconcile_hostname_link


FUTURE_RRD_GRACE_SECONDS = 300


def get_members(tar, prefix):
    for tarinfo in tar.getmembers():
        if tarinfo.name.startswith(prefix):
            tarinfo.name = tarinfo.name[len(prefix):]
            yield tarinfo


class ReportingService(Service):

    @private
    def remove_future_rrds(self, rrd_dir):
        """
        RRD refuses updates older than a database's last update timestamp.
        If the system clock is corrected backwards after early boot, any RRDs
        created before the correction can spam collectd until wall time catches
        up. Drop only those future-dated files and let collectd recreate them.
        """
        rrdtool = shutil.which('rrdtool')
        if rrdtool is None:
            self.middleware.logger.debug('Skipping future RRD check: rrdtool is not available')
            return 0

        now = int(time.time())
        removed = 0
        max_skew = 0
        localhost_dir = os.path.join(rrd_dir, 'localhost')
        if not os.path.isdir(localhost_dir):
            return 0

        for dirpath, _dirnames, filenames in os.walk(localhost_dir):
            for filename in filenames:
                if not filename.endswith('.rrd'):
                    continue

                path = os.path.join(dirpath, filename)
                try:
                    cp = subprocess.run(
                        [rrdtool, 'last', path],
                        capture_output=True,
                        check=False,
                        text=True,
                        timeout=5,
                    )
                    if cp.returncode != 0:
                        self.middleware.logger.debug(
                            'Failed to read RRD last update for %s: %s', path, cp.stderr.strip()
                        )
                        continue

                    last_update = int(cp.stdout.strip())
                except Exception:
                    self.middleware.logger.debug('Failed to inspect RRD timestamp for %s', path, exc_info=True)
                    continue

                skew = last_update - now
                if skew <= FUTURE_RRD_GRACE_SECONDS:
                    continue

                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
                except OSError:
                    self.middleware.logger.warning('Failed to remove future-dated RRD %s', path, exc_info=True)
                    continue

                removed += 1
                max_skew = max(max_skew, skew)

        if removed:
            self.middleware.logger.warning(
                'Removed %d reporting RRD files with timestamps up to %d seconds in the future',
                removed,
                max_skew,
            )

        return removed

    @private
    @lock('reporting.setup')
    def setup(self):
        systemdatasetconfig = self.middleware.call_sync('systemdataset.config')
        if not systemdatasetconfig['path']:
            self.middleware.logger.debug('System dataset not yet mounted — reporting.setup deferred')
            return False

        rrd_mount = f'{systemdatasetconfig["path"]}/rrd-{systemdatasetconfig["uuid"]}'
        if not os.path.exists(rrd_mount):
            self.middleware.logger.error(f'{rrd_mount} does not exist or is not a directory')
            return False

        # Ensure that collectd working path is a symlink to system dataset
        base_collectd = '/var/db/collectd'
        pwd = os.path.join(base_collectd, 'rrd')
        if os.path.islink(pwd):
            if os.path.realpath(pwd) != rrd_mount:
                os.unlink(pwd)
        else:
            if os.path.exists(pwd):
                shutil.move(pwd, f'{pwd}.{time.strftime("%Y%m%d%H%M%S")}')
        if not os.path.exists(pwd):
            os.makedirs(base_collectd, exist_ok=True)
            os.symlink(rrd_mount, pwd)

        # Migrate legacy RAMDisk
        persist_file = '/data/rrd_dir.tar.bz2'
        if os.path.isfile(persist_file):
            with tarfile.open(persist_file) as tar:
                if 'collectd/rrd' in tar.getnames():
                    tar.extractall(pwd, get_members(tar, 'collectd/rrd/'))

            os.unlink('/data/rrd_dir.tar.bz2')

        network_config = self.middleware.call_sync('network.configuration.config')
        hostname = f"{network_config['hostname_local']}.{network_config['domain']}"

        # Migrate from old version, where `hostname` was a real directory and `localhost` was a symlink.
        # Skip the case where `hostname` is "localhost", so symlink was not (and is not) needed.
        if (
            hostname != 'localhost' and
            os.path.isdir(os.path.join(pwd, hostname)) and
            not os.path.islink(os.path.join(pwd, hostname))
        ):
            if os.path.exists(os.path.join(pwd, 'localhost')):
                if os.path.islink(os.path.join(pwd, 'localhost')):
                    os.unlink(os.path.join(pwd, 'localhost'))
                else:
                    # This should not happen, but just in case
                    shutil.move(
                        os.path.join(pwd, 'localhost'),
                        os.path.join(pwd, f'localhost.bak.{time.strftime("%Y%m%d%H%M%S")}')
                    )
            shutil.move(os.path.join(pwd, hostname), os.path.join(pwd, 'localhost'))

        reconcile_hostname_link(pwd, hostname)

        self.remove_future_rrds(pwd)

        # Let's return a positive value to indicate that necessary collectd operations were performed successfully
        return True
