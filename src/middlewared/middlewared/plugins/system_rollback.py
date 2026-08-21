"""
Return-to-13.3 rollback window (the internal development record).

Two of the three pieces this needs already exist in the platform:

  * the config database rides the boot environment - `/data` is not a dataset, so
    `freenas-v1.db` travels with the BE and activating the 13.3 BE restores the 13.3
    configuration by itself;
  * pinning a BE so the updater cannot reap it is one existing call,
    `bootenv.set_attribute(<be>, {'keep': True})`.

`.system` is shared across boot environments and does NOT roll back with the BE.
Samba upgrades its tdb/ldb databases in place and they are not backward compatible,
so this plugin captures `.system` and iocage under one coordinated snapshot name and
can stage their restore for a late shutdown hook before activating the 13.3 BE.

The one automatic entry point is `capture_on_boot`: `ix-update` leaves it a one-shot
arrival marker, and `pool.import_on_boot` calls it after data-pool import but before
`systemdataset.setup`.  With no marker and no captured window, ordinary boots remain
inert apart from retrying the teardown of an already-closed window.

The capture is persistent.  Nothing here runs on a timer: the return stays on offer
until the operator removes it (`system.rollback.remove`) or upgrades a pool's feature
flags past what 13.3 can import, and the space it holds is readable at any time
(`system.rollback.space`).
"""
from datetime import datetime
import json
import os
import tempfile

from middlewared.schema import accepts, Int, Str
from middlewared.service import CallError, Service, job, periodic, private
import middlewared.sqlalchemy as sa
from middlewared.utils import run
from middlewared.utils.asyncio_ import asyncio_map


DATASTORE = 'system.rollbackwindow'

# Every dataset captured for one window is snapshotted under this single coordinated
# name so that `.system` and iocage restore as a matched set.
SNAPSHOT_PREFIX = 'freecore-rollback'

# Written into the new boot environment by the ISO installer's upgrade path, see
# src/freenas-installer/etc/install.sh.
CD_UPGRADE_SENTINEL = '/data/cd-upgrade'

# `ix-update` consumes the update sentinels one reboot before data pools are imported.
# It persists the arrival path and the source system's synchronised Unix timestamp
# here instead.  The timestamp keeps the early-boot capture independent of a wall
# clock that NTP may still step after middleware starts.
ARRIVAL_PATH_MARKER = '/data/system-rollback.arrival'

CAPTURE_FAILED_ALERT = 'SystemRollbackCaptureFailed'

# How this system arrived at 15.0.
ARRIVAL_PATHS = ['manual_update', 'train', 'cd_upgrade', 'unknown']

# Why a captured return was closed.  `consumed` means the return was performed;
# `removed` means the operator discarded the capture to reclaim its space.
CLOSED_REASONS = ['pool_upgraded', 'consumed', 'removed']

# `execute()` stages an immutable restore plan in the current boot environment.
# A late shutdown hook consumes it only after middlewared and its dependent
# services have stopped, while the data pools are still imported.
RESTORE_PLAN_PATH = '/data/system-rollback.pending'
RESTORE_RUNNING_PATH = '/data/system-rollback.running'
RESTORE_FAILED_PATH = '/data/system-rollback.failed'

# A normal shutdown budget covers init tasks and the longest VM timeout, but
# the rollback transaction runs near the end of shutdown and may roll back
# hundreds of snapshots.  The first production-sized restore needed more than
# the ordinary 210-second budget and completed with this runtime-only floor.
ROLLBACK_SHUTDOWN_TIMEOUT = 900
SHUTDOWN_TIMEOUT_SYSCTL = 'kern.init_shutdown_timeout'
SYSCTL = '/sbin/sysctl'
WORKLOAD_JOB_PREFIXES = ('jail.', 'plugin.', 'vm.')


class RollbackWindowModel(sa.Model):
    __tablename__ = 'system_rollbackwindow'

    id = sa.Column(sa.Integer(), primary_key=True)
    origin_be = sa.Column(sa.String(255))
    arrival_path = sa.Column(sa.String(32))
    captured_at = sa.Column(sa.DateTime())
    system_dataset = sa.Column(sa.String(255))
    snapshots = sa.Column(sa.JSON(list))
    pool_state = sa.Column(sa.JSON(dict))
    closed_reason = sa.Column(sa.String(32), nullable=True)


class SystemRollbackService(Service):

    class Config:
        namespace = 'system.rollback'

    @accepts()
    async def config(self):
        """
        The rollback window recorded on this system, or `null` when there is none.

        A record is created by `system.rollback.capture`; the boot path calls it only
        when `ix-update` left a one-shot arrival marker.  A normal or fresh-install boot
        has no marker, so on a system that never captured a window this returns `null`
        and every other part of the feature stays inert.
        """
        windows = await self.middleware.call('datastore.query', DATASTORE, [], {'order_by': ['id']})
        if not windows:
            return None

        return windows[0]

    @accepts()
    async def available(self):
        """
        Whether returning to the 13.3 boot environment is still on offer.

        Returns `available` and, when it is not, a `reason` (`no_window`, `removed`,
        `iso_install`, `pool_upgraded`, `origin_be_missing`,
        `origin_be_unpinned`,
        `snapshots_missing`, `system_dataset_changed` or `iocage_changed`).

        The stored row is not trusted on its own.  Nothing runs on a timer here, so a row
        can outlive its own window; and the two things that destroy a rollback - the
        origin boot environment being deleted, and a pool having its feature flags
        upgraded past what 13.3 can import - both happen through paths that never touch
        this record.  So the boot environment and the pools are re-read every time.
        """
        window = await self.config()
        if window is None:
            return self.unavailable('no_window')

        if window['closed_reason'] is not None:
            # `consumed` means the rollback was performed, which leaves nothing to offer;
            # it has no reason of its own, so it reads as no window.
            return self.unavailable({
                'pool_upgraded': 'pool_upgraded',
                'removed': 'removed',
            }.get(window['closed_reason'], 'no_window'))

        if window['arrival_path'] == 'cd_upgrade':
            # An ISO upgrade rewrites the system outside middleware's control, so the
            # capture cannot be shown to have beaten 15.0 touching `.system`.
            return self.unavailable('iso_install')

        origin = await self.middleware.call('bootenv.query', [['id', '=', window['origin_be']]])
        if not origin:
            return self.unavailable('origin_be_missing')
        if origin[0].get('keep') is not True:
            # The updater is allowed to reap an unpinned BE, so advertising a
            # persistent return in this state would be a promise the system is not
            # actually keeping.
            return self.unavailable('origin_be_unpinned')

        if await self.pools_upgraded_since_capture(window):
            return self.unavailable('pool_upgraded')

        missing = await self.missing_snapshots(window)
        if missing:
            self.logger.warning(
                '%d recorded rollback snapshot(s) are missing: %s', len(missing), ', '.join(missing)
            )
            return self.unavailable('snapshots_missing')

        current_system_dataset = (await self.middleware.call('systemdataset.config'))['basename']
        if current_system_dataset != window['system_dataset']:
            return self.unavailable('system_dataset_changed')

        if set(await self.iocage_datasets()) != set(self.recorded_iocage_datasets(window)):
            return self.unavailable('iocage_changed')

        return {'available': True, 'reason': None}

    @private
    def unavailable(self, reason):
        return {'available': False, 'reason': reason}

    @private
    async def pools_upgraded_since_capture(self, window):
        """
        Whether any pool that was not already upgraded when the window was captured has
        been upgraded since.

        A pool that was already upgraded at capture time was upgraded under 13.3, so 13.3
        can still import it and it is not a blocker.  A pool that has gone away, or that
        now carries a different GUID under the same name, is not a blocker either - it is
        no longer the pool the window was recorded against.
        """
        recorded = window['pool_state'] or {}
        if not recorded:
            return False

        current = await self.pool_state()
        for name, before in recorded.items():
            after = current.get(name)
            if after is None:
                continue

            if before.get('guid') and after.get('guid') and before['guid'] != after['guid']:
                continue

            if not before.get('features_upgraded') and after.get('features_upgraded'):
                self.logger.debug('Pool %r has been feature upgraded since the rollback window was captured', name)
                return True

        return False

    @private
    async def origin_boot_environment(self):
        """
        The boot environment this one was cloned from, i.e. the one to return to.

        An update creates the new BE as a clone of the running one, so *before the switch*
        the new BE's dataset carries `origin=<boot pool>/ROOT/<previous BE>@<snapshot>`.
        That direct signal is checked first: it is stronger than parsing version strings out
        of BE names, and it is the only one that survives a BE being renamed.

        It does not survive the switch.  `bectl activate` **promotes** the environment it
        activates (`lib/libbe/be.c:be_activate()` -> `be_zfs_promote()`), which inverts every
        clone relationship in the pool: once 15.0 has booted, the running dataset owns the
        snapshots and every other boot environment - including the 13.3 one we came from - is
        a clone of *it*.  So on any box that has actually rebooted into the upgrade, the
        running dataset reads `origin=-` and the direct check finds nothing.  That is why
        this returned `null` on every upgraded box, which made `capture()` a silent no-op.

        In that state the origin is recovered from the inverted relationship: of the boot
        environments cloned from the running dataset, the one whose origin snapshot is
        **newest** is the one we came from, because that snapshot is taken at update time.
        Measured on a real upgraded box, the three clones and their origin snapshots are

            13.3-U1.2        @2026-08-10-05:35:36   1786365336   <- came from here
            Initial-Install  @2026-08-10-03:39:31   1786333171
            default          @2026-08-09-18:43:55   1786326235

        Returns `null` when there is genuinely nothing to return to - a fresh install, or an
        origin that has since been destroyed.
        """
        current = await self.middleware.call('bootenv.query', [['activated', '=', True]])
        if not current:
            self.logger.warning('Unable to determine the active boot environment')
            return None

        current = current[0]
        boot_pool = await self.middleware.call('boot.pool_name')
        prefix = f'{boot_pool}/ROOT/'
        running = f'{prefix}{current["realname"]}'

        datasets = await self.middleware.call(
            'zfs.dataset.query', [['id', '^', prefix]], {'extra': {'properties': ['origin']}}
        )
        boot_environments = {
            boot_environment['realname']: boot_environment['id']
            for boot_environment in await self.middleware.call('bootenv.query')
        }

        def origin_of(dataset):
            return (dataset['properties'].get('origin') or {}).get('parsed') or ''

        # Before the switch: the running dataset is still the clone, so read it directly.
        for dataset in datasets:
            if dataset['id'] != running:
                continue
            origin = origin_of(dataset)
            if '@' not in origin:
                break
            origin_dataset = origin.split('@', 1)[0]
            if not origin_dataset.startswith(prefix) or origin_dataset == running:
                return None
            return boot_environments.get(origin_dataset[len(prefix):])

        # After the switch: promotion inverted the relationship, so look for the boot
        # environments cloned from us and take the one with the newest origin snapshot.
        creation = {
            snapshot['id']: int((snapshot['properties'].get('creation') or {}).get('rawvalue') or 0)
            for snapshot in await self.middleware.call(
                'zfs.snapshot.query', [['dataset', '=', running]],
                {'extra': {'properties': ['creation']}},
            )
        }

        candidates = []
        for dataset in datasets:
            if dataset['id'] == running:
                continue
            origin = origin_of(dataset)
            if '@' not in origin or origin.split('@', 1)[0] != running:
                continue
            candidates.append((creation.get(origin, 0), dataset['id'][len(prefix):]))

        # Newest first; the realname only ever breaks a tie, and only to stay deterministic.
        # A candidate with no live boot environment is skipped rather than failing the whole
        # derivation, so a half-removed BE cannot mask the real origin behind it.
        for _, origin_realname in sorted(candidates, reverse=True):
            if origin_realname in boot_environments:
                return boot_environments[origin_realname]

        return None

    @private
    async def detect_arrival_path(self):
        """
        How this system arrived at 15.0, as far as it can be told after the reboot.

        Only the ISO upgrade path leaves a durable marker in the new boot environment.
        A train update and a manual update file are indistinguishable once the system is
        running on the new BE, so those have to be passed to `capture` by the caller that
        performed them; unstated, they are recorded as `unknown` rather than guessed.
        """
        if os.path.exists(CD_UPGRADE_SENTINEL):
            return 'cd_upgrade'

        return 'unknown'

    @private
    async def capture_on_boot(self):
        """
        Consume `ix-update`'s one-shot arrival marker and capture the rollback window.

        The marker is removed before capture starts.  That is deliberately at-most-once:
        if capture fails, a later boot must not snapshot `.system` after 15.0 services
        have already used it and then claim that state is safe to restore under 13.3.

        This method is called only after data-pool import and before
        `systemdataset.setup`.  It returns `None` without side effects when no marker is
        present, and consumes ISO-upgrade markers without offering an impossible window.
        """
        try:
            with open(ARRIVAL_PATH_MARKER) as f:
                arrival_marker = f.read(64).strip()
        except FileNotFoundError:
            return None
        except Exception:
            try:
                os.unlink(ARRIVAL_PATH_MARKER)
            except FileNotFoundError:
                pass
            except Exception:
                self.logger.warning('Unable to consume the unreadable rollback arrival marker', exc_info=True)
            await self.capture_failed_alert()
            self.logger.error('Unable to read the automatic rollback arrival marker', exc_info=True)
            raise

        # Consume before validation or capture.  Retrying after this boot would be unsafe.
        try:
            os.unlink(ARRIVAL_PATH_MARKER)
        except Exception:
            await self.capture_failed_alert()
            self.logger.error('Unable to consume the automatic rollback arrival marker', exc_info=True)
            raise

        parts = arrival_marker.split()
        arrival_path = parts[0] if parts else None
        captured_epoch = None
        try:
            if len(parts) == 2:
                captured_epoch = int(parts[1])
                if captured_epoch <= 0:
                    raise ValueError
                datetime.utcfromtimestamp(captured_epoch)
            elif len(parts) != 1:
                raise ValueError
        except (OSError, OverflowError, ValueError):
            arrival_path = None

        if arrival_path not in ARRIVAL_PATHS:
            await self.capture_failed_alert()
            self.logger.error('Automatic rollback arrival marker contained malformed or unsupported data')
            raise CallError('Automatic rollback arrival marker is invalid')

        if arrival_path == 'cd_upgrade':
            await self.clear_capture_failed_alert()
            self.logger.info('ISO upgrade has no origin boot environment; no rollback window will be captured')
            return None

        try:
            window = await self.capture(arrival_path, captured_epoch)
        except Exception:
            await self.capture_failed_alert()
            self.logger.error('Automatic rollback-window capture failed', exc_info=True)
            raise

        if window is None:
            await self.capture_failed_alert()
            self.logger.error('Automatic rollback-window capture produced no rollback window')
            raise CallError('Automatic rollback window could not be captured')

        await self.clear_capture_failed_alert()
        return window

    @private
    async def capture_failed_alert(self):
        try:
            await self.middleware.call('alert.oneshot_create', CAPTURE_FAILED_ALERT, None)
        except Exception:
            self.logger.error('Unable to create the rollback capture failure alert', exc_info=True)

    @private
    async def clear_capture_failed_alert(self):
        try:
            await self.middleware.call('alert.oneshot_delete', CAPTURE_FAILED_ALERT, None)
        except Exception:
            # The coordinated snapshots already exist.  Alert cleanup must not turn a
            # successful capture into a failed pool-import job.
            self.logger.warning('Unable to clear the rollback capture failure alert', exc_info=True)

    @private
    async def iocage_datasets(self):
        """
        The active iocage dataset(s), located the same way `jail.iocage_set_up` locates
        them: the pool root carries `org.freebsd.ioc:active`.

        Returns `[]` when jails were never set up, which is not an error.
        """
        roots = await self.middleware.call(
            'zfs.dataset.query',
            [['properties.org\\.freebsd\\.ioc:active.value', '=', 'yes']],
            {'extra': {'properties': ['mountpoint'], 'flat': False}},
        )

        return [
            child['name']
            for root in roots
            for child in (root.get('children') or [])
            if child['name'].endswith('/iocage')
        ]

    @private
    def recorded_iocage_datasets(self, window):
        """
        Recover the captured iocage roots from the recorded snapshot names.

        The row deliberately stores the full recursive snapshot list rather than a
        second roots field.  Every dataset outside the recorded system-dataset tree
        therefore belongs to an iocage tree; the top-most such datasets are its roots.
        """
        system_dataset = window['system_dataset']
        datasets = {
            name.split('@', 1)[0]
            for name in (window['snapshots'] or [])
            if '@' in name and not (
                name.split('@', 1)[0] == system_dataset
                or name.split('@', 1)[0].startswith(f'{system_dataset}/')
            )
        }

        return sorted(
            dataset for dataset in datasets
            if not any(dataset.startswith(f'{other}/') for other in datasets if other != dataset)
        )

    @private
    async def missing_snapshots(self, window):
        """Return every snapshot recorded by the window that is no longer present."""
        recorded = set(window['snapshots'] or [])
        if not recorded:
            # A valid capture always contains at least the system-dataset root.
            return ['<recorded snapshot list is empty>']

        present = set()
        for suffix in {name.split('@', 1)[1] for name in recorded if '@' in name}:
            present.update(
                snapshot['name']
                for snapshot in await self.middleware.call(
                    'zfs.snapshot.query', [['name', '$', f'@{suffix}']], {'select': ['name']}
                )
            )

        return sorted(recorded - present)

    @private
    async def ensure_no_active_workload_jobs(self):
        """Refuse to race queued or running workload mutations while quiescing."""
        active_jobs = await self.middleware.call(
            'core.get_jobs', [('state', 'in', ['WAITING', 'RUNNING'])]
        )
        active_jobs = [
            active_job for active_job in active_jobs
            if active_job['method'].startswith(WORKLOAD_JOB_PREFIXES)
        ]
        if active_jobs:
            raise CallError(
                'Rollback was not staged because VM or jail jobs are still active: ' +
                ', '.join(
                    f'{active_job["method"]} (job {active_job["id"]}, {active_job["state"].lower()})'
                    for active_job in active_jobs
                ) + '. Wait for them to finish or abort them, then retry.'
            )

    @private
    async def quiesce_workloads(self, job):
        """Synchronously stop workloads that ordinary shutdown handles asynchronously."""
        await self.ensure_no_active_workload_jobs()

        running_vms = await self.middleware.call('vm.query', [('status.state', '=', 'RUNNING')])

        async def stop_vm(vm):
            stop_job = await self.middleware.call('vm.stop', vm['id'], {'force_after_timeout': True})
            await stop_job.wait()
            if stop_job.error:
                raise CallError(f'Failed to stop VM {vm["name"]!r}: {stop_job.error}')

        if running_vms:
            job.set_progress(20, f'Stopping {len(running_vms)} running VM(s)')
            await asyncio_map(stop_vm, running_vms, 16)

        remaining_vms = await self.middleware.call('vm.query', [('status.state', '=', 'RUNNING')])
        if remaining_vms:
            raise CallError(
                'Rollback was not staged because these VMs are still running: ' +
                ', '.join(vm['name'] for vm in remaining_vms)
            )

        if await self.middleware.call('jail.iocage_set_up'):
            job.set_progress(35, 'Stopping active jails')
            await self.middleware.call('jail.stop_on_shutdown')
            remaining_jails = await self.middleware.call('jail.query', [('state', '=', 'up')])
            if remaining_jails:
                raise CallError(
                    'Rollback was not staged because these jails are still running: ' +
                    ', '.join(jail.get('host_hostuuid', str(jail.get('id'))) for jail in remaining_jails)
                )

        # A request can be queued while the workloads above are stopping.  Refuse it
        # before staging the restore rather than let it repopulate an iocage mount.
        await self.ensure_no_active_workload_jobs()

    @private
    async def reserve_shutdown_timeout(self):
        """Apply the rollback shutdown floor and return a changed value for restoration."""
        try:
            result = await run(SYSCTL, '-n', SHUTDOWN_TIMEOUT_SYSCTL, encoding='utf8')
            previous = int(result.stdout.strip())
        except Exception as e:
            raise CallError(f'Unable to read {SHUTDOWN_TIMEOUT_SYSCTL}: {e}')

        if previous >= ROLLBACK_SHUTDOWN_TIMEOUT:
            return None

        try:
            await run(
                SYSCTL, f'{SHUTDOWN_TIMEOUT_SYSCTL}={ROLLBACK_SHUTDOWN_TIMEOUT}', encoding='utf8'
            )
        except Exception as e:
            raise CallError(f'Unable to reserve the rollback shutdown window: {e}')

        return previous

    @private
    async def restore_shutdown_timeout(self, previous):
        """Best-effort restoration when staging or reboot dispatch fails."""
        if previous is None:
            return

        try:
            await run(SYSCTL, f'{SHUTDOWN_TIMEOUT_SYSCTL}={previous}', encoding='utf8')
        except Exception:
            self.logger.warning(
                'Unable to restore %s to %d after rollback staging failed',
                SHUTDOWN_TIMEOUT_SYSCTL, previous, exc_info=True,
            )

    @private
    def stage_restore_plan(self, plan):
        """Atomically stage a root-only restore plan for the shutdown hook."""
        directory = os.path.dirname(RESTORE_PLAN_PATH)
        fd, temporary = tempfile.mkstemp(prefix='.system-rollback-', dir=directory)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'w') as f:
                fd = None
                json.dump(plan, f, sort_keys=True)
                f.write('\n')
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporary, RESTORE_PLAN_PATH)
        finally:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    @accepts()
    @job(lock='system_rollback_mutation')
    async def execute(self, job):
        """
        Restore the captured system dataset and iocage trees, activate the origin
        boot environment, and reboot.

        This job validates the live host and stages the exact recorded targets.  The
        destructive work runs from `ix-system-rollback` late in shutdown, after the
        services holding `.system` and iocage have stopped.  The hook activates the
        origin boot environment only after every dataset was restored successfully.
        """
        for path in (RESTORE_PLAN_PATH, RESTORE_RUNNING_PATH, RESTORE_FAILED_PATH):
            if os.path.exists(path):
                raise CallError(
                    f'A rollback restore state file already exists at {path!r}; '
                    'inspect and resolve that attempt before starting another one.'
                )

        availability = await self.available()
        if not availability['available']:
            raise CallError(f'Rollback is not available: {availability["reason"]}')

        window = await self.config()
        origin = await self.middleware.call('bootenv.query', [['id', '=', window['origin_be']]])
        if not origin:
            # `available()` checked this immediately above.  Keep the execute path
            # fail-closed if the BE disappears in between the two reads.
            raise CallError('Rollback is not available: origin_be_missing')

        boot_pool = await self.middleware.call('boot.pool_name')
        roots = [window['system_dataset']] + self.recorded_iocage_datasets(window)
        snapshots = sorted(
            window['snapshots'],
            key=lambda name: (name.split('@', 1)[0].count('/'), name),
            reverse=True,
        )
        plan = {
            'version': 1,
            'window_id': window['id'],
            'origin_be': window['origin_be'],
            'origin_realname': origin[0]['realname'],
            'origin_dataset': f'{boot_pool}/ROOT/{origin[0]["realname"]}',
            'roots': roots,
            'snapshots': snapshots,
        }

        job.set_progress(10, 'Rollback preconditions passed; quiescing VM and jail workloads')
        await self.quiesce_workloads(job)

        job.set_progress(50, 'Workloads stopped; reserving the shutdown restore window')
        previous_shutdown_timeout = await self.reserve_shutdown_timeout()
        try:
            self.stage_restore_plan(plan)
            await self.middleware.call('system.reboot', {'delay': 3})
        except Exception:
            try:
                os.unlink(RESTORE_PLAN_PATH)
            except FileNotFoundError:
                pass
            await self.restore_shutdown_timeout(previous_shutdown_timeout)
            raise

        job.set_progress(100, 'Restore staged; the system is rebooting into the origin boot environment')
        return True

    @accepts()
    @job(lock='system_rollback_mutation')
    async def remove(self, job):
        """
        Discard the rollback capture: release the keep pin on the origin boot
        environment and destroy the coordinated snapshots.

        This is the operator's end of the persistent return.  The capture holds real
        space (`system.rollback.space`) for as long as it stands, so the decision to
        stop paying for it is deliberately a manual one - the only other thing that
        ends an open capture is a pool feature upgrade, which forfeits it as a side
        effect the upgrade itself already confirmed.

        Idempotent: removing an already-closed window retries any outstanding
        teardown without rewriting its recorded reason, and removing when no window
        exists returns `None`.  There is no undo.
        """
        window = await self.config()
        if window is None:
            job.set_progress(100, 'No captured return exists')
            return None

        job.set_progress(10, 'Closing the captured return')
        if window['closed_reason'] is None:
            window = await self.close('removed')
        else:
            window = await self.cleanup()

        held = await self.space()
        if held and held['cleanup_pending']:
            job.set_progress(100, 'The return is closed; some retained state still needs cleanup')
        else:
            job.set_progress(100, 'The captured return was removed')
        return window

    @accepts()
    async def space(self):
        """
        The space the rollback capture is holding, as far as ZFS accounts for it.

        Returns `None` when no window was ever captured.

        `snapshot_bytes_lower_bound` sums each recorded snapshot's `used` - the bytes
        unique to that snapshot.  It is explicitly a lower bound because blocks shared
        by snapshots in the coordinated set can be retained without being unique to any
        one member.  `origin_be_bytes_estimate` is bootenv's best-effort estimate of the
        space deleting the origin BE would release.  Removing the captured return only
        unpins that BE; it does not delete it, so the two measurements are intentionally
        kept separate and no misleading "bytes freed" total is returned.

        `cleanup_pending` remains true after closure while either recorded snapshots or
        the keep pin still stand.  The UI uses it to offer an idempotent cleanup retry.
        """
        window = await self.config()
        if window is None:
            return None

        recorded = set(window['snapshots'] or [])
        snapshot_count = 0
        snapshot_bytes_lower_bound = 0
        for suffix in {name.split('@', 1)[1] for name in recorded if '@' in name}:
            for snapshot in await self.middleware.call(
                'zfs.snapshot.query', [['name', '$', f'@{suffix}']],
                {'extra': {'properties': ['used']}},
            ):
                if snapshot['name'] not in recorded:
                    continue
                snapshot_count += 1
                snapshot_bytes_lower_bound += int(
                    (snapshot['properties'].get('used') or {}).get('rawvalue') or 0
                )

        origin = await self.middleware.call('bootenv.query', [['id', '=', window['origin_be']]])
        origin_be_pinned = bool(origin and origin[0].get('keep') is True)
        origin_be_bytes_estimate = None
        if origin and origin[0].get('rawspace') is not None:
            origin_be_bytes_estimate = int(origin[0]['rawspace'])

        return {
            'snapshot_count': snapshot_count,
            'snapshot_bytes_lower_bound': snapshot_bytes_lower_bound,
            'origin_be_bytes_estimate': origin_be_bytes_estimate,
            'origin_be_pinned': origin_be_pinned,
            'cleanup_pending': bool(snapshot_count or origin_be_pinned),
        }

    @private
    async def pool_state(self):
        """
        Every pool's GUID and whether its feature flags are already upgraded.

        The boot pool is included deliberately: if 15.0 upgrades its features the 13.3
        loader cannot import it and the BE pin is worth nothing.
        """
        state = {}

        boot_pool = await self.middleware.call('boot.pool_name')
        if boot_pool:
            zpools = await self.middleware.call('zfs.pool.query', [['name', '=', boot_pool]])
            if zpools:
                state[boot_pool] = {
                    'guid': str(zpools[0].get('guid') or ''),
                    'features_upgraded': await self.zfs_pool_is_upgraded(boot_pool),
                }

        for pool in await self.middleware.call('pool.query'):
            state[pool['name']] = {
                'guid': str(pool['guid'] or ''),
                'features_upgraded': await self.middleware.call('pool.is_upgraded', pool['id']),
            }

        return state

    @private
    async def zfs_pool_is_upgraded(self, name):
        """
        `pool.is_upgraded` only takes a `storage.volume` id, which the boot pool does not
        have.  Failing closed (`False`) means a pool we could not read is treated as "not
        upgraded at capture time", so a later upgrade of it still closes the window.
        """
        try:
            return await self.middleware.call('zfs.pool.is_upgraded', name)
        except Exception:
            self.logger.warning('Unable to read feature flags of pool %r', name, exc_info=True)
            return False

    @private
    @accepts(
        Str('arrival_path', null=True, default=None, enum=ARRIVAL_PATHS),
        Int('captured_epoch', null=True, default=None),
    )
    async def capture(self, arrival_path, captured_epoch=None):
        """
        Capture the state that does NOT ride the boot environment, so that activating the
        13.3 boot environment later gives a bootable 13.3 system.

        ORDERING CONSTRAINT - whatever eventually calls this must respect it:

            after   pool.import_on_boot     (middlewared/plugins/pool.py)
            before  sysdataset.setup        (middlewared/plugins/sysdataset.py)

        The constraint is NOT "before alembic".  `/data` is not a dataset, so
        `freenas-v1.db` rides the boot environment; the 15.0 migrations run against the
        15.0 BE's own copy and cannot reach the 13.3 BE's database.  What has to be
        beaten is 15.0 services upgrading `.system` in place.  `.system` is shared by
        every boot environment and does not roll back with the BE, and Samba rewrites its
        tdb/ldb databases into a form 4.19-era binaries cannot read, so the snapshot has
        to exist before `sysdataset.setup` mounts `.system` and the services behind it
        start.

        The lower bound is `pool.import_on_boot` because the system dataset usually lives
        on a data pool (for example `tank/.system`) and is unreachable until the
        data pools are imported.  For the same reason `etc/ix.rc.d/ix-update` cannot host
        this: it runs `BEFORE: middlewared`, when only the boot pool is imported.

        The boot path calls this through `capture_on_boot`, after consuming the durable
        arrival marker left by `ix-update`.

        Idempotent: a second call returns the window the first call recorded and takes no
        further snapshots.  Records nothing at all when there is no boot environment to
        return to, or no reachable system dataset to protect.
        """
        window = await self.config()
        if window is not None:
            self.logger.debug(
                'Rollback window back to %r already captured at %s, not capturing again',
                window['origin_be'], window['captured_at'],
            )
            return window

        origin_be = await self.origin_boot_environment()
        if origin_be is None:
            self.logger.info('No boot environment to return to, not capturing a rollback window')
            return None

        system_dataset = (await self.middleware.call('systemdataset.config'))['basename']
        if not system_dataset:
            # A hardcoded `boot-pool/.system` would "succeed" here and protect nothing,
            # because a stale one of those exists alongside the real system dataset.
            self.logger.warning(
                'System dataset is not available, not capturing a rollback window that would protect nothing'
            )
            return None

        if arrival_path is None:
            arrival_path = await self.detect_arrival_path()

        # Automatic arrivals carry the timestamp recorded by the already-running,
        # NTP-synchronised source system.  The new BE reaches this hook before its
        # own clock is necessarily corrected; using datetime.utcnow() here would
        # record a capture time NTP later steps away from.
        captured_at = (
            datetime.utcfromtimestamp(captured_epoch) if captured_epoch is not None else datetime.utcnow()
        ).replace(microsecond=0)
        snapshot_name = f'{SNAPSHOT_PREFIX}-{captured_at.strftime("%Y%m%d%H%M%S")}'
        roots = [system_dataset] + await self.iocage_datasets()

        pool_state = await self.pool_state()
        snapshots = await self.take_snapshots(roots, snapshot_name)
        try:
            await self.middleware.call('bootenv.set_attribute', origin_be, {'keep': True})
            await self.middleware.call('datastore.insert', DATASTORE, {
                'origin_be': origin_be,
                'arrival_path': arrival_path,
                'captured_at': captured_at,
                'system_dataset': system_dataset,
                'snapshots': snapshots,
                'pool_state': pool_state,
                'closed_reason': None,
            })
        except Exception:
            # Leave nothing half-captured behind: a retry has to be able to lay down one
            # coordinated snapshot set, not find orphans from this attempt.
            await self.destroy_snapshots(snapshots)
            try:
                await self.middleware.call('bootenv.set_attribute', origin_be, {'keep': False})
            except Exception:
                self.logger.warning(
                    'Failed to release the keep pin on boot environment %r', origin_be, exc_info=True
                )
            raise

        self.logger.info(
            'Captured a persistent rollback window back to boot environment %r (%s, %d snapshot(s) of %s)',
            origin_be, arrival_path, len(snapshots), ', '.join(roots),
        )
        return await self.config()

    @private
    async def take_snapshots(self, roots, snapshot_name):
        """
        Snapshot each of `roots` recursively under the single name `snapshot_name`, and
        return the full names of every snapshot that produced.

        `zfs.snapshot.delete` is not recursive, so the descendants have to be recorded
        individually or cleanup would leave them behind.
        """
        created = []
        try:
            for root in roots:
                await self.middleware.call('zfs.snapshot.create', {
                    'dataset': root,
                    'name': snapshot_name,
                    'recursive': True,
                })
                created.append(root)
        except Exception:
            await self.destroy_snapshots(await self.snapshot_names(created, snapshot_name))
            raise

        return await self.snapshot_names(created, snapshot_name)

    @private
    async def snapshot_names(self, roots, snapshot_name):
        """
        Every existing snapshot called `snapshot_name` that sits on one of `roots` or on
        a descendant of one of them.
        """
        if not roots:
            return []

        names = [
            snapshot['name']
            for snapshot in await self.middleware.call(
                'zfs.snapshot.query', [['name', '$', f'@{snapshot_name}']], {'select': ['name']}
            )
        ]

        return sorted(
            name for name in names
            if any(
                name.split('@', 1)[0] == root or name.split('@', 1)[0].startswith(f'{root}/')
                for root in roots
            )
        )

    @private
    async def destroy_snapshots(self, names):
        """
        Destroy `names`, and return the ones still standing afterwards.

        A snapshot that is already gone is not a failure and does not stop the rest from
        being destroyed - the list is checked against what actually exists first, so the
        common "somebody already pruned it" case never even raises.
        """
        if not names:
            return []

        present = set()
        for suffix in {name.split('@', 1)[1] for name in names if '@' in name}:
            present.update(
                snapshot['name']
                for snapshot in await self.middleware.call(
                    'zfs.snapshot.query', [['name', '$', f'@{suffix}']], {'select': ['name']}
                )
            )

        remaining = []
        for name in sorted(names):
            if name not in present:
                continue

            try:
                await self.middleware.call('zfs.snapshot.delete', name)
            except Exception:
                self.logger.warning('Failed to destroy rollback snapshot %r', name, exc_info=True)
                remaining.append(name)

        return remaining

    @private
    @accepts(Str('reason', enum=CLOSED_REASONS))
    async def close(self, reason):
        """
        Close an open window: `pool_upgraded` (the user upgraded a pool's feature
        flags, so 13.3 can no longer boot or import it), `consumed` (the rollback was
        performed) or `removed` (the operator discarded the capture via
        `system.rollback.remove`).

        Only the reason is set here; the teardown itself is `cleanup`'s, which already
        handles "closed_reason set, snapshots still standing" and releases the keep pin
        and destroys the snapshots.  Duplicating that here would be a second copy of the
        one piece of this feature that destroys things.

        Idempotent: closing an already-closed window, or one that does not exist, is a
        no-op that returns the window unchanged.
        """
        window = await self.config()
        if window is None or window['closed_reason'] is not None:
            return window

        await self.middleware.call('datastore.update', DATASTORE, window['id'], {'closed_reason': reason})
        return await self.cleanup()

    @periodic(3600, run_on_start=False)
    @private
    async def cleanup(self):
        """
        Tear down a closed window: release the keep pin on the origin boot environment
        and destroy the snapshots it recorded.  An open capture is persistent and this
        never closes one.

        `pool.import_on_boot` calls this after data pools are visible, and middleware also
        runs it hourly (with `run_on_start=False`, so it cannot mistake unimported
        data-pool snapshots for missing state).  It is safe to run repeatedly: on an open
        or absent window it is a no-op, once a closed window is cleaned up it is a no-op,
        and in between it retries only the snapshots that are still standing.  A single
        snapshot that cannot be destroyed is logged and left recorded; it does not abort
        the rest of the work.
        """
        window = await self.config()
        if window is None:
            return None

        if window['closed_reason'] is None:
            # An open capture is persistent.  Ending it is the operator's call
            # (`remove`) or `pool.upgrade`'s (`close('pool_upgraded')`) - never this.
            return window

        closed_reason = window['closed_reason']

        try:
            origin = await self.middleware.call('bootenv.query', [['id', '=', window['origin_be']]])
            if origin and origin[0].get('keep') is True:
                await self.middleware.call('bootenv.set_attribute', window['origin_be'], {'keep': False})
        except Exception:
            # Retry on the next boot/hourly pass.  This runs independently from snapshot
            # cleanup so a successful snapshot teardown can never suppress a later
            # attempt to release a keep pin that initially failed.
            self.logger.warning(
                'Failed to release the keep pin on boot environment %r', window['origin_be'], exc_info=True
            )

        remaining = await self.destroy_snapshots(window['snapshots'])
        if remaining:
            self.logger.warning(
                '%d rollback snapshot(s) could not be destroyed and are still recorded: %s',
                len(remaining), ', '.join(remaining),
            )

        await self.middleware.call('datastore.update', DATASTORE, window['id'], {
            'snapshots': remaining,
            'closed_reason': closed_reason,
        })
        self.logger.info(
            'Closed the rollback window back to boot environment %r (%s)', window['origin_be'], closed_reason
        )
        return await self.config()
