#!/usr/local/bin/python3
"""Consume a staged FreeCORE return-to-13.3 plan during late shutdown."""

from datetime import datetime
import json
import os
import sqlite3
import subprocess
import sys
import tempfile


PLAN_PATH = '/data/system-rollback.pending'
RUNNING_PATH = '/data/system-rollback.running'
FAILED_PATH = '/data/system-rollback.failed'
LOG_PATH = '/data/system-rollback.log'
DATABASE_PATH = '/data/freenas-v1.db'

ZFS = '/sbin/zfs'
BECTL = '/sbin/bectl'
MOUNT = '/sbin/mount'
UMOUNT = '/sbin/umount'


class RestoreError(Exception):
    pass


def log(message, path=LOG_PATH):
    line = f'{datetime.utcnow().isoformat(timespec="seconds")}Z {message}'
    print(line, flush=True)
    try:
        with open(path, 'a') as f:
            f.write(f'{line}\n')
    except OSError:
        # The console remains available even if the boot environment cannot be
        # written.  Logging must never hide the original restore error.
        pass


def run_command(argv, check=True):
    process = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and process.returncode:
        detail = process.stderr.strip() or process.stdout.strip() or f'exit {process.returncode}'
        raise RestoreError(f'{" ".join(argv)}: {detail}')
    return process


def atomic_json(path, data):
    directory = os.path.dirname(path)
    fd, temporary = tempfile.mkstemp(prefix='.system-rollback-', dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as f:
            fd = None
            json.dump(data, f, sort_keys=True)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def validate_plan(plan):
    expected = {
        'version': int,
        'window_id': int,
        'origin_be': str,
        'origin_realname': str,
        'origin_dataset': str,
        'roots': list,
        'snapshots': list,
    }
    if not isinstance(plan, dict):
        raise RestoreError('restore plan is not an object')
    for key, type_ in expected.items():
        if not isinstance(plan.get(key), type_):
            raise RestoreError(f'restore plan field {key!r} has the wrong type')

    if plan['version'] != 1 or plan['window_id'] < 1:
        raise RestoreError('restore plan version or window id is invalid')
    if not plan['origin_be'] or not plan['origin_realname'] or not plan['origin_dataset']:
        raise RestoreError('restore plan has no origin boot environment')
    if not plan['roots'] or not plan['snapshots']:
        raise RestoreError('restore plan has no roots or snapshots')

    for value in [
        plan['origin_be'], plan['origin_realname'], plan['origin_dataset'], *plan['roots'], *plan['snapshots'],
    ]:
        if not isinstance(value, str) or not value or value.startswith('-') or any(c in value for c in '\r\n\0'):
            raise RestoreError(f'unsafe restore-plan value: {value!r}')

    if len(plan['roots']) != len(set(plan['roots'])) or len(plan['snapshots']) != len(set(plan['snapshots'])):
        raise RestoreError('restore plan contains duplicate roots or snapshots')

    captured = set()
    suffixes = set()
    for snapshot in plan['snapshots']:
        if snapshot.count('@') != 1:
            raise RestoreError(f'restore plan contains an invalid snapshot name: {snapshot!r}')
        dataset, suffix = snapshot.rsplit('@', 1)
        if not dataset or not suffix:
            raise RestoreError(f'restore plan contains an invalid snapshot name: {snapshot!r}')
        captured.add(dataset)
        suffixes.add(suffix)
    if len(suffixes) != 1 or not next(iter(suffixes)).startswith('freecore-rollback-'):
        raise RestoreError('restore snapshots do not share the coordinated rollback name')

    for root in plan['roots']:
        if root not in captured:
            raise RestoreError(f'restore root {root!r} has no recorded snapshot')
    for dataset in captured:
        if not any(dataset == root or dataset.startswith(f'{root}/') for root in plan['roots']):
            raise RestoreError(f'snapshot dataset {dataset!r} is outside the recorded roots')

    return plan


def dataset_depth(name):
    return name.count('/')


def list_datasets(root, command):
    process = command([ZFS, 'list', '-H', '-r', '-o', 'name', '-t', 'filesystem,volume', root])
    datasets = {line.strip() for line in process.stdout.splitlines() if line.strip()}
    if root not in datasets:
        raise RestoreError(f'restore root {root!r} is no longer present')
    return datasets


def mounted_zfs_datasets(command):
    process = command([MOUNT, '-p'])
    mounted = set()
    for line in process.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[2] == 'zfs':
            mounted.add(fields[0])
    return mounted


def topmost_datasets(datasets):
    return sorted(
        (
            dataset for dataset in datasets
            if not any(dataset.startswith(f'{other}/') for other in datasets if other != dataset)
        ),
        key=lambda dataset: (dataset_depth(dataset), dataset),
        reverse=True,
    )


def mark_consumed(plan, snapshots, database_path, logger):
    try:
        with sqlite3.connect(database_path) as database:
            cursor = database.execute(
                'UPDATE system_rollbackwindow SET closed_reason = ?, snapshots = ? WHERE id = ?',
                ('consumed', json.dumps(snapshots), plan['window_id']),
            )
            if cursor.rowcount != 1:
                raise RestoreError(f'rollback window row {plan["window_id"]} was not found')
    except Exception as e:
        logger(f'WARNING: unable to mark the 15.0 rollback window consumed: {e}')


def execute_plan(plan, command=run_command, database_path=DATABASE_PATH, logger=log):
    plan = validate_plan(plan)
    snapshots = plan['snapshots']
    captured_datasets = {snapshot.rsplit('@', 1)[0] for snapshot in snapshots}

    # Everything is checked before the first destructive command.  In particular,
    # a missing descendant snapshot must not be discovered halfway through restore.
    for snapshot in snapshots:
        process = command([ZFS, 'list', '-H', '-o', 'name', '-t', 'snapshot', snapshot])
        if process.stdout.strip() != snapshot:
            raise RestoreError(f'recorded snapshot {snapshot!r} is no longer present')

    origin = command([BECTL, 'list', '-H'])
    boot_environments = {
        field
        for line in origin.stdout.splitlines()
        for field in (line.split('\t')[0], line.split('\t')[5] if len(line.split('\t')) > 5 else '-')
        if field != '-'
    }
    if plan['origin_be'] not in boot_environments and plan['origin_realname'] not in boot_environments:
        raise RestoreError(f'origin boot environment {plan["origin_be"]!r} is no longer present')

    current_datasets = set()
    for root in plan['roots']:
        current_datasets.update(list_datasets(root, command))
    missing_datasets = captured_datasets - current_datasets
    if missing_datasets:
        raise RestoreError(f'captured datasets are missing: {sorted(missing_datasets)!r}')

    # Recursive snapshots do not remove child datasets created after capture.  Those
    # datasets are exactly the post-upgrade jails/plugins the rollback contract says
    # must disappear, so destroy only the new descendants inside the recorded roots.
    extra_datasets = current_datasets - captured_datasets
    unsafe_ancestors = {
        dataset for dataset in extra_datasets
        if any(captured.startswith(f'{dataset}/') for captured in captured_datasets)
    }
    if unsafe_ancestors:
        raise RestoreError(
            f'uncaptured datasets are parents of captured state: {sorted(unsafe_ancestors)!r}'
        )

    mounted = mounted_zfs_datasets(command)
    for dataset in sorted(current_datasets & mounted, key=lambda name: (dataset_depth(name), name), reverse=True):
        command([UMOUNT, '-f', dataset])

    still_mounted = current_datasets & mounted_zfs_datasets(command)
    if still_mounted:
        raise RestoreError(f'recorded datasets are still mounted: {sorted(still_mounted)!r}')

    for dataset in topmost_datasets(extra_datasets):
        command([ZFS, 'destroy', '-r', dataset])

    for snapshot in sorted(
        snapshots,
        key=lambda name: (dataset_depth(name.rsplit('@', 1)[0]), name),
        reverse=True,
    ):
        command([ZFS, 'rollback', '-r', snapshot])

    # This is deliberately last: a preflight or restore failure leaves the current
    # 15.0 boot environment selected instead of booting 13.3 on a partial restore.
    command([BECTL, 'activate', plan['origin_be']])

    # Everything after activation is cleanup.  None of it is allowed to turn a
    # successfully restored box into a failed shutdown-time transaction.
    mark_consumed(plan, snapshots, database_path, logger)

    remaining = []
    for snapshot in snapshots:
        process = command([ZFS, 'destroy', snapshot], check=False)
        if process.returncode:
            remaining.append(snapshot)
            logger(f'WARNING: unable to destroy consumed rollback snapshot {snapshot!r}: {process.stderr.strip()}')

    for property_ in ('beadm:keep=False', 'bectl:keep=False'):
        process = command([ZFS, 'set', property_, plan['origin_dataset']], check=False)
        if process.returncode:
            logger(
                'WARNING: unable to release the origin boot-environment keep pin '
                f'{property_!r}: {process.stderr.strip()}'
            )

    mark_consumed(plan, remaining, database_path, logger)
    logger(f'restored {len(snapshots)} snapshot(s); activated boot environment {plan["origin_be"]!r}')


def consume_plan(
    plan_path=PLAN_PATH,
    running_path=RUNNING_PATH,
    failed_path=FAILED_PATH,
    log_path=LOG_PATH,
    database_path=DATABASE_PATH,
    command=run_command,
):
    if not os.path.exists(plan_path):
        return False
    if os.path.exists(running_path) or os.path.exists(failed_path):
        raise RestoreError('a previous rollback restore state file already exists')

    os.replace(plan_path, running_path)
    plan = None

    def logger(message):
        log(message, log_path)

    try:
        with open(running_path) as f:
            plan = json.load(f)
        execute_plan(plan, command=command, database_path=database_path, logger=logger)
    except Exception as e:
        failure = dict(plan) if isinstance(plan, dict) else {'version': 1}
        failure.update({
            'failed_at': f'{datetime.utcnow().isoformat(timespec="seconds")}Z',
            'error': str(e),
        })
        atomic_json(failed_path, failure)
        try:
            os.unlink(running_path)
        except FileNotFoundError:
            pass
        logger(f'ROLLBACK RESTORE FAILED; the current boot environment remains selected: {e}')
        raise
    else:
        os.unlink(running_path)
        return True


def main():
    try:
        consume_plan()
    except Exception:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
