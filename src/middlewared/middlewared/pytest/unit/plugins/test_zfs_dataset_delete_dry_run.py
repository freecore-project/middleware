# the internal development record (15.0 has no test_zfs.py): zfs.dataset.delete's private dry_run runs only `zfs destroy -n`.
import subprocess
import sys
import types
from types import SimpleNamespace
from unittest.mock import Mock, patch

try:
    import libzfs  # noqa: F401
except ModuleNotFoundError:
    sys.modules['libzfs'] = types.ModuleType('libzfs')

from middlewared.plugins.zfs import ZFSDatasetService


def run_recorder():
    calls = []

    def run(args, **kwargs):
        calls.append(list(args))
        return SimpleNamespace(returncode=0, stdout='', stderr='')
    return calls, run


def test_dry_run_adds_n_and_skips_the_receive_abort():
    calls, run = run_recorder()
    with patch('middlewared.plugins.zfs.subprocess.run', side_effect=run):
        ZFSDatasetService(Mock()).do_delete('tank/work', {'force': True, 'recursive': True, 'dry_run': True})
    assert calls == [['zfs', 'destroy', '-f', '-r', '-n', 'tank/work']]


def test_a_real_delete_still_aborts_a_resumable_receive_first():
    calls, run = run_recorder()
    with patch('middlewared.plugins.zfs.subprocess.run', side_effect=run):
        ZFSDatasetService(Mock()).do_delete('tank/work', {'recursive': True})
    assert calls == [['zfs', 'recv', '-A', 'tank/work'], ['zfs', 'destroy', '-r', 'tank/work']]


def test_a_dry_run_refusal_is_raised():
    def run(args, **kwargs):
        if args[:2] == ['zfs', 'destroy']:
            raise subprocess.CalledProcessError(1, args, stderr="cannot destroy 'tank/work': filesystem has children")
        return SimpleNamespace(returncode=0)
    with patch('middlewared.plugins.zfs.subprocess.run', side_effect=run):
        try:
            ZFSDatasetService(Mock()).do_delete('tank/work', {'dry_run': True})
        except Exception as e:
            assert 'filesystem has children' in str(e)
        else:
            raise AssertionError('the refusal must be raised')
