import os
from unittest.mock import patch

import pytest

from middlewared.plugins.reporting.utils import reconcile_hostname_link


HOSTNAME = 'freecore.local'


def assert_desired_link(pwd):
    link = pwd / HOSTNAME
    assert link.is_symlink()
    assert link.resolve() == (pwd / 'localhost').resolve()


def test_create_hostname_link(tmp_path):
    reconcile_hostname_link(str(tmp_path), HOSTNAME)

    assert (tmp_path / 'localhost').is_dir()
    assert_desired_link(tmp_path)


def test_repeated_hostname_link_is_idempotent(tmp_path):
    (tmp_path / 'localhost').mkdir()
    (tmp_path / HOSTNAME).symlink_to(tmp_path / 'localhost', target_is_directory=True)

    reconcile_hostname_link(str(tmp_path), HOSTNAME)

    assert_desired_link(tmp_path)


def test_stale_hostname_link_is_replaced(tmp_path):
    (tmp_path / 'localhost').mkdir()
    stale = tmp_path / 'stale'
    stale.mkdir()
    (tmp_path / HOSTNAME).symlink_to(stale, target_is_directory=True)

    reconcile_hostname_link(str(tmp_path), HOSTNAME)

    assert_desired_link(tmp_path)
    assert not stale.exists()


def test_localhost_backup_is_preserved(tmp_path):
    (tmp_path / 'localhost').mkdir()
    backup = tmp_path / 'localhost.bak.20260813'
    backup.mkdir()

    reconcile_hostname_link(str(tmp_path), HOSTNAME)

    assert backup.is_dir()
    assert_desired_link(tmp_path)


@pytest.mark.parametrize('kind', ['file', 'directory'])
def test_conflicting_entry_is_reconciled(tmp_path, kind):
    (tmp_path / 'localhost').mkdir()
    conflict = tmp_path / HOSTNAME
    if kind == 'file':
        conflict.write_text('stale')
    else:
        conflict.mkdir()
        (conflict / 'stale').write_text('stale')

    reconcile_hostname_link(str(tmp_path), HOSTNAME)

    assert_desired_link(tmp_path)


def test_file_exists_race_accepts_desired_link(tmp_path):
    (tmp_path / 'localhost').mkdir()
    real_symlink = os.symlink

    def raced_symlink(source, destination):
        real_symlink(source, destination)
        raise FileExistsError(destination)

    with patch('middlewared.plugins.reporting.utils.os.symlink', side_effect=raced_symlink):
        reconcile_hostname_link(str(tmp_path), HOSTNAME)

    assert_desired_link(tmp_path)


def test_file_exists_race_does_not_hide_conflict(tmp_path):
    (tmp_path / 'localhost').mkdir()

    def raced_symlink(_source, destination):
        with open(destination, 'w') as conflict:
            conflict.write('unexpected')
        raise FileExistsError(destination)

    with patch('middlewared.plugins.reporting.utils.os.symlink', side_effect=raced_symlink):
        with pytest.raises(FileExistsError):
            reconcile_hostname_link(str(tmp_path), HOSTNAME)
