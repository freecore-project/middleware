import importlib.util
from pathlib import Path

import pytest


MIGRATION_PATH = (
    Path(__file__).parents[2]
    / 'alembic/versions/15.0/2026-06-01_00-00_rar2fs_service.py'
)


@pytest.fixture(scope='module')
def rar2fs_migration():
    spec = importlib.util.spec_from_file_location('rar2fs_service_migration', MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('option,expected', [
    ('', 0),
    ('--seek-length=0', 0),
    ('--seek-length=1', 1),
    ('--seek-length 1', 1),
    ('--seek-length=7', 7),
])
def test_parse_rar2fs_command_preserves_explicit_seek_length(rar2fs_migration, option, expected):
    parsed = rar2fs_migration.parse_rar2fs_command(
        f'/usr/local/bin/rar2fs /source /mount {option} -o allow_other'
    )

    assert parsed['seek_length'] == expected


def test_parse_rar2fs_command_preserves_captured_13_3_configuration(rar2fs_migration):
    parsed = rar2fs_migration.parse_rar2fs_command(
        '/usr/local/bin/rar2fs /mnt/z2media/qbittorrent /media '
        '--seek-length=1 -o allow_other'
    )

    assert parsed == {
        'source': '/mnt/z2media/qbittorrent',
        'mountpoint': '/media',
        'seek_length': 1,
        'allow_other': True,
        'extra_options': '',
    }
