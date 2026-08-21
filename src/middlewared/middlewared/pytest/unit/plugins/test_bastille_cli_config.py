"""the internal development record -- make `bastille` work in a shell without exporting BASTILLE_CONFIG.

The file being managed here is the administrator's, not the package's, so the whole
contract is about touching as little of it as possible: own one delimited block, leave
every other byte alone, and refuse to rewrite anything we cannot parse.
"""

import os
import stat
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

from middlewared.plugins import bastille_freebsd
from middlewared.plugins.bastille_ import utils
from middlewared.plugins.bastille_.utils import apply_config_pointer, render_config_pointer
from middlewared.plugins.bastille_freebsd import BastilleService
from middlewared.service_exception import CallError

SAMPLE = 'bastille_prefix="/usr/local/bastille"\nbastille_zfs_enable="NO"\n'


def test_pointer_sources_the_pool_config_behind_a_readability_guard():
    block = render_config_pointer('tank')

    assert (
        '[ -r /mnt/tank/bastille/config/bastille.conf ] && '
        '. /mnt/tank/bastille/config/bastille.conf\n'
    ) in block
    assert block.startswith(utils.CONFIG_POINTER_BEGIN)
    assert block.endswith(utils.CONFIG_POINTER_END + '\n')


def test_applying_a_pointer_appends_to_an_administrators_file_without_touching_it():
    result = apply_config_pointer(SAMPLE, 'tank')

    assert result.startswith(SAMPLE)
    assert result == SAMPLE + render_config_pointer('tank')


def test_applying_a_pointer_twice_changes_nothing():
    once = apply_config_pointer(SAMPLE, 'tank')

    assert apply_config_pointer(once, 'tank') == once


def test_changing_pool_repoints_the_block_rather_than_adding_one():
    result = apply_config_pointer(apply_config_pointer(SAMPLE, 'tank'), 'fast')

    assert result.count(utils.CONFIG_POINTER_BEGIN) == 1
    assert '/mnt/fast/bastille/config/bastille.conf' in result
    assert 'tank' not in result


def test_a_block_the_administrator_moved_stays_where_they_put_it():
    moved = 'first="1"\n' + render_config_pointer('tank') + 'last="2"\n'

    result = apply_config_pointer(moved, 'fast')

    assert result.startswith('first="1"\n')
    assert result.endswith('last="2"\n')
    assert result.count(utils.CONFIG_POINTER_BEGIN) == 1


def test_duplicate_blocks_left_by_an_earlier_write_collapse_into_one():
    duplicated = SAMPLE + render_config_pointer('tank') + render_config_pointer('tank')

    result = apply_config_pointer(duplicated, 'tank')

    assert result == SAMPLE + render_config_pointer('tank')


def test_removing_the_pointer_leaves_only_the_administrators_lines():
    assert apply_config_pointer(apply_config_pointer(SAMPLE, 'tank'), None) == SAMPLE


def test_removing_a_pointer_that_was_never_there_is_a_no_op():
    assert apply_config_pointer(SAMPLE, None) == SAMPLE


def test_a_file_without_a_trailing_newline_does_not_run_into_the_block():
    result = apply_config_pointer('bastille_zfs_enable="NO"', 'tank')

    assert result == 'bastille_zfs_enable="NO"\n' + render_config_pointer('tank')


@pytest.mark.parametrize('content', [
    utils.CONFIG_POINTER_BEGIN + '\n. /mnt/tank/bastille/config/bastille.conf\n',
    utils.CONFIG_POINTER_END + '\n',
    f'{utils.CONFIG_POINTER_BEGIN}\n{utils.CONFIG_POINTER_BEGIN}\n{utils.CONFIG_POINTER_END}\n',
])
def test_an_unbalanced_block_is_refused_rather_than_guessed_at(content):
    # Rewriting a file we cannot parse could silently discard hand-written settings.
    with pytest.raises(CallError):
        apply_config_pointer(content, 'tank')


def seed_path(tmp_path):
    """The copy /etc/local is rebuilt from at boot (the internal development record)."""
    return tmp_path / 'conf-base' / 'bastille.conf'


def service_with_config(tmp_path, monkeypatch):
    live = tmp_path / 'bastille.conf'
    sample = tmp_path / 'bastille.conf.sample'
    sample.write_text(SAMPLE)
    seed = seed_path(tmp_path)
    seed.parent.mkdir()
    seed.write_text(SAMPLE)
    monkeypatch.setattr(bastille_freebsd, 'BASTILLE_DEFAULT_CONFIG', str(live))
    monkeypatch.setattr(bastille_freebsd, 'BASTILLE_SAMPLE_CONFIG', str(sample))
    monkeypatch.setattr(bastille_freebsd, 'BASTILLE_BASE_CONFIG', str(seed))
    middleware = Mock()
    middleware.call = AsyncMock()
    return BastilleService(middleware), live, sample


def test_a_first_write_starts_from_the_package_sample(tmp_path, monkeypatch):
    service, live, _ = service_with_config(tmp_path, monkeypatch)

    assert service._write_cli_config_pointer('tank') is True

    content = live.read_text()
    assert content == SAMPLE + render_config_pointer('tank')
    assert stat.S_IMODE(os.lstat(live).st_mode) == 0o644


def test_an_existing_file_is_backed_up_once_and_keeps_its_mode(tmp_path, monkeypatch):
    service, live, _ = service_with_config(tmp_path, monkeypatch)
    live.write_text('bastille_zfs_zpool="handwritten"\n')
    os.chmod(live, 0o640)
    backup = Path(f'{live}.freecore-backup')

    service._write_cli_config_pointer('tank')
    assert backup.read_text() == 'bastille_zfs_zpool="handwritten"\n'
    assert stat.S_IMODE(os.lstat(live).st_mode) == 0o640

    # A later repoint must not overwrite the record of what was there originally.
    service._write_cli_config_pointer('fast')
    assert backup.read_text() == 'bastille_zfs_zpool="handwritten"\n'
    assert 'handwritten' in live.read_text()


def test_rewriting_an_unchanged_pointer_reports_no_write(tmp_path, monkeypatch):
    service, live, _ = service_with_config(tmp_path, monkeypatch)
    service._write_cli_config_pointer('tank')
    before = os.lstat(live).st_mtime_ns

    assert service._write_cli_config_pointer('tank') is False
    assert os.lstat(live).st_mtime_ns == before


def test_deconfiguring_removes_only_our_block(tmp_path, monkeypatch):
    service, live, _ = service_with_config(tmp_path, monkeypatch)
    live.write_text('bastille_zfs_zpool="handwritten"\n')
    service._write_cli_config_pointer('tank')

    service._write_cli_config_pointer(None)

    assert live.read_text() == 'bastille_zfs_zpool="handwritten"\n'


@pytest.mark.parametrize('kind', ['symlink', 'directory'])
def test_a_config_that_is_not_a_plain_file_is_never_rewritten(tmp_path, monkeypatch, kind):
    service, live, _ = service_with_config(tmp_path, monkeypatch)
    if kind == 'symlink':
        (tmp_path / 'elsewhere').write_text('elsewhere\n')
        os.symlink(tmp_path / 'elsewhere', live)
    else:
        live.mkdir()

    with pytest.raises(CallError, match='not a regular file'):
        service._write_cli_config_pointer('tank')


def test_removing_a_pointer_needs_neither_the_package_nor_the_file(tmp_path, monkeypatch):
    # deactivate_pool runs while a pool is being exported. Failing there because
    # bastille has since been deinstalled would block the export itself.
    service, live, sample = service_with_config(tmp_path, monkeypatch)
    sample.unlink()
    monkeypatch.setattr(
        bastille_freebsd, 'BASTILLE_DEFAULT_CONFIG', str(tmp_path / 'gone' / 'bastille.conf'),
    )

    assert service._write_cli_config_pointer(None) is False


def test_writing_a_pointer_refuses_when_bastille_is_not_installed(tmp_path, monkeypatch):
    service, _, _ = service_with_config(tmp_path, monkeypatch)
    monkeypatch.setattr(
        bastille_freebsd, 'BASTILLE_DEFAULT_CONFIG', str(tmp_path / 'gone' / 'bastille.conf'),
    )

    with pytest.raises(CallError, match='Bastille is not installed'):
        service._write_cli_config_pointer('tank')


# --- the internal development record: the pointer must outlive a reboot ---------------------------
# /etc is a tmpfs seeded from /conf/base/etc at boot and /usr/local/etc is /etc/local, so a
# block that only reaches the live file is gone on the next boot. The seed mirrors the live
# file, the way ix-savehostid carries /etc/hostid across boots.

def test_the_pointer_is_carried_into_the_boot_seed(tmp_path, monkeypatch):
    service, live, _ = service_with_config(tmp_path, monkeypatch)
    seed = seed_path(tmp_path)

    service._write_cli_config_pointer('tank')

    assert seed.read_text() == live.read_text()
    assert render_config_pointer('tank') in seed.read_text()
    assert stat.S_IMODE(os.lstat(seed).st_mode) == stat.S_IMODE(os.lstat(live).st_mode)


def test_repointing_and_deconfiguring_keep_the_seed_in_step(tmp_path, monkeypatch):
    service, live, _ = service_with_config(tmp_path, monkeypatch)
    seed = seed_path(tmp_path)
    service._write_cli_config_pointer('tank')

    service._write_cli_config_pointer('vault')
    assert seed.read_text() == live.read_text()
    assert render_config_pointer('vault') in seed.read_text()
    assert 'tank' not in seed.read_text()

    service._write_cli_config_pointer(None)
    assert seed.read_text() == live.read_text() == SAMPLE


def test_an_appliance_without_a_seed_directory_gets_only_the_live_file(tmp_path, monkeypatch):
    service, live, _ = service_with_config(tmp_path, monkeypatch)
    monkeypatch.setattr(
        bastille_freebsd, 'BASTILLE_BASE_CONFIG', str(tmp_path / 'no-such-base' / 'bastille.conf'),
    )

    assert service._write_cli_config_pointer('tank') is True

    assert render_config_pointer('tank') in live.read_text()
    assert not (tmp_path / 'no-such-base').exists()


def test_a_rolled_back_first_configuration_strips_only_our_block_from_the_seed(tmp_path, monkeypatch):
    # _restore_failed_configure unlinks a live file that did not exist before the attempt;
    # the seed already carried the block by then and must go back to the administrator's
    # lines alone, not to an empty file.
    service, live, _ = service_with_config(tmp_path, monkeypatch)
    seed = seed_path(tmp_path)
    seed.write_text('bastille_zfs_zpool="handwritten"\n')
    live.write_text('bastille_zfs_zpool="handwritten"\n')
    service._write_cli_config_pointer('tank')
    assert render_config_pointer('tank') in seed.read_text()

    live.unlink()
    service._sync_cli_config_seed()

    assert seed.read_text() == 'bastille_zfs_zpool="handwritten"\n'


def test_an_unchanged_live_pointer_still_reaches_a_stale_seed(tmp_path, monkeypatch):
    # An appliance configured before the seed was kept in step: the live file already
    # carries the block, the seed does not. A repeat configure must not skip the seed
    # just because the live file needs no rewrite.
    service, live, _ = service_with_config(tmp_path, monkeypatch)
    seed = seed_path(tmp_path)
    service._write_cli_config_pointer('tank')
    seed.write_text(SAMPLE)

    assert service._write_cli_config_pointer('tank') is False

    assert seed.read_text() == live.read_text()


# --- the internal development record: the pointer is rendered by the rc group and verified with it --
# An upgrade installs a boot environment with the stock file, which the #451 seed cannot
# help with. The `rc` etc group now renders the block (test_bastille_cli_pointer), and the
# rc postcondition verifies it the way it verifies the rc.conf lines.

def rc_file(tmp_path, pool):
    rc = tmp_path / 'rc.conf.freenas'
    lines = ['bastille_enable="NO"']
    if pool:
        lines += [
            f'bastille_conf="/mnt/{pool}/bastille/config/bastille.conf"',
            f'bastille_env="BASTILLE_CONFIG=/mnt/{pool}/bastille/config/bastille.conf"',
            f'bastille_jailsdir="/mnt/{pool}/bastille/jails"',
            'bastille_startup_delay="0"',
            'bastille_parallel_limit="1"',
        ]
    rc.write_text('\n'.join(lines) + '\n')
    return rc


def rc_config(pool):
    return {'pool': pool, 'startup_delay': 0, 'parallel_limit': 1}


def test_the_rc_postcondition_accepts_a_live_file_carrying_exactly_the_configured_pool(tmp_path, monkeypatch):
    _, live, _ = service_with_config(tmp_path, monkeypatch)
    monkeypatch.setattr(bastille_freebsd, 'RC_CONFIG_PATH', str(rc_file(tmp_path, 'tank')))
    live.write_text('bastille_zfs_zpool="handwritten"\n' + render_config_pointer('tank'))

    BastilleService._validate_generated_rc(rc_config('tank'), False)


@pytest.mark.parametrize('content, pool', [
    (SAMPLE, 'tank'),                                          # block missing
    (SAMPLE + render_config_pointer('vault'), 'tank'),         # block names another pool
    (SAMPLE + render_config_pointer('tank') * 2, 'tank'),      # duplicated block
    (SAMPLE + render_config_pointer('tank'), None),            # block left behind after deconfigure
    (SAMPLE + utils.CONFIG_POINTER_BEGIN + '\n', 'tank'),      # unbalanced markers
])
def test_the_rc_postcondition_rejects_a_pointer_that_does_not_match_the_row(
    tmp_path, monkeypatch, content, pool,
):
    _, live, _ = service_with_config(tmp_path, monkeypatch)
    monkeypatch.setattr(bastille_freebsd, 'RC_CONFIG_PATH', str(rc_file(tmp_path, pool)))
    live.write_text(content)

    with pytest.raises(CallError):
        BastilleService._validate_generated_rc(rc_config(pool), False)


def test_the_rc_postcondition_ignores_a_missing_live_file(tmp_path, monkeypatch):
    # No bastille.conf at all means bastille is not installed; the package capability
    # check reports that on its own, and the rc lines are still verified.
    _, live, _ = service_with_config(tmp_path, monkeypatch)
    monkeypatch.setattr(bastille_freebsd, 'RC_CONFIG_PATH', str(rc_file(tmp_path, 'tank')))
    assert not live.exists()

    BastilleService._validate_generated_rc(rc_config('tank'), False)


def test_the_rc_postcondition_refuses_a_live_file_that_is_not_a_plain_file(tmp_path, monkeypatch):
    _, live, _ = service_with_config(tmp_path, monkeypatch)
    monkeypatch.setattr(bastille_freebsd, 'RC_CONFIG_PATH', str(rc_file(tmp_path, 'tank')))
    live.mkdir()

    with pytest.raises(CallError, match='not a plain file'):
        BastilleService._validate_generated_rc(rc_config('tank'), False)


@pytest.mark.asyncio
async def test_configure_backs_up_the_administrators_file_before_the_rc_group_renders_the_pointer(
    tmp_path, monkeypatch,
):
    # The renderer would otherwise write the block first, and the one-time backup of the
    # untouched file would never be taken.
    service, live, _ = service_with_config(tmp_path, monkeypatch)
    live.write_text('bastille_zfs_zpool="handwritten"\n')
    order = []
    original_write = service._write_cli_config_pointer

    def write_pointer(pool):
        order.append(('pointer', pool))
        return original_write(pool)

    async def generate_rc(config, enabled):
        order.append(('rc', config['pool'], enabled))
        # What the rc group does on the box: the block is rendered for the row.
        live.write_text(apply_config_pointer(live.read_text(), config['pool']))

    monkeypatch.setattr(service, '_write_cli_config_pointer', write_pointer)
    monkeypatch.setattr(service, '_generate_and_validate_rc', generate_rc)
    service._validate_package_capability = Mock()
    service._raw_config = AsyncMock(return_value={
        'id': 1, 'pool': None, 'startup_delay': 0, 'parallel_limit': 1,
    })
    service._service_row = AsyncMock(return_value={'id': 9, 'srv_enable': False})
    service._validate_pool = AsyncMock()
    service._validate_configured_row = AsyncMock(return_value=True)
    service._prepare_switch_target = AsyncMock()
    service.config = AsyncMock(return_value={'pool': 'tank'})
    real_atomic_write = bastille_freebsd.atomic_write

    def atomic_write(path, content, mode=0o600):
        # The pool config lives under /mnt on the box; keep everything else real so the
        # backup and the pointer are written where the fixture redirected them.
        if not str(path).startswith('/mnt/'):
            real_atomic_write(path, content, mode)

    monkeypatch.setattr(bastille_freebsd, 'atomic_write', atomic_write)

    await service.configure(Mock(), {'pool': 'tank', 'startup_delay': 0, 'parallel_limit': 1})

    assert order == [('rc', None, False), ('pointer', 'tank'), ('rc', 'tank', False), ('rc', 'tank', False)]
    assert Path(f'{live}.freecore-backup').read_text() == 'bastille_zfs_zpool="handwritten"\n'
