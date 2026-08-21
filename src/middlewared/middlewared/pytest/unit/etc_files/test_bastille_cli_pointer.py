"""the internal development record: the bastille CLI's pool pointer is rendered from the rc group.

The block of the internal development record survived a reboot through the /conf/base seed (#451) but
not an upgrade, whose new boot environment ships the stock file. Rendering it beside
the rc.conf bastille lines makes it part of the regeneration every boot and every
pool transition already performs. The administrator's own lines are never touched.
"""
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from middlewared.plugins.bastille_ import utils
from middlewared.plugins.bastille_.utils import render_config_pointer
from middlewared.plugins.etc import EtcService, FileShouldNotExist, PyRenderer
from middlewared.service_exception import CallError

FILES_DIR = Path(__file__).parents[3] / 'etc_files'
POINTER = 'local/bastille/bastille.conf'
SAMPLE = '## package sample\nbastille_prefix="/usr/local/bastille"\nbastille_zfs_enable="NO"\n'
HANDWRITTEN = 'bastille_zfs_zpool="handwritten"\n'


class PointerMiddleware:

    def __init__(self, pool='tank'):
        self.config = {'pool': pool, 'enabled': True, 'configuration_valid': True}
        self.calls = []

    def call_sync(self, name, *args):
        self.calls.append((name, args))
        assert name == 'bastille.rc_config'
        assert not args
        return self.config

    async def run_in_thread(self, method, *args):
        return method(*args)


class PointerService:

    def __init__(self, middleware):
        self.middleware = middleware


async def render(middleware):
    return await PyRenderer(PointerService(middleware)).render(str(FILES_DIR / POINTER), None)


@pytest.fixture
def files(tmp_path):
    """The live file and the package sample live under tmp_path; only the sample starts present."""
    live = tmp_path / 'bastille.conf'
    sample = tmp_path / 'bastille.conf.sample'
    sample.write_text(SAMPLE)
    with patch.object(utils, 'BASTILLE_DEFAULT_CONFIG', str(live)), \
            patch.object(utils, 'BASTILLE_SAMPLE_CONFIG', str(sample)):
        yield {'live': live, 'sample': sample}


def test_rc_group_renders_the_pointer_right_after_rc_conf():
    entries = EtcService.GROUPS['rc']
    paths = [entry['path'] for entry in entries]

    assert paths.index('rc.conf') + 1 == paths.index(POINTER)
    entry = entries[paths.index(POINTER)]
    assert entry['type'] == 'py'
    assert entry['platform'] == 'FreeBSD'
    assert os.path.isfile(FILES_DIR / f'{POINTER}.py'), f'{POINTER}.py is missing from etc_files'


async def test_a_configured_pool_is_appended_to_the_administrators_file(files):
    files['live'].write_text(HANDWRITTEN)

    rendered = await render(PointerMiddleware())

    assert rendered == HANDWRITTEN + render_config_pointer('tank')
    assert '    . /mnt/tank/bastille/config/bastille.conf\n' in rendered


async def test_rendering_again_changes_nothing(files):
    files['live'].write_text(HANDWRITTEN + render_config_pointer('tank'))

    assert await render(PointerMiddleware()) == files['live'].read_text()


async def test_a_pool_change_repoints_the_block_in_place(files):
    files['live'].write_text('first="1"\n' + render_config_pointer('tank') + 'last="2"\n')

    rendered = await render(PointerMiddleware(pool='vault'))

    assert rendered == 'first="1"\n' + render_config_pointer('vault') + 'last="2"\n'


async def test_no_configured_pool_swaps_only_our_block_for_the_stop(files):
    files['live'].write_text(HANDWRITTEN + render_config_pointer('tank'))

    assert await render(PointerMiddleware(pool=None)) == HANDWRITTEN + render_config_pointer(None)


async def test_a_fresh_boot_environment_starts_from_the_package_sample(files):
    # The upgrade case: the new BE has the stock file, or none at all yet.
    assert await render(PointerMiddleware()) == SAMPLE + render_config_pointer('tank')


async def test_a_stock_file_with_no_pool_gets_the_stop_after_the_sample(files):
    # the internal development record: the sample alone sends bastille to /usr/local with ZFS off.
    assert await render(PointerMiddleware(pool=None)) == SAMPLE + render_config_pointer(None)


async def test_without_bastille_installed_no_file_is_written(files):
    files['sample'].unlink()

    with pytest.raises(FileShouldNotExist):
        await render(PointerMiddleware())


@pytest.mark.parametrize('kind', ['symlink', 'directory'])
async def test_a_live_file_that_is_not_a_plain_file_is_never_rewritten(files, kind):
    if kind == 'symlink':
        elsewhere = files['live'].parent / 'elsewhere'
        elsewhere.write_text(SAMPLE)
        os.symlink(elsewhere, files['live'])
    else:
        files['live'].mkdir()

    with pytest.raises(CallError, match='not a regular file'):
        await render(PointerMiddleware())


async def test_an_unbalanced_block_is_refused_rather_than_guessed_at(files):
    files['live'].write_text(HANDWRITTEN + utils.CONFIG_POINTER_BEGIN + '\n')

    with pytest.raises(CallError):
        await render(PointerMiddleware())


async def test_the_pool_comes_from_the_same_call_as_the_rc_conf_lines(files):
    middleware = PointerMiddleware()

    await render(middleware)

    assert middleware.calls == [('bastille.rc_config', ())]
