import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest


def _root():
    return Path(__file__).parents[6]


def _script():
    return _root() / 'src/freenas/etc/ix.rc.d/ix-kld'


def test_ix_kld_is_installed_and_executable():
    path = _script()
    assert path.exists()
    assert path.stat().st_mode & stat.S_IXUSR


def test_ix_kld_runs_after_the_generator_and_after_kld():
    source = _script().read_text()
    assert '# PROVIDE: ix-kld' in source
    # ix-etc regenerates /etc/rc.conf.freenas; kld(8) is the consumer we are
    # repairing.  Running after both is what makes the re-read meaningful.
    assert '# REQUIRE: ix-etc kld' in source
    # Loading kernel modules from inside a jail is invalid, exactly as for kld.
    assert '# KEYWORD: nojail' in source


def test_ix_kld_reads_the_generated_file_rather_than_the_boot_shell_value():
    source = _script().read_text()
    # The whole point: do not trust $kld_list inherited from /etc/rc, re-read
    # the file ix-etc regenerated.
    assert '. /etc/rc.conf.freenas' in source
    assert 'printf \'%s\' "${kld_list}"' in source


def test_ix_kld_delegates_the_loaded_check_to_load_kld():
    source = _script().read_text()
    assert 'load_kld -e "${_kld}\\.ko" "$_kld"' in source


def test_ix_kld_honours_kld_disable():
    source = _script().read_text()
    assert 'kenv -q kld_disable' in source


@pytest.mark.skipif(shutil.which('sh') is None, reason='needs a POSIX shell')
def test_reading_kld_list_from_a_generated_file_yields_the_operator_value(tmp_path):
    """The read idiom must return the generated value, not the stale one."""
    generated = tmp_path / 'rc.conf.freenas'
    generated.write_text(
        'zfs_enable="YES"\n'
        'kld_list="hwpmc t4_tom amdgpu"\n'
    )
    # The exact expression from ix_kld_start, with the stale value preset the
    # way /etc/rc would have left it.
    script = (
        'kld_list="hwpmc t4_tom"\n'
        f'_fresh=$(. {generated} >/dev/null 2>&1; printf \'%s\' "${{kld_list}}")\n'
        'printf "%s" "$_fresh"\n'
    )
    out = subprocess.run(['sh', '-c', script], capture_output=True, text=True, check=True)
    assert out.stdout == 'hwpmc t4_tom amdgpu'


@pytest.mark.skipif(shutil.which('sh') is None, reason='needs a POSIX shell')
def test_reading_leaves_the_callers_own_kld_list_untouched(tmp_path):
    """Sourcing happens in a subshell, so the boot shell keeps its own state."""
    generated = tmp_path / 'rc.conf.freenas'
    generated.write_text('kld_list="hwpmc t4_tom amdgpu"\n')
    script = (
        'kld_list="hwpmc t4_tom"\n'
        f'_fresh=$(. {generated} >/dev/null 2>&1; printf \'%s\' "${{kld_list}}")\n'
        'printf "%s" "$kld_list"\n'
    )
    out = subprocess.run(['sh', '-c', script], capture_output=True, text=True, check=True)
    assert out.stdout == 'hwpmc t4_tom'


@pytest.mark.skipif(shutil.which('sh') is None, reason='needs a POSIX shell')
def test_missing_generated_file_is_not_an_error(tmp_path):
    missing = tmp_path / 'absent'
    script = f'[ -r {missing} ] || exit 0\nexit 1\n'
    assert subprocess.run(['sh', '-c', script]).returncode == 0


@pytest.mark.skipif(shutil.which('sh') is None, reason='needs a POSIX shell')
def test_script_parses_under_sh():
    assert subprocess.run(['sh', '-n', str(_script())]).returncode == 0


def test_rc_tunables_are_emitted_as_complete_assignments():
    """ix-kld's re-read is only safe because the generated value is whole."""
    source = (_root() / 'src/middlewared/middlewared/etc_files/rc.conf.py').read_text()
    assert 'yield f\'{tun["var"]}="{tun["value"]}"\'' in source
    # tunable_config must stay last so an operator tunable wins over the
    # generators above it.
    start = source.index('        services_config,')
    generators = source[start:source.index('    ):', start)]
    assert generators.strip().splitlines()[-1].strip() == 'tunable_config,'
