import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).parents[5]
SHELL = ROOT / 'src/freenas/usr/local/bin/scponly'
PKG_PLIST = ROOT / 'nas_ports/freenas/freenas-files/pkg-plist'
MAKEFILE = ROOT / 'nas_ports/freenas/freenas-files/Makefile'
SFTP_SERVER = '/usr/local/libexec/sftp-server'


@pytest.fixture
def shell(tmp_path):
    """The real shell, with only its sftp-server path pointed at a stub that records its argv."""
    record = tmp_path / 'argv'
    stub = tmp_path / 'sftp-server'
    stub.write_text(f'#!/bin/sh\n: > {record}\nfor a in "$@"; do printf "%s\\n" "$a" >> {record}; done\nexit 0\n')
    stub.chmod(0o755)

    text = SHELL.read_text()
    assert text.count(f'SFTP_SERVER={SFTP_SERVER}\n') == 1
    copy = tmp_path / 'scponly'
    copy.write_text(text.replace(f'SFTP_SERVER={SFTP_SERVER}\n', f'SFTP_SERVER={stub}\n'))
    copy.chmod(0o755)

    def run(*args):
        cp = subprocess.run([str(copy), *args], capture_output=True, text=True, env={}, timeout=10)
        argv = record.read_text().splitlines() if record.exists() else None
        if record.exists():
            record.unlink()
        return cp, argv

    run.stub = str(stub)
    return run


def test_shell_is_executable_and_posix_sh():
    assert os.access(SHELL, os.X_OK)
    assert SHELL.read_text().startswith('#!/bin/sh\n')


@pytest.mark.parametrize('command, expected', [
    ('{stub} -l ERROR -f AUTH', ['-l', 'ERROR', '-f', 'AUTH']),
    ('{stub} -f LOCAL7 -l DEBUG3', ['-f', 'LOCAL7', '-l', 'DEBUG3']),
    ('{stub}', []),
])
def test_sftp_subsystem_runs_sftp_server_with_only_the_logging_options(shell, command, expected):
    cp, argv = shell('-c', command.format(stub=shell.stub))
    assert cp.returncode == 0, cp.stderr
    assert argv == expected


@pytest.mark.parametrize('args', [
    (),                                           # interactive login
    ('-c',),
    ('-c', ''),
    ('-c', 'id'),
    ('-c', '/bin/sh'),
    ('-c', 'scp -t /tmp'),                        # legacy scp protocol
    ('-c', 'rsync --server -vlogDtpre.iLsfxCIvu . /tmp'),
    ('-c', '/bin/sh .ssh/rc'),                    # sshd running ~/.ssh/rc
    ('-c', '{stub} -d /'),                        # other sftp-server options
    ('-c', '{stub} -P open'),
    ('-c', '{stub} -l'),                          # option without value
    ('-c', '{stub} -l ERROR;id'),                 # shell metacharacters
    ('-c', '{stub} -l $(id)'),
    ('-c', '{stub} -l error'),                    # values are upper-case tokens
    ('-c', '{stub}* -l ERROR'),                   # no globbing
    ('-c', '{stub}x'),
    ('-c', '{stub} -l ERROR', 'extra'),
    ('-x', '{stub}'),
])
def test_everything_else_is_refused_without_running_anything(shell, args):
    cp, argv = shell(*(a.format(stub=shell.stub) for a in args))
    assert cp.returncode == 1
    assert argv is None
    assert cp.stderr == 'This account is restricted to SFTP.\n'


def test_shell_is_registered_in_etc_shells_by_the_package():
    lines = PKG_PLIST.read_text().splitlines()
    assert lines.count('@shell /usr/local/bin/scponly') == 1
    assert 'usr/local/bin/scponly' not in lines


def test_generated_plist_leaves_the_shell_to_the_static_entry():
    makefile = MAKEFILE.read_text()
    line = next(line for line in makefile.splitlines() if 'scponly' in line)
    pattern = line.split('"')[1].replace('$$', '$')
    staged = './usr/local/bin/scponly\n./usr/local/bin/scponly.bak\n./usr/local/bin/zarcstat\n'
    cp = subprocess.run(['grep', '-v', pattern], input=staged, capture_output=True, text=True)
    assert cp.stdout == './usr/local/bin/scponly.bak\n./usr/local/bin/zarcstat\n'
