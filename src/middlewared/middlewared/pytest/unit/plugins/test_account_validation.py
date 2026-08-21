import ctypes.util
import sys
import types
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from middlewared.service_exception import ValidationErrors

if sys.platform.startswith('freebsd'):
    from middlewared.plugins.account import pw_checkname, validate_sudo_commands
else:
    # account.py needs two things at import time that only a FreeCORE box has: Samba's
    # Python bindings (through the SMB plugin) and FreeBSD's libcrypt. Elsewhere they are
    # stood in for by an empty loadparm and the C library's crypt(3).
    samba3 = types.ModuleType('samba.samba3')
    samba3.param = SimpleNamespace(get_context=lambda: None)
    sys.modules.setdefault('samba', types.ModuleType('samba'))
    sys.modules.setdefault('samba.samba3', samba3)
    find_library = ctypes.util.find_library
    with patch('ctypes.util.find_library', lambda name: find_library('c' if name == 'crypt' else name)):
        from middlewared.plugins.account import pw_checkname, validate_sudo_commands


def checkname(name):
    verrors = ValidationErrors()
    pw_checkname(verrors, 'user_create.username', name)
    return [errmsg for attribute, errmsg, errno in verrors]


@pytest.mark.parametrize('name', ['alice', 'Bob_2', 'a.b-c', 'machine$'])
def test_pw_checkname_accepts_unix_name(name):
    assert checkname(name) == []


# Only U+00E9 and U+4E80 have bit 7 of their code point set.
@pytest.mark.parametrize('char', ['é', 'Ā', '中', '亀'])
def test_pw_checkname_rejects_any_non_ascii_character(char):
    assert checkname(f'user{char}') == [f'name contains invalid characters: {char}']


def test_pw_checkname_lists_each_invalid_character_once():
    assert checkname('é:é:') == ['name contains invalid characters: é, :']


@pytest.mark.parametrize('command', [' ', '\t\n'])
def test_validate_sudo_commands_rejects_blank_command(command):
    verrors = validate_sudo_commands(['/bin/ls', command])
    assert [(attribute, errmsg) for attribute, errmsg, errno in verrors] == [('1', 'Command must not be empty')]
