"""smb.synchronize_passdb skips an SMB user whose stored smbhash is not in smbpasswd format.

A configuration restored without its secret seed decrypts every smbhash to ''. The user then gets
no passdb.tdb entry and cannot log in to SMB; an alert names them instead of only a log line.
"""
import subprocess
import sys
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

if not sys.platform.startswith('freebsd'):
    # The SMB plugin reads Samba's loadparm context at import time; only a FreeCORE box has it.
    samba3 = types.ModuleType('samba.samba3')
    samba3.param = SimpleNamespace(get_context=lambda: None)
    sys.modules.setdefault('samba', types.ModuleType('samba'))
    sys.modules.setdefault('samba.samba3', samba3)

from middlewared.alert.base import AlertClass
from middlewared.plugins.smb_.passdb import SMBService

NT_HASH = '8846F7EAEE8FB117AD06BDD830B7586C'


def user(id, username, smbhash, password_disabled=False):
    return {
        'id': id, 'username': username, 'smbhash': smbhash, 'locked': False,
        'password_disabled': password_disabled,
    }


def smbhash(username, uid):
    return f'{username}:{uid}:{"X" * 32}:{NT_HASH}:[U         ]:LCT-6720B2A1:'


def service(users, fail_alerts=False):
    middleware = Mock()
    calls = []
    svc = SMBService(middleware)
    svc.logger = Mock()

    async def call(method, *args):
        calls.append((method, *args))
        if method == 'smb.getparm':
            return 'tdbsam'
        if method == 'user.query':
            return users
        if method == 'smb.update_passdb_user':
            return await svc.update_passdb_user(*args)
        if method.startswith('alert.'):
            if fail_alerts:
                raise Exception('alert service not ready')
            return
        raise AssertionError((method, args))

    middleware.call = AsyncMock(side_effect=call)
    return svc, calls


async def synchronize(svc, passdb=''):
    pdbedit = []

    async def run(cmd, check=True):
        pdbedit.append(cmd)
        return SimpleNamespace(returncode=0, stdout=passdb.encode() if '-Lw' in cmd else b'', stderr=b'')

    async def popen(cmd, **kwargs):
        pdbedit.append(cmd)
        assert kwargs['stdin'] == subprocess.PIPE
        return SimpleNamespace(communicate=AsyncMock(return_value=(b'', b'')))

    with patch('middlewared.plugins.smb_.passdb.run', run), patch('middlewared.plugins.smb_.passdb.Popen', popen):
        await svc.synchronize_passdb(Mock())
    return pdbedit


def created(pdbedit):
    return [cmd[cmd.index('-a') + 1] for cmd in pdbedit if '-a' in cmd]


@pytest.mark.asyncio
async def test_users_without_a_usable_hash_are_alerted():
    svc, calls = service([
        user(1, 'alice', ''),
        user(2, 'bob', 'bob:1002:XXXX'),
        user(3, 'dave', smbhash('dave', 1004)),
    ])

    pdbedit = await synchronize(svc)

    assert created(pdbedit) == ['dave']
    assert calls[-1] == ('alert.oneshot_create', 'SMBUserMissingHash', {'users': 'alice, bob'})


@pytest.mark.asyncio
async def test_an_existing_entry_is_kept_but_not_updated():
    # Its old NT hash still works, but locking the user in the UI does not reach passdb.tdb.
    alice = user(1, 'alice', '')
    alice['locked'] = True
    svc, calls = service([alice])

    pdbedit = await synchronize(svc, passdb=smbhash('alice', 1001) + '\n')

    assert pdbedit == [['pdbedit', '-d', '0', '-Lw']]
    assert calls[-1] == ('alert.oneshot_create', 'SMBUserMissingHash', {'users': 'alice'})


@pytest.mark.asyncio
async def test_the_alert_is_cleared_once_every_hash_is_usable():
    # A password-disabled user has smbhash '*' by design and is not reported.
    svc, calls = service([user(3, 'dave', smbhash('dave', 1004)), user(4, 'erin', '*', password_disabled=True)])

    pdbedit = await synchronize(svc)

    assert created(pdbedit) == ['dave']
    assert calls[-1] == ('alert.oneshot_delete', 'SMBUserMissingHash', None)


@pytest.mark.asyncio
async def test_an_alert_failure_does_not_stop_the_sync():
    svc, calls = service([user(1, 'alice', ''), user(3, 'dave', smbhash('dave', 1004))], fail_alerts=True)

    pdbedit = await synchronize(svc, passdb=smbhash('mallory', 1005) + '\n')

    assert created(pdbedit) == ['dave']
    assert ('alert.oneshot_create', 'SMBUserMissingHash', {'users': 'alice'}) in calls
    svc.logger.warning.assert_called_with('Unable to update the SMB password hash alert', exc_info=True)
    assert pdbedit[-1] == ['pdbedit', '-d', '0', '-x', 'mallory']


@pytest.mark.asyncio
async def test_there_is_one_alert_naming_the_users():
    klass = AlertClass.class_by_name['SMBUserMissingHash']
    instance = klass(Mock())

    alert = await instance.create({'users': 'alice, bob'})
    later = await instance.create({'users': 'alice'})

    assert alert.key == later.key
    assert klass.format(alert.args) == (
        'SMB users alice, bob have no valid SMB password hash, so their SMB accounts are not created or updated '
        'and they may be unable to log in to SMB shares. '
        'This usually happens when a configuration is restored without its secret seed. '
        'Set the password of each user again, or turn off Samba Authentication for them.'
    )
    assert await instance.delete([alert], None) == []
