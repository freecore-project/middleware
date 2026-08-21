import asyncio
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from middlewared.plugins import activedirectory
from middlewared.plugins.activedirectory import ActiveDirectoryService


class Middleware:
    def __init__(self):
        self.calls = []

    async def call(self, name, *args):
        self.calls.append((name, args))
        if name == 'nfs.config':
            return {'v4_krb': True}
        if name == 'kerberos.keytab.store_samba_keytab':
            return 1
        if name == 'kerberos.keytab.has_nfs_principal':
            return True


def completed(returncode=0, stdout=b'', stderr=b''):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_heimdal_keeps_inherited_add_update_ads(monkeypatch):
    middleware = Middleware()
    service = ActiveDirectoryService(middleware)
    commands = []

    async def run(command, **kwargs):
        commands.append(command)
        return completed()

    monkeypatch.setattr(activedirectory.KRB5, 'platform', lambda: activedirectory.KRB5.HEIMDAL)
    monkeypatch.setattr(activedirectory, 'run', run)

    assert asyncio.run(service.net_keytab_add_update_ads('nfs')) is True
    assert commands == [[
        activedirectory.SMBCmd.NET.value,
        '--use-kerberos', 'required',
        '--use-krb5-ccache', activedirectory.krb5ccache.SYSTEM.value,
        'ads', 'keytab', 'add_update_ads', 'nfs',
    ]]
    assert middleware.calls == [
        ('kerberos.check_ticket', ()),
        ('nfs.config', ()),
    ]


def test_mit_reconciles_spns_and_rebuilds_mixed_keytab(tmp_path, monkeypatch):
    middleware = Middleware()
    service = ActiveDirectoryService(middleware)
    service.get_spn_list = AsyncMock(return_value=[
        'HOST/NAS',
        'HOST/nas.example.test',
        'nfs/NAS',
    ])
    commands = []
    staged_keytab = tmp_path / '.samba.keytab.test'

    async def run(command, **kwargs):
        commands.append(command)
        if command[-3:] == ['ads', 'keytab', 'create']:
            staged_keytab.write_bytes(b'machine-and-nfs-keytab')
        return completed()

    def mkstemp(**kwargs):
        fd = os.open(staged_keytab, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        return fd, str(staged_keytab)

    monkeypatch.setattr(activedirectory.KRB5, 'platform', lambda: activedirectory.KRB5.MIT)
    monkeypatch.setattr(activedirectory, 'run', run)
    monkeypatch.setattr(activedirectory.tempfile, 'mkstemp', mkstemp)

    assert asyncio.run(service.net_keytab_add_update_ads('nfs', {
        'netbiosname': 'NAS',
        'domainname': 'EXAMPLE.TEST',
    })) is True

    setspn = [command for command in commands if 'setspn' in command]
    assert len(setspn) == 1
    assert setspn[0][-4:] == ['ads', 'setspn', 'add', 'nfs/nas.example.test']

    creates = [command for command in commands if command[-3:] == ['ads', 'keytab', 'create']]
    assert len(creates) == 1
    assert any(
        argument.startswith('--option=sync machine password to keytab=')
        for argument in creates[0]
    )
    assert middleware.calls[-3:] == [
        ('kerberos.keytab.store_samba_keytab', (str(staged_keytab),)),
        ('etc.generate', ('kerberos',)),
        ('kerberos.keytab.has_nfs_principal', ()),
    ]
    assert not staged_keytab.exists()


def test_mit_setspn_failure_stops_before_keytab_sync(monkeypatch):
    middleware = Middleware()
    service = ActiveDirectoryService(middleware)
    service.get_spn_list = AsyncMock(return_value=['HOST/NAS'])
    commands = []

    async def run(command, **kwargs):
        commands.append(command)
        return completed(1, stderr=b'LDAP constraint violation')

    monkeypatch.setattr(activedirectory.KRB5, 'platform', lambda: activedirectory.KRB5.MIT)
    monkeypatch.setattr(activedirectory, 'run', run)

    with pytest.raises(Exception, match='LDAP constraint violation'):
        asyncio.run(service.net_keytab_add_update_ads('nfs', {
            'netbiosname': 'NAS',
            'domainname': 'EXAMPLE.TEST',
        }))

    assert len(commands) == 1
    assert 'setspn' in commands[0]
    assert all(name != 'kerberos.keytab.store_samba_keytab' for name, _ in middleware.calls)
