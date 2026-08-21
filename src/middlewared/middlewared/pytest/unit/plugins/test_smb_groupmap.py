import sys
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

if not sys.platform.startswith('freebsd'):
    # The SMB plugins need Samba's Python bindings (loadparm, tdb) at import time, which
    # only a FreeCORE box has. Elsewhere they are stood in for by empty modules.
    samba3 = types.ModuleType('samba.samba3')
    samba3.param = SimpleNamespace(get_context=lambda: None)
    sys.modules.setdefault('samba', types.ModuleType('samba'))
    sys.modules.setdefault('samba.samba3', samba3)
    sys.modules.setdefault('tdb', types.ModuleType('tdb'))

from middlewared.plugins.smb_ import groupmap, sid  # noqa: E402

LOCALSID = 'S-1-5-21-1000-2000-3000'
DOMAIN_SID = 'S-1-5-21-7-8-9'
LOCAL_ADMINS = f'{LOCALSID}-512'
LOCAL_GUESTS = f'{LOCALSID}-514'
BUILTIN_USERS = f'{LOCALSID}-200041'
ADMIN_GROUP = f'{LOCALSID}-200050'

GROUPMAP = {
    'localsid': LOCALSID,
    'local_builtins': {544: {'sid': LOCAL_ADMINS}, 546: {'sid': LOCAL_GUESTS}},
    'local': {545: {'sid': BUILTIN_USERS, 'nt_name': 'builtin_users'}},
    'builtins': {},
    'invalid': [],
}


def groupmap_service(ad_state, admin_group, members):
    middleware = Mock()

    async def call_middleware(method, *args):
        return {
            'smb.config': {'admin_group': admin_group},
            'activedirectory.get_state': ad_state,
            'idmap.domain_info': {'SID': DOMAIN_SID},
            'group.get_group_obj': {'gr_gid': 3000},
            'idmap.unixid_to_sid': ADMIN_GROUP,
        }[method]

    middleware.call = AsyncMock(side_effect=call_middleware)
    svc = groupmap.SMBService(middleware)
    svc.groupmap_list = AsyncMock(return_value=GROUPMAP)
    svc.groupmap_listmem = AsyncMock(side_effect=lambda alias: members[alias])
    svc.batch_groupmap = AsyncMock()
    return svc


def changes(payload, key):
    return {x['alias']: sorted(m['sid'] for m in x['members']) for x in payload[key]}


@pytest.mark.asyncio
async def test_standalone_users_alias_keeps_builtin_users_and_gets_no_admins():
    # Every alias already holds exactly what it should, so nothing needs to change.
    svc = groupmap_service('DISABLED', None, {
        'S-1-5-32-544': [LOCAL_ADMINS],
        'S-1-5-32-545': [BUILTIN_USERS],
        'S-1-5-32-546': [LOCAL_GUESTS, f'{LOCALSID}-501'],
    })

    await svc.sync_foreign_groups()

    payload = svc.batch_groupmap.await_args.args[0]
    assert changes(payload, 'ADDMEM') == {}
    assert changes(payload, 'DELMEM') == {}


@pytest.mark.asyncio
async def test_ad_users_alias_is_builtin_users_and_domain_users():
    svc = groupmap_service('HEALTHY', 'smbadmins', {
        'S-1-5-32-544': [],
        'S-1-5-32-545': [],
        'S-1-5-32-546': [],
    })

    await svc.sync_foreign_groups()

    payload = svc.batch_groupmap.await_args.args[0]
    assert changes(payload, 'ADDMEM') == {
        'S-1-5-32-544': sorted([LOCAL_ADMINS, f'{DOMAIN_SID}-512', ADMIN_GROUP]),
        'S-1-5-32-545': sorted([BUILTIN_USERS, f'{DOMAIN_SID}-513']),
        'S-1-5-32-546': sorted([LOCAL_GUESTS, f'{LOCALSID}-501', f'{DOMAIN_SID}-514']),
    }
    assert changes(payload, 'DELMEM') == {}


def sid_service(db_sid, system_sid):
    middleware = Mock()
    middleware.call = AsyncMock(return_value={'cifs_SID': db_sid})
    svc = sid.SMBService(middleware)
    svc.get_system_sid = AsyncMock(return_value=system_sid)
    svc.set_database_sid = AsyncMock()
    return svc


@pytest.mark.asyncio
async def test_fixsid_keeps_database_sid_when_system_sid_is_unavailable():
    svc = sid_service(LOCALSID, None)

    await svc.fixsid()

    svc.set_database_sid.assert_not_awaited()


@pytest.mark.asyncio
async def test_fixsid_stores_a_changed_system_sid():
    svc = sid_service(LOCALSID, DOMAIN_SID)

    await svc.fixsid()

    svc.set_database_sid.assert_awaited_once_with(DOMAIN_SID)
