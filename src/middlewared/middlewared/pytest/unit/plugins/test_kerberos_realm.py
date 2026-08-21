import asyncio
import enum
import sys
import types
from unittest.mock import AsyncMock, Mock

import pytest

from middlewared.service_exception import ValidationErrors
from middlewared.utils import filter_list

if sys.platform.startswith('freebsd'):
    from middlewared.plugins.kerberos import KerberosRealmService
else:
    # kerberos.py imports DSType from the idmap plugin, which needs Samba's bindings; as in
    # test_kerberos.py, a stand-in is used only while the plugin is first imported.
    idmap = types.ModuleType('middlewared.plugins.idmap')
    idmap.DSType = enum.Enum('DSType', 'DS_TYPE_ACTIVEDIRECTORY DS_TYPE_LDAP')
    # Only while the real plugin is not loaded: replacing (and then deleting) a loaded one would make the next
    # import declare its tables a second time (`Table ... is already defined`).
    standin = 'middlewared.plugins.idmap' not in sys.modules
    if standin:
        sys.modules['middlewared.plugins.idmap'] = idmap
    try:
        from middlewared.plugins.kerberos import KerberosRealmService
    finally:
        if standin:
            del sys.modules['middlewared.plugins.idmap']


class Middleware(dict):
    # A minimal stand-in for pytest/unit/middleware.py, which imports asynctest (gone with Python 3.11).

    def __init__(self):
        super().__init__()
        self['failover.licensed'] = Mock(return_value=False)
        self.event_register = Mock()
        self.send_event = Mock()
        self.call_hook = AsyncMock()

    async def call(self, name, *args):
        result = self[name](*args)
        if asyncio.iscoroutine(result):
            result = await result
        return result


# do_update's Patch schema is resolved only when middleware starts, so the tests call the undecorated method.
# Realm names are unique regardless of case: create refused a case variant of an existing realm, but update did not
# check at all, so a rename to 'example.com' next to 'EXAMPLE.COM' was stored, and a rename to the exact name of
# another realm reached the unique index on krb_realm and failed with a raw sqlite IntegrityError.

REALMS = [
    {'id': 1, 'realm': 'EXAMPLE.COM', 'kdc': [], 'admin_server': [], 'kpasswd_server': []},
    {'id': 2, 'realm': 'OTHER.COM', 'kdc': [], 'admin_server': [], 'kpasswd_server': []},
]


def service():
    middleware = Middleware()
    middleware['datastore.insert'] = AsyncMock(return_value=3)
    middleware['datastore.update'] = AsyncMock()
    middleware['etc.generate'] = AsyncMock()
    middleware['service.restart'] = AsyncMock()
    svc = KerberosRealmService(middleware)
    realms = [dict(r) for r in REALMS]
    svc.query = AsyncMock(
        side_effect=lambda filters=None, options=None: filter_list(realms, filters or [], options or {})
    )
    svc._get_instance = AsyncMock(side_effect=lambda id: dict(next((r for r in realms if r['id'] == id), {'id': id})))
    return svc, middleware


@pytest.mark.asyncio
@pytest.mark.parametrize('name', ['EXAMPLE.COM', 'example.com'])
async def test_update_to_the_name_of_another_realm_is_refused(name):
    svc, middleware = service()
    with pytest.raises(ValidationErrors) as ve:
        await KerberosRealmService.do_update.wraps(svc, 2, {'realm': name})
    assert ve.value.errors[0].attribute == 'kerberos_realm_update.kerberos_realm'
    middleware['datastore.update'].assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('data', [{'kdc': ['dc1.example.com']}, {'realm': 'EXAMPLE.COM'}, {'realm': 'example.com'}])
async def test_update_of_a_realm_does_not_collide_with_itself(data):
    svc, middleware = service()
    await KerberosRealmService.do_update.wraps(svc, 1, data)
    middleware['datastore.update'].assert_awaited_once()


@pytest.mark.asyncio
async def test_create_of_a_case_variant_is_refused():
    svc, middleware = service()
    with pytest.raises(ValidationErrors):
        await svc.do_create({'realm': 'other.com'})
    middleware['datastore.insert'].assert_not_awaited()


# Nothing cron runs depends on the realms (crontab and cron.d/middlewared do not read them), so create has no
# reason to restart cron.
@pytest.mark.asyncio
async def test_create_regenerates_kerberos_without_restarting_cron():
    svc, middleware = service()
    await svc.do_create({'realm': 'NEW.COM'})
    middleware['datastore.insert'].assert_awaited_once()
    middleware['etc.generate'].assert_awaited_once_with('kerberos')
    middleware['service.restart'].assert_not_awaited()
