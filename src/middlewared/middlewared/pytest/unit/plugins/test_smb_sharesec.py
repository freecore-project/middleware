"""smb.sharesec names a share the way Samba does.

Samba knows the home share only as [homes]; its sharing.smb row has a name of its own ('homes' is a reserved
row name). setacl ran `sharesec homes --replace` and then looked for a row named 'homes', so editing the home
share ACL changed Samba and failed with a bare MatchNotFound without storing it. _flush_share_info passed the
row's own name to sharesec, which rejects a section it does not know, so the flush stopped at the home share.
getacl (and update, which answered through it) upper-cased the share name that query reports as Samba prints
it, and synchronize_acls indexed the first entry of an ACL that can be empty.
"""
import asyncio
import logging
import sys
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

if not sys.platform.startswith('freebsd'):
    # the SMB plugin builds a loadparm context at import time from Samba's Python bindings,
    # which only a FreeCORE box has; elsewhere an empty one stands in
    samba3 = types.ModuleType('samba.samba3')
    samba3.param = SimpleNamespace(get_context=lambda: None)
    sys.modules.setdefault('samba', types.ModuleType('samba'))
    sys.modules.setdefault('samba.samba3', samba3)

from middlewared.plugins.smb_ import sharesec  # noqa: E402
from middlewared.service_exception import CallError  # noqa: E402
from middlewared.utils import filter_list  # noqa: E402

EVERYONE_FULL = 'S-1-1-0:ALLOWED/0x0/FULL'
ADMINS_FULL = 'S-1-5-32-544:ALLOWED/0x0/FULL'
USERS_READ = 'S-1-5-32-545:ALLOWED/0x0/READ'


class FakeSharesec:
    """sharesec(1) over an in-memory share_info.tdb: section names compare case-insensitively and a section
    that is not in the configuration is refused, as source3/utils/sharesec.c does."""

    def __init__(self, sections):
        self.sections = sections
        self.acls = {s.lower(): [EVERYONE_FULL] for s in sections}

    def view(self, share):
        return 'REVISION:1\nCONTROL:SR|DP\nOWNER:\nGROUP:\n' + ''.join(
            f'ACL:{ace}\n' for ace in self.acls[share.lower()]
        )

    async def run(self, command, check=False):
        _, share, action, args = command
        if action == '--view-all':
            return self.result(''.join(f'[{s}]\n{self.view(s)}\n' for s in self.sections))
        if share.lower() not in self.acls:
            return self.result(returncode=255, stderr=f'Invalid sharename: {share}\n')
        if action == '--view':
            return self.result(self.view(share))
        assert action == '--replace', action
        self.acls[share.lower()] = args.split(',')
        return self.result()

    @staticmethod
    def result(stdout='', returncode=0, stderr=''):
        return SimpleNamespace(returncode=returncode, stdout=stdout.encode(), stderr=stderr.encode())


class Middleware(dict):
    """The calls CRUDService and smb.sharesec make. (pytest/unit/middleware.py needs asynctest, which does not
    import on Python 3.11.)"""

    def __init__(self):
        super().__init__()
        self.call_hook = AsyncMock()
        self.event_register = Mock()
        self.send_event = Mock()
        self.logger = logging.getLogger('middlewared')

    async def _call(self, name, serviceobj, method, args, app=None):
        return await method(*args)

    async def call(self, name, *args):
        result = self[name](*args)
        if asyncio.iscoroutine(result):
            result = await result
        return result


@pytest.fixture
def env(monkeypatch):
    samba = FakeSharesec(['homes', 'media'])
    # datastore rows as datastore.query returns them with the cifs_ prefix stripped; the home row comes first
    rows = [
        {'id': 2, 'name': 'smbhome', 'home': True, 'share_acl': ADMINS_FULL},
        {'id': 1, 'name': 'media', 'home': False, 'share_acl': USERS_READ},
    ]
    monkeypatch.setattr(sharesec, 'run', samba.run)

    middleware = Middleware()
    service = sharesec.ShareSec(middleware)

    def datastore_update(name, id, data):
        assert name == 'sharing.cifs_share'
        next(r for r in rows if r['id'] == id)['share_acl'] = data['cifs_share_acl']

    async def query(filters=None, options=None):
        # ShareSec.query itself, without the query-filters schema it is declared with
        return filter_list(await service._view_all({'resolve_sids': True}), filters, options)

    middleware['datastore.query'] = lambda name, filters, options: [dict(r) for r in rows]
    middleware['datastore.update'] = datastore_update
    middleware['sharing.smb.query'] = lambda filters, options=None: filter_list(rows, filters, options)
    middleware['idmap.sid_to_name'] = AsyncMock(side_effect=CallError('winbindd is not running'))
    middleware['smb.sharesec.query'] = query
    middleware['smb.sharesec._view_all'] = service._view_all
    return SimpleNamespace(service=service, middleware=middleware, samba=samba, rows=rows)


async def test_update_stores_the_home_share_acl_on_the_home_row(env):
    # what the web UI does: find the share as 'homes' in query, then update it by id
    home = await env.middleware.call('smb.sharesec.query', [('share_name', '=', 'homes')], {'get': True})
    acl = [{'ae_who_sid': 'S-1-5-32-544', 'ae_perm': 'CHANGE', 'ae_type': 'ALLOWED'}]

    await env.service.update(None, home['id'], {'share_acl': acl})

    assert env.samba.acls['homes'] == ['S-1-5-32-544:ALLOWED/0x0/CHANGE']
    assert env.rows[0]['share_acl'] == 'S-1-5-32-544:ALLOWED/0x0/CHANGE'


async def test_a_share_without_a_row_is_refused_before_samba_is_changed(env):
    # Samba matches 'MEDIA' to [media]; the configuration has no row of that name
    with pytest.raises(CallError, match='MEDIA: share does not exist'):
        await env.service.setacl({'share_name': 'MEDIA', 'share_acl': [
            {'ae_who_sid': 'S-1-5-32-544', 'ae_perm': 'READ', 'ae_type': 'ALLOWED'}
        ]})

    assert env.samba.acls['media'] == [EVERYONE_FULL]


async def test_flush_writes_the_home_share_acl_under_homes(env):
    await env.service._flush_share_info()

    assert env.samba.acls == {'homes': [ADMINS_FULL], 'media': [USERS_READ]}


async def test_getacl_and_update_answer_the_name_query_answers(env):
    media = await env.middleware.call('smb.sharesec.query', [('share_name', '=', 'media')], {'get': True})

    assert (await env.service.getacl('media'))['share_name'] == 'media'

    acl = [{'ae_who_sid': 'S-1-5-32-545', 'ae_perm': 'CHANGE', 'ae_type': 'ALLOWED'}]
    updated = await env.service.update(None, media['id'], {'share_acl': acl})

    assert updated == {
        'share_name': 'media', 'id': media['id'],
        'share_acl': [{'ae_who_sid': 'S-1-5-32-545', 'ae_type': 'ALLOWED', 'ae_perm': 'CHANGE'}],
    }
    env.middleware.send_event.assert_called_once_with(
        'smb.sharesec.query', 'CHANGED', id=media['id'], fields=updated
    )


async def test_synchronize_acls_takes_an_empty_share_acl_as_set(env):
    # a share whose permissions were all removed (e.g. from Windows) has a DACL without entries
    env.samba.acls['media'] = []

    await env.service.synchronize_acls()

    assert env.samba.acls == {'homes': [EVERYONE_FULL], 'media': []}
    assert env.rows[1]['share_acl'] == ''
