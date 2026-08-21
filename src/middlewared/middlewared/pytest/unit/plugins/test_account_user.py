import ctypes.util
import sys
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from middlewared.schema import Schemas, resolve_methods
from middlewared.service_exception import ValidationErrors

if sys.platform.startswith('freebsd'):
    from middlewared.plugins.account import UserService
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
        from middlewared.plugins.account import UserService

# As middlewared does at startup, so that `user.update` is checked against its Patch of `user_create`.
resolve_methods(Schemas(), [UserService.do_create, UserService.do_update])

WHEEL = 1
STAFF = 41


class Datastore:
    """
    The rows `UserService` reads and writes: account.bsdgroupmembership as {row id: (group id, user id)},
    and the inserted account.bsdusers rows.
    """

    def __init__(self, memberships=None, groups=(WHEEL, STAFF)):
        self.memberships = dict(memberships or {})
        self.groups = groups
        self.users = []

    async def call(self, method, *args):
        if method == 'datastore.query' and args[0] == 'account.bsdgroupmembership':
            [(_, _, user)] = args[1]
            return [
                {'id': row, 'group': {'id': group}, 'user': {'id': user}}
                for row, (group, member) in self.memberships.items() if member == user
            ]
        if method == 'datastore.query' and args[0] == 'account.bsdgroups':
            [(_, _, group)] = args[1]
            return [{'id': group, 'bsdgrp_gid': group, 'bsdgrp_group': 'g'}] if group in self.groups else []
        if method == 'datastore.query' and args[0] == 'account.bsdusers':
            return []
        if method == 'datastore.delete' and args[0] == 'account.bsdgroupmembership':
            del self.memberships[args[1]]
            return
        if method == 'datastore.insert' and args[0] == 'account.bsdgroupmembership':
            row = max(self.memberships, default=0) + 1
            self.memberships[row] = (args[1]['group'], args[1]['user'])
            return row
        if method == 'datastore.insert' and args[0] == 'account.bsdusers':
            self.users.append(args[1])
            return 7
        if method == 'group.query':
            [(_, _, group)] = args[0]
            return [{'id': group, 'gid': group, 'group': 'g'}]
        if method in ('filesystem.setperm', 'filesystem.chown', 'service.reload'):
            return
        raise AssertionError((method, args))


def service(datastore):
    middleware = Mock()
    middleware.call = AsyncMock(side_effect=datastore.call)
    return UserService(middleware), middleware


def user_instance(**kwargs):
    return {
        'id': 5, 'uid': 1001, 'username': 'alice', 'home': '/nonexistent', 'builtin': False, 'smb': False,
        'microsoft_account': False, 'group': {'id': STAFF, 'bsdgrp_gid': STAFF, 'bsdgrp_group': 'staff'},
        'groups': [], 'sshpubkey': None, **kwargs,
    }


@pytest.mark.asyncio
async def test_set_groups_leaves_a_wanted_membership_in_place():
    datastore = Datastore({7: (STAFF, 5)})
    svc, middleware = service(datastore)

    await svc._UserService__set_groups(5, [STAFF])

    assert datastore.memberships == {7: (STAFF, 5)}
    assert not [c for c in middleware.call.await_args_list if c.args[0] in ('datastore.delete', 'datastore.insert')]


@pytest.mark.asyncio
async def test_set_groups_drops_a_membership_whose_row_id_is_a_wanted_group_id():
    # Row 41 makes user 5 a member of wheel; the caller asks for group 41 (staff) only.
    datastore = Datastore({STAFF: (WHEEL, 5)})
    svc, middleware = service(datastore)

    await svc._UserService__set_groups(5, [STAFF])

    assert sorted(group for group, user in datastore.memberships.values()) == [STAFF]


@pytest.mark.asyncio
async def test_update_with_an_unknown_primary_group_is_a_validation_error():
    svc, middleware = service(Datastore())
    svc._get_instance = AsyncMock(return_value=user_instance())

    with pytest.raises(ValidationErrors) as ve:
        await svc.do_update(5, {'group': 999})

    assert [e.attribute for e in ve.value.errors] == ['user_update.group']


@pytest.mark.asyncio
async def test_update_of_a_builtin_users_home_mode_is_a_validation_error():
    svc, middleware = service(Datastore())
    svc._get_instance = AsyncMock(return_value=user_instance(uid=0, username='root', builtin=True))

    with pytest.raises(ValidationErrors) as ve:
        await svc.do_update(1, {'home_mode': '700'})

    assert [(e.attribute, e.errmsg) for e in ve.value.errors] == [
        ('user_update.home_mode', 'This attribute cannot be changed'),
    ]


@pytest.mark.asyncio
async def test_sshpubkey_error_for_an_unwritable_home_has_no_stray_quote():
    svc, middleware = service(Datastore())
    svc._get_instance = AsyncMock(return_value=user_instance())

    with pytest.raises(ValidationErrors) as ve:
        await svc.do_update(5, {'sshpubkey': 'ssh-ed25519 AAAA'})

    assert [(e.attribute, e.errmsg) for e in ve.value.errors] == [
        ('user_update.sshpubkey', 'Home directory is not writable, leave this blank'),
    ]


@pytest.mark.asyncio
# uid 0 still means "pick the next one" on create (the internal development record kept `if not data.get('uid')`).
@pytest.mark.parametrize('uid, expected', [(None, 1000), (0, 1000), (1500, 1500)])
async def test_create_owns_the_home_directory_by_the_uid_it_stores(tmp_path, uid, expected):
    datastore = Datastore()
    svc, middleware = service(datastore)
    data = {
        'username': 'alice', 'full_name': 'Alice', 'group': STAFF, 'password_disabled': True, 'smb': False,
        'home': str(tmp_path / 'alice'),
    }
    if uid is not None:
        data['uid'] = uid
    skel = tmp_path / 'skel'
    skel.mkdir()

    with patch.object(UserService, '_UserService__common_validation', AsyncMock()), \
            patch('middlewared.plugins.account.SKEL_PATH', str(skel)):
        await svc.do_create(data)

    [setperm] = [c.args[1] for c in middleware.call.await_args_list if c.args[0] == 'filesystem.setperm']
    assert setperm['uid'] == expected
    assert [user['uid'] for user in datastore.users] == [expected]
