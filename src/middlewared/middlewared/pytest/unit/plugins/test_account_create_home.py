import ctypes.util
import sys
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call, patch

import pytest

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


GROUP = {'id': 7, 'gid': 1007, 'group': 'alice'}


@pytest.fixture
def service(tmp_path):
    middleware = Mock()

    async def call_middleware(method, *args):
        if method == 'group.query':
            return {
                repr([('group', '=', 'alice')]): [],
                repr([('id', '=', GROUP['id'])]): [GROUP],
            }[repr(args[0])]
        if method == 'group.create_internal':
            return GROUP['id']
        if method == 'datastore.query':
            # user.get_next_uid: no local users yet
            return []
        if method == 'datastore.insert':
            return 42
        if method in ('filesystem.setperm', 'filesystem.chown', 'service.reload'):
            return Mock()
        raise AssertionError((method, args))

    middleware.call = AsyncMock(side_effect=call_middleware)
    svc = UserService(middleware)
    svc._UserService__common_validation = AsyncMock()
    svc._UserService__set_password = AsyncMock()
    svc._UserService__set_groups = AsyncMock()
    svc.sync_smb_username_map = AsyncMock()
    svc.update_sshpubkey = AsyncMock()

    skel = tmp_path / 'skel'
    skel.mkdir()
    with patch('middlewared.plugins.account.SKEL_PATH', str(skel)):
        yield svc, middleware


def create_payload(home, **kwargs):
    return {
        'username': 'alice',
        'full_name': 'Alice',
        'group_create': True,
        'home': str(home),
        'password_disabled': True,
        'smb': False,
        **kwargs,
    }


def inserted_user(middleware):
    return next(c.args[2] for c in middleware.call.await_args_list if c.args[0] == 'datastore.insert')


@pytest.mark.asyncio
async def test_a_new_home_is_owned_by_the_assigned_uid_when_none_is_given(service, tmp_path):
    svc, middleware = service
    home = tmp_path / 'alice'

    assert await svc.do_create(create_payload(home)) == 42

    assert home.is_dir()
    assert call('filesystem.setperm', {
        'path': str(home),
        'mode': '755',
        'uid': 1000,
        'gid': GROUP['gid'],
        'options': {'stripacl': True},
    }) in middleware.call.await_args_list
    assert inserted_user(middleware)['uid'] == 1000


@pytest.mark.asyncio
async def test_an_existing_home_is_chowned_to_the_assigned_uid_when_none_is_given(service, tmp_path):
    svc, middleware = service
    home = tmp_path / 'alice'
    home.mkdir()

    assert await svc.do_create(create_payload(home)) == 42

    assert call('filesystem.chown', {
        'path': str(home),
        'uid': 1000,
        'gid': GROUP['gid'],
    }) in middleware.call.await_args_list
    assert inserted_user(middleware)['uid'] == 1000


@pytest.mark.asyncio
async def test_an_explicit_uid_is_kept(service, tmp_path):
    svc, middleware = service
    home = tmp_path / 'alice'

    assert await svc.do_create(create_payload(home, uid=2000)) == 42

    assert call('filesystem.setperm', {
        'path': str(home),
        'mode': '755',
        'uid': 2000,
        'gid': GROUP['gid'],
        'options': {'stripacl': True},
    }) in middleware.call.await_args_list
    assert inserted_user(middleware)['uid'] == 2000
    assert not any(c.args[0] == 'datastore.query' for c in middleware.call.await_args_list)
