import ast
import ctypes.util
import inspect
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


def service(cifs_started):
    middleware = Mock()

    async def call_middleware(method, *args):
        if method == 'service.started':
            assert args == ('cifs',)
            return cifs_started
        if method == 'service.reload':
            assert args == ('cifs',)
            return True
        raise AssertionError((method, args))

    middleware.call = AsyncMock(side_effect=call_middleware)
    return UserService(middleware), middleware


@pytest.mark.asyncio
@pytest.mark.parametrize('before, after', [(False, True), (True, False)])
async def test_a_flag_change_reloads_running_smb(before, after):
    svc, middleware = service(cifs_started=True)

    await svc.sync_smb_username_map(before, after)

    assert middleware.call.await_args_list == [call('service.started', 'cifs'), call('service.reload', 'cifs')]


@pytest.mark.asyncio
@pytest.mark.parametrize('before, after', [(False, True), (True, False)])
async def test_a_flag_change_leaves_stopped_smb_stopped(before, after):
    svc, middleware = service(cifs_started=False)

    await svc.sync_smb_username_map(before, after)

    assert middleware.call.await_args_list == [call('service.started', 'cifs')]


@pytest.mark.asyncio
@pytest.mark.parametrize('before, after', [(False, False), (True, True), (None, False)])
async def test_an_unchanged_flag_touches_nothing(before, after):
    svc, middleware = service(cifs_started=True)

    await svc.sync_smb_username_map(before, after)

    middleware.call.assert_not_awaited()


def method_source(name):
    # The schema decorators wrap these methods, so read their bodies from the module.
    module_source = inspect.getsource(sys.modules[UserService.__module__])
    service = next(
        node for node in ast.parse(module_source).body
        if isinstance(node, ast.ClassDef) and node.name == 'UserService'
    )
    method = next(
        node for node in service.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == name
    )
    return ast.get_source_segment(module_source, method)


@pytest.mark.parametrize('method', ['do_create', 'do_update', 'do_delete'])
def test_every_user_change_syncs_smb_after_rendering_the_map_file(method):
    source = method_source(method)
    reload_user = source.rindex("call('service.reload', 'user')")

    assert source.count('self.sync_smb_username_map(') == 1
    assert source.index('self.sync_smb_username_map(') > reload_user
