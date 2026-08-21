# the internal development record: user.query and group.query keep their own copy of the extend path. It left `offset`
# and `select` in the datastore options, so offset was applied twice (SQL, then filter_list) and select trimmed
# the rows before the filters ran (filters on unselected fields matched nothing; get raised MatchNotFound).
import ctypes.util
import sys
import types
from types import SimpleNamespace
from unittest.mock import patch

import pytest

if sys.platform.startswith('freebsd'):
    from middlewared.plugins.account import GroupService, UserService
else:
    # Off a FreeCORE box: an empty Samba loadparm and the C library's crypt(3), as test_account_smb_username_map does.
    samba3 = types.ModuleType('samba.samba3')
    samba3.param = SimpleNamespace(get_context=lambda: None)
    sys.modules.setdefault('samba', types.ModuleType('samba'))
    sys.modules.setdefault('samba.samba3', samba3)
    find_library = ctypes.util.find_library
    with patch('ctypes.util.find_library', lambda name: find_library('c' if name == 'crypt' else name)):
        from middlewared.plugins.account import GroupService, UserService
from middlewared.utils import filter_list

USERS = [{'id': i, 'username': name, 'uid': 1000 + i} for i, name in enumerate(['root', 'daemon', 'kodi', 'zfs'])]
GROUPS = [{'id': i, 'group': name, 'gid': i} for i, name in enumerate(['wheel', 'daemon', 'kmem', 'sys', 'tty'])]


class Middleware:
    """datastore.query honours offset/limit/select the way plugins/datastore/read.py does."""

    def __init__(self, rows):
        self.rows = rows
        self.datastore_options = None

    async def call(self, method, *args):
        assert method == 'datastore.query', method
        _, filters, options = args
        assert filters == []
        self.datastore_options = dict(options)
        rows = [dict(row) for row in self.rows]
        if options.get('offset'):
            rows = rows[options['offset']:]
        if options.get('limit'):
            rows = rows[:options['limit']]
        if options.get('select'):
            rows = [{k: v for k, v in row.items() if k in options['select']} for row in rows]
        return rows

    async def run_in_thread(self, method, *args):
        return method(*args)


def query(cls, rows, filters, options):
    service = object.__new__(cls)
    service.middleware = Middleware(rows)
    query = getattr(cls.query, 'wraps', cls.query)
    return service, query(service, filters, options)


@pytest.mark.asyncio
@pytest.mark.parametrize('cls,rows', [(UserService, USERS), (GroupService, GROUPS)])
async def test_offset_is_applied_once(cls, rows):
    service, result = query(cls, rows, [], {'offset': 2})
    result = await result

    assert [row['id'] for row in result] == [row['id'] for row in rows[2:]]
    assert 'offset' not in service.middleware.datastore_options


@pytest.mark.asyncio
@pytest.mark.parametrize('cls,rows,field,value', [(UserService, USERS, 'username', 'kodi'), (GroupService, GROUPS, 'group', 'kmem')])
async def test_select_does_not_hide_the_filtered_field(cls, rows, field, value):
    service, one = query(cls, rows, [[field, '=', value]], {'select': ['id'], 'get': True})
    assert await one == {'id': 2}

    _, count = query(cls, rows, [[field, '=', value]], {'select': ['id'], 'count': True})
    assert await count == 1
    assert 'select' not in service.middleware.datastore_options


@pytest.mark.asyncio
async def test_options_without_select_or_offset_are_unchanged():
    service, result = query(UserService, USERS, [['uid', '>', 1001]], {'limit': 1})
    assert [row['username'] for row in await result] == ['kodi']
    assert filter_list(USERS, [['uid', '>', 1001]], {'limit': 1})[0]['username'] == 'kodi'
