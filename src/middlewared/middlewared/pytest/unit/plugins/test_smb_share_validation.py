import asyncio
import errno
import os
import sys
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

if not sys.platform.startswith('freebsd'):
    # The SMB plugin builds a Samba loadparm context at import time; off-box an empty one stands in.
    samba3 = types.ModuleType('samba.samba3')
    samba3.param = SimpleNamespace(get_context=lambda: None)
    sys.modules.setdefault('samba', types.ModuleType('samba'))
    sys.modules.setdefault('samba.samba3', samba3)

from middlewared.plugins.smb import SharingSMBService  # noqa: E402
from middlewared.plugins.smb_.registry import SharingSMBService as SharingSMBRegistryService  # noqa: E402
from middlewared.service import ValidationErrors  # noqa: E402
from middlewared.service_exception import CallError, ValidationError  # noqa: E402
from middlewared.utils import filter_list  # noqa: E402


class Middleware(dict):
    logger = Mock()
    event_register = Mock()

    async def call(self, name, *args):
        result = self[name](*args)
        if asyncio.iscoroutine(result):
            result = await result
        return result


def share_row(**overrides):
    row = {
        'id': 1, 'purpose': 'DEFAULT_SHARE', 'path': '/mnt/tank/a', 'path_suffix': '', 'home': False,
        'name': 'a', 'comment': '', 'ro': False, 'browsable': True, 'timemachine': False,
        'recyclebin': False, 'guestok': False, 'abe': False, 'hostsallow': [], 'hostsdeny': [],
        'aapl_name_mangling': False, 'acl': True, 'durablehandle': True, 'shadowcopy': True,
        'streams': True, 'fsrvp': False, 'auxsmbconf': '', 'enabled': True, 'vuid': '', 'locked': False,
    }
    row.update(overrides)
    return row


@pytest.fixture
def smb(tmp_path):
    """A sharing.smb whose datastore holds `rows` and whose registry renders through the real
    share_to_smbconf, with the SMB service config held in `state`."""
    m = Middleware()
    svc = SharingSMBService(m)
    reg = SharingSMBRegistryService(m)
    svc.validate_path_field = AsyncMock()  # the /mnt pool check is not under test
    rows = []
    state = {'aapl_extensions': False, 'registered': {}}

    def datastore_query(table, filters=None, options=None):
        if table == 'storage.volume':
            return [{'vol_name': 'tank'}]
        return filter_list(rows, filters, {k: v for k, v in (options or {}).items() if k == 'get'})

    def datastore_insert(table, data, options=None):
        rows.append({**data, 'id': len(rows) + 1})
        return len(rows)

    def datastore_update(table, id_, data, options=None):
        if table == 'services_cifs':
            state['aapl_extensions'] = data['cifs_srv_aapl_extensions']

    async def reg_addshare(data):
        name = 'homes' if data['home'] else data['name']
        if name in state['registered']:
            # what netconf raises when net(8) refuses (source3/utils/net_conf.c)
            raise CallError(f'net conf addshare [{name}] failed with error: ERROR: share {name} already exists.\n')
        state['registered'][name] = await reg.share_to_smbconf(data)

    def acl_is_trivial(path):
        # what filesystem.acl_is_trivial does for a missing path
        if not os.path.exists(path):
            raise CallError(f'Path not found [{path}].', errno.ENOENT)
        return True

    m['datastore.query'] = Mock(side_effect=datastore_query)
    m['datastore.insert'] = Mock(side_effect=datastore_insert)
    m['datastore.update'] = Mock(side_effect=datastore_update)
    m['sharing.smb.query'] = lambda filters=None, options=None: filter_list(rows, filters, options)
    m['sharing.smb.reg_addshare'] = reg_addshare
    m['sharing.smb.strip_comments'] = svc.strip_comments
    m['sharing.afp.query'] = Mock(return_value=[])
    m['sharing.nfs.query'] = Mock(return_value=[])
    m['activedirectory.config'] = Mock(return_value={'enable': False})
    m['smb.config'] = lambda: {'aapl_extensions': state['aapl_extensions']}
    m['filesystem.acl_is_trivial'] = Mock(side_effect=acl_is_trivial)
    m['service.query'] = Mock(return_value={'state': 'RUNNING'})
    for name in ('etc.generate', 'service.reload', 'service.restart', 'fcsearch.schedule_reconfigure'):
        m[name] = AsyncMock(return_value=True)

    return svc, reg, rows, state, tmp_path


@pytest.mark.asyncio
async def test_create_rejects_a_second_home_share(smb):
    svc, reg, rows, state, tmp_path = smb
    rows.append(share_row(id=1, name='home1', path=str(tmp_path), home=True))
    state['registered']['homes'] = {}

    with pytest.raises(ValidationErrors) as ve:
        await svc.do_create({'path': str(tmp_path), 'name': 'home2', 'home': True})

    assert [e.attribute for e in ve.value.errors] == ['sharingsmb_create.home']
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_update_of_the_home_share_keeps_it_home(smb):
    svc, reg, rows, state, tmp_path = smb
    rows.append(share_row(id=1, name='home1', path=str(tmp_path), home=True))
    verrors = ValidationErrors()

    await svc.validate(dict(rows[0]), 'sharingsmb_update', verrors, old=rows[0])

    assert not verrors


@pytest.mark.asyncio
async def test_timemachine_create_registers_the_share_with_fruit(smb):
    svc, reg, rows, state, tmp_path = smb

    await svc.do_create({'path': str(tmp_path), 'name': 'tm', 'timemachine': True})

    assert state['aapl_extensions'] is True
    conf = state['registered']['tm']
    assert 'fruit' in conf['vfs objects']
    assert conf['fruit:metadata'] == 'stream'
    assert conf['fruit:time machine'] == 'yes'


@pytest.mark.asyncio
async def test_create_without_name_takes_the_path_basename(smb):
    svc, reg, rows, state, tmp_path = smb
    (tmp_path / 'media').mkdir()

    await svc.do_create({'path': str(tmp_path / 'media')})

    assert rows[0]['name'] == 'media'
    assert 'media' in state['registered']


@pytest.mark.asyncio
async def test_create_without_acl_on_a_missing_path_is_a_validation_error(smb):
    svc, reg, rows, state, tmp_path = smb

    with pytest.raises(ValidationErrors) as ve:
        await svc.do_create({'path': '/mnt/tank/missing', 'name': 'noacl', 'acl': False})

    assert [e.attribute for e in ve.value.errors] == ['sharingsmb_create.path']
    assert rows == []


@pytest.mark.asyncio
async def test_include_with_spaces_is_not_rendered(smb):
    svc, reg, rows, state, tmp_path = smb

    conf = await reg.share_to_smbconf(share_row(auxsmbconf='include = /tmp/x.conf\ninclude=/tmp/y.conf'))

    assert 'include' not in conf


@pytest.mark.asyncio
async def test_update_of_a_missing_share_names_it(smb):
    svc, reg, rows, state, tmp_path = smb

    with pytest.raises(ValidationError) as ve:
        await SharingSMBService.do_update.wraps(svc, 42, {'comment': 'x'})

    assert ve.value.errno == errno.ENOENT
    assert '42 does not exist' in ve.value.errmsg
