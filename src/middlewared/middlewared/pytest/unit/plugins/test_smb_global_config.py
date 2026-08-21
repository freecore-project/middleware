import sys
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

if not sys.platform.startswith('freebsd'):
    # The SMB plugin loads Samba's Python bindings at import time. Off a FreeCORE box an
    # empty loadparm stands in; the tests that need one install their own.
    samba3 = types.ModuleType('samba.samba3')
    samba3.param = SimpleNamespace(get_context=lambda: None)
    sys.modules.setdefault('samba', types.ModuleType('samba'))
    sys.modules.setdefault('samba.samba3', samba3)

import middlewared.plugins.smb as smb_plugin
from middlewared.plugins.smb import RE_NETBIOSNAME, SharingSMBService, SMBService
from middlewared.plugins.smb_.admin_group import SMBService as SMBAdminGroupService
from middlewared.service_exception import ValidationErrors


class LoadParm:
    """samba.param.LoadParm.dump_a_parameter: an unknown name is a RuntimeError, a known one
    is printed to `file_name`, or to the C stdout when that is empty."""

    def __init__(self, known):
        self.known = known
        self.calls = []

    def dump_a_parameter(self, param_name, section_name=None, file_name=''):
        self.calls.append((param_name, section_name, file_name))
        if param_name not in self.known:
            raise RuntimeError(f'Parameter {param_name} unknown for section {section_name or "global"}')


@pytest.fixture
def lp_ctx(monkeypatch):
    lp = LoadParm({'include', 'log level', 'server string'})
    monkeypatch.setattr(smb_plugin, 'LP_CTX', lp)
    return lp


def sharing_service():
    return SharingSMBService(Mock())


async def smb_update_errors(smb_options):
    sharing = sharing_service()

    async def call(method, *args):
        assert method == 'sharing.smb.validate_aux_params'
        return await sharing.validate_aux_params(*args)

    middleware = Mock()
    middleware.call = AsyncMock(side_effect=call)
    svc = SMBService(middleware)
    svc.unixcharset_choices = AsyncMock(return_value={})
    svc.get_smb_ha_mode = AsyncMock(return_value='STANDALONE')

    verrors = ValidationErrors()
    await svc.validate_smb({
        'smb_options': smb_options, 'unixcharset': '', 'workgroup': 'WORKGROUP', 'netbiosname': 'FREECORE',
        'netbiosname_b': '', 'netbiosalias': [], 'guest': '', 'bindip': [], 'filemask': '', 'dirmask': '',
    }, verrors)
    return list(verrors)


@pytest.mark.asyncio
async def test_a_global_aux_error_is_named_after_the_smb_options_field(lp_ctx):
    errors = await smb_update_errors('include = /tmp/x.conf')

    assert [attr for attr, _, _ in errors] == ['smb_update.smb_options']


@pytest.mark.asyncio
async def test_a_share_aux_error_is_named_after_the_auxsmbconf_field():
    svc = sharing_service()
    svc.home_exists = AsyncMock(return_value=None)
    svc.validate_path_field = AsyncMock()

    verrors = ValidationErrors()
    await svc.validate({
        'home': False, 'path': '/mnt/tank/share', 'name': 'share', 'acl': True, 'path_suffix': '',
        'auxsmbconf': 'include = /tmp/x.conf',
    }, 'sharingsmb_create', verrors)

    assert [attr for attr, _, _ in verrors] == ['sharingsmb_create.auxsmbconf']


@pytest.mark.asyncio
async def test_a_blacklisted_key_is_named_without_its_padding(lp_ctx):
    errors = await smb_update_errors('include  = /tmp/x.conf')

    assert errors[0][1].startswith('include is a blacklisted auxiliary parameter.')


@pytest.mark.asyncio
async def test_a_line_without_a_key_is_a_format_error(lp_ctx):
    errors = await smb_update_errors(' = x')

    assert [msg for _, msg, _ in errors] == ['Auxiliary parameters must be in the format of "key = value":  = x']
    assert lp_ctx.calls == []


@pytest.mark.asyncio
async def test_a_known_global_parameter_is_not_printed_to_stdout(lp_ctx):
    assert await smb_update_errors('log level = 1') == []

    assert lp_ctx.calls == [('log level', 'global', '/dev/null')]


@pytest.mark.asyncio
async def test_an_unknown_global_parameter_is_rejected(lp_ctx):
    errors = await smb_update_errors('no such parameter = 1')

    assert [msg for _, msg, _ in errors] == ['Parameter no such parameter unknown for section global']


@pytest.mark.parametrize('name', ['FREECORE\n', 'FREECORE\r', '', 'A' * 16])
def test_netbios_name_rejects(name):
    assert RE_NETBIOSNAME.match(name) is None


@pytest.mark.parametrize('name', ['FREECORE', 'A' * 15, "a.b-c_d!@#$%^&()'{}~"[:15]])
def test_netbios_name_accepts(name):
    assert RE_NETBIOSNAME.match(name)


@pytest.mark.asyncio
async def test_a_missing_admin_group_is_a_validation_error(monkeypatch):
    def get_uncached_group(groupname):
        # dscache.get_uncached_group -> grp.getgrnam
        raise KeyError(f"getgrnam(): name not found: '{groupname}'")

    async def call(method, *args):
        assert method == 'dscache.get_uncached_group'
        return get_uncached_group(*args)

    middleware = Mock()
    middleware.call = AsyncMock(side_effect=call)

    with pytest.raises(ValidationErrors) as e:
        await SMBAdminGroupService(middleware).add_admin_group('nosuchgroup')

    assert list(e.value) == [('smb_update.admin_group', 'Failed to validate group: nosuchgroup', 22)]


@pytest.mark.asyncio
async def test_a_netbios_rename_waits_for_the_group_mappings():
    old = {
        'netbiosname_local': 'OLD', 'admin_group': None, 'spotlight': False, 'aapl_extensions': False,
        'loglevel': 'MINIMUM', 'workgroup': 'WORKGROUP', 'netbiosname': 'OLD', 'netbiosname_b': '',
        'netbiosalias': [],
    }
    new = dict(old, netbiosname_local='NEW', netbiosname='NEW')
    gm_job = Mock(wait=AsyncMock())
    calls = []

    async def call(method, *args, **kwargs):
        calls.append(method)
        return {
            'activedirectory.get_state': 'DISABLED',
            'smb.get_system_sid': 'S-1-5-21-1-2-3',
            'smb.synchronize_group_mappings': gm_job,
        }.get(method)

    middleware = Mock()
    middleware.call = AsyncMock(side_effect=call)
    svc = SMBService(middleware)
    svc.config = AsyncMock(side_effect=[old, new])
    svc.validate_smb = AsyncMock()
    svc.compress = AsyncMock()
    svc._update_service = AsyncMock()
    svc.reset_smb_ha_mode = AsyncMock()

    result = await SMBService.do_update.wraps(svc, {'netbiosname': 'NEW'})

    assert 'smb.synchronize_group_mappings' in calls
    gm_job.wait.assert_awaited_once_with(raise_error=True)
    assert result['cifs_SID'] == 'S-1-5-21-1-2-3'


@pytest.mark.asyncio
async def test_sync_registry_warning_is_two_sentences(monkeypatch):
    svc = sharing_service()
    svc.logger = Mock()
    monkeypatch.setattr(smb_plugin.os.path, 'exists', lambda path: False)

    await svc.sync_registry(Mock())

    message = svc.logger.warning.call_args.args[0]
    assert 'synchronization. This may indicate' in message
