from unittest.mock import AsyncMock, Mock

import pytest

from middlewared.plugins.snmp import SNMPService
from middlewared.service_exception import ValidationErrors


def snmp_service(**config):
    # The factory row: v3 off, but v3_authtype defaults to SHA and v3_password reads back as '' (migrate writes a
    # fresh pwenc secret, so the seeded ciphertext no longer decrypts).
    old = {
        'id': 1,
        'location': '',
        'contact': '',
        'traps': False,
        'v3': False,
        'community': 'public',
        'v3_username': '',
        'v3_authtype': 'SHA',
        'v3_password': '',
        'v3_privproto': None,
        'v3_privpassphrase': '',
        'options': '',
        'loglevel': 3,
        'zilstat': False,
        **config,
    }
    service = SNMPService(Mock())
    service.config = AsyncMock(return_value=old)
    service._update_service = AsyncMock()
    return service


@pytest.mark.asyncio
async def test_partial_update_of_factory_config_with_v3_disabled():
    service = snmp_service()

    await service.do_update({'contact': 'admin@example.com'})

    service._update_service.assert_awaited_once()
    assert service._update_service.await_args.args[1]['contact'] == 'admin@example.com'


@pytest.mark.asyncio
async def test_v3_privproto_without_passphrase_is_ignored_when_v3_disabled():
    service = snmp_service(v3_privproto='AES')

    await service.do_update({'location': 'rack 1'})

    service._update_service.assert_awaited_once()


@pytest.mark.asyncio
async def test_enabling_v3_with_authtype_requires_password():
    service = snmp_service()

    with pytest.raises(ValidationErrors) as ve:
        await service.do_update({'v3': True, 'v3_username': 'monitor'})

    assert [(e.attribute, e.errmsg) for e in ve.value.errors] == [
        ('snmp_update.v3_password', 'This field is required when SNMPv3 auth type is specified'),
    ]
    service._update_service.assert_not_awaited()


@pytest.mark.asyncio
async def test_v3_privproto_requires_passphrase():
    service = snmp_service(v3=True, v3_username='monitor', v3_password='authpass1')

    with pytest.raises(ValidationErrors) as ve:
        await service.do_update({'v3_privproto': 'AES'})

    assert [(e.attribute, e.errmsg) for e in ve.value.errors] == [
        ('snmp_update.v3_privpassphrase', 'This field is required when SNMPv3 private protocol is specified'),
    ]
    service._update_service.assert_not_awaited()


@pytest.mark.asyncio
async def test_v3_with_password_and_passphrase_saves():
    service = snmp_service()

    await service.do_update({
        'v3': True, 'v3_username': 'monitor', 'v3_password': 'authpass1',
        'v3_privproto': 'AES', 'v3_privpassphrase': 'privpass1',
    })

    service._update_service.assert_awaited_once()
