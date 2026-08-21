from unittest.mock import AsyncMock, Mock, patch

import pytest

from middlewared.plugins.ftp import FTPService
from middlewared.service_exception import ValidationErrors

FTP_CONFIG = {
    'passiveportsmin': 0,
    'passiveportsmax': 0,
    'onlyanonymous': False,
    'anonpath': None,
    'tls': False,
    'ssltls_certificate': None,
    'masqaddress': '',
    'tls_opt_no_cert_request': False,
}


@pytest.mark.parametrize('ports,attribute', [
    ({'passiveportsmin': 0, 'passiveportsmax': 50000}, 'ftp_update.passiveportsmin'),
    ({'passiveportsmin': 50000, 'passiveportsmax': 40000}, 'ftp_update.passiveportsmax'),
])
async def test_passive_port_errors_name_a_form_field(ports, attribute):
    with patch.object(FTPService, 'config', AsyncMock(return_value=dict(FTP_CONFIG))):
        with pytest.raises(ValidationErrors) as ve:
            await FTPService(Mock()).do_update(ports)

    assert [e.attribute for e in ve.value.errors] == [attribute]
