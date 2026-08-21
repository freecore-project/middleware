import enum
import sys
import types
from unittest.mock import Mock

import pytest

if sys.platform.startswith('freebsd'):
    from middlewared.plugins.kerberos import KerberosService
else:
    # kerberos.py imports DSType from the idmap plugin, which needs Samba's tdb bindings; DSType is
    # only used at runtime. The stand-in is dropped once the plugin is loaded, and the plugin stays
    # loaded so that its models are only declared once.
    idmap = types.ModuleType('middlewared.plugins.idmap')
    idmap.DSType = enum.Enum('DSType', 'DS_TYPE_ACTIVEDIRECTORY DS_TYPE_LDAP')
    # Only while the real plugin is not loaded: replacing (and then deleting) a loaded one would make the next
    # import declare its tables a second time (`Table ... is already defined`).
    standin = 'middlewared.plugins.idmap' not in sys.modules
    if standin:
        sys.modules['middlewared.plugins.idmap'] = idmap
    try:
        from middlewared.plugins.kerberos import KerberosService
    finally:
        if standin:
            del sys.modules['middlewared.plugins.idmap']


@pytest.mark.asyncio
@pytest.mark.parametrize('line', ['forwardable true', '  ticket_lifetime 1d', 'proxiable'])
async def test_an_appdefaults_option_without_equals_is_rejected(line):
    # krb5.conf cannot use such a line, so it must not be stored
    verrors = await KerberosService(Mock())._validate_appdefaults(f'encrypt = true\n{line}')
    assert [e.errmsg for e in verrors.errors] == [
        f'{line.strip()} is an invalid appdefaults parameter. Use the form "name = value".'
    ]


@pytest.mark.asyncio
async def test_appdefaults_blocks_blank_lines_and_other_text_are_still_accepted():
    appdefaults = 'pam = {\n  forwardable = false\n}\n\n# a comment\nforwardable = true'
    verrors = await KerberosService(Mock())._validate_appdefaults(appdefaults)
    assert not verrors
