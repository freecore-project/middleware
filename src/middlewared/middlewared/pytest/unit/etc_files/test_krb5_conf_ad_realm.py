# the internal development record: an existing realm for the AD domain is rendered once and linked to the AD row by its id.
import enum
import importlib
import sys
import types
from pathlib import Path
from unittest.mock import patch

from mako.template import Template

from middlewared.utils import filter_list

try:
    import middlewared.plugins.kerberos  # noqa: F401
except ModuleNotFoundError as e:
    if e.name != 'tdb':
        raise
    # The template imports the kerberos plugin, which takes only DSType from the idmap plugin; that one needs Samba's
    # tdb bindings. The plugin stays imported so that its models are declared once however often the template renders.
    idmap = types.ModuleType('middlewared.plugins.idmap')
    idmap.DSType = enum.Enum('DSType', 'DS_TYPE_ACTIVEDIRECTORY DS_TYPE_LDAP DS_TYPE_NIS DS_TYPE_FREEIPA')
    with patch.dict(sys.modules, {'middlewared.plugins.idmap': idmap}):
        kerberos = importlib.import_module('middlewared.plugins.kerberos')
    sys.modules.setdefault('middlewared.plugins.kerberos', kerberos)

TEMPLATE = Path(__file__).parents[3] / 'etc_files/krb5.conf'

AD_ROW_ID = 3


class Krb5Middleware:

    def __init__(self, realms, kerberos_realm=None):
        self.realms = realms
        self.ad = {
            'id': AD_ROW_ID, 'enable': True, 'domainname': 'AD.EXAMPLE.COM', 'kerberos_realm': kerberos_realm,
        }
        self.writes = []

    def call_sync(self, name, *args):
        if name == 'activedirectory.config':
            return dict(self.ad)
        if name == 'datastore.query':
            return {'ldap_enable': False, 'ldap_kerberos_realm': None}
        if name == 'kerberos.config':
            return {'appdefaults_aux': '', 'libdefaults_aux': ''}
        if name == 'kerberos.realm.query':
            return [dict(r) for r in filter_list(self.realms, *args)]
        if name == 'datastore.insert':
            self.writes.append((name, *args))
            realm = {'id': max([r['id'] for r in self.realms], default=0) + 1, 'realm': args[1]['krb_realm'],
                     'kdc': [], 'admin_server': [], 'kpasswd_server': []}
            self.realms.append(realm)
            return realm['id']
        if name == 'datastore.update':
            self.writes.append((name, *args))
            return
        raise AssertionError(name)


def render(middleware):
    return Template(filename=str(TEMPLATE)).render(middleware=middleware).splitlines()


def section(lines, name):
    start = lines.index(f'[{name}]') + 1
    end = next((i for i, line in enumerate(lines[start:], start) if line.startswith('[')), len(lines))
    return [line.strip() for line in lines[start:end] if line.strip()]


def realm_ad_example():
    return {'id': 7, 'realm': 'AD.EXAMPLE.COM', 'kdc': ['dc1.ad.example.com'], 'admin_server': [],
            'kpasswd_server': ['dc1.ad.example.com']}


def test_an_existing_realm_for_the_ad_domain_is_written_once():
    middleware = Krb5Middleware([realm_ad_example()])
    lines = render(middleware)

    assert section(lines, 'realms') == [
        'AD.EXAMPLE.COM = {',
        'default_domain = AD.EXAMPLE.COM',
        'kdc = dc1.ad.example.com',
        'kpasswd_server = dc1.ad.example.com',
        '}',
    ]
    assert section(lines, 'domain_realm') == [
        'ad.example.com = AD.EXAMPLE.COM',
        '.ad.example.com = AD.EXAMPLE.COM',
        'AD.EXAMPLE.COM = AD.EXAMPLE.COM',
        '.AD.EXAMPLE.COM = AD.EXAMPLE.COM',
    ]


def test_an_existing_realm_for_the_ad_domain_is_linked_to_the_ad_row_by_its_id():
    middleware = Krb5Middleware([realm_ad_example()])
    render(middleware)

    assert middleware.writes == [
        ('datastore.update', 'directoryservice.activedirectory', AD_ROW_ID, {'ad_kerberos_realm': 7}),
    ]


def test_a_missing_realm_for_the_ad_domain_is_created_once_and_linked_to_the_ad_row_by_its_id():
    middleware = Krb5Middleware([])
    lines = render(middleware)

    assert middleware.writes == [
        ('datastore.insert', 'directoryservice.kerberosrealm', {'krb_realm': 'AD.EXAMPLE.COM'}),
        ('datastore.update', 'directoryservice.activedirectory', AD_ROW_ID, {'ad_kerberos_realm': 1}),
    ]
    assert section(lines, 'realms') == ['AD.EXAMPLE.COM = {', 'default_domain = AD.EXAMPLE.COM', '}']


def test_a_linked_ad_realm_is_rendered_without_database_writes():
    middleware = Krb5Middleware([realm_ad_example()], kerberos_realm=7)
    lines = render(middleware)

    assert middleware.writes == []
    assert section(lines, 'realms').count('AD.EXAMPLE.COM = {') == 1
