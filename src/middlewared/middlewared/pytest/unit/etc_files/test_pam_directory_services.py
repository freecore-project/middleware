"""the internal development record: with Active Directory enabled, local accounts meet pam_unix before pam_winbind.

pam_winbind also authenticates local SMB users (winbind serves the box's own user database) and then renames PAM_USER
to MACHINE\\user, which is no unix account, so those users could not log in. The AD block now starts with a sufficient
pam_unix; in su it sits after the wheel check, which that pam_unix must not skip.
"""
from pathlib import Path

import pytest
from mako.lookup import TemplateLookup

PAM_DIR = Path(__file__).parents[3] / 'etc_files/pam.d'
# Every service that includes the directory-service auth block; sudo includes it for LDAP only.
SERVICES = ['ftp', 'ftpd', 'login', 'netatalk', 'samba', 'sshd', 'su', 'sudo']
AD_SERVICES = [s for s in SERVICES if s != 'sudo']
UNIX_FIRST = 'auth\t\tsufficient\tpam_unix.so\t\tno_warn try_first_pass'
WINBIND = 'auth\t\tsufficient\t/usr/local/lib/pam_winbind.so\ttry_first_pass krb5_auth krb5_ccache_type=FILE'
WHEEL = 'auth\t\trequisite\tpam_group.so\t\tno_warn group=wheel root_only ruser'


class PamMiddleware:

    def __init__(self, ad=False, ldap=False, twofactor=False):
        self.configs = {
            'activedirectory.config': {'enable': ad, 'restrict_pam': False, 'verbose_logging': False},
            'ldap.config': {'enable': ldap, 'kerberos_realm': None, 'auxiliary_parameters': ''},
            'nis.config': {'enable': False},
            'auth.twofactor.config': {'enabled': twofactor, 'window': 0, 'services': {'ssh': True, 'console': True}},
        }

    def call_sync(self, name, *args, **kwargs):
        return self.configs[name]


def render(service, **state):
    lookup = TemplateLookup(directories=[str(PAM_DIR)])
    return lookup.get_template(service).render(middleware=PamMiddleware(**state))


def auth_lines(text):
    return [line for line in text.splitlines() if line.startswith('auth')]


@pytest.mark.parametrize('service', AD_SERVICES)
def test_with_ad_a_local_account_meets_pam_unix_before_pam_winbind(service):
    lines = auth_lines(render(service, ad=True))
    assert WINBIND in lines, lines
    assert UNIX_FIRST in lines, lines
    assert lines.index(UNIX_FIRST) == lines.index(WINBIND) - 1, lines


def test_with_ad_sudo_has_no_directory_block():
    lines = auth_lines(render('sudo', ad=True))
    assert WINBIND not in lines and UNIX_FIRST not in lines, lines


def test_with_ad_su_keeps_the_wheel_check_before_the_directory_block():
    lines = auth_lines(render('su', ad=True))
    assert lines.index(WHEEL) < lines.index(UNIX_FIRST) < lines.index(WINBIND), lines


@pytest.mark.parametrize('service', SERVICES)
def test_without_ad_no_pam_unix_line_is_added(service):
    assert UNIX_FIRST not in auth_lines(render(service)), service


@pytest.mark.parametrize('service', SERVICES)
def test_with_ldap_no_pam_unix_line_is_added(service):
    text = render(service, ldap=True)
    assert UNIX_FIRST not in auth_lines(text), service
    assert 'pam_ldap.so' in text, service


def test_with_ldap_su_keeps_its_directory_block_before_the_wheel_check():
    lines = auth_lines(render('su', ldap=True))
    ldap = next(i for i, line in enumerate(lines) if 'pam_ldap.so' in line)
    assert ldap < lines.index(WHEEL), lines


@pytest.mark.parametrize('service', ['sshd', 'login'])
def test_with_two_factor_the_directory_block_stays_out(service):
    lines = auth_lines(render(service, ad=True, twofactor=True))
    assert WINBIND not in lines and UNIX_FIRST not in lines, lines
