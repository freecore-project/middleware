import pytest

from middlewared.utils import krb5


@pytest.mark.parametrize('system,release,expected', [
    ('Linux', '6.12.0', krb5.KRB5.MIT),
    ('FreeBSD', '15.0-CURRENT', krb5.KRB5.MIT),
    ('FreeBSD', '14.3-RELEASE', krb5.KRB5.MIT),
    ('FreeBSD', '13.3-RELEASE', krb5.KRB5.HEIMDAL),
    ('FreeBSD', 'unknown', krb5.KRB5.HEIMDAL),
])
def test_platform(system, release, expected, monkeypatch):
    monkeypatch.setattr(krb5.platform, 'system', lambda: system)
    monkeypatch.setattr(krb5.platform, 'release', lambda: release)

    assert krb5.KRB5.platform() == expected
