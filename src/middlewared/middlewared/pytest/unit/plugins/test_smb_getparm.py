import sys
import types
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

if sys.platform.startswith('freebsd'):
    from middlewared.plugins import smb
else:
    # Samba's Python bindings exist only on a FreeCORE box. The SMB plugin just has to
    # import here: the tests stand in their own loadparm for it.
    samba3 = types.ModuleType('samba.samba3')
    samba3.param = SimpleNamespace(get_context=lambda: None)
    sys.modules.setdefault('samba', types.ModuleType('samba'))
    sys.modules.setdefault('samba.samba3', samba3)
    from middlewared.plugins import smb


AD_MEMBER = '[global]\n\tworkgroup = AD\n\trealm = AD.EXAMPLE.COM\n\tregistry shares = yes\n\tinclude = registry\n'
LDAP_MEMBER = (
    '[global]\n\tworkgroup = WORKGROUP\n\tpassdb backend = ldapsam:"ldap://ldap.example.com"\n'
    '\tregistry shares = yes\n\tinclude = registry\n'
)
STANDALONE = '[global]\n\tworkgroup = WORKGROUP\n\tregistry shares = yes\n\tinclude = registry\n'
DEFAULTS = {'realm': '', 'passdb backend': 'tdbsam'}


def parse(text):
    return {
        name.strip().lower(): value.strip()
        for name, sep, value in (line.partition('=') for line in text.splitlines()) if sep
    }


class S3Context:
    """
    samba.samba3.param.get_context(): load() is lp_load_no_reinit(), which leaves the
    process-wide globals as they are instead of resetting them to their defaults first
    (source3/param/loadparm.c, loadparm_s3_init_globals()).
    """
    def __init__(self, files):
        self.files = files
        self.params = dict(DEFAULTS)

    def load(self, path):
        self.params.update(parse(self.files[path]))

    def get(self, name, section=None):
        return self.params.get(name.lower())


@pytest.fixture
def write_smb4_conf():
    files = {}

    class LoadParm:
        """ samba.param.LoadParm(path): a context of its own, built from defaults and the file """
        def __init__(self, path):
            self.params = DEFAULTS | parse(files[path])

        def get(self, name, section=None):
            return self.params.get(name.lower())

    with (
        patch.object(smb, 'LP_CTX', S3Context(files)),
        patch.object(smb, 'LoadParm', LoadParm, create=True),
    ):
        yield lambda text: files.update({smb.SMBPath.GLOBALCONF.platform(): text})


@pytest.mark.parametrize('parm, joined, value, default', [
    # activedirectory.stop regenerates smb4.conf and restarts cifs, which regenerates
    # rc.conf and wsdd.conf from this realm (wsdd_domain).
    ('realm', AD_MEMBER, 'AD.EXAMPLE.COM', ''),
    ('passdb backend', LDAP_MEMBER, 'ldapsam:"ldap://ldap.example.com"', 'tdbsam'),
], ids=['realm', 'passdb backend'])
def test_a_parameter_dropped_from_smb4_conf_reads_as_its_default(write_smb4_conf, parm, joined, value, default):
    svc = smb.SMBService(Mock())

    write_smb4_conf(joined)
    assert svc.getparm(parm, 'GLOBAL') == value

    write_smb4_conf(STANDALONE)
    assert svc.getparm(parm, 'GLOBAL') == default


def test_realm_is_gone_after_leaving_ad_with_samba(tmp_path):
    pytest.importorskip('samba.param')
    conf = tmp_path / 'smb4.conf'
    svc = smb.SMBService(Mock())

    with patch.object(smb.SMBPath, 'platform', lambda self: str(conf)):
        conf.write_text(AD_MEMBER)
        assert svc.getparm('realm', 'GLOBAL') == 'AD.EXAMPLE.COM'

        conf.write_text(STANDALONE)
        assert svc.getparm('realm', 'GLOBAL') == ''
