import os
import stat
import sys
import types
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from middlewared.service_exception import ValidationError

if not sys.platform.startswith('freebsd'):
    # filesystem.py imports the SMB plugin, which needs Samba's Python bindings at import time.
    samba3 = types.ModuleType('samba.samba3')
    samba3.param = SimpleNamespace(get_context=lambda: None)
    sys.modules.setdefault('samba', types.ModuleType('samba'))
    sys.modules.setdefault('samba.samba3', samba3)

from middlewared.plugins import filesystem  # noqa: E402


@pytest.fixture
def service(monkeypatch):
    monkeypatch.setattr(filesystem, 'acl', Mock())
    middleware = Mock()
    middleware.call_sync = Mock(return_value=True)  # filesystem.acl_is_trivial
    svc = filesystem.FilesystemService(middleware)
    svc._common_perm_path_validate = Mock()
    return svc


def mode_of(path):
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.mark.parametrize('recursive', [False, True])
def test_an_empty_mode_is_rejected_before_anything_changes(service, tmp_path, recursive):
    service._winacl = Mock()
    os.chmod(tmp_path, 0o750)

    with pytest.raises(ValidationError) as ve:
        service.setperm(Mock(), {'path': str(tmp_path), 'mode': '000', 'options': {'recursive': recursive}})

    assert ve.value.attribute == 'filesystem.setperm.mode'
    assert mode_of(tmp_path) == 0o750
    filesystem.acl.ACL.assert_not_called()
    service._winacl.assert_not_called()


def test_a_mode_is_applied(service, tmp_path):
    os.chmod(tmp_path, 0o750)

    service.setperm(Mock(), {'path': str(tmp_path), 'mode': '700'})

    assert mode_of(tmp_path) == 0o700
