"""the internal development record: the ENOTSUP of an NFSv4 ACL write names acltype=posix and the fix."""
import sys
import types

try:
    import libzfs  # noqa: F401
except ModuleNotFoundError:
    # The off-box harness has no py-libzfs; nothing here enters it. Same guard as test_pool_dataset_delete.py.
    sys.modules['libzfs'] = types.ModuleType('libzfs')

from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

import pytest

try:
    from samba.samba3 import param  # noqa: F401
except ImportError:
    # plugins.smb (imported by plugins.filesystem) calls samba's param.get_context() at import; the
    # off-box harness has no samba python. Same shape as the libzfs guard above.
    _samba = types.ModuleType('samba')
    _samba3 = types.ModuleType('samba.samba3')
    _samba3.param = MagicMock()
    _samba.samba3 = _samba3
    sys.modules['samba'] = _samba
    sys.modules['samba.samba3'] = _samba3

from middlewared.plugins.filesystem import FilesystemService

PATH = '/mnt/vknstrt9/fileshare'


def message(acltype, returncode=0, raises=None):
    service = FilesystemService(Mock())
    run = Mock(side_effect=raises) if raises else Mock(
        return_value=SimpleNamespace(returncode=returncode, stdout=f'{acltype}\n', stderr='')
    )
    with patch('middlewared.plugins.filesystem.subprocess.run', run):
        text = service.nfs4_unsupported_message(PATH)
    return text, run


def test_a_posix_dataset_names_the_cause_and_the_fix():
    text, run = message('posix')

    assert run.call_args.args[0] == ['zfs', 'get', '-H', '-o', 'value', 'acltype', PATH]
    assert text.startswith(f'NFSv4 ACLS are not supported on path {PATH}: the dataset has acltype=posix')
    assert '"zfs set acltype=nfsv4 <dataset>"' in text


@pytest.mark.parametrize('acltype', ['nfsv4', 'off'])
def test_any_other_acltype_keeps_the_bare_message(acltype):
    text, _ = message(acltype)

    assert text == f'NFSv4 ACLS are not supported on path {PATH}'


def test_a_failing_zfs_get_keeps_the_bare_message():
    assert message('', returncode=1)[0] == f'NFSv4 ACLS are not supported on path {PATH}'
    assert message('', raises=FileNotFoundError('zfs'))[0] == f'NFSv4 ACLS are not supported on path {PATH}'
