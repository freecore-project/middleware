"""pool.dataset.create share_type, pool.dataset.permission and filesystem.setacl input errors are validation errors.

- `share_type: SMB` on a VOLUME set casesensitivity and aclmode after the VOLUME check had run, so libzfs refused
  the create ("'aclmode' does not apply to datasets of this type").
- pool.dataset.permission filed two errors under `pool_dataset_permissions.*`, reported a missing user or group as
  `str(KeyError)` ("\"getpwnam(): name not found: 'x'\"", "'pw_uid'"), and gave filesystem.chown a None path for a
  zvol ("[path] null not allowed").
- filesystem.setacl raised `KeyError: 'id'` for an entry without `id` and "'USER_OBJ' is not a valid ACLWho" for a
  POSIX1e entry under the default NFS4 acltype.
"""
import enum
import errno
from unittest.mock import AsyncMock, Mock, patch

import sys
import types
from types import SimpleNamespace

import pytest

if not sys.platform.startswith('freebsd'):
    # filesystem.py reaches the SMB plugin, which needs Samba's Python bindings at import time, and
    # pool.py needs py-libzfs; as in test_account_validation.py, stand-ins are used off-box.
    samba3 = types.ModuleType('samba.samba3')
    samba3.param = SimpleNamespace(get_context=lambda: None)
    sys.modules.setdefault('samba', types.ModuleType('samba'))
    sys.modules.setdefault('samba.samba3', samba3)
    sys.modules.setdefault('libzfs', types.ModuleType('libzfs'))

from middlewared.plugins import filesystem as filesystem_plugin  # noqa: E402
from middlewared.plugins.filesystem import FilesystemService  # noqa: E402
from middlewared.plugins.pool import PoolDatasetService  # noqa: E402
from middlewared.service_exception import CallError, ValidationErrors  # noqa: E402


def errors(e):
    return {(error.attribute, error.errmsg) for error in e.errors}


# pool.dataset.create

def create_service():
    calls = []

    async def call(method, *args, **kwargs):
        calls.append((method, args))
        if method == 'zfs.dataset.query':
            if len(args) > 1 and args[1].get('get'):
                return {'encrypted': False}
            return [{
                'id': 'tank', 'encrypted': False, 'key_loaded': False,
                'properties': {'readonly': {'rawvalue': 'off'}, 'available': {'rawvalue': str(100 * 1024 ** 3)}},
            }]

    middleware = Mock()
    middleware.call = AsyncMock(side_effect=call)
    middleware.call_hook = AsyncMock()
    service = PoolDatasetService(middleware)
    service.insert_or_update_encrypted_record = AsyncMock()
    service.get_instance = AsyncMock(return_value={})
    return service, calls


def create_data(**kwargs):
    return {
        'name': 'tank/vol', 'type': 'VOLUME', 'volsize': 1024 ** 3, 'share_type': 'GENERIC', 'encryption': False,
        'inherit_encryption': True, 'encryption_options': {'generate_key': False, 'passphrase': None, 'key': None},
        **kwargs,
    }


@pytest.mark.asyncio
async def test_smb_share_type_on_a_volume_is_a_validation_error():
    service, calls = create_service()

    with pytest.raises(ValidationErrors) as ve:
        await PoolDatasetService.do_create.wraps(service, None, create_data(share_type='SMB'))

    assert errors(ve.value) == {('pool_dataset_create.share_type', 'This field is not valid for VOLUME')}
    assert 'zfs.dataset.create' not in [method for method, args in calls]


@pytest.mark.asyncio
async def test_generic_share_type_on_a_volume_still_creates_it():
    service, calls = create_service()

    await PoolDatasetService.do_create.wraps(service, None, create_data())

    create = [args[0] for method, args in calls if method == 'zfs.dataset.create']
    assert create == [{'name': 'tank/vol', 'type': 'VOLUME', 'properties': {'volsize': str(1024 ** 3)}}]


# pool.dataset.permission

def permission_service(dataset, user=None, group=None, acl_is_trivial=True):
    async def call(method, *args):
        if method == 'dscache.get_uncached_user':
            return user(args[0])
        if method == 'dscache.get_uncached_group':
            return group(args[0])
        if method == 'filesystem.acl_is_trivial':
            return acl_is_trivial
        pjob = Mock(error=None)
        pjob.wait = AsyncMock()
        return pjob

    middleware = Mock()
    middleware.call = AsyncMock(side_effect=call)
    service = PoolDatasetService(middleware)
    service.get_instance = AsyncMock(return_value=dataset)
    return service


FILESYSTEM = {'type': 'FILESYSTEM', 'mountpoint': '/mnt/tank/share'}
OPTIONS = {'stripacl': False, 'recursive': False, 'traverse': False}


def not_found(name):
    # dscache.get_uncached_user/group: pwd.getpwnam()/grp.getgrnam() miss, or {} for an empty name
    if not name:
        return {}
    raise KeyError(f'getpwnam(): name not found: {name!r}')


async def permission(service, data):
    return await PoolDatasetService.permission.wraps(service, Mock(), 'tank/share', {'options': dict(OPTIONS), **data})


@pytest.mark.asyncio
@pytest.mark.parametrize('name', ['nobody-here', ''])
async def test_unknown_user_and_group_are_named_in_the_error(name):
    service = permission_service(FILESYSTEM, user=not_found, group=not_found)

    with pytest.raises(ValidationErrors) as ve:
        await permission(service, {'user': name, 'group': name})

    assert errors(ve.value) == {
        ('pool_dataset_permission.user', f'Provided user "{name}" does not exist'),
        ('pool_dataset_permission.group', f'Provided group "{name}" does not exist'),
    }


@pytest.mark.asyncio
async def test_acl_with_stripacl_is_filed_under_the_schema_name():
    service = permission_service(FILESYSTEM)

    with pytest.raises(ValidationErrors) as ve:
        await permission(service, {'acl': [{'tag': 'owner@'}], 'options': {**OPTIONS, 'stripacl': True}})

    assert errors(ve.value) == {
        ('pool_dataset_permission.acl', 'Simultaneously setting and removing ACL is not permitted.'),
    }


@pytest.mark.asyncio
async def test_mode_on_an_extended_acl_is_filed_under_the_schema_name():
    service = permission_service(FILESYSTEM, acl_is_trivial=False)

    with pytest.raises(ValidationErrors) as ve:
        await permission(service, {'mode': '755'})

    assert errors(ve.value) == {
        ('pool_dataset_permission.options',
         '/mnt/tank/share has an extended ACL. The option "stripacl" must be selected.'),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize('dataset,data,message', [
    ({'type': 'VOLUME', 'mountpoint': None}, {}, 'Permissions cannot be set on a VOLUME'),
    ({'type': 'FILESYSTEM', 'mountpoint': None}, {'mode': '755'}, 'tank/share is not mounted'),
])
async def test_dataset_without_a_mountpoint_is_refused_before_any_filesystem_call(dataset, data, message):
    service = permission_service(dataset)

    with pytest.raises(ValidationErrors) as ve:
        await permission(service, data)

    assert errors(ve.value) == {('id', message)}
    assert [c.args[0] for c in service.middleware.call.await_args_list if c.args[0].startswith('filesystem.')] == []


@pytest.mark.asyncio
async def test_chown_on_a_filesystem_is_unchanged():
    service = permission_service(FILESYSTEM, user=lambda name: {'pw_uid': 1000})

    await permission(service, {'user': 'alice'})

    service.middleware.call.assert_awaited_with('filesystem.chown', {
        'path': '/mnt/tank/share', 'uid': 1000, 'gid': -1, 'options': {'recursive': False, 'traverse': False},
    })


# filesystem.setacl

class ACLWho(enum.Enum):
    # py-bsd's bsd.acl.ACLWho as filesystem.getacl_nfs4 uses it: names are the ACL state tags, values the API tags.
    USER_OBJ = 'owner@'
    GROUP_OBJ = 'group@'
    EVERYONE = 'everyone@'
    USER = 'USER'
    GROUP = 'GROUP'


@pytest.fixture
def setacl():
    applied = []

    class ACL:
        # bsd.acl.ACL as setacl_nfs4 builds one
        def __setstate__(self, state):
            self.state = state

        def apply(self, path):
            applied.append((path, self.state))

    with (
        patch.object(filesystem_plugin, 'acl', Mock(ACLWho=ACLWho, ACL=ACL)),
        patch.object(filesystem_plugin.osc, 'IS_LINUX', False),
        patch.object(filesystem_plugin.os, 'pathconf', Mock(return_value=1)),
        patch.object(filesystem_plugin.os, 'chown'),
        patch.object(FilesystemService, '_common_perm_path_validate'),
        # These map BASIC perms and flags through py-bsd's NFS4 enums.
        patch.object(FilesystemService, '_FilesystemService__convert_to_adv_permset', lambda self, perm: {perm: True}),
        patch.object(FilesystemService, '_FilesystemService__convert_to_adv_flagset', lambda self, flag: {
            'FILE_INHERIT': flag == 'INHERIT', 'DIRECTORY_INHERIT': flag == 'INHERIT',
        }),
    ):
        service = FilesystemService(Mock())

        def run(dacl):
            # The decorated method: the filesystem_acl schema cleans `dacl` as a call would.
            return service.setacl(Mock(), {'path': '/mnt/tank/share', 'dacl': dacl})

        run.applied = applied
        yield run


OWNER = {
    'tag': 'owner@', 'id': None, 'type': 'ALLOW', 'perms': {'BASIC': 'FULL_CONTROL'}, 'flags': {'BASIC': 'INHERIT'},
}


def test_nfs4_entry_without_id_is_refused(setacl):
    entry = {key: value for key, value in OWNER.items() if key != 'id'}

    with pytest.raises(CallError) as ce:
        setacl([entry])

    assert ce.value.errno == errno.EINVAL
    assert ce.value.errmsg == "NFSv4 ACL is invalid: ACL entry [0] is missing required keys(s): {'id'}"
    assert setacl.applied == []


def test_posix1e_entry_under_nfs4_acltype_is_refused(setacl):
    entry = {'tag': 'USER_OBJ', 'id': -1, 'perms': {'READ': True, 'WRITE': True, 'EXECUTE': True}}

    with pytest.raises(CallError) as ce:
        setacl([entry])

    assert ce.value.errno == errno.EINVAL
    assert ce.value.errmsg.startswith('NFSv4 ACL is invalid: ACL entry [0] contains invalid extra key(s): ')
    assert 'is missing required keys(s): ' in ce.value.errmsg
    assert setacl.applied == []


def test_complete_nfs4_entry_is_applied(setacl):
    setacl([dict(OWNER)])

    assert [(path, [(ace['tag'], ace['id']) for ace in state]) for path, state in setacl.applied] == [
        ('/mnt/tank/share', [('USER_OBJ', None), ('EVERYONE', None)]),
    ]
