import inspect
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import ANY, AsyncMock, Mock, call, patch

import pytest

from middlewared.plugins import update as update_module
from middlewared.plugins.update import UpdateService
from middlewared.plugins.update_ import install_freebsd, install_linux
from middlewared.service_exception import CallError


def update_service():
    middleware = Mock()
    middleware.call = AsyncMock()
    middleware.run_in_thread = AsyncMock(side_effect=lambda function, *args: function(*args))
    return UpdateService(middleware), middleware


def test_update_check_is_independent_of_legacy_plugin_inventory():
    service, middleware = update_service()

    def call_sync(name, *args):
        if name == 'cache.get':
            raise KeyError(name)
        if name == 'failover.licensed':
            return False
        if name == 'update.get_trains':
            return {
                'selected': 'FreeCORE-15.1-STABLE',
                'trains': {'FreeCORE-15.1-STABLE': {}},
            }
        if name == 'update.check_train':
            return {
                'status': 'AVAILABLE',
                'version': 'FreeCORE-15.1-STABLE-202609030900',
                'notice': 'Release notice',
            }
        raise AssertionError((name, args))

    middleware.call_sync.side_effect = call_sync

    assert service.check_available() == {
        'status': 'AVAILABLE',
        'version': 'FreeCORE-15.1-STABLE-202609030900',
        'notice': 'Release notice',
    }
    assert not any(
        invocation.args[0] == 'plugin.query'
        for invocation in middleware.call_sync.call_args_list
    )


@pytest.mark.asyncio
async def test_online_update_does_not_inspect_or_gate_on_legacy_plugins():
    service, middleware = update_service()

    async def call_middleware(name, *args):
        if name == 'update.get_trains':
            return {
                'selected': 'FreeCORE-15.1-STABLE',
                'trains': {'FreeCORE-15.1-STABLE': {}},
            }
        if name == 'update.get_update_location':
            return '/var/db/system/update'
        if name == 'update.download_update':
            return True
        if name in {'update.install_impl', 'cache.put'}:
            return None
        if name in {'system.is_freenas', 'failover.licensed'}:
            return False
        raise AssertionError((name, args))

    middleware.call.side_effect = call_middleware

    assert await service.update(Mock(), {}) is True
    middleware.call.assert_any_await(
        'update.install_impl', ANY, '/var/db/system/update',
    )
    assert not any(
        invocation.args[0] == 'plugin.query'
        for invocation in middleware.call.call_args_list
    )
    middleware.run_in_thread.assert_not_awaited()


def test_update_apis_expose_only_standard_parameters():
    assert not hasattr(update_module, 'LEGACY_PLUGIN_CONFIRMATION')
    assert set(UpdateService.update.accepts[0].attrs) == {'train', 'reboot'}
    assert [schema.name for schema in UpdateService.manual.accepts] == ['path']
    assert set(UpdateService.file.accepts[0].attrs) == {'destination'}

    assert list(inspect.signature(install_freebsd.UpdateService.install_impl).parameters) == [
        'self', 'job', 'location',
    ]
    assert list(inspect.signature(install_freebsd.UpdateService.install_manual_impl).parameters) == [
        'self', 'job', 'path', 'dest_extracted',
    ]
    assert list(inspect.signature(install_linux.UpdateService.install_impl).parameters) == [
        'self', 'job', 'location',
    ]
    assert list(inspect.signature(install_linux.UpdateService.install_manual_impl).parameters) == [
        'self', 'job', 'path', 'dest_extracted',
    ]


@pytest.mark.parametrize(('signature', 'verified'), [
    (None, True),
    ('signed-manifest', False),
])
def test_freebsd_installer_rejects_unverified_manifest_before_target_use(
    signature, verified,
):
    middleware = Mock()
    installer = install_freebsd.UpdateService(middleware)
    configuration = Mock()
    configuration.SystemManifest.return_value = Mock()
    new_manifest = Mock()
    new_manifest.Signature.return_value = signature
    new_manifest.VerifySignature.return_value = verified

    with (
        patch.object(
            install_freebsd.Configuration, 'Configuration', return_value=configuration,
        ),
        patch.object(
            install_freebsd.Manifest, 'Manifest', return_value=new_manifest,
        ) as manifest_constructor,
        pytest.raises(CallError, match='manifest signature is missing or invalid'),
    ):
        installer.install_impl(Mock(id=42), '/unverified-update')

    manifest_constructor.assert_called_once_with(require_signature=True)
    new_manifest.LoadPath.assert_called_once_with('/unverified-update/MANIFEST')
    new_manifest.Version.assert_not_called()
    middleware.call_sync.assert_not_called()


def test_freebsd_installer_applies_verified_manifest_without_plugin_gate():
    middleware = Mock()
    installer = install_freebsd.UpdateService(middleware)
    old_manifest = Mock()
    old_manifest.Version.return_value = 'FreeCORE-15.0-STABLE'
    configuration = Mock()
    configuration.SystemManifest.return_value = old_manifest
    new_manifest = Mock()
    new_manifest.Version.return_value = 'FreeCORE-15.1-STABLE-20260903'
    new_manifest.Signature.return_value = 'signed-manifest'
    new_manifest.VerifySignature.return_value = True
    install_job = Mock()
    install_job.wait_sync.return_value = True

    def call_sync(name, *args):
        if name == 'update.install_impl_job':
            return install_job
        raise AssertionError((name, args))

    middleware.call_sync.side_effect = call_sync

    with (
        patch.object(
            install_freebsd.Configuration, 'Configuration', return_value=configuration,
        ),
        patch.object(
            install_freebsd.Manifest, 'Manifest', return_value=new_manifest,
        ) as manifest_constructor,
    ):
        assert installer.install_impl(Mock(id=42), '/signed-update') is True

    manifest_constructor.assert_called_once_with(require_signature=True)
    new_manifest.LoadPath.assert_called_once_with('/signed-update/MANIFEST')
    assert new_manifest.method_calls[:4] == [
        call.LoadPath('/signed-update/MANIFEST'),
        call.Signature(),
        call.VerifySignature(),
        call.Version(),
    ]
    middleware.call_sync.assert_called_once_with(
        'update.install_impl_job', 42, '/signed-update',
    )
    install_job.wait_sync.assert_called_once_with(raise_error=True)


def test_freebsd_manual_backend_applies_after_extraction_without_confirmation():
    middleware = Mock()
    installer = install_freebsd.UpdateService(middleware)
    job = Mock()

    with (
        patch.object(
            install_freebsd.subprocess,
            'run',
            return_value=SimpleNamespace(stdout='POSIX tar archive'),
        ),
        patch.object(install_freebsd.Update, 'ExtractFrozenUpdate') as extract,
        patch.object(installer, 'install_impl', return_value=True) as install,
    ):
        installer.install_manual_impl(
            job, '/tmp/manual-update.tar', '/tmp/.update',
        )

    extract.assert_called_once_with(
        '/tmp/manual-update.tar', '/tmp/.update', verbose=True,
    )
    install.assert_called_once_with(job, '/tmp/.update')


def test_manual_path_propagates_failure_and_cleans_staged_files(tmp_path):
    service, middleware = update_service()
    update_path = tmp_path / 'manual-update.tar'
    extracted = tmp_path / '.update'
    update_path.write_bytes(b'update')
    extracted.mkdir()
    middleware.call_sync.side_effect = CallError('install failed')

    with pytest.raises(CallError, match='install failed'):
        service.manual(Mock(), str(update_path))

    middleware.call_sync.assert_called_once_with(
        'update.install_manual_impl', ANY, str(update_path), str(extracted),
    )
    assert not update_path.exists()
    assert not extracted.exists()


def test_manual_upload_location_is_destroyed_after_install_failure(tmp_path):
    service, middleware = update_service()
    update_path = tmp_path / 'manual-update.tar'
    extracted = tmp_path / '.update'
    update_path.write_bytes(b'update')
    extracted.mkdir()

    def call_sync(name, *args):
        if name == 'update.install_manual_impl':
            raise CallError('install failed')
        if name == 'update.destroy_upload_location':
            return None
        raise AssertionError((name, args))

    middleware.call_sync.side_effect = call_sync
    with (
        patch('middlewared.plugins.update.UPLOAD_LOCATION', str(tmp_path)),
        pytest.raises(CallError, match='install failed'),
    ):
        service.manual(Mock(), str(update_path))

    assert middleware.call_sync.call_args_list == [
        call(
            'update.install_manual_impl', ANY, str(update_path), str(extracted),
        ),
        call('update.destroy_upload_location'),
    ]
    assert not update_path.exists()
    assert not extracted.exists()


@pytest.mark.asyncio
async def test_streamed_upload_cleans_temporary_state_after_install_failure(tmp_path):
    service, middleware = update_service()
    job = Mock()
    job.pipes = SimpleNamespace(input=SimpleNamespace(r=BytesIO(b'update')))

    async def call_middleware(name, *args):
        if name == 'update.create_upload_location':
            return None
        if name == 'update.install_manual_impl':
            (tmp_path / '.update').mkdir()
            raise CallError('install failed')
        if name == 'update.destroy_upload_location':
            return None
        raise AssertionError((name, args))

    middleware.call.side_effect = call_middleware
    with (
        patch('middlewared.plugins.update.UPLOAD_LOCATION', str(tmp_path)),
        pytest.raises(CallError, match='install failed'),
    ):
        await service.file(job, {'destination': None})

    assert middleware.call.await_args_list == [
        call('update.create_upload_location'),
        call(
            'update.install_manual_impl',
            job,
            str(tmp_path / 'manualupdate.tar'),
            str(tmp_path / '.update'),
        ),
        call('update.destroy_upload_location'),
    ]
    assert not (tmp_path / 'manualupdate.tar').exists()
    assert not (tmp_path / '.update').exists()
