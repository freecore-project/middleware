"""The guided move to TrueNAS SCALE (the internal development record): the check, the target, the download, the job.

Off-box: the network, the middleware and the install are stand-ins; the decisions are the real code.
"""
import hashlib
import os
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

from middlewared.plugins.config_ import scale as scale_config
from middlewared.plugins.update_ import install_freebsd
from middlewared.plugins.update_ import scale_sidegrade as sidegrade
from middlewared.service_exception import CallError

MANIFEST_2404 = {'filename': 'TrueNAS-SCALE-24.04.2.5.update', 'version': '24.04.2.5',
                 'checksum': 'd' * 64, 'filesize': 1320603648}


# --- the pure decisions ---------------------------------------------------------------------------------

def test_the_target_is_a_complete_24_04_entry_or_a_refusal():
    expected = {key: MANIFEST_2404[key] for key in ('version', 'filename', 'filesize', 'checksum')}
    assert sidegrade.move_target(MANIFEST_2404) == expected
    with pytest.raises(CallError, match='24.04 only'):
        sidegrade.move_target(dict(MANIFEST_2404, version='24.10.2.4'))
    for broken in ({'checksum': 'nope'}, {'filesize': '1'}, {'filename': '../x.update'}, {'filename': None}):
        with pytest.raises(CallError, match='incomplete'):
            sidegrade.move_target(dict(MANIFEST_2404, **broken))


def test_the_pinned_target_is_ixs_published_24_04_2_5():
    assert sidegrade.PINNED_TARGET['checksum'] == 'dfee3b50dd183619ee08714b4abff9158588e3a9c07847bac579cdfa1092f3be'
    assert sidegrade.move_target(sidegrade.PINNED_TARGET)['version'] == '24.04.2.5'


def test_24_04_lacks_three_of_24_10s_pool_features():
    assert scale_config.SCALE_POOL_FEATURES - sidegrade.SCALE_2404_POOL_FEATURES == {
        'fast_dedup', 'raidz_expansion', 'redaction_list_spill'}


def report(refused=(), read_only=(), dormant=(), pool='tank'):
    return {'pool': pool, 'reference': 'x', 'refused': list(refused), 'read_only': list(read_only),
            'dormant': list(dormant)}


def test_a_pool_warns_and_names_the_release_it_waits_for():
    assert sidegrade.pool_warning(None) is None
    assert sidegrade.pool_warning(report()) is None
    # Enabled-but-unused features travel: a pool carrying them imported on 24.04 in the acceptance round.
    assert sidegrade.pool_warning(report(dormant=['block_cloning_endian'])) is None
    warning = sidegrade.pool_warning(report(refused=['raidz_expansion', 'block_cloning_endian']))
    assert warning['unavailable'] and warning['until'] == 'TrueNAS 27'
    assert 'stays unavailable until TrueNAS 27 or later runs' in warning['text']
    # Read-only compatible is still unavailable: SCALE does not import the pool on its own (canary, 24.04.2.5).
    read_only = sidegrade.pool_warning(report(read_only=['fast_dedup']))
    assert read_only['unavailable'] and read_only['read_only_import']
    assert 'stays unavailable until TrueNAS SCALE 24.10 or later runs' in read_only['text']
    assert 'read-only from the shell' in read_only['text']
    assert not warning['read_only_import']
    unknown = sidegrade.pool_warning(report(refused=['xattr_compat']))
    assert unknown['until'] is None and 'a TrueNAS release whose OpenZFS has them' in unknown['text']


def test_the_pool_report_takes_the_24_04_reference():
    states = 'feature@raidz_expansion\tactive\nfeature@lz4_compress\tactive\nfeature@longname\tenabled\n'
    support = 'raidz_expansion\nlz4_compress\nlongname\n'

    def run(cmd, **kwargs):
        return SimpleNamespace(stdout=states if cmd[1] == 'get' else support)
    got = scale_config.pool_feature_report('tank', run=run, features=sidegrade.SCALE_2404_POOL_FEATURES,
                                           reference=sidegrade.SCALE_2404_RELEASE)
    assert got == {'pool': 'tank', 'reference': 'TrueNAS SCALE 24.04', 'refused': ['raidz_expansion'],
                   'read_only': [], 'dormant': ['longname']}
    # The configuration-file route keeps judging against 24.10, where raidz_expansion is known.
    assert scale_config.pool_feature_report('tank', run=run)['refused'] == []


def test_the_move_needs_room_for_the_file_and_its_image():
    assert sidegrade.required_space({'filesize': 1000}) == 2000 + 512 * 1024 * 1024


# --- the service ------------------------------------------------------------------------------------------

class Response:
    def __init__(self, payload=None, status=200, headers=None, body=b''):
        self.payload, self.status, self.headers, self.body = payload, status, headers or {}, body

    def raise_for_status(self):
        if self.status >= 400:
            raise requests.HTTPError(str(self.status))

    def json(self):
        return self.payload

    def iter_content(self, chunk_size):
        yield self.body

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def service(calls=None):
    middleware = Mock()
    answers = {'system.is_enterprise': False, 'boot.pool_name': 'boot-pool', 'update.get_update_location': '/tmp',
               'pool.query': [{'name': 'tank'}], 'service.query': [], 'applications.config': {'configured': False},
               'jail.query': []}
    answers.update(calls or {})
    middleware.call_sync = Mock(side_effect=lambda method, *args: answers[method])
    svc = install_freebsd.UpdateService(middleware)
    svc.logger = Mock()
    return svc


def test_the_target_comes_from_ix_then_the_pinned_mirror_then_nowhere():
    svc = service()
    got = svc.scale_move_target(get=lambda url, **kw: Response(MANIFEST_2404))
    assert got['source'] == 'iX' and got['url'].endswith('/TrueNAS-SCALE-Dragonfish/TrueNAS-SCALE-24.04.2.5.update')

    def ix_gone(url, **kw):
        if 'update.freenas.org' in url:
            return Response(status=404)
        return Response(headers={'Content-Length': str(sidegrade.PINNED_TARGET['filesize'])})
    mirrored = svc.scale_move_target(get=ix_gone)
    assert mirrored['source'] == 'FreeCORE mirror' and mirrored['checksum'] == sidegrade.PINNED_TARGET['checksum']
    assert mirrored['url'] == ('https://updates.freecore.org/scale/TrueNAS-SCALE-Dragonfish/'
                               'TrueNAS-SCALE-24.04.2.5.update')

    def nowhere(url, **kw):
        raise requests.ConnectionError('offline')
    with pytest.raises(CallError, match='not available from iX or from FreeCORE.*clean install'):
        svc.scale_move_target(get=nowhere)


def test_a_mirror_serving_anything_but_the_pinned_size_is_not_used():
    svc = service()

    def wrong_size(url, **kw):
        if 'update.freenas.org' in url:
            return Response(status=404)
        return Response(headers={'Content-Length': '12'})
    with pytest.raises(CallError, match='not available'):
        svc.scale_move_target(get=wrong_size)


def test_the_check_gates_on_blockers_and_only_warns_on_pools(monkeypatch):
    svc = service({'service.query': [{'service': 'wireguard', 'enable': True, 'state': 'STOPPED'},
                                     {'service': 'bastille', 'enable': False, 'state': 'STOPPED'}],
                   'applications.config': {'configured': True}, 'applications.query': [{}, {}],
                   'jail.query': [{'id': 'nextcloud'}]})
    monkeypatch.setattr(sidegrade, 'check_tools', lambda: None)
    monkeypatch.setattr(svc, 'scale_move_target', lambda: dict(sidegrade.PINNED_TARGET, source='iX', url='u'))
    monkeypatch.setattr(install_freebsd.shutil, 'disk_usage', lambda path: SimpleNamespace(free=10 ** 12))
    monkeypatch.setattr(scale_config, 'pool_feature_report',
                        lambda pool, **kw: report(refused=['block_cloning_endian'], pool=pool))

    monkeypatch.setattr(sidegrade, 'check_boot_pool', lambda pool: 12)
    monkeypatch.setattr(sidegrade, 'boot_method', lambda: 'UEFI')
    check = svc.scale_move_check()
    assert check['available'] and check['blockers'] == []
    assert [p['pool'] for p in check['pools']] == ['tank'] and check['pools'][0]['until'] == 'TrueNAS 27'
    assert check['not_carried'] == ['WireGuard server', 'Applications (2 installed)', 'iocage jails and plugins (1)']
    assert 'power the system off and on' in check['way_back']

    def ashift_14(pool):
        raise CallError('The boot pool boot-pool was created with ashift 14 ...')
    monkeypatch.setattr(sidegrade, 'check_boot_pool', ashift_14)
    monkeypatch.setattr(install_freebsd.shutil, 'disk_usage', lambda path: SimpleNamespace(free=10))
    blocked = svc.scale_move_check()
    assert not blocked['available'] and len(blocked['blockers']) == 2
    assert 'ashift 14' in blocked['blockers'][0] and 'free at /tmp' in blocked['blockers'][1]


def test_a_download_that_misses_the_published_checksum_is_removed_and_refused(tmp_path):
    svc = service()
    body = b'not the update'
    target = {'filename': 'x.update', 'filesize': len(body), 'checksum': 'e' * 64, 'version': '24.04.2.5',
              'source': 'iX', 'url': 'u'}
    job = Mock()
    with pytest.raises(CallError, match='does not match its published SHA-256.*Nothing was installed'):
        svc.scale_move_download(job, target, str(tmp_path), get=lambda url, **kw: Response(body=body))
    assert not (tmp_path / 'x.update').exists()

    good = dict(target, checksum=hashlib.sha256(body).hexdigest())
    path = svc.scale_move_download(job, good, str(tmp_path), get=lambda url, **kw: Response(body=body))
    assert open(path, 'rb').read() == body
    # A verified file already there is used as it is.
    assert svc.scale_move_download(job, good, str(tmp_path), get=None) == path


def test_the_job_refuses_on_blockers_and_otherwise_installs_and_cleans_up(tmp_path, monkeypatch):
    svc = service()
    monkeypatch.setattr(svc, 'scale_move_check', lambda: {'blockers': ['no GRUB'], 'target': None})
    with pytest.raises(CallError, match='no GRUB'):
        install_freebsd.UpdateService.scale_move.wraps(svc, Mock(), {'reboot': False})

    update = tmp_path / 'u.update'
    update.write_bytes(b'x')
    installed = []
    monkeypatch.setattr(svc, 'scale_move_check', lambda: {'blockers': [], 'target': {'filename': 'u.update'}})
    monkeypatch.setattr(svc, 'scale_move_download', lambda job, target, location: str(update))
    monkeypatch.setattr(svc, '_install_scale', lambda job, path: installed.append(
        (isinstance(job, install_freebsd.ScaledProgress), job.start, path)))
    assert install_freebsd.UpdateService.scale_move.wraps(svc, Mock(), {'reboot': False}) is True
    assert installed == [(True, 40, str(update))] and not os.path.exists(update)


# --- the internal development record: BIOS systems ----------------------------------------------------------------

def test_the_check_blocks_a_bios_system_whose_image_lacks_grubs_i386_pc(monkeypatch):
    svc = service()
    monkeypatch.setattr(sidegrade, 'check_tools', lambda: None)
    monkeypatch.setattr(sidegrade, 'check_boot_pool', lambda pool: 12)
    monkeypatch.setattr(svc, 'scale_move_target', lambda: dict(sidegrade.PINNED_TARGET, source='iX', url='u'))
    monkeypatch.setattr(install_freebsd.shutil, 'disk_usage', lambda path: SimpleNamespace(free=10 ** 12))
    monkeypatch.setattr(scale_config, 'pool_feature_report', lambda pool, **kw: report(pool=pool))
    monkeypatch.setattr(sidegrade, 'boot_method', lambda: 'BIOS')
    monkeypatch.setattr(sidegrade.os.path, 'isfile', lambda path: not path.endswith('.mod'))
    blocked = svc.scale_move_check()
    assert not blocked['available'] and len(blocked['blockers']) == 1
    assert blocked['blockers'][0].startswith('This system boots through the BIOS')


def install_stubs(monkeypatch, svc, method, install_error):
    monkeypatch.setattr(sidegrade, 'read_manifest', lambda path: MANIFEST_2404)
    monkeypatch.setattr(sidegrade, 'check_target', lambda manifest: (24, 4))
    monkeypatch.setattr(sidegrade, 'check_tools', lambda: None)
    monkeypatch.setattr(sidegrade, 'check_boot_pool', lambda pool: 12)
    monkeypatch.setattr(sidegrade, 'boot_method', lambda: method)
    monkeypatch.setattr(sidegrade, 'check_bios_grub', lambda method: None)
    monkeypatch.setattr(sidegrade, 'bios_boot_partitions', lambda disks: [(disk, 1) for disk in disks])
    monkeypatch.setattr(sidegrade, 'discard_staged_root', lambda staged: None)
    monkeypatch.setattr(install_freebsd.subprocess, 'run', lambda *a, **kw: None)
    monkeypatch.setattr(install_freebsd.shutil, 'rmtree', lambda *a, **kw: None)
    monkeypatch.setattr(svc, '_stage_old_root', lambda staged: None)
    restored = []
    monkeypatch.setattr(sidegrade, 'restore_bios_boot', lambda partitions: restored.append(partitions) or [])

    def call_sync(method_name, *args):
        if method_name == 'update.install_scale':
            raise install_error
        return {'boot.pool_name': 'boot-pool', 'boot.get_disks': ['vtbd0']}[method_name]
    svc.middleware.call_sync = Mock(side_effect=call_sync)
    return restored


def test_a_failed_install_on_bios_puts_freebsds_boot_partition_back(tmp_path, monkeypatch):
    svc = service()
    error = CallError("Command ['grub-install', '--target=i386-pc', '/dev/vtbd0'] failed with exit code 1")
    restored = install_stubs(monkeypatch, svc, 'BIOS', error)
    with pytest.raises(CallError) as raised:
        svc._install_scale(Mock(), str(tmp_path / 'u.update'))
    assert restored == [[('vtbd0', 1)]]
    assert 'grub-install' in raised.value.errmsg
    assert "FreeCORE's BIOS boot partition was restored (vtbd0 partition 1)" in raised.value.errmsg


def test_a_failed_install_on_uefi_is_reported_unchanged(tmp_path, monkeypatch):
    svc = service()
    error = CallError('the installer failed')
    restored = install_stubs(monkeypatch, svc, 'UEFI', error)
    with pytest.raises(CallError) as raised:
        svc._install_scale(Mock(), str(tmp_path / 'u.update'))
    assert raised.value is error and restored == []
