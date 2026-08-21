import pytest
from mock import ANY, Mock, patch

from middlewared.plugins.nfs import NFSService as NFSConfigService, SharingNFSService
from middlewared.plugins.service_.services.nfs import NFSService


class NFSServiceMiddleware:

    def __init__(self, v4=False, v4_krb_enabled=False):
        self.v4 = v4
        self.v4_krb_enabled = v4_krb_enabled

    async def call(self, name, *args):
        if name == "nfs.setup_v4":
            return None
        if name == "nfs.config":
            return {"v4": self.v4, "v4_krb_enabled": self.v4_krb_enabled}
        if name == "nis.get_state":
            return "DISABLED"

        raise AssertionError(f"unexpected call {name!r}")


def make_nfs_service(v4=False, v4_krb_enabled=False, gssd_status=0):
    service = NFSService(NFSServiceMiddleware(v4, v4_krb_enabled))
    freebsd_calls = []

    async def _freebsd_service(rc, verb, force=False):
        freebsd_calls.append((rc, verb, force))
        return Mock(returncode=gssd_status if rc == "gssd" and verb == "status" else 0)

    service._freebsd_service = _freebsd_service
    return service, freebsd_calls


@pytest.mark.asyncio
async def test__nfs_service__start_freebsd__does_not_start_gssd_without_kerberos():
    service, freebsd_calls = make_nfs_service(v4_krb_enabled=False)

    await service._start_freebsd()

    assert all(call[0] != "gssd" for call in freebsd_calls)
    assert ("nfsd", "start", False) in freebsd_calls


@pytest.mark.asyncio
async def test__nfs_service__start_freebsd__starts_gssd_with_kerberos():
    service, freebsd_calls = make_nfs_service(v4=True, v4_krb_enabled=True, gssd_status=1)

    await service._start_freebsd()

    assert ("gssd", "status", False) in freebsd_calls
    assert ("gssd", "start", False) in freebsd_calls
    assert freebsd_calls.index(("gssd", "start", False)) < freebsd_calls.index(("nfsd", "start", False))


@pytest.mark.asyncio
async def test__nfs_service__start_freebsd__does_not_start_gssd_without_v4():
    service, freebsd_calls = make_nfs_service(v4=False, v4_krb_enabled=True, gssd_status=1)

    await service._start_freebsd()

    assert all(call[0] != "gssd" for call in freebsd_calls)
    assert ("nfsd", "start", False) in freebsd_calls


@pytest.mark.asyncio
async def test__nfs_config_service__extend__requires_v4_for_kerberos_enabled():
    class Middleware:
        async def call(self, name, *args):
            assert name == "kerberos.keytab.has_nfs_principal"
            return True

    config = await NFSConfigService(Middleware()).nfs_extend({
        "16": False,
        "v4": False,
        "v4_krb": False,
        "v4_owner_major": "",
    })

    assert config["v4_krb_enabled"] is False


def test__sharing_nfs_service__validate_paths__same_filesystem():
    with patch("middlewared.plugins.nfs.os.stat", lambda dev: {
        "/mnt/data-1": Mock(st_dev=1),
        "/mnt/data-1/a": Mock(st_dev=1),
        "/mnt/data-1/b": Mock(st_dev=1),
    }[dev]):
        middleware = Mock()

        verrors = Mock()

        SharingNFSService(middleware).validate_paths(
            {
                "paths": ["/mnt/data-1/a", "/mnt/data-1/b"],
            },
            "sharingnfs_update",
            verrors,
        )

        assert not verrors.add.called


def test__sharing_nfs_service__validate_paths__not_same_filesystem():
    with patch("middlewared.plugins.nfs.os.stat", lambda dev: {
        "/mnt/data-1": Mock(st_dev=1),
        "/mnt/data-2": Mock(st_dev=2),
        "/mnt/data-1/d": Mock(st_dev=1),
        "/mnt/data-2/d": Mock(st_dev=2),
    }[dev]):
        middleware = Mock()

        verrors = Mock()

        SharingNFSService(middleware).validate_paths(
            {
                "paths": ["/mnt/data-1/d", "/mnt/data-2/d"],
            },
            "sharingnfs_update",
            verrors,
        )

        verrors.add.assert_called_once_with("sharingnfs_update.paths.1",
                                            "Paths for a NFS share must reside within the same filesystem")


def test__sharing_nfs_service__validate_hosts_and_networks__host_is_32_network():
    with patch("middlewared.plugins.nfs.os.stat", lambda dev: {
        "/mnt/data/a": Mock(st_dev=1),
        "/mnt/data/b": Mock(st_dev=1),
    }[dev]):
        middleware = Mock()

        verrors = Mock()

        SharingNFSService(middleware).validate_hosts_and_networks(
            [
                {
                    "paths": ["/mnt/data/a"],
                    "hosts": ["192.168.0.1"],
                    "networks": [],
                    "alldirs": False,
                },
            ],
            {
                "paths": ["/mnt/data/b"],
                "hosts": ["192.168.0.1"],
                "networks": [],
                "alldirs": False,
            },
            "sharingnfs_update",
            verrors,
            {
                "192.168.0.1": "192.168.0.1",
            },
        )

        verrors.add.assert_called_once_with("sharingnfs_update.hosts.0", ANY)


def test__sharing_nfs_service__validate_hosts_and_networks__dataset_is_already_exported():
    with patch("middlewared.plugins.nfs.os.stat", lambda dev: {
        "/mnt/data/a": Mock(st_dev=1),
        "/mnt/data/b": Mock(st_dev=1),
    }[dev]):
        middleware = Mock()

        verrors = Mock()

        SharingNFSService(middleware).validate_hosts_and_networks(
            [
                {
                    "paths": ["/mnt/data/a"],
                    "hosts": [],
                    "networks": ["192.168.0.0/24"],
                    "alldirs": False,
                },
            ],
            {
                "paths": ["/mnt/data/b"],
                "hosts": [],
                "networks": ["192.168.0.0/24"],
                "alldirs": False,
            },
            "sharingnfs_update",
            verrors,
            {
                "192.168.0.1": "192.168.0.1",
            },
        )

        verrors.add.assert_called_once_with("sharingnfs_update.networks.0", ANY)


def test__sharing_nfs_service__validate_hosts_and_networks__fs_is_already_exported_for_world():
    with patch("middlewared.plugins.nfs.os.stat", lambda dev: {
        "/mnt/data/a": Mock(st_dev=1),
        "/mnt/data/b": Mock(st_dev=1),
    }[dev]):
        middleware = Mock()

        verrors = Mock()

        SharingNFSService(middleware).validate_hosts_and_networks(
            [
                {
                    "paths": ["/mnt/data/a"],
                    "hosts": ["192.168.0.1"],
                    "networks": [],
                    "alldirs": False,
                },
            ],
            {
                "paths": ["/mnt/data/b"],
                "hosts": [],
                "networks": [],
                "alldirs": False,
            },
            "sharingnfs_update",
            verrors,
            {
                "192.168.0.1": "192.168.0.1",
            },
        )

        verrors.add.assert_called_once_with("sharingnfs_update.networks", ANY)
