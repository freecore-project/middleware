import errno

import pytest
from mock import ANY, Mock, patch

from middlewared.plugins.nfs import NFSService as NFSConfigService, SharingNFSService, interface_post_sync
from middlewared.plugins.service_.services.nfs import NFSService
from middlewared.service_exception import ValidationError, ValidationErrors


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

        verrors.add.assert_called_once_with("sharingnfs_update.hosts", ANY)


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

        verrors.add.assert_called_once_with("sharingnfs_update.networks", ANY)


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


class InterfacePostSyncMiddleware:
    """the internal development record: the first interface.sync after middlewared starts."""

    def __init__(self, started, bindip=("192.0.2.5",), enabled=True, shares=True):
        self.cache = {}
        self.started = started
        self.bindip = list(bindip)
        self.enabled = enabled
        self.shares = shares
        self.calls = []
        self.tasks = []

    async def call(self, name, *args):
        self.calls.append(name)
        if name == "cache.has_key":
            return args[0] in self.cache
        if name == "cache.put":
            self.cache[args[0]] = args[1]
            return None
        if name == "datastore.query":
            return {"srv_enable": self.enabled}
        if name == "sharing.nfs.query":
            return [{"enabled": True}] if self.shares else []
        if name == "nfs.config":
            return {"bindip": self.bindip}
        if name == "service.started":
            return self.started
        if name == "service.restart":
            return None
        raise AssertionError(f"unexpected call {name!r}")

    def create_task(self, coro):
        self.tasks.append(coro)
        coro.close()


@pytest.mark.asyncio
async def test__interface_post_sync__boot_leaves_nfs_to_rc():
    # At boot NFS is not running yet: /etc/rc starts it once, with the bind IP.
    middleware = InterfacePostSyncMiddleware(started=False)
    await interface_post_sync(middleware)
    assert middleware.tasks == []
    assert "service.restart" not in middleware.calls


@pytest.mark.asyncio
async def test__interface_post_sync__restarts_running_nfs_onto_bind_ip():
    # middlewared restarted on a running box: NFS is restarted as before.
    middleware = InterfacePostSyncMiddleware(started=True)
    await interface_post_sync(middleware)
    assert len(middleware.tasks) == 1


@pytest.mark.asyncio
async def test__interface_post_sync__runs_once_and_ignores_unbound_nfs():
    middleware = InterfacePostSyncMiddleware(started=True, bindip=())
    await interface_post_sync(middleware)
    assert middleware.tasks == []
    assert "service.started" not in middleware.calls
    middleware.bindip = ["192.0.2.5"]
    await interface_post_sync(middleware)
    assert middleware.tasks == []


def test__sharing_nfs_service__validate_hosts_and_networks__hosts_of_one_share_resolve_to_one_address():
    # mountd(8) ignores a duplicate host within one exports line, and a share's hosts share a line
    with patch("middlewared.plugins.nfs.os.stat", lambda dev: {
        "/mnt/data/a": Mock(st_dev=1),
    }[dev]):
        middleware = Mock()

        verrors = Mock()

        SharingNFSService(middleware).validate_hosts_and_networks(
            [],
            {
                "paths": ["/mnt/data/a"],
                "hosts": ["nfs-client", "nfs-client.example.com"],
                "networks": [],
                "alldirs": False,
            },
            "sharingnfs_update",
            verrors,
            {
                "nfs-client": "192.0.2.10",
                "nfs-client.example.com": "192.0.2.10",
            },
        )

        assert not verrors.add.called


def test__sharing_nfs_service__validate_hosts_and_networks__host_and_network_of_one_share_are_one_address():
    # A host and each network are exported on separate lines; the kernel refuses the same addr/mask twice
    with patch("middlewared.plugins.nfs.os.stat", lambda dev: {
        "/mnt/data/a": Mock(st_dev=1),
    }[dev]):
        middleware = Mock()

        verrors = Mock()

        SharingNFSService(middleware).validate_hosts_and_networks(
            [],
            {
                "paths": ["/mnt/data/a"],
                "hosts": ["192.0.2.10"],
                "networks": ["192.0.2.10/32"],
                "alldirs": False,
            },
            "sharingnfs_update",
            verrors,
            {
                "192.0.2.10": "192.0.2.10",
            },
        )

        verrors.add.assert_called_once_with("sharingnfs_update.networks", ANY)


class SharingNFSMiddleware:

    def __init__(self, shares):
        self.shares = shares
        self.calls = []
        self.events = []

    def event_register(self, name, description):
        pass

    async def _call(self, name, serviceobj, method, args, app=None):
        return await method(*args)

    async def call_hook(self, name, *args, **kwargs):
        pass

    def send_event(self, name, event_type, **kwargs):
        self.events.append((name, event_type, kwargs))

    async def call(self, name, *args):
        self.calls.append(name)
        if name == "sharing.nfs.query":
            return [share for share in self.shares if share["id"] == args[0][0][2]]
        if name == "datastore.delete":
            return True
        if name == "service.query":
            return {"state": "RUNNING"}
        if name in ("etc.generate", "service.reload"):
            return True
        if name == "alert.oneshot_delete":
            return None

        raise AssertionError(f"unexpected call {name!r}")


@pytest.mark.asyncio
async def test__sharing_nfs_service__delete__missing_share():
    middleware = SharingNFSMiddleware([{"id": 1}])

    with pytest.raises(ValidationError) as ve:
        await SharingNFSService(middleware).delete(None, 2)

    assert ve.value.errno == errno.ENOENT
    assert "datastore.delete" not in middleware.calls
    assert "service.reload" not in middleware.calls
    assert "alert.oneshot_delete" not in middleware.calls
    assert middleware.events == []


@pytest.mark.asyncio
async def test__sharing_nfs_service__delete__existing_share():
    middleware = SharingNFSMiddleware([{"id": 1}])

    await SharingNFSService(middleware).delete(None, 1)

    assert "datastore.delete" in middleware.calls
    assert "service.reload" in middleware.calls
    assert middleware.events == [("sharing.nfs.query", "CHANGED", {"id": 1, "cleared": True})]


def make_nfs_config_service(**config):
    class Middleware:
        async def call(self, name, *args):
            if name == "kerberos.keytab.has_nfs_principal":
                return False
            if name == "interface.ip_in_use":
                return []

            raise AssertionError(f"unexpected call {name!r}")

    service = NFSConfigService(Middleware())
    updates = []

    async def nfs_config():
        return {
            "id": 1,
            "servers": 4,
            "udp": False,
            "allow_nonroot": False,
            "v4": True,
            "v4_v3owner": False,
            "v4_krb": False,
            "v4_domain": "",
            "bindip": [],
            "mountd_port": None,
            "rpcstatd_port": None,
            "rpclockd_port": None,
            "userd_manage_gids": False,
            "mountd_log": True,
            "statd_lockd_log": False,
            "v4_owner_major": "",
            "v4_krb_enabled": False,
            **config,
        }

    async def _update_service(old, new):
        updates.append(new.copy())

    service.config = nfs_config
    service._update_service = _update_service
    return service, updates


@pytest.mark.asyncio
async def test__nfs_config_service__update__turning_v4_off_clears_v4_domain():
    service, updates = make_nfs_config_service(v4_v3owner=True, v4_domain="example.com")

    await service.do_update({"v4": False})

    assert updates[0]["v4"] is False
    assert updates[0]["v4_v3owner"] is False
    assert updates[0]["v4_domain"] == ""


@pytest.mark.asyncio
async def test__nfs_config_service__update__v4_domain_without_v4():
    service, updates = make_nfs_config_service(v4_domain="example.com")

    with pytest.raises(ValidationErrors) as ve:
        await service.do_update({"v4": False, "v4_domain": "example.com"})

    assert [e.attribute for e in ve.value.errors] == ["nfs_update.v4_domain"]
    assert updates == []
