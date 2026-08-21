from unittest.mock import Mock

from middlewared.plugins.update_ import trains_freebsd


class FakeManifest:
    def __init__(self, version, build_time=None, sequence="seq"):
        self.version = version
        self.build_time = build_time
        self.sequence = sequence

    def dict(self):
        data = {}
        if self.build_time is not None:
            data["BuildTime"] = self.build_time
        return data

    def Version(self):
        return self.version

    def Notice(self):
        return None

    def Notes(self):
        return None

    def Sequence(self):
        return self.sequence


class FakeConfiguration:
    def __init__(self, system_manifest):
        self.system_manifest = system_manifest

    def SystemManifest(self):
        return self.system_manifest


def test__get_trains_data__freecore_server_does_not_fetch_scale_trains(monkeypatch):
    configuration = Mock()
    configuration.AvailableTrains.return_value = {}
    configuration.CurrentTrain.return_value = "FreeCORE-15.0-Nightlies"
    configuration.UpdateServerMaster.return_value = "https://updates.freecore.org/FreeCORE/"

    monkeypatch.setattr(trains_freebsd.Configuration, "Configuration", lambda: configuration)

    middleware = Mock()
    middleware.call_sync.return_value = False
    service = trains_freebsd.UpdateService(middleware)
    monkeypatch.setattr(service, "_get_redir_trains", lambda: {})

    service.get_trains_data()

    middleware.call_sync.assert_called_once_with("system.is_enterprise")


def test__check_train__missing_latest_manifest_is_unavailable(monkeypatch):
    def check_for_updates(**kwargs):
        raise trains_freebsd.UpdateNetworkFileNotFoundException("latest manifest missing")

    monkeypatch.setattr(trains_freebsd, "CheckForUpdates", check_for_updates)

    service = trains_freebsd.UpdateService(Mock())

    assert service.check_train("TrueNAS-15.0-Nightlies") == {"status": "UNAVAILABLE"}


def test__check_train__stale_manifest_build_time_is_unavailable(monkeypatch):
    current = FakeManifest("TrueNAS-15.0-MASTER-202606011224", 1780322044, "current-seq")
    latest = FakeManifest("TrueNAS-15.0-MASTER-202606010626", 1780300506, "latest-seq")

    monkeypatch.setattr(trains_freebsd, "CheckForUpdates", lambda **kwargs: latest)
    monkeypatch.setattr(trains_freebsd.Configuration, "Configuration", lambda: FakeConfiguration(current))

    service = trains_freebsd.UpdateService(Mock())

    assert service.check_train("TrueNAS-15.0-Nightlies") == {"status": "UNAVAILABLE"}


def test__check_train__newer_manifest_build_time_is_available(monkeypatch):
    current = FakeManifest("TrueNAS-15.0-MASTER-202606010626", 1780300506, "current-seq")
    latest = FakeManifest("TrueNAS-15.0-MASTER-202606011224", 1780322044, "latest-seq")

    monkeypatch.setattr(trains_freebsd, "CheckForUpdates", lambda **kwargs: latest)
    monkeypatch.setattr(trains_freebsd.Configuration, "Configuration", lambda: FakeConfiguration(current))
    monkeypatch.setattr(trains_freebsd, "get_changelog", lambda train, start="", end="": None)

    service = trains_freebsd.UpdateService(Mock())

    assert service.check_train("TrueNAS-15.0-Nightlies") == {
        "status": "AVAILABLE",
        "changes": [],
        "notice": None,
        "notes": None,
        "changelog": None,
        "version": "TrueNAS-15.0-MASTER-202606011224",
    }
