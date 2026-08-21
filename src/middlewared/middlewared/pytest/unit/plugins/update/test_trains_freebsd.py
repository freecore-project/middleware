from unittest.mock import Mock

from middlewared.plugins.update_ import trains_freebsd


class FakeManifest:
    def __init__(self, version, build_time=None, sequence="seq", train=None):
        self.version = version
        self.build_time = build_time
        self.sequence = sequence
        self.train = train

    def dict(self):
        data = {}
        if self.build_time is not None:
            data["BuildTime"] = self.build_time
        if self.train is not None:
            data["Train"] = self.train
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


def test__check_train__cross_train_upgrade_ignores_older_build_time(monkeypatch):
    """A 15.0 release cut after a 15.1 candidate must still reach 15.1.

    The regression this pins (the internal development record follow-up): FreeCORE-15.0-U1.4
    was built 2026-09-08 and FreeCORE-15.1-RC1 on 2026-09-07, so the newer
    product carries the OLDER BuildTime.  Comparing build times across trains
    refused the upgrade and would have done so for U1.5, U1.6 and every 15.0
    release thereafter.
    """
    current = FakeManifest(
        "FreeCORE-15.0-U1.4", 1788872778, "current-seq", train="FreeCORE-15.0-STABLE",
    )
    latest = FakeManifest(
        "FreeCORE-15.1-RC1", 1788821815, "latest-seq", train="FreeCORE-15.1-STABLE",
    )

    monkeypatch.setattr(trains_freebsd, "CheckForUpdates", lambda **kwargs: latest)
    monkeypatch.setattr(trains_freebsd.Configuration, "Configuration", lambda: FakeConfiguration(current))
    monkeypatch.setattr(trains_freebsd, "get_changelog", lambda *args, **kwargs: None)

    service = trains_freebsd.UpdateService(Mock())

    assert service.check_train("FreeCORE-15.1-STABLE") == {
        "status": "AVAILABLE",
        "changes": [],
        "notice": None,
        "notes": None,
        "changelog": None,
        "version": "FreeCORE-15.1-RC1",
    }


def test__check_train__cross_train_downgrade_is_unavailable(monkeypatch):
    """The reverse pair must stay refused, so can_update's asymmetry is pinned.

    Here the older product carries the NEWER BuildTime, which is precisely the
    case a naive build-time comparison would wave through.
    """
    current = FakeManifest(
        "FreeCORE-15.1-RC1", 1788821815, "current-seq", train="FreeCORE-15.1-STABLE",
    )
    latest = FakeManifest(
        "FreeCORE-15.0-U1.4", 1788872778, "latest-seq", train="FreeCORE-15.0-STABLE",
    )

    monkeypatch.setattr(trains_freebsd, "CheckForUpdates", lambda **kwargs: latest)
    monkeypatch.setattr(trains_freebsd.Configuration, "Configuration", lambda: FakeConfiguration(current))

    service = trains_freebsd.UpdateService(Mock())

    assert service.check_train("FreeCORE-15.0-STABLE") == {"status": "UNAVAILABLE"}


def test__check_train__same_train_stale_build_time_is_still_unavailable(monkeypatch):
    """the internal development record must keep working when trains ARE named.

    The two pre-existing BuildTime tests carry no Train at all, so they only
    exercise the fallback.  This one names the same train on both manifests and
    proves the staleness guard still fires there.
    """
    current = FakeManifest(
        "FreeCORE-15.1-MASTER-202606011224", 1780322044, "current-seq",
        train="FreeCORE-15.1-Nightlies",
    )
    latest = FakeManifest(
        "FreeCORE-15.1-MASTER-202606010626", 1780300506, "latest-seq",
        train="FreeCORE-15.1-Nightlies",
    )

    monkeypatch.setattr(trains_freebsd, "CheckForUpdates", lambda **kwargs: latest)
    monkeypatch.setattr(trains_freebsd.Configuration, "Configuration", lambda: FakeConfiguration(current))

    service = trains_freebsd.UpdateService(Mock())

    assert service.check_train("FreeCORE-15.1-Nightlies") == {"status": "UNAVAILABLE"}
