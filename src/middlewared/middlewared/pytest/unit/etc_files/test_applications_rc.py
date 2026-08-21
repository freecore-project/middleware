import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock, patch

import pytest

RC_CONF = Path(__file__).parents[3] / 'etc_files/rc.conf.py'


class ApplicationsRcMiddleware:

    def __init__(self, pool='tank', restart_on_boot=True):
        self.config = {
            'pool': pool,
            'restart_on_boot': restart_on_boot,
        }

    def call_sync(self, name, *args):
        assert name == 'applications.config'
        assert not args
        return self.config


@pytest.fixture(scope='module')
def rc_conf():
    spec = importlib.util.spec_from_file_location('applications_rc_conf_test', RC_CONF)
    module = importlib.util.module_from_spec(spec)
    middlewared_utils = ModuleType('middlewared.utils')
    middlewared_utils.__path__ = []
    middlewared_utils_io = ModuleType('middlewared.utils.io')
    middlewared_utils_io.write_if_changed = Mock()
    with patch.dict(sys.modules, {
        'middlewared.utils': middlewared_utils,
        'middlewared.utils.io': middlewared_utils_io,
        'sysctl': Mock(),
    }):
        spec.loader.exec_module(module)
    return module


def test_applications_rc_is_absent_until_a_pool_is_selected(rc_conf):
    result = list(rc_conf.applications_config(ApplicationsRcMiddleware(pool=None), {}))

    assert result == []


def test_applications_rc_keeps_daemon_and_pf_inert_until_runtime_is_ready(
    rc_conf, tmp_path,
):
    ready = tmp_path / 'ready'
    with patch.object(rc_conf, 'RUNTIME_READY', str(ready)):
        result = list(rc_conf.applications_config(ApplicationsRcMiddleware(), {}))

    assert result == [
        'podman_enable="NO"',
        'podman_service_enable="NO"',
    ]


def test_applications_rc_enables_pool_scoped_restart_orchestration_when_ready(
    rc_conf, tmp_path,
):
    ready = tmp_path / 'ready'
    ready.write_text('ready\n')
    with patch.object(rc_conf, 'RUNTIME_READY', str(ready)):
        result = list(rc_conf.applications_config(ApplicationsRcMiddleware(), {}))

    assert result == [
        'podman_enable="YES"',
        'podman_service_enable="NO"',
        (
            'podman="/usr/bin/env '
            'CONTAINERS_STORAGE_CONF=/mnt/tank/applications/config/storage.conf '
            'CONTAINERS_CONF_OVERRIDE=/mnt/tank/applications/config/containers.conf '
            '/usr/local/bin/podman"'
        ),
        'pf_enable="YES"',
        'pf_rules="/etc/pf.conf.block"',
    ]


def test_applications_rc_keeps_restart_orchestration_off_without_restart_workloads(
    rc_conf, tmp_path,
):
    ready = tmp_path / 'ready'
    ready.write_text('ready\n')
    with patch.object(rc_conf, 'RUNTIME_READY', str(ready)):
        result = list(rc_conf.applications_config(
            ApplicationsRcMiddleware(restart_on_boot=False), {}
        ))

    assert result == [
        'podman_enable="NO"',
        'podman_service_enable="NO"',
        'pf_enable="YES"',
        'pf_rules="/etc/pf.conf.block"',
    ]


class FlaggedRcMiddleware(ApplicationsRcMiddleware):
    """the internal development record: the Linux ABI lines follow the flag, unless a tunable owns them."""

    def __init__(self, linux_compat_enabled=True, tunables=(), **kwargs):
        super().__init__(**kwargs)
        self.config['linux_compat_enabled'] = linux_compat_enabled
        self.tunables = list(tunables)
        self.queries = []

    def call_sync(self, name, *args):
        if name == 'tunable.query':
            self.queries.append(args)
            return self.tunables
        return super().call_sync(name, *args)


def test_linux_compat_flag_owns_the_rc_lines_when_enabled(rc_conf, tmp_path):
    middleware = FlaggedRcMiddleware(linux_compat_enabled=True)
    with patch.object(rc_conf, 'RUNTIME_READY', str(tmp_path / 'missing')):
        result = list(rc_conf.applications_config(middleware, {}))

    assert result == [
        'podman_enable="NO"',
        'podman_service_enable="NO"',
        'linux_enable="YES"',
        'linux_mounts_enable="NO"',
    ]
    assert middleware.queries == [(
        [('type', '=', 'RC'), ('var', '=', 'linux_enable'), ('enabled', '=', True)],
    )]


def test_linux_compat_flag_off_renders_exactly_what_it_rendered_before(rc_conf, tmp_path):
    middleware = FlaggedRcMiddleware(linux_compat_enabled=False)
    with patch.object(rc_conf, 'RUNTIME_READY', str(tmp_path / 'missing')):
        result = list(rc_conf.applications_config(middleware, {}))

    assert result == ['podman_enable="NO"', 'podman_service_enable="NO"']
    assert middleware.queries == []


def test_an_administrator_tunable_for_linux_enable_keeps_precedence(rc_conf, tmp_path):
    middleware = FlaggedRcMiddleware(
        linux_compat_enabled=True,
        tunables=[{'id': 1, 'var': 'linux_enable', 'value': 'YES', 'type': 'RC', 'enabled': True}],
    )
    with patch.object(rc_conf, 'RUNTIME_READY', str(tmp_path / 'missing')):
        result = list(rc_conf.applications_config(middleware, {}))

    assert result == ['podman_enable="NO"', 'podman_service_enable="NO"']
