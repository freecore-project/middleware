# the internal development record (Codeberg freecore#111): a UPS driver/upsd start that failed
# during rc is retried for a bounded time after boot, and only while it is still ours.
import itertools
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from middlewared.plugins import ups as ups_plugin
from middlewared.plugins.ups import (
    UPS_BOOT_RETRY_DEADLINE, UPS_BOOT_RETRY_INTERVAL, UPSMON_PIDFILE, UPSService, _ups_system_ready,
)


class FakeMiddleware:
    def __init__(self, started=(), enabled=True):
        self.started = list(started)
        self.enabled = enabled
        self.calls = []
        self.alerts = []

    async def call(self, method, *args):
        self.calls.append(method)
        if method == 'service.started':
            assert args == ('ups',)
            return self.started.pop(0)
        if method in ('alert.oneshot_create', 'alert.oneshot_delete'):
            self.alerts.append((method, *args))
            return None
        if method == 'datastore.query':
            assert args[0] == 'services.services'
            return [{'id': 14, 'srv_service': 'ups', 'srv_enable': True}] if self.enabled else []
        raise AssertionError(f'unexpected call {method}')


def make_service(middleware, mode='MASTER'):
    service = UPSService.__new__(UPSService)
    service.middleware = middleware
    service.logger = Mock()
    service.config = AsyncMock(return_value={'mode': mode, 'identifier': 'ups'})
    return service


def upsmon(alive):
    async def run(*args, **kwargs):
        assert args == ('pgrep', '-F', UPSMON_PIDFILE, 'upsmon')
        return SimpleNamespace(returncode=0 if alive else 1, stdout=b'2337\n' if alive else b'')
    return run


async def retry(service, wanted=(), clock=None):
    start = AsyncMock()
    sleep = AsyncMock()
    service.boot_retry_wanted = AsyncMock(side_effect=list(wanted))
    clock = clock or itertools.repeat(0)
    with (
        patch.object(ups_plugin, 'freebsd_service', start),
        patch.object(ups_plugin.asyncio, 'sleep', sleep),
        patch.object(ups_plugin.time, 'monotonic', Mock(side_effect=clock)),
    ):
        await service.boot_retry()
    return start, sleep


@pytest.mark.asyncio
async def test_a_healthy_boot_is_left_alone():
    service = make_service(FakeMiddleware(started=[True]))

    start, sleep = await retry(service)

    start.assert_not_awaited()
    sleep.assert_not_awaited()
    service.boot_retry_wanted.assert_not_awaited()
    service.logger.info.assert_not_called()


@pytest.mark.asyncio
async def test_the_stack_heals_once_the_ups_answers():
    service = make_service(FakeMiddleware(started=[False, False, True]))

    start, sleep = await retry(service, wanted=[True, True])

    assert start.await_args_list == [(('nut', 'onestart'),)] * 2
    assert sleep.await_args_list == [((UPS_BOOT_RETRY_INTERVAL,),)] * 2
    service.logger.info.assert_called_with('UPS service came up after %d retr%s', 2, 'ies')
    service.logger.error.assert_not_called()


@pytest.mark.asyncio
async def test_stopping_or_disabling_the_service_mid_window_ends_the_retries():
    service = make_service(FakeMiddleware(started=[False, False]))

    start, _ = await retry(service, wanted=[True, False])

    assert start.await_count == 1
    assert 'stopped after' in service.logger.info.call_args.args[0]


@pytest.mark.asyncio
async def test_the_retries_are_bounded_and_end_with_one_error():
    attempts = UPS_BOOT_RETRY_DEADLINE // UPS_BOOT_RETRY_INTERVAL
    service = make_service(FakeMiddleware(started=[False] * (attempts + 1)))
    # One reading for the deadline, then one per pass, each a retry interval later.
    clock = itertools.chain([0], itertools.count(0, UPS_BOOT_RETRY_INTERVAL))

    start, _ = await retry(service, wanted=[True] * (attempts + 1), clock=clock)

    assert start.await_count == attempts
    service.logger.error.assert_called_once()
    # the internal development record: giving up raises one alert, so the stopped service is not silent.
    assert service.middleware.alerts == [('alert.oneshot_create', 'UPSServiceNotRunning', {'ups': 'ups'})]


@pytest.mark.asyncio
async def test_healing_or_handing_back_raises_no_alert():
    healed = make_service(FakeMiddleware(started=[False, True]))
    await retry(healed, wanted=[True])
    stopped = make_service(FakeMiddleware(started=[False]))
    await retry(stopped, wanted=[False])

    assert healed.middleware.alerts == [] and stopped.middleware.alerts == []


@pytest.mark.asyncio
async def test_retry_is_wanted_only_for_an_enabled_master_with_upsmon_up():
    with patch.object(ups_plugin, 'run', upsmon(alive=True)):
        assert await make_service(FakeMiddleware()).boot_retry_wanted() is True


@pytest.mark.asyncio
@pytest.mark.parametrize('enabled,mode,upsmon_alive', [
    (False, 'MASTER', True),   # disabled
    (True, 'SLAVE', True),     # remote upsd, nothing local to start
    (True, 'MASTER', False),   # stopped by hand: upsmon always starts at boot
])
async def test_retry_is_not_wanted_otherwise(enabled, mode, upsmon_alive):
    service = make_service(FakeMiddleware(enabled=enabled), mode=mode)

    with patch.object(ups_plugin, 'run', upsmon(alive=upsmon_alive)):
        assert await service.boot_retry_wanted() is False


@pytest.mark.asyncio
async def test_only_the_ready_event_starts_the_retry():
    middleware = Mock()
    middleware.call = AsyncMock()

    await _ups_system_ready(middleware, 'ADDED', {'id': 'reboot'})
    middleware.call.assert_not_awaited()

    await _ups_system_ready(middleware, 'ADDED', {'id': 'ready'})
    middleware.call.assert_awaited_once_with('ups.boot_retry')


@pytest.mark.asyncio
async def test_a_failing_retry_is_logged_and_never_breaks_the_ready_event():
    middleware = Mock()
    middleware.call = AsyncMock(side_effect=RuntimeError('boom'))

    await _ups_system_ready(middleware, 'ADDED', {'id': 'ready'})

    middleware.logger.error.assert_called_once()


@pytest.mark.asyncio
async def test_setup_subscribes_to_the_system_event():
    middleware = Mock()
    middleware.call = AsyncMock()

    await ups_plugin.setup(middleware)

    middleware.event_subscribe.assert_called_once_with('system', _ups_system_ready)


@pytest.mark.asyncio
@pytest.mark.parametrize('service_state,cleared', [
    (True, True),     # service start/stop, identifier change, middlewared start
    (False, False),   # a NOTIFY event: upsmon keeps sending NOCOMM while upsd is down
])
async def test_only_the_service_hooks_clear_the_not_running_alert(service_state, cleared):
    middleware = FakeMiddleware()
    service = make_service(middleware)
    service.alerts_mapping = AsyncMock(return_value={'COMMBAD': 'UPSCommbad'})

    await service.dismiss_alerts(service_state=service_state)

    deleted = [args[1] for args in middleware.alerts if args[0] == 'alert.oneshot_delete']
    assert 'UPSCommbad' in deleted
    assert ('UPSServiceNotRunning' in deleted) is cleared


def test_comm_restored_after_the_commbad_timer_fired_is_a_notify_event():
    # the internal development record: upssched passes CANCEL-TIMER's command only when the timer has already fired, i.e.
    # when UPSCommbad was raised. A bare `COMMOK` fell through upssched_event as "unrecognized" and the alert stayed.
    from pathlib import Path
    import middlewared
    conf = Path(middlewared.__file__).parent / 'etc_files/local/nut/upssched.conf'
    commok = [line.split() for line in conf.read_text().splitlines() if line.startswith('AT COMMOK')]
    assert commok == [['AT', 'COMMOK', '*', 'CANCEL-TIMER', 'NOTIFY-COMMBAD', 'NOTIFY-COMMOK']]
