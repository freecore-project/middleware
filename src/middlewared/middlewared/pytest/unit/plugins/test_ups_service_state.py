# the internal development record (Codeberg freecore#111): the UPS service is RUNNING only when
# the local upsd is up too, not on the upsmon pid alone.
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from middlewared.plugins.service_.services import base_freebsd
from middlewared.plugins.service_.services import ups as ups_service
from middlewared.plugins.service_.services.ups import UPSD_PIDFILE, UPSService

PIDFILES = {'upsmon': '/var/db/nut/upsmon.pid', 'upsd': UPSD_PIDFILE}


class FakeMiddleware:
    def __init__(self, mode):
        self.mode = mode
        self.calls = []

    async def call(self, method, *args):
        self.calls.append(method)
        assert method == 'ups.config'
        return {'mode': self.mode}


def pgrep(alive, seen):
    """A `run` stand-in answering `pgrep -F <pidfile> <procname>` from `alive`."""
    async def run(*args, **kwargs):
        assert args[:2] == ('pgrep', '-F')
        pidfile, procname = args[2], args[3]
        assert pidfile == PIDFILES[procname]
        seen.append(procname)
        pid = alive.get(procname)
        if pid is None:
            return SimpleNamespace(returncode=1, stdout='')
        return SimpleNamespace(returncode=0, stdout=f'{pid}\n')
    return run


async def state(mode, alive):
    seen = []
    middleware = FakeMiddleware(mode)
    run = pgrep(alive, seen)
    with patch.object(base_freebsd, 'run', run), patch.object(ups_service, 'run', run):
        result = await UPSService(middleware)._get_state_freebsd()
    return result, seen, middleware.calls


@pytest.mark.asyncio
async def test_upsmon_without_upsd_is_not_running_in_master_mode():
    # The reporter's boot: the driver failed in the nut precmd, rc skipped upsd, and
    # upsmon/upslog started anyway. This used to read RUNNING with pids=[upsmon].
    result, seen, _ = await state('MASTER', {'upsmon': 2337})

    assert result.running is False
    assert result.pids == []
    assert seen == ['upsmon', 'upsd']


@pytest.mark.asyncio
async def test_upsmon_and_upsd_are_running_with_both_pids():
    result, _, _ = await state('MASTER', {'upsmon': 4801, 'upsd': 4875})

    assert result.running is True
    assert result.pids == [4801, 4875]


@pytest.mark.asyncio
async def test_no_upsmon_is_stopped_without_looking_any_further():
    result, seen, calls = await state('MASTER', {'upsd': 4875})

    assert result.running is False
    assert seen == ['upsmon']
    assert calls == []


@pytest.mark.asyncio
async def test_slave_mode_has_no_local_upsd_and_keeps_the_upsmon_check():
    result, seen, _ = await state('SLAVE', {'upsmon': 2337})

    assert result.running is True
    assert result.pids == [2337]
    assert seen == ['upsmon']
