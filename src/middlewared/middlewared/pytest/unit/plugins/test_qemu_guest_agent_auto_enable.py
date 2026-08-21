from unittest.mock import Mock, patch

import pytest

from middlewared.plugins.qemu_guest_agent import (
    DECISION_KEY, SERVICE, QemuGuestAgentAutoEnableService, _event_system_ready, decide,
)
from middlewared.plugins.service_.services.qemu_guest_agent import GUEST_AGENT_CHANNEL

CHANNEL_EXISTS = 'middlewared.plugins.qemu_guest_agent.os.path.exists'


# The channel is the only detection: a host that defines it is asking for the agent,
# and one that does not cannot run it whatever the hardware says. A remembered
# decision beats everything, so an operator's OFF is never undone.
@pytest.mark.parametrize('channel,enabled,decided,expected', [
    (True, False, False, 'enable'),       # fresh guest with the channel: switch it on
    (True, True, False, 'remember'),      # already on (tunable migration, or by hand): only remember
    (True, False, True, None),            # decided before, since turned off: leave it
    (True, True, True, None),             # decided before, still on: nothing to do
    (False, False, False, None),          # no channel: bare metal, bhyve, VMware, Xen
    (False, True, False, None),           # no channel but enabled by hand: not ours to touch
    (False, False, True, None),
])
def test_the_decision(channel, enabled, decided, expected):
    assert decide(channel, enabled, decided) == expected


class FakeMiddleware:
    """Answers the calls auto_enable makes and records the ones that change state."""

    def __init__(self, enabled, decided, fail=()):
        self.enabled = enabled
        self.decided = decided
        self.fail = fail
        self.calls = []

    async def call(self, method, *args):
        if method in self.fail:
            raise RuntimeError(method)
        if method == 'datastore.query':
            assert args[0] == 'services.services'
            assert args[1] == [['srv_service', '=', SERVICE]]
            return {'id': 21, 'srv_service': SERVICE, 'srv_enable': self.enabled}
        if method == 'keyvalue.has_key':
            assert args == (DECISION_KEY,)
            return self.decided
        self.calls.append((method, *args))


def service(enabled, decided, fail=()):
    return QemuGuestAgentAutoEnableService(FakeMiddleware(enabled, decided, fail))


@pytest.mark.asyncio
async def test_a_guest_with_the_channel_gets_the_agent_enabled_started_and_remembered():
    s = service(enabled=False, decided=False)

    with patch(CHANNEL_EXISTS, return_value=True):
        assert await s.auto_enable() == 'enable'

    # Enable first (that regenerates rc.conf), remember, then start: the memory is
    # written before the start so a failing start cannot cause a second attempt.
    assert s.middleware.calls == [
        ('service.update', SERVICE, {'enable': True}),
        ('keyvalue.set', DECISION_KEY, 'enable'),
        ('service.start', SERVICE),
    ]


@pytest.mark.asyncio
async def test_an_agent_already_on_is_only_remembered():
    s = service(enabled=True, decided=False)

    with patch(CHANNEL_EXISTS, return_value=True):
        assert await s.auto_enable() == 'remember'

    assert s.middleware.calls == [('keyvalue.set', DECISION_KEY, 'remember')]


@pytest.mark.asyncio
async def test_a_remembered_decision_is_never_revisited():
    # The operator turned it off after it was enabled for them: that is final.
    s = service(enabled=False, decided=True)

    with patch(CHANNEL_EXISTS, return_value=True):
        assert await s.auto_enable() is None

    assert s.middleware.calls == []


@pytest.mark.asyncio
async def test_a_guest_without_the_channel_is_left_alone_and_nothing_is_remembered():
    s = service(enabled=False, decided=False)
    seen = []

    def exists(path):
        seen.append(path)
        return False

    with patch(CHANNEL_EXISTS, exists):
        assert await s.auto_enable() is None

    assert seen == [GUEST_AGENT_CHANNEL]
    # No key: the channel may be added to the VM later, and the next boot must look again.
    assert s.middleware.calls == []


@pytest.mark.asyncio
async def test_a_failed_enable_remembers_nothing_and_does_not_start():
    s = service(enabled=False, decided=False, fail=('service.update',))
    s.logger = Mock()

    with patch(CHANNEL_EXISTS, return_value=True):
        assert await s.auto_enable() is None

    assert s.middleware.calls == []
    s.logger.error.assert_called_once()


@pytest.mark.asyncio
async def test_a_failed_start_still_leaves_the_service_enabled_and_the_decision_made():
    s = service(enabled=False, decided=False, fail=('service.start',))
    s.logger = Mock()

    with patch(CHANNEL_EXISTS, return_value=True):
        assert await s.auto_enable() == 'enable'

    assert s.middleware.calls == [
        ('service.update', SERVICE, {'enable': True}),
        ('keyvalue.set', DECISION_KEY, 'enable'),
    ]
    s.logger.error.assert_called_once()


@pytest.mark.asyncio
async def test_only_the_boot_ready_event_triggers_the_decision():
    middleware = Mock()

    await _event_system_ready(middleware, 'ADDED', {'id': 'shutdown'})
    middleware.create_task.assert_not_called()

    await _event_system_ready(middleware, 'ADDED', {'id': 'ready'})
    middleware.create_task.assert_called_once()
    # Close the coroutine handed to create_task; the mock never runs it.
    middleware.create_task.call_args.args[0].close()
