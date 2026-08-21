import importlib.util
from pathlib import Path
from unittest.mock import patch

import pytest

from middlewared.plugins.service_.services.all import all_services
from middlewared.plugins.service_.services.qemu_guest_agent import (
    GUEST_AGENT_CHANNEL, QemuGuestAgentService,
)
from middlewared.service_exception import CallError


MIGRATION_PATH = (
    Path(__file__).parents[3]
    / 'alembic/versions/15.0/2026-09-10_00-00_qemu_guest_agent_service.py'
)


@pytest.fixture(scope='module')
def migration():
    spec = importlib.util.spec_from_file_location('qga_service_migration', MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_service_is_registered_under_its_datastore_name():
    registered = {service.name for service in all_services}

    assert 'qemu_guest_agent' in registered


def test_state_is_read_from_the_running_daemon_not_the_rc_script_name():
    service = QemuGuestAgentService.__new__(QemuGuestAgentService)

    # The rc script is qemu-guest-agent while the binary is qemu-ga, so matching on
    # the script name would never find the process.
    assert service.freebsd_rc == 'qemu-guest-agent'
    assert service.freebsd_procname == 'qemu-ga'
    assert service.freebsd_pidfile == '/var/run/qemu-ga.pid'
    # 'rc' has to regenerate, or qemu_guest_agent_enable never follows the setting.
    assert 'rc' in service.etc


@pytest.mark.asyncio
async def test_a_start_without_the_channel_says_what_to_do_about_it():
    service = QemuGuestAgentService.__new__(QemuGuestAgentService)

    with patch('middlewared.plugins.service_.services.qemu_guest_agent.os.path.exists',
               return_value=False):
        with pytest.raises(CallError) as error:
            await service.before_start()

    message = error.value.errmsg
    assert 'org.qemu.guest_agent.0' in message
    assert 'virtio-serial' in message
    # A system that is not a QEMU guest is told to leave it alone, not to retry.
    assert 'leave this service disabled' in message


@pytest.mark.asyncio
async def test_a_start_with_the_channel_present_is_not_refused():
    service = QemuGuestAgentService.__new__(QemuGuestAgentService)
    seen = []

    def exists(path):
        seen.append(path)
        return True

    with patch('middlewared.plugins.service_.services.qemu_guest_agent.os.path.exists', exists):
        assert await service.before_start() is None

    assert seen == [GUEST_AGENT_CHANNEL]


# The agent shipped with no service of its own, so the only way to run it at boot was
# an RC tunable. rc.conf renders tunables after service settings, so the variable has
# to change hands or the two owners disagree.
@pytest.mark.parametrize('rows,expected', [
    ([], 0),                                        # no tunable: fresh install
    ([(1, 'YES', True)], 1),                        # was starting at boot
    ([(1, 'yes', True)], 1),                        # rc.conf is not case sensitive
    ([(1, '"YES"', True)], 1),                      # stored with the quotes kept
    ([(1, 'NO', True)], 0),                         # explicitly off
    ([(1, 'YES', False)], 0),                       # disabled: never reached rc.conf
    ([(1, 'NO', True), (2, 'YES', True)], 1),       # any enabled YES wins
    ([(1, '', True)], 0),
])
def test_the_boot_setting_carries_the_meaning_of_the_tunable_it_replaces(
    migration, rows, expected,
):
    assert migration.enable_from_tunables(rows) == expected


def test_the_migration_continues_the_current_chain(migration):
    assert migration.revision == 'c5e1a7b93d24'
    assert migration.down_revision == 'd4b7e29c5a61'
