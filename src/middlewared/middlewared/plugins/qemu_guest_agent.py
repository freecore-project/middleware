import os

from middlewared.plugins.service_.services.qemu_guest_agent import GUEST_AGENT_CHANNEL
from middlewared.service import Service

SERVICE = 'qemu_guest_agent'

# Written once this module has switched the agent on, or found it already on. From
# then on an operator may have had a say, so the presence of the key stops this
# module from ever touching the service again: an operator's OFF stays OFF.
#
# It is deliberately NOT written while the channel is absent. A guest gets the
# channel only once its host defines it, which can happen after installation, and
# the agent should follow on the next boot rather than wait for a click.
DECISION_KEY = 'qemu_guest_agent.auto_enable'


def decide(channel_present, service_enabled, decided):
    """The one decision, kept free of I/O so every case is a plain unit test.

    Returns 'enable' (switch the service on and remember it), 'remember' (it is on
    already, only remember it) or None (nothing to do, nothing to remember).
    """
    if decided or not channel_present:
        return None
    return 'remember' if service_enabled else 'enable'


class QemuGuestAgentAutoEnableService(Service):

    class Config:
        namespace = 'qemu_guest_agent'
        private = True

    async def auto_enable(self):
        """Switch the agent on, once, on the first boot that offers it a channel.

        The inherited baseline already does this for VMware -- rc.conf turns
        vmware_guestd on whenever vmware-checkvm says so -- but that daemon has no
        service row, so nothing it overrides. This one has a boot checkbox, which is
        why the decision is taken once and remembered instead of re-applied on
        every render.
        """
        service = await self.middleware.call(
            'datastore.query', 'services.services', [['srv_service', '=', SERVICE]], {'get': True},
        )
        action = decide(
            os.path.exists(GUEST_AGENT_CHANNEL),
            service['srv_enable'],
            await self.middleware.call('keyvalue.has_key', DECISION_KEY),
        )
        if action is None:
            return None

        if action == 'enable':
            try:
                await self.middleware.call('service.update', SERVICE, {'enable': True})
            except Exception:
                # Nothing is remembered, so the next boot gets one more attempt.
                self.logger.error('Failed to enable the QEMU Guest Agent', exc_info=True)
                return None
            self.logger.info(
                'Enabled the QEMU Guest Agent: the hypervisor offers %s', GUEST_AGENT_CHANNEL,
            )

        await self.middleware.call('keyvalue.set', DECISION_KEY, action)

        if action == 'enable':
            # Boot has passed the rc scripts by now, so starting it is on us. A start
            # that fails is reported once; the service is enabled either way and the
            # decision stands, exactly as if the operator had ticked the box.
            try:
                await self.middleware.call('service.start', SERVICE)
            except Exception:
                self.logger.error('Failed to start the QEMU Guest Agent', exc_info=True)

        return action


async def _auto_enable_at_boot(middleware):
    try:
        await middleware.call('qemu_guest_agent.auto_enable')
    except Exception:
        middleware.logger.error('QEMU Guest Agent automatic enable failed', exc_info=True)


async def _event_system_ready(middleware, event_type, args):
    # Sent once per boot from the postinit rc script, not on a middlewared restart,
    # so the decision is looked at exactly when the rc scripts are done.
    if args['id'] != 'ready':
        return

    middleware.create_task(_auto_enable_at_boot(middleware))


async def setup(middleware):
    middleware.event_subscribe('system', _event_system_ready)
