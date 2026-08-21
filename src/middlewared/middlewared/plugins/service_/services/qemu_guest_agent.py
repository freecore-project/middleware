import os

from middlewared.service_exception import CallError

from .base import SimpleService

# The agent is not a network daemon: it speaks to the hypervisor over one
# virtio-serial channel, and without it qemu-ga has nothing to attach to. A guest
# only has the device once its host defines the channel, so its presence is the
# honest test for "is this a QEMU/KVM guest that can run the agent".
GUEST_AGENT_CHANNEL = '/dev/vtcon/org.qemu.guest_agent.0'


class QemuGuestAgentService(SimpleService):
    name = 'qemu_guest_agent'

    # 'rc' is required so that toggling the service regenerates rc.conf and
    # qemu_guest_agent_enable follows the service setting. the internal development record
    # introduced the agent through an RC tunable, and rc.conf renders tunables
    # *after* service-generated settings -- so without the service owning the
    # variable, a leftover tunable would silently win over the boot checkbox.
    etc = ['rc']

    freebsd_rc = 'qemu-guest-agent'

    # The port's script writes this pidfile and runs the binary under its own
    # name, so state is a direct question about the running daemon rather than a
    # guess from the rc script name.
    freebsd_pidfile = '/var/run/qemu-ga.pid'
    freebsd_procname = 'qemu-ga'

    async def before_start(self):
        if not os.path.exists(GUEST_AGENT_CHANNEL):
            # Raising here rather than starting and failing follows rar2fs: a
            # service that cannot possibly work says so once, with the thing the
            # operator has to go and do. It is listed in the api2 suite's
            # OPTIONAL_UNCONFIGURED_SERVICES for the same reason rar2fs is.
            raise CallError(
                'This system has no QEMU guest agent channel, so the agent has nothing '
                'to attach to. On the hypervisor, add a virtio-serial channel named '
                'org.qemu.guest_agent.0 to this virtual machine and reboot it. On a '
                'system that is not a QEMU or KVM guest, leave this service disabled.'
            )
