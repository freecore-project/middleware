import os

import libvirt

from middlewared.service import CallError

from .arch import BHYVE, QEMU, LIBVIRT_QEMU_DRIVER

# One libvirtd, two drivers.  Both URIs are served from the monolithic daemon's socket;
# naming it keeps the remote driver from probing for the modular virtqemud socket that
# this system does not run.  the internal development record
LIBVIRT_SOCKET = '/var/run/libvirt/libvirt-sock'
LIBVIRT_URI = f'{BHYVE}+unix:///system'
LIBVIRT_URIS = {
    BHYVE: LIBVIRT_URI,
    QEMU: f'{QEMU}+unix:///system?socket={LIBVIRT_SOCKET}',
}


class LibvirtConnectionMixin:

    # The bhyve connection, under the name the rest of the plugin has always used.
    LIBVIRT_CONNECTION = None
    # hypervisor -> connection; only drivers the daemon was built with are present.
    LIBVIRT_CONNECTIONS = {}

    def _open(self):
        connections = {}
        try:
            # We want to do this before initializing libvirt connection
            libvirt.virEventRegisterDefaultImpl()
            connections[BHYVE] = libvirt.open(LIBVIRT_URIS[BHYVE])
        except libvirt.libvirtError as e:
            raise CallError(f'Failed to open libvirt connection: {e}')

        if os.path.exists(LIBVIRT_QEMU_DRIVER):
            try:
                connections[QEMU] = libvirt.open(LIBVIRT_URIS[QEMU])
            except libvirt.libvirtError as e:
                # The bhyve lane must not depend on the emulated one.
                logger = getattr(getattr(self, 'middleware', None), 'logger', None)
                if logger:
                    logger.warning('Emulated guest lane unavailable, QEMU driver connection failed: %s', e)

        LibvirtConnectionMixin.LIBVIRT_CONNECTIONS = connections
        LibvirtConnectionMixin.LIBVIRT_CONNECTION = connections[BHYVE]

    def _close(self):
        errors = []
        for hypervisor, connection in list(LibvirtConnectionMixin.LIBVIRT_CONNECTIONS.items()):
            try:
                connection.close()
            except libvirt.libvirtError as e:
                errors.append(f'{hypervisor}: {e}')
        LibvirtConnectionMixin.LIBVIRT_CONNECTIONS = {}
        LibvirtConnectionMixin.LIBVIRT_CONNECTION = None
        if errors:
            raise CallError(f'Failed to close libvirt connection: {"; ".join(errors)}')

    def _is_connection_alive(self):
        return LibvirtConnectionMixin.LIBVIRT_CONNECTION and LibvirtConnectionMixin.LIBVIRT_CONNECTION.isAlive()

    def _check_connection_alive(self):
        if not self._is_connection_alive():
            raise CallError('Failed to connect to libvirt')

    def _check_setup_connection(self):
        if not self._is_connection_alive():
            self.middleware.call_sync('vm.wait_for_libvirtd', 10)
        self._check_connection_alive()

    def _connection_for(self, hypervisor):
        connection = LibvirtConnectionMixin.LIBVIRT_CONNECTIONS.get(hypervisor)
        if connection is None:
            if hypervisor == QEMU:
                raise CallError(
                    'The emulated guest lane is not available: libvirt on this system has no QEMU driver.'
                )
            raise CallError(f'No libvirt connection for the {hypervisor} driver')
        return connection
