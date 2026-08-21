"""the internal development record: the host's podman uses the Applications network and event log.

A containers.conf drop-in, present only while the Applications runtime is ready,
byte for byte the pool's containers.conf. It layers on the package's own
containers.conf (the ocijail runtime), and middleware's CONTAINERS_CONF_OVERRIDE,
which names the same content, still loads last.
"""
from middlewared.plugins.applications_.utils import host_podman_ready, render_containers_conf
from middlewared.plugins.etc import FileShouldNotExist


def render(service, middleware):
    config = middleware.call_sync('applications.config')
    if not host_podman_ready(config):
        raise FileShouldNotExist()
    return render_containers_conf(config['pool'], config['subnet'])
