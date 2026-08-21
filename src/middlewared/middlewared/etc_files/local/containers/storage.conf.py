"""the internal development record: the host's podman finds the Applications store as root.

containers/storage has no drop-in directory, so while the Applications runtime is
ready the system storage.conf is the pool's storage.conf, byte for byte. Otherwise
it is the containers-common package's @sample copy again, so a box without
Applications stays stock, and it is absent when the package ships no sample.
Middleware's own podman keeps its CONTAINERS_STORAGE_CONF, which names the same
content; this file is for everyone else.
"""
from middlewared.plugins.applications_.utils import (
    HOST_STORAGE_CONF_SAMPLE,
    host_podman_ready,
    render_storage_conf,
)
from middlewared.plugins.etc import FileShouldNotExist


def render(service, middleware):
    config = middleware.call_sync('applications.config')
    if host_podman_ready(config):
        return render_storage_conf(config['pool'])
    try:
        with open(HOST_STORAGE_CONF_SAMPLE, encoding='utf8') as sample:
            return sample.read()
    except FileNotFoundError:
        raise FileShouldNotExist() from None
