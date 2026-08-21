"""the internal development record: an unaided `bastille` finds the data pool on every boot.

The pointer block of the internal development record used to be written only by
`bastille.configure` and mirrored into the /conf/base seed (#451). A reboot kept
it; an upgrade did not, because a new boot environment ships the package's stock
file, so the CLI lost the pool after every build until Configure was clicked
again. Rendering the block from the `rc` etc group makes it part of the same
regeneration as the rc.conf bastille lines: at the initial checkpoint of every
boot and on every pool transition.

Everything outside the block is the administrator's and is preserved byte for
byte: the live file is read back and the block applied for the configured pool,
or stripped when no pool is configured. A box without a live file starts from
the package sample, as bastille itself would; a box with neither has no bastille,
and no file is written.
"""
from middlewared.plugins.bastille_.utils import apply_config_pointer, read_cli_config_source
from middlewared.plugins.etc import FileShouldNotExist


def render(service, middleware):
    config = middleware.call_sync('bastille.rc_config')
    source = read_cli_config_source()
    if source is None:
        raise FileShouldNotExist()
    return apply_config_pointer(source, config.get('pool') or None)
