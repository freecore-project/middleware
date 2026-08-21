# /etc/rc.conf.d/nfsd — the internal development record: the NFS flags /etc/rc re-reads after ix-nfsbind.
# See middlewared/utils/nfs_rc.py.
from middlewared.plugins.etc import FileShouldNotExist
from middlewared.utils.nfs_rc import rc_conf_d_line


def render(service, middleware):
    line = rc_conf_d_line(middleware, 'nfsd')
    if line is None:
        raise FileShouldNotExist()
    return line
