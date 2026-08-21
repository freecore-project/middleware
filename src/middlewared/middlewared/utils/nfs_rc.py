"""rc.conf(5) flags for the NFS daemons.

the internal development record: /etc/rc sources the rc.conf files once and rc.subr caches them for the whole
boot, so a bind IP that enters rc.conf.freenas only after NETWORKING (ix-nfsbind regenerates it) never
reaches rpcbind, statd, lockd, mountd or nfsd on that boot. rc.subr does re-read /etc/rc.conf.d/<script>
on every load_rc_config, so the same flags are also written there, one file per rc.d script, whenever
the 'rc' etc group is generated.
"""
import itertools

# rc.d script name -> the rc.conf variables its start reads. statd and lockd take their flags from
# statd_flags / lockd_flags, defaulted from the rpc_* variables only since FreeBSD d85e97c16f03
# ("rc.d: fix lockd and statd flags processing after svcj", 2026-06-27); on an older base the
# script's own rc_flags=${rpc_statd_flags} is clobbered by run_rc_command. Both are written so the
# bind IP reaches rpc.statd and rpc.lockd on either base.
RC_CONF_D = {
    'rpcbind': ('rpcbind_flags',),
    'statd': ('rpc_statd_flags', 'statd_flags'),
    'lockd': ('rpc_lockd_flags', 'lockd_flags'),
    'mountd': ('mountd_flags',),
    'nfsd': ('nfs_server_flags',),
}


def nfs_rc_flags(nfs, bindip):
    """{rc.conf variable: value} for the NFS daemons, in rc.conf.freenas order. rpcbind_flags is only
    present when a bind IP is set, as rc.conf.freenas has always rendered it."""
    mountd_flags = ['-rS']
    if nfs['mountd_log']:
        mountd_flags.append('-l')
    if nfs['allow_nonroot']:
        mountd_flags.append('-n')
    if nfs['mountd_port']:
        mountd_flags += ['-p', str(nfs['mountd_port'])]

    statd_flags = []
    lockd_flags = []
    if nfs['statd_lockd_log']:
        statd_flags.append('-d')
        lockd_flags += ['-d', '10']
    if nfs['rpcstatd_port']:
        statd_flags += ['-p', str(nfs['rpcstatd_port'])]
    if nfs['rpclockd_port']:
        lockd_flags += ['-p', str(nfs['rpclockd_port'])]

    nfs_server_flags = ['-t', '-n', str(nfs['servers'])]
    if not (nfs['v4'] and nfs['v4_krb_enabled']):
        nfs_server_flags.append('-S')
    if nfs['udp']:
        nfs_server_flags.append('-u')

    flags = {}
    if bindip:
        ips = list(itertools.chain(*[['-h', i] for i in bindip]))
        mountd_flags += ips
        nfs_server_flags += ips
        statd_flags += ips
        flags['rpcbind_flags'] = ' '.join(ips)
    flags['nfs_server_flags'] = ' '.join(nfs_server_flags)
    flags['rpc_statd_flags'] = ' '.join(statd_flags)
    flags['rpc_lockd_flags'] = ' '.join(lockd_flags)
    flags['mountd_flags'] = ' '.join(mountd_flags)
    return flags


def rc_conf_d_line(middleware, script):
    """The content of /etc/rc.conf.d/<script>, or None when rc.conf.freenas renders no such variable."""
    nfs = middleware.call_sync('nfs.config')
    flags = nfs_rc_flags(nfs, middleware.call_sync('nfs.bindip', nfs))
    variables = RC_CONF_D[script]
    if variables[0] not in flags:
        return None
    value = flags[variables[0]]
    return ''.join(f'{var}="{value}"\n' for var in variables)
