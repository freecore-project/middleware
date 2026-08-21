import itertools
import re
import subprocess
import sysctl as _sysctl

from middlewared.utils.io import write_if_changed

NFS_BINDIP_NOTFOUND = '/tmp/.nfsbindip_notfound'
RE_FIRMWARE_VERSION = re.compile(r'Firmware Revision\s*:\s*(\S+)', re.M)
KLDLOAD = '/sbin/kldload'
SYSCTL = '/sbin/sysctl'


def rc_conf_value(value):
    return str(value).replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')


def _load_nfsd_module():
    try:
        subprocess.run(
            [KLDLOAD, 'nfsd'],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        pass


def _set_sysctl(oid, value):
    try:
        _sysctl.filter(oid)[0].value = value
        return
    except (IndexError, OSError):
        pass

    try:
        subprocess.run(
            [SYSCTL, f'{oid}={value}'],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        pass


def get_context(middleware):
    context = {
        'is_freenas': middleware.call_sync('system.is_freenas'),
        'failover_licensed': False,
        'failover_status': 'SINGLE',
    }

    if not context['is_freenas']:
        context['failover_licensed'] = middleware.call_sync('failover.licensed')
        context['failover_status'] = middleware.call_sync('failover.status')

    return context


def collectd_config(middleware, context):
    if not context['failover_licensed'] or context['failover_status'] == 'MASTER':
        yield 'collectd_daemon_enable="YES"'
        yield 'rrdcached_enable="YES"'

        yield 'rrdcached_group="www"'
        yield 'rrdcached_address="/var/run/rrdcached.sock"'
        yield 'rrdcached_pid="/var/run/rrdcached.pid"'

        rrdcached_flags = ''
        sysds = middleware.call_sync('systemdataset.config')
        if sysds['pool'] in ('', middleware.call_sync('boot.pool_name')):
            rrdcached_flags = '-w 3600 -f 7200'
        yield f'rrdcached_flags="{rrdcached_flags}"'
    else:
        return []


def geli_config(middleware, context):
    if not context['failover_licensed'] or context['failover_status'] == 'MASTER':
        providers = []
        for ed in middleware.call_sync(
            'datastore.query',
            'storage.encrypteddisk',
            [('encrypted_volume__vol_encrypt', '=', 1)],
        ):
            providers.append(ed['encrypted_provider'])
            provider = ed['encrypted_provider'].replace('/', '_').replace('-', '_')
            key = f'/data/geli/{ed["encrypted_volume"]["vol_encryptkey"]}.key'
            yield f'geli_{provider}_flags="-p -k {key}"'
        yield f'geli_devices="{" ".join(providers)}"'
    else:
        return []


def host_config(middleware, context):
    config = middleware.call_sync('network.configuration.config')
    yield f'hostname="{config["hostname_local"]}.{config["domain"]}"'

    if config['ipv4gateway']:
        yield f'defaultrouter="{config["ipv4gateway"]}"'

    if config['ipv6gateway']:
        yield f'ipv6_defaultrouter="{config["ipv6gateway"]}"'

    if config['netwait_enabled']:
        yield 'netwait_enable="YES"'
        if not config['netwait_ip']:
            if config['ipv4gateway']:
                config['netwait_ip'] = config['ipv4gateway']
            elif config['ipv6gateway']:
                config['netwait_ip'] = config['ipv6gateway']
        else:
            config['netwait_ip'] = ' '.join(config["netwait_ip"])

        yield f'netwait_ip="{config["netwait_ip"]}"'


def kbdmap_config(middleware, context):
    general = middleware.call_sync('system.general.config')
    if general['kbdmap']:
        yield f'keymap="{general["kbdmap"]}"'
    else:
        return []


def ldap_config(middleware, context):
    ldap = middleware.call_sync('datastore.config', 'directoryservice.ldap', {'prefix': 'ldap_'})
    yield f'nslcd_enable="{"YES" if ldap["enable"] else "NO"}"'


def lldp_config(middleware, context):
    lldp = middleware.call_sync('lldp.config')
    ladvd_flags = ['-a']
    if lldp['intdesc']:
        ladvd_flags.append('-z')
    if lldp['country']:
        ladvd_flags += ['-c', lldp['country']]
    if lldp['location']:
        ladvd_flags += ['-l', rf'\"{lldp["location"]}\"']
    yield f'ladvd_flags="{" ".join(ladvd_flags)}"'


def service_announcement(middleware, context):
    announce = middleware.call_sync("network.configuration.config")["service_announcement"]
    yield f'nmbd_enable="{"YES" if announce["netbios"] else "NO"}"'
    yield f'avahi_daemon_enable="{"YES" if announce["mdns"] else "NO"}"'
    yield f'wsdd_enable="{"YES" if announce["wsd"] else "NO"}"'


def wsdd_config(middleware, context):
    announce = middleware.call_sync("network.configuration.config")["service_announcement"]
    if not announce["wsd"]:
        return []

    smb_config = middleware.call_sync("smb.config")
    interfaces = smb_config["bindip"] or list(middleware.call_sync("smb.bindip_choices").values())

    flags = []
    if smb_config["netbiosname_local"]:
        flags += ["-n", smb_config["netbiosname_local"]]
    for interface in interfaces:
        flags += ["-i", interface]

    if flags:
        yield f'wsdd_flags="{rc_conf_value(" ".join(flags))}"'

    try:
        realm = middleware.call_sync("smb.getparm", "realm", "GLOBAL")
    except Exception:
        middleware.logger.debug("Failed to read SMB realm for wsdd rc configuration", exc_info=True)
        realm = None

    if realm:
        yield f'wsdd_domain="{rc_conf_value(realm)}"'
    else:
        yield f'wsdd_group="{rc_conf_value(smb_config["workgroup"])}"'


def samba_daemons_config(middleware, context):
    # samba_server rc.d reads smbd_enable / winbindd_enable / nmbd_enable to
    # decide which of the three to launch. smbd + winbindd are always-on (the
    # cifs service lifecycle is middleware-controlled via forcestart).
    # nmbd_enable is emitted by service_announcement based on announce[netbios].
    yield 'smbd_enable="YES"'
    yield 'winbindd_enable="YES"'


def services_config(middleware, context):
    services = middleware.call_sync('datastore.query', 'services.services', [], {'prefix': 'srv_'})

    """
    JIRA NAS-103496
    These daemons should be configured to start in the following scenarios:
        1. FreeNAS systems
        2. TrueNAS single controller systems
        3. ONLY TrueNAS ACTIVE controllers in HA systems
    """
    mapping = {}
    if not context['failover_licensed'] or context['failover_status'] == 'MASTER':
        mapping = {
            'afp': ['netatalk'],
            'dynamicdns': ['inadyn'],
            'ftp': ['proftpd'],
            'rar2fs': ['rar2fs'],
            'rsync': ['rsyncd'],
            'wireguard': ['wireguard_server'],
            'wireguard_client': ['wireguard_client'],
            'snmp': ['snmpd', 'snmp_agent'],
            'tftp': ['inetd'],
            'webdav': ['apache24'],
            'nfs': ['nfs_server', 'rpc_lockd', 'rpc_statd', 'mountd', 'nfsd', 'rpcbind'],
            'smartd': ['smartd_daemon']
        }

    """
    JIRA NAS-103496
    These daemons should be configured to start in the following scenarios:
        1. FreeNAS systems
        2. TrueNAS single controller systems
        3. On BOTH controllers in TrueNAS HA systems
    """
    mapping.update({
        'cifs': ['samba_server'],
        'iscsitarget': ['ctld'],
        'lldp': ['ladvd'],
        'ssh': ['openssh'],
        # Per-daemon smbd/winbindd rcvars are emitted by
        # samba_daemons_config; nmbd_enable by service_announcement.
    })

    for service in services:
        rcs_enable = mapping.get(service['service'])
        if not rcs_enable:
            continue
        value = 'YES' if service['enable'] else 'NO'
        for rc_enable in rcs_enable:
            yield f'{rc_enable}_enable="{value}"'


def nfs_config(middleware, context):
    # nfs.extend() method checks contents of keytab for
    # nfs service principal name entries. Ensure that
    # system keytab is generated before this point.
    middleware.call_sync('etc.generate', 'kerberos')
    nfs = middleware.call_sync('nfs.config')

    mountd_flags = ['-rS']
    if nfs['mountd_log']:
        mountd_flags.append('-l')
    if nfs['allow_nonroot']:
        mountd_flags.append('-n')
    if nfs['mountd_port']:
        mountd_flags += ['-p', str(nfs['mountd_port'])]

    statd_flags = []
    lockd_flags = []
    nfsuserd_flags = []
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

    """
    Make sure the IPs exist before we try to bind the NFS service to them
    Redmine 16044
    """
    bindip = middleware.call_sync('nfs.bindip', nfs)
    if bindip:
        ips = list(itertools.chain(*[['-h', i] for i in bindip]))
        mountd_flags += ips
        nfs_server_flags += ips
        statd_flags += ips
        yield f'rpcbind_flags="{" ".join(ips)}"'

    yield f'nfs_server_flags="{" ".join(nfs_server_flags)}"'
    yield f'rpc_statd_flags="{" ".join(statd_flags)}"'
    yield f'rpc_lockd_flags="{" ".join(lockd_flags)}"'
    yield f'mountd_flags="{" ".join(mountd_flags)}"'

    if not context['failover_licensed'] or context['failover_status'] == 'MASTER':
        enabled = middleware.call_sync(
            'datastore.query', 'services.services', [
                ('srv_service', '=', 'nfs'), ('srv_enable', '=', True),
            ]
        )
    else:
        enabled = False

    if nfs['userd_manage_gids']:
        nfsuserd_flags.append('-manage-gids')

    if nfs['v4']:
        yield 'nfsv4_server_enable="YES"'
        _load_nfsd_module()

        if nfs['v4_krb_enabled']:
            if enabled:
                yield 'gssd_enable="YES"'

            gc = middleware.call_sync("network.configuration.config")
            if gc.get("hostname_virtual") and gc["domain"]:
                yield f'nfs_server_vhost="{gc["hostname_virtual"]}.{gc["domain"]}"'

        if nfs['v4_v3owner']:
            # Per RFC7530, sending NFSv3 style UID/GIDs across the wire is now allowed
            # You must have both of these sysctl's set to allow the desired functionality
            for oid, val in [('vfs.nfsd.enable_stringtouid', 1), ('vfs.nfs.enable_uidtostring', 1)]:
                _set_sysctl(oid, val)
        else:
            for oid in ('vfs.nfsd.enable_stringtouid', 'vfs.nfs.enable_uidtostring'):
                _set_sysctl(oid, 0)
            if nfs['v4_domain']:
                nfsuserd_flags.append(f"-domain {nfs['v4_domain']}")

    if nfsuserd_flags and enabled:
        yield 'nfsuserd_enable="YES"'
        yield f"nfsuserd_flags=\"{' '.join(nfsuserd_flags)}\""

    elif enabled and nfs['v4'] and not nfs['v4_v3owner']:
        yield 'nfsuserd_enable="YES"'


def nis_config(middleware, context):
    nis = middleware.call_sync('datastore.config', 'directoryservice.nis', {'prefix': 'nis_'})
    if not nis['enable'] or not nis['domain']:
        return []

    domain = nis['domain']
    if nis['servers']:
        domain += ',' + nis['servers']

    yield f'nisdomainname="{nis["domain"]}"'
    yield 'nis_client_enable="YES"'

    flags = ['-S', domain]
    if nis['secure_mode']:
        flags.append('-s')
    if nis['manycast']:
        flags.append('-m')
    yield f'nis_client_flags="{" ".join(flags)}"'


def nut_config(middleware, context):
    enabled = middleware.call_sync(
        'datastore.query', 'services.services', [
            ('srv_service', '=', 'ups'), ('srv_enable', '=', True),
        ]
    )
    # FIXME: UPS will only work if "Start on boot" is enabled
    if not enabled:
        return []

    ups = middleware.call_sync('ups.config')
    if ups['mode'] == 'MASTER':
        yield 'nut_enable="YES"'
        yield f'nut_upslog_ups="{ups["identifier"]}"'
    else:
        yield f'nut_upslog_ups="{ups["identifier"]}@{ups["remotehost"]}:{ups["remoteport"]}"'
    yield 'nut_upslog_enable="YES"'
    yield 'nut_upsmon_enable="YES"'


def powerd_config(middleware, context):
    value = 'YES' if middleware.call_sync('system.advanced.config')['powerdaemon'] else 'NO'
    yield f'powerd_enable="{value}"'


def smart_config(middleware, context):
    smart = middleware.call_sync('smart.config')
    yield f'smartd_daemon_flags="-i {smart["interval"] * 60}"'


def snmp_config(middleware, context):
    yield 'snmpd_conffile="/etc/local/snmpd.conf"'
    loglevel = middleware.call_sync('snmp.config')['loglevel']
    yield f'snmpd_flags="-LS{loglevel}d"'
    # net-snmp 5.9.5.2's rc.d script defaults snmpd_sugid=YES and then passes
    # "-u snmpd -g snmpd", but the appliance has no snmpd account: builtin users
    # come from the middleware DB, and the internal development record deliberately refused to add one there.
    # 13.3 shipped net-snmp 5.9.1, whose rc.d script has no sugid handling at all,
    # so snmpd ran as root. Keep that behaviour rather than diverging the user model.
    yield 'snmpd_sugid="NO"'


def staticroute_config(middleware, context):
    ipv4_routes = []
    ipv6_routes = []
    for sr in middleware.call_sync('staticroute.query'):
        route = f'freenas{sr["id"]}'
        if ':' in sr['destination']:
            ipv6_routes.append(route)
            rcprefix = 'ipv6_'
        else:
            ipv4_routes.append(route)
            rcprefix = ''
        yield f'{rcprefix}route_{route}="-net {sr["destination"]} {sr["gateway"]}"'
    if ipv4_routes:
        yield f'static_routes="{" ".join(ipv4_routes)}"'
    if ipv6_routes:
        yield f'ipv6_static_routes="{" ".join(ipv6_routes)}"'


def tftp_config(middleware, context):
    tftp = middleware.call_sync('tftp.config')
    yield f'inetd_flags="-wW -C 60 -a {tftp["host"]}"'


def truenas_config(middleware, context):
    if context['is_freenas'] or not context['failover_licensed']:
        yield 'failover_enable="NO"'
    else:
        yield 'failover_enable="YES"'


# wireguard_config() used to live here as the sole owner of wireguard_interfaces,
# emitting wg0 for the TrueCommand Cloud tunnel. TrueCommand Cloud is gone
# (freecore/the internal development record) and wg0 with it (the internal development record), so nothing writes
# wireguard_interfaces any more: wg1 is named by wireguard_server_interface and wg2
# by wireguard_client_interface, each owned by its own rc script (the internal development record, the internal development record).
# Do not reintroduce wireguard_interfaces to start wg1 or wg2 -- the
# net/wireguard-tools rc script it feeds acts on every listed interface at once, so
# it cannot give either one an independent lifecycle, and its start never returns on
# FreeBSD 15.


def tunable_config(middleware, context):
    for tun in middleware.call_sync('tunable.query', [
        ('type', '=', 'RC'), ('enabled', '=', True)
    ]):
        yield f'{tun["var"]}="{tun["value"]}"'
    return []


def vmware_config(middleware, context):
    if context['is_freenas']:
        try:
            subprocess.run(
                ['vmware-checkvm'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
        except subprocess.CalledProcessError:
            yield 'vmware_guestd_enable="NO"'
        except Exception:
            middleware.logger.warn('Failed to run vmware-checkvm', exc_info=True)
            return []
        else:
            yield 'vmware_guestd_enable="YES"'


def _bmc_watchdog_is_broken():
    cp = subprocess.run(['ipmitool', 'mc', 'info'], capture_output=True, errors='ignore')
    reg = RE_FIRMWARE_VERSION.search(cp.stdout)
    if not reg:
        return False

    version = reg.group(1).split('.')
    if len(version) > 2:
        return False

    try:
        return [int(i) for i in version[:2]] < [0, 30]
    except ValueError:
        return False


def watchdog_config(middleware, context):
    if context['is_freenas']:
        # Bug the internal development record -- blacklist AMD systems for now
        model = _sysctl.filter('hw.model')
        model_value = model[0].value if model else ''
        if 'AMD' not in model_value:
            product = middleware.call_sync('system.dmidecode_info')['baseboard-product-name']

            if product in ('C2750D4I', 'C2550D4I') and _bmc_watchdog_is_broken():
                return [
                    'watchdogd_enable="YES"',
                    'watchdogd_flags="-t 30 --softtimeout --softtimeout-action log,printf '
                    '--pretimeout 15 --pretimeout-action log,printf -e \'sleep 1\' -w -T 3"',
                ]
            elif product not in ('X9DR3-F', 'X9DR3-LN4F+'):
                return [
                    'watchdogd_enable="YES"',
                    'watchdogd_flags="--pretimeout 5 --pretimeout-action log,printf"',
                ]
    return ['watchdogd_enable="NO"']


def zfs_config(middleware, context):
    if middleware.call_sync('datastore.query', 'storage.volume'):
        yield 'zfs_enable="YES"'


def render(service, middleware):

    context = get_context(middleware)

    rcs = []
    for i in (
        services_config,
        service_announcement,
        wsdd_config,
        samba_daemons_config,
        collectd_config,
        geli_config,
        host_config,
        kbdmap_config,
        ldap_config,
        lldp_config,
        nfs_config,
        nis_config,
        nut_config,
        powerd_config,
        smart_config,
        snmp_config,
        staticroute_config,
        tftp_config,
        truenas_config,
        vmware_config,
        watchdog_config,
        zfs_config,
        tunable_config,
    ):
        try:
            rcs += list(i(middleware, context))
        except Exception:
            middleware.logger.error('Failed to generate %s', i.__name__, exc_info=True)

    write_if_changed('/etc/rc.conf.freenas', '\n'.join(rcs) + '\n')
