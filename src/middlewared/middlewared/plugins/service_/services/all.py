from .afp import AFPService
from .cifs import CIFSService
from .dynamicdns import DynamicDNSService
from .ftp import FTPService
from .iscsitarget import ISCSITargetService
from .lldp import LLDPService
from .mdns import MDNSService
from .netbios import NetBIOSService
from .nfs import NFSService
from .rar2fs import Rar2fsService
from .rsync import RsyncService
from .smartd import SMARTDService
from .snmp import SNMPService
from .ssh import SSHService
from .tftp import TFTPService
from .ups import UPSService
from .webdav import WebDAVService
from .wireguard import WireguardService
from .wireguard_client import WireguardClientService
from .wsd import WSDService
from .routing import RoutingService
from .hostname import HostnameService

from .pseudo.ad import ActiveDirectoryService, LdapService, NisService
from .pseudo.collectd import CollectDService, RRDCacheDService
from .pseudo.libvirtd import LibvirtdService
from .pseudo.misc import (
    CronService,
    DiskService,
    FailoverService,
    LoaderService,
    MOTDService,
    HttpService,
    NetworkService,
    NetworkGeneralService,
    NtpdService,
    PowerdService,
    RcService,
    ResolvConfService,
    SslService,
    VtService,
    SysctlService,
    SyslogdService,
    SystemService,
    SystemDatasetsService,
    TimeservicesService,
    TtysService,
    UserService,
)

all_services = [
    AFPService,
    CIFSService,
    DynamicDNSService,
    FTPService,
    ISCSITargetService,
    LLDPService,
    MDNSService,
    NetBIOSService,
    NFSService,
    Rar2fsService,
    RsyncService,
    SMARTDService,
    SNMPService,
    SSHService,
    TFTPService,
    UPSService,
    WebDAVService,
    WireguardService,
    WireguardClientService,
    WSDService,
    ActiveDirectoryService,
    LdapService,
    NisService,
    CollectDService,
    RRDCacheDService,
    LibvirtdService,
    CronService,
    DiskService,
    FailoverService,
    LoaderService,
    MOTDService,
    HostnameService,
    HttpService,
    NetworkService,
    NetworkGeneralService,
    NtpdService,
    PowerdService,
    RcService,
    ResolvConfService,
    RoutingService,
    SslService,
    VtService,
    SysctlService,
    SyslogdService,
    SystemService,
    SystemDatasetsService,
    TimeservicesService,
    TtysService,
    UserService,
]
