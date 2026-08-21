import logging
import subprocess
import uuid

import sysctl
from middlewared.service import private, Service

logger = logging.getLogger(__name__)

KLDLOAD = "/sbin/kldload"
SYSCTL = "/sbin/sysctl"


def _load_nfsd_module():
    # FreeBSD's mountd/nfsd rc scripts do this before touching vfs.nfsd.*.
    subprocess.run(
        [KLDLOAD, "nfsd"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _set_sysctl(oid, value):
    """Set a sysctl value via py-sysctl, falling back to subprocess on failure."""
    try:
        sysctl.filter(oid)[0].value = value
        return
    except (IndexError, OSError):
        pass
    cp = subprocess.run(
        [SYSCTL, f"{oid}={value}"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if cp.returncode != 0:
        logger.warning("Failed to set sysctl %r to %r using %s", oid, value, SYSCTL)


class NFSService(Service):

    class Config:
        service = "nfs"
        service_verb = "restart"
        datastore_prefix = "nfs_srv_"
        datastore_extend = 'nfs.nfs_extend'

    @private
    def setup_v4(self):
        config = self.middleware.call_sync("nfs.config")

        if config["v4"] and config["v4_krb_enabled"]:
            subprocess.run(["service", "gssd", "onerestart"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(["service", "gssd", "forcestop"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        _load_nfsd_module()

        if config["v4"]:
            if self.middleware.call_sync("failover.licensed"):
                # on HA systems, when using NFSv4, starting with (we believe) ESXi 7+,
                # the ESXi NFS client expects that the nfs server scope or owner major
                # string be the same between the controllers. If they mismatch, on failover
                # the ESXi hypervisors go into a state that, apparently, requires them to be
                # rebooted. This defeats the entire purpose of the "stateful"-ness of NFSv4.
                # To prevent this scenario from occurring, we must set these values to a
                # globally unique value between the controllers.
                # NOTE: If this is changed while nfsd is started, then problems will occur
                # so it's important that if you're reading this and decide to change it that
                # you restart the nfsd service and then have your clients unmount and remount.
                owner_major = config["v4_owner_major"]
                if not owner_major:
                    owner_major = str(uuid.uuid4())
                    # write this to the database since it shouldn't change after it's been set
                    # and has to be shared between controllers on HA systems
                    self.middleware.call_sync(
                        "datastore.update", "services.nfs", config["id"],
                        {"v4_owner_major": owner_major},
                        {"prefix": self._config.datastore_prefix},
                    )

                # setting these to the same value works for our implementation
                _set_sysctl("vfs.nfsd.scope", owner_major)
                _set_sysctl("vfs.nfsd.owner_major", owner_major)

            _set_sysctl("vfs.nfsd.server_max_nfsvers", 4)
            if config["v4_v3owner"]:
                # Per RFC7530, sending NFSv3 style UID/GIDs across the wire is now allowed
                # You must have both of these sysctl"s set to allow the desired functionality
                _set_sysctl("vfs.nfsd.enable_stringtouid", 1)
                _set_sysctl("vfs.nfs.enable_uidtostring", 1)
                subprocess.run(["service", "nfsuserd", "forcestop"], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            else:
                _set_sysctl("vfs.nfsd.enable_stringtouid", 0)
                _set_sysctl("vfs.nfs.enable_uidtostring", 0)
                subprocess.run(["service", "nfsuserd", "onerestart"], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
        else:
            _set_sysctl("vfs.nfsd.server_max_nfsvers", 3)
            if config["userd_manage_gids"]:
                subprocess.run(["service", "nfsuserd", "onerestart"], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            else:
                subprocess.run(["service", "nfsuserd", "forcestop"], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
