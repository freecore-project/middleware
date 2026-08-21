from .base import SimpleService


class NFSService(SimpleService):
    name = "nfs"
    reloadable = True

    etc = ["nfsd"]

    freebsd_rc = "nfsd"

    systemd_unit = "nfs-ganesha"

    async def _ensure_gssd_freebsd(self):
        # FreeBSD 15 nfsd only needs gssd for Kerberos exports. Non-Kerberos
        # exports run with nfsd -S and should leave gssd stopped.
        nfs = await self.middleware.call("nfs.config")
        if not (nfs["v4"] and nfs["v4_krb_enabled"]):
            return

        gssd = await self._freebsd_service("gssd", "status")
        if gssd.returncode != 0:
            await self._freebsd_service("gssd", "start")

    async def _start_freebsd(self):
        await self._freebsd_service("rpcbind", "start")
        await self.middleware.call("nfs.setup_v4")
        await self._ensure_gssd_freebsd()
        await self._freebsd_service("mountd", "start")
        await self._freebsd_service("nfsd", "start")
        await self._freebsd_service("statd", "start")
        await self._freebsd_service("lockd", "start")

        if (await self.middleware.call("nis.get_state")) != 'DISABLED':
            try:
                await self.middleware.call("nis.started")
            except Exception:
                await self.middleware.call("service.restart", "nis")

    async def _stop_freebsd(self):
        await self._freebsd_service("lockd", "stop", force=True)
        await self._freebsd_service("statd", "stop", force=True)
        await self._freebsd_service("nfsd", "stop", force=True)
        await self._freebsd_service("mountd", "stop", force=True)
        await self._freebsd_service("nfsuserd", "stop", force=True)
        await self._freebsd_service("gssd", "stop", force=True)
        if (await self.middleware.call("nis.get_state")) == 'DISABLED':
            await self._freebsd_service("rpcbind", "stop", force=True)

    async def _reload_freebsd(self):
        await self.middleware.call("nfs.setup_v4")
        await self._ensure_gssd_freebsd()
        await self._freebsd_service("mountd", "reload", force=True)

    async def _stop_linux(self):
        await self._systemd_unit("nfs-ganesha-lock", "stop")
        await super()._stop_linux()
