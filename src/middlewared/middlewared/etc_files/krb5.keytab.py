import base64
from contextlib import suppress
import logging
import os
import stat
import subprocess
import tempfile

from middlewared.utils.krb5 import KRB5

logger = logging.getLogger(__name__)
kdir = "/etc/kerberos"
keytabfile = "/etc/krb5.keytab"
heimdal_ktutil_cmd = "/usr/sbin/ktutil"
mit_ktutil_cmd = "/usr/bin/ktutil"


def set_mode(fd, mode):
    if stat.S_IMODE(os.fstat(fd).st_mode) != mode:
        os.fchmod(fd, mode)


def write_keytab(dirfd, db_keytabname, db_keytabfile):
    def opener(path, flags):
        return os.open(path, flags, dir_fd=dirfd, mode=0o600)

    with open(db_keytabname, "wb", opener=opener) as f:
        set_mode(f.fileno(), 0o600)
        f.write(db_keytabfile)


def merge_keytabs_heimdal(source_keytabs, destination):
    for source_keytab in source_keytabs:
        ktutil = subprocess.run([
            heimdal_ktutil_cmd, "copy", source_keytab, destination
        ], check=False, capture_output=True)

        # Heimdal ktutil copy returns 1 even when the copy succeeds. Its stderr
        # and the generated destination are the reliable failure indicators.
        if ktutil.stderr:
            raise RuntimeError(
                f'failed to merge kerberos keytab: {ktutil.stderr.decode(errors="replace").strip()}'
            )


def merge_keytabs_mit(source_keytabs, destination):
    commands = [f'rkt {source_keytab}' for source_keytab in source_keytabs]
    commands.extend((f'wkt {destination}', 'q'))
    ktutil = subprocess.run(
        [mit_ktutil_cmd],
        input=f'{os.linesep.join(commands)}{os.linesep}'.encode(),
        check=False,
        capture_output=True,
    )

    if ktutil.returncode != 0 or ktutil.stderr:
        error = ktutil.stderr.decode(errors='replace').strip()
        raise RuntimeError(f'failed to merge kerberos keytabs with MIT ktutil: {error or ktutil.returncode}')


def merge_keytabs(source_keytabs, destination):
    if KRB5.platform() == KRB5.HEIMDAL:
        merge_keytabs_heimdal(source_keytabs, destination)
    else:
        merge_keytabs_mit(source_keytabs, destination)

    if not os.path.isfile(destination) or os.path.getsize(destination) == 0:
        raise RuntimeError('kerberos keytab generation produced no output')

    os.chmod(destination, 0o600)


def render(service, middleware):
    keytabs = middleware.call_sync('kerberos.keytab.query')
    if not keytabs:
        logger.trace('No keytabs in configuration database, skipping keytab generation')
        return

    with suppress(FileExistsError):
        os.mkdir(kdir, mode=0o700)

    dirfd = None
    db_keytabnames = []
    generated_keytab = None
    try:
        dirfd = os.open(kdir, os.O_DIRECTORY)
        set_mode(dirfd, 0o700)

        for keytab in keytabs:
            db_keytabfile = base64.b64decode(keytab['file'].encode())
            db_keytabname = f'keytab_{keytab["id"]}'
            db_keytabnames.append(db_keytabname)
            write_keytab(dirfd, db_keytabname, db_keytabfile)

        fd, generated_keytab = tempfile.mkstemp(prefix='.krb5.keytab.', dir=kdir)
        os.close(fd)
        os.unlink(generated_keytab)

        merge_keytabs(
            [f'{kdir}/{db_keytabname}' for db_keytabname in db_keytabnames],
            generated_keytab,
        )
        os.replace(generated_keytab, keytabfile)
        generated_keytab = None

    finally:
        if generated_keytab is not None:
            with suppress(FileNotFoundError):
                os.unlink(generated_keytab)

        if dirfd is not None:
            for db_keytabname in db_keytabnames:
                with suppress(FileNotFoundError):
                    os.remove(db_keytabname, dir_fd=dirfd)
            os.close(dirfd)
