import os
import subprocess


def reconcile_hostname_link(pwd, hostname):
    localhost_path = os.path.join(pwd, 'localhost')
    hostname_path = os.path.join(pwd, hostname)

    for item in os.listdir(pwd):
        if item == 'localhost' or item.startswith('localhost.bak.'):
            continue

        path = os.path.join(pwd, item)

        if (
            item == hostname and
            os.path.islink(path) and
            os.path.realpath(path) == os.path.realpath(localhost_path)
        ):
            continue

        if os.path.islink(path):
            # Remove all symlinks that are stale if hostname was changed.
            os.unlink(path)
        elif os.path.isdir(path):
            # Remove all directories except "localhost" and its backups (that may be erroneously created by
            # running collectd before this script).
            subprocess.run(['rm', '-rfx', path])
        else:
            os.unlink(path)

    if not os.path.exists(localhost_path):
        os.makedirs(localhost_path)

    if hostname == 'localhost':
        return

    if os.path.islink(hostname_path) and os.path.realpath(hostname_path) == os.path.realpath(localhost_path):
        return

    try:
        os.symlink(localhost_path, hostname_path)
    except FileExistsError:
        # collectd can create the hostname entry between the cleanup above and os.symlink(). Treat only the
        # desired link as success; a concurrently-created file, directory, or stale link must remain visible.
        if os.path.islink(hostname_path) and os.path.realpath(hostname_path) == os.path.realpath(localhost_path):
            return
        raise
