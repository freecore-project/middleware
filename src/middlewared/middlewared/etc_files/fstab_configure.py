import subprocess

from middlewared.utils import osc


def fstab_configuration(middleware):
    if osc.IS_LINUX:
        commands = [
            ['systemctl', 'daemon-reload'],
            ['systemctl', 'restart', 'local-fs.target'],
        ]
    else:
        # On FreeBSD 15+ with ZFS-only root, mount -uw / is unnecessary
        # and may fail. Only attempt it if root is not already read-write.
        ret = subprocess.run(
            ['mount', '-p'], capture_output=True, text=True,
        )
        root_is_zfs = any(
            line.split()[1] == '/' and line.split()[2] == 'zfs'
            for line in ret.stdout.splitlines()
            if len(line.split()) >= 3
        )
        commands = [] if root_is_zfs else [['mount', '-uw', '/']]

    for command in commands:
        ret = subprocess.run(command, capture_output=True)
        if ret.returncode:
            middleware.logger.debug(f'Failed to execute "{" ".join(command)}": {ret.stderr.decode()}')


def render(service, middleware):
    fstab_configuration(middleware)
