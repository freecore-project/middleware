import os
import platform


def write_if_changed(path, data):
    def opener(in_path_ignored, in_flags_ignored):
        to_open = path
        kwargs = {}
        flags = os.O_CREAT | os.O_RDWR

        if isinstance(path, int):
            if platform.system() == 'FreeBSD':
                # O_EMPTY_PATH is Linux-only; use /dev/fd/<N> on FreeBSD
                return os.open(f'/dev/fd/{path}', os.O_RDWR)
            else:
                O_EMPTY_PATH = 0x02000000
                flags = os.O_RDWR | O_EMPTY_PATH
                to_open = ''
                kwargs['dir_fd'] = path

        return os.open(to_open, flags, **kwargs)

    if isinstance(data, str):
        data = data.encode()

    changed = False

    with open(str(path), 'wb+', opener=opener) as f:
        f.seek(0)
        current = f.read()
        if current != data:
            changed = True
            f.seek(0)
            f.write(data)
            f.truncate()
        os.fsync(f)

    return changed
