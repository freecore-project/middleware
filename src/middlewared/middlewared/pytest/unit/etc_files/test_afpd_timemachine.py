# the internal development record: the Time Machine quota files in an AFP share root are written as root in a directory
# the share's user controls, so a symlink, a hard link or a FIFO in place of one must never redirect the write.
import os
import stat

import pytest

from middlewared.etc_files.afpd import write_owned_file


@pytest.fixture
def share(tmp_path):
    root = tmp_path / 'share'
    root.mkdir()
    outside = tmp_path / 'outside'
    outside.write_text('precious')
    os.chmod(outside, 0o600)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield root, outside, fd
    finally:
        os.close(fd)


def write(fd, name, content='x'):
    write_owned_file(fd, name, content, os.getuid(), os.getgid())


def test_creates_a_plain_file(share):
    root, _, fd = share
    write(fd, 'f', 'quota')
    st = os.lstat(root / 'f')
    assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o644
    assert (st.st_uid, st.st_gid) == (os.getuid(), os.getgid())
    assert (root / 'f').read_text() == 'quota'


def test_rewrites_an_existing_file(share):
    root, _, fd = share
    (root / 'f').write_text('a much longer previous content')
    write(fd, 'f', 'new')
    assert (root / 'f').read_text() == 'new'


def test_symlink_is_replaced_not_followed(share):
    root, outside, fd = share
    os.symlink(outside, root / 'f')
    write(fd, 'f', 'quota')
    assert not (root / 'f').is_symlink() and (root / 'f').read_text() == 'quota'
    assert outside.read_text() == 'precious' and stat.S_IMODE(os.stat(outside).st_mode) == 0o600


def test_dangling_symlink_is_replaced_not_followed(share):
    root, outside, fd = share
    target = outside.parent / 'created-through-link'
    os.symlink(target, root / 'f')
    write(fd, 'f')
    assert not target.exists() and (root / 'f').is_file() and not (root / 'f').is_symlink()


def test_hard_link_is_refused(share):
    root, outside, fd = share
    os.link(outside, root / 'f')
    with pytest.raises(OSError):
        write(fd, 'f', 'quota')
    assert outside.read_text() == 'precious' and stat.S_IMODE(os.stat(outside).st_mode) == 0o600


def test_fifo_is_refused_without_blocking(share):
    root, _, fd = share
    os.mkfifo(root / 'f')
    with pytest.raises(OSError):
        write(fd, 'f')
    assert stat.S_ISFIFO(os.lstat(root / 'f').st_mode)
