import shlex

import pytest

from middlewared.plugins.rsync_utils import ssh_remote_path


@pytest.mark.parametrize('path', [
    '/mnt/plain',
    '/mnt/path with spaces',
    "/mnt/path with a ' quote",
    '/mnt/path;touch RSYNC_INJECTED',
    '/mnt/path/$(touch RSYNC_INJECTED)',
    '/mnt/path/$HOME',
])
@pytest.mark.parametrize('remote, expected_remote', [
    ('"root"@example.test', 'root@example.test'),
    ('backup@example.test', 'backup@example.test'),
])
def test_ssh_remote_path_is_one_shell_argument(remote, expected_remote, path):
    result = ssh_remote_path(remote, path)

    assert shlex.split(result) == [f'{expected_remote}:{path}']
    assert result != f'{remote}:"{shlex.quote(path)}"'
