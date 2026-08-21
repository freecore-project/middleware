import importlib.util
import os
import stat
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from mako.template import Template

APACHE = Path(__file__).parents[3] / 'etc_files/local/apache24'


def load_webdav_config():
    spec = importlib.util.spec_from_file_location('webdav_config', APACHE / 'webdav_config.py')
    module = importlib.util.module_from_spec(spec)
    with patch('ctypes.CDLL'):
        spec.loader.exec_module(module)
    return module


@pytest.fixture
def apache_dir(tmp_path):
    (tmp_path / 'Includes').mkdir()
    old_umask = os.umask(0o022)
    dirfd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield tmp_path, dirfd
    finally:
        os.close(dirfd)
        os.umask(old_umask)


def generate(dirfd, protocol):
    load_webdav_config().generate_webdav_config(Mock(), {'webdav.config': {'protocol': protocol}}, dirfd)


def test_http_only_writes_an_empty_non_executable_ssl_include(apache_dir):
    path, dirfd = apache_dir

    generate(dirfd, 'HTTP')

    ssl_conf = path / 'Includes/webdav-ssl.conf'
    assert ssl_conf.read_text() == ''
    assert stat.S_IMODE(ssl_conf.stat().st_mode) == 0o644


def test_http_only_repairs_an_executable_ssl_include(apache_dir):
    path, dirfd = apache_dir
    ssl_conf = path / 'Includes/webdav-ssl.conf'
    ssl_conf.write_text('Listen 8081\n')
    ssl_conf.chmod(0o755)

    generate(dirfd, 'HTTP')

    assert ssl_conf.read_text() == ''
    assert stat.S_IMODE(ssl_conf.stat().st_mode) == 0o644


def test_a_failed_blanking_reports_the_os_error(apache_dir):
    path, dirfd = apache_dir
    (path / 'Includes').rmdir()

    with pytest.raises(FileNotFoundError):
        generate(dirfd, 'HTTP')


def test_each_share_alias_is_indented_like_the_directory_block():
    template = Template(filename=str(APACHE / 'Includes/webdav.conf'))
    render_ctx = {
        'webdav.config': {'tcpport': 8080, 'htauth': 'NONE'},
        'sharing.webdav.query': [{'id': 1, 'name': 'share', 'path': '/mnt/tank/share', 'ro': False, 'locked': False}],
    }
    with patch('os.mkdir'), patch('os.stat', return_value=Mock(st_mode=0o40774)), patch('shutil.chown'):
        lines = template.render(middleware=Mock(), render_ctx=render_ctx).splitlines()

    alias = lines.index('\t\tAlias /share "/mnt/tank/share"')
    assert lines[alias + 1] == '\t\t<Directory "/mnt/tank/share" >'
