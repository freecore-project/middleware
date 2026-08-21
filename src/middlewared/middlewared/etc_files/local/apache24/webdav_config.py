import re
import os
import secrets
import hashlib
import ctypes
import ctypes.util

from contextlib import suppress
from middlewared.plugins.etc import EtcUSR, EtcGRP
from string import digits, ascii_uppercase, ascii_lowercase

_libcrypt_path = ctypes.util.find_library('crypt')
if _libcrypt_path is None:
    # On FreeBSD 15, /usr/lib/libcrypt.so is an ld linker script (not ELF)
    # and ctypes.util.find_library can't validate it. Use the versioned
    # SONAME directly — ld.so resolves it via ldconfig to /lib/libcrypt.so.5.
    # (Note: crypt(3) is NOT in libc on FB15 — moved entirely into libcrypt.)
    _libcrypt_path = 'libcrypt.so.5'
_libcrypt = ctypes.CDLL(_libcrypt_path)
_libcrypt.crypt.restype = ctypes.c_char_p
_libcrypt.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]


def _crypt(word, salt):
    """Call crypt(3) directly via ctypes (replacement for removed Python crypt module)."""
    result = _libcrypt.crypt(word.encode('utf-8'), salt.encode('utf-8'))
    if result is None:
        raise OSError('crypt() returned NULL')
    return result.decode('utf-8')


def generate_webdav_auth(middlewared, render_ctx, dirfd):
    def opener(path, flags):
        return os.open(path, flags, dir_fd=dirfd)

    def salt():
        letters = f'{ascii_lowercase}{ascii_uppercase}{digits}/.'
        return '$6${0}'.format(''.join([secrets.choice(letters) for i in range(16)]))

    def remove_auth(dirfd):
        with suppress(FileNotFoundError):
            os.remove('webdavhtbasic', dir_fd=dirfd)

        with suppress(FileNotFoundError):
            os.remove('webdavhtdigest', dir_fd=dirfd)

    auth_type = render_ctx['webdav.config']['htauth'].upper()
    password = render_ctx['webdav.config']['password']

    if auth_type not in ['NONE', 'BASIC', 'DIGEST']:
        remove_auth(dirfd)
        raise ValueError("Invalid auth_type (must be one of 'NONE', 'BASIC', 'DIGEST')")

    if auth_type == 'BASIC':
        with suppress(FileNotFoundError):
            os.remove('webdavhtdigest', dir_fd=dirfd)

        with open('webdavhtbasic', 'w', opener=opener) as f:
            os.fchmod(f.fileno(), 0o600)
            os.fchown(f.fileno(), EtcUSR.WEBDAV, EtcGRP.WEBDAV)
            f.write(f'webdav:{_crypt(password, salt())}')

    elif auth_type == 'DIGEST':
        with suppress(FileNotFoundError):
            os.remove('webdavhtbasic', dir_fd=dirfd)

        with open('webdavhtdigest', 'w', opener=opener) as f:
            os.fchmod(f.fileno(), 0o600)
            os.fchown(f.fileno(), EtcUSR.WEBDAV, EtcGRP.WEBDAV)
            f.write(
                "webdav:webdav:{0}".format(hashlib.md5(f"webdav:webdav:{password}".encode()).hexdigest())
            )

    else:
        remove_auth(dirfd)


def generate_webdav_config(middleware, render_ctx, dirfd):
    def opener(path, flags):
        return os.open(path, flags, dir_fd=dirfd)

    webdav_config = render_ctx['webdav.config']
    to_blank = None

    if webdav_config['protocol'] in ('HTTPS', 'HTTPHTTPS'):
        middleware.call_sync('certificate.cert_services_validation', webdav_config['certssl'], 'webdav.certssl')

        with open('Includes/webdav.conf', 'r', opener=opener) as f:
            data = f.read()

        webdav_config['certssl'] = middleware.call_sync(
            'certificate.query',
            [['id', '=', webdav_config['certssl']]],
            {'get': True}
        )

        data = re.sub(
            'Listen .*\n\t<VirtualHost.*\n',
            f'Listen {webdav_config["tcpportssl"]}\n\t'
            f'<VirtualHost *:{webdav_config["tcpportssl"]}>\n\t\tSSLEngine on\n\t\t'
            f'SSLCertificateFile "{webdav_config["certssl"]["certificate_path"]}"\n\t\t'
            f'SSLCertificateKeyFile "{webdav_config["certssl"]["privatekey_path"]}"\n\t\t'
            f'SSLProtocol +TLSv1.2 +TLSv1.3\n\t\t'
            f'SSLCipherSuite HIGH:MEDIUM\n\n',
            data
        )

        with open('Includes/webdav-ssl.conf', 'w', opener=opener) as f:
            f.write(data)

        if webdav_config['protocol'] == 'HTTPS':
            to_blank = 'Includes/webdav.conf'

    elif webdav_config['protocol'] == 'HTTP':
        to_blank = 'Includes/webdav-ssl.conf'

    if to_blank is not None:
        try:
            fd = os.open(to_blank, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, dir_fd=dirfd)
        finally:
            os.close(fd)


def render(service, middleware, render_ctx):
    apache_dir = '/etc/local/apache24'
    dirfd = os.open(apache_dir, os.O_PATH | os.O_DIRECTORY)
    try:
        generate_webdav_config(middleware, render_ctx, dirfd)
        generate_webdav_auth(middleware, render_ctx, dirfd)
    finally:
        os.close(dirfd)
