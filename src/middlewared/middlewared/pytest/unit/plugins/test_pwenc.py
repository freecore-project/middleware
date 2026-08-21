# A stored secret that really ends in '{' (the legacy pad byte) must decrypt to itself, while every
# other secret keeps the exact legacy encoding that older middlewares and SCALE decrypt.
import base64

import pytest
from Crypto.Cipher import AES
from Crypto.Util import Counter

from middlewared.plugins.pwenc import PWENC_BLOCK_SIZE, PWENC_PADDING, PWEncService, decrypt, encrypt

SECRET = bytes(range(PWENC_BLOCK_SIZE))


@pytest.fixture(autouse=True)
def secret(monkeypatch):
    monkeypatch.setattr(PWEncService, 'secret', SECRET)


def plaintext(encrypted):
    encrypted = base64.b64decode(encrypted)
    cipher = AES.new(SECRET, AES.MODE_CTR, counter=Counter.new(64, prefix=encrypted[:8]))
    return cipher.decrypt(encrypted[8:])


def legacy_encrypt(data):
    data = data.encode('utf8')
    data += (PWENC_BLOCK_SIZE - len(data) % PWENC_BLOCK_SIZE) * PWENC_PADDING
    nonce = b'\x00' * 8
    cipher = AES.new(SECRET, AES.MODE_CTR, counter=Counter.new(64, prefix=nonce))
    return base64.b64encode(nonce + cipher.encrypt(data)).decode()


@pytest.mark.parametrize('data', [
    '', 'Donuts!', 'p@ss', 'x' * 31, 'x' * 32, 'x' * 33, '{x', 'Unicode 你好 世界',
    'abc{', 'p@ss{{', '{', '{' * 31, '{' * 32, '{' * 33, 'x' * 31 + '{', 'ключ{',
])
def test_encrypt_decrypt_roundtrip(data):
    assert decrypt(encrypt(data), _raise=True) == data


@pytest.mark.parametrize('data', ['', 'Donuts!', 'x' * 32, '{x'])
def test_encrypt_keeps_legacy_padding(data):
    padded = plaintext(encrypt(data))

    assert len(padded) % PWENC_BLOCK_SIZE == 0
    assert padded.rstrip(PWENC_PADDING) == data.encode('utf8')


@pytest.mark.parametrize('data', ['Donuts!', 'x' * 32, '', 'Unicode 你好 世界'])
def test_decrypt_legacy_value(data):
    assert decrypt(legacy_encrypt(data), _raise=True) == data
