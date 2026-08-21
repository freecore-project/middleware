from pathlib import Path

import pytest
from mako.template import Template

ETC_FILES = Path(__file__).parents[3] / 'etc_files'


def render_ctx():
    return {
        'nis.config': {'enable': False},
        'group.query': [
            {'id': i, 'group': name, 'gid': gid, 'builtin': builtin, 'users': []}
            for i, (name, gid, builtin) in enumerate([
                ('wheel', 0, True), ('nobody', 65534, True), ('ops', 1000, False), ('early', 10, False),
            ], 1)
        ],
        'user.query': [
            {
                'id': i, 'username': name, 'uid': uid, 'builtin': builtin, 'password_disabled': True,
                'locked': False, 'unixhash': '*', 'group': {'id': 1, 'bsdgrp_gid': 0}, 'full_name': name,
                'home': '/nonexistent', 'shell': '/usr/sbin/nologin',
            }
            for i, (name, uid, builtin) in enumerate([
                ('root', 0, True), ('nobody', 65534, True), ('alice', 1000, False), ('legacy', 50, False),
                ('svc0', 0, False),
            ], 1)
        ],
    }


@pytest.mark.parametrize('path,names', [
    ('group', ['wheel', 'nobody', 'early', 'ops']),
    ('master.passwd', ['root', 'nobody', 'svc0', 'legacy', 'alice']),
])
def test_builtin_accounts_are_listed_first_then_by_id(path, names):
    text = Template(filename=str(ETC_FILES / path)).render(render_ctx=render_ctx())
    assert [line.split(':')[0] for line in text.splitlines() if line] == names
