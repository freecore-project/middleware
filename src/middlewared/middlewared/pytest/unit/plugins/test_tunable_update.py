import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from middlewared.etc_files import sysctl_config
from middlewared.plugins import tunables
from middlewared.plugins.tunables import TunableService


# tunable.update puts a sysctl's recorded default back only when the tunable stops covering it (its var or type
# changes). It compared the stored type ('SYSCTL', from the upper() extend) with the lowered new one ('sysctl'),
# so every update of a SYSCTL tunable wrote the default to the kernel before the reload re-applied the value.
# service.reload runs the real sysctl_configuration against a fake kernel so the order of the writes is visible.

class Kernel:
    def __init__(self, values, refuse=()):
        self.values = dict(values)
        self.refuse = set(refuse)
        self.writes = []

    async def run(self, cmd, check=False, encoding=None):
        assert cmd[0] == 'sysctl'
        var, sep, value = cmd[1].partition('=')
        if not sep:
            return SimpleNamespace(returncode=0, stdout=f'{var}: {self.values[var]}\n', stderr='')
        self.writes.append((var, value))
        if (var, value) in self.refuse:
            return SimpleNamespace(returncode=1, stdout='', stderr='sysctl: Operation not permitted')
        self.values[var] = value
        return SimpleNamespace(returncode=0, stdout='', stderr='')


class FakeMiddleware(dict):
    event_register = Mock()
    logger = logging.getLogger('middlewared')

    async def call(self, method, *args):
        return await self[method](*args)


def service(row):
    rows = {row['id']: dict(row)}
    middleware = FakeMiddleware()
    svc = TunableService(middleware)

    async def get_instance(id):
        return await svc.upper(dict(rows[id]))

    async def datastore_update(datastore, id, data, options):
        rows[id] = {k: data[k] for k in row}

    async def query(filters):
        return [r for r in [await get_instance(id) for id in rows] if r['type'] == 'SYSCTL']

    async def reload(name):
        if name == 'sysctl':
            await sysctl_config.sysctl_configuration(middleware)

    svc.get_instance = get_instance
    middleware['datastore.query'] = AsyncMock(return_value=[])
    middleware['datastore.update'] = datastore_update
    middleware['datastore.delete'] = AsyncMock()
    middleware['tunable.query'] = query
    middleware['tunable.default_sysctl_config'] = svc.default_sysctl_config
    middleware['tunable.set_default_value'] = svc.set_default_value
    middleware['service.reload'] = reload
    return svc


ROW = {'id': 1, 'var': 'kern.ipc.somaxconn', 'value': '1024', 'type': 'sysctl', 'comment': '', 'enabled': True}


async def update(row, kernel, data):
    svc = service(row)
    with patch.object(tunables, 'run', kernel.run), patch.object(sysctl_config, 'run', kernel.run):
        # boot: the reload records the default and applies the value
        await svc.middleware.call('service.reload', 'sysctl')
        kernel.writes.clear()
        await TunableService.do_update.wraps(svc, row['id'], data)
    return svc


@pytest.mark.asyncio
@pytest.mark.parametrize('data', [{'value': '2048'}, {'comment': 'listen backlog'}, {}])
async def test_update_of_a_sysctl_tunable_does_not_write_the_default_first(data):
    kernel = Kernel({'kern.ipc.somaxconn': '128'})
    svc = await update(ROW, kernel, data)
    value = data.get('value', '1024')
    assert kernel.writes == [('kern.ipc.somaxconn', value)]
    assert kernel.values['kern.ipc.somaxconn'] == value
    assert await svc.default_sysctl_config() == {'kern.ipc.somaxconn': '128'}


@pytest.mark.asyncio
async def test_disabling_a_sysctl_tunable_restores_the_default_and_keeps_it_recorded():
    kernel = Kernel({'kern.ipc.somaxconn': '128'})
    svc = await update(ROW, kernel, {'enabled': False})
    assert kernel.writes == [('kern.ipc.somaxconn', '128')]
    assert await svc.default_sysctl_config() == {'kern.ipc.somaxconn': '128'}


@pytest.mark.asyncio
async def test_a_default_the_kernel_refuses_is_not_replaced_by_the_configured_value():
    kernel = Kernel({'kern.securelevel': '-1'}, refuse={('kern.securelevel', '-1')})
    row = dict(ROW, var='kern.securelevel', value='1')
    svc = await update(row, kernel, {'value': '2'})
    assert ('kern.securelevel', '-1') not in kernel.writes
    assert await svc.default_sysctl_config() == {'kern.securelevel': '-1'}


@pytest.mark.asyncio
async def test_renaming_a_sysctl_tunable_restores_the_old_variable():
    kernel = Kernel({'kern.ipc.somaxconn': '128', 'kern.ipc.maxsockbuf': '2097152'})
    svc = await update(ROW, kernel, {'var': 'kern.ipc.maxsockbuf', 'value': '4194304'})
    assert kernel.writes == [('kern.ipc.somaxconn', '128'), ('kern.ipc.maxsockbuf', '4194304')]
    assert await svc.default_sysctl_config() == {'kern.ipc.maxsockbuf': '2097152'}


@pytest.mark.asyncio
async def test_changing_the_type_of_a_sysctl_tunable_restores_the_default():
    kernel = Kernel({'kern.ipc.somaxconn': '128'})
    svc = await update(ROW, kernel, {'type': 'LOADER'})
    assert kernel.writes == [('kern.ipc.somaxconn', '128')]
    assert await svc.default_sysctl_config() == {}
