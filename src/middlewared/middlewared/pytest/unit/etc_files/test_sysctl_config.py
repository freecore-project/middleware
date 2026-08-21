from unittest.mock import AsyncMock, Mock, patch

import pytest

from middlewared.etc_files.sysctl_config import sysctl_configuration


class SysctlMiddleware:

    def __init__(self, enabled, default_sysctl_config):
        self.enabled = enabled
        self.default_sysctl_config = default_sysctl_config
        self.logger = Mock()

    async def call(self, name, *args):
        if name == 'tunable.default_sysctl_config':
            return self.default_sysctl_config
        if name == 'tunable.query':
            return [{'var': 'kern.maxfiles', 'value': '200000', 'type': 'SYSCTL', 'enabled': self.enabled}]
        if name == 'tunable.set_default_value':
            return None

        raise AssertionError(f'unexpected call {name!r}')


async def failing_set(args, **kwargs):
    if '=' in args[1]:
        return Mock(returncode=1, stderr='sysctl: kern.maxfiles=...: Invalid argument\n')
    return Mock(returncode=0, stdout='kern.maxfiles: 100000\n', stderr='')


@pytest.mark.asyncio
async def test_disabled_tunable_restore_failure_logs_default_value():
    m = SysctlMiddleware(False, {'kern.maxfiles': '100000'})
    with patch('middlewared.etc_files.sysctl_config.run', AsyncMock(side_effect=failing_set)) as run:
        await sysctl_configuration(m)

    run.assert_any_call(['sysctl', 'kern.maxfiles=100000'], check=False, encoding='utf8')
    m.logger.error.assert_called_once_with(
        'Failed to set sysctl %r -> %r : %s', 'kern.maxfiles', '100000', 'sysctl: kern.maxfiles=...: Invalid argument'
    )


@pytest.mark.asyncio
async def test_enabled_tunable_set_failure_logs_tunable_value():
    m = SysctlMiddleware(True, {'kern.maxfiles': '100000'})
    with patch('middlewared.etc_files.sysctl_config.run', AsyncMock(side_effect=failing_set)) as run:
        await sysctl_configuration(m)

    run.assert_any_call(['sysctl', 'kern.maxfiles=200000'], check=False, encoding='utf8')
    m.logger.error.assert_called_once_with(
        'Failed to set sysctl %r -> %r : %s', 'kern.maxfiles', '200000', 'sysctl: kern.maxfiles=...: Invalid argument'
    )
