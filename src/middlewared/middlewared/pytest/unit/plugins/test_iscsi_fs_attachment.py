from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from middlewared.plugins import iscsi as iscsi_plugin
from middlewared.plugins.iscsi import ISCSIFSAttachmentDelegate


@pytest.mark.asyncio
async def test_lock_stop_without_extents_does_not_reload_or_wait(monkeypatch):
    monkeypatch.setattr(iscsi_plugin.osc, 'IS_FREEBSD', True)
    sleep = AsyncMock()
    monkeypatch.setattr(iscsi_plugin, 'asyncio', SimpleNamespace(sleep=sleep))
    delegate = ISCSIFSAttachmentDelegate(Mock())
    delegate._service_change = AsyncMock()

    await delegate.stop([])

    delegate._service_change.assert_not_awaited()
    sleep.assert_not_awaited()

    await delegate.stop([{'id': 1}])

    delegate._service_change.assert_awaited_once_with('iscsitarget', 'reload')
    sleep.assert_awaited_once_with(5)
