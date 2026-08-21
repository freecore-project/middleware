from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from middlewared.plugins.service_.services import base_freebsd


@pytest.mark.asyncio
async def test__freebsd_service__forcestart_already_running_no_warning():
    async def run(*args, **kwargs):
        assert args == ("service", "wsdd", "forcestart")
        return SimpleNamespace(returncode=1, stdout="wsdd already running?  (pid=2508).\n")

    with (
        patch.object(base_freebsd, "run", run),
        patch.object(base_freebsd.logger, "warning", Mock()) as warning,
    ):
        result = await base_freebsd.freebsd_service("wsdd", "forcestart")

    assert result.returncode == 1
    warning.assert_not_called()


@pytest.mark.asyncio
async def test__freebsd_service__forcestart_other_failure_warns():
    async def run(*args, **kwargs):
        assert args == ("service", "wsdd", "forcestart")
        return SimpleNamespace(returncode=1, stdout="wsdd failed to start\n")

    with (
        patch.object(base_freebsd, "run", run),
        patch.object(base_freebsd.logger, "warning", Mock()) as warning,
    ):
        result = await base_freebsd.freebsd_service("wsdd", "forcestart")

    assert result.returncode == 1
    warning.assert_called_once()
