"""collectd.conf is left as it is while reporting.setup cannot run.

The template bails out when the system dataset is not mounted. Its early exit has to keep the
current file: an empty collectd.conf starts collectd with no plugins and reporting stays off
until the next render.
"""
import logging
from unittest.mock import Mock, patch

import pytest
from mako.lookup import TemplateLookup

from middlewared.plugins import etc
from middlewared.plugins.etc import EtcService, MakoRenderer


class CollectdMiddleware:

    def __init__(self, setup):
        self.setup = setup
        self.logger = logging.getLogger('middlewared')
        self.calls = []

    def call_sync(self, name, *args):
        self.calls.append(name)
        assert name == 'reporting.setup', f'{name} called after reporting.setup returned False'
        return self.setup

    async def run_in_thread(self, method, *args):
        return method(*args)


@pytest.fixture(autouse=True)
def no_mako_module_cache():
    # MakoRenderer caches compiled templates under /tmp/mako; keep them in memory here.
    with patch.object(etc, 'TemplateLookup', lambda directories, module_directory: TemplateLookup(directories)):
        yield


async def test_a_deferred_render_is_skipped_rather_than_empty():
    service = EtcService(CollectdMiddleware(setup=False))

    rendered = await MakoRenderer(service).render(f'{service.files_dir}/local/collectd.conf', None)

    assert rendered is None
    assert service.middleware.calls == ['reporting.setup']


async def test_a_deferred_render_keeps_the_current_collectd_conf():
    service = EtcService(CollectdMiddleware(setup=False))

    with patch.object(etc.osc, 'SYSTEM', 'FREEBSD'), patch.object(EtcService, 'make_changes', Mock()) as make_changes:
        await service.generate('collectd')

    make_changes.assert_not_called()
