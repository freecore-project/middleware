# the internal development record: a configuration update must judge "was it running?" before the row changes.
# Since #566 the UPS state check consults ups.config (MASTER requires upsd); reading it after the update
# made a SLAVE -> MASTER switch of a running service look STOPPED, so the restart was skipped.
import pytest

from middlewared.service import SystemServiceService


class Config:
    service = 'ups'
    service_model = None
    service_verb = 'restart'
    service_verb_sync = True
    datastore_prefix = 'ups_'


class UPSLike(SystemServiceService):
    pass


class Middleware:
    """Answers service.query the way the #566 UPS check does: RUNNING with the SLAVE row, STOPPED once the
    row says MASTER (no upsd runs in SLAVE mode)."""

    def __init__(self, running_before=True):
        self.calls = []
        self.mode = 'SLAVE'
        self.running_before = running_before

    async def call(self, method, *args):
        self.calls.append(method)
        if method == 'service.query':
            running = self.running_before and self.mode == 'SLAVE'
            return {'service': 'ups', 'state': 'RUNNING' if running else 'STOPPED'}
        if method == 'datastore.update':
            self.mode = args[2]['mode']
            return args[1]
        if method in ('etc.generate', 'service.restart'):
            return True
        raise AssertionError(f'unexpected call {method!r}')


def service(middleware):
    svc = object.__new__(UPSLike)
    svc.middleware = middleware
    svc._config = Config()
    return svc


@pytest.mark.asyncio
async def test_switching_a_running_slave_to_master_restarts_it():
    middleware = Middleware()

    await service(middleware)._update_service({'id': 1, 'mode': 'SLAVE'}, {'mode': 'MASTER'})

    assert 'service.restart' in middleware.calls
    assert middleware.calls.index('service.query') < middleware.calls.index('datastore.update')
    assert middleware.calls.index('etc.generate') < middleware.calls.index('service.restart')


@pytest.mark.asyncio
async def test_a_stopped_service_is_not_started_by_an_update():
    middleware = Middleware(running_before=False)

    await service(middleware)._update_service({'id': 1, 'mode': 'SLAVE'}, {'mode': 'MASTER'})

    assert 'service.restart' not in middleware.calls
    assert 'etc.generate' in middleware.calls


@pytest.mark.asyncio
async def test_service_change_without_a_prior_state_still_queries():
    middleware = Middleware()

    await service(middleware)._service_change('ups', 'restart')

    assert middleware.calls == ['service.query', 'etc.generate', 'service.restart']
