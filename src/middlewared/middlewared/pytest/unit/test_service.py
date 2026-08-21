import asyncio
import threading
import time

import pytest

from middlewared.plugins.datastore.read import DatastoreService
from middlewared.schema import Schemas, resolve_methods
from middlewared.service import CRUDService, throttle

WIDGETS = [{'id': 1, 'widget_name': 'one'}, {'id': 2, 'widget_name': 'two'}]


@pytest.mark.timeout(10)
def test__throttle():
    values = []
    errors = []

    @throttle(2, max_waiters=2)
    def f():
        return time.monotonic()

    def body():
        try:
            values.append(f())
        except Exception as e:
            errors.append(e)

    start = time.monotonic()
    t1 = threading.Thread(target=body)
    t1.start()
    t2 = threading.Thread(target=body)
    t2.start()
    t3 = threading.Thread(target=body)
    t3.start()

    t1.join()
    t2.join()
    t3.join()

    assert len(values) == 3
    assert len(errors) == 0

    values = sorted(values)
    assert values[0] - start < 1
    assert 1.99 <= values[1] - values[0] < 3
    assert 1.99 <= values[2] - values[1] < 3


@pytest.mark.timeout(10)
@pytest.mark.asyncio
async def test__async_throttle():
    values = []
    errors = []

    @throttle(2, max_waiters=2)
    async def f():
        return time.monotonic()

    async def body():
        try:
            values.append(await f())
        except Exception as e:
            errors.append(e)

    start = time.monotonic()
    await asyncio.wait([asyncio.ensure_future(body()) for _ in range(3)])

    assert len(values) == 3
    assert len(errors) == 0

    values = sorted(values)
    assert values[0] - start < 1
    assert 1.99 <= values[1] - values[0] < 3
    assert 1.99 <= values[2] - values[1] < 3


class WidgetMiddleware(dict):

    def event_register(self, name, description):
        pass

    async def call(self, name, *args):
        result = self[name](*args)
        if asyncio.iscoroutine(result):
            result = await result
        return result

    async def run_in_thread(self, method, *args):
        return method(*args)


class WidgetService(CRUDService):

    class Config:
        datastore = 'test.widget'
        datastore_prefix = 'widget_'
        datastore_extend = 'widget.extend'


class WidgetDatastore(DatastoreService):

    def _serialize_row(self, obj, table, aliases):
        return dict(obj)


@pytest.fixture
def widget_service():
    m = WidgetMiddleware()
    datastore = WidgetDatastore(m)

    async def datastore_query(name, filters, options):
        # Only the SQL fetch is faked: prefix stripping, extend and `select` are the datastore's own
        assert filters == []
        return await datastore._queryset_serialize(
            WIDGETS, None, {}, [{} for _ in WIDGETS], options['extend'], options['extend_context'],
            options['prefix'], options.get('select'), options.get('extra'),
        )

    m['datastore.query'] = datastore_query
    m['widget.extend'] = lambda data: {**data, 'label': data['name'].upper()}
    service = WidgetService(m)
    resolve_methods(Schemas(), [DatastoreService.query, service.query])
    return service


@pytest.mark.parametrize('filters,options,expected', [
    ([['name', '=', 'two']], {'select': ['id', 'name']}, [{'id': 2, 'name': 'two'}]),
    ([['name', '=', 'two']], {'select': ['id']}, [{'id': 2}]),
    ([['name', '=', 'two']], {'select': ['id'], 'get': True}, {'id': 2}),
    ([['name', '=', 'two']], {'select': ['id'], 'count': True}, 1),
    ([['label', '=', 'TWO']], {'select': ['name']}, [{'name': 'two'}]),
])
async def test__crud_query__filters_fields_left_out_of_select(widget_service, filters, options, expected):
    assert await widget_service.query(filters, options) == expected
