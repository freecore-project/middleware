# smart.test create/update: the "already have tests for this type" check, a disk listed twice, the
# shape create answers with, and the order of a test's disks. smart.update: collectd/snmp restarts.
import copy
from unittest.mock import AsyncMock, patch

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import declarative_base, relationship

import sys  # noqa: E402
import types  # noqa: E402

if not sys.platform.startswith('freebsd'):
    # smart.py imports the FreeBSD-only py-nvme (through common/smart/smartctl.py); get_nsid is not used here
    nvme = types.ModuleType('nvme')
    nvme.get_nsid = None
    sys.modules.setdefault('nvme', nvme)

from middlewared.plugins.datastore.read import DatastoreService  # noqa: E402
from middlewared.plugins.smart import SmartService, SMARTTestService  # noqa: E402
from middlewared.schema import Schemas, resolve_methods  # noqa: E402
from middlewared.service import CRUDService  # noqa: E402
from middlewared.service_exception import ValidationErrors  # noqa: E402

DISKS = {'{serial}A': 'ada0', '{serial}B': 'ada1', '{serial}C': 'ada2'}
SCHEDULE = {'hour': '3', 'dom': '*', 'month': '*', 'dow': '7'}


def setup_module():
    # What middlewared does at startup: query-filters/query-options come from datastore.query
    resolve_methods(Schemas(), [
        DatastoreService.query, CRUDService.query, SMARTTestService.do_create, SMARTTestService.do_update,
    ])


class FakeMiddleware:
    """tasks.smarttest rows as datastore.query returns them (prefix stripped, disks as storage_disk rows),
    run through the extend method like plugins/datastore/read.py does."""

    def __init__(self, rows):
        self.rows = {row['id']: row for row in rows}
        self.writes = []
        self.service = None

    def event_register(self, *args):
        pass

    def create_task(self, coro):
        coro.close()

    async def run_in_thread(self, method, *args):
        return method(*args)

    async def call(self, method, *args):
        if method == 'datastore.query':
            name, filters, options = args
            assert (name, filters, options['extend']) == ('tasks.smarttest', [], 'smart.test.smart_test_extend')
            return [await self.service.smart_test_extend(copy.deepcopy(row)) for row in self.rows.values()]

        if method in ('datastore.insert', 'datastore.update'):
            self.writes.append((method, copy.deepcopy(args[-2])))
            data = copy.deepcopy(args[-2])
            if method == 'datastore.insert':
                data['id'] = max(self.rows, default=0) + 1
            else:
                data['id'] = args[1]
            data['disks'] = [{'disk_identifier': disk} for disk in data['disks']]
            self.rows[data['id']] = {'desc': None, **data}
            return data['id']

        raise AssertionError(method)


def row(id, type, disks):
    return {
        'id': id, 'type': type, 'desc': None, 'hour': '*', 'daymonth': '*', 'month': '*', 'dayweek': '*',
        'all_disks': False, 'disks': [{'disk_identifier': disk} for disk in disks],
    }


def smart_test_service(*rows):
    middleware = FakeMiddleware(rows)
    service = middleware.service = SMARTTestService(middleware)
    service.disk_choices = AsyncMock(return_value=DISKS)
    service._service_change = AsyncMock()
    return service, middleware


@pytest.mark.asyncio
async def test_create_rejects_a_disk_that_already_has_a_test_of_this_type():
    service, middleware = smart_test_service(row(1, 'L', ['{serial}A']))

    with pytest.raises(ValidationErrors) as ve:
        await service.do_create({'type': 'LONG', 'disks': ['{serial}A'], 'schedule': SCHEDULE})

    assert [(e.attribute, e.errmsg) for e in ve.value.errors] == [
        ('smart_test_create.disks', 'The following disks already have tests for this type: ada0'),
    ]
    assert middleware.writes == []


@pytest.mark.asyncio
async def test_create_allows_a_disk_that_has_a_test_of_another_type():
    service, middleware = smart_test_service(row(1, 'L', ['{serial}A']))

    await service.do_create({'type': 'SHORT', 'disks': ['{serial}A'], 'schedule': SCHEDULE})

    assert [data['type'] for method, data in middleware.writes] == ['S']


@pytest.mark.asyncio
async def test_create_rejects_a_disk_listed_twice_before_writing():
    service, middleware = smart_test_service()

    with pytest.raises(ValidationErrors) as ve:
        await service.do_create({'type': 'LONG', 'disks': ['{serial}A', '{serial}A'], 'schedule': SCHEDULE})

    assert [e.attribute for e in ve.value.errors] == ['smart_task_create.disks.1']
    assert middleware.writes == []


@pytest.mark.asyncio
async def test_create_answers_like_query():
    service, middleware = smart_test_service()

    created = await service.do_create({'type': 'LONG', 'disks': ['{serial}A'], 'schedule': SCHEDULE})

    assert created == {
        'id': 1, 'type': 'LONG', 'desc': None, 'all_disks': False, 'disks': ['{serial}A'], 'schedule': SCHEDULE,
    }
    assert created == await service.query([('id', '=', 1)], {'get': True})


@pytest.mark.asyncio
async def test_update_to_a_type_another_test_has_on_the_disk_is_rejected():
    service, middleware = smart_test_service(row(1, 'L', ['{serial}A']), row(2, 'S', ['{serial}B']))

    with pytest.raises(ValidationErrors) as ve:
        await service.do_update(2, {'type': 'LONG', 'disks': ['{serial}A']})

    assert [e.errmsg for e in ve.value.errors] == ['The following disks already have tests for this type: ada0']
    assert middleware.writes == []


@pytest.mark.asyncio
async def test_update_rejects_a_disk_listed_twice_before_writing():
    service, middleware = smart_test_service(row(1, 'L', ['{serial}A']))

    with pytest.raises(ValidationErrors) as ve:
        await service.do_update(1, {'disks': ['{serial}B', '{serial}B']})

    assert [e.attribute for e in ve.value.errors] == ['smart_task_update.disks.1']
    assert middleware.writes == []


@pytest.mark.asyncio
async def test_update_does_not_conflict_with_itself():
    service, middleware = smart_test_service(row(1, 'L', ['{serial}A']), row(2, 'S', ['{serial}A']))

    updated = await service.do_update(1, {'desc': 'weekly', 'disks': ['{serial}A', '{serial}B']})

    assert [(data['type'], data['disks']) for method, data in middleware.writes] == [
        ('L', ['{serial}B', '{serial}A']),
    ]
    assert updated['type'] == 'LONG'


Model = declarative_base()


class StringDiskModel(Model):
    __tablename__ = 'test_stringdisk'

    disk_identifier = sa.Column(sa.String(42), primary_key=True)


class StringDiskTestModel(Model):
    __tablename__ = 'test_stringdisktest'

    id = sa.Column(sa.Integer(), primary_key=True)
    disks = relationship('StringDiskModel', secondary=lambda: StringDiskTestDiskModel.__table__)


class StringDiskTestDiskModel(Model):
    __tablename__ = 'test_stringdisktest_disks'

    id = sa.Column(sa.Integer(), primary_key=True)
    stringdisktest_id = sa.Column(sa.Integer(), sa.ForeignKey('test_stringdisktest.id'))
    disk_id = sa.Column(sa.String(42), sa.ForeignKey('test_stringdisk.disk_identifier'))


@pytest.mark.asyncio
async def test_many_to_many_keeps_the_link_table_order_of_string_ids():
    # Like tasks_smarttest_smarttest_disks -> storage_disk.disk_identifier. A set of str ids
    # iterates in PYTHONHASHSEED order, which differs in every middlewared process.
    identifiers = [f'{{serial}}DISK{i:02}' for i in range(24)][::-1]

    async def query(name, filters, options=None):
        if name == 'test.stringdisktest_disks':
            return [{'stringdisktest_id': 1, 'disk_id': identifier} for identifier in identifiers]
        assert name == 'test.stringdisk'
        return [{'disk_identifier': identifier} for identifier in sorted(filters[0][2])]

    table = Model.metadata.tables['test_stringdisktest']
    ds = DatastoreService(None)
    ds.query = query
    with patch('middlewared.plugins.datastore.schema.Model', Model):
        relationships = await ds._fetch_many_to_many(table, [{table.c.id: 1}])

    assert [disk['disk_identifier'] for disk in relationships[0]['disks']] == identifiers


class FakeSmartMiddleware:
    def __init__(self):
        self.calls = []

    def create_task(self, coro):
        coro.close()

    async def call(self, method, *args):
        if method == 'service.query':
            # _update_service reads the service state before the row changes (the internal development record)
            return {'state': 'STOPPED'}
        self.calls.append((method, *copy.deepcopy(args)))


async def smart_update(stored_powermode, data):
    middleware = FakeSmartMiddleware()
    service = SmartService(middleware)
    service._service_change = AsyncMock()
    stored = {'id': 1, 'interval': 30, 'powermode': stored_powermode, 'difference': 0, 'informational': 0,
              'critical': 0}
    service.config = AsyncMock(return_value=await service.smart_extend(stored))

    result = await service.do_update(data)

    restarts = [call for call in middleware.calls if call[0] == 'service.restart']
    restarts += [call.args for call in service._service_change.call_args_list if call.args[0] != 'smartd']
    return result, restarts, middleware.calls


@pytest.mark.asyncio
async def test_smart_update_without_a_powermode_change_does_not_restart_collectd_or_snmp():
    result, restarts, calls = await smart_update('never', {'interval': 60})

    assert restarts == []
    assert result['powermode'] == 'NEVER'
    assert calls[0][:2] == ('datastore.update', 'services.smart')
    assert calls[0][3]['powermode'] == 'never'


@pytest.mark.asyncio
async def test_smart_update_with_a_powermode_change_restarts_collectd_and_snmp():
    result, restarts, calls = await smart_update('never', {'powermode': 'STANDBY'})

    assert restarts == [('service.restart', 'collectd'), ('snmp', 'restart')]
    assert result['powermode'] == 'STANDBY'
    assert calls[0][3]['powermode'] == 'standby'
