# the internal development record: a boot environment's "created" is an aware UTC time, not bectl's local time sent as UTC.
import os
import subprocess
import time
from datetime import datetime, timezone
from unittest.mock import Mock, patch

import pytest

from middlewared.plugins.bootenv import BootEnvService

# bectl list -H: name, active, mountpoint, space, created (the box's local time, to the minute)
BECTL = 'with-dataset\tNR\t/\t2.1G\t2026-10-12 08:27\nno-dataset\t-\t-\t1.0G\t2026-10-12 08:31\n'
CREATION = datetime(2026, 10, 12, 15, 27, 40, tzinfo=timezone.utc)


@pytest.fixture
def pacific():
    old = os.environ.get('TZ')
    os.environ['TZ'] = 'America/Los_Angeles'
    time.tzset()
    yield
    if old is None:
        os.environ.pop('TZ')
    else:
        os.environ['TZ'] = old
    time.tzset()


def middleware():
    def call_sync(method, *args, **kwargs):
        if method == 'boot.pool_name':
            return 'boot-pool'
        if method == 'zfs.dataset.query':
            if not args:
                return []
            if args[0][0][2] == 'boot-pool/ROOT/with-dataset':
                return [{'snapshots': [], 'properties': {
                    'origin': {'parsed': ''}, 'creation': {'parsed': CREATION},
                    'usedbydataset': {'parsed': 2048}, 'usedbychildren': {'parsed': 0},
                }}]
            return []
        raise AssertionError(method)
    return Mock(call_sync=call_sync)


def query(filters=None, options=None):
    # the undecorated query: the accepts() wrapper needs a running middleware to resolve query-filters
    service = BootEnvService(middleware())
    done = subprocess.CompletedProcess(['bectl'], 0, stdout=BECTL, stderr='')
    with patch('middlewared.plugins.bootenv.subprocess.run', return_value=done):
        result = BootEnvService.query.wraps(service, filters or [], options or {})
    return result if options else {be['id']: be for be in result}


def test_created_is_the_datasets_own_creation_time(pacific):
    assert query()['with-dataset']['created'] == CREATION


def test_without_a_dataset_bectls_local_time_is_read_as_local(pacific):
    assert query()['no-dataset']['created'] == datetime(2026, 10, 12, 15, 31, tzinfo=timezone.utc)


def test_the_updater_can_still_order_boot_environments_by_created(pacific):
    assert [be['id'] for be in query([], {'order_by': ['created']})] == ['with-dataset', 'no-dataset']
