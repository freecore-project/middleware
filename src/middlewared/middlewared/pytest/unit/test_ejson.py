# middlewared.client.ejson: {"$date": <ms since epoch>} round trips exactly (rust/UPSTREAM.md #70)
from datetime import datetime, timedelta, timezone

import pytest

from middlewared.client import ejson


@pytest.mark.parametrize('ms', [0, 1, 530, 999, 1000, 1704092655530, 1704092655999])
def test_date_decodes_to_the_millisecond_it_encodes(ms):
    decoded = ejson.loads(f'{{"$date": {ms}}}')
    assert decoded == datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=ms)


def test_date_round_trip():
    value = datetime(2024, 1, 1, 7, 4, 15, 530000, tzinfo=timezone.utc)
    assert ejson.loads(ejson.dumps(value)) == value


def test_aware_datetime_is_encoded_in_utc():
    # 10:00 at UTC+2 is 08:00 UTC
    local = datetime(2024, 1, 1, 10, 0, tzinfo=timezone(timedelta(hours=2)))
    assert ejson.loads(ejson.dumps(local)) == datetime(2024, 1, 1, 8, 0, tzinfo=timezone.utc)
