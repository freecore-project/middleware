# the internal development record: TokenManager drops expired tokens when it mints a new one.
from middlewared.plugins.auth import TokenManager


def test_an_expired_token_is_dropped_by_the_next_create():
    manager = TokenManager()
    expired = manager.create(0)

    manager.create(300)

    assert expired.token not in manager.tokens


def test_a_valid_token_survives_the_next_create():
    manager = TokenManager()
    valid = manager.create(300)

    manager.create(300)

    assert manager.get(valid.token) is valid


def test_a_token_kept_alive_by_its_session_survives():
    manager = TokenManager()
    used = manager.create(300)
    used.last_used_at -= 299
    used.notify_used()

    manager.create(300)

    assert manager.get(used.token) is used


def test_re_minting_every_few_minutes_keeps_the_table_small():
    manager = TokenManager()
    for _ in range(100):
        stale = manager.create(300)
        stale.last_used_at -= 301

    assert len(manager.tokens) == 1
