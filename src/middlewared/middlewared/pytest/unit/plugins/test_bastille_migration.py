import importlib.util
from pathlib import Path
from unittest.mock import patch

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

MIGRATION = (
    Path(__file__).parents[3]
    / 'alembic/versions/15.0/2026-08-24_01-00_bastille_service.py'
)


def load_migration():
    spec = importlib.util.spec_from_file_location('bastille_service_migration', MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fresh_bastille_service_is_disabled_and_unconfigured():
    migration = load_migration()
    engine = sa.create_engine('sqlite://')

    with engine.begin() as connection:
        connection.exec_driver_sql(
            'CREATE TABLE services_services ('
            'id INTEGER PRIMARY KEY, srv_service VARCHAR(120), srv_enable BOOLEAN'
            ')'
        )
        context = MigrationContext.configure(connection)
        with patch.object(migration, 'op', Operations(context)):
            migration.upgrade()

        assert connection.exec_driver_sql(
            'SELECT bastille_pool, bastille_startup_delay, bastille_parallel_limit '
            'FROM services_bastille'
        ).one() == (None, 0, 1)
        assert connection.exec_driver_sql(
            "SELECT srv_enable FROM services_services WHERE srv_service = 'bastille'"
        ).scalar_one() == 0

        with patch.object(migration, 'op', Operations(context)):
            migration.downgrade()
        assert connection.exec_driver_sql(
            "SELECT COUNT(*) FROM services_services WHERE srv_service = 'bastille'"
        ).scalar_one() == 0
