import importlib.util
from pathlib import Path
from unittest.mock import patch

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

MIGRATION = (
    Path(__file__).parents[3]
    / 'alembic/versions/15.0/2026-08-24_00-00_applications_lifecycle.py'
)


def load_migration():
    spec = importlib.util.spec_from_file_location('applications_lifecycle_migration', MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fresh_applications_configuration_is_singleton_and_not_a_service():
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
            'SELECT app_pool, app_subnet, app_restart_on_boot, app_pf_owned, '
            'app_filter_local_original, app_ipv4_forwarding_original, '
            'app_bridge_pfil_member_original FROM services_applications'
        ).one() == (None, '10.88.0.0/16', 0, 0, None, None, None)
        assert connection.exec_driver_sql(
            'SELECT COUNT(*) FROM services_services'
        ).scalar_one() == 0

        columns = {
            column['name']
            for column in sa.inspect(connection).get_columns('services_applications')
        }
        assert columns == {
            'id',
            'app_pool',
            'app_subnet',
            'app_restart_on_boot',
            'app_pf_owned',
            'app_filter_local_original',
            'app_ipv4_forwarding_original',
            'app_bridge_pfil_member_original',
        }
