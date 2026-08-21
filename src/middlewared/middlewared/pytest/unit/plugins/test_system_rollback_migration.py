import importlib.util
from pathlib import Path
from unittest.mock import patch

from alembic.migration import MigrationContext
from alembic.operations import Operations
import sqlalchemy as sa


MIGRATIONS = Path(__file__).parents[3] / 'alembic/versions/15.0'


def load_migration(filename):
    path = MIGRATIONS / filename
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_upgrade(connection, migration):
    context = MigrationContext.configure(
        connection, opts={'render_as_batch': True},
    )
    with patch.object(migration, 'op', Operations(context)):
        migration.upgrade()


def column_names(connection):
    return {
        column['name']
        for column in sa.inspect(connection).get_columns(
            'system_rollbackwindow',
        )
    }


def test_fresh_rollback_schema_never_creates_expiry():
    migration = load_migration('2026-08-09_03-00_rollback_window.py')
    engine = sa.create_engine('sqlite://')

    with engine.begin() as connection:
        run_upgrade(connection, migration)
        assert 'expires_at' not in column_names(connection)


def test_upgrade_removes_expiry_without_losing_capture():
    migration = load_migration('2026-08-16_00-00_remove_rollback_expiry.py')
    engine = sa.create_engine('sqlite://')

    with engine.begin() as connection:
        connection.exec_driver_sql(
            'CREATE TABLE system_rollbackwindow ('
            'id INTEGER PRIMARY KEY, origin_be VARCHAR(255) NOT NULL, '
            'arrival_path VARCHAR(32) NOT NULL, '
            'captured_at DATETIME NOT NULL, expires_at DATETIME NOT NULL, '
            'system_dataset VARCHAR(255) NOT NULL, snapshots TEXT NOT NULL, '
            'pool_state TEXT NOT NULL, closed_reason VARCHAR(32)'
            ')'
        )
        connection.exec_driver_sql(
            "INSERT INTO system_rollbackwindow VALUES "
            "(1, '13.3-U1.2', 'train', '2026-08-16 12:00:00', "
            "'2026-09-15 12:00:00', 'tank/.system', '[]', '{}', NULL)"
        )

        run_upgrade(connection, migration)

        assert 'expires_at' not in column_names(connection)
        assert connection.exec_driver_sql(
            'SELECT id, origin_be, captured_at, system_dataset '
            'FROM system_rollbackwindow'
        ).one() == (1, '13.3-U1.2', '2026-08-16 12:00:00', 'tank/.system')


def test_expiry_removal_is_safe_when_fresh_schema_already_omits_it():
    create = load_migration('2026-08-09_03-00_rollback_window.py')
    remove = load_migration('2026-08-16_00-00_remove_rollback_expiry.py')
    engine = sa.create_engine('sqlite://')

    with engine.begin() as connection:
        run_upgrade(connection, create)
        run_upgrade(connection, remove)
        assert 'expires_at' not in column_names(connection)
