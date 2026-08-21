"""the internal development record: the OpenVPN tables come back exactly as TrueNAS 13.3 had them.

A configuration exported for TrueNAS SCALE is downgraded through this revision. Its downgrade must
recreate 13.3's schema -- NOT NULL columns, the certificate foreign keys and their indexes -- or the
exported database differs from 13.3's in exactly these two tables. Checked against the 13.3 factory
database the image ships, by replaying the downgrade on a copy of it with the two tables removed.
"""
import importlib.util
import os
import shutil
import sqlite3
from types import SimpleNamespace

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
MIDDLEWARED = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
REPOSITORY = os.path.dirname(os.path.dirname(MIDDLEWARED))
MIGRATION = os.path.join(MIDDLEWARED, 'alembic', 'versions', '15.0', '2026-08-09_01-00_remove_openvpn.py')
FACTORY = os.path.join(REPOSITORY, 'freenas', 'usr', 'local', 'share', 'truenas', 'factory-v1.db')
TABLES = ('services_openvpnclient', 'services_openvpnserver')


def schema(connection, table):
    return {
        'columns': [tuple(row[1:]) for row in connection.execute(f'PRAGMA table_info("{table}")')],
        'foreign_keys': sorted(tuple(row[2:5]) for row in connection.execute(f'PRAGMA foreign_key_list("{table}")')),
        'indexes': sorted(
            (row[1], row[2], tuple(column[2] for column in connection.execute(f'PRAGMA index_info("{row[1]}")')))
            for row in connection.execute(f'PRAGMA index_list("{table}")')
        ),
    }


@pytest.mark.skipif(not os.path.exists(FACTORY), reason='the 13.3 factory database is not in this checkout')
def test_downgrade_recreates_the_13_3_openvpn_tables(tmp_path):
    copy = tmp_path / 'factory.db'
    shutil.copyfile(FACTORY, copy)
    connection = sqlite3.connect(copy)
    expected = {table: schema(connection, table) for table in TABLES}
    services = sorted(connection.execute("SELECT srv_service FROM services_services WHERE srv_service LIKE 'openvpn%'"))
    for table in TABLES:
        connection.execute(f'DROP TABLE {table}')
    connection.execute("DELETE FROM services_services WHERE srv_service LIKE 'openvpn%'")

    spec = importlib.util.spec_from_file_location('remove_openvpn', MIGRATION)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    migration.op = SimpleNamespace(execute=connection.execute)
    migration.downgrade()

    assert {table: schema(connection, table) for table in TABLES} == expected
    assert sorted(connection.execute(
        "SELECT srv_service FROM services_services WHERE srv_service LIKE 'openvpn%'"
    )) == services
