"""Read-only probes of application state (the internal development record).

Every probe opens its input read-only and answers a question the plan needs:
which package version a jail carries, whether a Grafana database still holds
legacy dashboard alerts, which dashboards use AngularJS panels, which plugins
are frontend-only.  None of them writes.
"""
import json
import os
import re
import sqlite3
from pathlib import Path

ANGULAR_PANELS = {
    'graph', 'table-old', 'singlestat', 'grafana-piechart-panel', 'grafana-worldmap-panel',
    'natel-discrete-panel', 'grafana-singlestat-panel',
}
MAX_DASHBOARDS = 5000


def _connect_readonly(path):
    uri = f'file:{Path(path).as_posix()}?mode=ro&immutable=1'
    return sqlite3.connect(uri, uri=True, timeout=5)


def sqlite_scalar(path, query, parameters=()):
    if not os.path.isfile(path):
        return None
    try:
        with _connect_readonly(path) as connection:
            row = connection.execute(query, parameters).fetchone()
    except sqlite3.Error:
        return None
    return None if row is None else row[0]


def pkg_version(root, package):
    """The installed version of a package in a jail, from its pkg database."""
    return sqlite_scalar(
        os.path.join(root, 'var/db/pkg/local.sqlite'),
        'SELECT version FROM packages WHERE name = ? LIMIT 1',
        (package,),
    )


def legacy_alerts_present(db_path):
    """Count of legacy dashboard alerts in a Grafana database (0 when the table is absent)."""
    count = sqlite_scalar(db_path, 'SELECT count(*) FROM alert')
    return int(count or 0)


def angular_panels(db_path):
    """Dashboards that still carry AngularJS panels, as (title, panel type) pairs."""
    if not os.path.isfile(db_path):
        return []
    found = []
    try:
        with _connect_readonly(db_path) as connection:
            rows = connection.execute(
                'SELECT title, data FROM dashboard WHERE is_folder = 0 LIMIT ?', (MAX_DASHBOARDS,)
            ).fetchall()
    except sqlite3.Error:
        return []
    for title, data in rows:
        try:
            dashboard = json.loads(data)
        except (TypeError, ValueError):
            continue
        panels = list(dashboard.get('panels') or [])
        for row in dashboard.get('rows') or []:
            panels.extend(row.get('panels') or [])
        for panel in panels:
            for nested in panel.get('panels') or []:
                panels.append(nested)
        for panel in panels:
            kind = panel.get('type')
            if kind in ANGULAR_PANELS:
                found.append((title, kind))
    return found


def grafana_version_from_db(db_path):
    """The last Grafana version that migrated this database, if recorded."""
    return sqlite_scalar(
        db_path,
        "SELECT migration_id FROM migration_log ORDER BY id DESC LIMIT 1",
    )


def database_type(sections):
    database = (sections or {}).get('database') or {}
    return (database.get('type') or 'sqlite3').strip() or 'sqlite3'


def classify_plugins(plugins_dir):
    """Split a Grafana plugins directory into frontend-only (carried) and backend (dropped)."""
    carried = []
    dropped = []
    if not os.path.isdir(plugins_dir):
        return carried, dropped
    for name in sorted(os.listdir(plugins_dir)):
        path = os.path.join(plugins_dir, name)
        if not os.path.isdir(path):
            continue
        manifest = os.path.join(path, 'plugin.json')
        backend = False
        try:
            with open(manifest, 'rb') as file:
                data = json.loads(file.read().decode('utf-8'))
            backend = bool(data.get('backend')) or bool(data.get('executable'))
        except (OSError, ValueError):
            backend = any(
                os.access(os.path.join(path, entry), os.X_OK)
                and not entry.endswith(('.js', '.json', '.css', '.md', '.html'))
                for entry in os.listdir(path)
                if os.path.isfile(os.path.join(path, entry))
            )
        (dropped if backend else carried).append(name)
    return carried, dropped


def installed_packages(root, limit=2000):
    """Packages a jail's pkg database lists, as (name, version, automatic) triples.

    the internal development record: the lift asks only which software a jail carries;
    ``automatic`` (0 for what the administrator asked for) is read when the
    schema has it.
    """
    path = os.path.join(root, 'var/db/pkg/local.sqlite')
    if not os.path.isfile(path):
        return []
    try:
        with _connect_readonly(path) as connection:
            columns = {row[1] for row in connection.execute('PRAGMA table_info(packages)').fetchall()}
            if 'automatic' in columns:
                rows = connection.execute(
                    'SELECT name, version, automatic FROM packages ORDER BY name LIMIT ?', (limit,)
                ).fetchall()
            else:
                rows = [
                    (name, version, 0) for name, version in connection.execute(
                        'SELECT name, version FROM packages ORDER BY name LIMIT ?', (limit,)
                    ).fetchall()
                ]
    except sqlite3.Error:
        return []
    return [(str(name), str(version), bool(automatic)) for name, version, automatic in rows]


RC_SETTING = re.compile(r'^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>"[^"]*"|\'[^\']*\'|[^#\s]+)', re.M)
RC_DEFAULT = re.compile(
    r'(?::\s*\$\{(?P<a>[A-Za-z_][A-Za-z0-9_]*)(?::=|=)\s*(?P<av>"[^"]*"|\'[^\']*\'|[^}\s]+)\s*\})'
    r'|(?:^\s*(?P<b>[A-Za-z_][A-Za-z0-9_]*)=\$\{(?P=b)(?::-|-)(?P<bv>"[^"]*"|\'[^\']*\'|[^}]+)\})',
    re.M,
)


def _unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
        value = value[1:-1]
    return value


def rc_setting(rc_conf, name):
    """The value of one rc.conf setting, last assignment wins; None when absent."""
    found = None
    for match in RC_SETTING.finditer(rc_conf or ''):
        if match.group('name') == name:
            found = _unquote(match.group('value'))
    return found


def rc_script_default(root, script, name):
    """The default an rc.d script gives one of its variables (``: ${x:="v"}`` or ``x=${x:-v}``)."""
    path = os.path.join(root, 'usr/local/etc/rc.d', script)
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as file:
            text = file.read(256 * 1024)
    except OSError:
        return None
    for match in RC_DEFAULT.finditer(text):
        if match.group('a') == name:
            return _unquote(match.group('av'))
        if match.group('b') == name:
            return _unquote(match.group('bv'))
    return None
