"""INI configuration carry with an allow/deny list (the internal development record).

Grafana reads an ini file and lets ``GF_<SECTION>_<KEY>`` environment override
it.  The Linux source expresses most configuration as environment, the jail
source as the file; both are folded into one section map, environment winning,
and only then do the recipe's allow and deny patterns apply.
"""
import configparser
import fnmatch
import io
import re

# Section names Grafana uses; needed to split GF_<SECTION>_<KEY> where the
# section itself contains underscores (unified_alerting, auth.generic_oauth).
KNOWN_SECTIONS = (
    'DEFAULT', 'paths', 'server', 'database', 'remote_cache', 'dataproxy', 'analytics',
    'security', 'snapshots', 'dashboards', 'users', 'auth', 'auth.anonymous',
    'auth.github', 'auth.gitlab', 'auth.google', 'auth.grafana_com', 'auth.azuread',
    'auth.okta', 'auth.generic_oauth', 'auth.basic', 'auth.proxy', 'auth.jwt',
    'auth.ldap', 'aws', 'azure', 'smtp', 'emails', 'log', 'log.console', 'log.file',
    'log.syslog', 'log.frontend', 'quota', 'unified_alerting', 'alerting', 'annotations',
    'explore', 'metrics', 'grafana_com', 'tracing.jaeger', 'external_image_storage',
    'rendering', 'panels', 'plugins', 'live', 'plugin.grafana-image-renderer',
    'enterprise', 'feature_toggles', 'date_formats', 'expressions', 'geomap',
    'grpc_server', 'security.encryption', 'help', 'profile', 'news', 'query_history',
    'unified_alerting.screenshots', 'unified_alerting.reserved_labels',
)


def parse_ini(text):
    """Sections and keys of an ini file, tolerant of Grafana's comment styles."""
    parser = configparser.RawConfigParser(
        allow_no_value=True, strict=False, delimiters=('=',),
        comment_prefixes=('#', ';'), inline_comment_prefixes=(';',),
        empty_lines_in_values=False, default_section='DEFAULT',
    )
    parser.optionxform = str
    body = text
    stripped = '\n'.join(
        line for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith(('#', ';'))
    )
    if stripped and not stripped.lstrip().startswith('['):
        body = '[DEFAULT]\n' + text
    parser.read_string(body)
    result = {}
    defaults = dict(parser.defaults())
    if defaults:
        result['DEFAULT'] = {key: (value or '') for key, value in defaults.items()}
    for section in parser.sections():
        values = {}
        for key, value in parser.items(section, raw=True):
            if key in defaults and defaults[key] == value:
                continue
            values[key] = value or ''
        result[section] = values
    return result


def _normalize(section):
    return re.sub(r'[.-]', '_', section).upper()


def env_overrides(environment, prefix='GF_', known_sections=()):
    """GF_SECTION_KEY=value entries as a section map."""
    sections = list(dict.fromkeys([*known_sections, *KNOWN_SECTIONS]))
    by_normal = sorted(
        ((_normalize(section), section) for section in sections),
        key=lambda item: -len(item[0]),
    )
    result = {}
    for name, value in (environment or {}).items():
        if not isinstance(name, str) or not name.startswith(prefix):
            continue
        rest = name[len(prefix):]
        for normal, section in by_normal:
            if rest.startswith(normal + '_') and len(rest) > len(normal) + 1:
                key = rest[len(normal) + 1:].lower()
                result.setdefault(section, {})[key] = '' if value is None else str(value)
                break
    return result


def merged(ini_sections, env_sections):
    result = {section: dict(values) for section, values in (ini_sections or {}).items()}
    for section, values in (env_sections or {}).items():
        result.setdefault(section, {}).update(values)
    return result


def matches(pattern, section, key):
    dotted = f'{section}.{key}'
    if pattern == section:
        return True
    return fnmatch.fnmatchcase(dotted, pattern)


def translate(sections, allow, deny):
    """Keep only allowed keys that are not denied; report what was left behind."""
    carried = {}
    denied = []
    dropped = []
    for section, values in sorted(sections.items()):
        for key, value in sorted(values.items()):
            if any(matches(pattern, section, key) for pattern in deny):
                denied.append(f'{section}.{key}')
            elif any(matches(pattern, section, key) for pattern in allow):
                carried.setdefault(section, {})[key] = value
            else:
                dropped.append(f'{section}.{key}')
    return carried, denied, dropped


def render(sections, header=None):
    buffer = io.StringIO()
    if header:
        for line in header.splitlines():
            buffer.write(f'# {line}\n')
        buffer.write('\n')
    for section, values in sections.items():
        if not values:
            continue
        buffer.write(f'[{section}]\n')
        for key, value in values.items():
            buffer.write(f'{key} = {value}\n')
        buffer.write('\n')
    return buffer.getvalue()
