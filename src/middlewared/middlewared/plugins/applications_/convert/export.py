"""Export an Application as a Linux compose bundle (the internal development record).

The mirror of the export-bundle reader (the internal development record): the user's
state is lifted out of the application's Daemonless volume into the layout the
recipe's Linux image expects, beside a compose file that names that image.
The FreeBSD image, its annotations and its networking stay behind.  What is
written is exactly the format ``bundle.discover`` and
``compose.read_export_compose`` read, so a bundle can come back through #445.
"""
import json
import os
import re
import shutil
import subprocess

from middlewared.plugins.applications_.catalog import CatalogContractError
from middlewared.plugins.applications_.convert import plan as plan_doc

MANAGED_ROOTS = {'applications', 'iocage', 'bastille'}
OWNERSHIP_ENVIRONMENT = ('PUID', 'PGID')
VERSION_LABEL = 'org.opencontainers.image.version'
README_NAME = 'README.export'
COMPOSE_NAME = 'compose.yaml'


def package_version(version):
    """``1.34.3_1`` / ``1.34.3,1`` -> ``1.34.3``: the upstream version a Linux tag names."""
    if not isinstance(version, str) or not version.strip():
        return None
    return re.split(r'[_,]', version.strip(), maxsplit=1)[0].lstrip('v') or None


def candidate_tags(export, installed_version):
    """The tags to try, best first: the exact version when the recipe knows the tag shape, then latest."""
    tags = []
    version = package_version(installed_version)
    template = export.get('tag_template')
    if template and version:
        tags.append(template.replace('{version}', version))
    if 'latest' not in tags:
        tags.append('latest')
    return tags


def target_version(tag, template, installed_version, labels):
    """The application version a resolved Linux image carries, or None when it cannot be told."""
    label = (labels or {}).get(VERSION_LABEL)
    if isinstance(label, str) and plan_doc.version_key(label):
        return label
    version = package_version(installed_version)
    if template and version and tag == template.replace('{version}', version):
        return version
    return None


def ownership(environment):
    """The numeric owner the Daemonless image ran the application as (PUID/PGID, default 1000)."""
    values = dict(environment)
    result = []
    for name in OWNERSHIP_ENVIRONMENT:
        try:
            result.append(int(values.get(name, '1000')))
        except ValueError:
            result.append(1000)
    return tuple(result)


def export_environment(environment, export):
    """The environment the Linux service gets, and what changed on the way."""
    user_mode = export['user']
    drop = set(export.get('drop_environment') or [])
    if user_mode != 'puid':
        drop.update(OWNERSHIP_ENVIRONMENT)
    overrides = dict(export.get('environment') or {})
    result, changes = [], []
    for name, value in environment:
        if name in drop:
            changes.append(f'{name} dropped')
            continue
        if name in overrides:
            if overrides[name] != value:
                changes.append(f'{name}={overrides[name]} (was {value})')
            result.append((name, overrides.pop(name)))
            continue
        result.append((name, value))
    for name, value in overrides.items():
        changes.append(f'{name}={value} added')
        result.append((name, value))
    return result, changes


def bundle_directory(target, taken):
    """The directory (or file) name a container path gets inside the bundle."""
    name = target.strip('/').replace('/', '-').lower() or 'root'
    name = re.sub(r'[^a-z0-9._-]', '-', name)[:120] or 'volume'
    candidate, index = name, 2
    while candidate in taken:
        candidate = f'{name}-{index}'
        index += 1
    taken.add(candidate)
    return candidate


def check_destination(destination):
    """An existing directory on a dataset, outside the managed hierarchies."""
    if not isinstance(destination, str) or not destination.startswith('/mnt/') or \
            os.path.normpath(destination) != destination:
        raise CatalogContractError('The export destination must be a normalized path below /mnt.')
    parts = destination.split('/')
    if len(parts) < 4:
        raise CatalogContractError('Choose a directory inside a dataset, not the pool root.')
    if parts[3] in MANAGED_ROOTS:
        raise CatalogContractError(
            f'The export destination may not be inside the {parts[3]} hierarchy; choose a dataset of your own.'
        )
    if os.path.islink(destination) or not os.path.isdir(destination):
        raise CatalogContractError('The export destination is not an existing directory.')


def _quote(value):
    return json.dumps(value, ensure_ascii=False)


def compose_text(service, image, environment, ports, volumes, user, comments, labels=None, runtime=None):
    """A one-service compose file in the shape the #445 reader reads."""
    lines = [f'# {line}' for line in comments]
    lines += ['services:', f'  {service}:', f'    image: {_quote(image)}', '    restart: "unless-stopped"']
    # the internal development record: the provider's stop grace period.
    if (runtime or {}).get('stop_timeout') is not None:
        lines.append(f'    stop_grace_period: {_quote(str(runtime["stop_timeout"]) + "s")}')
    # the internal development record: and its fixed host names (host=address reads for IPv6 too).
    if (runtime or {}).get('extra_hosts'):
        lines.append('    extra_hosts:')
        lines += ['      - ' + _quote(f'{item["host"]}={item["address"]}') for item in runtime['extra_hosts']]
    if user:
        lines.append(f'    user: {_quote(user)}')
    # the internal development record: the application's own labels travel with it.
    if labels:
        lines.append('    labels:')
        lines += ['      - ' + _quote(f'{name}={value}') for name, value in labels]
    if environment:
        lines.append('    environment:')
        lines += ['      - ' + _quote(f'{name}={value}') for name, value in environment]
    published = [port for port in ports if port['host_port'] is not None]
    if published:
        lines.append('    ports:')
        lines += [
            '      - ' + _quote('{host_port}:{container_port}/{protocol}'.format(**port))
            for port in published
        ]
    # the internal development record: a port kept on the managed bridge is declared, not published.
    exposed = [port for port in ports if port['host_port'] is None]
    if exposed:
        lines.append('    expose:')
        lines += ['      - ' + _quote('{container_port}/{protocol}'.format(**port)) for port in exposed]
    if volumes:
        lines.append('    volumes:')
        lines += [
            '      - ' + _quote(volume['source'] + ':' + volume['target'] + (':ro' if volume['read_only'] else ''))
            for volume in volumes
        ]
    return '\n'.join(lines) + '\n'


def check_host_root(host_root):
    """An absolute, normalized Linux path a compose bind can name (the internal development record)."""
    if not isinstance(host_root, str) or not host_root.startswith('/') or host_root == '/' or \
            os.path.normpath(host_root) != host_root or ':' in host_root or \
            any(character.isspace() or ord(character) < 32 for character in host_root):
        raise CatalogContractError('host_root must be a normalized absolute path without colons or whitespace.')


def readme_text(plan, mode, commands, host_root=None):
    """What the bundle is, what travelled, what stayed behind, and what to run on the Linux host."""
    lines = [
        f'FreeCORE export of application {plan["source"]["ref"]!r} (plan {plan["plan_id"]}).',
        f'Written {plan["created_at"]} as a {mode} export.',
        '',
        f'Linux image: {plan["target"]["image"]}',
        f'Application version on FreeCORE: {plan["app"].get("version") or "unknown"}; '
        f'in the Linux image: {plan["target"].get("version") or "unknown -- check before the first start"}.',
        '',
    ]
    name = plan['source']['ref']
    if host_root:
        lines += [
            f'The binds are absolute: copy this directory to {host_root}/{name} on the Linux host.',
            'Then paste compose.yaml into TrueNAS SCALE 24.10+ (Apps -> Discover -> Install via YAML),',
            f'or run docker compose up -d in {host_root}/{name}.',
        ]
    else:
        lines += [
            'Start it on a Linux Docker host from this directory: docker compose up -d',
            '(TrueNAS SCALE 24.10+ Install via YAML needs absolute paths: export again with host_root',
            'set to where this directory will live, or edit the ./ binds.)',
        ]
    lines += [
        '',
        'What the plan did:',
    ]
    lines += [f'  [{entry["type"]}] {entry["human"]}' for entry in plan['entries']]
    if commands:
        lines += ['', 'Run on the Linux host before the first start:']
        lines += [f'  {command}' for command in commands]
    lines += [
        '',
        'Never run the FreeCORE application and the Linux service against the same data at once.',
        'To bring this bundle back into FreeCORE, copy the directory onto a FreeCORE pool, turn on Convert',
        'in the Applications settings and, from the FreeCORE shell, plan the conversion, then apply the',
        'plan it returns (the web interface converts jails only):',
        '  midclt call applications.convert.plan \'{"kind": "linux-export", "path": "/mnt/<pool>/<directory>"}\' \'{}\'',
        '  midclt call -job applications.convert.apply <plan_id> \'{"confirm": true}\'',
    ]
    return '\n'.join(lines) + '\n'


def logical_size(target, run=subprocess.run):
    """Bytes a dataset or snapshot holds before compression, or None when ZFS cannot say."""
    try:
        output = run(['zfs', 'get', '-Hp', '-o', 'value', 'logicalreferenced', target],
                     capture_output=True, text=True, check=True).stdout
        return int(output.strip())
    except (OSError, subprocess.CalledProcessError, ValueError):
        return None


def free_bytes(path):
    return shutil.disk_usage(path).free


def human_size(size):
    value = float(size)
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if value < 1024 or unit == 'TiB':
            return f'{value:.0f} {unit}' if unit == 'B' else f'{value:.1f} {unit}'
        value /= 1024


def copy_state(source, destination):
    """Copy one piece of state out of a snapshot, keeping owners, modes, ACLs and times.

    Streamed through tar, never cp: FreeBSD's cp uses copy_file_range, which ZFS turns into
    block cloning when source and destination share a pool, and that activates
    block_cloning_endian -- an OpenZFS 2.4 feature TrueNAS SCALE 24.10 can only import
    read-only. An export prepares a move; it must not make the pool harder to move.
    """
    if os.path.lexists(destination):
        raise CatalogContractError(f'{destination} already exists; the export never overwrites.')
    if os.path.isdir(source) and not os.path.islink(source):
        os.makedirs(destination, mode=0o755)
        _tar_stream(source, '.', destination)
    else:
        # A single file (e.g. grafana.ini): read and written, so nothing is cloned either.
        os.makedirs(os.path.dirname(destination), mode=0o755, exist_ok=True)
        info = os.lstat(source)
        with open(source, 'rb') as reader, open(destination, 'xb') as writer:
            shutil.copyfileobj(reader, writer, 1024 * 1024)
        os.chmod(destination, info.st_mode & 0o7777)
        try:
            os.chown(destination, info.st_uid, info.st_gid)
        except PermissionError:
            pass  # only root keeps foreign owners; the appliance runs this as root
        os.utime(destination, ns=(info.st_atime_ns, info.st_mtime_ns))


def _tar_stream(directory, member, destination):
    producer = subprocess.Popen(['tar', '-cf', '-', '-C', directory, member],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    consumer = subprocess.run(['tar', '-xpf', '-', '-C', destination],
                              stdin=producer.stdout, capture_output=True, text=True)
    producer.stdout.close()
    produced = producer.wait()
    error = producer.stderr.read().decode(errors='replace').strip()
    producer.stderr.close()
    if produced != 0 or consumer.returncode != 0:
        raise CatalogContractError(
            f'Copying {directory} failed: {(error or consumer.stderr or consumer.stdout).strip() or "tar error"}'
        )
