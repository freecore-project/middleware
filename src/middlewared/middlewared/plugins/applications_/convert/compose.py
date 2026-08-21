"""Read one service out of an exported compose file (the internal development record).

The reader turns the compose file of an export bundle into the same normalised
source description the jail adapter produces.  It refuses, by key, what a
jail-backed container cannot honour or what the Applications safety contract
never grants, and it drops with a note -- never silently -- what has no
equivalent on this side.
"""
import re

from middlewared.plugins.applications_.catalog import (
    MAX_STOP_TIMEOUT,
    CatalogContractError,
    compose_duration_seconds,
    compose_extra_hosts,
    parse_catalog_yaml,
)
from middlewared.plugins.applications_.utils import validate_image_reference

REFUSE_KEYS = {
    'privileged': 'privileged containers are never granted',
    'cap_add': 'Linux capabilities cannot be granted to a jail-backed container',
    'devices': 'host device access is never granted',
    'sysctls': 'container sysctls are not supported',
    'security_opt': 'security options have no equivalent',
    'userns_mode': 'user namespaces are not available',
    'cgroup_parent': 'cgroups are not available',
    'build': 'a build context cannot be reproduced on the appliance',
    'secrets': 'compose secrets are not expressible; pass values as environment',
    'configs': 'compose configs are not expressible',
    'env_file': 'env_file must be resolved into environment before export so the bundle is self-contained',
    'depends_on': 'multi-service stacks are not supported yet; export one service per bundle',
}
REFUSE_VALUES = {
    'network_mode': {'host': 'host networking is never granted; attach the application to a LAN network instead'},
    'pid': {'host': 'the host PID namespace is never shared'},
    'ipc': {'host': 'the host IPC namespace is never shared'},
}
DROP_KEYS = {
    'deploy': 'resource and placement settings are ignored',
    'logging': 'the runtime keeps its own log driver',
    'dns': 'the container resolves through the Applications bridge',
    'dns_search': 'the container resolves through the Applications bridge',
    'networks': 'the application joins the Applications bridge',
    'stdin_open': 'interactive settings are not carried',
    'tty': 'interactive settings are not carried',
    'hostname': 'the container hostname is managed',
    'container_name': 'the container name is managed',
    'links': 'legacy links are not carried',
    'ulimits': 'resource limits are not carried',
    'mem_limit': 'resource limits are not carried',
    'cpus': 'resource limits are not carried',
    'shm_size': 'the runtime sizes /dev/shm',
    'tmpfs': 'tmpfs mounts are not carried',
    'entrypoint': 'entrypoint overrides are not carried; the image entrypoint runs',
    'working_dir': 'working directory overrides are not carried',
    'read_only': 'read-only root filesystems are not carried',
    'init': 'the runtime decides on an init process',
    'platform': 'the platform is chosen by the tier',
    'profiles': 'compose profiles are ignored',
    'healthcheck': 'compose health checks are folded into the startup probe where expressible',
}
KNOWN_KEYS = {
    'image', 'environment', 'ports', 'volumes', 'restart', 'user', 'command', 'expose',
    # the internal development record: labels used to be dropped as "information only"; they are
    # carried onto the container now, so an import keeps them.
    'network_mode', 'pid', 'ipc', 'healthcheck', 'labels',
    # the internal development record: carried as the container's stop timeout.
    'stop_grace_period',
    # the internal development record: carried as the container's fixed host names.
    'extra_hosts',
} | set(REFUSE_KEYS) | set(DROP_KEYS)
RESTART_POLICIES = {
    'always': 'always', 'unless-stopped': 'always', 'on-failure': 'on-failure', 'no': 'no',
}
ENVIRONMENT_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
PORT = re.compile(
    r'^(?:(?P<host_ip>[0-9a-fA-F.:\[\]]+):)?(?:(?P<host>\d+)(?:-\d+)?:)?'
    r'(?P<container>\d+)(?:-\d+)?(?:/(?P<protocol>tcp|udp))?$'
)


def _environment(service):
    source = service.get('environment') or []
    values = []
    if isinstance(source, dict):
        values = list(source.items())
    elif isinstance(source, list):
        for item in source:
            if not isinstance(item, str):
                raise CatalogContractError('Environment list entries must be text.')
            name, _, value = item.partition('=')
            values.append((name, value))
    else:
        raise CatalogContractError('Service environment must be a list or a mapping.')
    result = []
    seen = set()
    for name, value in values:
        if not isinstance(name, str) or not ENVIRONMENT_NAME.fullmatch(name) or name in seen:
            raise CatalogContractError(f'Environment variable name {name!r} is invalid or repeated.')
        seen.add(name)
        if value is None:
            value = ''
        elif isinstance(value, bool):
            value = str(value).lower()
        elif isinstance(value, (int, float, str)):
            value = str(value)
        else:
            raise CatalogContractError(f'Environment value for {name!r} must be scalar.')
        if '${' in value:
            raise CatalogContractError(
                f'Environment value for {name!r} uses interpolation; resolve it before export.'
            )
        result.append({'name': name, 'value': value})
    return sorted(result, key=lambda item: item['name'])


def _ports(service, drops):
    result = []
    for item in service.get('ports') or []:
        if isinstance(item, dict):
            container = item.get('target')
            host = item.get('published')
            protocol = item.get('protocol') or 'tcp'
            host_ip = item.get('host_ip')
        else:
            # Read from the right: [host_ip:][host:]container[/protocol]. A digits-only
            # left part is a host port, never an address (the internal development record).
            text = str(item).strip()
            protocol = 'tcp'
            if '/' in text:
                text, protocol = text.rsplit('/', 1)
            if not PORT.fullmatch(f'{text}/{protocol}'):
                raise CatalogContractError(f'Port declaration {item!r} is not understood.')
            parts = text.split(':')
            host_ip = None
            host = None
            if len(parts) == 2:
                host, container = parts
            elif len(parts) > 2:
                host_ip, host, container = ':'.join(parts[:-2]), parts[-2], parts[-1]
            else:
                container = parts[0]
            container = container.split('-', 1)[0]
            host = host.split('-', 1)[0] if host else host
        try:
            container_port = int(container)
            host_port = int(host) if host not in (None, '') else container_port
        except (TypeError, ValueError) as error:
            raise CatalogContractError(f'Port declaration {item!r} is not understood.') from error
        if protocol not in {'tcp', 'udp'} or not 1 <= container_port <= 65535 or not 1 <= host_port <= 65535:
            raise CatalogContractError(f'Port declaration {item!r} is out of range.')
        if host_ip:
            drops.append(
                f'port {host_port}: the host address binding {host_ip!r} is dropped; '
                'the port is published on every address'
            )
        result.append({'host_port': host_port, 'container_port': container_port, 'protocol': protocol})
    return result


def _exposed(service, published, drops):
    """``expose:``: ports a FreeCORE export kept on the managed network (the internal development record).

    A port that is also published stays published; an entry that is not a single port is left out.
    """
    result = []
    for item in service.get('expose') or []:
        text = str(item).strip()
        protocol = 'tcp'
        if '/' in text:
            text, protocol = text.rsplit('/', 1)
        if not text.isdigit() or protocol not in {'tcp', 'udp'} or not 1 <= int(text) <= 65535:
            drops.append(f'expose: {item!r} is not a single port, ignored')
            continue
        port = {'container_port': int(text), 'protocol': protocol}
        if port in result or any(
            other['container_port'] == port['container_port'] and other['protocol'] == protocol for other in published
        ):
            continue
        result.append(port)
    return result


def _volumes(service, named_volumes):
    result = []
    for item in service.get('volumes') or []:
        if isinstance(item, dict):
            kind = item.get('type')
            source = item.get('source')
            target = item.get('target')
            read_only = bool(item.get('read_only'))
            if kind == 'tmpfs':
                continue
            if kind not in {'bind', 'volume'}:
                raise CatalogContractError(f'Volume declaration {item!r} is not understood.')
        else:
            parts = str(item).split(':')
            if len(parts) == 1:
                raise CatalogContractError(
                    f'Anonymous volume {item!r} has no source; export it as a named volume.'
                )
            source, target = parts[0], parts[1]
            options = parts[2].split(',') if len(parts) > 2 else []
            read_only = 'ro' in options
            kind = 'bind' if source.startswith(('/', './', '../', '~')) else 'volume'
        if not isinstance(target, str) or not target.startswith('/'):
            raise CatalogContractError(f'Volume target {target!r} must be an absolute path.')
        if kind == 'volume' and source not in named_volumes:
            raise CatalogContractError(
                f'Named volume {source!r} is not declared at the top level of the compose file.'
            )
        result.append({
            'kind': kind,
            'source': source,
            'target': target.rstrip('/') or '/',
            'read_only': read_only,
        })
    return result


def _healthcheck(service):
    check = service.get('healthcheck')
    if not isinstance(check, dict) or check.get('disable'):
        return None
    test = check.get('test')
    if isinstance(test, str):
        text = test
    elif isinstance(test, list):
        text = ' '.join(str(part) for part in test)
    else:
        return None
    match = re.search(r'https?://(?:localhost|127\.0\.0\.1)(?::(\d+))?(/\S*)?', text)
    if match is None:
        return None
    return {
        'container_port': int(match.group(1) or 80),
        'path': match.group(2) or '/',
    }


def read_export_compose(text):
    """Normalise a single-service compose file into a source description.

    Returns a mapping with ``service``, ``image``, ``environment``, ``ports``,
    ``exposed``, ``volumes``, ``restart``, ``healthcheck``, ``user``, ``command``,
    ``labels``, ``refusals`` and ``drops``.  ``refusals`` non-empty means the plan
    refuses.
    """
    data = parse_catalog_yaml(text)
    services = data.get('services')
    if not isinstance(services, dict) or not services:
        raise CatalogContractError('The compose file declares no services.')
    refusals = []
    drops = []
    if len(services) != 1:
        refusals.append(
            'the compose file declares several services '
            f'({", ".join(sorted(str(name) for name in services))}); export one service per bundle'
        )
    service_name, service = next(iter(services.items()))
    if not isinstance(service, dict):
        raise CatalogContractError('The compose service is malformed.')
    named_volumes = set((data.get('volumes') or {}).keys()) if isinstance(data.get('volumes'), dict) else set()

    for key in sorted(service):
        if key in REFUSE_KEYS:
            refusals.append(f'{key}: {REFUSE_KEYS[key]}')
        elif key in REFUSE_VALUES and str(service.get(key)) in REFUSE_VALUES[key]:
            refusals.append(f'{key}: {REFUSE_VALUES[key][str(service[key])]}')
        elif key in DROP_KEYS:
            drops.append(f'{key}: {DROP_KEYS[key]}')
        elif key not in KNOWN_KEYS:
            drops.append(f'{key}: not understood, ignored')

    image = service.get('image')
    if not isinstance(image, str):
        raise CatalogContractError('The compose service declares no image.')
    try:
        validate_image_reference(image)
    except ValueError as error:
        raise CatalogContractError(str(error)) from error

    restart = RESTART_POLICIES.get(service.get('restart', 'unless-stopped'))
    if restart is None:
        drops.append(f'restart: {service.get("restart")!r} is not understood; "always" is used')
        restart = 'always'
    command = service.get('command')
    if command is not None:
        command = [str(part) for part in command] if isinstance(command, list) else [str(command)]
    labels = service.get('labels') or {}
    if isinstance(labels, list):
        labels = dict(item.partition('=')[::2] for item in labels if isinstance(item, str))
    ports = _ports(service, drops)
    stop_timeout = None
    if 'stop_grace_period' in service:
        stop_timeout = compose_duration_seconds(service['stop_grace_period'])
        if stop_timeout is None or stop_timeout > MAX_STOP_TIMEOUT:
            drops.append('stop_grace_period: not a duration of at most 3600 seconds, ignored')
            stop_timeout = None
    extra_hosts = []
    if 'extra_hosts' in service:
        try:
            extra_hosts = compose_extra_hosts(service['extra_hosts'])
        except ValueError as error:
            drops.append(f'extra_hosts: {error}, ignored')
    return {
        'service': str(service_name),
        'image': image,
        'environment': _environment(service),
        'ports': ports,
        'exposed': _exposed(service, ports, drops),
        'volumes': _volumes(service, named_volumes),
        'restart': restart,
        'healthcheck': _healthcheck(service),
        'user': str(service['user']) if service.get('user') is not None else None,
        'command': command,
        'labels': {str(key): str(value) for key, value in labels.items()} if isinstance(labels, dict) else {},
        'stop_timeout': stop_timeout,
        'extra_hosts': extra_hosts,
        'refusals': refusals,
        'drops': drops,
    }
