"""Bind new administrator choices to an installed application's own contract
(the internal development record).

An installed record already carries every declaration the install form was
built from -- container ports and protocols, environment names, volume names,
targets and read-only flags, the portal and health check bindings -- so a
change of host ports, values, storage mappings or restart policy binds to the
record alone: no catalog read, no pull, the image stays exactly what it is.
"""
import copy

from middlewared.plugins.applications_ import certificates as app_certificates

RESTART_POLICIES = {'no', 'on-failure', 'always'}
# the internal development record: the install-time label rules (applications_freebsd._validate_install).
RESERVED_LABEL_PREFIX = 'io.freecore.'
MAX_LABELS = 128
MAX_LABEL_VALUE_BYTES = 4096


class ReconfigureError(ValueError):
    pass


def _mounted(entry):
    return {key: value for key, value in entry.items() if key not in ('name', 'fingerprint')}


def _bind_certificates(record, data):
    """``(certificates, changed_targets)`` (the internal development record).

    Mounted certificates are the operator's own, like labels: ``None`` keeps the
    installed set, and a list -- the empty one included -- replaces it. The entries are
    checked against the application's own volume targets here, because an edit can move
    a volume and a certificate in the same request.
    """
    current = copy.deepcopy(record.get('certificates') or [])
    requested = data.get('certificates')
    if requested is None:
        return current, []
    volume_targets = [item['target'] for item in record.get('volumes') or []]
    errors = app_certificates.validate_entries(requested, volume_targets)
    if errors:
        raise ReconfigureError(errors[0][1])
    certificates = [app_certificates.bound_entry(entry) for entry in requested]
    # What the container sees: the name and fingerprint only describe the binding, and a
    # renewal or a rename refreshes them without changing what is mounted.
    before = {item['target']: _mounted(item) for item in current}
    after = {item['target']: _mounted(item) for item in certificates}
    changed = sorted(
        target for target in set(before) | set(after) if before.get(target) != after.get(target)
    )
    return certificates, changed


def _port_index(ports, host_port):
    return next((
        index for index, port in enumerate(ports)
        if port['protocol'] == 'tcp' and port['host_port'] == host_port
    ), None)


def _bind_labels(record, data):
    """``(labels, changed_names)`` (the internal development record).

    Labels are the operator's own, not declarations the record binds: ``None`` keeps the
    installed set (a caller that predates labels, or does not edit them), and a list -- the
    empty one included -- replaces it. A record written before labels existed has none.
    """
    current = copy.deepcopy(record.get('labels') or [])
    requested = data.get('labels')
    if requested is None:
        return current, []
    if len(requested) > MAX_LABELS:
        raise ReconfigureError(f'An application may carry at most {MAX_LABELS} labels.')
    names = [item['name'] for item in requested]
    if len(names) != len(set(names)):
        raise ReconfigureError('Label names must be unique.')
    for item in requested:
        if item['name'].startswith(RESERVED_LABEL_PREFIX):
            raise ReconfigureError(
                f'Label names beginning with {RESERVED_LABEL_PREFIX} are reserved for '
                "FreeCORE's own management labels."
            )
        if len(item['value'].encode()) > MAX_LABEL_VALUE_BYTES:
            raise ReconfigureError(
                f'A label value may be at most {MAX_LABEL_VALUE_BYTES} bytes.'
            )
    labels = [{'name': item['name'], 'value': item['value']} for item in requested]
    before = {item['name']: item['value'] for item in current}
    after = {item['name']: item['value'] for item in labels}
    changed = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))
    return labels, changed


def bind_reconfigure(record, data):
    """``(prepare, fields, changes)`` for an installed record and the new choices.

    ``prepare`` is what ``_prepare_volumes`` consumes (name, resolved environment,
    volumes with their requested dataset); ``fields`` are the record fields the
    replacement carries; ``changes`` says what differs from the record, per
    volume with the old and new mapping, so the job and the page can name what
    a storage change leaves behind.
    """
    if not isinstance(record, dict) or record.get('name') != data['name']:
        raise ReconfigureError('The installed application changed; review it again.')
    catalog = record.get('catalog')
    installed_hash = catalog.get('compose_sha256') if isinstance(catalog, dict) else None
    if (data.get('compose_sha256') or None) != installed_hash:
        raise ReconfigureError(
            'The installed application changed since this form was opened; review it again.'
        )
    if data['restart_policy'] not in RESTART_POLICIES:
        raise ReconfigureError('Restart policy is invalid.')

    current_ports = record.get('ports') or []
    if len(data['ports']) != len(current_ports):
        raise ReconfigureError('Port declarations do not match the installed application.')
    ports = []
    for current, requested in zip(current_ports, data['ports']):
        if any(requested[field] != current[field] for field in ('container_port', 'protocol')):
            raise ReconfigureError('Port identity does not match the installed application.')
        ports.append({
            'host_port': requested['host_port'],
            'container_port': current['container_port'],
            'protocol': current['protocol'],
        })

    current_environment = {item['name']: item['value'] for item in record.get('environment') or []}
    requested_environment = {item['name']: item.get('value') for item in data['environment']}
    if (
        len(requested_environment) != len(data['environment']) or
        set(requested_environment) != set(current_environment)
    ):
        raise ReconfigureError('Environment declarations do not match the installed application.')
    environment = [
        {
            'name': name,
            # None keeps the installed value: the page never sees values, so it
            # cannot echo them back.
            'value': current_environment[name] if requested_environment[name] is None
            else requested_environment[name],
        }
        for name in sorted(current_environment)
    ]

    current_volumes = {item['name']: item for item in record.get('volumes') or []}
    requested_volumes = {item['name']: item.get('dataset') or None for item in data['volumes']}
    if (
        len(requested_volumes) != len(data['volumes']) or
        set(requested_volumes) != set(current_volumes)
    ):
        raise ReconfigureError('Volume declarations do not match the installed application.')
    volumes = []
    volume_changes = []
    for name, current in current_volumes.items():
        requested = requested_volumes[name]
        volumes.append({
            'name': name,
            'target': current['target'],
            'read_only': bool(current.get('read_only')),
            'dataset': requested,
        })
        before = None if current.get('owned') else current.get('dataset')
        if before != requested:
            volume_changes.append({
                'name': name,
                'target': current['target'],
                'from': before,
                'to': requested,
                # The owned dataset an external mapping leaves behind.
                'kept_dataset': current.get('dataset') if current.get('owned') else None,
            })

    # the internal development record: None keeps the installed attachment; a request
    # binds to nothing pre-existing, it simply replaces the block.
    current_network = record.get('network') or {'mode': 'managed'}
    requested_network = data.get('network')
    if requested_network is None:
        network = copy.deepcopy(current_network)
    elif requested_network.get('mode') != 'lan':
        network = {'mode': 'managed'}
        # the internal development record: the pinned bridge address is preserved.
        if current_network.get('mode') == 'managed' and current_network.get('bridge_address'):
            network['bridge_address'] = current_network['bridge_address']
    else:
        network = {
            'mode': 'lan',
            'interface': requested_network.get('interface'),
            'address': requested_network.get('address'),
            'gateway': requested_network.get('gateway'),
        }
        # the internal development record: the assigned managed-leg address is preserved,
        # never re-requested; turning the leg on leaves assignment to the job.
        if requested_network.get('managed_access'):
            network['managed_access'] = True
            if current_network.get('managed_access') and current_network.get('managed_address'):
                network['managed_address'] = current_network['managed_address']

    portal = copy.deepcopy(record.get('portal'))
    if portal is not None:
        index = _port_index(current_ports, portal['port'])
        if index is None:
            raise ReconfigureError('The installed portal is not bound to a declared TCP port.')
        # the internal development record: the portal is a link on the host, so its port stays published.
        if ports[index]['host_port'] is None:
            raise ReconfigureError(
                f'Container port {ports[index]["container_port"]}/tcp opens the application\'s '
                'web page and must stay published on the host.'
            )
        portal['port'] = ports[index]['host_port']
    healthcheck = copy.deepcopy(record.get('healthcheck'))
    if healthcheck is not None:
        index = next((
            i for i, port in enumerate(current_ports)
            if (
                port['protocol'] == 'tcp' and
                port['container_port'] == healthcheck['container_port'] and
                port['host_port'] == healthcheck['host_port']
            )
        ), None)
        if index is None:
            raise ReconfigureError('The installed health check is not bound to a declared TCP port.')
        healthcheck['host_port'] = ports[index]['host_port']

    labels, label_changes = _bind_labels(record, data)
    certificates, certificate_changes = _bind_certificates(record, data)

    changes = {
        'ports': [
            {'container_port': c['container_port'], 'protocol': c['protocol'],
             'from': c['host_port'], 'to': n['host_port']}
            for c, n in zip(current_ports, ports) if c['host_port'] != n['host_port']
        ],
        'environment': sorted(
            name for name, value in requested_environment.items()
            if value is not None and value != current_environment[name]
        ),
        'volumes': volume_changes,
        # the internal development record: the names added, removed or given another value.
        'labels': label_changes,
        # the internal development record: the target directories added, removed or rebound.
        'certificates': certificate_changes,
        'restart_policy': data['restart_policy'] != record.get('restart_policy'),
        # An unpinned managed application (installed before #484) is pinned by
        # any edit, even one that changes nothing else.
        'network': network != current_network or (
            network['mode'] == 'managed' and not network.get('bridge_address')
        ),
    }
    prepare = {
        'name': record['name'],
        'environment': environment,
        'volumes': volumes,
    }
    fields = {
        'ports': ports,
        'environment': environment,
        'labels': labels,
        'certificates': certificates,
        'restart_policy': data['restart_policy'],
        'portal': portal,
        'healthcheck': healthcheck,
        'network': network,
    }
    return prepare, fields, changes


def anything_changed(changes):
    return bool(
        changes['ports'] or changes['environment'] or changes['volumes'] or
        changes.get('labels') or changes.get('certificates') or
        changes['restart_policy'] or changes['network']
    )
