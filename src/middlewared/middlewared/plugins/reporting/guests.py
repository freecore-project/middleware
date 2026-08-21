import copy
import json
import math
import re
import subprocess
import threading
import time

import psutil
try:
    import sysctl
except ImportError:
    sysctl = None

from middlewared.event import EventSource
from middlewared.service import CallError


DEFAULT_INTERVAL = 5
MINIMUM_INTERVAL = 2
IDENTITY_CACHE_SECONDS = 30
CPU_TIME_RE = re.compile(
    r'^(?:(?P<days>\d+)-)?(?:(?P<hours>\d+):)?(?P<minutes>\d+):(?P<seconds>\d+(?:\.\d+)?)$'
)


def parse_options(arg):
    try:
        options = json.loads(arg) if arg else {}
    except (TypeError, json.JSONDecodeError) as e:
        raise CallError(f'Invalid guest.stats options: {e}')

    if not isinstance(options, dict):
        raise CallError('guest.stats options must be a JSON object')

    interval = options.get('interval', DEFAULT_INTERVAL)
    if isinstance(interval, bool) or not isinstance(interval, (int, float)):
        raise CallError('guest.stats interval must be a number')
    if not math.isfinite(interval) or interval < MINIMUM_INTERVAL:
        raise CallError(f'guest.stats interval must be at least {MINIMUM_INTERVAL} seconds')

    return {'interval': interval}


def parse_cpu_time(value):
    match = CPU_TIME_RE.match(value.strip())
    if match is None:
        raise ValueError(f'Invalid process CPU time: {value!r}')

    parts = match.groupdict(default='0')
    return (
        int(parts['days']) * 86400 +
        int(parts['hours']) * 3600 +
        int(parts['minutes']) * 60 +
        float(parts['seconds'])
    )


def parse_process_rows(output):
    rows = []
    for line_number, line in enumerate(output.splitlines(), 1):
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 4:
            raise CallError(f'Unable to parse guest process sample at line {line_number}')
        try:
            jid, pid, rss = map(int, fields[:3])
            cpu_time = parse_cpu_time(fields[3])
        except ValueError as e:
            raise CallError(f'Unable to parse guest process sample at line {line_number}: {e}')
        # FreeBSD includes the host kernel as PID 0; it is not a jail process.
        if jid < 0 or pid < 0 or rss < 0 or (pid == 0 and jid > 0):
            raise CallError(f'Unable to parse guest process sample at line {line_number}: invalid identifiers')
        rows.append({
            'jid': jid,
            'pid': pid,
            'rss': rss * 1024,
            'cpu_time': cpu_time,
        })
    return rows


def app_container_names(middleware):
    """Map an application's OCI container id to the name a user gave it.

    the internal development record: an Applications container runs in a jail whose
    name *is* its 64-hex container id, so it reached the dashboard as a jail
    called `662c2016f524...`. applications.query knows it as `openspeedtest`.
    Applications are optional, so a host without them -- or one whose app
    runtime is down -- must still report its VMs and jails rather than fail
    the whole sample.
    """
    try:
        apps = middleware.call_sync('applications.query')
    except Exception:
        return {}

    result = {}
    for app in apps if isinstance(apps, list) else []:
        try:
            container_id = str(app['container_id'])
            name = str(app['name'])
        except (KeyError, TypeError, ValueError):
            continue
        if container_id and name:
            result[container_id] = name
    return result


# the internal development record: a Bastille jail lives at <prefix>/bastille/jails/<name>/root,
# on a FreeCORE pool or under Bastille's stock prefix. The path is already in the jls
# inventory, so the family is decided without another middleware call on the dashboard
# load path (the the internal development record law).
BASTILLE_JAIL_PATH_RE = re.compile(
    r'^(?:/mnt/[^/]+|/usr/local)/bastille/jails/[^/]+/root/?$'
)


def is_bastille_jail_path(path):
    return bool(path) and BASTILLE_JAIL_PATH_RE.match(str(path)) is not None


def parse_jail_inventory(output):
    """Return {jid: {'name': ..., 'path': ...}} from `jls --libxo json -v`."""
    try:
        document = json.loads(output or '{}')
        rows = document.get('jail-information', {}).get('jail', [])
    except (AttributeError, TypeError, json.JSONDecodeError) as e:
        raise CallError(f'Unable to parse jail identity inventory: {e}')

    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        raise CallError('Unable to parse jail identity inventory: jail list is malformed')

    result = {}
    for row in rows:
        try:
            jid = int(row['jid'])
            name = str(row['name'])
        except (KeyError, TypeError, ValueError) as e:
            raise CallError(f'Unable to parse jail identity inventory row: {e}')
        if jid < 1 or not name:
            raise CallError('Unable to parse jail identity inventory row: invalid jid or name')
        if name.startswith('ioc-'):
            name = name[4:]
        path = row.get('path') if isinstance(row, dict) else None
        result[jid] = {'name': name, 'path': str(path) if isinstance(path, str) else ''}
    return result


def parse_jail_rows(output):
    return {jid: row['name'] for jid, row in parse_jail_inventory(output).items()}


def arc_size():
    try:
        if sysctl is not None:
            values = sysctl.filter('kstat.zfs.misc.arcstats.size')
            return int(values[0].value) if values else 0
        result = subprocess.run(
            ['/sbin/sysctl', '-n', 'kstat.zfs.misc.arcstats.size'],
            capture_output=True, text=True, check=False,
        )
        return int(result.stdout.strip()) if result.returncode == 0 and result.stdout.strip() else 0
    except FileNotFoundError:
        return 0
    except (AttributeError, IndexError, TypeError, ValueError):
        return 0


class GuestIdentityCache:

    def __init__(self):
        self.lock = threading.Lock()
        self.identities_at = None
        self.identities = None

    @staticmethod
    def _run(command):
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode:
            detail = result.stderr.strip().splitlines()[0] if result.stderr.strip() else 'no error text'
            raise CallError(f'{command[0]} failed while refreshing guest identities: {detail[:200]}')
        return result.stdout

    def _refresh(self, middleware, now):
        vms = []
        vm_by_pid = {}
        passthrough = {}
        for vm in middleware.call_sync('vm.query'):
            status = vm.get('status') or {}
            pid = status.get('pid')
            try:
                pid = int(pid)
            except (TypeError, ValueError):
                pid = None
            vcpus = (
                max(0, int(vm.get('vcpus') or 0)) *
                max(1, int(vm.get('cores') or 1)) *
                max(1, int(vm.get('threads') or 1))
            )
            row = {
                'id': vm.get('id'),
                'name': vm.get('name'),
                'state': status.get('state', 'UNKNOWN'),
                'provisioned': max(0, int(vm.get('memory') or 0)) * 1024 * 1024,
                'vcpus': vcpus,
                'pid': pid if pid is not None and pid > 0 else None,
            }
            vms.append(row)
            if row['pid'] is not None:
                vm_by_pid[row['pid']] = row

            for device in vm.get('devices') or []:
                if device.get('dtype') != 'PCI':
                    continue
                pptdev = (device.get('attributes') or {}).get('pptdev')
                try:
                    selector = ':'.join(str(int(part)) for part in pptdev.split('/'))
                except (AttributeError, TypeError, ValueError):
                    continue
                if selector.count(':') == 2:
                    passthrough[selector] = {'id': vm.get('id'), 'name': vm.get('name')}

        inventory = parse_jail_inventory(self._run(['/usr/sbin/jls', '--libxo', 'json', '-v']))
        self.identities = {
            'vms': vms,
            'vm_by_pid': vm_by_pid,
            'jails': {jid: row['name'] for jid, row in inventory.items()},
            'jail_paths': {jid: row['path'] for jid, row in inventory.items()},
            'apps': app_container_names(middleware),
            'passthrough': passthrough,
        }
        self.identities_at = now

    def snapshot(self, middleware, now, force=False):
        with self.lock:
            if (
                force or self.identities is None or self.identities_at is None or
                now - self.identities_at >= IDENTITY_CACHE_SECONDS
            ):
                self._refresh(middleware, now)
            return copy.deepcopy(self.identities)


class GuestStatsSampler:

    def __init__(self, identity_cache=None):
        self.lock = threading.Lock()
        self.payload = None
        self.payload_at = None
        self.vms = []
        self.vm_by_pid = {}
        self.jails = {}
        self.jail_paths = {}
        self.apps = {}
        self.identity_cache = identity_cache or GuestIdentityCache()
        self.previous_cpu = {}
        self.previous_cpu_at = None

    @staticmethod
    def _run(command):
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode:
            detail = result.stderr.strip().splitlines()[0] if result.stderr.strip() else 'no error text'
            raise CallError(f'{command[0]} failed while sampling guest statistics: {detail[:200]}')
        return result.stdout

    def _identities(self, middleware, now, force=False):
        identities = self.identity_cache.snapshot(middleware, now, force)
        self.vms = identities['vms']
        self.vm_by_pid = identities['vm_by_pid']
        self.jails = identities['jails']
        self.jail_paths = identities.get('jail_paths') or {}
        self.apps = identities.get('apps') or {}

    def _cpu_pct(self, keys, current_cpu, elapsed, cpu_count):
        if elapsed is None or elapsed <= 0:
            return None
        delta = sum(
            max(0, current_cpu[key] - self.previous_cpu[key])
            for key in keys if key in self.previous_cpu
        )
        return round(min(100.0, delta / elapsed / cpu_count * 100), 2)

    def _collect(self, middleware, now):
        self._identities(middleware, now)
        # On FreeBSD, everything after '=' in one -o argument is the header.
        processes = parse_process_rows(self._run([
            '/bin/ps', '-axo', 'jid=', '-o', 'pid=', '-o', 'rss=', '-o', 'time=',
        ]))

        process_pids = {row['pid'] for row in processes}
        unknown_jids = {row['jid'] for row in processes if row['jid'] > 0 and row['jid'] not in self.jails}
        if unknown_jids or set(self.vm_by_pid) - process_pids:
            self._identities(middleware, now, force=True)

        current_cpu = {(row['jid'], row['pid']): row['cpu_time'] for row in processes}
        elapsed = None if self.previous_cpu_at is None else now - self.previous_cpu_at
        cpu_count = psutil.cpu_count(logical=True) or 1

        host_processes = {row['pid']: row for row in processes if row['jid'] == 0}
        vm_rows = []
        for vm in sorted(self.vms, key=lambda row: (row['id'] is None, row['id'], row['name'] or '')):
            result = {key: vm[key] for key in ('id', 'name', 'state', 'provisioned', 'vcpus')}
            process = host_processes.get(vm['pid'])
            if process is not None:
                key = (0, process['pid'])
                result.update({
                    'cpu_pct': self._cpu_pct([key], current_cpu, elapsed, cpu_count),
                    'rss': process['rss'],
                })
            vm_rows.append(result)

        jail_processes = {}
        for process in processes:
            if process['jid'] > 0 and process['jid'] in self.jails:
                jail_processes.setdefault(process['jid'], []).append(process)

        jail_rows = []
        app_rows = []
        bastille_rows = []
        for jid, members in sorted(jail_processes.items()):
            keys = [(member['jid'], member['pid']) for member in members]
            jail_name = self.jails[jid]
            row = {
                'jid': jid,
                'name': jail_name,
                'cpu_pct': self._cpu_pct(keys, current_cpu, elapsed, cpu_count),
                'rss': sum(member['rss'] for member in members),
                'nproc': len(members),
            }
            # An Applications container is a jail by implementation only. Report
            # it under the name the user knows, in its own family.
            app_name = self.apps.get(jail_name)
            if app_name is not None:
                app_rows.append({**row, 'name': app_name})
            elif is_bastille_jail_path(self.jail_paths.get(jid)):
                # the internal development record: a Bastille jail is its own family too, so
                # the card can route it to Bastille Jails instead of the iocage list.
                bastille_rows.append(row)
            else:
                jail_rows.append(row)

        memory = psutil.virtual_memory()
        services_bytes = max(0, int(memory.total) - int(memory.free) - arc_size())
        attributed_bytes = (
            sum(row.get('rss', 0) for row in vm_rows) +
            sum(row['rss'] for row in jail_rows) +
            sum(row['rss'] for row in app_rows) +
            sum(row['rss'] for row in bastille_rows)
        )

        self.previous_cpu = current_cpu
        self.previous_cpu_at = now
        return {
            'cpu_count': cpu_count,
            'vms': vm_rows,
            'jails': jail_rows,
            'apps': app_rows,
            'bastille': bastille_rows,
            'services_bytes': services_bytes,
            'attributed_bytes': attributed_bytes,
        }

    def sample(self, middleware, max_age):
        now = time.monotonic()
        with self.lock:
            if self.payload is None or self.payload_at is None or now - self.payload_at >= max_age:
                self.payload = self._collect(middleware, now)
                self.payload_at = now
            return copy.deepcopy(self.payload)


GUEST_IDENTITIES = GuestIdentityCache()
SAMPLER = GuestStatsSampler(GUEST_IDENTITIES)


class GuestStatsEventSource(EventSource):
    """
    Retrieve per-VM and per-jail CPU and memory attribution.

    Jails arrive in three families: `jails` (iocage and anything unclassified), `apps`
    (Applications containers, the internal development record) and `bastille` (Bastille jails,
    the internal development record), each row {jid, name, cpu_pct, rss, nproc}.

    Usage: guest.stats:{"interval": 5}
    """

    def run(self):
        interval = parse_options(self.arg)['interval']
        while not self._cancel.is_set():
            self.send_event('ADDED', fields=SAMPLER.sample(self.middleware, interval))
            if self._cancel.wait(interval):
                break


def setup(middleware):
    middleware.register_event_source('guest.stats', GuestStatsEventSource)
