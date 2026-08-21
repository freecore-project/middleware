import copy
import ctypes
import ctypes.util
import glob
import json
import math
import os
import re
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

import psutil
try:
    import sysctl
except ImportError:
    sysctl = None

from middlewared.event import EventSource
from middlewared.plugins.reporting.guests import GUEST_IDENTITIES
from middlewared.service import CallError


DEFAULT_INTERVAL = 5
MINIMUM_INTERVAL = 2
INVENTORY_CACHE_SECONDS = 30
NVIDIA_SMI = '/usr/local/bin/nvidia-smi'
PCICONF_HEADER_RE = re.compile(
    r'^(?P<attachment>[^@\s]+)@pci\d+:(?P<bus>\d+):(?P<slot>\d+):(?P<function>\d+):'
    r'\s+class=0x(?P<class>[0-9a-f]+).*?vendor=0x(?P<vendor>[0-9a-f]+)',
    re.IGNORECASE,
)
PCICONF_DETAIL_RE = re.compile(r"^\s+(?P<key>vendor|device|class|subclass)\s+=\s+'(?P<value>.*)'$")
DRI_NODE_RE = re.compile(r'^(?:card(?P<card>\d+)|renderD(?P<render>\d+))$')
DRI_BUS_ID_RE = re.compile(r'^hw\.dri\.(?P<index>\d+)\.busid$')
AMDGPU_INFO_SENSOR_GPU_TEMP = 0x3
AMDGPU_INFO_SENSOR_GPU_LOAD = 0x4
AMDGPU_GEM_DOMAIN_VRAM = 0x4


class AmdgpuHeapInfo(ctypes.Structure):
    _fields_ = [
        ('heap_size', ctypes.c_uint64),
        ('heap_usage', ctypes.c_uint64),
        ('max_allocation', ctypes.c_uint64),
    ]


def parse_options(arg):
    try:
        options = json.loads(arg) if arg else {}
    except (TypeError, json.JSONDecodeError) as e:
        raise CallError(f'Invalid gpu.stats options: {e}')

    if not isinstance(options, dict):
        raise CallError('gpu.stats options must be a JSON object')

    interval = options.get('interval', DEFAULT_INTERVAL)
    if isinstance(interval, bool) or not isinstance(interval, (int, float)):
        raise CallError('gpu.stats interval must be a number')
    if not math.isfinite(interval) or interval < MINIMUM_INTERVAL:
        raise CallError(f'gpu.stats interval must be at least {MINIMUM_INTERVAL} seconds')
    return {'interval': interval}


def normalize_pci(value, base=10):
    if not isinstance(value, str):
        return None
    value = value.strip().lower().replace('/', ':').replace('.', ':')
    if value.startswith('pci'):
        value = value.split(':', 1)[-1]
    parts = value.split(':')
    if len(parts) == 4:
        parts = parts[-3:]
    if len(parts) != 3:
        return None
    try:
        return ':'.join(str(int(part, base)) for part in parts)
    except ValueError:
        return None


def _vendor(vendor_id, vendor_name):
    value = f'{vendor_id} {vendor_name}'.lower()
    if '10de' in value or 'nvidia' in value:
        return 'nvidia'
    if '1002' in value or 'amd' in value or 'advanced micro devices' in value or 'ati ' in value:
        return 'amd'
    if '8086' in value or 'intel' in value:
        return 'intel'
    return 'unknown'


def parse_pciconf(output):
    devices = []
    current = None

    def finish():
        if current is None or not current['class'].zfill(6).startswith('03'):
            return
        details = current['details']
        vendor_name = details.get('vendor', '')
        vendor = _vendor(current['vendor_id'], vendor_name)
        attachment = re.sub(r'\d+$', '', current['attachment'])
        devices.append({
            'id': current['id'],
            'name': details.get('device') or f'{vendor_name or vendor} display controller',
            'vendor': vendor,
            'driver': attachment,
        })

    for line in output.splitlines():
        header = PCICONF_HEADER_RE.match(line)
        if header:
            finish()
            current = {
                'attachment': header.group('attachment'),
                'id': normalize_pci(':'.join(header.group(key) for key in ('bus', 'slot', 'function'))),
                'class': header.group('class'),
                'vendor_id': header.group('vendor'),
                'details': {},
            }
            continue
        detail = PCICONF_DETAIL_RE.match(line)
        if detail and current is not None:
            current['details'][detail.group('key')] = detail.group('value')
    finish()
    return devices


def dri_bus_ids():
    if sysctl is None:
        return {}

    result = {}
    try:
        values = sysctl.filter('hw.dri')
    except (AttributeError, OSError):
        return result
    for value in values:
        match = DRI_BUS_ID_RE.match(str(getattr(value, 'name', '')))
        if match is None:
            continue
        selector = normalize_pci(str(value.value), 16)
        if selector is not None:
            result[int(match.group('index'))] = selector
    return result


def attach_dri_nodes(devices, paths, bus_ids=None):
    by_index = {}
    for path in sorted(paths):
        match = DRI_NODE_RE.match(os.path.basename(path))
        if match is None:
            continue
        index = int(match.group('card')) if match.group('card') is not None else int(match.group('render')) - 128
        if index >= 0:
            by_index.setdefault(index, []).append(path)

    for device in devices:
        device['_node_paths'] = []
        device['nodes'] = []

    # hw.dri.N.busid is the authoritative cardN -> PCI mapping on FreeBSD. The
    # ordinal fallback is retained for parser callers, but production passes an
    # explicit map so a driverless or passthrough GPU cannot shift every node.
    by_pci = {device['id']: device for device in devices}
    associations = (
        {index: by_pci.get(selector) for index, selector in bus_ids.items()}
        if bus_ids is not None else
        {index: device for index, device in enumerate(devices)}
    )
    for index, node_paths in by_index.items():
        device = associations.get(index)
        if device is None:
            continue
        device['_node_paths'].extend(node_paths)
        device['nodes'].extend(os.path.basename(path) for path in node_paths)
    return devices


def parse_fstat(output, node_to_gpu):
    consumers = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        try:
            pid = int(fields[2])
        except ValueError:
            continue
        path = fields[-1]
        gpu = node_to_gpu.get(path)
        if gpu is None:
            continue
        consumers.setdefault(gpu, {})[pid] = fields[1]
    return consumers


def _number(value, suffix):
    if not value or value.strip().upper() in {'N/A', '[N/A]'}:
        return None
    match = re.search(r'-?\d+(?:\.\d+)?', value)
    if match is None:
        return None
    number = float(match.group())
    if suffix == 'percent':
        return max(0.0, min(100.0, number))
    if suffix == 'temperature':
        return number
    return number


def _bytes(value):
    number = _number(value, None)
    if number is None:
        return None
    units = value.upper()
    if 'GIB' in units:
        factor = 1024 ** 3
    elif 'MIB' in units:
        factor = 1024 ** 2
    elif 'KIB' in units:
        factor = 1024
    else:
        factor = 1
    return int(number * factor)


def parse_nvidia_smi_xml(output):
    root = ET.fromstring(output)
    driver_version = root.findtext('driver_version')
    result = {}
    for gpu in root.findall('gpu'):
        pci = normalize_pci(gpu.findtext('pci/pci_bus_id'), 16)
        if pci is None:
            continue
        processes = {}
        for process in gpu.findall('processes/process_info'):
            try:
                pid = int(process.findtext('pid'))
            except (TypeError, ValueError):
                continue
            processes[pid] = {
                'name': os.path.basename(process.findtext('process_name') or str(pid)),
                'gpu_mem': _bytes(process.findtext('used_memory')),
            }
        result[pci] = {
            'name': gpu.findtext('product_name'),
            'driver_version': driver_version,
            'util_pct': _number(gpu.findtext('utilization/gpu_util'), 'percent'),
            'enc_pct': _number(gpu.findtext('utilization/encoder_util'), 'percent'),
            'dec_pct': _number(gpu.findtext('utilization/decoder_util'), 'percent'),
            'vram_used': _bytes(gpu.findtext('fb_memory_usage/used')),
            'vram_total': _bytes(gpu.findtext('fb_memory_usage/total')),
            'temp_c': _number(gpu.findtext('temperature/gpu_temp'), 'temperature'),
            'processes': processes,
        }
    return result


def collect_amdgpu(node_path, library=None):
    if library is None:
        library_name = ctypes.util.find_library('drm_amdgpu') or '/usr/local/lib/libdrm_amdgpu.so.1'
        library = ctypes.CDLL(library_name)
        library.amdgpu_device_initialize.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        library.amdgpu_device_initialize.restype = ctypes.c_int
        library.amdgpu_device_deinitialize.argtypes = [ctypes.c_void_p]
        library.amdgpu_device_deinitialize.restype = ctypes.c_int
        library.amdgpu_query_sensor_info.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ]
        library.amdgpu_query_sensor_info.restype = ctypes.c_int
        library.amdgpu_query_heap_info.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(AmdgpuHeapInfo),
        ]
        library.amdgpu_query_heap_info.restype = ctypes.c_int

    descriptor = os.open(node_path, os.O_RDWR | getattr(os, 'O_CLOEXEC', 0))
    device = ctypes.c_void_p()
    major = ctypes.c_uint32()
    minor = ctypes.c_uint32()
    initialized = False
    try:
        if library.amdgpu_device_initialize(
            descriptor, ctypes.byref(major), ctypes.byref(minor), ctypes.byref(device),
        ):
            raise OSError('amdgpu_device_initialize failed')
        initialized = True

        def sensor(sensor_type):
            value = ctypes.c_uint32()
            if library.amdgpu_query_sensor_info(
                device, sensor_type, ctypes.sizeof(value), ctypes.byref(value),
            ):
                return None
            return value.value

        heap = AmdgpuHeapInfo()
        heap_result = library.amdgpu_query_heap_info(
            device, AMDGPU_GEM_DOMAIN_VRAM, 0, ctypes.byref(heap),
        )
        temperature = sensor(AMDGPU_INFO_SENSOR_GPU_TEMP)
        return {
            'util_pct': sensor(AMDGPU_INFO_SENSOR_GPU_LOAD),
            'enc_pct': None,
            'dec_pct': None,
            'vram_used': None if heap_result else heap.heap_usage,
            'vram_total': None if heap_result else heap.heap_size,
            'temp_c': None if temperature is None else round(temperature / 1000, 1),
            'processes': {},
        }
    finally:
        try:
            if initialized:
                library.amdgpu_device_deinitialize(device)
        finally:
            os.close(descriptor)


def process_jid(pid):
    try:
        jid = getattr(psutil.Process(pid), 'jid', None)
        return int(jid()) if callable(jid) else 0
    except (psutil.Error, TypeError, ValueError):
        return 0


class GpuStatsSampler:

    def __init__(self, identity_cache=None):
        self.lock = threading.Lock()
        self.payload = None
        self.payload_at = None
        self.inventory = None
        self.inventory_at = None
        self.identity_cache = identity_cache or GUEST_IDENTITIES

    @staticmethod
    def _run(command):
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode:
            detail = result.stderr.strip().splitlines()[0] if result.stderr.strip() else 'no error text'
            raise CallError(f'{command[0]} failed while sampling GPU statistics: {detail[:200]}')
        return result.stdout

    def _inventory(self, now):
        if self.inventory is None or self.inventory_at is None or now - self.inventory_at >= INVENTORY_CACHE_SECONDS:
            devices = parse_pciconf(self._run(['/usr/sbin/pciconf', '-lv']))
            paths = glob.glob('/dev/dri/card*') + glob.glob('/dev/dri/renderD*')
            self.inventory = attach_dri_nodes(devices, paths, dri_bus_ids())
            self.inventory_at = now
        return copy.deepcopy(self.inventory)

    def _nvidia(self):
        try:
            return parse_nvidia_smi_xml(self._run([NVIDIA_SMI, '-q', '-x']))
        except (CallError, FileNotFoundError, OSError, ET.ParseError, ValueError):
            return {}

    def _amd(self, device):
        nodes = sorted(device['_node_paths'], key=lambda path: not os.path.basename(path).startswith('renderD'))
        if not nodes:
            return None
        try:
            return collect_amdgpu(nodes[0])
        except (AttributeError, OSError, TypeError, ValueError):
            return None

    def _fstat(self, devices):
        node_to_gpu = {
            path: device['id']
            for device in devices if device.get('state') != 'passthrough'
            for path in device['_node_paths']
        }
        if not node_to_gpu:
            return {}
        try:
            return parse_fstat(self._run(['/usr/bin/fstat', *sorted(node_to_gpu)]), node_to_gpu)
        except (CallError, FileNotFoundError):
            return {}

    @staticmethod
    def _rollup_users(pids, process_telemetry, identities, jid_by_pid):
        groups = {}
        for pid in set(pids) | set(process_telemetry):
            if pid in identities['vm_by_pid']:
                vm = identities['vm_by_pid'][pid]
                key = ('vm', vm['name'])
            else:
                jid = jid_by_pid.get(pid, 0)
                if jid > 0 and jid in identities['jails']:
                    key = ('jail', identities['jails'][jid])
                else:
                    process = process_telemetry.get(pid) or {}
                    key = ('host', pids.get(pid) or process.get('name') or str(pid))
            group = groups.setdefault(key, {'kind': key[0], 'name': key[1], 'pids': set(), 'gpu_mem': 0})
            group['pids'].add(pid)
            memory = (process_telemetry.get(pid) or {}).get('gpu_mem')
            if memory is not None:
                group['gpu_mem'] += memory

        users = []
        for group in groups.values():
            user = {
                'kind': group['kind'],
                'name': group['name'],
                'procs': len(group['pids']),
            }
            if group['gpu_mem']:
                user['gpu_mem'] = group['gpu_mem']
            users.append(user)
        return sorted(users, key=lambda user: (-user.get('gpu_mem', 0), -user['procs'], user['name']))

    def _collect(self, middleware, now):
        devices = self._inventory(now)
        identities = self.identity_cache.snapshot(middleware, now)
        for device in devices:
            owner = identities['passthrough'].get(device['id'])
            device['passthrough_vm'] = owner
            device['state'] = 'passthrough' if owner or device['driver'] == 'ppt' else None

        fstat = self._fstat(devices)
        nvidia = self._nvidia() if any(
            device['vendor'] == 'nvidia' and device['state'] != 'passthrough' for device in devices
        ) else {}

        observed_pids = {
            pid
            for processes in fstat.values()
            for pid in processes
        } | {
            pid
            for telemetry in nvidia.values()
            for pid in (telemetry.get('processes') or {})
        }
        jid_by_pid = {pid: process_jid(pid) for pid in observed_pids}
        if any(jid > 0 and jid not in identities['jails'] for jid in jid_by_pid.values()):
            identities = self.identity_cache.snapshot(middleware, now, force=True)

        rows = []
        for device in devices:
            telemetry = None
            if device['state'] != 'passthrough':
                if device['vendor'] == 'nvidia':
                    telemetry = nvidia.get(device['id'])
                elif device['vendor'] == 'amd':
                    telemetry = self._amd(device)

            if telemetry:
                if telemetry.get('name'):
                    device['name'] = telemetry['name']
                if telemetry.get('driver_version'):
                    device['driver'] = f'nvidia-drm {telemetry["driver_version"]}'
            else:
                telemetry = {}

            process_telemetry = telemetry.get('processes') or {}
            users = self._rollup_users(
                fstat.get(device['id'], {}), process_telemetry, identities, jid_by_pid,
            )
            if device['state'] != 'passthrough':
                has_driver = bool(device['_node_paths'] or telemetry) and device['driver'] not in {'none'}
                device['state'] = 'active' if users or (telemetry.get('util_pct') or 0) > 0 else (
                    'idle' if has_driver else 'no-driver'
                )

            rows.append({
                'id': device['id'],
                'name': device['name'],
                'vendor': device['vendor'],
                'driver': device['driver'],
                'nodes': device['nodes'],
                'state': device['state'],
                'passthrough_vm': device['passthrough_vm'],
                'util_pct': telemetry.get('util_pct'),
                'enc_pct': telemetry.get('enc_pct'),
                'dec_pct': telemetry.get('dec_pct'),
                'vram_used': telemetry.get('vram_used'),
                'vram_total': telemetry.get('vram_total'),
                'temp_c': telemetry.get('temp_c'),
                'users': users,
            })
        return {'gpus': rows}

    def sample(self, middleware, max_age):
        now = time.monotonic()
        with self.lock:
            if self.payload is None or self.payload_at is None or now - self.payload_at >= max_age:
                self.payload = self._collect(middleware, now)
                self.payload_at = now
            return copy.deepcopy(self.payload)


SAMPLER = GpuStatsSampler()


class GpuStatsEventSource(EventSource):
    """
    Retrieve per-GPU telemetry and consumer attribution.

    Usage: gpu.stats:{"interval": 5}
    """

    def run(self):
        interval = parse_options(self.arg)['interval']
        while not self._cancel.is_set():
            self.send_event('ADDED', fields=SAMPLER.sample(self.middleware, interval))
            if self._cancel.wait(interval):
                break


def setup(middleware):
    middleware.register_event_source('gpu.stats', GpuStatsEventSource)
