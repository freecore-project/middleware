#!/usr/bin/env python3
"""Collect the api2 suite with NO target and NO network.

Eight modules call the REST API at import time, so plain `pytest --collect-only`
needs a live, reachable appliance -- which means the suite cannot be checked for
import/collection errors until you already have a canary burning. This stubs the
transport with canned responses so collection becomes a pure offline gate.

    python _collect_offline.py [extra pytest args]

Exit status is pytest's, so it works as an import/collection pre-flight. Because
the transport is stubbed, its result is never runtime or parity evidence.
"""
import json
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
sys.path.insert(0, HERE)

# --- auto_config, as runtest.py would have generated it ----------------------
ac = types.ModuleType('auto_config')
for k, v in dict(
    user="root", password="STUB", ip="127.0.0.1",
    hostname="freecore", domain="freecore.local",
    api_url="http://127.0.0.1/api/v2.0", interface="vtnet0",
    ntpServer="192.0.2.123", localHome="/root",
    keyPath="/root/.ssh/test_id_rsa", pool_name="tank",
    ha=False, dev_test=False, sshKey="ssh-rsa STUB",
).items():
    setattr(ac, k, v)
sys.modules['auto_config'] = ac
sys.modules.setdefault('config', types.ModuleType('config'))

# functions.py imports websocket-client even though collection never opens a
# socket. Keep that optional in the offline-only collector.
try:
    import websocket  # noqa: F401
except ImportError:
    websocket = types.ModuleType('websocket')
    websocket.create_connection = lambda *args, **kwargs: None
    sys.modules['websocket'] = websocket

# --- samba python bindings (protocols.py) ------------------------------------
# Present on the runner, absent on a dev box. Stub so collection is portable;
# the runner still exercises the real bindings at run time.
if 'samba' not in sys.modules:
    try:
        import samba  # noqa: F401
    except ImportError:
        samba = types.ModuleType('samba')
        for name, attrs in {
            'samba': ['credentials', 'NTSTATUSError', 'ntstatus'],
            'samba.samba3': ['libsmb_samba_internal', 'param'],
            'samba.dcerpc': ['security'],
        }.items():
            m = sys.modules.setdefault(name, types.ModuleType(name))
            for a in attrs:
                sub = types.ModuleType(f'{name}.{a}')
                setattr(m, a, sub)
                sys.modules[f'{name}.{a}'] = sub
        sys.modules['samba'].NTSTATUSError = type('NTSTATUSError', (Exception,), {})
        sys.modules['samba.samba3'].libsmb_samba_internal.Conn = object
        for f in ('FILE_ATTRIBUTE_HIDDEN', 'FILE_ATTRIBUTE_READONLY',
                  'FILE_ATTRIBUTE_SYSTEM', 'FILE_ATTRIBUTE_ARCHIVE'):
            setattr(sys.modules['samba.samba3'].libsmb_samba_internal, f, 0)

# --- canned transport --------------------------------------------------------
# Only import-time calls matter here; the shapes below are what module scope in
# test_008/test_011/test_160/test_170/test_400 actually indexes into.
_CANNED = {
    '/service/': [{'id': 1, 'service': 'ssh'}, {'id': 2, 'service': 'cifs'}],
    '/boot/get_disks/': ['vtbd0'],
    '/device/get_info/': {'vtbd0': {'name': 'vtbd0'}, 'vtbd1': {'name': 'vtbd1'}},
    '/group/?group=wheel': [{'id': 1, 'group': 'wheel', 'gid': 0}],
    '/stats/get_sources/': {'cpu-0': ['cpu-user'], 'load': ['load']},
}


class StubResponse:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


def _stub(testpath, payload=None, **kw):
    for key, val in _CANNED.items():
        if testpath.startswith(key) or key.startswith(testpath):
            return StubResponse(val)
    return StubResponse([])


# pysnmp is a declared test dep (requirements.txt: pysnmplib) and is present on
# the runner; stub it so this gate also runs on a machine without it.
try:
    import pysnmp  # noqa: F401
except ImportError:
    _p = types.ModuleType('pysnmp')
    _h = types.ModuleType('pysnmp.hlapi')
    for _n in ('CommunityData', 'ContextData', 'ObjectIdentity', 'ObjectType',
               'SnmpEngine', 'UdpTransportTarget', 'getCmd', 'nextCmd', 'bulkCmd'):
        setattr(_h, _n, type(_n, (), {}))
    _p.hlapi = _h
    sys.modules['pysnmp'], sys.modules['pysnmp.hlapi'] = _p, _h


import functions  # noqa: E402  (must follow the auto_config stub)
for _name in ('GET', 'POST', 'PUT', 'DELETE'):
    setattr(functions, _name, _stub)

import pytest  # noqa: E402

args = ['--collect-only', '-q', '-p', 'no:cacheprovider', 'api2'] + sys.argv[1:]
print(f'pytest {pytest.__version__} | python {sys.version.split()[0]} | '
      f'collect-only, stubbed transport, no target\n')
sys.exit(pytest.main(args))
