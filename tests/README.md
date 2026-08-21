# FreeNAS REST API test
This is the folder of all tests for FreeNAS REST API testing.

## Dependency REST API tests

### Require dependency run

```
Python 3 pip
samba
sshpass
smbclient
snmpwalk
```

### Installing of dependency on FreeBSD base OS

#### Require packages
`pkg install py39-pip samba* sshpass net-snmp`

In middleware/tests run the command bellow

`pip install -r requirements.txt`

### Installing of dependency on Debian base OS

#### Require packages

`apt install python3-pip samba smbclient sshpass snmp`

In middleware/tests run the command bellow

`pip3 install -r requirements.txt`

### Runner-side samba config — required, and easy to miss

The SMB tests are driven **from the runner**: `protocols.py` uses the `libsmb`
python bindings plus the `smbclient`, `smbcacls` and `smbcquotas` binaries. All
of those need a client-side `smb4.conf` on the runner itself. Without one they
fail with *"Can't load /usr/local/etc/smb4.conf"* and the whole SMB block of
the suite goes red for a reason that has nothing to do with the appliance under
test — which is exactly what a freshly built runner does.

`smb4.conf` in this directory is the working one. Install it and check it:

```
cp smb4.conf /usr/local/etc/smb4.conf     # FreeBSD; /etc/samba/ on Debian
testparm -s                               # must be clean
```

It is runner-side only — nothing in the suite reads it from this directory, and
it is never installed on an appliance. Read the comments in it before editing:
`client min protocol = NT1` is load-bearing for the SMB1-parametrised cases, and
`client use spnego` must stay out (samba 4.16 raises on it, which silently fails
`test_437_smb_vss`).

## Running REST API test
`runtest.py` runs the API2 parity suite against one already-running appliance.
It never installs or updates an OS, controls an outer hypervisor, rolls back a
zvol, or returns an appliance between releases. Perform those transitions
manually, outside pytest, and run the same frozen test revision independently on
the 13.3 reference and FreeCORE target.

The API2 directory deliberately excludes:

- removed Enterprise/HA-only tests and the removed AFP test;
- the inherited update driver, which fetched iX lab state and controlled an
  outer bhyve VM (OS upgrades are manual acceptance work);
- FreeCORE plugin-origin acceptance, kept separately in
  `freecore/test_plugin.py` because it is an intentional product divergence;
- `test_540_vm.py` by default, because it probes nested bhyve at import time.
  It is reported as excluded and requires the explicit `--run-nested-vm` pytest
  option on suitable hardware.

All other shipped-service modules run by default. Tests needing AD, LDAP, NIS,
cloud, iSCSI, or VMware fixtures retain their upstream self-skip behavior when
the corresponding `config.py` values are absent.

```
freenas/tests/api% ./runtest.py
Usage for ./runtest.py:
Mandatory option
    --ip <###.###.###.###>     - IP of the FreeNAS
    --password <root password> - Password of the FreeNAS root user
    --interface <interface>    - The interface that FreeNAS is run one
    --ntp-server <ip>           - Explicit non-production NTP test fixture

Optional option
    --test <test name>         - Test name (Network, ALL)

```

### Example command

`./runtest.py --ip 192.168.2.45 --interface vtnet0 --password testing --ntp-server 192.168.2.1`


## How REST API tests should be written?

REST API test code should be written with flake8 standard. All code lines should be under 80 character per line.

### Code example
```
#!/usr/bin/env python3.6

import sys
import os
from time import sleep

apifolder = os.getcwd()
sys.path.append(apifolder)
from functions import POST, DELETE, GET, PUT


def test_01_creating_a_new_boot_environment():
    payload = {"name": "bootenv01", "source": "default"}
    results = POST("/bootenv/", payload)
    assert results.status_code == 200, results.text
    sleep(1)


def test_02_look_new_bootenv_is_created():
    assert len(GET('/bootenv?name=bootenv01').json()) == 1


def test_03_activate_bootenv01():
    payload = None
    results = POST("/bootenv/id/bootenv01/activate/", payload)
    assert results.status_code == 200, results.text


# Update tests
def test_04_cloning_a_new_boot_environment():
    payload = {"name": "bootenv02", "source": "bootenv01"}
    results = POST("/bootenv/", payload)
    assert results.status_code == 200, results.text
```
