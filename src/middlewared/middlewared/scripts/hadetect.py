#!/usr/bin/env python3

import subprocess
import re
import json
import glob

from licenselib.license import License

SESUTIL = '/usr/sbin/sesutil'
GETENCSTAT = '/usr/sbin/getencstat'
ZSERIES = 'SD_9GV12P1J_12R6K4'
XSERIES = 'Enclosure Name: CELESTIC (P3215-O|P3217-B)'
MSERIES = 'Enclosure Name: (ECStream|iX) 4024S([ps])'
LICENSE = '/data/license'


def main():
    result = {'hardware': 'MANUAL', 'node': '', 'licensed': False}
    try:
        for enclosure in glob.iglob('/dev/ses*'):
            # grab enclosure status (sesutil on FB14+, getencstat on older)
            encstat = None
            for cmd in ([SESUTIL, '-u', enclosure, 'map'], [GETENCSTAT, '-V', enclosure]):
                try:
                    cp = subprocess.run(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10,
                    )
                    if cp.returncode == 0 and cp.stdout:
                        encstat = cp.stdout.decode('utf8', 'ignore').strip()
                        break
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue
            if encstat:
                if re.search(ZSERIES, encstat, re.M):
                    # echostream (Z-series)
                    result['hardware'] = 'ECHOSTREAM'

                    # now get node position
                    node = re.search(r"3U20D-Encl-([AB])", encstat, re.M)
                    if node:
                        result['node'] = node.group(1)
                        break

                elif re.search(XSERIES, encstat, re.M):
                    # puma (X-series)
                    result['hardware'] = 'PUMA'

                    # now get node position
                    try:
                        smp = subprocess.run(
                            ['/sbin/camcontrol', 'smpphylist', enclosure, '-q'],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=10,
                        )
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        continue
                    if smp.stdout:
                        smp = smp.stdout.decode('utf8', 'ignore').strip()

                        regA = re.search(
                            'ESCE A_(5[0-9A-F]{15})', encstat, re.M
                        )
                        if regA:
                            addr = hex(int(regA.group(1), 16) - 1)
                            if addr in smp:
                                result['node'] = 'A'
                                break
                        regB = re.search(
                            'ESCE B_(5[0-9A-F]{15})', encstat, re.M
                        )
                        if regB:
                            addr = hex(int(regB.group(1), 16) - 1)
                            if addr in smp:
                                result['node'] = 'B'
                                break
                else:
                    reg = re.search(MSERIES, encstat, re.M)
                    if reg:
                        # echowarp (M-series)
                        result['hardware'] = 'ECHOWARP'

                        # now get node position
                        if reg.group(2) == 'p':
                            result['node'] = 'A'
                            break
                        elif reg.group(2) == 's':
                            result['node'] = 'B'
                            break

        # check if this system is licensed for HA
        with open(LICENSE, 'r') as f:
            if License.load(f.read().strip('\n')).system_serial_ha:
                result['licensed'] = True

    except Exception:
        # this script is called as a fallback mechanism in
        # ix-netif rc script so if any type of error occurs
        # then things are really broken
        pass

    print(json.dumps(result))


if __name__ == '__main__':
    main()
