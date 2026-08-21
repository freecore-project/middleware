#!/usr/bin/env python3

# Author: Eric Turgeon
# License: BSD

from subprocess import call
from sys import argv
import atexit
import glob
import os
import getopt
import sys
import random
import string

workdir = os.getcwd()
sys.path.append(workdir)
workdir = os.getcwd()
results_xml = f'{workdir}/results/'
localHome = os.path.expanduser('~')
dotsshPath = localHome + '/.ssh'
keyPath = localHome + '/.ssh/test_id_rsa'

ixautomation_dot_conf_url = "https://raw.githubusercontent.com/iXsystems/" \
    "ixautomation/master/src/etc/ixautomation.conf.dist"
config_file_msg = "Please add config.py to freenas/tests which can be empty " \
    f"or contain settings from {ixautomation_dot_conf_url}"

if not os.path.exists('config.py'):
    print(config_file_msg)
    exit(1)

error_msg = """Usage for %s:
Mandatory option
    --ip <###.###.###.###>     - IP of the FreeNAS
    --password <root password> - Password of the FreeNAS root user
    --interface <interface>    - The interface that FreeNAS is run one
    --ntp-server <ip>           - Explicit non-production NTP test fixture

Optional option
    --test <test name>         - Test name (Network, ALL)
    --ha                       - Run test for HA
    --dev-test                 - Run only the test that are not mark with
                                 pytestmark skipif dev_test is true.
    """ % argv[0]

# if have no argument stop
if len(argv) == 1:
    print(error_msg)
    exit()

option_list = [
    "ip=",
    "password=",
    "interface=",
    "ntp-server=",
    'test=',
    "ha",
    "dev-test"
]

# look if all the argument are there.
try:
    myopts, args = getopt.getopt(argv[1:], 'aipItk:', option_list)
except getopt.GetoptError as e:
    print(str(e))
    print(error_msg)
    exit()

ip = None
passwd = None
interface = None
ntp_server = None
testName = ''
testexpr = None
ha = False
dev_test = False
for output, arg in myopts:
    if output in ('-i', '--ip'):
        ip = arg
    elif output in ('-p', '--password'):
        passwd = arg
    elif output in ('-I', '--interface'):
        interface = arg
    elif output in ('-t', '--test'):
        testName = arg
    elif output == '-k':
        testexpr = arg
    elif output == '--ntp-server':
        ntp_server = arg
    elif output == '--ha':
        ha = True
    elif output == '--dev-test':
        dev_test = True

if None in (ip, passwd, interface, ntp_server):
    print("Mandatory option missing!\n")
    print(error_msg)
    exit()

# create random hostname and random fake domain
digit = ''.join(random.choices(string.digits, k=2))
hostname = f'test{digit}'
domain = f'test{digit}.freecore.local'

cfg_content = f"""#!{sys.executable}

user = "root"
password = "{passwd}"
ip = "{ip}"
hostname = "{hostname}"
domain = "{domain}"
api_url = 'http://{ip}/api/v2.0'
interface = "{interface}"
ntpServer = "{ntp_server}"
localHome = "{localHome}"
keyPath = "{keyPath}"
pool_name = "tank"
ha = {ha}
dev_test = {dev_test}
"""

cfg_file = open("auto_config.py", 'w')
cfg_file.writelines(cfg_content)
cfg_file.close()


def remove_generated_config():
    for path in ['auto_config.py', *glob.glob('__pycache__/auto_config.*.pyc')]:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


atexit.register(remove_generated_config)

from functions import setup_ssh_agent, create_key, add_ssh_key, get_folder
from functions import SSH_TEST
# Setup ssh agent before starting test.
setup_ssh_agent()
if os.path.isdir(dotsshPath) is False:
    os.makedirs(dotsshPath)
if os.path.exists(keyPath) is False:
    create_key(keyPath)
add_ssh_key(keyPath)

f = open(keyPath + '.pub', 'r')
Key = f.readlines()[0].rstrip()

cfg_file = open("auto_config.py", 'a')
cfg_file.writelines(f'sshKey = "{Key}"\n')
cfg_file.close()


# Use the right python version to start pytest with sys.executable
# So that we can support virtualenv python pytest.
pytest_result = call([
    sys.executable,
    "-m",
    "pytest",
    "-v",
    "-o", "junit_family=xunit2",
    "--timeout=300",
    "--junitxml",
    'results/api_v2_tests_result.xml',
    f"api2/{testName}"
])

# get useful logs
artifacts = f"{workdir}/artifacts/"
if not os.path.exists(artifacts):
    os.makedirs(artifacts)

artifact_result = 0
try:
    copied = get_folder('/var/log', f'{artifacts}/log', 'root', passwd, ip)
    if not copied['result']:
        raise RuntimeError(f"log copy failed: {copied['stderr']}")

    # get dmesg and put it in artifacts
    results = SSH_TEST('dmesg -a', 'root', passwd, ip)
    with open(f'{artifacts}/dmesg', 'w') as dmsg:
        dmsg.writelines(results['output'])

    # get core.get_jobs and put it in artifacts
    results = SSH_TEST('midclt call core.get_jobs | jq .', 'root', passwd, ip)
    with open(f'{artifacts}/core.get_jobs', 'w') as jobs:
        jobs.writelines(results['output'])
except Exception as e:
    artifact_result = 1
    print(f'artifact collection failed: {type(e).__name__}: {e}')

# Never hide either a pytest failure or an artifact-collection failure.
raise SystemExit(pytest_result or artifact_result)
