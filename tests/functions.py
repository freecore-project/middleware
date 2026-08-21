#!/usr/bin/env python3

# Author: Eric Turgeon
# License: BSD

import json
import os
import re
import uuid
from subprocess import PIPE, Popen, TimeoutExpired, run
from time import sleep

import requests
import websocket

from auto_config import api_url, password, user

if "controller1_ip" in os.environ:
    controller1_ip = os.environ["controller1_ip"]
    controller1_api_url = f'http://{controller1_ip}/api/v2.0'
else:
    controller1_api_url = api_url

global header
header = {'Content-Type': 'application/json', 'Vary': 'accept'}
global authentication
authentication = (user, password)

failed = [None]

# nginx's proxy_read_timeout for the middleware upstream.
NGINX_PROXY_READ_TIMEOUT = 60


def _note_html_response(verb, testpath, response):
    """
    An HTML error body from this API is nginx talking, not middleware: the upstream
    call outlived nginx's proxy_read_timeout and nginx returned its own error page.

    The test then asserts against `<!DOCTYPE html>`, which names neither the call nor
    the cause. Five failures in the first 15.0 gate run looked like that and the real
    defect took a night to find (freecore/the internal development record -- service.start cifs never
    returned). Say it at the moment it happens; pytest captures stdout and prints it
    with the failure, so the next person reads a sentence instead of an error page.

    Diagnostic only. Never changes a result.
    """
    if response.status_code < 400:
        return response
    if 'html' not in response.headers.get('Content-Type', '').lower():
        return response
    print(
        f'\n*** {verb} {testpath} -> HTTP {response.status_code} with an HTML body.'
        f'\n*** That is nginx, not middleware: the API call did not return within its'
        f' {NGINX_PROXY_READ_TIMEOUT}s proxy_read_timeout, so nginx gave up on the'
        f' upstream and served its own error page.'
        f'\n*** The assertion below will show that page. The cause is a middleware call'
        f' that never returned -- check middlewared.log for what it was doing.'
    )
    return response


def GET(testpath, payload=None, controller_a=False, **optional):
    data = {} if payload is None else payload
    url = controller1_api_url if controller_a else api_url
    if testpath.startswith('http'):
        getit = requests.get(testpath)
    else:
        if optional.pop("anonymous", False):
            auth = None
        else:
            auth = authentication
        getit = requests.get(f'{url}{testpath}', headers=dict(header, **optional.get("headers", {})),
                             auth=auth, data=json.dumps(data))
    return _note_html_response('GET', testpath, getit)


def POST(testpath, payload=None, controller_a=False, **optional):
    data = {} if payload is None else payload
    url = controller1_api_url if controller_a else api_url
    if optional.pop("anonymous", False):
        auth = None
    else:
        auth = authentication
    if payload is None:
        postit = requests.post(f'{url}{testpath}', headers=dict(header, **optional.get("headers", {})),
                               auth=auth)
    else:
        postit = requests.post(f'{url}{testpath}', headers=dict(header, **optional.get("headers", {})),
                               auth=auth, data=json.dumps(data))
    return _note_html_response('POST', testpath, postit)


def PUT(testpath, payload=None, controller_a=False, **optional):
    data = {} if payload is None else payload
    url = controller1_api_url if controller_a else api_url
    if optional.pop("anonymous", False):
        auth = None
    else:
        auth = authentication
    putit = requests.put(f'{url}{testpath}', headers=dict(header, **optional.get("headers", {})),
                         auth=auth, data=json.dumps(data))
    return _note_html_response('PUT', testpath, putit)


def DELETE(testpath, payload=None, controller_a=False, **optional):
    data = {} if payload is None else payload
    url = controller1_api_url if controller_a else api_url
    if optional.pop("anonymous", False):
        auth = None
    else:
        auth = authentication
    deleteit = requests.delete(f'{url}{testpath}', headers=dict(header, **optional.get("headers", {})),
                               auth=auth,
                               data=json.dumps(data))
    return _note_html_response('DELETE', testpath, deleteit)


class SSHError(Exception):
    """Base: ssh(1) failed before the remote command produced an exit status."""


class SSHConnectionError(SSHError):
    """ssh(1) could not reach the target at all."""


class SSHAuthError(SSHError):
    """ssh(1) reached the target, but authentication was rejected.

    Deliberately distinct from SSHConnectionError: the target is up and
    answering, we just cannot log in (yet). test_001_ssh enables root login and
    starts the service, but if sshd was already running the start is a no-op and
    the regenerated config may not be loaded for a moment -- so an auth rejection
    early in a run is transient and local to the test, not a dead target.
    conftest only aborts the run for SSHConnectionError.
    """


# ssh(1) reserves 255 for its own failures; everything else is the remote
# command's exit status. Distinguish by what it printed, since 255 covers both.
_SSH_AUTH_MARKERS = (
    'Permission denied',
    'Too many authentication failures',
    'sshpass: Invalid/incorrect password',
    'sshpass: Failed to run command',
)
_SSH_UNREACHABLE_MARKERS = (
    'Connection refused',
    'Connection closed',
    'Connection timed out',
    'Connection reset',
    'No route to host',
    'Network is unreachable',
    'Could not resolve hostname',
    'Host key verification failed',
    'Operation timed out',
)


def _ssh_failure(process):
    """Return an exception to raise, or None if ssh itself ran fine.

    The discriminator is the exit status, NOT the text. ssh(1) reserves 255 for
    its own failures and otherwise passes through the remote command's status,
    so anything != 255 means ssh connected, authenticated, ran the command, and
    the command decided the outcome -- that is a result, never a transport error.

    This matters more than it looks: the ACL and POSIX-mode suites deliberately
    run commands as an unprivileged user to prove access IS refused, so
    "Permission denied" appears on stderr as the correct answer. Matching that
    text regardless of status turned 53 passing baseline tests into errors
    (observed on the 13.3 run, 2026-08-09). Only ssh's own "Permission denied
    (publickey,password)" at rc 255 is an auth failure.
    """
    err = process.stderr or ''
    # sshpass reports its own failures with a distinctive prefix and does not
    # use 255, so it has to be matched on text.
    if re.search(r'^sshpass: ', err, re.M):
        return SSHAuthError
    if process.returncode != 255:
        return None
    if any(m in err for m in _SSH_AUTH_MARKERS):
        return SSHAuthError
    if any(m in err for m in _SSH_UNREACHABLE_MARKERS):
        return SSHConnectionError
    # ssh failed but did not say why -- conservative reading is unreachable.
    return SSHConnectionError


def SSH_TEST(command, username, passwrd, host):
    cmd = [] if passwrd is None else ["sshpass", "-p", passwrd]
    cmd += [
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "VerifyHostKeyDNS=no",
        f"{username}@{host}",
        command
    ]
    process = run(cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True)
    output = process.stdout
    stderr = process.stderr
    # A great many tests assert `result is False` to mean "the remote command
    # exited non-zero" (e.g. "grep found nothing"). Without this guard an
    # unreachable target satisfies every one of them, so the suite reports
    # green for the one condition it most needs to catch.
    exc = _ssh_failure(process)
    if exc is not None:
        raise exc(
            f'ssh to {username}@{host} failed (rc={process.returncode}): {stderr.strip()}'
        )
    return {
        'result': process.returncode == 0,
        'output': output,
        'stderr': stderr,
        'returncode': process.returncode,
    }


def async_SSH_start(command, username, passwrd, host):
    cmd = [] if passwrd is None else ["sshpass", "-p", passwrd]
    cmd += [
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "VerifyHostKeyDNS=no",
        "-o",
        "LogLevel=quiet",
        f"{username}@{host}",
        command
    ]
    return Popen(cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True)


def async_SSH_done(proc, timeout=120):
    try:
        outs, errs = proc.communicate(timeout=timeout)
    except TimeoutExpired:
        proc.kill()
        outs, errs = proc.communicate()

    return outs, errs


def send_file(file, destination, username, passwrd, host):
    cmd = [] if passwrd is None else ["sshpass", "-p", passwrd]
    cmd += [
        "scp",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "VerifyHostKeyDNS=no",
        file,
        f"{username}@{host}:{destination}"
    ]
    process = run(cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True)
    output = process.stdout
    stderr = process.stderr
    if process.returncode != 0:
        return {'result': False, 'output': output, 'stderr': stderr}
    else:
        return {'result': True, 'output': output, 'stderr': stderr}


def get_file(file, destination, username, passwrd, host):
    cmd = [] if passwrd is None else ["sshpass", "-p", passwrd]
    cmd += [
        "scp",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "VerifyHostKeyDNS=no",
        f"{username}@{host}:{file}",
        destination
    ]
    process = run(cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True)
    output = process.stdout
    stderr = process.stderr
    if process.returncode != 0:
        return {'result': False, 'output': output, 'stderr': stderr}
    else:
        return {'result': True, 'output': output, 'stderr': stderr}


def get_folder(folder, destination, username, passwrd, host):
    cmd = [] if passwrd is None else ["sshpass", "-p", passwrd]
    cmd += [
        "scp",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "VerifyHostKeyDNS=no",
        "-r",
        f"{username}@{host}:{folder}",
        destination
    ]
    process = run(cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True)
    output = process.stdout
    stderr = process.stderr
    if process.returncode != 0:
        return {'result': False, 'output': output, 'stderr': stderr}
    else:
        return {'result': True, 'output': output, 'stderr': stderr}


def cmd_test(command):
    process = run(command, shell=True, stdout=PIPE, stderr=PIPE, universal_newlines=True)
    output = process.stdout
    stderr = process.stderr
    if process.returncode != 0:
        return {'result': False, 'output': output, 'stderr': stderr}
    else:
        return {'result': True, 'output': output, 'stderr': stderr}


def start_ssh_agent():
    process = run(['ssh-agent', '-s'], stdout=PIPE, universal_newlines=True)
    to_recompile = r'SSH_AUTH_SOCK=(?P<socket>[^;]+).*SSH_AGENT_PID=(?P<pid>\d+)'
    OUTPUT_PATTERN = re.compile(to_recompile, re.MULTILINE | re.DOTALL)
    match = OUTPUT_PATTERN.search(process.stdout)
    if match is None:
        return False
    else:
        agentData = match.groupdict()
        os.environ['SSH_AUTH_SOCK'] = agentData['socket']
        os.environ['SSH_AGENT_PID'] = agentData['pid']
        return True


def is_agent_setup():
    return os.environ.get('SSH_AUTH_SOCK') is not None


def setup_ssh_agent():
    if is_agent_setup():
        return True
    else:
        return start_ssh_agent()


def create_key(keyPath):
    process = run('ssh-keygen -t rsa -f %s -q -N ""' % keyPath, shell=True)
    if process.returncode != 0:
        return False
    else:
        return True


def if_key_listed():
    process = run('ssh-add -L', shell=True)
    if process.returncode != 0:
        return False
    else:
        return True


def add_ssh_key(keyPath):
    process = run(['ssh-add', keyPath])
    if process.returncode != 0:
        return False
    else:
        return True


def ping_host(host, count):
    process = run(['ping', '-c', f'{count}', host])
    if process.returncode != 0:
        return False
    else:
        return True


def wait_on_job(job_id, max_timeout):
    global job_results
    timeout = 0
    while True:
        job_results = GET(f'/core/get_jobs/?id={job_id}')
        jobs = job_results.json()
        if not jobs:
            return {'state': 'MISSING',
                    'results': f'no job with id {job_id}: {job_results.text}'}
        job = jobs[0]
        job_state = job['state']
        if job_state in ('SUCCESS', 'FAILED'):
            return {'state': job_state, 'results': job}
        # Any other state (ABORTED, HOLD, ...) previously fell through without
        # sleeping, so the loop spun at full speed hammering /core/get_jobs/
        # and then reported TIMEOUT instead of the state it actually saw.
        if job_state not in ('RUNNING', 'WAITING'):
            return {'state': job_state, 'results': job}
        if timeout >= max_timeout:
            return {'state': 'TIMEOUT', 'results': job}
        sleep(5)
        timeout += 5


def make_ws_request(ip, payload):
    # create connection
    ws = websocket.create_connection(f'ws://{ip}:80/websocket')

    # setup features
    ws.send(json.dumps({'msg': 'connect', 'version': '1', 'support': ['1'], 'features': []}))
    ws.recv()

    # login
    id = str(uuid.uuid4())
    ws.send(json.dumps({'id': id, 'msg': 'method', 'method': 'auth.login', 'params': list(authentication)}))
    ws.recv()

    # return the request
    payload.update({'id': id})
    ws.send(json.dumps(payload))
    return json.loads(ws.recv())


def fail(reason):
    """
    Prematurely abort the whole test suite execution, failing the test where this function is called
    (as opposed to just using `pytest.exit` which will not fail the test, and, if no previous tests failed, junit
    Jenkins plugin will display the test suite as green)
    """
    failed[0] = reason
    assert False, reason
