# -*- coding=utf-8 -*-
import ctypes
import ctypes.util
import logging
from multiprocessing import Process, Queue, Value
import os
import pwd
import queue
import signal
import subprocess
import time

logger = logging.getLogger(__name__)

__all__ = ["run_command_with_user_context"]


def setusercontext(user):
    libc = ctypes.cdll.LoadLibrary(ctypes.util.find_library('c'))
    # On FreeBSD 14+, libutil is merged into libc. Try libutil first, fall back to libc.
    libutil_path = ctypes.util.find_library('util')
    libutil = ctypes.cdll.LoadLibrary(libutil_path) if libutil_path else libc
    libc.getpwnam.restype = ctypes.POINTER(ctypes.c_void_p)
    pwnam = libc.getpwnam(user.encode('utf-8'))
    passwd = pwd.getpwnam(user)

    libutil.login_getpwclass.restype = ctypes.POINTER(ctypes.c_void_p)
    lc = libutil.login_getpwclass(pwnam)
    os.setgid(passwd.pw_gid)
    if lc and lc[0]:
        libc.initgroups(user.encode('utf-8'), passwd.pw_gid)
        libutil.setusercontext(
            lc, pwnam, passwd.pw_uid, ctypes.c_uint(0x07ff)  # 0x07ff LOGIN_SETALL
        )
        libutil.login_close(lc)
    else:
        os.setgid(passwd.pw_gid)
        libc.setlogin(user.encode('utf-8'))
        libc.initgroups(user.encode('utf-8'), passwd.pw_gid)
        os.setuid(passwd.pw_uid)

    try:
        os.chdir(passwd.pw_dir)
    except Exception:
        os.chdir('/')

    os.environ['HOME'] = passwd.pw_dir


def _run_command(user, commandline, q, rv, grouped):
    if grouped:
        # Put the shell and every descendant it creates (ssh and both local
        # rsync processes included) in a group the middleware parent can reap.
        os.setsid()
    setusercontext(user)

    os.environ['PATH'] = (
        '/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/root/bin'
    )
    proc = subprocess.Popen(
        commandline, shell=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )

    while True:
        line = proc.stdout.readline()
        if line == b'':
            break

        try:
            q.put(line, False)
        except queue.Full:
            pass
    proc.communicate()
    rv.value = proc.returncode
    q.put(None)


def _process_group_exists(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    else:
        return True


def _terminate_process_group(process, grace=2):
    """Terminate and reap a multiprocessing child and the command tree it owns."""
    pgid = process.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        if process.is_alive():
            process.terminate()

    deadline = time.monotonic() + grace
    while _process_group_exists(pgid) and time.monotonic() < deadline:
        process.join(0.05)

    if _process_group_exists(pgid):
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    process.join(grace)
    if process.is_alive():
        process.kill()
        process.join()


def run_command_with_user_context(commandline, user, callback, abort=None):
    q = Queue(maxsize=100)
    rv = Value('i')
    stdout = b''
    aborted = False
    p = Process(
        target=_run_command, args=(user, commandline, q, rv, abort is not None),
        daemon=True
    )
    p.start()
    while p.is_alive() or not q.empty():
        if abort is not None and abort():
            aborted = True
            _terminate_process_group(p)
            break

        try:
            get = q.get(True, 0.2)
            if get is None:
                break
            stdout += get
            callback(get)
        except queue.Empty:
            pass
        except Exception:
            logger.error('Unhandled exception', exc_info=True)
            _terminate_process_group(p)
            raise

    if not aborted:
        p.join()

    return subprocess.CompletedProcess(
        commandline, stdout=stdout, returncode=-signal.SIGTERM if aborted else rv.value
    )
