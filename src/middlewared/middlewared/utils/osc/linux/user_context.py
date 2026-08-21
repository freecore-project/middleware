# -*- coding=utf-8 -*-
import logging
import os
import select
import signal
import subprocess

logger = logging.getLogger(__name__)

__all__ = ["run_command_with_user_context"]


def _terminate_process_group(process, grace=2):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return

    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def run_command_with_user_context(commandline, user, callback, abort=None):
    if abort is None:
        # Preserve the established execution and streaming path for cron and
        # every caller that did not opt into cooperative process-tree abort.
        p = subprocess.Popen(
            ["sudo", "-H", "-u", user, "sh", "-c", commandline],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        stdout = b""
        while True:
            line = p.stdout.readline()
            if not line:
                break
            stdout += line
            callback(line)
        p.communicate()
        return subprocess.CompletedProcess(commandline, stdout=stdout, returncode=p.returncode)

    p = subprocess.Popen(["sudo", "-H", "-u", user, "sh", "-c", commandline],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)

    stdout = b""
    while True:
        if abort is not None and abort():
            _terminate_process_group(p)
            return subprocess.CompletedProcess(commandline, stdout=stdout, returncode=-signal.SIGTERM)

        readable, _, _ = select.select([p.stdout], [], [], 0.2)
        if readable:
            line = p.stdout.readline()
            if line:
                stdout += line
                callback(line)
                continue

        if p.poll() is not None:
            for line in p.stdout:
                stdout += line
                callback(line)
            break

    p.communicate()

    return subprocess.CompletedProcess(commandline, stdout=stdout, returncode=p.returncode)
