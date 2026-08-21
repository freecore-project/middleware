import multiprocessing
import os
import signal
import uuid

import pytest

from middlewared.utils.osc.freebsd import user_context


@pytest.fixture
def fork_context(monkeypatch):
    # Fork so the child inherits this process's patches (and imports, which a
    # spawned child cannot repeat off-box); the start method is not under test.
    ctx = multiprocessing.get_context('fork')
    monkeypatch.setattr(user_context, 'Process', ctx.Process)
    monkeypatch.setattr(user_context, 'Queue', ctx.Queue)
    monkeypatch.setattr(user_context, 'Value', ctx.Value)


def test_unknown_user_is_a_failure(fork_context):
    user = f'freecore-missing-{uuid.uuid4().hex[:8]}'
    output = []

    result = user_context.run_command_with_user_context('echo ran', user, output.append)

    assert result.returncode == 1
    assert result.stdout == b''
    assert output == []


def test_child_killed_before_reporting_is_a_failure(fork_context, monkeypatch):
    monkeypatch.setattr(user_context, 'setusercontext', lambda user: os.kill(os.getpid(), signal.SIGKILL))

    result = user_context.run_command_with_user_context('echo ran', 'root', lambda line: None)

    assert result.returncode == -signal.SIGKILL


@pytest.mark.parametrize('commandline,returncode,stdout', [
    ('echo ran', 0, b'ran\n'),
    ('echo ran; exit 3', 3, b'ran\n'),
])
def test_command_exit_status_is_returned(fork_context, monkeypatch, commandline, returncode, stdout):
    monkeypatch.setattr(user_context, 'setusercontext', lambda user: None)
    output = []

    result = user_context.run_command_with_user_context(commandline, 'root', output.append)

    assert result.returncode == returncode
    assert result.stdout == stdout
    assert b''.join(output) == stdout
