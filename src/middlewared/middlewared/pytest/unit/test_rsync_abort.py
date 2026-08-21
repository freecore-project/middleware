import asyncio
from io import BytesIO
import subprocess
import sys
import threading
import time
import uuid
from unittest.mock import Mock, patch

import pytest

from middlewared.job import Job, State
from middlewared.plugins import rsync


def running_job(*, abortable):
    job = object.__new__(Job)
    job.state = State.RUNNING
    job.options = {'abortable': abortable}
    job.aborted = False
    job.future = Mock()
    job.loop = Mock()
    job.loop.call_soon_threadsafe.side_effect = lambda callback: callback()
    return job


def test_regular_job_abort_keeps_existing_asyncio_cancellation():
    job = running_job(abortable=False)
    job.abort()
    assert job.aborted is True
    job.future.cancel.assert_called_once_with()


def test_abortable_sync_job_waits_for_worker_cleanup():
    job = running_job(abortable=True)
    job.abort()
    assert job.aborted is True
    job.future.cancel.assert_not_called()


@pytest.mark.asyncio
async def test_abortable_job_becomes_terminal_only_after_worker_cleanup():
    abort_seen = threading.Event()
    allow_cleanup = threading.Event()
    cleanup_done = threading.Event()

    def worker(job):
        while not job.aborted:
            time.sleep(0.01)
        abort_seen.set()
        allow_cleanup.wait()
        cleanup_done.set()
        raise asyncio.CancelledError()

    class JobMiddleware:

        def __init__(self):
            self.loop = asyncio.get_running_loop()
            self.send_event = Mock()

        async def run_in_thread(self, method, *args):
            return await self.loop.run_in_executor(None, method, *args)

        def dump_args(self, args, method=None):
            return args

    middleware = JobMiddleware()
    options = {
        'abortable': True,
        'check_pipes': False,
        'logs': False,
        'pipes': [],
        'transient': False,
    }
    job = Job(middleware, 'test.abortable', None, worker, [], options, None, None)
    job.set_id(1)
    queue = Mock()

    running = asyncio.create_task(job.run(queue))
    while job.state == State.WAITING:
        await asyncio.sleep(0)
    job.abort()
    assert await asyncio.to_thread(abort_seen.wait, 1)
    assert job.state == State.RUNNING
    queue.release_lock.assert_not_called()

    allow_cleanup.set()
    await running
    assert cleanup_done.is_set()
    assert job.state == State.ABORTED
    queue.release_lock.assert_called_once_with(job)


def test_rsync_job_opts_into_cooperative_abort():
    assert rsync.RsyncTaskService.run._job['abortable'] is True


class Middleware:

    def __init__(self):
        self.calls = []
        self.event_register = Mock()

    def call_sync(self, name, *args):
        self.calls.append((name, args))
        if name == 'rsynctask.get_instance':
            return {
                'id': 1,
                'locked': False,
                'user': 'root',
                'quiet': False,
                'direction': 'PUSH',
                'path': '/tmp/source',
            }
        if name == 'rsynctask.commandline':
            return '/usr/local/bin/rsync /tmp/source remote:/tmp/destination'
        raise AssertionError(f'unexpected middleware call {name!r}')


def test_aborted_rsync_emits_no_terminal_alert():
    middleware = Middleware()
    service = rsync.RsyncTaskService(middleware)
    job = Mock(aborted=True, logs_fd=BytesIO())

    with (
        patch.object(rsync, 'run_command_with_user_context', return_value=subprocess.CompletedProcess(
            'rsync', -15, b'',
        )) as run_command,
        pytest.raises(asyncio.CancelledError),
    ):
        service.run(job, 1)

    assert run_command.call_args.kwargs['abort']() is True
    assert not any(name.startswith('alert.') for name, _ in middleware.calls)


@pytest.mark.skipif(not sys.platform.startswith('freebsd'), reason='FreeBSD process-group implementation')
@pytest.mark.parametrize('writes_output', [False, True])
def test_freebsd_abort_reaps_the_complete_process_group(writes_output):
    from middlewared.utils.osc.freebsd.user_context import run_command_with_user_context

    token = f'freecore-rsync-abort-{uuid.uuid4().hex}'
    program = (
        'import time; print("ready", flush=True); time.sleep(30)'
        if writes_output else
        'import time; time.sleep(30)'
    )
    commandline = f'/usr/local/bin/python3.11 -u -c \'{program}\' {token}'
    started = time.monotonic()
    output = []

    result = run_command_with_user_context(
        commandline, 'root', output.append, abort=lambda: time.monotonic() - started >= 0.4,
    )

    assert result.returncode < 0
    assert time.monotonic() - started < 5
    if writes_output:
        assert b'ready' in b''.join(output)

    processes = subprocess.run(
        ['ps', 'ax', '-o', 'command='], capture_output=True, check=True, text=True,
    ).stdout.splitlines()
    assert not [process for process in processes if token in process]
