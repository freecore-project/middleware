# the internal development record: aborting a RUNNING synchronous job that does not observe `aborted` is refused; it no longer
# reports ABORTED and releases its lock while its worker thread (or process pool worker) keeps going.
import asyncio
import threading
from unittest.mock import Mock

import pytest

from middlewared.job import Job, State
from middlewared.service_exception import CallError


class JobMiddleware:

    def __init__(self):
        self.loop = asyncio.get_running_loop()
        self.send_event = Mock()
        self.worker_job = None

    async def run_in_thread(self, method, *args):
        return await self.loop.run_in_executor(None, method, *args)

    async def _call_worker(self, name, *args, job=None):
        # Stands in for the process pool: the method runs outside the event loop
        return await self.loop.run_in_executor(None, self.worker_job.method, self.worker_job, *args)

    def dump_args(self, args, method=None):
        return args


def make_job(middleware, method, **options):
    job = Job(middleware, 'test.job', None, method, [], {
        'check_pipes': False, 'logs': False, 'pipes': [], 'transient': False, **options,
    }, None, None)
    job.set_id(1)
    return job


async def start(job):
    queue = Mock()
    running = asyncio.create_task(job.run(queue))
    while job.state == State.WAITING:
        await asyncio.sleep(0)
    return queue, running


@pytest.mark.asyncio
@pytest.mark.parametrize('process', [False, True])
async def test_running_sync_job_refuses_abort_and_keeps_its_lock(process):
    started, finish = threading.Event(), threading.Event()

    def worker(job):
        started.set()
        finish.wait(5)
        return 'done'

    middleware = JobMiddleware()
    job = make_job(middleware, worker, process=process)
    middleware.worker_job = job
    queue, running = await start(job)
    try:
        assert await asyncio.to_thread(started.wait, 1)
        with pytest.raises(CallError, match='cannot be aborted while it is running'):
            job.abort()
        await asyncio.sleep(0.1)
        assert job.aborted is False
        assert job.state == State.RUNNING
        queue.release_lock.assert_not_called()
    finally:
        finish.set()
    await running
    assert job.state == State.SUCCESS and job.result == 'done'
    queue.release_lock.assert_called_once_with(job)


@pytest.mark.asyncio
async def test_abortable_sync_job_observes_the_flag_and_keeps_its_lock_until_it_stops():
    started = threading.Event()

    def worker(job):
        started.set()
        for _ in range(500):
            if job.aborted:
                raise asyncio.CancelledError()
            threading.Event().wait(0.01)
        return 'not aborted'

    middleware = JobMiddleware()
    job = make_job(middleware, worker, abortable=True)
    queue, running = await start(job)
    assert await asyncio.to_thread(started.wait, 1)
    job.abort()
    assert job.aborted is True
    await running
    assert job.state == State.ABORTED
    queue.release_lock.assert_called_once_with(job)


@pytest.mark.asyncio
async def test_waiting_sync_job_can_still_be_aborted():
    job = make_job(JobMiddleware(), lambda job: 'never')
    assert job.state == State.WAITING
    job.abort()
    assert job.aborted is True


@pytest.mark.asyncio
async def test_running_async_job_is_cancelled_as_before():
    started = asyncio.Event()

    async def worker(job):
        started.set()
        await asyncio.sleep(5)
        return 'not aborted'

    middleware = JobMiddleware()
    job = make_job(middleware, worker)
    queue, running = await start(job)
    await asyncio.wait_for(started.wait(), 1)
    job.abort()
    await running
    assert job.state == State.ABORTED
