import asyncio
import errno
from unittest.mock import Mock

import pytest

from middlewared.job import Job, JobsDeque, State
from middlewared.service import CoreService
from middlewared.service_exception import CallError


class JobMiddleware:

    def __init__(self):
        self.loop = asyncio.get_running_loop()
        self.jobs = JobsDeque()
        self.send_event = Mock()

    async def run_in_thread(self, method, *args):
        return await self.loop.run_in_executor(None, method, *args)

    def dump_args(self, args, method=None):
        return args


async def run_job(middleware, method_name, method, *args):
    job = Job(middleware, method_name, None, method, list(args), dict(method._job), None, None)
    middleware.jobs.add(job)
    await job.run(Mock())
    return job


@pytest.mark.asyncio
async def test__job_wait_on_unknown_job_id_says_the_job_does_not_exist():
    middleware = JobMiddleware()
    core = CoreService(middleware)

    job = await run_job(middleware, 'core.job_wait', core.job_wait, 999)

    assert job.state == State.FAILED
    assert isinstance(job.exc_info[1], CallError)
    assert job.exc_info[1].errno == errno.ENOENT
    assert job.error == '[ENOENT] Job with id 999 does not exist'


@pytest.mark.asyncio
async def test__job_wait_returns_the_result_of_an_existing_job():
    middleware = JobMiddleware()
    core = CoreService(middleware)

    async def target(job):
        return 'done'

    target._job = core.job_wait._job
    target_job = await run_job(middleware, 'test.target', target)

    job = await run_job(middleware, 'core.job_wait', core.job_wait, target_job.id)

    assert job.state == State.SUCCESS
    assert job.result == 'done'
