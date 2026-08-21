import asyncio
from unittest.mock import AsyncMock, Mock

from aiohttp.test_utils import make_mocked_request
import pytest

from middlewared.job import State
from middlewared.main import FileApplication
from middlewared.pipe import Pipe, Pipes


def download_setup(state):
    loop = asyncio.get_event_loop()
    middleware = Mock()
    middleware.loop = loop
    middleware.run_in_thread = lambda method, *args: loop.run_in_executor(None, method, *args)
    middleware.call = AsyncMock(return_value={'attributes': {'job': 1, 'filename': 'keys.json'}})

    job = Mock(id=1, state=state, error=None, pipes=Pipes(output=Pipe(middleware)))
    middleware.jobs = {1: job}

    fileapp = FileApplication(middleware, loop)
    fileapp.register_job(1, False)
    return fileapp, job, make_mocked_request('GET', '/_download/1?auth_token=token')


def fail_job(job):
    # What Job.run does when the method raises
    job.state = State.FAILED
    job.error = '[EFAULT] Pool tank not found'
    job.pipes.output.w.close()


@pytest.mark.asyncio
async def test_download_of_failed_job_is_not_200():
    fileapp, job, request = download_setup(State.RUNNING)
    fail_job(job)

    resp = await fileapp.download(request)

    assert resp.status == 422
    assert resp.text == '[EFAULT] Pool tank not found'


@pytest.mark.asyncio
async def test_download_of_job_that_fails_while_client_waits_is_not_200():
    fileapp, job, request = download_setup(State.RUNNING)
    asyncio.get_event_loop().call_later(0.1, fail_job, job)

    resp = await fileapp.download(request)

    assert resp.status == 422
    assert resp.text == '[EFAULT] Pool tank not found'


@pytest.mark.asyncio
async def test_download_of_successful_job_streams_output():
    fileapp, job, request = download_setup(State.RUNNING)
    job.pipes.output.w.write(b'{"tank": "key"}')
    job.pipes.output.w.close()
    job.state = State.SUCCESS

    resp = await fileapp.download(request)

    assert resp.status == 200
    request._payload_writer.write.assert_called_once_with(b'{"tank": "key"}')
