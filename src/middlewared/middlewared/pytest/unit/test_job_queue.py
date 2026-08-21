import asyncio
from unittest.mock import Mock

import pytest

from middlewared.job import Job, JobsQueue
from middlewared.service import job


@job(lock="process_alerts", transient=True, lock_queue_size=1)
async def process_alerts(job):
    pass


def new_job(middleware):
    return Job(middleware, "alert.process_alerts", None, process_alerts, [], process_alerts._job, None, None)


def test_job_refused_by_lock_queue_size_is_not_kept_in_lock():
    middleware = Mock()
    queue = JobsQueue(middleware)

    queued = new_job(middleware)
    assert queue.add(queued) is queued

    refused = new_job(middleware)
    assert queue.add(refused) is queued

    assert queue.job_locks["process_alerts"].get_jobs() == {queued}


@pytest.mark.asyncio
async def test_lock_is_dropped_after_jobs_refused_by_lock_queue_size():
    middleware = Mock()
    queue = JobsQueue(middleware)

    running = new_job(middleware)
    assert queue.add(running) is running
    assert await asyncio.wait_for(queue.next(), 1) is running

    queued = new_job(middleware)
    assert queue.add(queued) is queued
    for i in range(3):
        assert queue.add(new_job(middleware)) is queued

    queue.release_lock(running)
    assert await asyncio.wait_for(queue.next(), 1) is queued
    queue.release_lock(queued)

    assert queue.job_locks == {}
