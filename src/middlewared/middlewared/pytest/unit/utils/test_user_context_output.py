# the internal development record: the FreeBSD runner never drops output lines when its caller is slow.
import os
import queue
import sys
import threading
import time
from unittest.mock import patch

import pytest

from middlewared.utils.osc.freebsd import user_context


class ThreadProcess(threading.Thread):
    # The child side as a thread; like a multiprocessing child that ran to its end, it reports exit code 0
    # (run_command_with_user_context reads p.exitcode since the internal development record).
    exitcode = 0


def seq_output(lines):
    return b''.join(f'{i}\n'.encode() for i in range(1, lines + 1))


def test_freebsd_runner_keeps_output_while_the_caller_is_busy():
    # Run the child side in a thread without the user switch so this runs off-box. The thread
    # gets a queue.Queue with the same bound: a multiprocessing.Queue shared inside one process
    # can still hold lines in its feeder thread after the thread has ended, and the parent, seeing
    # the child gone and the pipe empty, would stop reading early (a real child flushes before it
    # exits). The old non-blocking put drops lines on either queue.
    received = []

    def callback(line):
        if not received:
            # The caller (job log, syslog) stalls while the command keeps writing.
            time.sleep(0.5)
        received.append(line)

    with (
        patch.dict(os.environ),
        patch.object(user_context, 'setusercontext'),
        patch.object(user_context, 'Process', ThreadProcess),
        patch.object(user_context, 'Queue', queue.Queue),
    ):
        result = user_context.run_command_with_user_context('seq 1 1000', 'root', callback)

    assert result.returncode == 0
    assert b''.join(received) == seq_output(1000)
    assert result.stdout == seq_output(1000)


@pytest.mark.skipif(not sys.platform.startswith('freebsd'), reason='FreeBSD setusercontext in a child process')
def test_freebsd_runner_keeps_output_of_a_fast_command():
    received = []

    result = user_context.run_command_with_user_context('seq 1 100000', 'root', received.append)

    assert result.returncode == 0
    assert b''.join(received) == seq_output(100000)
    assert result.stdout == seq_output(100000)
