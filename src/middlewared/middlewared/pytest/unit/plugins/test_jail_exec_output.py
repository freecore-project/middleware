"""the internal development record: jail.exec returns the command's output as it was printed.

iocage hands back the output in chunks that each end in a newline (consume_and_log only appends a complete
line). Joining them with another newline put an empty line at every chunk boundary: `seq 1 20000` came back
108901 bytes instead of 108894.
"""
from unittest.mock import Mock, patch

import pytest

from middlewared.plugins.jail_freebsd import JailService


def run_exec(chunks, command=('seq 1 20000',)):
    iocage = Mock()
    iocage.exec.return_value = chunks
    service = JailService(Mock())
    with patch.object(JailService, 'check_jail_existence', return_value=(None, None, iocage)):
        result = JailService.exec.wraps(service, Mock(), 'web', list(command), {'host_user': 'root'})
    return result, iocage


@pytest.mark.parametrize('chunks', [
    ['1\n2\n3\n'],
    ['1\n2\n', '3\n4\n', '5\n'],
    ['x' * 12287 + '\n', 'y' * 20479 + '\n', 'z\n'],
])
def test_output_is_the_chunks_unchanged(chunks):
    result, _ = run_exec(chunks)

    assert result == ''.join(chunks)
    assert '\n\n' not in result


def test_no_output_is_an_empty_string():
    assert run_exec([])[0] == ''


def test_a_single_command_still_runs_through_the_shell():
    _, iocage = run_exec(['ok\n'], command=('echo ok && true',))

    assert iocage.exec.call_args.args[0] == ['/bin/sh', '-c', 'echo ok && true']
