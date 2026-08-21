import asyncio
import errno
import os
import queue
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from middlewared.plugins import webterminal


class OutputSocket:
    def __init__(self):
        self.output = bytearray()
        self.closed = asyncio.Event()

    async def send_bytes(self, data):
        assert not self.closed.is_set(), 'PTY output must be forwarded before closing the websocket'
        self.output.extend(data)

    async def close(self):
        self.closed.set()


async def wait_for_output(socket, marker):
    async def wait():
        while marker not in socket.output:
            assert not socket.closed.is_set(), bytes(socket.output)
            await asyncio.sleep(0.01)
    await asyncio.wait_for(wait(), 5)


async def finish_session(proc, fd, session):
    session.die()
    if proc.poll() is None:
        proc.kill()
    await asyncio.to_thread(proc.wait, 2)
    await asyncio.to_thread(session.join, 2)
    os.close(fd)
    assert not session.is_alive()


@pytest.mark.asyncio
async def test_real_shell_stays_connected_until_exit_then_drains_output_and_closes():
    proc, fd = webterminal._spawn(['/bin/sh', '-c', 'printf "READY\\n"; read value; printf "FINAL:%s\\n" "$value"'])
    socket = OutputSocket()
    inputs = queue.Queue()
    session = webterminal.ShellSession2Thread(socket, fd, proc.pid, inputs, asyncio.get_running_loop())
    session.start()
    try:
        await wait_for_output(socket, b'READY')
        await asyncio.sleep(0.05)
        assert proc.poll() is None
        assert not socket.closed.is_set()
        inputs.put(b'canary-input\n')
        await asyncio.wait_for(socket.closed.wait(), 5)
        assert b'FINAL:canary-input' in socket.output
        await asyncio.to_thread(session.join, 2)
        assert not session.is_alive()
        assert await asyncio.to_thread(proc.wait, 2) == 0
    finally:
        await finish_session(proc, fd, session)


@pytest.mark.asyncio
async def test_exec_failure_is_forwarded_from_real_pty_before_websocket_close():
    proc, fd = webterminal._spawn(['/nonexistent-freecore-terminal-canary-command'])
    socket = OutputSocket()
    session = webterminal.ShellSession2Thread(socket, fd, proc.pid, queue.Queue(), asyncio.get_running_loop())
    session.start()
    try:
        await asyncio.wait_for(socket.closed.wait(), 5)
        assert b'FileNotFoundError' in socket.output
        assert b'/nonexistent-freecore-terminal-canary-command' in socket.output
        assert await asyncio.to_thread(proc.wait, 2) != 0
    finally:
        await finish_session(proc, fd, session)


@pytest.mark.asyncio
async def test_inherited_pty_remains_controlling_terminal_and_accepts_resize():
    command = [sys.executable, '-c', (
        'import fcntl,os,struct,sys,termios; '
        'print("READY", flush=True); sys.stdin.readline(); '
        'rows,cols,_,_=struct.unpack("HHHH", fcntl.ioctl(0,termios.TIOCGWINSZ,b"\\0"*8)); '
        'print(f"SIZE:{rows}:{cols};TTY:{os.isatty(0)}:{os.tcgetpgrp(0)==os.getpgrp()}", flush=True)'
    )]
    proc, fd = webterminal._spawn(command)
    socket = OutputSocket()
    inputs = queue.Queue()
    session = webterminal.ShellSession2Thread(socket, fd, proc.pid, inputs, asyncio.get_running_loop())
    session.start()
    try:
        await wait_for_output(socket, b'READY')
        inputs.put(('resize', 119, 37))
        inputs.put(b'\n')
        await asyncio.wait_for(socket.closed.wait(), 5)
        assert b'SIZE:37:119;TTY:True:True' in socket.output
        assert await asyncio.to_thread(proc.wait, 2) == 0
    finally:
        await finish_session(proc, fd, session)


def test_spawn_failure_closes_both_parent_pty_descriptors(monkeypatch):
    real_openpty = os.openpty
    descriptors = []

    def openpty():
        descriptors.extend(real_openpty())
        return tuple(descriptors)

    monkeypatch.setattr(webterminal.os, 'openpty', openpty)
    monkeypatch.setattr(webterminal.subprocess, 'Popen', Mock(side_effect=OSError(errno.EAGAIN, 'spawn refused')))
    with pytest.raises(OSError, match='spawn refused'):
        webterminal._spawn(['/bin/sh'])
    for descriptor in descriptors:
        with pytest.raises(OSError) as error:
            os.fstat(descriptor)
        assert error.value.errno == errno.EBADF


@pytest.mark.asyncio
async def test_spawn_failure_reports_failure_and_closes_authenticated_socket(monkeypatch):
    socket = Mock(
        prepare=AsyncMock(),
        receive=AsyncMock(return_value=SimpleNamespace(type=webterminal.WSMsgType.TEXT, data='single-use-ticket')),
        send_json=AsyncMock(), close=AsyncMock(),
    )
    monkeypatch.setattr(webterminal.web, 'WebSocketResponse', lambda: socket)
    monkeypatch.setattr(webterminal.WebTerminalService, 'pop_ticket', Mock(return_value={
        'options': {'jail': 'test'}, 'remote': '192.0.2.1', 'target': 'jail',
    }))
    monkeypatch.setattr(webterminal.ShellApplication2, 'sessions', {})
    monkeypatch.setattr(webterminal, '_spawn', Mock(side_effect=OSError(errno.EAGAIN, 'spawn refused')))
    monkeypatch.setattr(webterminal.syslog, 'openlog', Mock())
    monkeypatch.setattr(webterminal.syslog, 'syslog', Mock())
    application = webterminal.ShellApplication2(Mock())
    request = SimpleNamespace(remote='127.0.0.1', headers={'X-Real-Remote-Addr': '192.0.2.1'})
    assert await application.ws_handler(request) is socket
    message = socket.send_json.await_args.args[0]
    assert message['msg'] == 'failed'
    assert message['error']['error'] == errno.EAGAIN
    assert 'spawn refused' in message['error']['reason']
    socket.close.assert_awaited_once()
    assert application.sessions == {}


@pytest.mark.asyncio
async def test_real_child_exit_finishes_websocket_handler_reaps_child_and_releases_session(monkeypatch):
    class Socket(OutputSocket):
        prepare = AsyncMock()
        receive = AsyncMock(return_value=SimpleNamespace(type=webterminal.WSMsgType.TEXT, data='ticket'))
        send_json = AsyncMock()

        def __aiter__(self):
            return self

        async def __anext__(self):
            await self.closed.wait()
            raise StopAsyncIteration

    socket = Socket()
    monkeypatch.setattr(webterminal.web, 'WebSocketResponse', lambda: socket)
    monkeypatch.setattr(webterminal.WebTerminalService, 'pop_ticket', Mock(return_value={
        'options': {'jail': 'test'}, 'remote': '192.0.2.1', 'target': 'jail',
    }))
    monkeypatch.setattr(webterminal.ShellApplication2, 'sessions', {})
    monkeypatch.setattr(webterminal.syslog, 'openlog', Mock())
    monkeypatch.setattr(webterminal.syslog, 'syslog', Mock())
    real_spawn = webterminal._spawn
    children = []

    def spawn(command):
        result = real_spawn(command)
        children.append(result[:2])
        return result

    monkeypatch.setattr(webterminal, '_spawn', spawn)
    middleware = Mock(run_in_thread=asyncio.to_thread)
    application = webterminal.ShellApplication2(middleware)
    # 15.0 leg: this line builds the command with the module-level _get_command (15.1 has
    # ShellApplication2._resolve_command), so the fake child is injected there.
    monkeypatch.setattr(webterminal, '_get_command', Mock(return_value=['/bin/sh', '-c', 'printf "FINAL-HANDLER\\n"']))
    request = SimpleNamespace(remote='127.0.0.1', headers={'X-Real-Remote-Addr': '192.0.2.1'})
    try:
        assert await asyncio.wait_for(application.ws_handler(request), 6) is socket
        assert b'FINAL-HANDLER' in socket.output
        assert socket.closed.is_set()
        assert application.sessions == {}
        proc, fd = children[0]
        assert proc.returncode == 0
        with pytest.raises(ChildProcessError):
            await asyncio.to_thread(os.waitpid, proc.pid, os.WNOHANG)
        with pytest.raises(OSError) as error:
            os.fstat(fd)
        assert error.value.errno == errno.EBADF
    finally:
        for proc, fd in children:
            if proc.poll() is None:
                proc.kill()
                await asyncio.to_thread(proc.wait, 2)
            try:
                os.close(fd)
            except OSError:
                pass
