"""
Redesigned web terminal — strangler fig over the legacy `/_shell` endpoint
in main.py. See freecore/the internal development record for the full design record.

This endpoint serves four targets: an interactive root `shell`, a `jail`
console, a VM serial console (`vm`), and the System Processes viewer
(`processes`).

`system.webterminal.enabled` is False by default (migrated in) and gates the
interactive root `shell` **only**. The other three back pages that already
ship and already work; putting them behind a new default-off toggle would
change how an upgraded install behaves, which guard 1 of the epic forbids.
The toggle exists because an interactive root shell is the new capability —
not because attaching to a jail console is.

The legacy `/_shell` endpoint is untouched by any of this and keeps working
exactly as it does today, regardless of this toggle.

Three concerns kept deliberately separate, per the epic:

  1. Authorization — a short-lived, single-use ticket minted over the
     already-authenticated main RPC websocket (`system.webterminal.get_ticket`),
     consumed on connect to `/_webterminal`. One auth attempt, then the socket
     closes either way.

  2. Execution — `os.posix_spawn` of a tiny single-purpose bootstrap that
     itself calls `setsid()` + acquires the pty as its controlling terminal
     (`TIOCSCTTY`) + `execve()`s the real command. This never calls `fork()`
     from this daemon's own (multi-threaded) process — that is the root
     cause of the DoS documented in internal development note on the epic. Proven
     on the canary (internal development note follow-up): FreeBSD's libc has no
     `posix_spawnattr_setsid`, so the bootstrap does the session/ctty dance
     itself as a fresh, single-threaded process, which is safe.

  3. Transport — binary frames, pty bytes passed through undecoded (deletes
     the UTF-8 split-read crash class outright), resize as an in-band
     control frame on the same socket.
"""
import asyncio
import errno
import fcntl
import json
import os
import queue
import secrets
import select
import signal
import struct
import sys
import syslog
import termios
import threading
import time
import uuid

from aiohttp import web
from aiohttp.http_websocket import WSMsgType

import middlewared.sqlalchemy as sa
from middlewared.schema import accepts, Bool, Dict, Int, Str
from middlewared.service import CallError, ConfigService, pass_app


SHELL_TICKET_TTL = 15  # seconds; single-use regardless
MAX_CONCURRENT_SESSIONS = 8
IDLE_TIMEOUT = 3600  # seconds with no client input before a session is reaped


class WebTerminalModel(sa.Model):
    __tablename__ = 'system_webterminal'

    id = sa.Column(sa.Integer(), primary_key=True)
    enabled = sa.Column(sa.Boolean(), default=False)


class WebTerminalService(ConfigService):
    """
    Enable/disable the redesigned web terminal (`/_webterminal`) and mint the
    single-use connect tickets it requires.
    """

    class Config:
        datastore = 'system.webterminal'
        namespace = 'system.webterminal'

    _tickets = {}

    @accepts(Dict(
        'webterminal_update',
        Bool('enabled'),
        update=True,
    ))
    async def do_update(self, data):
        """
        Enable or disable the redesigned web terminal. Disabled by default.

        This does not affect the legacy `/_shell` endpoint (jail console, VM
        serial console, System Processes) either way.
        """
        old = await self.config()
        new = old.copy()
        new.update(data)
        await self.middleware.call('datastore.update', self._config.datastore, old['id'], new)
        return await self.config()

    @accepts(Dict(
        'webterminal_get_ticket',
        Str('jail', default=None, null=True),
        Int('vm_id', default=None, null=True),
        Bool('processes', default=False),
    ))
    @pass_app()
    async def get_ticket(self, app, data):
        """
        Mint a single-use, short-lived ticket for connecting to `/_webterminal`.
        Must be called over the authenticated main websocket. The ticket is
        bound to the remote address it was minted for and expires in
        `SHELL_TICKET_TTL` seconds whether or not it is used.
        """
        target = _target(data)

        # The toggle guards the *new* feature — an interactive root shell —
        # and nothing else. The jail console, the VM serial console and the
        # System Processes page are pre-existing, always-available pages; if
        # migrating them onto this endpoint made them depend on a new,
        # default-off toggle, an upgraded install would see exactly the
        # behaviour change guard 1 of freecore/the internal development record forbids.
        if target == 'shell' and not (await self.config())['enabled']:
            raise CallError('The web terminal is not enabled.', errno.EPERM)

        self._prune()
        ticket = secrets.token_urlsafe(32)
        self._tickets[ticket] = {
            'remote': _real_remote(app.request),
            'target': target,
            'options': {
                'jail': data.get('jail'),
                'vm_id': data.get('vm_id'),
                'processes': data.get('processes'),
            },
            'deadline': time.monotonic() + SHELL_TICKET_TTL,
        }
        return ticket

    @classmethod
    def pop_ticket(cls, ticket, remote):
        """Single-use: pops regardless of outcome, so a retried/guessed ticket never validates twice."""
        cls._prune()
        data = cls._tickets.pop(ticket, None)
        if data is None:
            return None
        if data['remote'] != remote:
            return None
        return data

    @classmethod
    def _prune(cls):
        now = time.monotonic()
        for key in [k for k, v in cls._tickets.items() if v['deadline'] < now]:
            cls._tickets.pop(key, None)


def _real_remote(request):
    """
    Behind nginx every connection arrives from 127.0.0.1, and the true client
    address is forwarded in `X-Real-Remote-Addr` (see nginx.conf). Resolve it
    the same way auth.py:129 does, so the ticket binding is not trivially
    satisfied by "everyone is loopback" and the audit record below names the
    operator's actual address rather than the proxy's.
    """
    remote = request.remote
    if remote in ('127.0.0.1', '::1'):
        forwarded = request.headers.get('X-Real-Remote-Addr')
        if forwarded:
            return forwarded
    return remote


def _target(options):
    """
    Exactly one of the four things this endpoint can attach you to. Single
    place that decides, so the ticket, the gate and the command can never
    disagree about what was asked for.

    Presence is tested explicitly rather than by truthiness. `vm_id` 0 is a
    perfectly good id and an empty jail name is malformed input; under a
    truthiness test both look like "nothing was asked for", and the caller
    silently lands on the *most privileged* target instead — a root login
    shell. Caught on the canary driving /ui/vm/serial/0, which opened a root
    prompt rather than `cu`. The legacy `get_command` in main.py has the same
    shape and therefore the same behaviour, so this is 13.3-symmetric and
    stays a finding on the epic rather than a regression report.
    """
    requested = {
        'jail': options.get('jail'),
        'vm': options.get('vm_id'),
        'processes': True if options.get('processes') else None,
    }
    selected = [key for key, value in requested.items() if value is not None]
    if len(selected) > 1:
        raise CallError(f'Only one option is supported from {", ".join(selected)}')
    if not selected:
        return 'shell'

    target = selected[0]
    if target == 'jail' and not str(requested['jail']).strip():
        raise CallError('A jail name is required.')
    return target


def _get_command(target, options, remote_addr):
    if target == 'jail':
        return ['/usr/local/bin/iocage', 'console', '-f', options['jail']]
    elif target == 'vm':
        return ['/usr/bin/cu', '-l', f'nmdm{options["vm_id"]}B']
    elif target == 'processes':
        # The System Processes page only ever wanted `top` on a tty. It got
        # there by opening a full root login shell and typing `top` into it
        # (webui system-processes.component.ts), which is a great deal more
        # authority than the page needs. Spawn the thing itself instead —
        # combined with the server-side input suppression in ws_handler, the
        # page can no longer be talked into being a shell.
        return ['/usr/bin/top']
    else:
        # -h carries PAM_RHOST into the PAM session stack — the accounting
        # `-f` otherwise suppresses (login.c:503 assumes the caller already
        # logged it; that obligation is ours now, hence the syslog calls below).
        return ['/usr/bin/login', '-p', '-f', '-h', remote_addr or 'unknown', 'root']


# Runs as a freshly execve()'d, single-threaded process — never a fork() of
# this (multi-threaded) daemon, so there is nothing frozen to inherit. Does
# explicitly what forkpty() used to do in the child branch, because FreeBSD's
# posix_spawn has no session-creation flag (no posix_spawnattr_setsid in
# libc — confirmed on the canary, not assumed from the Linux/glibc behavior).
_BOOTSTRAP = (
    "import os,sys,fcntl,termios\n"
    "os.setsid()\n"
    "fd=os.open(sys.argv[1], os.O_RDWR)\n"
    "fcntl.ioctl(fd, termios.TIOCSCTTY, 0)\n"
    "os.dup2(fd,0); os.dup2(fd,1); os.dup2(fd,2)\n"
    "if fd>2: os.close(fd)\n"
    "os.execve(sys.argv[2], sys.argv[2:], {"
    "'TERM':'xterm','HOME':'/root','LANG':'en_US.UTF-8',"
    "'PATH':'/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:/root/bin'})\n"
)


def _spawn(command):
    master_fd, slave_fd = os.openpty()
    slave_name = os.ttyname(slave_fd)
    # Deliberately NOT closed here. Closing the parent's only slave reference
    # immediately after openpty() races the child's own os.open() of the same
    # device by path: if the refcount hits zero before the child re-opens it,
    # the kernel signals EOF to the master — observed directly on the canary
    # (posix_spawn'd /bin/sh AND /usr/bin/login both got a same-instant EOF
    # on read() with this closed early, even though the child was alive and
    # healthy). Keeping this reference open for the session's lifetime holds
    # the refcount >= 1 throughout, so it can never race. Closed in _reap().

    interpreter = sys.executable
    argv = [interpreter, '-c', _BOOTSTRAP, slave_name] + command
    pid = os.posix_spawn(interpreter, argv, {
        'PATH': '/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin',
    })
    return pid, master_fd, slave_fd


class ShellSession2Thread(threading.Thread):
    """
    Bridges the pty (raw fd) to the input_queue/websocket, mirroring the
    reader/writer split of the legacy ShellWorkerThread, but reading/writing
    raw bytes only — no decode, so a multibyte boundary can't kill this
    thread the way it kills the legacy one (internal development note finding 1).
    """

    def __init__(self, ws, master_fd, pid, input_queue, loop):
        self.ws = ws
        self.master_fd = master_fd
        self.pid = pid
        self.input_queue = input_queue
        self.loop = loop
        self.last_activity = time.monotonic()
        self._die = False
        super().__init__(daemon=True)

    def die(self):
        self._die = True

    def run(self):
        t_reader = threading.Thread(target=self._reader, daemon=True)
        t_reader.start()

        t_writer = threading.Thread(target=self._writer, daemon=True)
        t_writer.start()

        t_reader.join()
        t_writer.join()

        asyncio.run_coroutine_threadsafe(self.ws.close(), self.loop)

    def _reader(self):
        while True:
            try:
                read = os.read(self.master_fd, 4096)
            except OSError:
                break
            if read == b'':
                break
            self.last_activity = time.monotonic()
            try:
                asyncio.run_coroutine_threadsafe(
                    self.ws.send_bytes(read), loop=self.loop
                ).result()
            except Exception:
                break

    def _writer(self):
        while True:
            if self._die:
                break
            try:
                item = self.input_queue.get(timeout=1)
                self.last_activity = time.monotonic()
                if isinstance(item, tuple) and item[0] == 'resize':
                    _, cols, rows = item
                    try:
                        fcntl.ioctl(
                            self.master_fd, termios.TIOCSWINSZ,
                            struct.pack('HHHH', rows, cols, 0, 0),
                        )
                    except OSError:
                        pass
                else:
                    os.write(self.master_fd, item)
            except queue.Empty:
                try:
                    os.kill(self.pid, 0)
                except ProcessLookupError:
                    break
                if time.monotonic() - self.last_activity > IDLE_TIMEOUT:
                    break
            except OSError:
                break


class ShellApplication2:
    """
    Strangler-fig replacement for ShellApplication (main.py). Registered
    alongside it at `/_webterminal`; the old endpoint is never touched.
    """

    sessions = {}  # id -> ShellSession2Thread

    def __init__(self, middleware):
        self.middleware = middleware

    async def ws_handler(self, request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        session_id = str(uuid.uuid4())

        try:
            msg = await ws.receive(timeout=SHELL_TICKET_TTL)
        except Exception:
            await ws.close()
            return ws

        if msg.type not in (WSMsgType.TEXT, WSMsgType.BINARY):
            await ws.close()
            return ws

        ticket_raw = msg.data if isinstance(msg.data, str) else msg.data.decode(errors='ignore')

        ticket_data = WebTerminalService.pop_ticket(ticket_raw.strip(), _real_remote(request))
        if ticket_data is None:
            await ws.send_json({
                'msg': 'failed',
                'error': {'error': errno.EACCES, 'reason': 'Invalid or expired ticket'},
            })
            await ws.close()
            return ws

        if len(self.sessions) >= MAX_CONCURRENT_SESSIONS:
            await ws.send_json({
                'msg': 'failed',
                'error': {'error': errno.EAGAIN, 'reason': 'Too many concurrent terminal sessions'},
            })
            await ws.close()
            return ws

        options = ticket_data['options']
        remote = ticket_data['remote']
        target = ticket_data['target']
        # `top` is a viewer, not a shell: refuse client input server-side
        # rather than trusting the page to keep asking politely. The old page
        # set xterm's `disableStdin` and nothing else, so anything speaking
        # the socket had a root shell's keyboard.
        read_only = target == 'processes'

        try:
            command = _get_command(target, options, remote)
        except CallError as e:
            await ws.send_json({'msg': 'failed', 'error': {'error': errno.EINVAL, 'reason': str(e)}})
            await ws.close()
            return ws

        syslog.openlog('webterminal', facility=syslog.LOG_AUTHPRIV)
        syslog.syslog(
            syslog.LOG_NOTICE,
            f'webterminal: session {session_id} opening {target} ({command[0]}) for remote {remote}',
        )

        pid, master_fd, slave_fd = _spawn(command)

        input_queue = queue.Queue()
        loop = asyncio.get_event_loop()
        t_session = ShellSession2Thread(ws, master_fd, pid, input_queue, loop)
        self.sessions[session_id] = t_session
        t_session.start()

        await ws.send_json({'msg': 'connected', 'id': session_id})

        try:
            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    if not read_only:
                        input_queue.put(msg.data)
                elif msg.type == WSMsgType.TEXT:
                    self._handle_control(msg.data, input_queue)
                else:
                    break
        finally:
            self.sessions.pop(session_id, None)
            await self._reap(pid, t_session)
            for fd in (slave_fd, master_fd):
                try:
                    os.close(fd)
                except OSError:
                    pass
            syslog.syslog(
                syslog.LOG_NOTICE,
                f'webterminal: session {session_id} closed for remote {remote}',
            )

        return ws

    def _handle_control(self, data, input_queue):
        try:
            msg = json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return
        if isinstance(msg, dict) and msg.get('resize'):
            resize = msg['resize']
            try:
                cols = int(resize['cols'])
                rows = int(resize['rows'])
            except (KeyError, TypeError, ValueError):
                return
            input_queue.put(('resize', cols, rows))

    async def _reap(self, pid, t_session):
        # Same kqueue-based wait as the legacy ShellApplication.worker_kill
        # (main.py) — efficient exit notification, SIGTERM then SIGKILL escalation.
        t_session.die()
        try:
            kqueue = select.kqueue()
            kevent = select.kevent(
                pid, select.KQ_FILTER_PROC, select.KQ_EV_ADD | select.KQ_EV_ENABLE, select.KQ_NOTE_EXIT
            )
            kqueue.control([kevent], 0)

            os.kill(pid, signal.SIGTERM)

            events = await self.middleware.run_in_thread(kqueue.control, None, 1, 2)
            if not events:
                os.kill(pid, signal.SIGKILL)
                await self.middleware.run_in_thread(kqueue.control, None, 1, 2)
        except ProcessLookupError:
            pass

        # A kqueue exit notification says the process has *died*; it does not
        # take it out of the process table. These are posix_spawn'd children of
        # this daemon, so nobody else is going to wait on them — without this
        # every terminal session leaves a zombie behind for the lifetime of
        # middlewared. Measured on the canary: 15 sessions, 15 zombie
        # bootstraps plus their login/top.
        #
        # WNOHANG with a couple of retries rather than a blocking wait: in the
        # pathological case where the process outlived even SIGKILL, a blocking
        # waitpid would pin a thread forever.
        for _ in range(3):
            try:
                reaped, _status = await self.middleware.run_in_thread(os.waitpid, pid, os.WNOHANG)
            except ChildProcessError:
                break  # already reaped elsewhere
            if reaped:
                break
            await asyncio.sleep(0.1)

        await self.middleware.run_in_thread(t_session.join, 2)
