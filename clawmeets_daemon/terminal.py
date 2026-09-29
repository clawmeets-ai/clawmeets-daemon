# SPDX-License-Identifier: MIT
"""
clawmeets_daemon/terminal.py

Shell sessions on this computer, opened from the user's Computer page and
carried over the daemon's one socket.

## Where this sits next to the allowlist

The allowlist in ``protocol.py`` is the fixed set of things the server can ask
this machine to do. This module is the other half of the connection, stated
plainly on the page: an unconstrained shell, as the user, which the user turns
off ON THIS MACHINE with ``clawmeets computer terminal disable``. The switch is
a local file only the CLI writes (:func:`config.terminal_enabled`); nothing that
arrives on the socket can change it. It is re-read before every session opens
and every :data:`WATCHDOG_SECONDS`, so turning it off also ends live sessions.

## Shape of a session

``$SHELL -l`` on a fresh pty, in ``$HOME``, as its own session and process
group. A login shell because under autostart (launchd / systemd) the daemon's
own environment is minimal, and a terminal whose PATH cannot find ``claude`` is
not the user's terminal.

Output is read with ``loop.add_reader`` into a buffer that one sender task
drains, so bursts coalesce into few frames and order is kept. Flow control is
credit-based: the browser acknowledges bytes it has drawn, and once
:data:`TERM_UNACKED_LIMIT` is outstanding this module stops reading the pty.
The kernel then blocks the writing program, which is the backpressure — a
runaway ``yes`` waits instead of flooding the relay and freezing the tab.

POSIX only, like the rest of the daemon. Standard library only, because the
daemon's three-dependency limit is what lets it start when everything else on
the machine is broken.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import fcntl
import os
import pwd
import signal
import struct
import subprocess
import termios
import time
from typing import Awaitable, Callable, Optional

from clawmeets_daemon import config as cfg
from clawmeets_daemon.protocol import (
    TERM_ACK,
    TERM_CLOSE,
    TERM_EXIT,
    TERM_IDLE_SECONDS,
    TERM_INPUT,
    TERM_MAX_INPUT_BYTES,
    TERM_MAX_SECONDS,
    TERM_MAX_SESSIONS,
    TERM_OPEN,
    TERM_OPENED,
    TERM_OUTPUT,
    TERM_RESIZE,
    TERM_UNACKED_LIMIT,
    validate_session_id,
    validate_size,
)

Send = Callable[[dict], Awaitable[None]]

# How often the switch, idle and age limits are re-checked. This is the bound on
# "`disable` ends open sessions within a few seconds".
WATCHDOG_SECONDS = 5

_READ_CHUNK = 16384
_MAX_OUTPUT_FRAME = 64 * 1024
# Grace between SIGHUP and SIGKILL, so an editor can save its swap file.
_HANGUP_GRACE_SECONDS = 2.0

OFF_MESSAGE = (
    "The terminal is turned off on this computer. Turn it on there with "
    "`clawmeets computer terminal enable`."
)


def _login_shell() -> str:
    """The user's shell: ``$SHELL``, else the passwd entry, else ``/bin/sh``."""
    for candidate in (os.environ.get("SHELL"), _passwd_shell()):
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return "/bin/sh"


def _passwd_shell() -> Optional[str]:
    try:
        return pwd.getpwuid(os.getuid()).pw_shell
    except (KeyError, OSError):
        return None


def _take_controlling_tty() -> None:  # pragma: no cover - runs in the child
    """Make the pty the child's controlling terminal (after setsid).

    Without it job control, Ctrl-C and SIGWINCH do not reach the programs the
    user runs.
    """
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


class TerminalSession:
    """One shell on one pty, streaming to one browser tab."""

    def __init__(
        self,
        session_id: str,
        cols: int,
        rows: int,
        send: Send,
        on_closed: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.session_id = session_id
        self._send = send
        self._on_closed = on_closed
        self._cols, self._rows = cols, rows
        self._proc: Optional[subprocess.Popen] = None
        self._fd: Optional[int] = None
        self._tty = ""
        self._out = bytearray()
        self._in = bytearray()
        self._out_ready = asyncio.Event()
        self._unacked = 0
        self._reading = False
        self._closing = False
        self._sender: Optional[asyncio.Task] = None
        self.opened_at = time.monotonic()
        self.last_activity = self.opened_at

    # ---------------------------------------------------------------- start

    def start(self) -> None:
        """Spawn the shell. Raises ``OSError`` if it cannot be started."""
        master, slave = os.openpty()
        try:
            self._tty = os.ttyname(slave)
            self._set_size(master, self._cols, self._rows)
            env = dict(os.environ)
            env.update({"TERM": "xterm-256color", "COLORTERM": "truecolor"})
            home = os.path.expanduser("~")
            self._proc = subprocess.Popen(
                [_login_shell(), "-l"],
                stdin=slave, stdout=slave, stderr=slave,
                cwd=home if os.path.isdir(home) else "/",
                env=env,
                start_new_session=True,
                preexec_fn=_take_controlling_tty,
                close_fds=True,
            )
        except BaseException:
            os.close(master)
            os.close(slave)
            raise
        # The parent must not hold the slave open, or the pty never reports EOF
        # when the shell exits.
        os.close(slave)
        os.set_blocking(master, False)
        self._fd = master
        self._resume_reading()
        self._sender = asyncio.create_task(self._drain_output())

    # --------------------------------------------------------------- inputs

    def write(self, data: bytes) -> None:
        """Queue keystrokes for the shell. Never blocks the event loop."""
        if self._fd is None or self._closing or not data:
            return
        self.last_activity = time.monotonic()
        was_empty = not self._in
        self._in.extend(data)
        if was_empty:
            self._flush_input()

    def resize(self, cols: int, rows: int) -> None:
        """Set the window size; the kernel sends SIGWINCH to the foreground job."""
        if self._fd is None:
            return
        self._cols, self._rows = cols, rows
        self._set_size(self._fd, cols, rows)

    def ack(self, n: int) -> None:
        """The browser drew ``n`` more bytes. Resume reading once under half the limit."""
        self._unacked = max(0, self._unacked - max(0, n))
        if not self._reading and self._unacked < TERM_UNACKED_LIMIT // 2:
            self._resume_reading()

    # ---------------------------------------------------------------- close

    async def close(self, reason: str) -> None:
        """End the session: hang up the tty and the process group, reap, report.

        The master fd is closed FIRST. That is a real hangup — the kernel sends
        SIGHUP to the session — and it matters on macOS in particular, where a
        process exiting with unread output on its tty blocks in exit until that
        output drains; with nobody reading the master it would never die, not
        even to SIGKILL. SIGHUP to the group follows, then SIGKILL after a short
        grace. Idempotent — the reader hitting EOF and the watchdog can race.
        """
        if self._closing:
            return
        self._closing = True
        loop = asyncio.get_running_loop()
        if self._fd is not None:
            loop.remove_reader(self._fd)
            loop.remove_writer(self._fd)
        self._reading = False

        # Found while the tty still has them: under job control every
        # background job is its own process group, out of reach of a signal to
        # the shell's group alone.
        job_groups = await asyncio.to_thread(_process_groups_on, self._tty)

        # Whatever the shell already printed still reaches the tab.
        if self._sender is not None:
            self._sender.cancel()
            try:
                await self._sender
            except asyncio.CancelledError:
                pass
        await self._flush_output_now()

        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

        # SIGHUP to every job, as a real hangup does. A program started with
        # `nohup` ignores it and survives, exactly as it would over ssh.
        for pgid in job_groups:
            _signal_group(pgid, signal.SIGHUP)
        proc = self._proc
        if proc is not None and proc.poll() is None:
            self._signal_group(signal.SIGHUP)
            deadline = time.monotonic() + _HANGUP_GRACE_SECONDS
            while proc.poll() is None and time.monotonic() < deadline:
                await asyncio.sleep(0.05)
            if proc.poll() is None:
                self._signal_group(signal.SIGKILL)
                await asyncio.to_thread(proc.wait)

        code = proc.returncode if proc is not None else None
        if self._on_closed is not None:
            self._on_closed(self.session_id)
        await self._send({
            "type": TERM_EXIT,
            "session_id": self.session_id,
            "code": code,
            "reason": reason,
        })

    @property
    def closing(self) -> bool:
        return self._closing

    # ------------------------------------------------------------ internals

    @staticmethod
    def _set_size(fd: int, cols: int, rows: int) -> None:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def _signal_group(self, sig: int) -> None:
        if self._proc is not None:
            _signal_group(self._proc.pid, sig)

    def _resume_reading(self) -> None:
        if self._fd is None or self._closing or self._reading:
            return
        asyncio.get_running_loop().add_reader(self._fd, self._on_readable)
        self._reading = True

    def _on_readable(self) -> None:
        try:
            data = os.read(self._fd, _READ_CHUNK)  # type: ignore[arg-type]
        except BlockingIOError:
            return
        except OSError:
            data = b""  # EIO: every slave fd is closed, i.e. the shell exited
        if not data:
            asyncio.get_running_loop().remove_reader(self._fd)  # type: ignore[arg-type]
            self._reading = False
            asyncio.ensure_future(self._on_shell_exit())
            return
        self.last_activity = time.monotonic()
        self._out.extend(data)
        self._unacked += len(data)
        self._out_ready.set()
        if self._unacked >= TERM_UNACKED_LIMIT:
            asyncio.get_running_loop().remove_reader(self._fd)  # type: ignore[arg-type]
            self._reading = False

    async def _on_shell_exit(self) -> None:
        # EOF means every slave fd is closed; the shell is exiting or gone.
        # Polled rather than `proc.wait` in a thread, so `close` never races a
        # second waiter for Popen's wait lock.
        proc = self._proc
        for _ in range(100):
            if proc is None or proc.poll() is not None:
                break
            await asyncio.sleep(0.02)
        await self.close("The shell exited.")

    def _flush_input(self) -> None:
        loop = asyncio.get_running_loop()
        if self._fd is None:
            return
        while self._in:
            try:
                n = os.write(self._fd, self._in)
            except BlockingIOError:
                # The program is not reading its input; wait for room rather
                # than spin or block the loop.
                loop.add_writer(self._fd, self._flush_input)
                return
            except OSError:
                self._in.clear()
                break
            del self._in[:n]
        loop.remove_writer(self._fd)

    async def _drain_output(self) -> None:
        while True:
            await self._out_ready.wait()
            self._out_ready.clear()
            # A few ms of coalescing turns a burst of tiny reads into one frame.
            await asyncio.sleep(0.01)
            await self._flush_output_now()

    async def _flush_output_now(self) -> None:
        while self._out:
            chunk = bytes(self._out[:_MAX_OUTPUT_FRAME])
            del self._out[:_MAX_OUTPUT_FRAME]
            await self._send({
                "type": TERM_OUTPUT,
                "session_id": self.session_id,
                "data_b64": base64.b64encode(chunk).decode("ascii"),
            })


class TerminalManager:
    """Every terminal session on one socket connection.

    Created per connection and closed with it: a dropped socket means nobody
    can see the shell any more, so it is hung up rather than left running
    unattended until someone reconnects.
    """

    def __init__(
        self,
        send: Send,
        on_switch_change: Optional[Callable[[], Awaitable[None]]] = None,
    ) -> None:
        self._send = send
        self._on_switch_change = on_switch_change
        self._sessions: dict[str, TerminalSession] = {}
        self._enabled = cfg.terminal_enabled()

    @property
    def session_count(self) -> int:
        return len(self._sessions)

    async def handle(self, frame: dict) -> None:
        """Route one server frame. Malformed frames are dropped, never raised."""
        kind = frame.get("type")
        try:
            session_id = validate_session_id(frame.get("session_id"))
        except ValueError:
            return
        if kind == TERM_OPEN:
            await self._open(session_id, frame)
            return
        session = self._sessions.get(session_id)
        if session is None:
            return
        if kind == TERM_INPUT:
            data = _decode(frame.get("data_b64"))
            if data is not None and len(data) <= TERM_MAX_INPUT_BYTES:
                session.write(data)
        elif kind == TERM_RESIZE:
            try:
                session.resize(*validate_size(frame.get("cols"), frame.get("rows")))
            except (ValueError, OSError):
                pass
        elif kind == TERM_ACK:
            try:
                session.ack(int(frame.get("bytes") or 0))
            except (TypeError, ValueError):
                pass
        elif kind == TERM_CLOSE:
            await self._end(session_id, "Session ended.")

    async def watchdog(self) -> None:
        """Enforce the switch and the idle/age limits, forever."""
        while True:
            await asyncio.sleep(WATCHDOG_SECONDS)
            await self.check()

    async def check(self) -> None:
        """One watchdog pass. Separate from the loop so tests can drive it."""
        enabled = cfg.terminal_enabled()
        if enabled != self._enabled:
            self._enabled = enabled
            if self._on_switch_change is not None:
                await self._on_switch_change()
        if not enabled:
            await self.close_all("The terminal was turned off on this computer.")
            return
        now = time.monotonic()
        for session_id, session in list(self._sessions.items()):
            if now - session.last_activity >= TERM_IDLE_SECONDS:
                await self._end(session_id, "Closed after 15 minutes of inactivity.")
            elif now - session.opened_at >= TERM_MAX_SECONDS:
                await self._end(session_id, "Closed after 8 hours.")

    async def close_all(self, reason: str) -> None:
        for session_id in list(self._sessions):
            await self._end(session_id, reason)

    # ------------------------------------------------------------ internals

    async def _open(self, session_id: str, frame: dict) -> None:
        if session_id in self._sessions:
            return
        detail = ""
        if not cfg.terminal_enabled():
            detail = OFF_MESSAGE
        elif len(self._sessions) >= TERM_MAX_SESSIONS:
            detail = (
                f"This computer already has {TERM_MAX_SESSIONS} terminal "
                f"sessions open. End one first."
            )
        if not detail:
            try:
                cols, rows = validate_size(frame.get("cols"), frame.get("rows"))
                session = TerminalSession(
                    session_id, cols, rows, self._send, on_closed=self._forget
                )
                session.start()
            except (ValueError, OSError) as e:
                detail = f"Could not start a shell: {e}"
            else:
                self._sessions[session_id] = session
                cfg.append_log(f"terminal session {session_id[:8]} opened")
        await self._send({
            "type": TERM_OPENED,
            "session_id": session_id,
            "ok": not detail,
            "detail": detail,
        })

    async def _end(self, session_id: str, reason: str) -> None:
        session = self._sessions.pop(session_id, None)
        if session is None:
            return
        await session.close(reason)
        cfg.append_log(f"terminal session {session_id[:8]} closed: {reason}")

    def _forget(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)


def _signal_group(pgid: int, sig: int) -> None:
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def _process_groups_on(tty: str) -> set[int]:
    """Process groups with ``tty`` as their controlling terminal, best-effort.

    ``ps`` is the one portable way to ask on both macOS and Linux. A failure
    returns nothing, and the shell's own group is still signalled.
    """
    name = tty.removeprefix("/dev/")
    if not name:
        return set()
    try:
        out = subprocess.run(
            ["ps", "-A", "-o", "pgid=,tty="],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return set()
    groups: set[int] = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == name and parts[0].isdigit():
            groups.add(int(parts[0]))
    groups.discard(os.getpgrp())
    return groups


def _decode(value: object) -> Optional[bytes]:
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
