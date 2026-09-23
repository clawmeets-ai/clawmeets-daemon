# SPDX-License-Identifier: MIT
"""
clawmeets_daemon/client.py

The connection loop: stay attached to the server, report what is running on this
machine, and carry out the five allowed commands.

## The one invariant

**This process stays connected when every agent on the machine is dead.** That
is the entire reason it exists. An agent's own socket cannot report "no agents
are running" — it is gone in that case, indistinguishable from the computer
being off — and that ambiguity is what let someone sit for two and a half days
believing the product was down. So nothing in this loop depends on any runner
being alive: it scans the filesystem, reports zero, and keeps the socket open.

## Reconnect policy

Exponential backoff with jitter, capped, forever — with two exceptions that must
not be retried:

- **4001, invalid token.** The credential is wrong. Retrying cannot fix it and a
  loop would look like a brute-force attempt against our own server.
- **4004, computer not connected.** The user disconnected this machine, or the
  record is gone. The credential is destroyed server-side, so this is final:
  the local config is deleted and the process exits. That is what makes
  "Disconnect this computer" take effect within seconds instead of at the next
  reconnect.

Anything else — a network drop, a server restart, a laptop lid — is transient
and retried.
"""
from __future__ import annotations

import asyncio
import json
import platform
import random
import socket
from typing import Optional

import websockets

from clawmeets_daemon import commands, config as cfg
from clawmeets_daemon.protocol import (
    CLOSE_BAD_TOKEN,
    CLOSE_NO_HOST,
    HOST_ACCEPTED,
    HOST_COMMAND,
    HOST_HEARTBEAT,
    HOST_HELLO,
    HOST_STATE,
)

# The machine re-reports its agent roster on this cadence even when nothing
# asked it to. 30 seconds is the resolution of "3 of 5 running" on the page: an
# agent that crashes shows up as "Stopped on its own" within one tick, without
# anything having to notice the crash.
SCAN_INTERVAL_SECONDS = 30

# Keep-alive, well inside any reasonable idle-connection timeout in front of the
# server. A heartbeat also restamps `last_seen_at`, which is what "not
# answering" vs "off" is decided on.
HEARTBEAT_INTERVAL_SECONDS = 20

_BACKOFF_START = 1.0
_BACKOFF_MAX = 60.0


class ComputerDisconnected(Exception):
    """The server said this machine is no longer connected (4004). Final."""


class BadCredential(Exception):
    """The server rejected our token (4001). Retrying cannot help."""


def describe_machine() -> dict:
    """What this computer says about itself, best-effort.

    Every field is decorative except the hostname, which seeds the default
    display name. Nothing here is trusted server-side and nothing here is
    required, so each lookup degrades to "" rather than failing the connection —
    a machine that cannot name its own OS still needs to be reachable.
    """
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = ""
    try:
        system = platform.system()
        release = platform.mac_ver()[0] if system == "Darwin" else platform.release()
        pretty = {"Darwin": "macOS", "Windows": "Windows", "Linux": "Linux"}.get(
            system, system
        )
    except Exception:
        pretty, release = "", ""
    return {
        "hostname": hostname,
        "platform": pretty,
        "os_version": release,
    }


def ws_url(server_url: str, host_id: str) -> str:
    """``https://host`` -> ``wss://host/ws/host/<id>`` (and http -> ws)."""
    base = server_url.rstrip("/")
    if base.startswith("https://"):
        base = "wss://" + base[len("https://"):]
    elif base.startswith("http://"):
        base = "ws://" + base[len("http://"):]
    return f"{base}/ws/host/{host_id}"


class ComputerClient:
    """One machine's connection to the server."""

    def __init__(self, config: cfg.ComputerConfig) -> None:
        self._config = config
        self._version = commands.daemon_version()

    # ----------------------------------------------------------------- frames

    def _state_frame(self, result: Optional[dict] = None) -> dict:
        frame = {
            "type": HOST_STATE,
            "agents": commands.snapshot(self._config.username),
            "daemon_version": self._version,
        }
        if result is not None:
            frame["result"] = result
        return frame

    def _hello_frame(self) -> dict:
        frame = {
            "type": HOST_HELLO,
            "token": self._config.token,
            "daemon_version": self._version,
            "agents": commands.snapshot(self._config.username),
        }
        frame.update(describe_machine())
        return frame

    # ------------------------------------------------------------------ loops

    async def run_forever(self) -> None:
        """Connect, and keep reconnecting until told not to.

        The backoff is reset on every SUCCESSFUL session rather than on every
        connect attempt, so a server that accepts the socket and then drops it
        immediately still backs off instead of hammering.
        """
        backoff = _BACKOFF_START
        while True:
            try:
                await self._session()
                backoff = _BACKOFF_START
            except ComputerDisconnected:
                cfg.append_log(
                    "This computer was disconnected from ClawMeets. "
                    "Forgetting its key and stopping.",
                    error=True,
                )
                cfg.clear_config()
                return
            except BadCredential:
                cfg.append_log(
                    "The server rejected this computer's key. Stopping rather "
                    "than retrying — run `clawmeets computer install --code …` "
                    "with a fresh code from the web app.",
                    error=True,
                )
                return
            except asyncio.CancelledError:
                raise
            except Exception as e:
                cfg.append_log(
                    f"connection lost ({type(e).__name__}: {e})", error=True
                )

            # Jitter so a fleet of machines coming back from the same network
            # outage does not arrive in one synchronized burst.
            delay = min(backoff, _BACKOFF_MAX) * (0.8 + 0.4 * random.random())
            # Stays on stderr with the failure it follows: a retry line read on
            # its own says nothing, and split across two files the story of an
            # outage would have to be reassembled by hand.
            cfg.append_log(f"retrying in {delay:.0f}s", error=True)
            await asyncio.sleep(delay)
            backoff = min(backoff * 2, _BACKOFF_MAX)

    async def _session(self) -> None:
        url = ws_url(self._config.server_url, self._config.host_id)
        cfg.append_log(f"connecting to {url}")
        async with websockets.connect(url, open_timeout=20, close_timeout=5) as ws:
            await ws.send(json.dumps(self._hello_frame()))
            cfg.append_log("connected; reporting what is running here")

            heartbeat = asyncio.create_task(self._heartbeat(ws))
            scanner = asyncio.create_task(self._periodic_scan(ws))
            try:
                await self._receive(ws)
            finally:
                for task in (heartbeat, scanner):
                    task.cancel()

    async def _heartbeat(self, ws) -> None:
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)
            await ws.send(json.dumps({"type": HOST_HEARTBEAT}))

    async def _periodic_scan(self, ws) -> None:
        """Re-report the roster on a timer.

        Unconditional, not change-detected. A diff would need state that
        survives a reconnect to be correct, and a 30-second full snapshot of
        at most a few dozen rows is cheaper than being wrong about which agents
        are up.
        """
        while True:
            await asyncio.sleep(SCAN_INTERVAL_SECONDS)
            await ws.send(json.dumps(self._state_frame()))

    async def _receive(self, ws) -> None:
        try:
            async for raw in ws:
                try:
                    frame = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(frame, dict):
                    continue
                kind = frame.get("type")
                if kind == HOST_ACCEPTED:
                    continue
                if kind == HOST_COMMAND:
                    await self._handle_command(ws, frame)
        except websockets.ConnectionClosed as e:
            if e.code == CLOSE_NO_HOST:
                raise ComputerDisconnected() from e
            if e.code == CLOSE_BAD_TOKEN:
                raise BadCredential() from e
            raise

    async def _handle_command(self, ws, frame: dict) -> None:
        """Run one command and report the outcome with a fresh roster.

        The command runs in a worker thread because it shells a subprocess that
        can take seconds (a start resolves a Python environment; a stop waits out
        the 5-second grace period). Running it inline would block the heartbeat
        and make the machine look unreachable exactly while it was doing what it
        was asked.

        The result rides on the ordinary state frame rather than a dedicated
        one, so the page's roster and the page's "what just happened" can never
        describe different moments.
        """
        action = str(frame.get("action") or "")
        agent = frame.get("agent")
        command_id = str(frame.get("command_id") or "")
        cfg.append_log(f"command: {action} {agent or ''}".rstrip())

        result = await asyncio.to_thread(
            commands.execute, action, agent, self._config.username
        )
        cfg.append_log(
            f"  -> {'ok' if result.ok else 'failed'}: {result.detail}",
            error=not result.ok,
        )

        await ws.send(json.dumps(self._state_frame({
            "command_id": command_id,
            "action": action,
            "agent": agent,
            "ok": result.ok,
            "detail": result.detail,
        })))

        # An `update` that landed needs this process replaced to take effect,
        # and that is done HERE rather than inside `execute` so the frame above
        # is actually on the wire first — `os.execv` discards anything still
        # buffered. The sleep is the flush window; losing the race would cost
        # the page one stale version string until the reconnect, not
        # correctness.
        if result.restart_required:
            await asyncio.sleep(0.3)
            commands.restart_process()


async def run(config: cfg.ComputerConfig) -> None:
    await ComputerClient(config).run_forever()
