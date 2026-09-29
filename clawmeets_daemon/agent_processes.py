# SPDX-License-Identifier: MIT
"""
clawmeets/utils/agent_processes.py

Agent discovery and process liveness on ONE machine — the single copy of the
logic that answers "which agents are set up here, and which of them are
actually running right now".

Extracted from ``cli_lifecycle.py`` because it now has two consumers that must
never disagree:

- ``clawmeets/cli_lifecycle.py`` — the ``clawmeets start / stop / status``
  commands a human runs in a terminal.
- ``clawmeets_daemon/`` — the connection daemon shipped as the separate
  ``clawmeets-daemon`` distribution, which reports the same facts to the
  server so the web UI can show them.

The daemon is a DIFFERENT distribution and cannot import ``clawmeets`` (that
is the whole point — it must install in seconds and start even when the
runner's heavy dependency stack is broken). ``scripts/build-daemon-package.sh``
therefore copies this file verbatim into the daemon wheel as
``clawmeets_daemon/agent_processes.py``, and ``clawmeets_daemon/discovery.py``
imports whichever copy exists. Two consequences, both load-bearing:

1. **Stdlib only.** No ``clawmeets.*`` import, no third-party import, not even
   ``typer``. Anything added here that is not in the standard library breaks
   the daemon's "tiny dependencies" guarantee. Reporting is the caller's job:
   the functions here return values and never print.
2. **Public names only.** ``discovery.py`` re-exports with ``import *``, which
   skips underscore-prefixed names. A helper that needs to be visible to the
   daemon must not start with ``_``.

``cli_lifecycle`` keeps its historical ``_``-prefixed aliases (``_pid_is_alive``
and friends) so existing imports and tests continue to resolve.
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"

# How long a graceful stop is given before escalating to a force kill. Kept
# here rather than at the call sites so a terminal `clawmeets stop` and a
# remote stop driven from the web behave identically.
STOP_GRACE_SECONDS = 5.0
_STOP_POLL_SECONDS = 0.25


def popen_detached_kwargs() -> dict:
    """Popen kwargs that detach the child so it outlives the parent shell.

    Windows needs DETACHED_PROCESS (no inherited console) plus
    CREATE_NEW_PROCESS_GROUP (so we can later deliver CTRL_BREAK_EVENT).
    POSIX just needs start_new_session=True.
    """
    if IS_WINDOWS:
        flags = (
            getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        )
        return {"creationflags": flags}
    return {"start_new_session": True}


def pid_is_alive(pid: int) -> bool:
    """Check whether a PID refers to a live process, without signaling it.

    On Windows, ``os.kill(pid, 0)`` actually terminates the target — so we
    must use a non-signaling query (tasklist) instead.
    """
    if IS_WINDOWS:
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH", "/FO", "CSV"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, check=False,
        )
        return f'"{pid}"' in (result.stdout or "")
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def signal_terminate(pid: int) -> None:
    """Send a graceful termination request. Silently no-ops if the target is gone.

    POSIX: SIGTERM. Windows: CTRL_BREAK_EVENT to the process group (works
    because agents are spawned with CREATE_NEW_PROCESS_GROUP).
    """
    try:
        if IS_WINDOWS:
            os.kill(pid, getattr(signal, "CTRL_BREAK_EVENT", 15))
        else:
            os.kill(pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        pass


def signal_kill(pid: int) -> None:
    """Force-kill a process. Silently no-ops on failure.

    POSIX: SIGKILL. Windows: ``taskkill /F`` — reliable even when graceful
    signaling didn't land.
    """
    try:
        if IS_WINDOWS:
            subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def read_pid(pid_file: Path) -> int | None:
    """The live PID recorded in ``pid_file``, or None.

    None covers all three "not running" shapes with one answer: no pidfile, an
    unreadable/garbage pidfile, and a pidfile naming a process that has since
    died (the stale-pidfile case). Callers that need to tell the last one apart
    check ``pid_file.exists()`` themselves.
    """
    if not pid_file.exists():
        return None
    try:
        pid = int(pid_file.read_text().strip())
        return pid if pid_is_alive(pid) else None
    except (ValueError, OSError):
        return None


def stop_pid(pid_file: Path) -> int | None:
    """Stop the process named by ``pid_file``. Returns the PID it stopped, else None.

    Graceful first (SIGTERM / CTRL_BREAK_EVENT), then a force kill after a
    :data:`STOP_GRACE_SECONDS` grace period (SIGKILL / taskkill /F). The
    pidfile is removed either way, including when it was already stale — that
    cleanup is why a caller should prefer this over signalling by hand.

    Returns None when there was nothing to stop, so a caller can distinguish
    "stopped it" from "it wasn't running" without a second probe. Never prints:
    the terminal CLI and the remote daemon word the outcome differently.
    """
    if not pid_file.exists():
        return None
    try:
        pid = int(pid_file.read_text().strip())
    except (ValueError, OSError):
        pid_file.unlink(missing_ok=True)
        return None

    if not pid_is_alive(pid):
        pid_file.unlink(missing_ok=True)
        return None

    signal_terminate(pid)
    for _ in range(int(STOP_GRACE_SECONDS / _STOP_POLL_SECONDS)):
        time.sleep(_STOP_POLL_SECONDS)
        if not pid_is_alive(pid):
            break
    else:
        signal_kill(pid)

    pid_file.unlink(missing_ok=True)
    return pid


def agents_dir(data_dir: Path) -> Path:
    """``{data_dir}/agents`` — where every locally registered agent lives."""
    return Path(data_dir).expanduser() / "agents"


def prefixed_name(username: str, agent_name: str) -> str:
    """``budget-analyst`` -> ``alice-budget-analyst`` (idempotent)."""
    prefix = f"{username}-"
    return agent_name if agent_name.startswith(prefix) else f"{prefix}{agent_name}"


def find_agent_dir(agents_root: Path, prefixed: str) -> Path | None:
    """Find an agent's directory matching ``{prefixed}-{id}/``.

    Requires ``credential.json`` so a half-registered directory is invisible,
    the same rule :func:`list_owned_agent_short_names` applies.
    """
    if not agents_root.exists():
        return None
    for d in agents_root.iterdir():
        if d.is_dir() and d.name.startswith(f"{prefixed}-"):
            if (d / "credential.json").exists():
                return d
    return None


def list_owned_agent_short_names(agents_root: Path, username: str) -> list[str]:
    """Return owned agents' short names by globbing the filesystem.

    Pattern: ``{agents_root}/{username}-{short}-{id}/`` with ``credential.json``
    present. Skips ``DELETED-*`` (renamed by self-destruct) and any dir
    without a ``credential.json`` (half-registered). The trailing ``-{id}``
    is stripped off the right.

    Deliberately a filesystem glob rather than a read of ``settings.json``:
    the directory is what a process can actually be started from, so an agent
    that exists on disk is reported even if some config file forgot it.
    """
    if not agents_root.exists():
        return []
    prefix = f"{username}-"
    names: list[str] = []
    for entry in sorted(agents_root.iterdir()):
        if not entry.is_dir() or entry.name.startswith("DELETED-"):
            continue
        if not entry.name.startswith(prefix):
            continue
        if not (entry / "credential.json").exists():
            continue
        rest = entry.name[len(prefix):]
        short = rest.rsplit("-", 1)[0] if "-" in rest else rest
        if short:
            names.append(short)
    return names


def agent_pid_file(agent_dir: Path) -> Path:
    """The pidfile ``clawmeets start`` writes for one agent."""
    return Path(agent_dir) / "agent.pid"


# The per-agent env-var store (``clawmeets/utils/env_store.py`` reads and
# writes it; it imports these so there is one definition of the file and the
# key rule). Here because the machine reports key NAMES from this module, and
# this module is the one copied into the daemon wheel.
ENV_STORE_FILENAME = "env.json"
ENV_KEY_PATTERN = r"^[A-Z_][A-Z0-9_]*$"
ENV_RESERVED_PREFIX = "CLAWMEETS_"


def env_key_names(agent_dir: Path) -> list[str]:
    """Sorted key names in an agent's env-var store. Never the values.

    Missing, unreadable or malformed store -> ``[]``. Keys the runner would
    ignore (illegal names, the reserved ``CLAWMEETS_`` prefix) are left out, so
    the list is exactly the variables a skill will actually see.
    """
    try:
        data = json.loads((Path(agent_dir) / ENV_STORE_FILENAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    pattern = re.compile(ENV_KEY_PATTERN)
    return sorted(
        k for k in data
        if isinstance(k, str) and pattern.match(k) and not k.startswith(ENV_RESERVED_PREFIX)
    )


def scan_agents(agents_root: Path, username: str) -> list[dict]:
    """One dict per locally registered agent, with its OBSERVED run state.

    ``[{"short_name", "name", "dir", "pid", "state", "env_keys"}, …]`` sorted
    by ``short_name``, where ``env_keys`` is :func:`env_key_names` (names only)
    and ``state`` is one of:

    - ``"running"``   — the pidfile names a live process.
    - ``"crashed"``   — a pidfile exists but the process is gone. The machine
      started this agent and it exited without being asked to; the web UI
      shows it as "Stopped on its own" so the user can tell it apart from a
      stop they performed.
    - ``"stopped"``   — no pidfile. Never started, or stopped cleanly.

    Observed, never remembered: the state is read off the filesystem on every
    call, so an agent that died without saying goodbye reads as ``crashed``
    within one scan rather than lingering as "running" until something notices.
    """
    rows: list[dict] = []
    for short in list_owned_agent_short_names(agents_root, username):
        full = prefixed_name(username, short)
        agent_dir = find_agent_dir(agents_root, full)
        if agent_dir is None:
            continue
        pid_file = agent_pid_file(agent_dir)
        pid = read_pid(pid_file)
        if pid is not None:
            state = "running"
        elif pid_file.exists():
            state = "crashed"
        else:
            state = "stopped"
        rows.append({
            "short_name": short,
            "name": full,
            "dir": str(agent_dir),
            "pid": pid,
            "state": state,
            "env_keys": env_key_names(agent_dir),
        })
    return rows
