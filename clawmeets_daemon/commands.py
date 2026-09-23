# SPDX-License-Identifier: MIT
"""
clawmeets_daemon/commands.py

The five things this machine will do when asked, and nothing else.

Every one of them is performed by shelling the CANONICAL ``clawmeets``
lifecycle command, never by hand-rolling ``Popen`` or ``kill``. That is not
tidiness — the CLI already owns detached start (``start_new_session=True`` /
``DETACHED_PROCESS``), the graceful SIGTERM→5s→SIGKILL escalation, stale-pidfile
cleanup, and the refusal to stop the runner that is asking. Re-implementing any
of it here would mean a start from the web behaved differently from a start in a
terminal, and the difference would only show up in the failure cases.

So the split is: the CLI does the work, this module decides whether the work is
allowed, resolves the binary, and reports the result.

``restart`` is stop-then-start as two explicit steps, because there is no
``clawmeets restart`` verb and inventing one here would put a second
implementation of stop-then-start in the tree.

``update`` is the one action that is about the daemon rather than the agents: it
upgrades this package and re-executes, so a machine can be kept current without
the user opening a terminal. It is on the allowlist precisely because the
alternative — a stale daemon that can never be fixed remotely — is the state
this whole feature exists to escape.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from clawmeets_daemon import config as cfg
from clawmeets_daemon.discovery import agents_dir, scan_agents
from clawmeets_daemon.protocol import HostCommandRejected, validate_host_action

# A start can involve resolving a Python environment and importing the runner's
# dependency stack; a stop waits out the 5-second grace period. 120s is
# comfortably above both and still bounded, so a wedged subprocess cannot pin
# the daemon's command loop forever.
COMMAND_TIMEOUT_SECONDS = 120

# `clawmeets` is not importable from here (different distribution), so it is
# resolved as an executable. The env override exists for the case that actually
# happens: a runner installed with `uv tool install` or `pipx` lives outside the
# PATH of a process started from a login shell the user never opened.
CLAWMEETS_BIN_ENV = "CLAWMEETS_BIN"


@dataclass
class CommandResult:
    ok: bool
    detail: str
    # Set only by `update`. The upgrade has landed on disk but this process is
    # still running the old modules, so somebody has to re-exec — and it must
    # not be this function, which is called from a worker thread and whose
    # result still has to reach the server. The caller reports first, then calls
    # `restart_process`.
    restart_required: bool = False


def clawmeets_bin() -> Optional[str]:
    """Absolute path of the ``clawmeets`` executable, or None.

    Checked on every command rather than cached at startup: a user who fixes a
    broken runner install should not have to restart the daemon for the buttons
    on their computer's page to start working again.
    """
    override = os.environ.get(CLAWMEETS_BIN_ENV, "").strip()
    if override:
        return override if Path(override).exists() else None
    found = shutil.which("clawmeets")
    if found:
        return found
    # uv tool / pipx default install locations, for a daemon started outside a
    # login shell (launchd, a bare `nohup`, a fresh terminal on Windows).
    for candidate in (
        Path.home() / ".local" / "bin" / "clawmeets",
        Path.home() / ".local" / "bin" / "clawmeets.exe",
    ):
        if candidate.exists():
            return str(candidate)
    return None


def snapshot(username: str) -> list[dict]:
    """What is running on this machine, observed now.

    The full roster every time, not a delta: the server replaces its copy
    wholesale, so an agent that has been deleted locally disappears from the
    page instead of lingering because no event mentioned it.
    """
    return scan_agents(agents_dir(cfg.data_dir()), username)


def _lifecycle_argv(binary: str, verb: str, agent: str, username: str) -> list[str]:
    """``clawmeets <verb> --agent X --user alice``.

    ``--user`` is not optional dressing. Without it the runner falls back to
    whichever account is selected on the machine (``config/current_user``), which
    is NOT necessarily the account this daemon was paired to — one machine can
    host several. The failure it prevents is the bad kind: if the other account
    happens to have an agent of the same short name, a Start pressed on one
    account's computer page would start a DIFFERENT account's agent, silently.
    Pinning the account makes the command mean the same thing as the page.
    """
    argv = [binary, verb, "--agent", agent]
    if username:
        argv += ["--user", username]
    return argv


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
        check=False,
    )


def _tail(output: str, limit: int = 300) -> str:
    """The last of a subprocess's output, for the one-line detail a UI shows.

    The tail rather than the head: the interesting part of a failed start is the
    exception at the end, not the banner at the beginning.
    """
    cleaned = " ".join((output or "").split())
    return cleaned[-limit:] if len(cleaned) > limit else cleaned


def execute(action: str, agent: Optional[str], username: str) -> CommandResult:
    """Run one allowlisted action. Never raises.

    The allowlist is checked HERE, on the machine, even though the server
    already refused anything unlisted before sending. That redundancy is the
    point: this is the fence that holds if the server is wrong, compromised, or
    simply running newer rules than this machine agreed to. A rejection is
    reported as an ordinary failed result so the user sees the refusal rather
    than a silent no-op.

    Never raises, because the caller is a websocket loop: an exception escaping
    into it would drop the connection, and a dropped connection is exactly the
    state that makes a user believe the product is down.
    """
    try:
        cleaned, agent_name = validate_host_action(action, agent)
    except HostCommandRejected as e:
        return CommandResult(False, f"Refused: {e}")

    binary = clawmeets_bin()
    if cleaned != "update" and binary is None:
        return CommandResult(
            False,
            "Could not find the clawmeets command on this computer, so nothing "
            "was run. Reinstall it and try again.",
        )

    try:
        if cleaned == "status":
            rows = snapshot(username)
            running = sum(1 for r in rows if r["state"] == "running")
            return CommandResult(True, f"{running} of {len(rows)} running")

        if cleaned == "start":
            proc = _run(_lifecycle_argv(binary, "start", agent_name, username))
            return _lifecycle_result(proc, f"Started {agent_name}")

        if cleaned == "stop":
            proc = _run(_lifecycle_argv(binary, "stop", agent_name, username))
            return _lifecycle_result(proc, f"Stopped {agent_name}")

        if cleaned == "restart":
            # Two explicit steps, in this order, matching what a person would do
            # in a terminal. A failed stop still attempts the start: the common
            # cause of "stop failed" is that the agent was already down, and
            # refusing to start it would turn a restart into a no-op.
            stopped = _run(_lifecycle_argv(binary, "stop", agent_name, username))
            started = _run(_lifecycle_argv(binary, "start", agent_name, username))
            if started.returncode != 0:
                return CommandResult(
                    False,
                    f"Stopped {agent_name} but could not start it again: "
                    f"{_tail(started.stdout)}",
                )
            return CommandResult(
                True,
                f"Restarted {agent_name}"
                + ("" if stopped.returncode == 0 else " (it was already stopped)"),
            )

        if cleaned == "update":
            return update_self()

    except subprocess.TimeoutExpired:
        return CommandResult(
            False,
            f"{cleaned} took longer than {COMMAND_TIMEOUT_SECONDS} seconds and "
            f"was given up on.",
        )
    except OSError as e:
        return CommandResult(False, f"Could not run {cleaned}: {e}")

    # Unreachable while `validate_host_action` and the branches above agree.
    return CommandResult(False, f"{cleaned} is not implemented on this computer")


def _lifecycle_result(
    proc: subprocess.CompletedProcess, success: str
) -> CommandResult:
    """Read the CLI's exit status, and say what it printed when it failed.

    The exit code is the verdict, not the text: `clawmeets start` prints
    "already running" and exits 0, which is a success from the user's point of
    view ("is it running?" — yes).
    """
    if proc.returncode == 0:
        return CommandResult(True, success)
    return CommandResult(False, _tail(proc.stdout) or f"exit code {proc.returncode}")


def daemon_version() -> str:
    """This package's version, or "unknown".

    "unknown" is an honest answer and appears on the machine's page as such —
    better than a guess, since the version is what tells a user whether an
    update actually landed.
    """
    try:
        from importlib.metadata import version
        return version("clawmeets-daemon")
    except Exception:
        return "unknown"


def update_self() -> CommandResult:
    """Upgrade this package. Does NOT restart — see ``restart_process``.

    Tries ``uv tool upgrade`` first and falls back to ``pip install --upgrade``,
    matching how the runner is actually installed in the wild. Both name THIS
    distribution explicitly — there is no code path here that can install
    anything else, which is what keeps "Install or change anything else" an
    honest never.

    The split from the restart is deliberate. This runs in a worker thread and
    its result still has to reach the server; replacing the process image here
    would discard the frame that tells the user the update landed. So it reports
    ``restart_required`` and the connection loop re-execs after the frame is on
    the wire.
    """
    before = daemon_version()
    attempts: list[list[str]] = []
    uv = shutil.which("uv")
    if uv:
        attempts.append([uv, "tool", "upgrade", "clawmeets-daemon"])
    attempts.append(
        [sys.executable, "-m", "pip", "install", "--upgrade", "clawmeets-daemon"]
    )

    last = ""
    for argv in attempts:
        try:
            proc = _run(argv)
        except (OSError, subprocess.TimeoutExpired) as e:
            last = str(e)
            continue
        if proc.returncode == 0:
            return CommandResult(
                True,
                f"Updated the connection software (was {before}); restarting it now",
                restart_required=True,
            )
        last = _tail(proc.stdout)

    return CommandResult(False, f"Could not update: {last or 'no installer available'}")


def restart_process() -> None:
    """Replace this process with a fresh one running the upgraded code.

    A running Python process keeps the modules it already imported, so upgrading
    the files under it changes nothing until it restarts. ``os.execv`` replaces
    the image in place and KEEPS THE PID, which is why nothing has to coordinate
    a handover: the pidfile written at start is still correct afterwards, and
    ``clawmeets computer stop`` still finds the right process.

    The argv is rebuilt as ``python -m clawmeets_daemon.cli run --user <account>``
    rather than reused from ``sys.argv``. Under ``-m``, ``sys.argv[0]`` is the
    path of ``cli.py`` itself, which is not executable — exec'ing it would fail
    on every machine. This form is also exactly what ``_start_detached`` spawns,
    so a re-exec'd process is indistinguishable from a freshly started one.

    The account is carried across explicitly. A machine can host several, and a
    process that re-derived its identity after an update could come back as a
    different account than the one whose page triggered the update.

    On failure it logs and returns rather than raising. The daemon carries on
    running the old code — degraded but connected — which is strictly better
    than a machine that disappears from its owner's page because an upgrade
    could not re-exec.
    """
    cfg.append_log("update: re-executing to pick up the new version")
    try:
        argv = [sys.executable, "-m", "clawmeets_daemon.cli", "run"]
        account = cfg.active_account()
        if account:
            argv += ["--user", account]
        os.execv(sys.executable, argv)
    except OSError as e:
        cfg.append_log(
            f"update: could not restart automatically ({e}); still running the "
            f"previous version. Run `clawmeets computer start` here to finish.",
            error=True,
        )
