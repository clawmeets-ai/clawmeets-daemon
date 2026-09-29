# SPDX-License-Identifier: MIT
"""
clawmeets_daemon/commands.py

The seven things this machine will do when asked, and nothing else.

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

``env_set`` / ``env_unset`` shell ``clawmeets env set|unset`` the same way, so
a key added from the web lands in exactly the store a terminal ``env set``
writes — the value reaches that command on stdin, never argv. Only key names
ever come back (on the roster's ``env_keys``); nothing here reads a value.

``update`` is the one action that is about the software rather than the agents:
it upgrades the runner (``clawmeets``) and this package (``clawmeets-daemon``),
each with whichever installer owns it, restarts the agents that were running and
re-executes, so a machine can be kept current without the user opening a
terminal. It is on the allowlist precisely because the
alternative — a stale daemon that can never be fixed remotely — is the state
this whole feature exists to escape.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from clawmeets_daemon import config as cfg
from clawmeets_daemon import upgrade
from clawmeets_daemon.discovery import agents_dir, scan_agents
from clawmeets_daemon.protocol import (
    HostCommandRejected,
    validate_env_change,
    validate_host_action,
)

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


# How often the machine re-asks which model CLIs are installed and signed in.
# They change when a human installs a CLI or completes a browser sign-in —
# minutes apart at the fastest — so a check every five minutes is prompt enough
# while keeping five `--version` subprocesses off the 30-second roster scan.
MODEL_CLI_RECHECK_SECONDS = 300
MODEL_CLIS_NAME = "model_clis.json"


def probe_model_clis() -> Optional[list[dict]]:
    """Which model CLIs are installed and signed in, as the server wants them.

    Shells ``clawmeets doctor --model-clis`` rather than probing the binaries
    here. That indirection is the point: ``clawmeets/doctor.py`` owns the table
    of which CLIs exist, what each one's binary is called and where it leaves its
    credential, and a second copy in this distribution would drift — the web
    checklist would then claim a model CLI was missing while `clawmeets doctor`
    in the same terminal said it was fine. One definition, asked over a
    subprocess boundary.

    Returns None when the runner is absent or the probe fails: this machine
    cannot tell, and saying ``[]`` would tell the server that nothing is
    installed — the checklist row would turn into a warning on a machine where
    everything works. Blocking (it shells a subprocess), so async callers run it
    in a worker thread.
    """
    binary = clawmeets_bin()
    if binary is None:
        return None
    try:
        result = subprocess.run(
            [binary, "doctor", "--model-clis"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        # An older runner with no `--model-clis` flag lands here. Not an error
        # worth logging on a timer: the server simply has no observation to show,
        # which is exactly what an un-upgraded machine should produce.
        return None
    try:
        parsed = json.loads(result.stdout or "[]")
    except ValueError:
        return None
    return parsed if isinstance(parsed, list) else None


def saved_model_clis() -> Optional[dict]:
    """The last successful check, as ``{"checked_at": iso, "clis": [...]}``.

    Kept on disk next to the account's credential so a restarted connection
    reports what it already knows instead of nothing, and so a check that
    cannot run right now (a runner mid-upgrade, a login item started with a
    bare PATH) falls back to the last real answer rather than a wrong one.
    """
    try:
        data = json.loads((cfg.computer_dir() / MODEL_CLIS_NAME).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("clis"), list):
        return None
    return {"checked_at": str(data.get("checked_at") or ""), "clis": data["clis"]}


def check_model_clis() -> Optional[dict]:
    """Probe now; save and return a fresh result, else the last saved one.

    The saved result keeps its own ``checked_at`` when it is the fallback, so the
    page's "last checked" says honestly how old the answer is.
    """
    clis = probe_model_clis()
    if clis is None:
        return saved_model_clis()
    report = {"checked_at": datetime.now(timezone.utc).isoformat(), "clis": clis}
    path = cfg.computer_dir() / MODEL_CLIS_NAME
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(report))
        os.replace(tmp, path)
    except OSError:
        pass  # Reporting still works; only the restart fallback is lost.
    return report


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


def _run(argv: list[str], stdin: Optional[str] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
        check=False,
    )


def _env_argv(binary: str, verb: str, key: str, agent_dir: str) -> list[str]:
    """``clawmeets env <verb> KEY --agent <dir name> --data-dir <data dir>``.

    The agent is named by its exact directory name from this account's own
    roster, not by short name: ``clawmeets env`` resolves ``--agent`` by prefix,
    so ``backend`` could also match ``backend-v2``, and a short name alone could
    match another account's agent. The directory is the one the page showed.

    ``set`` never gets the value on its argument list — ``--value-stdin`` reads
    it from stdin, so it is not visible to other users in ``ps``.
    """
    path = Path(agent_dir)
    argv = [binary, "env", verb, key, "--agent", path.name, "--data-dir", str(path.parent.parent)]
    if verb == "set":
        argv.append("--value-stdin")
    return argv


def _env_change(
    binary: str, action: str, agent: str, key: str, value: Optional[str], username: str
) -> CommandResult:
    """Add/replace or remove one key in one agent's env-var store.

    Every detail string names the key and never the value: it goes to the log
    and back to the page. The CLI's own output is key-only too (``env set``
    prints ``{"status": "ok", "key": …}``), so its tail is safe to relay.
    """
    row = next((r for r in snapshot(username) if r["short_name"] == agent), None)
    if row is None:
        return CommandResult(False, f"{agent} is not set up on this computer")
    if action == "env_set":
        proc = _run(_env_argv(binary, "set", key, row["dir"]), stdin=value)
        return _lifecycle_result(proc, f"Set {key} on {agent}")
    proc = _run(_env_argv(binary, "unset", key, row["dir"]))
    return _lifecycle_result(proc, f"Removed {key} from {agent}")


def _tail(output: str, limit: int = 300) -> str:
    """The last of a subprocess's output, for the one-line detail a UI shows.

    The tail rather than the head: the interesting part of a failed start is the
    exception at the end, not the banner at the beginning.
    """
    cleaned = " ".join((output or "").split())
    return cleaned[-limit:] if len(cleaned) > limit else cleaned


def execute(
    action: str,
    agent: Optional[str],
    username: str,
    key: Optional[str] = None,
    value: Optional[str] = None,
) -> CommandResult:
    """Run one allowlisted action. Never raises.

    ``key`` / ``value`` are read only by the env actions; ``value`` is a secret
    and must not reach a log line or a result.

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
        env_key, env_value = validate_env_change(cleaned, key, value)
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
            return update_self(username)

        if cleaned in ("env_set", "env_unset"):
            return _env_change(
                binary, cleaned, agent_name, env_key, env_value, username
            )

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


def runner_version() -> Optional[str]:
    """The installed ``clawmeets`` runner's version, or None if it cannot be told.

    Asked of the runner's own interpreter, not of this process: the two are
    usually separate environments (the one-line installer gives each its own
    uv tool env), so ``importlib.metadata`` here would answer about the wrong
    copy — or about none. Blocking; async callers use a worker thread.
    """
    binary = clawmeets_bin()
    if binary is None:
        return None
    python = upgrade.python_for_script(binary)
    if python is not None:
        found = upgrade.installed_version(python, upgrade.RUNNER_DIST)
        if found:
            return found
    # A console script with no readable interpreter (a Windows launcher): the
    # CLI can say it itself, at the cost of importing it.
    try:
        proc = _run([binary, "--version"])
    except (OSError, subprocess.SubprocessError):
        return None
    words = (proc.stdout or "").split()
    return words[-1] if proc.returncode == 0 and words else None


def _restart_running_agents(username: str) -> tuple[int, list[str]]:
    """Stop-then-start every agent of this account that is running now.

    An upgrade on disk changes nothing for a runner that already imported the
    old code, so without this the page would report the new version while every
    agent kept running the old one. Only agents that are RUNNING are touched —
    a stopped agent picks up the new code whenever it is next started, and
    starting it here would override the user's decision to stop it.
    """
    binary = clawmeets_bin()
    if binary is None:
        return 0, []
    restarted, failed = 0, []
    for row in snapshot(username):
        if row.get("state") != "running":
            continue
        name = row["short_name"]
        try:
            _run(_lifecycle_argv(binary, "stop", name, username))
            started = _run(_lifecycle_argv(binary, "start", name, username))
        except (OSError, subprocess.SubprocessError):
            failed.append(name)
            continue
        if started.returncode == 0:
            restarted += 1
        else:
            failed.append(name)
    return restarted, failed


def _describe(label: str, outcome: "upgrade.UpgradeOutcome") -> str:
    if not outcome.ok:
        return f"{label}: could not update ({outcome.detail})"
    if outcome.changed:
        return f"{label} {outcome.before or '?'} → {outcome.after} (via {outcome.installer})"
    current = outcome.after or outcome.before
    return f"{label} {current} is already the latest" if current else f"{label} is up to date"


def update_self(username: str = "") -> CommandResult:
    """Upgrade the runner (``clawmeets``) and this package (``clawmeets-daemon``).

    Each is upgraded in ITS OWN environment with the installer that owns it —
    uv tool, pipx, pip or ``uv pip`` — found by :mod:`clawmeets_daemon.upgrade`.
    They are independent: a runner that fails to upgrade does not stop the
    daemon from upgrading, and vice versa, and the detail says which is which.
    Both names are fixed there; no code path here can install anything else,
    which is what keeps "Install or change anything else" an honest never.

    When the runner actually moved, the agents of ``username`` that were
    running are restarted so they run the new code. When the daemon moved, it
    reports ``restart_required`` and the connection loop re-execs after the
    result frame is on the wire — replacing the process image here, in a worker
    thread, would discard the frame that tells the user the update landed.
    """
    parts: list[str] = []
    ok = True

    binary = clawmeets_bin()
    if binary is None:
        parts.append("clawmeets: not found on this computer, so it was not updated")
        ok = False
    else:
        runner = upgrade.upgrade(upgrade.RUNNER_DIST, upgrade.python_for_script(binary))
        ok = ok and runner.ok
        parts.append(_describe("clawmeets", runner))
        if runner.ok and runner.after != runner.before:
            restarted, failed = _restart_running_agents(username)
            if restarted:
                parts.append(
                    f"restarted {restarted} running agent{'s' if restarted != 1 else ''}"
                )
            if failed:
                ok = False
                parts.append(f"could not restart {', '.join(failed)}")

    daemon = upgrade.upgrade(upgrade.DAEMON_DIST, upgrade.daemon_python())
    ok = ok and daemon.ok
    parts.append(_describe("connection software", daemon))

    return CommandResult(
        ok,
        "; ".join(parts),
        # An unknown "after" (the version could not be read back) still
        # restarts: a needless re-exec costs a second, a missed one leaves the
        # old code running indefinitely.
        restart_required=daemon.ok and (daemon.changed or not daemon.after),
    )


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
