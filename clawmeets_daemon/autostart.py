# SPDX-License-Identifier: MIT
"""
clawmeets_daemon/autostart.py

Start this computer's connection again at login, without being asked.

## Why this exists

Before this module the connection was detached but unsupervised: it survived the
terminal that started it and did not survive a reboot. That is the wrong
asymmetry, because almost nobody stops their agents on purpose — they reboot,
close the lid for the weekend, or take a system update overnight. Every one of
those looked identical to "ClawMeets is broken": the web app said the computer
was off, which was true, and offered no reason to think a single command would
fix it. Registering with the OS login manager is the one change that makes most
of those reports disappear.

## One account, one unit

A unit is per clawmeets account, named after it, exactly as the credential,
pidfile and logs are. Two accounts on one machine get two units that start two
processes; disabling one leaves the other running. Anything shared would make
"stop starting my work account at login" impossible to express.

## Deliberately not a supervisor

launchd's ``KeepAlive`` and systemd's ``Restart=`` are both OFF. They would
fight ``clawmeets computer stop``: that command signals the process directly,
which both managers read as an unexpected death and answer by starting it again
within seconds. A user who stops their computer's connection and watches it come
back has been told the product ignores them, and that is a worse failure than
the crash-recovery this gives up. The connection already reconnects across
network failures on its own (``client.run_forever``), so what is lost is
recovery from a hard crash of the process itself — which the next login fixes
anyway.

## What is written where

- macOS  — ``~/Library/LaunchAgents/ai.clawmeets.computer.<account>.plist``,
  loaded with ``launchctl bootstrap gui/<uid>`` (falling back to ``load -w`` on
  older systems).
- Linux  — ``~/.config/systemd/user/clawmeets-computer-<account>.service``,
  enabled with ``systemctl --user enable``. ``loginctl enable-linger`` is
  attempted too, because without it the unit stops at logout, which on a
  headless box means it never runs at all.
- Windows — unsupported here and reported as such rather than half-done. The
  honest answer ("run ``clawmeets computer start``") beats a Task Scheduler
  entry this module could not reliably remove again.

Every function reports rather than raises: a failure to register autostart must
never fail the install that asked for it. The connection still works; it just
will not come back by itself, and the caller gets a sentence saying so.
"""
from __future__ import annotations

import os
import plistlib
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from clawmeets_daemon import config as cfg

# The reverse-DNS label launchd knows this by, and the prefix of the systemd
# unit name. Public because `status` output and the uninstall path both key off
# it, and because a user grepping their LaunchAgents folder should find one
# obvious name.
LABEL_PREFIX = "ai.clawmeets.computer"
SYSTEMD_PREFIX = "clawmeets-computer"

# How long any launchctl / systemctl call may take. These are local IPC calls
# that either answer at once or are wedged; waiting longer helps nobody.
_CMD_TIMEOUT_SECONDS = 20


@dataclass(frozen=True)
class AutostartState:
    """Whether this account's connection is registered to start at login.

    ``supported`` false means this platform has no mechanism we manage, and
    ``installed`` is then meaningless — callers must check ``supported`` first
    rather than reading ``installed=False`` as "the user should enable it".
    """

    supported: bool
    installed: bool
    detail: str
    # The plist / unit file, when there is one. Shown so a user can read or
    # delete by hand what we wrote on their machine.
    path: str = ""


def _account(username: str = "") -> str:
    """Select the account these paths belong to, and return its name."""
    if username:
        cfg.use_account(username)
    return cfg.active_account()


def _run(argv: list[str]) -> tuple[bool, str]:
    """Run a manager command. ``(ok, output)``; never raises.

    Both managers are chatty on stderr and silent on success, so the message is
    whichever stream spoke — that is what a user needs to see when enabling
    autostart did not take.
    """
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=_CMD_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return False, f"{argv[0]} is not available on this computer"
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    message = (result.stderr or result.stdout or "").strip()
    return result.returncode == 0, message


def _run_argv(username: str) -> list[str]:
    """The command the OS should run at login, as an absolute argv.

    ``sys.executable -m clawmeets_daemon.cli run`` rather than the
    ``clawmeets-computer`` console script: launchd and systemd start with a
    minimal PATH that does not include ``~/.local/bin``, where uv puts the
    script, so resolving the interpreter now is what makes the unit work at
    login rather than only in the shell that created it.

    The account is spelled out for the same reason ``_start_detached`` spells it
    out — the logged-in account can change under a unit that runs for months,
    and a connection that silently began reporting a different account's agents
    would be the worst available bug.

    ``-P`` for the same reason ``cli_daemon._resolve`` passes it: ``python -m``
    puts the working directory on ``sys.path``, and both units below run from
    ``$HOME``. A file named ``typing.py`` or ``httpx.py`` sitting in someone's
    home directory would otherwise shadow the real module and the connection
    would die in an import traceback at every login — the least debuggable
    possible version of "my agents stopped coming back".
    """
    return [
        sys.executable, "-P", "-m", "clawmeets_daemon.cli",
        "run", "--user", username,
    ]


def _login_path() -> str:
    """The PATH the login-started process should see: the installing shell's.

    launchd and systemd start units with a bare system PATH
    (``/usr/bin:/bin:/usr/sbin:/sbin``). ``_run_argv`` pins the interpreter so
    the connection itself starts, but everything IT shells — ``clawmeets`` for
    agent start/stop and the model-CLI check, and through that ``claude`` /
    ``codex`` in ``~/.local/bin`` or ``/opt/homebrew/bin`` — is found by PATH.
    On a bare PATH the model check finds nothing and the page tells a working
    user that no model is available. Recording the PATH of the shell that ran
    ``computer install`` is what makes the login process see what the user sees.
    Re-running install (or ``autostart enable``) refreshes it.
    """
    entries: list[str] = []
    for entry in (
        str(Path(sys.executable).parent),
        str(Path.home() / ".local" / "bin"),
        *os.environ.get("PATH", "").split(os.pathsep),
    ):
        if entry and entry not in entries:
            entries.append(entry)
    return os.pathsep.join(entries)


# ---------------------------------------------------------------------------
# macOS — launchd
# ---------------------------------------------------------------------------


def _launchd_label(account: str) -> str:
    return f"{LABEL_PREFIX}.{account}" if account else LABEL_PREFIX


def _launchd_path(account: str) -> Path:
    return (
        Path.home() / "Library" / "LaunchAgents" / f"{_launchd_label(account)}.plist"
    )


def _launchd_plist(account: str) -> dict:
    """The agent definition.

    ``RunAtLoad`` is the whole feature. ``KeepAlive`` is absent on purpose — see
    the module docstring on why supervising would break ``computer stop``.

    The two log paths are the SAME files the foreground and detached paths write
    (``cfg.log_paths``), so "why did my computer stop last night" is one
    ``clawmeets computer logs`` regardless of who started it.
    """
    stdout_log, stderr_log = cfg.log_paths()
    return {
        "Label": _launchd_label(account),
        "ProgramArguments": _run_argv(account),
        "EnvironmentVariables": {"PATH": _login_path()},
        "RunAtLoad": True,
        "ProcessType": "Background",
        "StandardOutPath": str(stdout_log),
        "StandardErrorPath": str(stderr_log),
        "WorkingDirectory": str(Path.home()),
    }


def _launchctl_domain() -> str:
    return f"gui/{os.getuid()}"


def _launchd_enable(account: str) -> AutostartState:
    path = _launchd_path(account)
    path.parent.mkdir(parents=True, exist_ok=True)
    stdout_log, _ = cfg.log_paths()
    stdout_log.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        plistlib.dump(_launchd_plist(account), fh)

    # Replace rather than add: re-enabling after an upgrade must pick up the new
    # interpreter path, and `bootstrap` refuses a label that is already loaded.
    _run(["launchctl", "bootout", f"{_launchctl_domain()}/{_launchd_label(account)}"])
    ok, message = _run(["launchctl", "bootstrap", _launchctl_domain(), str(path)])
    if not ok:
        # `bootstrap` arrived in macOS 10.11 and `load` still works everywhere;
        # trying the old verb costs one call and covers older systems.
        ok, message = _run(["launchctl", "load", "-w", str(path)])
    if not ok:
        return AutostartState(
            supported=True,
            installed=False,
            detail=f"Could not register with macOS: {message}",
            path=str(path),
        )
    return AutostartState(
        supported=True,
        installed=True,
        detail="Will start when you log in",
        path=str(path),
    )


def _launchd_disable(account: str) -> AutostartState:
    path = _launchd_path(account)
    _run(["launchctl", "bootout", f"{_launchctl_domain()}/{_launchd_label(account)}"])
    _run(["launchctl", "unload", "-w", str(path)])
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError as e:
        return AutostartState(
            supported=True,
            installed=True,
            detail=f"Could not remove {path}: {e}",
            path=str(path),
        )
    return AutostartState(
        supported=True,
        installed=False,
        detail="Will no longer start when you log in",
        path=str(path),
    )


def _launchd_status(account: str) -> AutostartState:
    path = _launchd_path(account)
    if not path.is_file():
        return AutostartState(
            supported=True,
            installed=False,
            detail="Not set to start when you log in",
            path=str(path),
        )
    return AutostartState(
        supported=True,
        installed=True,
        detail="Starts when you log in",
        path=str(path),
    )


# ---------------------------------------------------------------------------
# Linux — systemd user units
# ---------------------------------------------------------------------------


def _systemd_unit(account: str) -> str:
    return f"{SYSTEMD_PREFIX}-{account}.service" if account else f"{SYSTEMD_PREFIX}.service"


def _systemd_path(account: str) -> Path:
    return Path.home() / ".config" / "systemd" / "user" / _systemd_unit(account)


def _systemd_text(account: str) -> str:
    """The unit file.

    ``Restart`` is absent for the reason given in the module docstring.
    ``WantedBy=default.target`` is what makes ``enable`` mean "at login".

    The process writes its own logs, so output goes to the journal as well and
    nothing here redirects it — a systemd user unit that writes to files AND the
    journal duplicates every line.
    """
    argv = " ".join(_shell_quote(a) for a in _run_argv(account))
    return (
        "[Unit]\n"
        f"Description=ClawMeets — keep this computer connected ({account})\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={argv}\n"
        # Quoted whole, with `%` doubled: systemd expands `%` specifiers here.
        f'Environment="PATH={_login_path().replace("%", "%%")}"\n'
        f"WorkingDirectory={Path.home()}\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def _shell_quote(value: str) -> str:
    """Quote one systemd ``ExecStart`` argument.

    systemd parses ExecStart itself rather than handing it to a shell, and it
    understands double quotes. Only paths with spaces need it, which is a real
    case (``/Users/Some Name/...``).
    """
    return f'"{value}"' if " " in value else value


def _systemd_enable(account: str) -> AutostartState:
    if not shutil.which("systemctl"):
        return AutostartState(
            supported=False,
            installed=False,
            detail="This Linux has no systemd, so there is nothing to register with",
        )
    path = _systemd_path(account)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_systemd_text(account))

    _run(["systemctl", "--user", "daemon-reload"])
    ok, message = _run(["systemctl", "--user", "enable", _systemd_unit(account)])
    if not ok:
        return AutostartState(
            supported=True,
            installed=False,
            detail=f"Could not register with systemd: {message}",
            path=str(path),
        )

    # Without lingering, a user unit is torn down at logout — so on a machine
    # nobody sits in front of, "starts at login" would never happen. Best-effort:
    # it needs a polkit yes on some distros, and failing it still leaves a unit
    # that works for a logged-in desktop user.
    linger_ok, _ = _run(["loginctl", "enable-linger", os.environ.get("USER", "")])
    detail = "Will start when you log in"
    if not linger_ok:
        detail += " (while you are logged in — `loginctl enable-linger` to cover reboots with no login)"
    return AutostartState(
        supported=True, installed=True, detail=detail, path=str(path)
    )


def _systemd_disable(account: str) -> AutostartState:
    path = _systemd_path(account)
    _run(["systemctl", "--user", "disable", _systemd_unit(account)])
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError as e:
        return AutostartState(
            supported=True,
            installed=True,
            detail=f"Could not remove {path}: {e}",
            path=str(path),
        )
    _run(["systemctl", "--user", "daemon-reload"])
    return AutostartState(
        supported=True,
        installed=False,
        detail="Will no longer start when you log in",
        path=str(path),
    )


def _systemd_status(account: str) -> AutostartState:
    if not shutil.which("systemctl"):
        return AutostartState(
            supported=False,
            installed=False,
            detail="This Linux has no systemd, so there is nothing to register with",
        )
    path = _systemd_path(account)
    if not path.is_file():
        return AutostartState(
            supported=True,
            installed=False,
            detail="Not set to start when you log in",
            path=str(path),
        )
    # The FILE existing is not the same as the unit being enabled — a user can
    # `systemctl --user disable` without deleting it, and reporting that as
    # enabled would be the checklist lying.
    ok, _ = _run(["systemctl", "--user", "is-enabled", _systemd_unit(account)])
    return AutostartState(
        supported=True,
        installed=ok,
        detail="Starts when you log in" if ok else "Registered but switched off",
        path=str(path),
    )


# ---------------------------------------------------------------------------
# The platform-agnostic surface
# ---------------------------------------------------------------------------


_UNSUPPORTED = (
    "Starting at login is not something ClawMeets sets up on this platform yet. "
    "Run `clawmeets computer start` after a restart."
)


def supported() -> bool:
    return sys.platform in ("darwin", "linux")


def enable(username: str = "") -> AutostartState:
    """Register this account's connection to start at login. Never raises."""
    account = _account(username)
    if not account:
        return AutostartState(
            supported=supported(),
            installed=False,
            detail="No account is selected, so there is nothing to start at login",
        )
    if sys.platform == "darwin":
        return _launchd_enable(account)
    if sys.platform == "linux":
        return _systemd_enable(account)
    return AutostartState(supported=False, installed=False, detail=_UNSUPPORTED)


def disable(username: str = "") -> AutostartState:
    """Stop starting this account's connection at login. Never raises.

    Does NOT stop a connection that is running now — the two are separate
    decisions, and silently disconnecting a working machine because the user
    asked about next Tuesday would be the wrong reading of the request.
    """
    account = _account(username)
    if sys.platform == "darwin":
        return _launchd_disable(account)
    if sys.platform == "linux":
        return _systemd_disable(account)
    return AutostartState(supported=False, installed=False, detail=_UNSUPPORTED)


def status(username: str = "") -> AutostartState:
    """Is it registered? Never raises, never changes anything."""
    account = _account(username)
    if sys.platform == "darwin":
        return _launchd_status(account)
    if sys.platform == "linux":
        return _systemd_status(account)
    return AutostartState(supported=False, installed=False, detail=_UNSUPPORTED)
