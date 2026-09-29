# SPDX-License-Identifier: MIT
"""
clawmeets_daemon/upgrade.py

Upgrade ONE of the two ClawMeets distributions in place, using the installer
that put it there.

## Why the installer has to be detected, not assumed

People install ``clawmeets`` and ``clawmeets-daemon`` every way Python software
can be installed: ``uv tool install`` (what the one-line installer does),
``pipx``, ``pip`` into a virtualenv or conda env, ``uv pip`` into a venv that
has no pip at all, or ``pip --user``. Each of those only upgrades cleanly with
its own tool:

- ``uv tool upgrade`` refuses a package it did not install;
- ``pip install --upgrade`` into a uv-tool or pipx environment works once and
  then leaves that tool's receipt describing a version that is no longer there;
- ``sys.executable -m pip`` upgrades the DAEMON's environment, which is the
  wrong one for the runner whenever the two were installed separately (the
  default).

So every upgrade starts from the package's own environment — the interpreter
that actually runs it — and reads the marker the installer left there:
``uv-receipt.toml`` for a uv tool, ``pipx_metadata.json`` for pipx, neither for
a plain environment.

## What this module can install

Only the two names in :data:`DISTRIBUTIONS`. That constant is what keeps
"Install or change anything else" an honest *never* on the consent screen; a
caller cannot pass a package name through.

Stdlib only, like the rest of this distribution.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

RUNNER_DIST = "clawmeets"
DAEMON_DIST = "clawmeets-daemon"
DISTRIBUTIONS: frozenset[str] = frozenset({RUNNER_DIST, DAEMON_DIST})

# One `uv`/`pip` resolve-and-install. Generous because a cold pip cache on a
# slow link is the normal case for a machine that updates once a month.
UPGRADE_TIMEOUT_SECONDS = 300

_VERSION_SNIPPET = (
    "import importlib.metadata as m, sys\n"
    "try:\n"
    "    print(m.version(sys.argv[1]))\n"
    "except m.PackageNotFoundError:\n"
    "    sys.exit(3)\n"
)


@dataclass
class UpgradeOutcome:
    dist: str
    ok: bool
    # "uv tool", "pipx", "pip", "uv pip" — what actually did the upgrade, for
    # the one-line detail. Empty when nothing ran.
    installer: str = ""
    before: str = ""
    after: str = ""
    detail: str = ""

    @property
    def changed(self) -> bool:
        return self.ok and bool(self.after) and self.after != self.before


def _tail(output: str, limit: int = 240) -> str:
    cleaned = " ".join((output or "").split())
    return cleaned[-limit:] if len(cleaned) > limit else cleaned


def find_tool(name: str) -> Optional[str]:
    """``uv`` / ``pipx`` on PATH, or at a default install location.

    The fallbacks matter: a daemon started by launchd or systemd gets a bare
    PATH that usually does not include ``~/.local/bin`` or Homebrew.
    """
    found = shutil.which(name)
    if found:
        return found
    exe = f"{name}.exe" if os.name == "nt" else name
    for directory in (
        Path.home() / ".local" / "bin",
        Path.home() / ".cargo" / "bin",
        Path("/opt/homebrew/bin"),
        Path("/usr/local/bin"),
    ):
        candidate = directory / exe
        if candidate.exists():
            return str(candidate)
    return None


def python_for_script(script: str) -> Optional[str]:
    """The interpreter that runs a console script, or None if it cannot be told.

    The script is resolved first because uv tool and pipx both put a SYMLINK in
    ``~/.local/bin`` pointing into the tool's own environment. The interpreter
    itself is deliberately NOT resolved: a venv's ``python`` is a symlink to
    the base interpreter, and following it would lose the venv.

    POSIX console scripts name their interpreter on the shebang line. Windows
    ones are launcher executables with no readable shebang, so there the
    ``python.exe`` next to the script (``<venv>/Scripts``) is the answer.
    """
    try:
        path = Path(script).resolve()
    except OSError:
        return None
    try:
        with path.open("rb") as fh:
            first = fh.readline(512)
    except OSError:
        first = b""
    if first.startswith(b"#!"):
        line = first[2:].decode("utf-8", "replace").strip()
        # `#!/usr/bin/env python3` → not a specific environment.
        if line and not line.startswith("/usr/bin/env"):
            candidate = line.split()[0]
            if Path(candidate).exists():
                return candidate
    for sibling in ("python", "python3", "python.exe"):
        candidate = path.parent / sibling
        if candidate.exists():
            return str(candidate)
    return None


def env_root(python: str) -> Path:
    """``<prefix>`` for ``<prefix>/bin/python`` or ``<prefix>/Scripts/python.exe``."""
    return Path(python).parent.parent


def detect_installer(python: str) -> str:
    """``"uv tool"``, ``"pipx"`` or ``"pip"`` — who owns this environment."""
    root = env_root(python)
    if (root / "uv-receipt.toml").exists():
        return "uv tool"
    if (root / "pipx_metadata.json").exists():
        return "pipx"
    return "pip"


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=UPGRADE_TIMEOUT_SECONDS,
        check=False,
    )


def installed_version(python: str, dist: str) -> str:
    """The version of ``dist`` in ``python``'s environment, or ``""``.

    Asked of that interpreter over a subprocess rather than read in-process:
    the runner lives in a different environment from this daemon, and even for
    the daemon itself a fresh process is the only reader guaranteed not to see
    a stale metadata cache after an upgrade.
    """
    try:
        proc = subprocess.run(
            [python, "-c", _VERSION_SNIPPET, dist],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def upgrade_attempts(dist: str, python: Optional[str]) -> list[tuple[str, list[str]]]:
    """The commands to try, in order, as ``(installer label, argv)``.

    The installer that owns the environment goes first. Fallbacks follow only
    where they are still correct for that environment: a pipx venv can be
    upgraded by its own pip; a plain venv created by ``uv`` has no pip, so
    ``uv pip --python`` targets the same interpreter instead. There is no
    fallback that switches environments — upgrading a DIFFERENT copy than the
    one that runs would report success and change nothing.
    """
    if dist not in DISTRIBUTIONS:
        raise ValueError(f"{dist!r} is not a ClawMeets package")
    uv = find_tool("uv")
    attempts: list[tuple[str, list[str]]] = []

    if python is None:
        # A console script we cannot trace to an interpreter (a Windows uv
        # trampoline, a wrapper script). The one-line installer uses uv tool,
        # so that is the best guess; pipx second.
        if uv:
            attempts.append(("uv tool", [uv, "tool", "upgrade", dist]))
        pipx = find_tool("pipx")
        if pipx:
            attempts.append(("pipx", [pipx, "upgrade", dist]))
        return attempts

    installer = detect_installer(python)
    if installer == "uv tool" and uv:
        attempts.append(("uv tool", [uv, "tool", "upgrade", dist]))
        return attempts
    if installer == "pipx":
        pipx = find_tool("pipx")
        if pipx:
            attempts.append(("pipx", [pipx, "upgrade", dist]))
    attempts.append(("pip", [python, "-m", "pip", "install", "--upgrade", dist]))
    if uv:
        attempts.append(
            ("uv pip", [uv, "pip", "install", "--python", python, "--upgrade", dist])
        )
    return attempts


def upgrade(dist: str, python: Optional[str]) -> UpgradeOutcome:
    """Upgrade ``dist`` in the environment ``python`` belongs to. Never raises."""
    before = installed_version(python, dist) if python else ""
    attempts = upgrade_attempts(dist, python)
    if not attempts:
        return UpgradeOutcome(
            dist, False, before=before,
            detail="could not tell how it was installed, and neither uv nor "
                   "pipx is available",
        )
    last = ""
    for installer, argv in attempts:
        try:
            proc = _run(argv)
        except subprocess.TimeoutExpired:
            last = f"{installer} took longer than {UPGRADE_TIMEOUT_SECONDS}s"
            continue
        except OSError as e:
            last = f"{installer}: {e}"
            continue
        if proc.returncode == 0:
            after = installed_version(python, dist) if python else ""
            return UpgradeOutcome(dist, True, installer, before, after)
        last = f"{installer}: {_tail(proc.stdout)}"
    return UpgradeOutcome(dist, False, before=before, detail=last)


def daemon_python() -> str:
    """This process's own interpreter — by definition the daemon's environment."""
    return sys.executable
