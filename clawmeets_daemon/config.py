# SPDX-License-Identifier: MIT
"""
clawmeets_daemon/config.py

Where this machine keeps its connection credential, and where it writes its logs.

Layout, under the same ``~/.clawmeets`` tree the runner already owns so a user
has one directory to reason about::

    ~/.clawmeets/computer/<clawmeets-username>/
      config.json      # host id + token + server url + username  (mode 0600)
      computer.pid     # the daemon's own pidfile
      stdout.log       # what it did
      stderr.log       # what went wrong, including an uncaught crash

## Why the username is in the path

One machine can host several clawmeets accounts — that is a supported shape,
not an edge case: the runner already keeps ``config/<username>/settings.json``
per account and prefixes every agent directory with its owner's name, and
``clawmeets start --user alice`` exists precisely so two accounts can run side
by side. A machine-wide ``computer/`` directory would have been the one part of
the tree that could not: the second account to pair would overwrite the first
account's ``config.json``, destroying a token that is minted once and not
recoverable, and would take over the first account's pidfile — leaving a live,
unstoppable daemon still holding the old connection while the first account's
computer page said "off" forever.

So the account name is the namespace, mirroring ``config/<username>/`` exactly.
Each account gets its own credential, its own pidfile and its own pair of logs,
and two daemons can run on one machine without knowing about each other. The
server side already worked this way (``hosts/<owner_user_id>/<host_id>.json``),
so this makes the machine agree with it.

The namespace is the USERNAME and not the host id or the token. A host id is
not known until after pairing, so nothing could find the credential in order to
read it. A token in a path would be worse than useless: paths are printed by
``status``, captured in shell history, listed by ``ps`` for any process on the
machine, and swept up by backups — a secret must live inside a 0600 file, which
is where this one stays.

The log pair is named the way every other long-lived clawmeets process names
its output — an agent writes ``stdout.log`` / ``stderr.log`` into its agent
directory, the server writes them into its own — so someone who already knows
where to look for one knows where to look for all of them. Splitting by stream
also means "did anything go wrong on this machine?" is answered by whether one
file is empty, without reading it.

These files are local-only. Nothing uploads them, and the web app never shows
them; the browser says a machine is not answering, and these say why.

The directory is named ``computer`` rather than ``daemon`` for the same reason
every string a user can see says "computer": a path is user-visible surface the
moment anyone opens a terminal.

``config.json`` holds the only secret on this machine that lets the server ask
it to do anything, so it is written with mode 0600 and never logged. The token
is minted once by ``POST /computers/pair`` and is not recoverable — a lost
credential is re-paired, which is also what makes "Disconnect this computer"
final.
"""
from __future__ import annotations

import json
import os
import stat
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Optional

DEFAULT_SERVER = os.environ.get("CLAWMEETS_SERVER_URL", "https://clawmeets.ai")
DEFAULT_DATA_DIR = os.environ.get(
    "CLAWMEETS_DATA_DIR", str(Path.home() / ".clawmeets")
)

COMPUTER_SUBDIR = "computer"
CONFIG_NAME = "config.json"
TERMINAL_NAME = "terminal.json"
PID_NAME = "computer.pid"
STDOUT_LOG_NAME = "stdout.log"
STDERR_LOG_NAME = "stderr.log"

# The size at which a log is rotated to `.1`. A daemon that runs for months must
# not quietly fill a laptop's disk, and one generation of history is enough to
# answer "why did it stop yesterday".
MAX_LOG_BYTES = 2 * 1024 * 1024


# The clawmeets account this process is acting for. Set once, at the top of
# every entry point, by `use_account()`. A daemon process serves exactly one
# account for its whole life — it is paired to one, it reports one account's
# agents, and it runs commands as that account — so this is process-wide state
# rather than an argument threaded through every path helper and every log line.
_active_account: str = ""


def use_account(username: str) -> None:
    """Select the account whose computer files this process reads and writes.

    Called by each CLI command and by the background process it spawns, before
    anything touches a path. Passing "" clears the selection, which is only
    useful in tests.
    """
    global _active_account
    _active_account = (username or "").strip()


def active_account() -> str:
    """The account in force, resolving through the logged-in user if unset.

    Deliberately never raises and never invents a name. On a machine with no
    account selected at all there is nothing to keep separate, so the paths
    collapse back to the un-namespaced directory — the same place a pre-account
    layout wrote them, which is also what makes the one-time migration below
    find them.
    """
    return _active_account or local_username()


def data_dir() -> Path:
    return Path(DEFAULT_DATA_DIR).expanduser()


def computer_root() -> Path:
    """``~/.clawmeets/computer`` — the parent of every account's directory."""
    return data_dir() / COMPUTER_SUBDIR


def computer_dir() -> Path:
    """Where the account in force keeps its credential, pidfile and logs."""
    account = active_account()
    root = computer_root()
    return root / account if account else root


def account_dirs() -> list[tuple[str, Path]]:
    """``(username, dir)`` for every account that has connected this machine.

    Used by commands that are asked about the machine rather than about one
    account, so "which of my accounts has this computer connected?" is
    answerable without the user guessing names.
    """
    root = computer_root()
    if not root.is_dir():
        return []
    found: list[tuple[str, Path]] = []
    for entry in sorted(root.iterdir()):
        if entry.is_dir() and (entry / CONFIG_NAME).is_file():
            found.append((entry.name, entry))
    return found


def config_path() -> Path:
    return computer_dir() / CONFIG_NAME


def pid_path() -> Path:
    return computer_dir() / PID_NAME


def stdout_log_path() -> Path:
    return computer_dir() / STDOUT_LOG_NAME


def stderr_log_path() -> Path:
    return computer_dir() / STDERR_LOG_NAME


def log_paths() -> tuple[Path, Path]:
    """Both logs, in the order a reader wants them: what happened, then what broke."""
    return stdout_log_path(), stderr_log_path()


@dataclass
class ComputerConfig:
    """This machine's identity to the server.

    ``username`` is the local clawmeets account whose agents this machine hosts.
    It is recorded at pair time rather than looked up on every scan because the
    scan is the daemon's hot path and ``current_user`` can change under it — a
    user who logs in as someone else should not have this machine silently
    start reporting the other account's agents.
    """

    host_id: str
    token: str
    server_url: str = DEFAULT_SERVER
    username: str = ""

    def to_json(self) -> dict:
        return {
            "host_id": self.host_id,
            "token": self.token,
            "server_url": self.server_url,
            "username": self.username,
        }


# Files an earlier, machine-wide layout wrote directly under `computer/`, in the
# order they should be carried across. The `.1` rotations come along so a user
# who upgrades mid-incident does not lose the log they were about to read.
_LEGACY_NAMES = (
    CONFIG_NAME, PID_NAME,
    STDOUT_LOG_NAME, STDERR_LOG_NAME,
    STDOUT_LOG_NAME + ".1", STDERR_LOG_NAME + ".1",
)


def migrate_legacy_layout() -> Optional[Path]:
    """Move a machine-wide ``computer/config.json`` into its account's directory.

    A machine paired before the account namespace existed keeps its credential
    one level up. Left alone it would read as "not connected" after an upgrade
    while a daemon from the old layout was still running and still holding the
    connection — the confusing state this whole change exists to prevent. So the
    files are moved once, to the account the config itself names.

    Returns the new config path when something moved, else None. Best-effort
    throughout: a machine that cannot be migrated must still start, and re-
    pairing is always available as the fallback.

    Renaming an open log is safe on POSIX (the old process keeps writing to the
    same inode) and is skipped on Windows, where it would fail; the log is then
    simply left behind, which costs history and nothing else.
    """
    legacy_config = computer_root() / CONFIG_NAME
    if not legacy_config.is_file():
        return None
    try:
        data = json.loads(legacy_config.read_text())
        username = str(data.get("username") or "").strip()
    except (OSError, ValueError):
        return None
    if not username:
        return None

    target = computer_root() / username
    if (target / CONFIG_NAME).is_file():
        return None  # the account already has a newer credential; leave the old one
    try:
        target.mkdir(parents=True, exist_ok=True)
        for name in _LEGACY_NAMES:
            source = computer_root() / name
            if source.is_file():
                try:
                    source.replace(target / name)
                except OSError:
                    pass
    except OSError:
        return None
    return target / CONFIG_NAME


def read_config() -> Optional[ComputerConfig]:
    """This machine's config for the account in force, or None if never connected.

    Runs :func:`migrate_legacy_layout` first. A read with a side effect is worth
    the exception here because this is the single funnel every command passes
    through, and the alternative is each of them remembering to migrate.
    """
    migrate_legacy_layout()
    path = config_path()
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not data.get("host_id") or not data.get("token"):
        return None
    return ComputerConfig(
        host_id=str(data["host_id"]),
        token=str(data["token"]),
        server_url=str(data.get("server_url") or DEFAULT_SERVER),
        username=str(data.get("username") or ""),
    )


def write_config(config: ComputerConfig) -> Path:
    """Persist the credential at mode 0600.

    The chmod is applied AFTER the write and is not conditional on the file
    being new: a config rewritten by a re-pair must not inherit a looser mode
    from an earlier version of this code. It is best-effort on Windows, where
    the POSIX bits are advisory.
    """
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config.to_json(), indent=2))
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return path


def clear_config() -> None:
    """Forget this machine's credential. Used when the server says 4004.

    The pidfile is deliberately left alone — the process removes that itself on
    the way out, and deleting it here would orphan a live process.
    """
    try:
        config_path().unlink(missing_ok=True)
    except OSError:
        pass


def terminal_path() -> Path:
    return computer_dir() / TERMINAL_NAME


def terminal_enabled() -> bool:
    """Is the terminal switched on at this machine?

    ON unless the user turned it off here. The file only ever records that
    choice, and only the CLI writes it — the daemon reads it, and nothing that
    arrives over the socket can reach this function's inputs.

    A file that exists but cannot be read counts as OFF: the user said
    something about the terminal on this machine, and when we cannot tell what,
    the shell stays closed.

    Read fresh on every call, no caching, so `disable` takes effect on a
    running daemon without a restart.
    """
    path = terminal_path()
    if not path.exists():
        return True
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and data.get("enabled") is True


def set_terminal_enabled(on: bool) -> Path:
    """Record the user's choice, at mode 0600. The CLI's job, never the daemon's."""
    path = terminal_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "enabled": bool(on),
        "changed_at": datetime.now(UTC).isoformat(),
    }, indent=2))
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return path


def local_username() -> str:
    """The clawmeets account currently selected on this machine, or "".

    Reads the same ``config/current_user`` file ``clawmeets start`` reads, so
    pairing picks up whoever is logged in rather than asking the user to retype
    their name.
    """
    path = data_dir() / "config" / "current_user"
    try:
        return path.read_text().strip()
    except OSError:
        return ""


def append_log(line: str, *, error: bool = False) -> None:
    """Append one timestamped line to ``stdout.log``, or to ``stderr.log``.

    ``error=True`` is for the things that make a computer stop being useful: a
    lost connection, a rejected key, a command that failed. Everything else —
    connecting, connected, a command accepted — is ordinary progress and goes to
    stdout. The split is the point of having two files: an empty ``stderr.log``
    is itself the answer to "is anything wrong here?".

    Deliberately not the ``logging`` module: this runs in a process whose entire
    job is to stay up, and a log write must never raise. Every failure path here
    swallows — losing a log line is always better than losing the connection the
    line was about to describe.

    When the matching stream is a terminal the line is echoed there too, so
    ``clawmeets computer run`` in the foreground shows its work. In the
    background both streams are redirected into these same two files, so the
    echo is suppressed and nothing is written twice.
    """
    path = stderr_log_path() if error else stdout_log_path()
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    text = f"{stamp}  {line.rstrip()}"

    stream = sys.stderr if error else sys.stdout
    try:
        if stream is not None and stream.isatty():
            print(text, file=stream, flush=True)
    except (OSError, ValueError):  # closed or detached stream
        pass

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > MAX_LOG_BYTES:
            path.replace(path.with_suffix(path.suffix + ".1"))
        with path.open("a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    except OSError:
        pass


@dataclass(frozen=True)
class UserSession:
    """The runner's saved sign-in for one account, as this process needs it.

    Read-only and read-through: the daemon never writes here. It exists so
    ``clawmeets computer install`` can mint its OWN pairing code instead of
    making the user carry one from the browser to a terminal — the code was only
    ever a way to prove "the human at this machine is the account holder", and a
    session the runner already persisted proves exactly that.

    A missing file, a missing token, or anything unparseable is all one answer
    (``None`` from :func:`read_user_session`): the caller falls back to asking
    for a code, which always works.
    """

    username: str
    server_url: str
    token: str


def read_user_session(username: str = "") -> Optional[UserSession]:
    """The runner's saved session for ``username`` (or the logged-in account).

    Reads ``~/.clawmeets/config/<username>/settings.json`` — the runner's file,
    not one of ours. That is a deliberate one-way dependency on a stable path
    the runner has written for as long as ``clawmeets user login`` has existed,
    and it is guarded the way every other cross-distribution read here is:
    never raises, returns None on anything unexpected.
    """
    name = (username or local_username()).strip()
    if not name:
        return None
    path = data_dir() / "config" / name / "settings.json"
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    user = data.get("user")
    token = (user or {}).get("token") if isinstance(user, dict) else None
    if not token:
        return None
    return UserSession(
        username=name,
        server_url=str(data.get("server_url") or DEFAULT_SERVER).rstrip("/"),
        token=str(token),
    )
