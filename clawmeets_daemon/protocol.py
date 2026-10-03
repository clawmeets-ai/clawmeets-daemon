# SPDX-License-Identifier: MIT
"""
clawmeets_daemon/protocol.py

The machine's half of the host-socket contract, and the machine's own copy of
the allowlist.

## Why this is a second copy

``clawmeets/api/host_protocol.py`` holds the server's copy. This module is not
an import of it and must never become one: ``clawmeets-daemon`` is a separate
distribution that installs without ``clawmeets`` and without pydantic, so that
it starts in seconds and keeps working when the runner's dependency stack is
broken — which is precisely the situation in which a user most needs to be told
what is happening on their machine.

Duplication here is a feature for the allowlist specifically. The server
refuses an unlisted action before it will send a frame; this module refuses it
again before anything runs. Two fences, and the second one holds even if the
first is wrong, compromised, or simply newer than this machine's copy of the
rules. ``tests/test_host_protocol_parity.py`` fails if the two lists disagree,
so drift is caught in CI rather than in someone's shell.

``delete`` is absent and must stay absent. Deleting an agent destroys
credentials, memory and sandbox state; it is a user-only action in the browser,
and a machine that would accept a remote delete would route around that.
"""
from __future__ import annotations

import re
from typing import Optional

# --- frame types -----------------------------------------------------------

# Machine -> server.
HOST_HELLO = "host_hello"
HOST_HEARTBEAT = "host_heartbeat"
HOST_STATE = "host_state"

# Server -> machine.
HOST_COMMAND = "host_command"
HOST_ACCEPTED = "host_accepted"

# --- the allowlist ---------------------------------------------------------

HOST_ACTIONS: tuple[str, ...] = ("start", "stop", "restart", "status", "update")

HOST_AGENT_ACTIONS: frozenset[str] = frozenset({"start", "stop", "restart"})

HOST_ACTION_LABELS: dict[str, str] = {
    "start": "Start one of your agents",
    "stop": "Stop one of your agents",
    "restart": "Restart one of your agents",
    "status": "Report which of them are running",
    "update": "Update the ClawMeets software on it (clawmeets and its connection software)",
}

HOST_NEVER_LABELS: tuple[str, ...] = (
    "Read or change your agents' environment variables",
    "Install or change anything else",
    "Delete an agent — only you can, here in the browser",
    "Reach any other computer or account",
)

# The rest of the truth about this connection, next to the fixed list. The
# allowlist bounds what the SERVER can ask for; it is not a bound on what runs
# here, because the agents it starts act as the user.
HOST_AGENTS_NOTE = (
    "The agents it runs act as you and can run commands on this computer."
)
TERMINAL_ON_LABEL = (
    "Terminal: on. You can open a full shell on this computer, as you, from "
    "your Computer page. Turn it off on this machine with "
    "`clawmeets computer terminal disable`."
)
TERMINAL_OFF_LABEL = (
    "Terminal: off. Turn it on on this machine with "
    "`clawmeets computer terminal enable`."
)

# --- the terminal channel --------------------------------------------------
#
# NOT an action, and deliberately outside HOST_ACTIONS: the allowlist above is
# the fixed set of things the server can ask this computer to do, and the
# terminal is a separate, unconstrained shell the user opens from their own
# Computer page. It is on by default and the user turns it off ON THE MACHINE
# (`clawmeets computer terminal disable`); no frame can change that switch.
#
# It adds no reach the connection did not already have: every agent this
# computer runs executes commands as the user with permission prompts off, and
# "start an agent" is on the allowlist. The terminal gives the user that same
# access directly.

# Server -> machine.
TERM_OPEN = "term_open"        # {session_id, cols, rows}
TERM_INPUT = "term_input"      # {session_id, data_b64}
TERM_RESIZE = "term_resize"    # {session_id, cols, rows}
TERM_ACK = "term_ack"          # {session_id, bytes}  flow-control credit
TERM_CLOSE = "term_close"      # {session_id}
# Machine -> server.
TERM_OPENED = "term_opened"    # {session_id, ok, detail}
TERM_OUTPUT = "term_output"    # {session_id, data_b64}
TERM_EXIT = "term_exit"        # {session_id, code, reason}

TERMINAL_FRAMES: tuple[str, ...] = (
    TERM_OPEN, TERM_INPUT, TERM_RESIZE, TERM_ACK, TERM_CLOSE,
    TERM_OPENED, TERM_OUTPUT, TERM_EXIT,
)

TERM_MAX_SESSIONS = 3
# One input frame. A paste larger than this is chunked by the browser.
TERM_MAX_INPUT_BYTES = 16384
TERM_IDLE_SECONDS = 15 * 60
TERM_MAX_SECONDS = 8 * 3600
# The machine stops reading the shell's output once this much is sent and not
# yet acknowledged by the browser, so a runaway `yes` blocks in the kernel
# instead of flooding the relay and freezing the tab.
TERM_UNACKED_LIMIT = 256 * 1024
TERM_MAX_COLS = 1000
TERM_MAX_ROWS = 500

_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")


def validate_session_id(value: object) -> str:
    """The session id, or raise ``ValueError``. It keys dicts on both ends."""
    if not isinstance(value, str) or not _SESSION_ID_RE.match(value):
        raise ValueError("invalid terminal session id")
    return value


def validate_size(cols: object, rows: object) -> tuple[int, int]:
    """``(cols, rows)`` clamped to a sane window, or raise ``ValueError``."""
    try:
        c, r = int(cols), int(rows)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise ValueError("terminal size must be two integers")
    return max(1, min(c, TERM_MAX_COLS)), max(1, min(r, TERM_MAX_ROWS))


CLOSE_BAD_TOKEN = 4001
CLOSE_NO_HOST = 4004


class HostCommandRejected(ValueError):
    """An action outside :data:`HOST_ACTIONS`, or missing its agent name."""


def validate_host_action(
    action: str, agent: Optional[str]
) -> tuple[str, Optional[str]]:
    """``(action, agent)`` normalized, or raise :class:`HostCommandRejected`.

    The machine-side fence. Refuses an action not on the allowlist, a per-agent
    action with no agent named, and an agent name containing anything but
    ``[A-Za-z0-9-_]``.

    That last check matters even though every call site passes the name inside a
    ``subprocess`` argument LIST rather than a shell string: "we never build a
    shell string" is a property of today's code, and this is a property of the
    input. It is the difference between safe and currently-safe.
    """
    cleaned = (action or "").strip().lower()
    if cleaned not in HOST_ACTIONS:
        raise HostCommandRejected(
            f"{action!r} is not one of the allowed actions "
            f"({', '.join(HOST_ACTIONS)})"
        )
    name = (agent or "").strip() or None
    if cleaned in HOST_AGENT_ACTIONS:
        if not name:
            raise HostCommandRejected(f"{cleaned!r} needs the name of one agent")
        if not all(c.isalnum() or c in "-_" for c in name):
            raise HostCommandRejected(f"{name!r} is not a valid agent name")
    else:
        name = None
    return cleaned, name
