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
    "update": "Update its own connection software",
}

HOST_NEVER_LABELS: tuple[str, ...] = (
    "Run any other command",
    "Open, read, copy or send your files",
    "Install or change anything else",
    "Delete an agent — only you can, here in the browser",
    "Reach any other computer or account",
)

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
