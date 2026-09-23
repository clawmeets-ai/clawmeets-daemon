# SPDX-License-Identifier: MIT
"""
clawmeets_daemon/discovery.py

Agent discovery + liveness, resolved to exactly ONE implementation.

``clawmeets/utils/agent_processes.py`` is the single editable copy. Which module
object this file re-exports depends on where the code is running, and both
answers are the same source:

- **In the published wheel** — ``scripts/build-daemon-package.sh`` copies that
  file verbatim to ``clawmeets_daemon/agent_processes.py``, so the first import
  wins and the daemon has no ``clawmeets`` dependency at all. That is what lets
  ``pip install clawmeets-daemon`` finish in seconds and start even when the
  runner's dependency stack is broken.
- **In the monorepo (and on a machine that has the runner)** — that file does
  not exist, the import falls through, and the canonical module is used
  directly.

The ``import *`` is why every name in ``agent_processes`` is public: a
leading underscore would be invisible here.
"""
from __future__ import annotations

try:  # published wheel: vendored copy, no clawmeets import
    from clawmeets_daemon.agent_processes import *  # type: ignore  # noqa: F401,F403
    from clawmeets_daemon.agent_processes import (  # type: ignore  # noqa: F401
        agents_dir,
        scan_agents,
    )
except ImportError:  # monorepo / runner installed alongside
    from clawmeets.utils.agent_processes import *  # type: ignore  # noqa: F401,F403
    from clawmeets.utils.agent_processes import (  # noqa: F401
        agents_dir,
        scan_agents,
    )
