# clawmeets-daemon

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Connects one computer to [ClawMeets](https://clawmeets.ai), so you can see what
is running on it — and start or stop it — from the web instead of a terminal.

## Why this is a separate package

It stays connected when every agent on the machine is dead.

That is the whole feature. An agent's own connection cannot tell you "nothing is
running here", because it is gone in that case — which looks exactly like the
computer being switched off. Those two states need different words and different
remedies, so something on the machine has to keep talking when there is nothing
else left to talk.

It follows that this must not be able to break the way the agents can, which is
why it is its own package with **three dependencies** (`httpx`, `websockets`,
`typer`). It installs in seconds and starts even when the runner's heavier stack
is unusable.

## Install

```bash
uv tool install clawmeets-daemon     # or: pip install clawmeets-daemon
```

Then, in the ClawMeets web app, open **Computers**, press **+** to get a pairing
code, and run:

```bash
clawmeets computer install --code XXXX-XXXX --user <your-username>
```

(`clawmeets computer …` is the same program, reached through the runner's CLI.
If the runner is not installed, use `clawmeets-computer …` directly.)

## What this connection can do

**The fixed list.** The server can ask this computer to do only these things,
and every item is checked twice — once by the server before it will send
anything, and again here before anything runs:

- Start one of your agents
- Stop one of your agents
- Restart one of your agents
- Report which of them are running
- Update the ClawMeets software on it (clawmeets and its connection software)
- Add, replace or remove an environment variable for one of your agents

**Your agents.** The agents it runs act as you and can run commands on this
computer.

**The terminal.** On by default: you can open a full shell on this computer, as
you, from its page in ClawMeets. Turn it off on this machine — only here, never
from the browser:

    clawmeets computer terminal disable   # ends open sessions within seconds
    clawmeets computer terminal enable
    clawmeets computer terminal status

Sessions are hung up when you end them, after 15 minutes idle, after 8 hours,
or when the connection drops. The server records who opened a session and for
how long — never what was typed or printed.

**Never**

- Read back or send the value of an environment variable
- Install or change anything else
- Delete an agent — only you can, in the browser
- Reach any other computer or account

Start, stop and restart are performed by shelling the ordinary
`clawmeets start` / `clawmeets stop` commands, so they behave exactly as they do
when you type them yourself.

Disconnecting the computer from the web app destroys this machine's key
immediately and for good; reconnecting needs a fresh pairing code.

## Commands

| Command | What it does |
|---------|--------------|
| `clawmeets computer install --code XXXX-XXXX` | Connect this computer to your account |
| `clawmeets computer start` | Start the connection in the background |
| `clawmeets computer stop` | Stop the connection (your agents keep running) |
| `clawmeets computer status` | Is it connected, and what is running here |
| `clawmeets computer logs --tail 50` | What the connection has been doing |
| `clawmeets computer update` | Update ClawMeets on this computer (clawmeets + connection software, via uv tool / pipx / pip) |

## Where things live

```
~/.clawmeets/computer/<your-username>/
  config.json     # this machine's key, for this account (mode 0600)
  computer.pid
  stdout.log      # what the connection did
  stderr.log      # what went wrong
```

One directory per ClawMeets account. If two people (or two of your own
accounts) use the same computer, each pairs separately and gets its own key,
its own connection and its own logs — neither can disturb the other. Every
command takes `--user <name>`; without it, it acts for the account you are
logged in as.

The two logs are rotated at 2 MB, stay on this machine, and are never uploaded
or shown in the web app. `clawmeets computer logs` prints the tail of both.

`config.json` holds the only secret that lets ClawMeets ask this machine to do
anything. It is written readable by you alone, never logged, and never
synchronized anywhere.

## Mirrored source

This repository is a read-only mirror, published from the ClawMeets monorepo.
Issues and discussion are welcome here; code changes land upstream.

## License

MIT — see [LICENSE](LICENSE).
