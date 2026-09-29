# SPDX-License-Identifier: MIT
"""
clawmeets_daemon/cli.py

``clawmeets-computer`` — the command surface of the connection daemon.

    clawmeets-computer install --code 7QK2-M4RD
    clawmeets-computer start | stop | status | logs | update

Users normally reach these through ``clawmeets computer …``, which is a
passthrough in the runner CLI (``clawmeets/cli_daemon.py``). Both spellings are
the same program; this one exists so the daemon is usable on a machine where the
runner is missing or broken, which is exactly when someone needs to see whether
their computer is connected.

Every string here says "computer". "Daemon" and "runner" appear in module names
and nowhere a user reads, which is the same rule the web copy follows — with one
acknowledged exception: the PyPI distribution is ``clawmeets-daemon``, named
after its own public mirror repo, for whoever is reading a package index rather
than using the product.

Every command acts on ONE clawmeets account — the logged-in one by default,
another with ``--user``, exactly as ``clawmeets start --user alice`` does. One
machine can host several accounts, each with its own key, its own connection
process and its own logs under ``~/.clawmeets/computer/<username>/``, so pairing
a second account never disturbs the first.

The process is detached and, by default, registered to start again at login
(``autostart.py`` — launchd on macOS, a systemd user unit on Linux). It is not
*supervised*: neither manager is asked to restart it, because that would fight
``clawmeets computer stop``. So a reboot brings it back and an explicit stop
keeps it stopped, which is the pair of behaviours a user expects and could not
get before.
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import httpx
import typer

from clawmeets_daemon import autostart, client, commands, config as cfg
from clawmeets_daemon.discovery import popen_detached_kwargs, read_pid, stop_pid
from clawmeets_daemon.protocol import (
    HOST_ACTION_LABELS,
    HOST_ACTIONS,
    HOST_AGENTS_NOTE,
    HOST_NEVER_LABELS,
    TERMINAL_OFF_LABEL,
    TERMINAL_ON_LABEL,
)

app = typer.Typer(
    name="clawmeets-computer",
    help="Connect this computer to ClawMeets so you can see and control its "
         "agents from the web.",
    no_args_is_help=True,
)

_STATE_WORDS = {
    "running": "running",
    "crashed": "stopped on its own",
    "stopped": "stopped",
}


_USER_OPTION = typer.Option(
    None, "--user", "-u",
    help="Which ClawMeets account to act for (defaults to the one you are "
         "logged in as on this computer).",
)


def _resolve_account(user: Optional[str]) -> str:
    """Decide which account's computer files this command is about, and select it.

    In order of how sure we can be:

    1. ``--user`` — an explicit answer beats every guess.
    2. The logged-in account, when it is one that has connected this computer.
    3. The only connected account, when there is exactly one. This is what makes
       ``clawmeets computer status`` still answer after a logout or an account
       switch, instead of reporting a connected machine as unconnected.
    4. Otherwise the logged-in account (possibly none), so the caller reports
       "not connected" for a named account rather than picking one at random.

    Never guesses between two connected accounts: with several present and
    nothing to choose by, the commands below list them and ask.
    """
    cfg.migrate_legacy_layout()
    if user:
        cfg.use_account(user.strip())
        return cfg.active_account()

    connected = dict(cfg.account_dirs())
    logged_in = cfg.local_username()
    if logged_in in connected:
        chosen = logged_in
    elif len(connected) == 1:
        chosen = next(iter(connected))
    else:
        chosen = logged_in
    cfg.use_account(chosen)
    return chosen


def _other_accounts_hint(account: str) -> str:
    """"…but these accounts have", for a command that found nothing for `account`."""
    others = [name for name, _ in cfg.account_dirs() if name != account]
    if not others:
        return ""
    return (
        "\nThis computer IS connected for: " + ", ".join(others) +
        "\nUse --user <name> to act for one of those."
    )


def _require_config() -> cfg.ComputerConfig:
    config = cfg.read_config()
    if config is None:
        typer.echo(
            "This computer is not connected to ClawMeets yet.\n"
            "Open ClawMeets in your browser, go to Computers, press + to get a "
            "code, then run:\n"
            "  clawmeets computer install --code XXXX-XXXX"
            + _other_accounts_hint(cfg.active_account()),
            err=True,
        )
        raise typer.Exit(1)
    return config


def _print_consent() -> None:
    """The same promise the browser shows, before anything is granted.

    Printed at install time, not buried in a doc, because this is the moment the
    permission is actually given and the terminal is where the user is standing.
    The wording is the same list the pairing dialog and the computer's page show,
    and it is generated from the same allowlist the machine enforces.
    """
    typer.echo("\nWhat this connection can do:")
    typer.echo("  The server can ask this computer to do only a fixed set of things:")
    for action in HOST_ACTIONS:
        typer.echo(f"  + {HOST_ACTION_LABELS[action]}")
    typer.echo(f"  {HOST_AGENTS_NOTE}")
    typer.echo(f"  {_terminal_label()}")
    typer.echo("\nWhat it will never do:")
    for never in HOST_NEVER_LABELS:
        typer.echo(f"  - {never}")
    typer.echo(
        "\nYou can disconnect this computer at any time from the web app, and "
        "that key stops working immediately."
    )


def _mint_pairing_code(session: cfg.UserSession) -> Optional[str]:
    """Ask the server for a pairing code using the account's own session.

    This is what lets ``clawmeets computer install`` take no arguments. The code
    was never a second factor — it exists so an UNAUTHENTICATED machine can
    prove it is acting for an account, and a signed-in machine has already
    proven that with a stronger credential. Carrying a code from the browser to
    a terminal was a step the one-command install could not afford.

    Returns None on any failure, and the caller falls back to asking for a code.
    Minting needs a user JWT specifically (the route refuses agent tokens), which
    is exactly what the runner persisted at login.
    """
    try:
        response = httpx.post(
            f"{session.server_url}/me/computers/pairing-code",
            headers={"Authorization": f"Bearer {session.token}"},
            timeout=30,
        )
    except httpx.HTTPError:
        return None
    if response.status_code != 200:
        return None
    try:
        return str(response.json().get("code") or "") or None
    except ValueError:
        return None


@app.command()
def install(
    code: Optional[str] = typer.Option(
        None, "--code",
        help="A pairing code from the web app. Omit it when you are already "
             "signed in on this computer — one is fetched for you.",
    ),
    server: Optional[str] = typer.Option(
        None, "--server", "-s", help="Server URL (defaults to https://clawmeets.ai)."
    ),
    start_after: bool = typer.Option(
        True, "--start/--no-start", help="Start the connection after pairing."
    ),
    autostart_after: bool = typer.Option(
        True, "--autostart/--no-autostart",
        help="Also start the connection automatically when you log in.",
    ),
    user: Optional[str] = _USER_OPTION,
) -> None:
    """Connect this computer to your ClawMeets account.

    Needs no arguments when you are already signed in here: it fetches its own
    pairing code, so there is nothing to copy out of the browser.

    Spends a one-time code, stores this machine's own key at
    ``~/.clawmeets/computer/<your-username>/config.json`` (mode 0600), and starts
    the connection. The key is minted once and is not recoverable — if it is
    lost, or you disconnect the computer from the web, you pair again with a new
    code.

    Pairs the account you are logged in as, or the one named by ``--user``. A
    second account on the same machine pairs separately and gets its own key,
    its own connection and its own computer page; neither disturbs the other.

    Re-running for an account that is ALREADY connected creates a SECOND record
    for the same machine, because the server has no way to recognize a machine
    it has never spoken to. If you paired by mistake, disconnect the duplicate
    from the web app.
    """
    username = (user or cfg.local_username()).strip()
    session = cfg.read_user_session(username)
    # The saved session knows which server this account signed in to, so
    # `--server` is only needed when there is no session to ask. Without this a
    # self-hosted user would silently pair against clawmeets.ai.
    server_url = (server or (session.server_url if session else cfg.DEFAULT_SERVER)).rstrip("/")
    if not username:
        # Refusing beats pairing anyway: a machine with no account reports no
        # agents forever, and finding that out costs a pairing code, which is
        # single-use. The fix is one command away.
        typer.echo(
            "No ClawMeets account is logged in on this computer, so there would "
            "be no agents to report.\n"
            "Log in first (`clawmeets login`), or name the account: "
            "`clawmeets computer install --code XXXX-XXXX --user <name>`.",
            err=True,
        )
        raise typer.Exit(1)
    cfg.use_account(username)

    # No code given: fetch one with the account's own session. This is the path
    # the one-line installer takes, and the reason it is one line.
    if not code:
        if session is None:
            typer.echo(
                f'No saved sign-in found for "{username}", so a pairing code '
                "cannot be fetched for you.\n"
                "Either sign in first (`clawmeets user login "
                f"{username}`), or paste a code from the web app:\n"
                "  clawmeets computer install --code XXXX-XXXX",
                err=True,
            )
            raise typer.Exit(1)
        code = _mint_pairing_code(session)
        if not code:
            typer.echo(
                f"Could not get a pairing code from {server_url}. Your sign-in "
                "may have expired.\n"
                f"Sign in again (`clawmeets user login {username}`), or paste a "
                "code from the web app:\n"
                "  clawmeets computer install --code XXXX-XXXX",
                err=True,
            )
            raise typer.Exit(1)

    machine = client.describe_machine()

    _print_consent()
    typer.echo("")

    try:
        response = httpx.post(
            f"{server_url}/computers/pair",
            json={
                "code": code,
                "hostname": machine["hostname"],
                "platform": machine["platform"],
                "os_version": machine["os_version"],
                "daemon_version": commands.daemon_version(),
            },
            timeout=30,
        )
    except httpx.HTTPError as e:
        typer.echo(f"Could not reach {server_url}: {e}", err=True)
        raise typer.Exit(1)

    if response.status_code != 200:
        detail = ""
        try:
            detail = response.json().get("detail", "")
        except ValueError:
            detail = response.text[:200]
        typer.echo(f"Pairing failed: {detail or response.status_code}", err=True)
        raise typer.Exit(1)

    body = response.json()
    saved = cfg.write_config(cfg.ComputerConfig(
        host_id=body["host_id"],
        token=body["token"],
        server_url=server_url,
        username=username,
    ))
    typer.echo(f"Connected as \"{body.get('name') or machine['hostname']}\".")
    typer.echo(f"  Account:   {username}")
    typer.echo(f"  Key stored at {saved} (only you can read it)")

    # Autostart BEFORE starting: registering is the step that can report a
    # problem, and a user reading this output should see it next to the pairing
    # it belongs to rather than after a "connected" line that looks like the end.
    if autostart_after:
        state = autostart.enable(username)
        if state.installed:
            typer.echo(f"  {state.detail}")
        elif state.supported:
            # Not fatal. The machine is paired and about to connect; it just
            # will not come back by itself, and saying so beats implying it will.
            typer.echo(f"  Could not set it to start at login: {state.detail}")
            typer.echo("  Run `clawmeets computer autostart enable` to retry.")

    if start_after:
        _start_detached(username)
    else:
        typer.echo("Run `clawmeets computer start` when you want it connected.")


def _start_detached(username: str) -> None:
    """Spawn the connection loop for ``username`` so it outlives this terminal.

    Reuses the runner's own detach kwargs (``start_new_session`` / Windows
    ``DETACHED_PROCESS`` + ``CREATE_NEW_PROCESS_GROUP``) rather than a second
    opinion about detaching, so the daemon and an agent behave the same way when
    the shell that started them closes — and so ``stop`` can deliver a graceful
    signal to the process group on Windows.

    The account is spelled out in the child's argv rather than left to be
    re-derived. The logged-in account can change under a process that runs for
    weeks, and a daemon that silently started reporting a different account's
    agents would be the worst possible version of this feature. It is also what
    lets the process re-exec itself after an update without losing track of who
    it is (``commands.restart_process``).
    """
    pid_file = cfg.pid_path()
    existing = read_pid(pid_file)
    if existing:
        typer.echo(f"Already connected (PID {existing}).")
        return

    pid_file.parent.mkdir(parents=True, exist_ok=True)
    argv = [sys.executable, "-m", "clawmeets_daemon.cli", "run", "--user", username]

    # The two streams go to two files, the way every other long-lived clawmeets
    # process writes them. Opened in append mode rather than the runner's
    # truncate-per-start: "why did my computer stop last night" is a question
    # about the run BEFORE this one, and size is already bounded by rotation.
    # This redirect is also the only thing that can catch an uncaught crash —
    # the ordinary lines route themselves.
    stdout_log, stderr_log = cfg.log_paths()
    with open(stdout_log, "a") as out, open(stderr_log, "a") as err:
        proc = subprocess.Popen(
            argv, stdout=out, stderr=err, **popen_detached_kwargs()
        )
    # The child writes the pidfile itself once it holds the account's lock
    # (`_claim_instance`), so the file always names the process that WON. The
    # one launchd started at login moments ago may be that process, in which
    # case this child exits at once — say which one is connected, not this one.
    pid = proc.pid
    for _ in range(30):
        running = read_pid(pid_file)
        if running:
            pid = running
            break
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    if pid != proc.pid:
        typer.echo(f"Already connected (PID {pid}).")
        return
    typer.echo(f"Connected in the background (PID {pid}).")
    typer.echo(f"  Logs: {stdout_log}")
    typer.echo(f"        {stderr_log}")


@app.command()
def start(user: Optional[str] = _USER_OPTION) -> None:
    """Start the connection to ClawMeets in the background."""
    _resolve_account(user)
    config = _require_config()
    _start_detached(config.username or cfg.active_account())


def _claim_instance():
    """Become this account's one connection on this machine, or return None.

    Two connections for one account both report to the same computer record,
    and the page shows whichever spoke last — so a login item started with a
    bare PATH and a terminal-started one with a full PATH made the model row
    flip between green and a false warning every few seconds. Nothing prevented
    it: ``computer install`` loads the login item (which launchd starts at once)
    and then starts a detached one too.

    An exclusive ``flock`` held for the life of the process, rather than a
    pidfile check: both starters race within milliseconds of each other, and
    only the kernel can make exactly one of them win. The lock dies with the
    process — including across the ``os.execv`` of an update, after which the
    new image claims it again. The returned handle must stay referenced.
    Windows has no ``fcntl``; there the pidfile check in ``_start_detached`` is
    the only guard, as before.
    """
    lock_path = cfg.computer_dir() / "computer.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(lock_path, "a")
    try:
        import fcntl
    except ImportError:
        fcntl = None
    if fcntl is not None:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            return None
    # Written by the winner itself, so `stop` / `status` see a connection that
    # launchd started, not only one this CLI spawned.
    cfg.pid_path().write_text(str(os.getpid()))
    return handle


@app.command()
def run(user: Optional[str] = _USER_OPTION) -> None:
    """Run the connection in the foreground (what ``start`` spawns).

    Exposed rather than hidden because it is the only way to watch the thing work
    while debugging a machine that will not stay connected — the background form
    writes to a log, which is a worse place to be standing when nothing is
    happening at all.
    """
    _resolve_account(user)
    config = _require_config()
    lock = _claim_instance()
    if lock is None:
        typer.echo(
            f"Already connected (PID {read_pid(cfg.pid_path()) or 'unknown'}).",
            err=True,
        )
        return
    try:
        asyncio.run(client.run(config))
    except KeyboardInterrupt:
        pass


@app.command()
def stop(user: Optional[str] = _USER_OPTION) -> None:
    """Disconnect this computer until you start it again.

    Local only. It does NOT revoke the key — the web app's "Disconnect this
    computer" does that, and the distinction matters: this is "be quiet for now",
    that is "never again without a new code". Agents already running are left
    alone either way.

    Stops the connection for ONE account. Another account's connection on the
    same machine keeps running — it is a separate process with a separate key.
    """
    _resolve_account(user)
    pid = stop_pid(cfg.pid_path())
    if pid is None:
        typer.echo("It was not running.")
        return
    typer.echo(f"Disconnected (PID {pid}). Your agents are untouched.")


@app.command()
def status(user: Optional[str] = _USER_OPTION) -> None:
    """Is this computer connected, and what is running on it?

    Reports the LOCAL truth: whether this process is alive, and what a fresh scan
    of the agents directory says. It deliberately does not ask the server —
    "what does ClawMeets think?" is the web app's job, and a status command that
    needs the network cannot answer the question you have when the network is the
    problem.
    """
    account = _resolve_account(user)
    config = cfg.read_config()
    if config is None:
        if account:
            typer.echo(f"This computer is not connected to ClawMeets for \"{account}\".")
        else:
            typer.echo("This computer is not connected to ClawMeets.")
        typer.echo("  Connect it: clawmeets computer install --code XXXX-XXXX")
        hint = _other_accounts_hint(account)
        if hint:
            typer.echo(hint.lstrip("\n"))
        raise typer.Exit(1)

    pid = read_pid(cfg.pid_path())
    typer.echo("=== This computer ===\n")
    typer.echo(f"  Server:     {config.server_url}")
    typer.echo(f"  Account:    {config.username or '(none selected)'}")
    typer.echo(f"  Connection: {f'on (PID {pid})' if pid else 'off'}")
    typer.echo(f"  Software:   {commands.daemon_version()}")
    stdout_log, stderr_log = cfg.log_paths()
    typer.echo(f"  Logs:       {stdout_log}")
    typer.echo(f"              {stderr_log}\n")

    rows = commands.snapshot(config.username)
    if not rows:
        typer.echo("  No agents are set up on this computer.")
        return
    running = sum(1 for r in rows if r["state"] == "running")
    typer.echo(f"  Agents: {running} of {len(rows)} running\n")
    for row in rows:
        word = _STATE_WORDS.get(row["state"], row["state"])
        suffix = f" (PID {row['pid']})" if row["pid"] else ""
        typer.echo(f"    {row['short_name']:30s}  {word}{suffix}")


@app.command()
def logs(
    tail: int = typer.Option(50, "--tail", "-n", help="How many lines to show."),
    user: Optional[str] = _USER_OPTION,
) -> None:
    """Show what this computer's connection has been doing.

    The first thing to reach for when a machine reads as "not answering" in the
    browser: the page can tell you contact was lost, and only this can tell you
    why.

    Both files are shown, ordinary activity first and failures last, so the
    thing most likely to explain a problem is the thing nearest the prompt. They
    are printed as two sections rather than merged: a crash lands in
    ``stderr.log`` as a multi-line traceback, and interleaving that by timestamp
    would take it apart.
    """
    _resolve_account(user)
    count = max(tail, 1)
    for path in cfg.log_paths():
        typer.echo(f"=== {path} ===")
        if not path.is_file():
            typer.echo("(nothing yet)\n")
            continue
        lines = path.read_text(errors="replace").splitlines()
        for line in lines[-count:]:
            typer.echo(line)
        typer.echo("")


@app.command()
def update(user: Optional[str] = _USER_OPTION) -> None:
    """Update ClawMeets on this computer: the runner and the connection software.

    The same action the web app's Update button triggers, run by hand. It
    upgrades ``clawmeets`` and ``clawmeets-daemon`` — each with whichever of uv
    tool / pipx / pip installed it — restarts this account's running agents if
    the runner changed, and restarts the connection if it changed.

    The packages are shared by every account on the machine, so one upgrade
    covers them all — but only the named account's agents and connection are
    restarted here, since that is the only account this command was asked about.
    """
    account = _resolve_account(user)
    result = commands.update_self(account)
    typer.echo(result.detail)
    if result.restart_required and read_pid(cfg.pid_path()):
        typer.echo("Restarting the connection so the new version takes effect…")
        stop_pid(cfg.pid_path())
        _start_detached(account)
    if not result.ok:
        raise typer.Exit(1)


autostart_app = typer.Typer(
    name="autostart",
    help="Start this computer's connection automatically when you log in.",
    no_args_is_help=True,
)
app.add_typer(autostart_app, name="autostart")


def _report(state: autostart.AutostartState) -> None:
    """Print one autostart outcome, and exit non-zero when it is not what was asked.

    ``supported=False`` exits 0: "this platform has no mechanism" is a complete,
    correct answer to the question, and a red exit would make the installer treat
    a Windows machine as a failed install.
    """
    typer.echo(state.detail)
    if state.path:
        typer.echo(f"  {state.path}")
    if state.supported and not state.installed:
        raise typer.Exit(1)


@autostart_app.command("enable")
def autostart_enable(user: Optional[str] = _USER_OPTION) -> None:
    """Start this computer's connection when you log in.

    This is on by default when you connect a computer; run it by hand after a
    `disable`, or if registering failed at install time.
    """
    account = _resolve_account(user)
    _require_config()
    _report(autostart.enable(account))


@autostart_app.command("disable")
def autostart_disable(user: Optional[str] = _USER_OPTION) -> None:
    """Stop starting this computer's connection at login.

    Leaves a running connection alone — this is about next time you log in, not
    about now. Use `clawmeets computer stop` for now.
    """
    account = _resolve_account(user)
    state = autostart.disable(account)
    typer.echo(state.detail)


@autostart_app.command("status")
def autostart_status(user: Optional[str] = _USER_OPTION) -> None:
    """Will this computer reconnect by itself after a restart?"""
    account = _resolve_account(user)
    state = autostart.status(account)
    typer.echo(state.detail)
    if state.path:
        typer.echo(f"  {state.path}")


terminal_app = typer.Typer(
    name="terminal",
    help="Allow or stop opening a shell on this computer from the web app. "
         "On by default.",
    no_args_is_help=True,
)
app.add_typer(terminal_app, name="terminal")


def _terminal_label() -> str:
    return TERMINAL_ON_LABEL if cfg.terminal_enabled() else TERMINAL_OFF_LABEL


@terminal_app.command("enable")
def terminal_enable(user: Optional[str] = _USER_OPTION) -> None:
    """Let your Computer page open a shell here, as you (the default)."""
    _resolve_account(user)
    cfg.set_terminal_enabled(True)
    typer.echo(
        "Terminal is on. You can open a shell on this computer, as you, from "
        "its page in ClawMeets.\n"
        "Turn it off again with: clawmeets computer terminal disable"
    )


@terminal_app.command("disable")
def terminal_disable(user: Optional[str] = _USER_OPTION) -> None:
    """Stop the web app from opening a shell here. Ends open sessions.

    Only a command run on this computer can turn it back on; nothing in the
    browser can.
    """
    _resolve_account(user)
    cfg.set_terminal_enabled(False)
    typer.echo(
        "Terminal is off. Any open terminal sessions end within a few seconds, "
        "and none can be opened from the web app.\n"
        "Turn it back on with: clawmeets computer terminal enable"
    )


@terminal_app.command("status")
def terminal_status(user: Optional[str] = _USER_OPTION) -> None:
    """Can the web app open a shell on this computer?"""
    _resolve_account(user)
    typer.echo(_terminal_label().replace("`", ""))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
