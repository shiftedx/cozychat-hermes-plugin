"""The plugin's real tunnel listener, driven over stdin and stdout, for the Swift interop test.

``CozyKit/Tests/CozyRelayTunnelTests/PluginInteropTests.swift`` launches this as a subprocess and
plays the phone with the app's own ``CozyRelayTunnel``. Run ``Scripts/test-tunnel-interop.sh``
rather than either half by hand.

The listener is the production ``Listener`` with the production pairing store, Noise, framing, mux
and services. The only test seam is ``ListenerConfig.interfaces`` (``tunnel_phone.loopback_binds``),
the loopback override no plugin config key, environment variable or CLI flag can set.

Behind the ``api`` service sits one of three API Servers:

- ``--api fake`` (default): the loopback fake from ``test_tunnel_end_to_end.py``. Needs only the
  plugin's dev requirements, so CI can run it.
- ``--api hermes``: Hermes's own API Server routes and agent with a deterministic local model,
  through ``Scripts/hermes-direct-test-server.py``. Needs ``COZY_HERMES_CHECKOUT`` (a copy of the
  Hermes source without ``.git``, never ``~/.hermes/hermes-agent`` itself) and
  ``COZY_HERMES_PYTHON`` (an interpreter with Hermes's dependencies). The fixture runs under a
  throwaway ``HERMES_HOME`` in a short ``/tmp`` directory; it never sees the user's ``~/.hermes``.
- ``--api resume``: a separate ``resume_api.py`` process with SSE ids and a durable fixture journal.
  Restarting it drops its replay buffer while preserving status and history.

Protocol, one JSON object per line:

- stdout ``{"link": ..., "reply_marker": ...}`` once the listener is up. ``reply_marker`` is text the
  run's SSE stream must contain.
- stdout ``{"code": "123456", "phone_name": ...}`` once a phone has proved the psk with its first
  frame and is waiting for the person (P1).
- stdin ``{"approve": "123456"}``: the person compares the codes. The host approves only if the code
  is the one it computed; anything else refuses (close code 7).
- stdout ``{"decision": "approved"}`` or ``{"decision": "refused"}``.
- stdin ``{"op": "drop"}`` / ``{"op": "restore"}`` stops / restarts the real listener at its
  original hint port; stdout acknowledges with ``{"done": "<op>"}``.
- In resume mode, ``advance`` finishes the producer, ``scenario`` with ``value`` sets ``ignore``
  or ``truncated`` behavior, or ``restart`` replaces the API process (the acknowledgement includes
  both PIDs). ``inspect`` returns observed resume headers/query values and the submission count.
- stdin EOF ends the harness; it then stops the listener and the API Server and exits 0.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent))

from cozychat.relay import pairing  # noqa: E402
from cozychat.relay.host import Listener, ListenerConfig  # noqa: E402
from cozychat.relay.pairing import PairingStore  # noqa: E402
from cozychat.relay.services import ApiTarget, capability_document  # noqa: E402
from cozychat.relay.files import FileService  # noqa: E402

from test_tunnel_end_to_end import FIXTURE_SCRIPT, fake_api  # noqa: E402
from tunnel_phone import loopback_binds  # noqa: E402
from resume_api import ResumeAPI  # noqa: E402

FAKE_REPLY = "fake reply through the tunnel"
HERMES_REPLY = "Hermes direct reply"


def emit(message: dict) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


class HermesFixture:
    """``Scripts/hermes-direct-test-server.py`` in a subprocess, under a throwaway HERMES_HOME."""

    def __init__(self) -> None:
        checkout = Path(os.environ.get("COZY_HERMES_CHECKOUT") or "/nonexistent")
        python = Path(os.environ.get("COZY_HERMES_PYTHON") or "/nonexistent")
        if not ((checkout / "gateway").is_dir() and python.is_file()):
            raise SystemExit("--api hermes needs COZY_HERMES_CHECKOUT and COZY_HERMES_PYTHON")
        if checkout.resolve() == (Path.home() / ".hermes" / "hermes-agent").resolve():
            raise SystemExit("COZY_HERMES_CHECKOUT must be a copy, not ~/.hermes/hermes-agent")
        self.short = Path(tempfile.mkdtemp(prefix="czt", dir="/tmp"))  # AF_UNIX paths stay short
        fixture = self.short / "fixture.json"
        env = {k: v for k, v in os.environ.items() if not k.startswith(("HERMES_", "API_SERVER_"))}
        env["TMPDIR"] = str(self.short)
        env["HERMES_HOME"] = str(self.short / "home")  # the fixture replaces it with its own temp dir
        # And `~` itself is a throwaway, so nothing that expands it can reach the user's ~/.hermes.
        (self.short / "user").mkdir()
        env["HOME"] = str(self.short / "user")
        env["HERMES_DISABLE_LAZY_INSTALLS"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        self.process = subprocess.Popen(
            [str(python), "-B", str(FIXTURE_SCRIPT), str(checkout), str(fixture)],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=str(self.short))
        deadline = time.monotonic() + 120
        while not fixture.exists():
            if self.process.poll() is not None:
                raise SystemExit("the Hermes fixture exited: " + (self.process.stdout.read() or ""))
            if time.monotonic() > deadline:
                self.stop()
                raise SystemExit("the Hermes fixture did not start")
            time.sleep(0.2)
        time.sleep(0.2)
        config = json.loads(fixture.read_text())
        self.target = ApiTarget(port=int(config["url"].rsplit(":", 1)[1]), key=config["key"])

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(20)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)
        shutil.rmtree(self.short, ignore_errors=True)


class ResumeFixture:
    """A separate fake API Server process; a restart really loses its in-memory SSE buffer."""

    def __init__(self):
        self.scratch = Path(tempfile.mkdtemp(prefix="czr"))
        self.port = 0

    async def start(self):
        self.process = await asyncio.create_subprocess_exec(
            sys.executable, "-B", str(Path(__file__).with_name("resume_api.py")),
            "--state", str(self.scratch / "durable.json"), "--port", str(self.port),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
        self.port = json.loads(await self.process.stdout.readline())["port"]

    async def command(self, op, **fields):
        self.process.stdin.write((json.dumps({"op": op, **fields}) + "\n").encode())
        await self.process.stdin.drain()
        return json.loads(await self.process.stdout.readline())

    async def restart(self):
        old_pid = self.process.pid
        await self.stop()
        await self.start()
        return {"previous_pid": old_pid, "pid": self.process.pid}

    async def stop(self):
        self.process.stdin.close()
        try:
            await asyncio.wait_for(self.process.wait(), 5)
        except TimeoutError:
            self.process.kill()
            await self.process.wait()
            raise

    async def finish(self):
        await self.stop()
        shutil.rmtree(self.scratch, ignore_errors=True)


async def main(arguments: argparse.Namespace) -> int:
    async def read_line():
        return await asyncio.to_thread(sys.stdin.buffer.readline)

    hermes = None
    server = None
    resume = None
    if arguments.api == "hermes":
        hermes = await asyncio.to_thread(HermesFixture)
        target, marker = hermes.target, HERMES_REPLY
    elif arguments.api == "resume":
        resume = ResumeFixture()
        await resume.start()
        target, marker = ApiTarget(port=resume.port, key=ResumeAPI.key), ResumeAPI.reply
    else:
        server, port = await fake_api(lambda: tunnel.api().key if arguments.phone_management
                                      else "interop-fake-key")
        target, marker = ApiTarget(port=port, key="interop-fake-key"), FAKE_REPLY

    state = Path(tempfile.mkdtemp(prefix="czp", dir="/tmp"))
    home = state / "hermes"
    user = state / "user"
    home.mkdir()
    user.mkdir()
    files = FileService(home, user_home=user, allowed_roots=[user, state], plugin_state=state / "relay")
    paths = {}
    if arguments.files:
        # No Hermes process or user files: a sparse movie and a symlink to a scratch private key.
        sparse = state / "movie.mp4"
        offset = 2 * 1024**3 - 8192
        with sparse.open("wb") as handle:
            handle.truncate(2 * 1024**3)
            handle.seek(offset)
            handle.write(b"sparse window")
        secret = user / ".ssh" / "id_ed25519"
        secret.parent.mkdir()
        secret.write_bytes(b"never send this private key")
        alias = state / "innocent.png"
        alias.symlink_to(secret)
        hardlink = state / "hardlink.png"
        os.link(secret, hardlink)
        private_state = home / "cozychat" / "devices.json"
        private_state.parent.mkdir()
        private_state.write_bytes(b"never send phone credentials")
        state_alias = state / "state-alias"
        state_alias.symlink_to(private_state.parent, target_is_directory=True)
        paths = {"hardlink": str(hardlink), "plugin_state": str(private_state),
                 "state_alias": str(state_alias / "devices.json"), "sparse": str(sparse), "offset": offset, "symlink": str(alias),
                 "secret": str(secret), "home": str(home.resolve())}
    store = PairingStore(state / "relay")
    tunnel = None
    if arguments.phone_management:
        # D34: credentials come only from Hermes's secret scope. This harness has no Hermes install,
        # so a stub that reads the scratch home's .env stands in for ``agent.secret_scope``.
        import types
        agent, scope = types.ModuleType("agent"), types.ModuleType("agent.secret_scope")

        def build_scope(home):
            values = {}
            for line in (Path(home) / ".env").read_text().splitlines():
                if "=" in line:
                    name, _, value = line.partition("=")
                    values[name.strip()] = value.strip()
            return values

        scope.build_profile_secret_scope = build_scope
        agent.secret_scope = scope
        sys.modules["agent"], sys.modules["agent.secret_scope"] = agent, scope
        from test_phone_management import tunnel_at, approve as approve_phone
        from test_key_rotation import rotation_for
        # A test-only lifecycle stand-in, never a Hermes command. The listener/control path is
        # production; the API fixture reads the credential persisted by the rotation adapter.
        tunnel = tunnel_at(state / "hermes")
        (tunnel.home / ".env").write_text(f"API_SERVER_KEY={target.key}\nAPI_SERVER_PORT={target.port}\n")
        store = tunnel.store
        tunnel.rotation = rotation_for(tunnel, lambda *args, **kw: None)
        tunnel.management._rotate = tunnel.rotation.start
    window = store.open_window()
    listener = tunnel.make_listener(port=0) if tunnel else Listener(
                        store, ListenerConfig(port=0, interfaces=loopback_binds),
                        capabilities=lambda hints: capability_document(
                            plugin_version="0.6.0", state_version="shared-v1", lan_addresses=hints,
                            push_available=False, push_paired=False, files=files.capabilities()),
                        api=lambda: target, files=files)
    await listener.start()
    try:
        ready = {"link": pairing.pairing_link(store.host_public(), window, listener.hints()),
                 "reply_marker": marker, "files": paths}
        if resume is not None:
            ready["partial_reply"] = ResumeAPI.partial_reply
        emit(ready)
        while (attempt := await asyncio.to_thread(store.attempt)) is None:
            await asyncio.sleep(0.05)
        emit({"code": attempt.code, "phone_name": attempt.phone_name})
        line = await read_line()
        answer = json.loads(line) if line.strip() else {}
        approve = answer.get("approve") == attempt.code
        await asyncio.to_thread(store.decide, attempt.id, approve)
        emit({"decision": "approved" if approve else "refused"})
        while line := await read_line():
            command = json.loads(line)
            if tunnel and "add_phone" in command:
                from cozychat.relay import noise
                private = noise.generate_private_key()
                approve_phone(store, noise.public_key(private), command["add_phone"])
                window = store.open_window()
                link = pairing.pairing_link(store.host_public(), window, listener.hints())
                store.cancel_window()
                emit({"link": link, "phone_private": private.hex()})
                continue
            if tunnel and "revoke_phone" in command:
                result = await asyncio.to_thread(tunnel.management.revoke, command["revoke_phone"],
                                                 rotate=command.get("rotate", False))
                emit(result)
                continue
            op = command.get("op")
            if op == "drop":
                await listener.stop()
                # Rebind the exact hint port after the old listening sockets have closed.
                listener.config.port = listener.port
            elif op == "restore":
                await listener.start()
            elif op == "advance" and resume is not None:
                await resume.command("advance")
            elif op == "scenario" and resume is not None:
                if command["value"] == "restart":
                    pids = await resume.restart()
                    emit({"done": op, **pids})
                    continue
                await resume.command("scenario", value=command["value"])
            elif op == "inspect" and resume is not None:
                emit(await resume.command("inspect"))
                continue
            emit({"done": op})
    finally:
        await listener.stop()
        if server is not None:
            server.close()
            await server.wait_closed()
        if resume is not None:
            await resume.finish()
        if hermes is not None:
            await asyncio.to_thread(hermes.stop)
        shutil.rmtree(state, ignore_errors=True)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--api", choices=("fake", "hermes", "resume"), default="fake")
    parser.add_argument("--files", action="store_true", help="create isolated sparse-file and policy fixtures")
    parser.add_argument("--phone-management", action="store_true")
    sys.exit(asyncio.run(main(parser.parse_args())))
