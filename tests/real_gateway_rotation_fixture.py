"""Runs only as the isolated subprocess of test_real_gateway_rotation.py."""

import asyncio
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

home = Path(os.environ["HERMES_HOME"]).resolve()
user = Path(os.environ["HOME"]).resolve()
source = Path(sys.argv[1]).resolve()
assert all(path.is_relative_to(Path("/private/tmp")) for path in (home, user, source))
assert not (source / ".git").exists() and not (source / ".hermes").exists()
sys.path.insert(0, str(source))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cozychat.relay.rotation import APIKeyRotation
from test_phone_management import paired_phone, tunnel_at
from test_tunnel_end_to_end import get, http


async def scenario():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    old = secrets.token_hex(32)
    (home / ".env").write_text(f"API_SERVER_KEY={old}\nAPI_SERVER_PORT={port}\n"
        "API_SERVER_HOST=127.0.0.1\nOPENAI_API_KEY=isolated-fixture-no-provider\n")
    (home / "config.yaml").write_text(
        "model:\n  default: fixture-model\n  provider: custom\n  base_url: http://127.0.0.1:9/v1\n"
        "gateway:\n  multiplex_profiles: false\nplatforms:\n  api_server:\n"
        f"    enabled: true\n    extra:\n      host: 127.0.0.1\n      port: {port}\n")
    log = (home / "gateway-fixture.log").open("w+")
    from hermes_cli._launchers import runtime_command
    command = runtime_command(source, ["gateway", "run"], python=sys.executable, home=str(home))
    command.insert(1, "-B")
    gateway = subprocess.Popen(command, env=dict(os.environ), cwd=home,
        stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
    processes = [gateway]
    def record_processes():
        import psutil
        (home / "fixture-processes.json").write_text(json.dumps([
            {"pid": p.pid, "created": psutil.Process(p.pid).create_time()} for p in processes
            if p.poll() is None]))
    record_processes()
    listener = a = b = None
    try:
        deadline = time.monotonic() + 60
        while await asyncio.to_thread(APIKeyRotation._status, port, old) != 200:
            assert gateway.poll() is None, "isolated gateway exited before API readiness"
            assert time.monotonic() < deadline, "isolated gateway API did not become ready"
            await asyncio.sleep(0.1)
        from gateway.status import get_running_pid
        initial_pid = get_running_pid()
        assert initial_pid == gateway.pid
        tunnel = tunnel_at(home)
        def spawn(argv, **kwargs):
            assert "API_SERVER_KEY" not in kwargs["env"]
            kwargs.update(stdout=log, stderr=log)
            # -I ignores PYTHONDONTWRITEBYTECODE; keep the dependency environment read only too.
            argv = list(argv)
            argv.insert(1, "-B")
            process = subprocess.Popen(argv, **kwargs)
            processes.append(process)
            record_processes()
            return process
        rotation = APIKeyRotation(home, spawn=spawn)
        tunnel.rotation = rotation
        tunnel.management._rotate = rotation.start
        listener = tunnel.make_listener(port=0)
        await listener.start()
        a = await paired_phone(tunnel, listener, "A")
        b = await paired_phone(tunnel, listener, "B")
        local = await b.expose_api()
        assert (await http(local, get("/v1/models", old)))[0] == 200
        result = await asyncio.to_thread(tunnel.management.revoke, a.static_public.hex(), rotate=True)
        assert result["rotation_pending"] and not result["rotated"]
        assert await asyncio.to_thread(rotation.wait, 60), "restart did not replace the cached API key"
        assert await b.next_control() == {"event": "credentials.rotated"}
        await asyncio.wait_for(a.mux.done.wait(), 1)
        assert not b.mux.done.is_set()
        fresh = (await b.request("bootstrap"))["api_key"]
        old_status = (await http(local, get("/v1/models", old)))[0]
        new_status = (await http(local, get("/v1/models", fresh)))[0]
        final_pid = get_running_pid()
        assert final_pid in [p.pid for p in processes] and final_pid != initial_pid
        print(json.dumps({"old_status": old_status, "new_status": new_status,
            "gateway_pid_changed": True, "rotation_event": True, "surviving_noise_session": True}))
    except BaseException:
        log.flush()
        log.seek(0)
        diagnostic = log.read()[-12000:]
        import re
        sys.stderr.write(re.sub(r"\b[0-9a-fA-F]{64}\b", "<REDACTED>", diagnostic))
        raise
    finally:
        if a is not None:
            await a.close()
        if b is not None:
            await b.close()
        if listener is not None:
            await listener.stop()
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                await asyncio.to_thread(process.wait, 10)
            except subprocess.TimeoutExpired:
                process.kill()
                await asyncio.to_thread(process.wait, 5)
        log.close()


async def main():
    task = asyncio.create_task(scenario())
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, task.cancel)
    await task


if __name__ == "__main__":
    asyncio.run(main())
