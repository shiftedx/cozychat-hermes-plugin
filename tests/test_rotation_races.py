"""Independent processes contend on the real cross-platform rotation lock."""

import json
import multiprocessing
from pathlib import Path

from cozychat.relay.services import discover_api
from test_key_rotation import rotation_for
from test_phone_management import tunnel_at


def install_secret_scope():
    """A spawned process has no conftest: stand in for ``agent.secret_scope`` (D34)."""
    import sys
    import types
    agent, scope = types.ModuleType("agent"), types.ModuleType("agent.secret_scope")

    def build(home):
        out = {}
        for line in (Path(home) / ".env").read_text().splitlines():
            if "=" in line:
                name, _, value = line.partition("=")
                out[name.strip()] = value.strip()
        return out

    scope.build_profile_secret_scope = build
    agent.secret_scope = scope
    sys.modules["agent"], sys.modules["agent.secret_scope"] = agent, scope


def rotate_in_process(home, entered, resume, attempting, results):
    install_secret_scope()
    tunnel = tunnel_at(Path(home))
    rotation = rotation_for(tunnel, lambda *a, **kw: (tunnel.home / "restarts").open("a").write("restart\n"))
    load = rotation._load
    config = load("hermes_cli.config")
    save = config.save_env_value
    def paused_save(*args):
        if entered is not None:
            entered.set()
            assert resume.wait(10)
        save(*args)
    config.save_env_value = paused_save
    attempting.set()
    result = rotation.start()
    results.put((result, rotation._new, discover_api(tunnel.home).key))


def test_concurrent_process_rotations_coalesce_and_all_copies_advertise_final_key(tmp_path):
    home = tmp_path / "hermes"
    home.mkdir()
    (home / ".env").write_text("API_SERVER_KEY=old-api-key-0123456789\n")
    context = multiprocessing.get_context("spawn")
    entered, resume = context.Event(), context.Event()
    first_started, second_started = context.Event(), context.Event()
    results = context.Queue()
    first = context.Process(target=rotate_in_process,
        args=(str(home), entered, resume, first_started, results))
    second = context.Process(target=rotate_in_process,
        args=(str(home), None, None, second_started, results))
    first.start()
    try:
        assert entered.wait(10)
        second.start()
        assert second_started.wait(10)
        resume.set()
        first.join(10)
        second.join(10)
        assert first.exitcode == second.exitcode == 0
        answers = [results.get(timeout=2), results.get(timeout=2)]
        final = discover_api(home, {}).key
        assert all(new == advertised == final for _, new, advertised in answers)
        assert (home / "restarts").read_text().splitlines() == ["restart"]
        marker = json.loads((home / "cozychat/relay/key-rotation.json").read_text())
        assert marker["pending"] and len(marker["retired"]) == 1
    finally:
        resume.set()
        for process in (first, second):
            if process.pid is not None and process.is_alive():
                process.terminate()
                process.join(5)
        results.close()
