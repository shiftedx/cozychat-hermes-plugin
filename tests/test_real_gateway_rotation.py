"""Opt-in real gateway restart; the installed source is read only, all runtime state disposable.

COZY_HERMES_RESTART_SOURCE names a Hermes checkout and COZY_HERMES_RESTART_PYTHON an interpreter
with its dependencies. Copy source without install metadata before importing or launching Hermes.
This does not use test_hermes_admits_the_plugin, a login service, a provider, or a real profile.
"""

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path

import pytest
import psutil

SOURCE = Path(os.environ.get("COZY_HERMES_RESTART_SOURCE") or "/nonexistent")
PYTHON = Path(os.environ.get("COZY_HERMES_RESTART_PYTHON") or "/nonexistent")


@pytest.mark.skipif(not (SOURCE.joinpath("gateway/run.py").is_file() and PYTHON.is_file()),
                    reason="opt in with COZY_HERMES_RESTART_SOURCE and COZY_HERMES_RESTART_PYTHON")
def test_real_gateway_restart_rejects_old_key_and_notifies_surviving_session():
    with tempfile.TemporaryDirectory(prefix="czr", dir="/private/tmp") as directory:
        scratch = Path(directory)
        source = scratch / "src"
        excluded = shutil.ignore_patterns(".*", "venv", "node_modules", "__pycache__",
                                         "apps", "website", "tests", "skills", "logs")
        shutil.copytree(SOURCE, source, ignore=excluded)
        home, user = scratch / "h", scratch / "u"
        home.mkdir()
        user.mkdir()
        # Supply no inherited provider keys, plugin configuration or profile selector.
        environment = {"PATH": os.environ.get("PATH", ""), "HOME": str(user),
            "HERMES_HOME": str(home), "TMPDIR": str(scratch), "PYTHONDONTWRITEBYTECODE": "1",
            "HERMES_DISABLE_LAZY_INSTALLS": "1", "NO_PROXY": "127.0.0.1,localhost"}
        script = Path(__file__).with_name("real_gateway_rotation_fixture.py")
        process = subprocess.Popen([str(PYTHON), "-B", str(script), str(source)],
            cwd=scratch, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        try:
            output, _ = process.communicate(timeout=150)
        except subprocess.TimeoutExpired:
            process.send_signal(signal.SIGTERM)
            output, _ = process.communicate(timeout=30)
            pytest.fail("The isolated restart fixture timed out.")
        finally:
            # Backup for an unexpectedly killed helper. Verify both creation time and its isolated
            # environment before touching a PID; never scan or signal the user's real gateway.
            manifest = home / "fixture-processes.json"
            for record in json.loads(manifest.read_text()) if manifest.exists() else []:
                try:
                    child = psutil.Process(record["pid"])
                    child_env = child.environ()
                    if child.create_time() != record["created"] or child_env.get("HERMES_HOME") != str(home):
                        continue
                    assert child_env.get("HOME") == str(user)
                    child.terminate()
                    try:
                        child.wait(10)
                    except psutil.TimeoutExpired:
                        child.kill()
                        child.wait(5)
                except psutil.NoSuchProcess:
                    pass
            if process.poll() is None:
                process.kill()
                process.wait(5)
        # Even a failing upstream diagnostic cannot put a generated API key in pytest output.
        output = re.sub(r"\b[0-9a-fA-F]{64}\b", "<REDACTED>", output)
        assert process.returncode == 0, output
        evidence = json.loads(output.strip().splitlines()[-1])
        assert evidence == {"old_status": 401, "new_status": 200, "gateway_pid_changed": True,
                            "rotation_event": True, "surviving_noise_session": True}
