"""CozyChat-owned login jobs. Hermes service definitions and launchers are read-only."""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import os
import plistlib
import shlex
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional
from xml.sax.saxutils import escape

from ..devices import write_private
from .pairing import PairingStore
from .platform import service_platform

EXISTING_HERMES_NOTE = "Already kept running by your Hermes service"
CHANGED_NOTE = "Automatic startup changed outside CozyChat and was kept."
STARTUP_FAILED_NOTE = ("Hermes could not set up automatic startup, so it will not start by itself at "
                       "login. Pairing still works. Choose Pair a phone to try again.")
STATE_TTL_SECONDS = 3.0


def _receipt(handle) -> Dict[str, Any]:
    handle.seek(0)
    content = handle.read()
    stat = os.fstat(handle.fileno())
    # Identity is content plus file identity. Metadata touches (chmod, backup tools, xattrs)
    # change ctime without changing the definition, so ctime is not part of the receipt.
    return {"sha256": hashlib.sha256(content).hexdigest(), "device": stat.st_dev, "inode": stat.st_ino}


def _same(identity: Dict[str, Any], expected: Any) -> bool:
    # Receipts written by earlier builds also carry ctime_ns; ignore it.
    return isinstance(expected, dict) and all(
        identity[key] == expected.get(key) for key in ("sha256", "device", "inode"))


class HermesService:
    """Native CozyChat jobs, using upstream only for command/env and service detection."""

    def __init__(self, home: Path, *, system: Optional[str] = None,
                 load=importlib.import_module) -> None:
        self.home = Path(home).resolve()
        self.kind = service_platform(system)
        self._load = load
        suffix = hashlib.sha256(os.path.normcase(str(self.home)).encode("utf-8")).hexdigest()[:16]
        self.name = {"launchd": f"ai.cozylabs.cozychat.gateway.{suffix}",
                     "systemd": f"cozychat-gateway-{suffix}.service",
                     "windows": f"\\CozyChat\\Gateway-{suffix}"}[self.kind]

    def module(self):
        return self._load({"launchd": "hermes_cli.gateway_launchd",
                           "systemd": "hermes_cli.gateway",
                           "windows": "hermes_cli.gateway_windows"}[self.kind])

    def _gateway(self):
        gateway = self._load("hermes_cli.gateway")
        if Path(gateway.get_hermes_home()).resolve() != self.home:
            raise RuntimeError("Open CozyChat in the Hermes profile you want to connect to.")
        return gateway

    def available(self) -> bool:
        if self.kind != "systemd":
            return True
        try:
            if not self.module().supports_systemd_services():
                return False
            self.module()._preflight_user_systemd()
            return True
        except (RuntimeError, OSError):
            return False

    def hermes_installed(self) -> bool:
        gateway = self._gateway()
        if self.kind == "launchd":
            path = Path(gateway.get_launchd_plist_path())
            if not path.is_file():
                return False
            try:
                home = plistlib.loads(path.read_bytes()).get("EnvironmentVariables", {}).get("HERMES_HOME")
                return not home or Path(home).resolve() == self.home
            except (OSError, ValueError, plistlib.InvalidFileException):
                return True  # Unknown existing definitions are retained, never repaired here.
        if self.kind == "systemd":
            def same_home(path):
                if not path.is_file():
                    return False
                try:
                    for line in path.read_text("utf-8").splitlines():
                        if line.startswith("Environment="):
                            for value in shlex.split(line.partition("=")[2]):
                                if value.startswith("HERMES_HOME="):
                                    return Path(value.partition("=")[2].replace("%%", "%")).resolve() == self.home
                except (OSError, ValueError):
                    pass
                return True
            return same_home(gateway.get_systemd_unit_path(system=False)) \
                or same_home(gateway.get_systemd_unit_path(system=True)) or gateway.has_legacy_hermes_units()
        return bool(self.module().is_installed())

    def path(self) -> Path:
        if self.kind == "launchd":
            return Path(self._gateway().get_launchd_plist_path()).parent / (self.name + ".plist")
        if self.kind == "systemd":
            return self._gateway().get_systemd_unit_path(system=False).parent / self.name
        # No gateway-service or Startup launchers: the task runs Python directly.
        return self.home / "cozychat" / "relay" / (self.name.rsplit("\\", 1)[-1] + ".xml")

    def installed(self) -> bool:
        return self.path().exists() or self.kind == "windows" and self._task("query") is not None

    def command(self, environment=None):
        gateway = self._gateway()
        command = self._load("hermes_cli._launchers").runtime_command(
            gateway.PROJECT_ROOT, ["gateway", "run", "--external-supervisor"],
            python=gateway.get_python_path(), home=str(self.home))
        if self.kind == "windows":
            # Task Scheduler has no action environment; pin before upstream's bootstrap too.
            index = command.index("-c") + 1
            environment = environment or {"HERMES_HOME": str(self.home)}
            command[index] = f"import os; os.environ.update({environment!r}); " + command[index]
        return command

    def definition(self) -> bytes:
        gateway = self._gateway()
        paths = gateway._build_service_path_dirs()
        gateway._append_node_dir_for_service(paths)
        paths += [path for path in os.environ.get("PATH", "").split(os.pathsep) if path]
        env = {"HERMES_HOME": str(self.home), "PATH": os.pathsep.join(dict.fromkeys(paths)),
               "HERMES_SUPERVISED_CHILD": "1", "PYTHONIOENCODING": "utf-8"}
        command = self.command(env)
        logs = self.home / "logs"
        if self.kind == "launchd":
            command = self.module().launchd_program_arguments(
                command, logs / "cozychat-gateway.log", logs / "cozychat-gateway.err.log")
            return plistlib.dumps({"Label": self.name, "ProgramArguments": command,
                "EnvironmentVariables": env, "WorkingDirectory": str(self.home),
                "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False},
                "ThrottleInterval": 30, "ExitTimeOut": 60,
                "StandardOutPath": str(logs / "cozychat-gateway.log"),
                "StandardErrorPath": str(logs / "cozychat-gateway.err.log")})
        if self.kind == "systemd":
            def quoted(value):
                value = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
                return '"' + value.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + '"'
            return ("[Unit]\nDescription=CozyChat Hermes gateway\n\n[Service]\nType=simple\n"
                + "ExecStart=" + " ".join(quoted(arg.replace("$", "$$")) for arg in command) + "\n"
                + "WorkingDirectory=" + quoted(self.home) + "\n"
                + "".join("Environment=" + quoted(f"{key}={value}") + "\n" for key, value in env.items())
                + "Restart=on-failure\nRestartSec=5\nRestartPreventExitStatus=78\nTimeoutStopSec=60\n"
                + "\n[Install]\nWantedBy=default.target\n").encode("utf-8")
        return (f'<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            f'<RegistrationInfo><URI>urn:cozychat:{uuid.uuid4()}</URI></RegistrationInfo>'
            '<Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>'
            '<Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType>'
            '<RunLevel>LeastPrivilege</RunLevel></Principal></Principals>'
            '<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>'
            '<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>'
            '<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit>'
            '<RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure></Settings>'
            f'<Actions Context="Author"><Exec><Command>{escape(command[0])}</Command>'
            f'<Arguments>{escape(subprocess.list2cmdline(command[1:]))}</Arguments>'
            f'<WorkingDirectory>{escape(str(self.home))}</WorkingDirectory></Exec></Actions></Task>').encode("utf-8")

    def _run(self, command, *, check=True):
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=30)
        if check and result.returncode:
            raise RuntimeError("Hermes could not change automatic startup. Try again.")
        return result

    def _task(self, action: str, expected: Optional[str] = None):
        # COM returns the created RegisteredTask object. Hash its XML before releasing it;
        # never adopt a later query's replacement as our receipt. TASK_CREATE (2) is exclusive.
        def literal(value):
            return "'" + str(value).replace("'", "''") + "'"
        leaf = self.name.rsplit("\\", 1)[-1]
        script = ("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new(); "
            "$s=New-Object -ComObject Schedule.Service; $s.Connect(); "
            "function Fingerprint($t) { $h=[Security.Cryptography.SHA256]::Create(); "
            "([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($t.Xml)))).Replace('-','').ToLower() }; "
            "try {$f=$s.GetFolder('\\CozyChat')} catch {"
            + ("$f=$s.GetFolder('\\').CreateFolder('CozyChat')" if action == "create" else "'null'; exit") + "}; ")
        if action == "create":
            script += (f"$xml=[IO.File]::ReadAllText({literal(self.path())}); "
                f"$t=$f.RegisterTask({literal(leaf)},$xml,2,[Security.Principal.WindowsIdentity]::GetCurrent().Name,$null,3); "
                "@{sha256=(Fingerprint $t)} | ConvertTo-Json -Compress")
        else:
            script += f"try {{$t=$f.GetTask({literal(leaf)})}} catch {{'null'; exit}}; "
            if action == "query":
                script += "@{sha256=(Fingerprint $t)} | ConvertTo-Json -Compress"
            elif action == "run":
                script += "$null=$t.Run($null); 'true'"
            else:
                # Compare the registered definition right before DeleteTask. The task is never
                # stopped: a running gateway keeps running. No upstream cleanup touches
                # Startup/legacy artifacts.
                script += (f"if ((Fingerprint $t) -ne {literal(expected)}) {{'false'; exit}}; "
                    f"$f.DeleteTask({literal(leaf)},0); 'true'")
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        result = self._run(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded])
        return json.loads(result.stdout.strip())

    def file_matches(self, expected: Dict[str, Any]) -> bool:
        try:
            with self.path().open("rb") as handle:
                return _same(_receipt(handle), expected.get("file")) and not self.path().is_symlink()
        except OSError:
            return False

    def matches(self, expected: Dict[str, Any]) -> bool:
        if not self.file_matches(expected):
            return False
        try:
            return self.kind != "windows" or bool(expected.get("task")) \
                and self._task("query") == expected["task"]
        except OSError:
            return False

    def registered(self) -> bool:
        """Whether the native job is registered/loaded, not merely whether its file exists."""
        if self.kind == "launchd":
            return self._run(["launchctl", "print", f"gui/{os.getuid()}/{self.name}"],
                             check=False).returncode == 0
        if self.kind == "systemd":
            return self._run(["systemctl", "--user", "is-enabled", self.name],
                             check=False).returncode == 0
        return self._task("query") is not None

    def register(self) -> Optional[Dict[str, Any]]:
        """Register the definition already on disk. Returns the Windows task receipt."""
        if self.kind == "windows":
            return self._task("create")
        if self.kind == "systemd":
            self._run(["systemctl", "--user", "daemon-reload"])
            self._run(["systemctl", "--user", "enable", self.name])
        else:
            # A previous Keep reachable off leaves the label disabled; bootstrap refuses those.
            self._run(["launchctl", "enable", f"gui/{os.getuid()}/{self.name}"], check=False)
            # Keep reachable off never boots the job out, so a gateway it started is still loaded
            # when the person turns it back on. bootstrap refuses a loaded label (EIO), and that
            # job is already ours and running; the definition on disk loads at next login.
            if not self.registered():
                self._run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(self.path())])
        return None

    def discard(self, expected: Dict[str, Any]) -> bool:
        """Remove our never-registered definition, only if it is still the file we wrote."""
        try:
            removed = self.file_matches(expected) and self._unlink(expected)
            if removed and self.kind == "systemd":
                self._run(["systemctl", "--user", "daemon-reload"], check=False)
            return removed
        except (OSError, RuntimeError, subprocess.SubprocessError):
            return False

    def install(self) -> Optional[Dict[str, Any]]:
        if self.hermes_installed() or self.installed():
            return None
        content, path = self.definition(), self.path()
        path.parent.mkdir(parents=True, exist_ok=True)
        (self.home / "logs").mkdir(parents=True, exist_ok=True)
        # Publish complete bytes with a no-replace link, keeping the created handle for fstat.
        fd, temporary = tempfile.mkstemp(prefix=".cozychat-", dir=path.parent)
        try:
            with os.fdopen(fd, "w+b") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
                try:
                    os.link(temporary, path)
                except FileExistsError:
                    return None
                os.unlink(temporary)
                created = {"file": _receipt(handle)}
        finally:
            Path(temporary).unlink(missing_ok=True)
        # Never register bytes that are no longer the ones we wrote.
        if not self.file_matches(created):
            return created
        try:
            task = self.register()
        except (RuntimeError, OSError, subprocess.SubprocessError):
            self.discard(created)  # no orphan definition for a retry to trip over
            raise
        if task is not None:
            created["task"] = task
        return created

    def _unlink(self, expected: Dict[str, Any]) -> bool:
        path = self.path()
        try:
            with path.open("rb") as handle:
                identity = _receipt(handle)
                if not _same(identity, expected.get("file")):
                    return False
                # Windows needs the read handle closed before unlink. Recheck the path after
                # that close too; POSIX keeps the verified handle open through removal.
                if self.kind == "windows":
                    handle.close()
                current = path.stat(follow_symlinks=False)
                if stat.S_ISLNK(current.st_mode) or (current.st_dev, current.st_ino) != (
                        identity["device"], identity["inode"]):
                    return False
                path.unlink()
                return True
        except FileNotFoundError:
            return True

    def uninstall(self, expected: Dict[str, Any]) -> bool:
        if not self.matches(expected):
            return False
        # Only remove start-at-login. A gateway that is running right now keeps running, so
        # a phone mid-chat is never dropped: no bootout, no stop.
        if self.kind == "launchd":
            self._run(["launchctl", "disable", f"gui/{os.getuid()}/{self.name}"], check=False)
        elif self.kind == "systemd":
            self._run(["systemctl", "--user", "disable", "--no-reload", self.name])
        elif not self._task("remove", expected["task"]["sha256"]):
            return False
        removed = self._unlink(expected)
        if removed and self.kind == "systemd":
            self._run(["systemctl", "--user", "daemon-reload"])
        return removed

    def start(self) -> None:
        if self.kind == "launchd":
            self._run(["launchctl", "kickstart", f"gui/{os.getuid()}/{self.name}"])
        elif self.kind == "systemd":
            self._run(["systemctl", "--user", "start", self.name])
        elif self._task("run") is None:
            raise RuntimeError("Hermes could not start its login job. Try again.")


class Reachable:
    def __init__(self, store: PairingStore, service: Optional[HermesService] = None,
                 *, clock=time.monotonic) -> None:
        self.store = store
        self.service = service or HermesService(store.root.parent.parent)
        self._clock = clock
        self._cached: Optional[tuple] = None

    @property
    def path(self) -> Path:
        return self.store.root / "reachable.json"

    def read(self) -> Dict[str, Any]:
        try:
            data = json.loads(self.path.read_text("utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def state(self) -> Dict[str, Any]:
        # The page polls this; on Windows each uncached read launches PowerShell.
        now = self._clock()
        if self._cached is not None and now - self._cached[0] < STATE_TTL_SECONDS:
            return dict(self._cached[1])
        value = self._state()
        self._cached = (now, value)
        return dict(value)

    def _state(self) -> Dict[str, Any]:
        if self.service.hermes_installed():
            return {"enabled": True, "installed": True, "owned": False,
                    "editable": False, "note": EXISTING_HERMES_NOTE}
        receipt = self.read()
        owned = receipt.get("kind") == self.service.kind and bool(receipt.get("definition")) \
            and self.service.matches(receipt["definition"])
        return {"enabled": bool(receipt.get("enabled", True)),
                "installed": self.service.installed(), "owned": bool(owned),
                "editable": True, "note": receipt.get("note")}

    def _turn_on(self, receipt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if self.service.installed():
            definition = receipt.get("definition") if receipt.get("kind") == self.service.kind else None
            if definition and self.service.file_matches(definition) and not self.service.registered():
                # Our definition is on disk but the job is not loaded (an earlier bootstrap or
                # enable failed). Retry; if it still fails, remove our orphan so the next try
                # starts clean instead of believing it is installed.
                try:
                    task = self.service.register()
                except (RuntimeError, OSError, subprocess.SubprocessError):
                    self.service.discard(definition)
                    raise
                if task is not None:
                    definition["task"] = task
            receipt["enabled"] = True
            return receipt
        if not self.service.available():
            return {"enabled": False, "note":
                    "Keep Hermes running to stay connected. This computer cannot "
                    "start Hermes automatically at login."}
        created = self.service.install()
        if created is None and self.service.hermes_installed():
            return None  # a Hermes service appeared meanwhile: leave it and write no receipt
        if not self.service.installed():
            raise RuntimeError("Hermes could not turn on automatic startup. Try again.")
        receipt = {"enabled": True}
        if created is not None and self.service.matches(created):
            receipt.update({"kind": self.service.kind, "definition": created})
        else:
            receipt["note"] = CHANGED_NOTE
        return receipt

    def set(self, enabled: bool) -> Dict[str, Any]:
        with self.store.locked():
            self._cached = None
            # An existing Hermes service is never edited, even if an old receipt claimed it.
            if self.service.hermes_installed():
                return self._state()
            receipt = self.read()
            if enabled:
                # Keep reachable is a convenience. A native failure is recorded as plain text
                # and never stops pairing.
                try:
                    receipt = self._turn_on(receipt)
                    if receipt is None:
                        return self._state()
                except (RuntimeError, OSError, subprocess.SubprocessError):
                    if self.service.hermes_installed():
                        return self._state()
                    kept = {key: receipt[key] for key in ("kind", "definition")
                            if key in receipt and self.service.installed()}
                    receipt = {"enabled": True, "note": STARTUP_FAILED_NOTE, **kept}
            else:
                installed = self.service.installed()
                expected = receipt.get("definition") if receipt.get("kind") == self.service.kind else None
                removed = not installed or bool(expected) and self.service.uninstall(expected)
                receipt = {"enabled": False}
                if installed and not removed:
                    receipt["note"] = CHANGED_NOTE
            write_private(self.path, json.dumps(receipt, sort_keys=True).encode("utf-8"))
            self._cached = None
        return self._state()
