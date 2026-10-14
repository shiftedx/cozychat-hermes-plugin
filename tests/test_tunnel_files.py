"""File policy, bounded reads, atomic uploads, and routing through the production listener."""

import asyncio
import hashlib
import json
import os
import re
import sys
from collections import deque
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from cozychat.relay import files, runtime
from cozychat.relay.mux import StreamClose
from test_tunnel_hardening import approved_phone, run
from tunnel_phone import Phone, loopback_binds


class MemoryStream:
    def __init__(self, args, chunks=()):
        self.args = args
        self.chunks = deque(chunks)
        self.output = bytearray()
        self.code = None
        self.reason = None

    async def read(self):
        return self.chunks.popleft() if self.chunks else b""

    async def write(self, chunk):
        self.output.extend(chunk)

    async def close(self, code, reason=""):
        self.code, self.reason = code, reason


@pytest.fixture
def service(tmp_path, request):
    if not files.platform_supported() and request.node.originalname not in (
            "test_native_windows_files_capability_is_off", "test_native_windows_junction_never_enables_or_reaches_files"):
        pytest.skip("POSIX files service; native Windows intentionally has no files capability")
    home = tmp_path / "hermes"
    home.mkdir()
    return files.FileService(home, user_home=tmp_path / "user", allowed_roots=[tmp_path])


def upload_args(data=b"document", name="report.pdf"):
    return {"op": "put", "name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def test_denylist_matches_the_app_ssh_reader_exactly():
    swift = Path(__file__).resolve().parents[4] / "CozyKit/Sources/CozyRelayTunnel/TunnelFilesClient.swift"
    if not swift.is_file():
        pytest.skip("needs CozyKit/Sources/CozyRelayTunnel/TunnelFilesClient.swift, which exists only in the CozyChat monorepo")
    source = swift.read_text()
    for label, expected in (("deniedTrees", files.DENIED_TREES),
                            ("deniedDirectories", files.DENIED_DIRECTORIES),
                            ("deniedNames", files.DENIED_NAMES),
                            ("deniedSuffixes", files.DENIED_SUFFIXES)):
        literal = source.split("private static let " + label, 1)[1].split("]", 1)[0]
        assert set(re.findall(r'"([^"\n]+)"', literal)) == set(expected)


@pytest.mark.parametrize("path", [
    "/etc/passwd", "/var/lib/db", "/proc/self/environ", "~/.ssh/id_ed25519",
    "~/.AWS/token", "/outputs/.gnupg/key", "/outputs/.kube/config", "/outputs/.docker/auth",
    "/outputs/.config/key", "/outputs/.azure/key", "/outputs/.gcloud/key", "/outputs/keychains/a",
    "/outputs/mcp-tokens/a", "/outputs/pairing/a", "/outputs/browser-profile/a",
    "/outputs/vault/a", "/outputs/sessions/a", "/outputs/state.db-wal",
    "/outputs/state.db-shm", "/outputs/state.db-journal", "/outputs/.env", "/outputs/.env.production",
    "/outputs/.envrc", "/outputs/id_rsa", "/outputs/server.pem", "/outputs/server.key",
    "/outputs/server.p12", "/outputs/server.pfx", "/outputs/login.keychain-db",
    "/outputs/auth.json", "/outputs/config.yaml", "/outputs/known_hosts", "/outputs/credentials",
    "C:\\Users\\phone\\.ssh\\id_ed25519", "C:\\Users\\phone\\.aws\\credentials",
    "~/.ssh/authorized_keys", "/Users/phone/.ssh/authorized_keys",
    "/home/phone/.ssh/authorized_keys2", "C:\\Users\\phone\\.ssh\\authorized_keys",
    "/etc/ssh/authorized_keys/phone", "/root/.ssh/authorized_keys",
])
def test_credential_shapes_are_refused(path):
    assert files.credential_path(path)


@pytest.mark.parametrize("path", ["/outputs/report.pdf", "~/Pictures/cat.png", "/outputs/keys.txt"])
def test_ordinary_media_is_not_credential_material(path):
    assert not files.credential_path(path)


def test_native_path_rules_refuse_windows_streams_and_preserve_posix_colons():
    files._safe(PurePosixPath("/outputs/movie:part-one.mp4"))
    files._safe(PureWindowsPath(r"C:\outputs\movie.mp4"))
    with pytest.raises(files.FilePolicyError):
        files._safe(PureWindowsPath(r"C:\outputs\movie.mp4:secret"))
    with pytest.raises(files.FilePolicyError):
        files._safe(PureWindowsPath(r"\\server\share\movie.mp4"))


def test_stat_does_not_read_and_range_reads_only_the_window(service, tmp_path):
    sparse = tmp_path / "film.mp4"
    offset = 2 * 1024**3 - 16384
    with sparse.open("wb") as handle:
        handle.truncate(2 * 1024**3)
        handle.seek(offset)
        handle.write(b"window marker")
    stat_stream = MemoryStream({"op": "stat", "path": str(sparse)})
    run(service.serve(stat_stream))
    assert json.loads(stat_stream.output)["size"] == 2 * 1024**3
    read = MemoryStream({"op": "read_range", "path": str(sparse), "offset": offset, "length": 256})
    run(service.serve(read))
    header, body = bytes(read.output).split(b"\n", 1)
    assert json.loads(header) == {"ok": True, "size": 256, "total_size": 2 * 1024**3}
    assert body == b"window marker" + bytes(256 - len(b"window marker"))
    assert len(read.output) < 512


@pytest.mark.parametrize("op", ["stat", "read_range"])
def test_symlink_to_credentials_and_normalized_escape_are_refused(service, tmp_path, op):
    secret = service.user_home / ".ssh" / "id_ed25519"
    secret.parent.mkdir(parents=True)
    secret.write_bytes(b"secret")
    alias = tmp_path / "innocent.png"
    try:
        alias.symlink_to(secret)
    except OSError as exc:
        pytest.skip(f"symlinks need OS permission: {exc}")
    for path in (str(alias), str(tmp_path / "outputs" / ".." / "user" / ".ssh" / "id_ed25519")):
        stream = MemoryStream({"op": op, "path": path, "offset": 0, "length": 16})
        run(service.serve(stream))
        assert stream.code == StreamClose.POLICY
        assert not stream.output


def test_even_safe_symlinks_are_refused(service, tmp_path):
    photo = tmp_path / "photo.png"
    photo.write_bytes(b"picture")
    alias = tmp_path / "alias.png"
    try:
        alias.symlink_to(photo)
    except OSError as exc:
        pytest.skip(f"symlinks need OS permission: {exc}")
    stream = MemoryStream({"op": "read_range", "path": str(alias), "offset": 3, "length": 99})
    run(service.serve(stream))
    assert stream.code == StreamClose.POLICY
    assert not stream.output


@pytest.mark.parametrize("path", ["/private/etc/passwd", "/private/var/log/system.log"])
def test_canonical_macos_system_tree_aliases_are_also_denied(service, path):
    stream = MemoryStream({"op": "stat", "path": path})
    run(service.serve(stream))
    assert stream.code == StreamClose.POLICY
    assert not stream.output


def test_leaf_symlink_swap_is_refused_before_any_read(service, tmp_path, monkeypatch):
    safe = tmp_path / "picture.png"
    safe.write_bytes(b"picture")
    secret = tmp_path / "secret.png"
    secret.write_bytes(b"secret")
    real_open = os.open

    def swapped(path, flags, *args, **kwargs):
        if path == safe.name:
            safe.unlink()
            safe.symlink_to(secret)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(files.os, "open", swapped)
    stream = MemoryStream({"op": "read_range", "path": str(safe), "offset": 0, "length": 16})
    run(service.serve(stream))
    assert stream.code == StreamClose.POLICY
    assert not stream.output


def test_double_ancestor_swap_stays_on_the_open_directory(service, tmp_path, monkeypatch):
    directory = tmp_path / "outputs"
    directory.mkdir()
    (directory / "picture.png").write_bytes(b"picture")
    secret = tmp_path / "secrets"
    secret.mkdir()
    (secret / "picture.png").write_bytes(b"secret")
    saved = tmp_path / "saved"
    real_open = os.open
    swaps = []

    def opened(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if path == "outputs":
            directory.rename(saved)
            directory.symlink_to(secret, target_is_directory=True)
            swaps.append("redirect after ancestor open")
        elif path == "picture.png":
            directory.unlink()
            saved.rename(directory)
            directory.rename(saved)
            directory.symlink_to(secret, target_is_directory=True)
            swaps.append("restore then redirect after leaf open")
        return fd

    monkeypatch.setattr(files.os, "open", opened)
    stream = MemoryStream({"op": "read_range", "path": str(directory / "picture.png"), "offset": 0, "length": 16})
    run(service.serve(stream))
    assert len(swaps) == 2
    assert bytes(stream.output).split(b"\n", 1)[1] == b"picture"


@pytest.mark.parametrize("args", [
    {"op": "read_range", "path": "/tmp/a", "offset": -1, "length": 1},
    {"op": "read_range", "path": "/tmp/a", "offset": 0, "length": files.WINDOW_LIMIT + 1},
    {"op": "read_range", "path": "/tmp/a", "offset": True, "length": 1},
    {"op": "stat", "path": "relative.png"}, {"op": "stat", "path": "/tmp/a\0b"},
    {"op": "unknown"},
    {**upload_args(), "size": files.MAX_BYTES + 1}, {**upload_args(), "size": 0},
    {**upload_args(), "size": True}, {**upload_args(), "sha256": "not-a-hash"},
])
def test_invalid_arguments_fail_before_io(service, args):
    stream = MemoryStream(args)
    run(service.serve(stream))
    assert stream.code == StreamClose.POLICY
    assert not stream.output


@pytest.mark.parametrize("name", ["../escape.pdf", "a/b", "a\\b", "a\0b", ".", "..", "a:stream",
                                 ".env", "state.db-wal", "id_ed25519", "private.key", "credentials"])
def test_upload_leaf_traversal_and_credential_names_are_refused(service, name):
    stream = MemoryStream(upload_args(name=name))
    run(service.serve(stream))
    assert stream.code == StreamClose.POLICY
    assert not list(service.home.rglob(".upload-*"))


def test_put_is_atomic_unique_and_verifies_bytes(service):
    data = b"binary\0document" * 10000
    paths = []
    for _ in range(2):
        stream = MemoryStream(upload_args(data), (data[:100], data[100:]))
        run(service.serve(stream))
        ready, receipt = map(json.loads, bytes(stream.output).splitlines())
        assert ready == {"ready": True}
        path = Path(receipt["path"])
        assert path.parent.parent == service.home / "cozychat-inbox"
        assert path.read_bytes() == data
        assert receipt["sha256"] == hashlib.sha256(data).hexdigest()
        paths.append(path)
    assert paths[0] != paths[1]
    assert not list(service.home.rglob(".upload-*"))


@pytest.mark.parametrize("chunks", [(b"doc",), (b"document extra",), (b"tampered",)])
def test_truncation_overrun_and_wrong_hash_never_publish(service, chunks):
    stream = MemoryStream(upload_args(), chunks)
    run(service.serve(stream))
    assert stream.code == StreamClose.POLICY
    assert not list(service.home.rglob("*.pdf"))
    assert not list(service.home.rglob(".upload-*"))


def test_inbox_symlink_escape_is_refused_before_creating_directories(service, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (service.home / "cozychat-inbox").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks need OS permission: {exc}")
    stream = MemoryStream(upload_args(), (b"document",))
    run(service.serve(stream))
    assert stream.code == StreamClose.POLICY
    assert not list(outside.iterdir())


def test_capabilities_are_absent_without_a_host_home_and_present_when_available(tmp_path):
    tunnel = runtime.Tunnel(runtime.store_for(tmp_path / "cozychat"), config={},
                            plugin_version="0.6.0", state_version="shared-v1", home=tmp_path / "home")
    assert tunnel.capabilities([])["services"]["files"] is None
    tunnel.home.mkdir()
    if not files.platform_supported():
        assert tunnel.capabilities([])["services"]["files"] is None
        return
    capability = tunnel.capabilities([])["services"]["files"]
    assert {k: capability[k] for k in ("put", "read_range", "max_bytes")} == {
        "put": True, "read_range": True, "max_bytes": files.MAX_BYTES}
    assert str(tunnel.files.inbox) in capability["read_roots"]


def test_real_listener_refuses_files_before_approval_and_serves_after(service, tmp_path):
    tunnel = runtime.Tunnel(runtime.store_for(service.home / "cozychat"), config={},
                            plugin_version="0.6.0", state_version="shared-v1", home=service.home,
                            environ={}, interfaces=loopback_binds)
    tunnel.files = service
    window = tunnel.store.open_window()
    photo = tmp_path / "photo.png"
    photo.write_bytes(b"picture")

    async def scenario():
        from cozychat.relay.pairing import pairing_link

        listener = tunnel.make_listener(port=0)
        await listener.start()
        phone = Phone(pairing_link(tunnel.store.host_public(), window, listener.hints()))
        await phone.connect()
        try:
            stream = await phone.mux.open("files", {"op": "stat", "path": str(photo)})
            assert await asyncio.wait_for(stream.read(), 5) == b""
            assert stream.close_code == StreamClose.POLICY
            await phone.close()
            phone = await approved_phone(tunnel.store, listener)
            assert (await phone.request("info"))["capabilities"]["services"]["files"]["read_range"]
            stream = await phone.mux.open("files", {"op": "read_range", "path": str(photo),
                                                   "offset": 1, "length": 3})
            output = b""
            while chunk := await asyncio.wait_for(stream.read(), 5):
                output += chunk
            assert output.split(b"\n", 1)[1] == b"ict"
            assert stream.close_code == StreamClose.NORMAL
        finally:
            await phone.close()
            await listener.stop()

    run(scenario())


def test_cancelled_upload_removes_partial_file(service):
    started = asyncio.Event()

    class StalledUpload(MemoryStream):
        async def read(self):
            started.set()
            await asyncio.Future()

    async def scenario():
        task = asyncio.create_task(service.serve(StalledUpload(upload_args())))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not list(service.home.rglob(".upload-*"))
        assert not list(service.home.rglob("*.pdf"))

    run(scenario())


@pytest.mark.parametrize("path", ["~/.awſ/credentialſ", "/PRIVATE/etc/hosts", "/private/ETC/hosts",
                                 "/outputs/credentialſ", "/outputs/．hidden/key", "/outputs/any/.hidden.png"])
def test_filesystem_equivalent_spellings_and_all_hidden_components_are_refused(path):
    assert files.credential_path(path)


@pytest.mark.parametrize("relative", ["cozychat/devices.json", "cozychat/keys/phone", "cozychat/outbox.sqlite",
                                      "cozychat/state.sqlite-wal", "cozychat/relay/pairing.json", "other.txt"])
def test_entire_hermes_home_except_inbox_is_private(service, relative):
    path = service.home / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"secret")
    stream = MemoryStream({"op": "stat", "path": str(path)})
    run(service.serve(stream))
    assert stream.code == StreamClose.POLICY
    assert not stream.output


def test_custom_plugin_state_and_alias_are_refused(service, tmp_path):
    state = tmp_path / "shared-state"
    state.mkdir()
    (state / "devices.json").write_bytes(b"secret")
    other = files.FileService(service.home, allowed_roots=[tmp_path], plugin_state=state)
    alias = tmp_path / "ordinary"
    alias.symlink_to(state, target_is_directory=True)
    for path in (state / "devices.json", alias / "devices.json"):
        stream = MemoryStream({"op": "stat", "path": str(path)})
        run(other.serve(stream))
        assert stream.code == StreamClose.POLICY
        assert not stream.output


def test_hardlink_alias_is_refused_for_stat_and_read(service, tmp_path):
    secret = service.home / "cozychat" / "keys" / "phone"
    secret.parent.mkdir(parents=True)
    secret.write_bytes(b"secret")
    alias = tmp_path / "photo.png"
    os.link(secret, alias)
    for op in ("stat", "read_range"):
        stream = MemoryStream({"op": op, "path": str(alias), "offset": 0, "length": 16})
        run(service.serve(stream))
        assert stream.code == StreamClose.POLICY
        assert not stream.output


def test_default_and_explicit_roots(service, tmp_path):
    for name in ("Pictures", "Documents"):
        (service.user_home / name).mkdir(parents=True)
    inside = service.user_home / "Pictures" / "photo.png"
    inside.write_bytes(b"picture")
    loose = service.user_home / "notes.txt"
    loose.write_bytes(b"not a media folder")
    outside = tmp_path / "outside.png"
    outside.write_bytes(b"secret")
    default = files.FileService(service.home, user_home=service.user_home)
    assert service.user_home / "Downloads" not in default.roots
    for path, allowed in ((inside, True), (loose, False), (outside, False)):
        stream = MemoryStream({"op": "stat", "path": str(path)})
        run(default.serve(stream))
        assert bool(stream.output) == allowed
    workspace = files.FileService(service.home, user_home=service.user_home, workspace=tmp_path)
    opened, _ = workspace._open(str(outside))
    opened.close()
    configured = files.FileService(service.home, user_home=service.user_home,
                                   allowed_roots=[service.user_home])
    opened, _ = configured._open(str(loose))
    opened.close()


def cache_service(service, tmp_path):
    return files.FileService(service.home, user_home=tmp_path / "nobody", allowed_roots=[])


def test_hermes_generated_media_in_the_delivery_cache_is_readable(service, tmp_path):
    only_cache = cache_service(service, tmp_path)
    for sub in files.MEDIA_CACHE_SUBDIRS:
        image = service.home / "cache" / sub / "a.png"
        image.parent.mkdir(parents=True)
        image.write_bytes(b"png-bytes")
        stream = MemoryStream({"op": "read_range", "path": str(image), "offset": 0, "length": 9})
        run(only_cache.serve(stream))
        assert stream.code is None and bytes(stream.output).endswith(b"png-bytes")
    assert str(service.home.resolve() / "cache" / "images") in only_cache.capabilities()["read_roots"]


def test_cache_allowance_keeps_every_other_check_and_the_rest_of_hermes_home_private(service, tmp_path):
    only_cache = cache_service(service, tmp_path)
    cache = service.home / "cache"
    (cache / "images" / ".hidden").mkdir(parents=True)
    (cache / "images" / ".hidden" / "a.png").write_bytes(b"x")
    (cache / "images" / "auth.json").write_bytes(b"x")
    (cache / "images" / "real.png").write_bytes(b"x")
    os.link(cache / "images" / "real.png", cache / "images" / "linked.png")
    (cache / "images" / "link.png").symlink_to(cache / "images" / "real.png")
    (cache / "tmp").mkdir()
    (cache / "tmp" / "a.png").write_bytes(b"x")
    (cache / "top.png").write_bytes(b"x")
    (service.home / "auth.json").write_bytes(b"x")
    (service.home / "cozychat").mkdir()
    (service.home / "cozychat" / "devices.json").write_bytes(b"x")
    for path in (cache / "images" / ".hidden" / "a.png", cache / "images" / "auth.json",
                 cache / "images" / "linked.png", cache / "images" / "link.png", cache / "tmp" / "a.png",
                 cache / "top.png", service.home / "auth.json", service.home / "cozychat" / "devices.json",
                 cache / "images" / ".." / ".." / "auth.json"):
        stream = MemoryStream({"op": "stat", "path": str(path)})
        run(only_cache.serve(stream))
        assert stream.code == StreamClose.POLICY and not stream.output, path


def test_configured_roots_cannot_reopen_private_hermes_state(service):
    narrowed = files.FileService(service.home, allowed_roots=[service.home, service.home / "cozychat"])
    assert not any(p == service.home.resolve() or p == (service.home / "cozychat").resolve()
                   for p in narrowed.roots)


def test_deny_trees_do_not_deny_a_home_that_lives_in_one(tmp_path, monkeypatch):
    # Service accounts and containers keep their home in /root or /var/lib.
    for home in ("/root/svc", "/var/lib/svc"):
        monkeypatch.setattr(files.Path, "is_dir", lambda self: True)
        service = files.FileService(tmp_path / "hermes", user_home=Path(home))
        _, relative = service._path(home + "/Documents/report.pdf")
        assert relative[-1] == "report.pdf"
        for refused in (home + "/Documents/.ssh/id_rsa", home + "/notes.txt",
                        "/etc/passwd", "/var/lib/other/file", "/root/other/file"):
            with pytest.raises(files.FilePolicyError):
                service._path(refused)
        explicit = files.FileService(tmp_path / "hermes", allowed_roots=[home])
        explicit._path(home + "/anything.txt")
        with pytest.raises(files.FilePolicyError):
            explicit._path(home + "/.ssh/id_rsa")


def test_a_benign_parent_escape_to_a_sibling_is_refused(service, tmp_path):
    root = tmp_path / "root"
    sibling = tmp_path / "sibling"
    root.mkdir()
    sibling.mkdir()
    (sibling / "file").write_bytes(b"sibling secret")
    narrow = files.FileService(service.home, user_home=tmp_path / "nobody", allowed_roots=[root])
    for path in (str(root) + "/../sibling/file", str(root / "x" / ".." / ".." / "sibling" / "file")):
        stream = MemoryStream({"op": "read_range", "path": path, "offset": 0, "length": 8})
        run(narrow.serve(stream))
        assert stream.code == StreamClose.POLICY and not stream.output


def test_a_root_under_tmp_requested_through_private_tmp(service):
    import shutil
    import tempfile
    root = Path(tempfile.mkdtemp(dir="/tmp", prefix="cozy-files-"))
    try:
        (root / "sub").mkdir()
        (root / "sub" / "a.txt").write_bytes(b"hello")
        narrow = files.FileService(service.home, user_home=root / "nobody", allowed_roots=[root])
        spellings = [str(root / "sub" / "a.txt")]
        if sys.platform == "darwin":
            spellings.append("/private" + spellings[0])
        for spelling in spellings:
            stream = MemoryStream({"op": "read_range", "path": spelling, "offset": 0, "length": 5})
            run(narrow.serve(stream))
            assert stream.code is None and bytes(stream.output).endswith(b"hello"), spelling
        stream = MemoryStream({"op": "stat", "path": str(root.parent / "elsewhere")})
        run(narrow.serve(stream))
        assert stream.code == StreamClose.POLICY
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.mark.parametrize("platform, supported", [("darwin", True), ("linux", True), ("win32", False)])
def test_native_windows_files_capability_is_off(platform, supported, service, monkeypatch):
    assert files.platform_supported(platform) is supported
    monkeypatch.setattr(files.sys, "platform", platform)
    assert (service.capabilities() is not None) is supported
    if not supported:
        # A junction or reparse point is never touched, even with a stale advertised capability.
        monkeypatch.setattr(files.os, "open", lambda *a, **k: pytest.fail("native Windows I/O"))
        stream = MemoryStream({"op": "stat", "path": r"C:\Users\phone\junction\file"})
        run(service.serve(stream))
        assert stream.code == StreamClose.POLICY


def test_inbox_quota_includes_committed_files_and_refuses_before_ready(service):
    service.quota = 2 * files.BLOCK_BYTES
    first = MemoryStream(upload_args(), (b"document",))
    run(service.serve(first))
    assert b'"ok":true' in first.output
    second = MemoryStream(upload_args(), (b"document",))
    run(service.serve(second))
    assert b'"ok":true' in second.output
    refused = MemoryStream(upload_args(), (b"document",))
    run(service.serve(refused))
    assert refused.reason == "inbox_quota"
    assert not refused.output
    assert service.reservations.bytes == 0


def test_free_space_floor_refuses_before_ready(service, monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(files.os, "fstatvfs", lambda fd: SimpleNamespace(f_bavail=8, f_frsize=1))
    service.free_floor = 1
    stream = MemoryStream(upload_args(), (b"document",))
    run(service.serve(stream))
    assert stream.reason == "free_space"
    assert not stream.output
    assert service.reservations.bytes == 0


def test_atomic_global_reservation_and_per_phone_fairness(service):
    service.phone_bytes = 8
    service.concurrent_bytes = 16
    started = asyncio.Event()

    class Stalled(MemoryStream):
        async def read(self):
            started.set()
            await asyncio.Future()

    async def scenario():
        first = asyncio.create_task(service.serve(Stalled(upload_args()), b"phone A"))
        await started.wait()
        assert service.reservations.bytes == 8
        same_phone = MemoryStream(upload_args(), (b"document",))
        await service.serve(same_phone, b"phone A")
        assert same_phone.reason == "busy" and not same_phone.output
        second = MemoryStream(upload_args(), (b"document",))
        await service.serve(second, b"phone B")
        assert b'"ok":true' in second.output
        service.concurrent_bytes = 8
        other = MemoryStream(upload_args(), (b"document",))
        await service.serve(other, b"phone C")
        assert other.reason == "busy" and not other.output
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert service.reservations.bytes == 0
        assert service.reservations.operations == 0

    run(scenario())


def test_upload_deadline_releases_reservation_and_temp(service):
    service.upload_seconds = 0.02

    class Stalled(MemoryStream):
        async def read(self):
            await asyncio.Future()

    stream = Stalled(upload_args())
    run(service.serve(stream))
    assert stream.code == StreamClose.UNREACHABLE
    assert service.reservations.bytes == 0
    assert not list(service.home.rglob(".upload-*"))


def test_repeated_cancellation_retains_worker_and_cleanup_ownership(service, monkeypatch):
    import threading

    entered, release = threading.Event(), threading.Event()
    cleaning, cleaned = threading.Event(), threading.Event()
    original = service._upload
    acquired = []

    def slow_upload(name):
        upload = original(name)
        acquired.append(upload)
        discard = upload.discard

        def slow_cleanup():
            cleaning.set()
            assert cleaned.wait(5)
            discard()

        upload.discard = slow_cleanup
        entered.set()
        assert release.wait(5)
        return upload

    monkeypatch.setattr(service, "_upload", slow_upload)

    async def scenario():
        task = asyncio.create_task(service.serve(MemoryStream(upload_args())))
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        release.set()
        assert await asyncio.to_thread(cleaning.wait, 5)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        assert service.reservations.bytes == 8
        cleaned.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert acquired[0].handle.closed
        with pytest.raises(OSError):
            os.fstat(acquired[0].directory)
        assert not list(service.home.rglob(".upload-*"))
        assert service.reservations.bytes == 0

    run(scenario())


def test_temporary_substitution_cannot_publish_unverified_identity(service, monkeypatch):
    original = service._commit

    def replaced(upload, count):
        os.unlink(upload.temporary, dir_fd=upload.directory)
        fd = os.open(upload.temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=upload.directory)
        os.write(fd, b"replaced")
        os.close(fd)
        original(upload, count)

    monkeypatch.setattr(service, "_commit", replaced)
    stream = MemoryStream(upload_args(), (b"document",))
    run(service.serve(stream))
    assert stream.reason == "path_changed"
    assert not list(service.home.rglob("*.pdf"))
    assert not list(service.home.rglob(".upload-*"))


def test_close_during_fsync_prevents_publication(service, monkeypatch):
    stream = MemoryStream(upload_args(), (b"document",))
    stream.closed = False
    original = os.fsync

    def closed(fd):
        original(fd)
        stream.closed = True

    monkeypatch.setattr(files.os, "fsync", closed)
    with pytest.raises(asyncio.CancelledError):
        run(service.serve(stream))
    assert not list(service.home.rglob("*.pdf"))
    assert not list(service.home.rglob(".upload-*"))
    assert service.reservations.bytes == 0


def test_commit_result_is_reconciled_when_receipt_is_cancelled(service):
    class ReceiptCancelled(MemoryStream):
        async def write(self, data):
            if b'"ok":true' in data:
                raise asyncio.CancelledError
            await super().write(data)

    with pytest.raises(asyncio.CancelledError):
        run(service.serve(ReceiptCancelled(upload_args(), (b"document",))))
    published = list(service.home.rglob("*.pdf"))
    assert len(published) == 1
    assert published[0].read_bytes() == b"document"
    assert not list(service.home.rglob(".upload-*"))
    assert service.reservations.bytes == 0


def test_revoked_phone_mid_transfer_never_publishes(service):
    tunnel = runtime.Tunnel(runtime.store_for(service.home / "cozychat"), config={},
                            plugin_version="0.6.0", state_version="shared-v1", home=service.home,
                            environ={}, interfaces=loopback_binds)
    tunnel.files = service

    async def scenario():
        listener = tunnel.make_listener(port=0, allowlist_poll_seconds=0.02)
        await listener.start()
        phone = await approved_phone(tunnel.store, listener)
        try:
            data = b"document" * 10000
            stream = await phone.mux.open("files", upload_args(data))
            assert json.loads(await stream.read()) == {"ready": True}
            await stream.write(data[:100])
            tunnel.store.remove_phone(phone.static_public)
            await asyncio.wait_for(phone.mux.done.wait(), 5)
            for _ in range(100):
                if service.reservations.operations == 0:
                    break
                await asyncio.sleep(0.01)
            assert service.reservations.bytes == 0
            assert not list(service.home.rglob("*.pdf"))
            assert not list(service.home.rglob(".upload-*"))
        finally:
            await phone.close()
            await listener.stop()

    run(scenario())


@pytest.mark.skipif(sys.platform != "win32", reason="native NTFS junction test")
def test_native_windows_junction_never_enables_or_reaches_files(service, tmp_path):
    import subprocess

    secret = tmp_path / "secrets"
    secret.mkdir()
    (secret / "devices.json").write_bytes(b"secret")
    junction = tmp_path / "junction"
    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(secret)], capture_output=True)
    assert result.returncode == 0
    try:
        assert service.capabilities() is None
        stream = MemoryStream({"op": "stat", "path": str(junction / "devices.json")})
        run(service.serve(stream))
        assert stream.code == StreamClose.POLICY
        assert not stream.output
    finally:
        junction.rmdir()


def test_two_services_share_an_atomic_host_reservation(service):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    other = files.FileService(service.home, concurrent_bytes=8, phone_bytes=8)
    service.concurrent_bytes = 8
    service.phone_bytes = 8
    gate = Barrier(2)

    def reserve(target, phone):
        gate.wait(timeout=5)
        try:
            target._reserve(phone, 8)
            return phone
        except files.FilePolicyError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(reserve, service, b"A")
        second = pool.submit(reserve, other, b"B")
        results = [first.result(), second.result()]
    assert sum(p is not None for p in results) == 1
    service.reservations.release(next(p for p in results if p is not None), 8)
    assert service.reservations.bytes == 0


def test_upload_component_swap_cannot_redirect_temp_creation_or_publication(service, tmp_path, monkeypatch):
    from datetime import date

    inbox = service.home / "cozychat-inbox"
    inbox.mkdir()
    directory = inbox / date.today().isoformat()
    directory.mkdir()
    saved = inbox / "saved"
    outside = tmp_path / "outside"
    outside.mkdir()
    real_open = os.open

    def swapped(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if str(path).startswith(".upload-"):
            directory.rename(saved)
            directory.symlink_to(outside, target_is_directory=True)
        return fd

    monkeypatch.setattr(files.os, "open", swapped)
    stream = MemoryStream(upload_args(), (b"document",))
    run(service.serve(stream))
    assert not list(outside.iterdir())
    assert stream.reason == "path_changed"
    assert not list(saved.glob("*.pdf"))
    assert not list(saved.glob(".upload-*"))


def test_unrelated_control_traffic_does_not_extend_upload_deadline(service):
    service.upload_seconds = 0.1
    tunnel = runtime.Tunnel(runtime.store_for(service.home / "cozychat"), config={},
                            plugin_version="0.6.0", state_version="shared-v1", home=service.home,
                            environ={}, interfaces=loopback_binds)
    tunnel.files = service

    async def scenario():
        listener = tunnel.make_listener(port=0)
        await listener.start()
        phone = await approved_phone(tunnel.store, listener)
        try:
            stream = await phone.mux.open("files", upload_args())
            assert json.loads(await stream.read()) == {"ready": True}
            for _ in range(20):
                assert (await phone.request("info"))["ok"]
                await asyncio.sleep(0.01)
            assert await asyncio.wait_for(stream.read(), 5) == b""
            assert stream.close_code == StreamClose.UNREACHABLE
            assert service.reservations.bytes == 0
            assert not list(service.home.rglob(".upload-*"))
        finally:
            await phone.close()
            await listener.stop()

    run(scenario())



def test_profiles_share_one_host_inbox_quota(service):
    profile = service.home / "profiles" / "worker"
    profile.mkdir(parents=True)
    other = files.FileService(profile, user_home=service.user_home)
    assert other.inbox == service.inbox
    assert other.reservations is service.reservations
    stream = MemoryStream(upload_args(), (b"document",))
    run(other.serve(stream))
    assert Path(json.loads(bytes(stream.output).splitlines()[-1])["path"]).parent.parent == service.inbox



def test_long_policy_hints_do_not_break_approved_reconnect(service):
    tunnel = runtime.Tunnel(runtime.store_for(service.home / "cozychat"), config={},
                            plugin_version="0.6.0", state_version="shared-v1", home=service.home,
                            environ={}, interfaces=loopback_binds)
    service.roots.append(Path("/workspace/" + "x" * 900))
    tunnel.files = service

    async def scenario():
        listener = tunnel.make_listener(port=0)
        await listener.start()
        phone = await approved_phone(tunnel.store, listener)
        private = phone.static_private
        await phone.close()
        phone = await approved_phone(tunnel.store, listener, private)
        try:
            assert phone.payload["services"]["files"]["read_range"]
            assert "read_roots" not in phone.payload["services"]["files"]
            info = (await phone.request("info"))["capabilities"]["services"]["files"]
            assert str(service.roots[-1]) in info["read_roots"]
        finally:
            await phone.close()
            await listener.stop()

    run(scenario())



def test_revocation_after_fsync_is_authoritative_before_the_watcher_polls(service, monkeypatch):
    tunnel = runtime.Tunnel(runtime.store_for(service.home / "cozychat"), config={},
                            plugin_version="0.6.0", state_version="shared-v1", home=service.home,
                            environ={}, interfaces=loopback_binds)
    tunnel.files = service
    original = os.fsync
    revoke = []

    def revoke_after_fsync(fd):
        original(fd)
        if revoke:
            key = revoke.pop()
            assert tunnel.store.remove_phone(key)

    monkeypatch.setattr(files.os, "fsync", revoke_after_fsync)

    async def scenario():
        listener = tunnel.make_listener(port=0, allowlist_poll_seconds=60)
        await listener.start()
        phone = await approved_phone(tunnel.store, listener)
        try:
            stream = await phone.mux.open("files", upload_args())
            assert json.loads(await stream.read()) == {"ready": True}
            revoke.append(phone.static_public)
            await stream.write(b"document")
            assert await asyncio.wait_for(stream.read(), 5) == b""
            assert stream.close_code == StreamClose.POLICY
            assert not list(service.inbox.rglob("*.pdf"))
            assert not list(service.inbox.rglob(".upload-*"))
            assert service.reservations.bytes == 0
        finally:
            await phone.close()
            await listener.stop()

    run(scenario())



def test_publication_also_supports_tasks_without_a_cancellation_counter(service, monkeypatch):
    # Python 3.10 tasks lack the newer cancelling() API; closure and worker ownership still apply.
    monkeypatch.setattr(files.asyncio, "current_task", lambda: object())
    stream = MemoryStream(upload_args(), (b"document",))
    run(service.serve(stream))
    assert b'"ok":true' in stream.output
    assert service.reservations.bytes == 0


def test_quota_charges_allocated_blocks_with_a_four_kib_minimum(service):
    inbox = service.inbox / "2026-01-01"
    inbox.mkdir(parents=True)
    (inbox / "tiny").write_bytes(b"x")
    with open(inbox / "empty", "wb"):
        pass
    sparse = inbox / "sparse"
    with open(sparse, "wb") as handle:
        handle.truncate(512 * 1024 * 1024)
    fd = os.open(service.inbox, os.O_RDONLY | os.O_DIRECTORY)
    try:
        used, count = files._usage(fd)
    finally:
        os.close(fd)
    assert count == 3
    assert used >= 2 * files.BLOCK_BYTES
    assert used < 64 * 1024 * 1024  # the sparse file's apparent size is not charged
    assert files._charge(0) == files.BLOCK_BYTES == files._charge(1)
    assert files._charge(4097) == 2 * files.BLOCK_BYTES
    assert files._charge(10, blocks=0) == files.BLOCK_BYTES
    assert files._charge(10, blocks=24) == 24 * 512


def test_a_tiny_upload_is_charged_a_whole_block(service):
    service.quota = files.BLOCK_BYTES - 1
    stream = MemoryStream(upload_args(b"x"), (b"x",))
    run(service.serve(stream))
    assert stream.reason == "inbox_quota" and not stream.output


def test_inbox_file_count_cap(service, monkeypatch):
    monkeypatch.setattr(files, "MAX_INBOX_FILES", 2)
    for _ in range(2):
        stream = MemoryStream(upload_args(), (b"document",))
        run(service.serve(stream))
        assert b'"ok":true' in stream.output
    refused = MemoryStream(upload_args(), (b"document",))
    run(service.serve(refused))
    assert refused.reason == "inbox_files" and not refused.output
    assert service.reservations.files == 0 and service.reservations.bytes == 0


def test_in_flight_uploads_count_toward_the_file_cap(service, monkeypatch):
    monkeypatch.setattr(files, "MAX_INBOX_FILES", 1)
    started = asyncio.Event()

    class Stalled(MemoryStream):
        async def read(self):
            started.set()
            await asyncio.Future()

    async def scenario():
        first = asyncio.create_task(service.serve(Stalled(upload_args()), b"a"))
        await started.wait()
        second = MemoryStream(upload_args(), (b"document",))
        await service.serve(second, b"b")
        assert second.reason == "inbox_files"
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first

    run(scenario())


def test_reservations_use_an_incremental_counter_not_a_rescan(service):
    for _ in range(3):
        stream = MemoryStream(upload_args(), (b"document",))
        run(service.serve(stream))
        assert b'"ok":true' in stream.output
    assert service.reservations.scans == 1
    assert service.reservations.used_files == 3
    assert service.reservations.used_bytes == 3 * files.BLOCK_BYTES
    # An external deletion is picked up when the periodic reconciliation fires.
    for path in [p for p in service.inbox.rglob("*") if p.is_file()]:
        path.unlink()
    service.reconcile_seconds = 0
    stream = MemoryStream(upload_args(), (b"document",))
    run(service.serve(stream))
    assert service.reservations.scans == 2
    assert service.reservations.used_files == 1


def test_orphaned_upload_temporaries_older_than_an_hour_are_swept(service):
    day = service.inbox / "2026-01-01"
    day.mkdir(parents=True)
    old, fresh, kept = day / ".upload-old", day / ".upload-fresh", day / "old-but-real.pdf"
    for path in (old, fresh, kept):
        path.write_bytes(b"x" * 10)
    long_ago = __import__("time").time() - files.ORPHAN_SECONDS - 60
    os.utime(old, (long_ago, long_ago))
    os.utime(kept, (long_ago, long_ago))
    stream = MemoryStream(upload_args(), (b"document",))
    run(service.serve(stream))
    assert b'"ok":true' in stream.output
    assert not old.exists() and fresh.exists() and kept.exists()
    assert service.reservations.used_files == 3  # fresh + kept + the new upload


def test_discard_unlinks_the_temporary_even_when_close_raises(service):
    upload = service._upload("report.pdf")
    real = upload.handle

    class Failing:
        def close(self):
            real.close()
            raise OSError("disk full")

    upload.handle = Failing()
    temporary = service.inbox / upload.path.parent.name / upload.temporary
    assert temporary.exists()
    with pytest.raises(OSError):
        upload.discard()
    assert not temporary.exists()
    for fd in (upload.directory, upload.inbox, upload.home):
        with pytest.raises(OSError):
            os.fstat(fd)
