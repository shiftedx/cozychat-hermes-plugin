"""The device store: what it keeps, what it refuses, and what a reader can see."""

import json
import stat

import pytest

from cozychat.devices import DeviceStore

DEVICE = {"device_id": "phone-1", "push_id": "push-abc", "key_hex": b"test-push-key".hex(),
          "environment": "production", "filters": {"replies": True, "approvals": False}}


def store(tmp_path):
    return DeviceStore(tmp_path)


def test_nothing_paired_reads_as_empty(tmp_path):
    assert store(tmp_path).list() == []


def test_add_then_read_back_the_key_and_the_record(tmp_path):
    subject = store(tmp_path)
    subject.add(DEVICE)
    (record,) = subject.list()
    assert record["push_id"] == "push-abc"
    assert record["filters"] == {"replies": True, "approvals": False}
    assert subject.key("phone-1") == b"test-push-key"


def test_the_index_never_carries_the_key(tmp_path):
    subject = store(tmp_path)
    subject.add(DEVICE)
    text = (tmp_path / "devices.json").read_text("utf-8")
    assert "key_hex" not in text and b"test-push-key".hex() not in text
    assert json.loads(text)[0]["device_id"] == "phone-1"


def test_key_and_index_are_owner_only(tmp_path):
    subject = store(tmp_path)
    subject.add(DEVICE)
    for path in (tmp_path / "devices.json", tmp_path / "keys" / "phone-1"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "keys").stat().st_mode) == 0o700


def test_no_temp_file_is_left_behind(tmp_path):
    subject = store(tmp_path)
    subject.add(DEVICE)
    assert not list(tmp_path.glob("*.tmp")) and not list((tmp_path / "keys").glob("*.tmp"))


def test_re_pairing_replaces_rather_than_duplicates(tmp_path):
    subject = store(tmp_path)
    subject.add(DEVICE)
    subject.add(dict(DEVICE, key_hex=b"rotated-push-key".hex(), push_id="push-def"))
    (record,) = subject.list()
    assert record["push_id"] == "push-def"
    assert subject.key("phone-1") == b"rotated-push-key"


def test_remove_forgets_the_record_and_the_key(tmp_path):
    subject = store(tmp_path)
    subject.add(DEVICE)
    assert subject.remove("phone-1") is True
    assert subject.list() == []
    assert not (tmp_path / "keys" / "phone-1").exists()
    assert subject.remove("phone-1") is False


@pytest.mark.parametrize("device_id", ["../escape", "", "with/slash", "a" * 65, "phone-1\n"])
def test_a_device_id_that_is_not_a_safe_file_name_is_refused(tmp_path, device_id):
    with pytest.raises(ValueError):
        store(tmp_path).add(dict(DEVICE, device_id=device_id))


def test_a_device_without_a_push_id_or_without_key_material_is_refused(tmp_path):
    with pytest.raises(ValueError):
        store(tmp_path).add(dict(DEVICE, push_id=""))
    with pytest.raises(ValueError):
        store(tmp_path).add(dict(DEVICE, key_hex=""))


def test_a_corrupt_index_reads_as_nothing_paired(tmp_path):
    (tmp_path / "devices.json").write_text("{not json", "utf-8")
    assert store(tmp_path).list() == []


@pytest.mark.parametrize("value", [None, 42, True, "text", {"device_id": "phone-1"}])
def test_a_non_list_json_index_reads_as_nothing_paired(tmp_path, value):
    (tmp_path / "devices.json").write_text(json.dumps(value), "utf-8")
    assert store(tmp_path).list() == []
