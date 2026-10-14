"""The ring, the replay, and the hook table behind them.

The route itself is exercised through FastAPI's test client where FastAPI is installed (it ships
with Hermes), so the SSE wire format and the `since` contract are asserted against the real router
rather than against a hand-rolled generator.
"""

import json
import sys

import pytest

from cozychat import events as events_module
from cozychat.events import Emitter
from cozychat.feed import LiveFeed


class FakeStore:
    def list(self):
        return []


class FakeOutbox:
    def enqueue(self, *args, **kwargs):
        pass


def emitter(**config):
    feed = LiveFeed()
    settings = {"profile_name": "luna"}
    settings.update(config)
    return Emitter(FakeStore(), FakeOutbox(), settings, feed=feed), feed


# -- the ring ------------------------------------------------------------

def test_seq_starts_at_one_and_never_repeats():
    feed = LiveFeed()
    first = feed.publish("message.delta", source="room", payload={"text": "a"})
    second = feed.publish("message.delta", source="room", payload={"text": "b"})
    assert (first["seq"], second["seq"]) == (1, 2)


def test_the_ring_drops_the_oldest_and_keeps_counting(tmp_path):
    # A table of three, so the prune is reachable without writing five thousand rows. The seq keeps
    # rising across it, which is the whole reason it is an AUTOINCREMENT: a phone that reconnects
    # with seq 3 must not be replayed frames numbered 1 and 2 again.
    from cozychat.state import SharedState

    feed = LiveFeed(SharedState(tmp_path / "small", capacity=3, prune_every=1))
    for index in range(5):
        feed.publish("message.delta", source="room", payload={"text": str(index)})
    kept = feed.since(0)
    assert [frame["seq"] for frame in kept] == [3, 4, 5]
    assert feed.state() == {"seq": 5, "oldest": 3, "capacity": 3}


def test_since_replays_only_what_is_newer():
    feed = LiveFeed()
    for index in range(4):
        feed.publish("message.delta", source="room", payload={"text": str(index)})
    assert [frame["payload"]["text"] for frame in feed.since(2)] == ["2", "3"]
    assert feed.since(4) == []


def test_frames_carry_the_coordinates_and_hash_the_session_key():
    feed = LiveFeed()
    frame = feed.publish("tool.started", source="session", session_id="s1", turn_id="t1",
                         session_key="telegram:4242", model="opus", payload={"name": "bash"})
    assert frame["session_id"] == "s1" and frame["turn_id"] == "t1"
    # The session key identifies the chat it came from, so only its hash may leave the process.
    assert "telegram" not in json.dumps(frame)
    assert len(frame["session_key_hash"]) == 16
    # A coordinate the feed does not name never reaches the frame.
    assert "model" not in frame


# -- the hook table ------------------------------------------------------

def test_every_room_kind_reaches_the_feed_even_when_rooms_are_muted():
    hooks, feed = emitter(push_rooms=False)
    hooks.room_activity(kind="message.delta", room_id="r1", member_id="scout", turn_id="t1",
                        seq=7, payload={"text": "hi"})
    frame = feed.since(0)[-1]
    assert frame["kind"] == "message.delta" and frame["source"] == "room"
    assert frame["room_id"] == "r1" and frame["member_id"] == "scout"
    assert frame["payload"] == {"text": "hi"}


@pytest.mark.parametrize("call, kind", [
    (lambda h: h.stream_start(session_id="s1", turn_id="t1"), "stream.started"),
    (lambda h: h.stream_delta(session_id="s1", delta="hello", kind="text"), "message.delta"),
    (lambda h: h.stream_delta(session_id="s1", delta="hmm", kind="reasoning"), "reasoning.delta"),
    (lambda h: h.stream_end(session_id="s1", final_text="done", finished=True), "stream.ended"),
    (lambda h: h.interim_message(session_id="s1", text="one moment"), "message.interim"),
    (lambda h: h.tool_started(tool_name="bash", tool_call_id="tc1", session_id="s1"),
     "tool.started"),
    (lambda h: h.tool_completed(tool_name="bash", tool_call_id="tc1", status="ok"),
     "tool.completed"),
    (lambda h: h.subagent_start(child_session_id="c1", child_role="scout"), "subagent.started"),
    (lambda h: h.subagent_stop(child_session_id="c1", child_status="ok"), "subagent.stopped"),
    (lambda h: h.loop_stopped(session_key="cli:1", reason="user"), "turn.stopped"),
])
def test_each_session_hook_produces_its_frame(call, kind):
    hooks, feed = emitter()
    call(hooks)
    assert [frame["kind"] for frame in feed.since(0)] == [kind]


def test_a_tool_call_never_carries_its_arguments():
    hooks, feed = emitter()
    hooks.tool_started(tool_name="bash", tool_call_id="tc1", session_id="s1",
                       args={"command": "cat ~/.ssh/id_ed25519"})
    frame = feed.since(0)[-1]
    assert frame["payload"] == {"tool_id": "tc1", "name": "bash"}
    assert "id_ed25519" not in json.dumps(frame)


def test_a_subagent_never_carries_its_goal_or_summary():
    hooks, feed = emitter()
    hooks.subagent_start(child_session_id="c1", child_role="scout", child_goal="read the secrets")
    hooks.subagent_stop(child_session_id="c1", child_status="ok", child_summary="found them")
    assert "secrets" not in json.dumps(feed.since(0))
    assert "found them" not in json.dumps(feed.since(0))


# -- the route -----------------------------------------------------------

fastapi = pytest.importorskip("fastapi")


@pytest.fixture
def client(plugin_app):
    """`(TestClient, ring)`, from the shared router fixture in `conftest.py`."""
    http, package, _api = plugin_app
    return http, package.feed


def test_info_reports_the_version_and_the_head(client):
    http, feed = client
    feed.publish("message.delta", source="room", payload={"text": "a"})
    body = http.get("/api/plugins/cozychat/info").json()
    assert body["name"] == "cozychat" and body["version"] == "0.2.0"
    assert body["attached"] is True and body["seq"] == 1


def _sse(api, since=0, disconnect_after=0, after_first_pass=None):
    """Drive the real route function to the point the client goes away, and decode what it wrote.

    Not through `TestClient`: an SSE route is an endless generator, and the test client's portal
    waits for it to finish. The ASGI `receive` this passes is the client hanging up, which is the
    same edge a real tunnel drop presents. The route polls it once per pass, so its first call is
    the end of the replay pass: `after_first_pass` runs there, while the client is still connected.
    """
    import asyncio

    from starlette.requests import Request

    calls = {"n": 0}

    async def receive():
        calls["n"] += 1
        if calls["n"] == 1 and after_first_pass is not None:
            after_first_pass()
        return {"type": "http.disconnect"} if calls["n"] > disconnect_after else {}

    scope = {"type": "http", "method": "GET", "path": "/events", "headers": [],
             "query_string": b""}

    async def run():
        response = await api.events(Request(scope, receive), since=since)
        assert response.media_type == "text/event-stream"
        return b"".join([chunk async for chunk in response.body_iterator])

    # Bounded, so a route that stops polling for the hang-up fails here instead of hanging the suite.
    body = asyncio.run(asyncio.wait_for(run(), timeout=5)).decode("utf-8")
    return [json.loads(line[6:]) for line in body.splitlines() if line.startswith("data: ")]


def test_events_replays_from_since_in_order(client):
    _, feed = client
    api = sys.modules["hermes_dashboard_plugin_cozychat"]
    for index in range(3):
        feed.publish("message.delta", source="room", payload={"text": str(index)})
    seen = _sse(api, since=1)
    assert [frame["seq"] for frame in seen] == [2, 3]
    assert [frame["payload"]["text"] for frame in seen] == ["1", "2"]


def test_events_keeps_delivering_after_the_replay(client):
    _, feed = client
    api = sys.modules["hermes_dashboard_plugin_cozychat"]
    feed.publish("message.delta", source="room", payload={"text": "first"})
    # A hook writes only once the replay is out, so this frame can arrive through the live tail alone.
    seen = _sse(api, since=0, disconnect_after=1, after_first_pass=lambda: feed.publish(
        "tool.started", source="room", payload={"name": "bash"}))
    assert [frame["kind"] for frame in seen] == ["message.delta", "tool.started"]


def test_events_refuses_when_no_ring_is_attached(monkeypatch, client):
    http, _ = client
    monkeypatch.delitem(sys.modules, "hermes_plugins.cozychat")
    assert http.get("/api/plugins/cozychat/events").status_code == 503
    assert http.get("/api/plugins/cozychat/info").json()["attached"] is False
