"""The approval transport: what silence does, what a late tap does, and what never leaves."""

import pathlib
import sys
import threading
import time

import pytest

from cozychat.approvals import ANSWERED, REFUSED, SETTLED, UNKNOWN, ApprovalDesk, ApprovalTransport
from cozychat.events import Emitter


class FakeStore:
    def list(self):
        return [{"device_id": "phone-1", "push_id": "push-1", "filters": {},
                 "profile": "luna", "consent_version": 1}]


class FakeOutbox:
    def __init__(self):
        self.rows = []

    def enqueue(self, device_id, category, collapse_id, payload, *, level=None, profile="",
                consent_version=0, now=None):
        self.rows.append({"device_id": device_id, "category": category,
                          "collapse_id": collapse_id, "payload": payload, "level": level})


class Decision:
    """`ApprovalDecision` as the host defines it: request id, digest, choice."""

    def __init__(self, request_id, digest, choice):
        self.request_id, self.request_digest, self.choice = request_id, digest, choice

    def __eq__(self, other):
        return (self.request_id, self.request_digest, self.choice) == (
            other.request_id, other.request_digest, other.choice)


class Request:
    """The host's immutable, already-redacted `ApprovalRequest`."""

    def __init__(self, request_id="req-1", timeout_seconds=0.2,
                 allowed_choices=("once", "session", "deny"),
                 command="rm -rf /tmp/build", description="Delete the build directory",
                 pattern_key="terminal:rm", surface="transport:cozychat"):
        self.schema_version = 1
        self.request_id = request_id
        self.digest = "digest-" + request_id
        self.command = command
        self.description = description
        self.pattern_key = pattern_key
        self.pattern_keys = (pattern_key,)
        self.surface = surface
        self.timeout_seconds = timeout_seconds
        self.allowed_choices = allowed_choices

    def respond(self, choice):
        return Decision(self.request_id, self.digest, choice)


def emitter(desk, **config):
    settings = {"profile_name": "luna", "push_approvals": True}
    settings.update(config)
    outbox = FakeOutbox()
    return Emitter(FakeStore(), outbox, settings, desk=desk), outbox


def answer_soon(desk, request_id, choice):
    def answer():
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if desk.answer(request_id, choice) != UNKNOWN:
                return
            time.sleep(0.01)

    thread = threading.Thread(target=answer)
    thread.start()
    return thread


def test_a_tap_becomes_the_hosts_own_decision_object():
    desk = ApprovalDesk()
    transport = ApprovalTransport(desk, emitter(desk)[0])
    request = Request(timeout_seconds=2.0)
    thread = answer_soon(desk, "req-1", "once")

    decision = transport.present(request)

    thread.join()
    assert decision == Decision("req-1", "digest-req-1", "once")


def test_silence_returns_nothing_so_the_host_default_applies():
    desk = ApprovalDesk()
    transport = ApprovalTransport(desk, emitter(desk)[0])

    assert transport.present(Request(timeout_seconds=0.05)) is None


def test_a_late_decision_is_discarded():
    desk = ApprovalDesk()
    transport = ApprovalTransport(desk, emitter(desk)[0])

    assert transport.present(Request(timeout_seconds=0.05)) is None
    # The turn has stopped waiting. A tap arriving now must not authorize anything.
    assert desk.answer("req-1", "once") == UNKNOWN
    assert desk.listing() == []


def test_a_choice_the_ask_did_not_offer_is_refused():
    desk = ApprovalDesk()
    desk.open(Request(timeout_seconds=5.0, allowed_choices=("once", "deny")))

    assert desk.answer("req-1", "always") == REFUSED
    assert desk.listing()[0]["request_id"] == "req-1"   # still open, still answerable


def test_an_id_nobody_is_holding_is_unknown():
    assert ApprovalDesk().answer("req-nope", "once") == UNKNOWN


def test_one_answer_settles_it():
    desk = ApprovalDesk()
    desk.open(Request(timeout_seconds=5.0))

    assert desk.answer("req-1", "once") == ANSWERED
    assert desk.answer("req-1", "deny") == SETTLED


def test_an_expired_row_is_settled_rather_than_open():
    desk = ApprovalDesk()
    desk.open(Request(timeout_seconds=0.0), now=time.time() - 10)

    assert desk.listing() == []
    assert desk.answer("req-1", "once") == SETTLED


def test_the_listing_carries_the_rule_and_the_choices_but_never_the_command():
    desk = ApprovalDesk()
    desk.open(Request(timeout_seconds=5.0, command="rm private-note.txt",
                      description="Delete private-note.txt"))

    row = desk.listing()[0]
    assert row["name"] == "terminal:rm"
    assert row["allowed_choices"] == ["once", "session", "deny"]
    # The host redacts the description it hands a transport; the command text itself is not a field
    # the desk keeps at all.
    assert "command" not in row
    assert row["detail"] == "Delete private-note.txt"


def test_a_very_long_description_is_one_bounded_line():
    desk = ApprovalDesk()
    desk.open(Request(timeout_seconds=5.0, description="word\n" * 500))

    assert len(desk.listing()[0]["detail"]) <= 400
    assert "\n" not in desk.listing()[0]["detail"]


def test_the_observer_push_and_the_transport_push_collapse_to_one_alert():
    desk = ApprovalDesk()
    emit, outbox = emitter(desk)

    # Exactly the order Hermes fires them in: `pre_approval_request` (with BOTH ids) and then the
    # transport, which only ever learns the request id.
    emit.approval_pending(pattern_key="terminal:rm", tool_call_id="call-7", turn_id="turn-3",
                          session_id="sess-9", request_id="req-1")
    record = desk.open(Request(timeout_seconds=5.0))
    emit.approval_transport_pending(record)

    assert record["tool_call_id"] == "call-7"
    assert record["turn_id"] == "turn-3"
    assert [row["collapse_id"] for row in outbox.rows] == ["call-7", "call-7"]
    # The second payload is the one that carries the id the phone answers by.
    assert outbox.rows[0]["payload"].get("requestId") == "req-1"
    assert outbox.rows[1]["payload"]["requestId"] == "req-1"
    assert outbox.rows[1]["payload"]["toolCallId"] == "call-7"


def test_without_the_observer_the_card_still_has_an_id():
    desk = ApprovalDesk()
    record = desk.open(Request(timeout_seconds=5.0))

    assert record["tool_call_id"] == "req-1"


def test_a_timed_out_transport_resolves_as_expired_not_denied():
    desk = ApprovalDesk()
    emit, outbox = emitter(desk)

    emit.approval_resolved(pattern_key="terminal:rm", tool_call_id="call-7",
                           choice="transport_timeout")

    assert outbox.rows[0]["payload"]["outcome"] == "expired"


def test_a_push_failure_never_denies_the_command():
    class Exploding:
        def approval_transport_pending(self, _record):
            raise RuntimeError("no relay")

    desk = ApprovalDesk()
    transport = ApprovalTransport(desk, Exploding())
    thread = answer_soon(desk, "req-1", "once")

    assert transport.present(Request(timeout_seconds=2.0)).choice == "once"
    thread.join()


@pytest.mark.parametrize("selected,expected", [("cozychat", True), ("builtin", False)])
def test_info_reports_whether_the_owner_selected_this_transport(monkeypatch, selected, expected):
    import sys
    import types

    module = types.ModuleType("hermes_cli.config")
    module.load_config_readonly = lambda: {"security": {"approval": {"transport": selected}}}
    package = types.ModuleType("hermes_cli")
    monkeypatch.setitem(sys.modules, "hermes_cli", package)
    monkeypatch.setitem(sys.modules, "hermes_cli.config", module)

    from cozychat.approvals import transport_selected

    assert transport_selected() is expected


def test_an_unreadable_config_reports_no_transport(monkeypatch):
    import types

    module = types.ModuleType("hermes_cli.config")

    def explode():
        raise OSError("config.yaml is unreadable")

    module.load_config_readonly = explode
    monkeypatch.setitem(sys.modules, "hermes_cli", types.ModuleType("hermes_cli"))
    monkeypatch.setitem(sys.modules, "hermes_cli.config", module)

    from cozychat.approvals import transport_selected

    # A config nobody can read is not a reason to offer a transport, and not a reason to raise
    # inside a route either.
    assert transport_selected() is False


# -- the routes ----------------------------------------------------------


def test_the_route_lists_what_the_transport_is_holding(plugin_app):
    http, package, _ = plugin_app
    package.desk.open(Request(timeout_seconds=30.0))

    rows = http.get("/api/plugins/cozychat/approvals").json()["approvals"]

    assert [row["request_id"] for row in rows] == ["req-1"]
    assert rows[0]["allowed_choices"] == ["once", "session", "deny"]
    assert "command" not in rows[0]


def test_the_route_answers_a_waiting_request(plugin_app):
    http, package, _ = plugin_app
    package.desk.open(Request(timeout_seconds=30.0))

    response = http.post("/api/plugins/cozychat/approvals/req-1", json={"choice": "once"})

    assert response.status_code == 200 and response.json()["choice"] == "once"
    assert http.get("/api/plugins/cozychat/approvals").json()["approvals"] == []


@pytest.mark.parametrize("request_id,choice,status", [
    ("req-nope", "once", 404),   # nobody is holding that
    ("req-1", "always", 400),    # a choice this ask never offered
])
def test_the_route_refuses_what_it_must(plugin_app, request_id, choice, status):
    http, package, _ = plugin_app
    package.desk.open(Request(timeout_seconds=30.0, allowed_choices=("once", "deny")))

    assert http.post(f"/api/plugins/cozychat/approvals/{request_id}",
                     json={"choice": choice}).status_code == status


def test_a_second_answer_is_a_conflict_not_a_second_decision(plugin_app):
    http, package, _ = plugin_app
    package.desk.open(Request(timeout_seconds=30.0))
    http.post("/api/plugins/cozychat/approvals/req-1", json={"choice": "once"})

    assert http.post("/api/plugins/cozychat/approvals/req-1",
                     json={"choice": "deny"}).status_code == 409


def test_info_carries_the_bit_the_app_gates_the_feature_on(plugin_app, shared_state):
    # Read out of the shared state, not out of this process's config: `/info` is served by the
    # dashboard's profile, which has nothing to say about whether the GATEWAY will ask a phone.
    # Measured wrong the other way against a real Hermes on 2026-09-15.
    http, _package, _ = plugin_app
    assert http.get("/api/plugins/cozychat/info").json()["approval_transport"] is False

    shared_state.note_transport(pathlib.Path("/hermes/profiles/other"), True)
    assert http.get("/api/plugins/cozychat/info").json()["approval_transport"] is True

    shared_state.note_transport(pathlib.Path("/hermes/profiles/other"), False)
    assert http.get("/api/plugins/cozychat/info").json()["approval_transport"] is False


def test_the_routes_refuse_when_the_plugin_is_not_loaded(monkeypatch, plugin_app):
    http, _package, _ = plugin_app
    monkeypatch.delitem(sys.modules, "hermes_plugins.cozychat")

    assert http.get("/api/plugins/cozychat/approvals").status_code == 503
    assert http.post("/api/plugins/cozychat/approvals/req-1",
                     json={"choice": "once"}).status_code == 503
