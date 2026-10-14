"""`GET /api/plugins/cozychat/events` and `/info`: the live feed, read through the dashboard.

AUTHENTICATION IS THE DASHBOARD'S. Hermes mounts this router behind the same middleware chain every
other dashboard route sits behind — host check, session cookie or `?token=`/`?ticket=`, then the
runtime gate that 404s a plugin the owner has disabled — so there is no auth code here to drift from
it. Nothing new listens: the phone reaches this only through the SSH tunnel it already holds.

HOW IT REACHES THE RING. Hermes imports this file as a standalone module (`spec_from_file_location`,
name `hermes_dashboard_plugin_cozychat`), not as part of the `cozychat` package, so a relative import
would build a SECOND ring nobody writes to. The package is looked up in `sys.modules` under the name
the plugin loader gives it instead, and when it is not there — the plugin's hooks are not loaded in
this process — `/info` says so and `/events` refuses, rather than serving a stream that is quiet
because nothing is attached.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any, AsyncIterator, Optional

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

router = APIRouter()

# The plugin loader imports a user plugin as `hermes_plugins.<slug>`, with a `__home_<digest>`
# suffix when a second Hermes home claims the same slug.
_PACKAGE = "hermes_plugins.cozychat"
# How often the route looks for new frames. The hooks write from turn threads, so a condition
# variable would need an executor hop per wakeup; ponytail: this poll costs 100 ms of latency on a
# feed whose alternative is a one-second `groups.log` read.
_TICK_SECONDS = 0.1
# A comment frame on a quiet feed, so a tunnel that has gone away is noticed by the write failing
# rather than by a timeout minutes later.
_KEEPALIVE_SECONDS = 15.0


def _package() -> Optional[Any]:
    for name, module in list(sys.modules.items()):
        if name == _PACKAGE or name.startswith(_PACKAGE + "__home_"):
            return module
    return None


def _feed() -> Optional[Any]:
    package = _package()
    return package.live_feed() if package is not None else None


def _cards() -> Any:
    """The Lock Screen cards, or a 503 — including when the plugin loaded but never configured
    them, which is the same fact to a phone: this process cannot drive a card."""
    cards = _attribute("live_activities")
    if not cards.ready:
        raise HTTPException(status_code=503, detail="cozychat plugin is not loaded in this process")
    return cards


def _attribute(name: str) -> Any:
    package = _package()
    if package is None:
        raise HTTPException(status_code=503, detail="cozychat plugin is not loaded in this process")
    return getattr(package, name)()


# The environments APNs has, mirrored from the relay's own register schema.
ENVIRONMENTS = frozenset({"development", "production"})


@router.get("/info")
def info() -> dict:
    """What the app checks before it opens the stream: the version, and whether anything is here.

    ``state`` is the whole gate on the app's side. A plugin whose feed, desk and cards were
    per-process reports no ``state`` at all, and CozyChat keeps the three features it gated on
    2026-09-15 switched off for it; ``shared-v1`` is the version that answers them across processes.

    ``writer_pid`` and ``serve_pid`` are for the person diagnosing a quiet feed. Two different
    numbers is the ordinary unified topology; the same number means this process runs both halves;
    a null writer means nothing has ever loaded the hooks against this shared directory.
    """
    package = _package()
    feed = _feed()
    payload: dict = {"name": "cozychat",
                     "version": getattr(package, "VERSION", None),
                     "plugin_version": getattr(package, "VERSION", None),
                     "relay_proto": getattr(package, "RELAY_PROTO", None),
                     "state": getattr(package, "STATE_VERSION", None),
                     "serve_pid": os.getpid(),
                     "writer_pid": None,
                     "attached": False}
    if feed is not None:
        store = feed.state_store
        payload["attached"] = store.attached()
        payload["writer_pid"] = store.writer_pid()
        payload.update(feed.state())
    # Whether "answer approvals from the phone" is on for this COMPUTER — read out of the shared
    # state, where each profile's gateway wrote its own answer. Asking this process's own config
    # would answer for the profile serving the route, which is not the profile that would hold the
    # command; measured wrong that way against a real Hermes on 2026-09-15.
    payload["push_available"] = False
    page = getattr(package, "pairing_page", None)
    if page is not None:
        try:
            payload["push_available"] = page().tunnel.capabilities([])["features"]["push"]["available"]
        except RuntimeError:
            pass
    payload["approval_transport"] = bool(
        feed is not None and feed.state_store.transport_selected())
    return payload


@router.get("/approvals")
def approvals() -> dict:
    """Every approval the transport is holding right now, as the cards that answer them.

    The phone asks for this on open because a push can be missed, silenced, or answered on another
    device; the list is the authority and the push is only the tap on the shoulder.
    """
    return {"approvals": [_card(record) for record in _attribute("approval_desk").listing()]}


@router.post("/approvals/{request_id}")
def answer(request_id: str, body: dict = Body(default={})) -> dict:
    """One decision, for one request, in one of the choices that request offered."""
    outcome = _attribute("approval_desk").answer(request_id, str((body or {}).get("choice") or ""))
    if outcome == "unknown":
        raise HTTPException(status_code=404, detail="no open approval with that id")
    if outcome == "settled":
        # Late, or answered elsewhere. A 409 rather than a 404 because the difference matters to the
        # card: it was real, and somebody else got there first.
        raise HTTPException(status_code=409, detail="that approval is no longer open")
    if outcome == "refused":
        raise HTTPException(status_code=400, detail="that approval did not offer that choice")
    return {"ok": True, "request_id": request_id, "choice": body.get("choice")}


# What a card may see. The desk already redacted the row; this is the second allowlist, so a field
# added to the desk for the transport's own use is not published by having been added.
_CARD_FIELDS = ("request_id", "tool_call_id", "turn_id", "session_id", "name", "pattern_keys",
                "detail", "surface", "allowed_choices", "opened_at", "expires_at")


def _card(record: dict) -> dict:
    return {field: record[field] for field in _CARD_FIELDS}


@router.post("/live-activities")
def add_live_activity(body: dict = Body(default={})) -> dict:
    """One Lock Screen card, registered by the phone that owns it.

    The TOKEN stops here: it is traded with the relay for a push id and never written down. A
    duplicate `activity_id` replaces its own registration, which is how a rotated ActivityKit token
    reaches the relay without leaving the old one live.
    """
    cards = _cards()
    fields = {name: str((body or {}).get(name) or "") for name in
              ("activity_id", "token", "environment", "session_id", "device_id", "profile")}
    if (not all(fields.values()) or len(fields["activity_id"]) > 128
            or len(fields["token"]) > 512 or len(fields["session_id"]) > 160
            or fields["environment"] not in ENVIRONMENTS
            or int((body or {}).get("consent_version") or 0) != 1):
        raise HTTPException(status_code=400, detail="malformed live activity registration")
    if not cards.register(**fields, consent_version=1):
        raise HTTPException(status_code=502, detail="the push relay would not take that token")
    return {"ok": True, "activity_id": fields["activity_id"]}


@router.delete("/live-activities/{activity_id}")
def remove_live_activity(activity_id: str) -> dict:
    """The card is gone from the phone. Stop pushing to it and release the relay registration."""
    return {"ok": True, "removed": _cards().forget(activity_id)}


@router.get("/events")
async def events(request: Request, since: int = Query(0, ge=0)) -> StreamingResponse:
    """Every frame after `since`, then every frame as it happens, as Server-Sent Events."""
    feed = _feed()
    if feed is None:
        raise HTTPException(status_code=503, detail="cozychat plugin is not loaded in this process")

    async def stream() -> AsyncIterator[bytes]:
        # The first byte is the handshake: a client waiting on the connection knows it is live
        # before the room says anything.
        yield b": ok\n\n"
        cursor = since
        quiet = 0.0
        while True:
            # The replay is written BEFORE the first disconnect check, so a phone that drops during
            # its own reconnect still costs exactly one pass rather than leaving a live generator.
            frames = feed.since(cursor)
            if frames:
                cursor = frames[-1]["seq"]
                quiet = 0.0
                for frame in frames:
                    yield f"id: {frame['seq']}\ndata: {json.dumps(frame)}\n\n".encode("utf-8")
            else:
                quiet += _TICK_SECONDS
                if quiet >= _KEEPALIVE_SECONDS:
                    quiet = 0.0
                    yield b": keep-alive\n\n"
            if await request.is_disconnected():
                return
            await asyncio.sleep(_TICK_SECONDS)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
