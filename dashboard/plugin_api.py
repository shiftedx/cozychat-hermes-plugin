"""CozyChat's Desktop pairing API, mounted behind Hermes's existing auth and plugin gates.

Hermes loads this file on its own, not as a package. Keep the existing feed router and reach the
registered pairing surface through the package Hermes already loaded in this process.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

from fastapi import Body, HTTPException, Response

_spec = importlib.util.spec_from_file_location("hermes_dashboard_cozychat_feed",
                                              Path(__file__).with_name("api.py"))
_feed = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_feed)
router = _feed.router


def _page():
    package = _feed._package()
    if package is None or not hasattr(package, "pairing_page"):
        raise HTTPException(503, "Enable the CozyChat plugin in Hermes to pair your phone.")
    return _call(package.pairing_page)


def _call(action, *args, **kwargs):
    try:
        return action(*args, **kwargs)
    except (RuntimeError, OSError, ValueError, TypeError, AttributeError, ImportError, SystemExit,
            subprocess.SubprocessError) as error:
        # No exception detail from Hermes config/service helpers: it may contain a credential
        # or an operator path. PageError's authored copy is the only exception we publish.
        status = getattr(error, "status", 503)
        message = str(error) if hasattr(error, "status") else \
            "Hermes could not finish setup. Check Hermes, then choose Pair a phone again."
        raise HTTPException(status, message) from error


def _private(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


@router.post("/pair/open")
def open_pairing(response: Response, body: dict = Body(default={})) -> dict:
    _private(response)
    automatic = body.get("automatic", False)
    if type(automatic) is not bool:
        raise HTTPException(400, "Choose Pair a phone to open a code.")
    return _call(_page().open, automatic=automatic)


@router.get("/pair/state")
def pairing_state(response: Response) -> dict:
    _private(response)
    return _call(_page().state)


@router.get("/pair/qr")
def pairing_qr(response: Response) -> dict:
    _private(response)
    return _call(_page().qr)


@router.post("/pair/approve")
def approve_pairing(body: dict = Body(default={})) -> dict:
    return _call(_page().decide, body.get("id"), True)


@router.post("/pair/refuse")
def refuse_pairing(body: dict = Body(default={})) -> dict:
    return _call(_page().decide, body.get("id"), False)


@router.get("/phones")
def phones(response: Response) -> dict:
    _private(response)
    return {"phones": _call(_page().phones)}


@router.delete("/phones/{phone_id}")
def remove_phone(phone_id: str, body: dict = Body(default={})) -> dict:
    return _call(_page().remove, phone_id, rotate=body.get("rotate", False))


@router.post("/rotate")
def rotate_key(response: Response) -> dict:
    _private(response)
    return _call(_page().rotate)


@router.post("/push/cleanup")
def retry_push_cleanup() -> dict:
    return _call(_page().retry_push_cleanup)


@router.post("/reachable")
def reachable(body: dict = Body(default={})) -> dict:
    return _call(_page().set_reachable, body.get("enabled"))
