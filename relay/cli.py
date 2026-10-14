"""``hermes cozychat pair``: show a pairing QR, then approve the phone with Enter.

No questions about routes (D15). Flags only:

``--advertise HOST:PORT``
    An extra address hint for the QR, repeatable: a VPN address or a forwarded port the person set
    up themselves. Remote access is theirs to arrange; CozyChat only carries the hint.
``--no-push``
    Backward-compatible no-op. Push is already off until a phone opts in.
``--relay WSS_URL``
    A self-hosted relay. Stored and put in the QR; the relay client ships after launch.

The window lasts 10 minutes. The listener that answers the phone is whichever process holds the
lock (``owner.py``); when no Hermes process is running one, this command runs it for as long as it
runs, so pairing works with nothing else started.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from typing import Callable, List, Optional, TextIO

from ..locks import exclusive
from . import pairing, platform
from .desktop import Gateway
from .reachable import HermesService
from .runtime import Tunnel
from .services import UPDATE_HERMES_COPY
from .control import ControlError

POLL_SECONDS = 0.25


def setup(parser: argparse.ArgumentParser) -> None:
    """``setup_fn`` for ``register_cli_command``: the ``cozychat`` subcommand tree."""
    commands = parser.add_subparsers(dest="cozychat_command", metavar="COMMAND")
    pair = commands.add_parser(
        "pair", help="Pair a phone with this computer over your home network",
        description="Shows a QR for CozyChat to scan, then asks you to approve the phone.")
    pair.add_argument("--advertise", action="append", default=[], metavar="HOST:PORT",
                      help="Extra address for the phone to try, such as a VPN address. Repeatable.")
    pair.add_argument("--no-push", action="store_true",
                      help="Accepted for compatibility; notifications are off by default.")
    push = commands.add_parser("push", help="Enable or disable away-from-home notifications")
    push.add_argument("action", choices=("enable", "disable"))
    push.add_argument("phone", help="Paired phone public key from the Desktop phone list")
    pair.add_argument("--relay", metavar="WSS_URL",
                      help="A relay you run yourself (advanced).")
    commands.add_parser("list", help="List phones paired with this computer")
    revoke = commands.add_parser("revoke", help="Remove a paired phone and its notifications")
    revoke.add_argument("phone_id", metavar="PHONE_ID", help="Phone id from hermes cozychat list")
    revoke.add_argument("--rotate", action="store_true",
                        help="Also rotate the shared API key (drains and restarts the gateway)")
    commands.add_parser("rotate", help="Rotate the API key; drains and restarts the gateway")


def handler(tunnel_factory: Callable[[], Tunnel]) -> Callable[[argparse.Namespace], int]:
    """``handler_fn`` for ``register_cli_command``."""
    def handle(args: argparse.Namespace) -> int:
        command = getattr(args, "cozychat_command", None)
        if command not in ("pair", "push", "list", "revoke", "rotate"):
            print("usage: hermes cozychat {pair,push,list,revoke,rotate}", file=sys.stderr)
            return 2
        tunnel = tunnel_factory()
        if command == "push":
            return set_push(tunnel, args.action, args.phone)
        if command == "pair":
            return pair(tunnel, advertise=args.advertise, push=False, relay=args.relay)
        try:
            if command == "list":
                for phone in tunnel.management.phones():
                    print(f'{phone["id"]}  {phone["name"]}')
            elif command == "revoke":
                result = tunnel.management.revoke(args.phone_id, rotate=args.rotate)
                print("Phone removed.")
                if args.rotate:
                    return _rotation_result(tunnel, result)
            else:
                return _rotation_result(tunnel, tunnel.management.rotate())
            return 0
        except (ControlError, OSError, RuntimeError) as error:
            code = str(error) if isinstance(error, ControlError) else "operation_failed"
            print(f"hermes cozychat {command}: {code}", file=sys.stderr)
            return 1
    return handle


def _rotation_result(tunnel: Tunnel, result) -> int:
    if result.get("rotated") or tunnel.rotation.wait():
        print("API key rotated. The old key is no longer accepted.")
        return 0
    print("The new key was saved, but rotation has not been verified. Restart Hermes after your "
          "current chat finishes, then check phone access.", file=sys.stderr)
    return 1


def pair(tunnel: Tunnel, *, advertise: List[str], push: bool, relay: Optional[str],
         prompt: Callable[[str], str] = input, out: TextIO = sys.stdout,
         run_listener: bool = True, owner_tick: float = 0.5) -> int:
    """The whole command. Returns the exit status."""
    try:
        advertise = [pairing.check_advertise(a) for a in advertise]
        relay = pairing.check_relay_url(relay) if relay else None
    except ValueError as error:
        print(f"hermes cozychat pair: {error}", file=out)
        return 2
    if not tunnel.enabled:
        print("The home-network listener is off (lan: false in the plugin config, or "
              "COZYCHAT_LAN=0). Turn it on to pair a phone.", file=out)
        return 1

    if not tunnel.secret_scope_ready():
        print(UPDATE_HERMES_COPY, file=out)
        return 1

    network_note = platform.pairing_network_note()
    if network_note is not None:
        print(network_note, file=out)
    store = tunnel.store
    try:
        store.ensure()
        with exclusive(store.root / "desktop.lock"):
            Gateway(tunnel, HermesService(tunnel.home)).ensure()
            window = store.open_window({"relay": relay, "advertise": advertise})
    except (OSError, RuntimeError) as error:
        print(f"hermes cozychat pair: {error}", file=out)
        return 1
    owner = tunnel.owner(tick_seconds=owner_tick).start() if run_listener else None
    try:
        return _pair(tunnel, window, relay, prompt, out, owner)
    except (KeyboardInterrupt, EOFError):
        store.cancel_window(window.id)
        print("\nCancelled. The code no longer works.", file=out)
        return 130
    finally:
        if owner is not None:
            owner.stop()


def _pair(tunnel: Tunnel, window: pairing.Window, relay: Optional[str],
          prompt: Callable[[str], str], out: TextIO, owner) -> int:
    store = tunnel.store
    if owner is not None:
        owner.tick()  # claim now if nobody else holds the listener, rather than in half a second
    listener = owner.listener if owner is not None else None
    hints = tunnel.listening_hints()
    if not hints and not relay:
        store.cancel_window(window.id)
        print("This computer has no home-network address to offer (no Wi-Fi or Ethernet on a "
              "private network). Connect it to your network and try again.", file=out)
        return 1

    link = pairing.pairing_link(store.host_public(), window, hints, relay)
    until = datetime.fromtimestamp(window.exp).strftime("%H:%M")
    _print_qr(link, out)
    print(link, file=out)
    print(f"\nScan this with CozyChat on your phone. It works until {until}.", file=out)
    if listener is not None:
        print("Nothing else is running the listener, so this command does. Keep it open while "
              "you pair.", file=out)
    out.flush()

    asked: Optional[str] = None
    while True:
        if store.window() is None or store.window().id != window.id:
            print("The pairing window closed before a phone was approved.", file=out)
            return 1
        attempt = store.attempt()
        if attempt is None or attempt.window_id != window.id or attempt.decision is not None \
                or attempt.id == asked:
            time.sleep(POLL_SECONDS)
            continue
        asked = attempt.id
        answer = prompt(f'Pair "{attempt.phone_name}"? code {pairing.grouped(attempt.code)}. '
                        "Press Enter to approve, anything else to refuse. ")
        approve = answer.strip() == ""
        if not store.decide(attempt.id, approve):
            print("That phone went away before you answered. Waiting for it to try again.",
                  file=out)
            continue
        if not approve:
            _wait_settled(store, attempt.id)
            store.cancel_window(window.id)
            print("Refused. The code no longer works.", file=out)
            return 1
        if _wait_approved(store, attempt.phone_key):
            # Give the listener a moment to tell the phone before this process (if it is the
            # listener) goes away.
            time.sleep(1.0 if listener is not None else 0)
            print(f'Paired "{attempt.phone_name}".', file=out)
            return 0
        print("The phone disconnected before pairing finished. Scan again to retry.", file=out)


def _wait_approved(store: pairing.PairingStore, phone_key: bytes, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if store.is_approved(phone_key):
            return True
        time.sleep(POLL_SECONDS)
    return False


def _wait_settled(store: pairing.PairingStore, attempt_id: str, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = store.attempt()
        if current is None or current.id != attempt_id:
            return
        time.sleep(POLL_SECONDS)


def _print_qr(link: str, out: TextIO) -> None:
    try:
        import qrcode
    except ImportError:
        print("(Install the qrcode package to see a QR here. You can also paste the link below "
              "into CozyChat.)", file=out)
        return
    code = qrcode.QRCode(border=1)
    code.add_data(link)
    code.print_ascii(out=out, invert=True)


def set_push(tunnel: Tunnel, action: str, phone: str, *, payload=None, out: TextIO = sys.stdout) -> int:
    """Enable consumes the device JSON on stdin; disable also deregisters the phone and its cards."""
    import json

    try:
        key = bytes.fromhex(phone)
        if len(key) != 32 or not tunnel.store.is_approved(key) or tunnel.push_devices is None:
            raise ValueError("Choose an approved phone from the CozyChat Desktop page.")
        request = {"op": "device.remove", "profile": "default"}
        if action == "enable":
            request = {"op": "device.add", "device": json.load(sys.stdin) if payload is None else payload}
        if action == "disable":
            devices = tunnel.push_devices.handle(key, {"op": "device.list"})["devices"]
            for device in devices:
                tunnel.push_devices.handle(key, {"op": "device.remove", "profile": device["profile"]})
            tunnel.push_devices.retry_retirements()
            if tunnel.push_devices.pending_retirements(key.hex()):
                print("Cleanup could not finish. Try again when the relay is reachable.", file=out)
                return 1
            print("Away-from-home notifications disabled.", file=out)
            return 0
        tunnel.push_devices.handle(key, request)
    except (ValueError, TypeError, KeyError, OSError) as error:
        print(f"hermes cozychat push: {error}", file=out)
        return 1
    print("Away-from-home notifications enabled.", file=out)
    return 0
