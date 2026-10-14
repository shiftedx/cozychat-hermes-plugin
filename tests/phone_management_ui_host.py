"""macOS UI-test listener. Prints disposable fixture credentials; stdin EOF stops it.

Use a throwaway HOME and HERMES_HOME under /private/tmp. Export the printed values as
COZY_PAIRED_PHONES_LINK, COZY_PAIRED_PHONE_PRIVATE_KEY and COZY_PAIRED_OTHER_PHONE_ID to the UI
test process. --omit-management also requires COZY_PAIRED_PHONES_OMITS_MANAGEMENT=1.
No Hermes process or simulator is started by this harness.
"""

import argparse
import asyncio
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cozychat.relay import noise, pairing
from test_phone_management import approve, tunnel_at


async def main(omit_management):
    with tempfile.TemporaryDirectory(prefix="cz-phones-ui-", dir="/private/tmp") as scratch:
        tunnel = tunnel_at(Path(scratch) / "hermes")
        private = noise.generate_private_key()
        other = noise.generate_private_key()
        approve(tunnel.store, noise.public_key(private), "This iPhone")
        approve(tunnel.store, noise.public_key(other), "Other iPhone")
        if omit_management:
            capabilities = tunnel.capabilities
            def without_management(hints):
                document = capabilities(hints)
                document["services"]["control"]["device_management"] = None
                return document
            tunnel.capabilities = without_management
        listener = tunnel.make_listener(port=0)
        await listener.start()
        try:
            window = tunnel.store.open_window()
            link = pairing.pairing_link(tunnel.store.host_public(), window, listener.hints())
            tunnel.store.cancel_window()
            print(json.dumps({"COZY_PAIRED_PHONES_LINK": link,
                "COZY_PAIRED_PHONE_PRIVATE_KEY": private.hex(),
                "COZY_PAIRED_OTHER_PHONE_ID": noise.public_key(other).hex(),
                "COZY_PAIRED_PHONES_OMITS_MANAGEMENT": "1" if omit_management else "0"}), flush=True)
            await asyncio.to_thread(sys.stdin.read)
        finally:
            await listener.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--omit-management", action="store_true")
    asyncio.run(main(parser.parse_args().omit_management))
