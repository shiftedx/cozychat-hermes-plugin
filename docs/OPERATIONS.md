# CozyChat for Hermes

Pair the CozyChat iPhone app with Hermes on your computer over your home network: QR pairing, end-to-end encrypted, no hosted chat relay.

[![MIT](https://img.shields.io/badge/license-MIT-blue)](https://github.com/shiftedx/cozychat-hermes-plugin/blob/main/LICENSE)
[Release notes](https://github.com/shiftedx/cozychat-hermes-plugin/blob/main/RELEASE_NOTES.md) ·
[Contributing](https://github.com/shiftedx/cozychat-hermes-plugin/blob/main/CONTRIBUTING.md) ·
[Security](https://github.com/shiftedx/cozychat-hermes-plugin/blob/main/SECURITY.md)

## Requirements

- Hermes 0.21.6 or later, Python 3.11 or later
- macOS, Linux, native Windows or WSL (WSL2 NAT needs mirrored networking or forwarding)
- CozyChat on iPhone, on the same Wi-Fi as the computer

## Install

Catalog (once listed), or Hermes Desktop > Plugins > CozyChat:

```sh
hermes plugins install cozychat --enable --yes-deps
```

Manual, pinned to the full commit named in the CozyChat app's setup screen:

```sh
hermes plugins install shiftedx/cozychat-hermes-plugin --ref <40-hex-commit> --enable --yes-deps
```

Updates go through Hermes. Dependencies (`cryptography`,
`psutil`, `zeroconf`, `qrcode`, `pypng`) install with consent; bounds are in
[plugin.yaml](../plugin.yaml). Without `zeroconf`, pairing uses the QR's addresses instead of mDNS.

## Pair

1. Hermes Desktop: open **CozyChat** in the sidebar (the first visit opens a 10-minute window; later, **Pair a phone**).
2. CozyChat on the phone: **Connect to Hermes**, scan the QR, allow Local Network.
3. Confirm both screens show the same six digits, then **Approve** on the computer.

No Desktop? Enable Hermes's API Server, keep its gateway running, run `hermes cozychat pair`, and press Enter to approve.

## CLI

| Command | Does |
|---|---|
| `hermes cozychat pair [--advertise HOST:PORT]...` | Show the QR, approve the phone. `--advertise` adds an address hint (repeatable). `--no-push` is an accepted no-op |
| `hermes cozychat list` | List paired phones (id, name) |
| `hermes cozychat revoke PHONE_ID [--rotate]` | Remove a phone and its notifications; `--rotate` also rotates the API key |
| `hermes cozychat rotate` | Rotate the API key; drains and restarts the gateway |
| `hermes cozychat push enable\|disable PHONE_KEY` | Advanced; the app normally does this. `enable` reads `registration.json` on stdin |

`registration.json`: `push_id`, `key_hex`, `environment`, `profile`, `consent_version: 1`, optional `filters`. Keep it private.

## Away from home

- Put phone and computer on a VPN you already run and pair while connected. CozyChat does not set up VPNs.
- Optional push relay `push.cozylabs.ai`: off until you turn on **Notify me when I'm away from home** per phone. Without it, nothing contacts that host.
- Self-hosted relay (`pair --relay WSS_URL`) is advanced and unreleased: 0.6.0 stores the URL but has no relay client.

## Keep reachable

Desktop pairing's **Keep reachable when Hermes Desktop is closed** (default on) installs a per-user login job for Hermes's gateway: launchd agent (macOS), systemd user unit (Linux), Scheduled Task (Windows). The computer must still be awake and on the network.
Turn it off on the same page to remove it; uninstalling the plugin alone does not.

## Settings

`plugins.entries.cozychat.settings` in `config.yaml`; keys and defaults are in [plugin.yaml](../plugin.yaml).

| Key | Effect |
|---|---|
| `lan: false` or `COZYCHAT_LAN=0` | Stop listening |
| `lan_advertise: false` | Disable mDNS discovery; QR addresses still work |
| `push_replies`, `push_approvals`, `push_rooms` | Per-category filters for opted-in phones |
| `preview_mode: none` | Content-free push alerts |
| `relay_url` | Push endpoint (default `https://push.cozylabs.ai`) |
| `security.approval.transport: cozychat` | Answer Hermes approvals from the phone; silence times out, never approves |

## Remove / unpair

- One phone: **Remove** in the Desktop phone list, or `hermes cozychat revoke PHONE_ID`. Add `--rotate` if the phone should lose the API key.
- Everything: switch off **Keep reachable**, `hermes plugins disable cozychat`, then delete `<Hermes root>/cozychat/` (pairings, keys, queued notifications).

## Privacy and security

- Listens only on private-network addresses (never wildcard, loopback or public; `100.64/10` only on a VPN interface), and only after the first pairing window opens.
- The QR holds a short-lived secret, not an API key. A phone gets Hermes credentials only through the encrypted connection after you approve.
- Push is opt-in per phone. Payloads are allowlisted, then sealed with AES-256-GCM; commands, tool arguments, paths and transcripts never leave. Live Activity cards are content-free JSON. The relay sees source IP, timing and sizes.
- State in `<Hermes root>/cozychat/` (host key, phone keys, queues) is mode 0700/0600 on POSIX; queued payloads are plaintext until sealed.
- No telemetry. Report vulnerabilities per [SECURITY.md](https://github.com/shiftedx/cozychat-hermes-plugin/blob/main/SECURITY.md).

## Troubleshooting

| Symptom | Fix |
|---|---|
| "The home-network listener is off" | Remove `lan: false` / `COZYCHAT_LAN=0` |
| "Update Hermes to use CozyChat" | Upgrade to 0.21.6 or later |
| Phone cannot find the computer | Same Wi-Fi, allow iOS Local Network, check VPN/firewall; try `--advertise HOST:PORT` |
| Fails under WSL | Use native Windows Hermes, or mirrored networking/forwarding to the listener port |
| Unreachable when Desktop is closed | Enable **Keep reachable**; keep the computer awake |
| Rotation not verified | Restart Hermes after the current chat ends, then recheck the phone |
| No away-from-home notifications | Enable the per-phone toggle; check `push_*` filters |

## Develop and test

Use a throwaway `HOME` and `HERMES_HOME`; never run the admission test against a personal Hermes.

```sh
python -m pip install -r requirements-dev.txt
python -m pytest -q tests -k 'not test_hermes_admits_the_plugin'
node --test tests/desktop.test.mjs
hermes plugins validate . --install-deps
```

Licensed under [MIT](https://github.com/shiftedx/cozychat-hermes-plugin/blob/main/LICENSE).
