# CozyChat for Hermes

Pair the CozyChat iPhone app with Hermes on your computer: QR pairing,
end-to-end encryption, and direct home-network chat with no hosted chat relay.
Requires **Hermes 0.21.6+** and CozyChat on iPhone.

[Operations guide](docs/OPERATIONS.md) · [Release notes](RELEASE_NOTES.md) · [Security](SECURITY.md) · [MIT](LICENSE)

## Install and pair

Use Hermes Desktop > Plugins > CozyChat, or the catalog once listed:

```sh
hermes plugins install cozychat --enable --yes-deps
```

For manual installation, use the full commit shown in CozyChat's setup screen:

```sh
hermes plugins install shiftedx/cozychat-hermes-plugin --ref <40-hex-commit> --enable --yes-deps
```

Dependencies install with consent; versions are bounded in [plugin.yaml](plugin.yaml).
Update through Hermes. Without `zeroconf`, the QR supplies addresses instead of mDNS.

1. Open **CozyChat** in Hermes Desktop; choose **Pair a phone** (first visit opens a 10-minute window).
2. On iPhone, choose **Connect to Hermes**, scan the QR, and allow Local Network.
3. Match the six digits, then **Approve** on the computer.

Without Desktop: enable Hermes's API Server, keep the gateway running, and run
`hermes cozychat pair`; press Enter to approve.

## Privacy and reachability

- Listens only on private addresses after pairing opens; never wildcard, loopback, or public. `100.64/10` is allowed only on VPN interfaces.
- The QR contains a short-lived secret. Hermes credentials reach the phone through the encrypted connection after approval.
- **Keep reachable when Hermes Desktop is closed** defaults on and installs a per-user gateway login job: launchd, systemd, or Windows Scheduled Task. The computer must remain awake and connected. Disable it on the pairing page; uninstall alone does not remove it.
- Away from home, use a VPN you operate. The advanced self-hosted relay client is unreleased; 0.6.0 only stores its URL.
- Push to `push.cozylabs.ai` is off until enabled per phone. Allowlisted payloads use AES-256-GCM; commands, tool arguments, paths, and transcripts never leave. Live Activity cards contain no content; the relay sees IP, timing, and sizes.
- Keys, pairings, and queues stay under `<Hermes root>/cozychat/`, mode 0700/0600 on POSIX. Queued payloads are plaintext until sealed. No telemetry.

## Operate

| Task | Action |
| --- | --- |
| Inspect phones | `hermes cozychat list` |
| Remove a phone / its notifications | `hermes cozychat revoke PHONE_ID`; add `--rotate` to rotate the API key |
| Rotate the API key | `hermes cozychat rotate` (drains/restarts the gateway) |
| Disable listener / discovery | `lan: false` or `COZYCHAT_LAN=0` / `lan_advertise: false` |
| Filter notifications / omit previews | `push_replies`, `push_approvals`, `push_rooms` / `preview_mode: none` |
| Answer approvals on phone | `security.approval.transport: cozychat`; silence times out |

Settings live in `plugins.entries.cozychat.settings` in `config.yaml`.
[CLI, push registration, endpoint settings, and troubleshooting](docs/OPERATIONS.md).

To remove everything, switch off **Keep reachable**, disable the plugin with
`hermes plugins disable cozychat`, then delete `<Hermes root>/cozychat/`.
This deletes keys, pairings, and queued notifications.

## Develop and test

Clone into a directory named `cozychat`; use disposable `HOME` and `HERMES_HOME`.
Never run the admission test against personal Hermes.

```sh
python -m pip install -r requirements-dev.txt
python -m pytest -q tests -k 'not test_hermes_admits_the_plugin'
node --test tests/desktop.test.mjs
```

[Contributing](CONTRIBUTING.md) covers safe validation and monorepo-only checks.
