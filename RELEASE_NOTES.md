# Release notes

## CozyChat for Hermes 0.6.0

First public release of the plugin. CozyChat on an iPhone connects directly to Hermes over home Wi-Fi: scan a QR, compare six digits, approve on the computer. The connection is a pinned Noise encrypted tunnel; CozyLabs runs no chat relay or hosted tunnel.

- **Pairing:** `hermes cozychat pair`, authenticated Dashboard routes and a Hermes Desktop sidebar page.
- **Private-address listener:** starts only when you open a pairing window; never binds a wildcard, loopback or public address; optional `_cozychat._tcp` discovery.
- **Keep reachable:** optional per-home login job so the phone can reconnect after a restart.
- **Notifications:** off by default per phone. Away-from-home push and Live Activities use `push.cozylabs.ai` only after explicit per-phone opt-in.
- **Hooks:** 13 hooks, no agent tools, no middleware, no required environment variables.

**Install:** needs Hermes 0.21.6 or later. Until the community catalog entry is approved, install the reviewed commit:

```sh
hermes plugins install shiftedx/cozychat-hermes-plugin --ref <COMMIT> --enable --yes-deps
```

where `<COMMIT>` is the full 40-character SHA of the release commit named in the catalog entry. Updates are user-initiated through Hermes. See the [README](README.md) for the full privacy and access disclosures.
