# AGENTS.md

CozyChat for Hermes is a Hermes Agent plugin (platform kind) that pairs the CozyChat iPhone app over the home network: a Noise-encrypted private-address listener, QR pairing, Dashboard routes and a Desktop page. This repository is the published copy of the plugin in the CozyChat monorepo.

## Layout

| Path | What |
| --- | --- |
| `__init__.py`, `plugin.yaml` | Entry point (`register()`) and manifest; versions must match |
| `relay/` | Tunnel, pairing, listener, files and push-device code |
| `dashboard/` | Authenticated Dashboard plugin routes and manifest |
| `desktop/` | Hermes Desktop sidebar page (plugin SDK and React only) |
| `tests/` | pytest suite, Node Desktop tests, interop vectors |

## Commands

Use a disposable environment and `HOME`/`HERMES_HOME`.

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q tests -k 'not test_hermes_admits_the_plugin'
node --test tests/desktop.test.mjs
hermes plugins validate . --json      # expect every check to pass
```

## Rules

- Never run `test_hermes_admits_the_plugin`, and never write the real `~/.hermes`.
- Keep the plugin inside the Hermes plugin SDK surface: no core rebinding, no self-update, no telemetry.
- Network, storage, command and file behavior is disclosed in the README; change both together.
- Every change ships with a test that fails without it.
- Never write credentials, host keys, pairing state or personal details into code, tests, docs or issues.
- See [CONTRIBUTING.md](CONTRIBUTING.md) for PR and commit conventions.
