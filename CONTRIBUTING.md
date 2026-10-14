# Contributing

Bug reports, fixes and focused features are welcome. This repository is the published copy of a plugin developed in the CozyChat monorepo, where it is tested alongside the iPhone app and a shared protocol. For anything larger than a bug fix, open an issue first so we can agree on the approach.

## Setup

Clone into a directory named `cozychat`. The plugin imports itself as the `cozychat` package, so pytest only resolves it when the checkout's directory has that name:

```bash
git clone https://github.com/shiftedx/cozychat-hermes-plugin cozychat
cd cozychat
python -m pip install -r requirements-dev.txt
python -m pytest -q tests -k 'not test_hermes_admits_the_plugin'
node --test tests/desktop.test.mjs
```

Use a throwaway `HOME` and `HERMES_HOME`; never run the admission test or `hermes plugins validate` against a personal Hermes installation. Two tests read app source files that exist only in the CozyChat monorepo; in a standalone clone they skip with a reason instead of failing. See the README's Develop and test section.

## Pull requests

1. Branch from `main`. `main` is protected: changes land through pull requests only.
2. Keep each PR to one change. Add or update tests with the code.
3. Run the tests above and paste the final lines in the PR. There is no hosted CI, so this local run is the gate.
4. Update the README when a disclosure changes (network, storage, commands or files).

Commits follow [Conventional Commits](https://www.conventionalcommits.org): `fix(pairing): ...`, `feat(files): ...`, `docs: ...`. Reference the issue (`#123`) when there is one.

## Rules

- Never commit credentials, host keys, pairing state, real hostnames or personal details, including in tests and fixtures. Use `example.com`, `home.arpa` and documentation IP ranges.
- No new runtime dependency without a reason in the PR description.
- The plugin must not self-update, rebind Hermes core, or add telemetry.
- Security issues go through [SECURITY.md](SECURITY.md), not public issues.

Coding agents: start with [AGENTS.md](AGENTS.md).

By contributing you agree your work is licensed under the [MIT License](LICENSE).
