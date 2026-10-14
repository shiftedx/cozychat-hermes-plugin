# Security policy

## Reporting

Report vulnerabilities through GitHub [private vulnerability reporting](https://github.com/shiftedx/cozychat-hermes-plugin/security/advisories/new), not public issues. Include the plugin version or commit, Hermes version, host OS, impact and reproduction steps. Use synthetic accounts and devices, and leave out API keys, host private keys, pairing codes, tokens and personal data.

Only the latest release is supported. Response is best-effort: acknowledgement within 3 business days, an initial assessment within 7, updates every 14 while a confirmed issue is open. Disclosure normally follows a fixed release, or 90 days after confirmation. There is no bug bounty. Good-faith research on systems you own or are authorised to test is welcome.

## In scope

Issues reproducible in the latest release using:

- the pairing flow (QR, six-digit comparison, approval on the computer) and the pinned Noise encrypted connection;
- the private-address listener: it must never bind a wildcard, loopback or public address, and an unpaired or unapproved peer must never receive the Hermes API key or any chat data;
- stored state under the Hermes `cozychat/` directory (host key, approved phones, push keys): permissions and what leaves the machine;
- the opt-in push and Live Activity requests, which must carry only the sealed or content-free payloads the README discloses;
- the tunnel `files` service, which may read only its trusted roots and write only to its quota-limited inbox;
- the Dashboard routes and Desktop page.

Out of scope: a compromised computer or phone, a hostile network that the user has bridged to the listener with their own port forwarding, social engineering, VPN misconfiguration, and bugs in Hermes or in the CozyChat iOS app (report those to their projects). Upstream dependency bugs are in scope when a supported configuration exposes them.
