# Security policy

## Reporting a vulnerability

Please report security problems **privately**, not in a public issue or pull request.

- Email: **info@f2c.io**
- Or use GitHub private vulnerability reporting: the repository's **Security** tab, **Report a vulnerability**.

Include the agent version (`f2c-agent version`), what you did, what you expected and what happened. Never include tokens, join tokens
(`f2cj_...`), server tokens (`f2cs_...`), private keys or other secrets in a report; describe where they appear instead.

We aim to acknowledge a report within 3 working days and to tell you the outcome or a plan within 14 days. Please give us a reasonable
time to release a fix before you disclose the problem publicly; we will credit you if you wish.

## Scope

In scope: the agent (`cmd/`, `internal/`), `deploy/install.sh` and `deploy/harden.sh`, the systemd units, the release signing and verification
(`scripts/release.sh`, `keys/`, `cmd/ed25519tool`), and the wire protocol in `docs/protocol.md`. The F2C engine is a separate component and
is not part of this repository.

## Supported versions

Security fixes go into the latest release only. Upgrade by re-running the install command from the README, or let the agent update itself
from a signed release.

## Release integrity

Releases are signed: `SHA256SUMS` carries an ed25519 signature, and `deploy/install.sh` and the agent refuse a binary whose signature does
not verify against the keys in `keys/release-keys.json`. See "Verify a release" in the README.

If you find a way to get an unsigned or wrongly signed file installed, please report it as above.

Release key fingerprints (SHA-256 of the raw 32-byte ed25519 public key; the key id is its first 16 hex characters):

- primary: `d5be90e42c884807626d7488bd6a755ada3a8c93c94881e62ad2087e8467bc8f`
- backup: `3d4fe084d4acbab8f9fe3b4712298e5f5d1f924c1a7fecc5fc8e42a1c718a584`
