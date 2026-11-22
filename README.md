# f2c-agent

The F2C server agent. It runs on a Linux server you own, dials the F2C engine over a secure WebSocket (`wss://<engine>/agent`),
sends a heartbeat every 15 seconds, and runs engine commands against the local Docker and Caddy (pull, run, build, route,
certificates, logs, console, and an optional "Harden server" step). It only touches containers it created (label `f2c.agent=1`).

- Language: Go (`go 1.26`), one dependency (`github.com/coder/websocket`).
- Licence: MIT (see [LICENSE](LICENSE)).
- Wire protocol: see [docs/protocol.md](docs/protocol.md) (draft v1).

## Install standalone

No engine is needed to install the agent. On a fresh Ubuntu/Debian server (systemd, `curl`, OpenSSL 3), as root:

```sh
curl -fsSL https://github.com/vinodkumar937/f2c-agent/releases/latest/download/install.sh | sudo sh -s -- --roles build,run
```

`install.sh` downloads everything from the public GitHub release (the agent for the server's architecture, the systemd units and the
other install files, and `SHA256SUMS` with its signatures). It verifies `SHA256SUMS` against the release public keys embedded in the
script, then checks every file against it; a bad or missing signature stops the install. It installs Docker and Caddy from their
official apt repositories if they are missing, sets up a default-deny `ufw` (SSH, 80, 443; `--no-firewall` skips it), creates the
`f2c-agent` user and installs the agent and its units. **The service is left disabled** until the server has joined an engine.
Options: `--roles build|run|build,run`, `--wildcard-domain` and `--dns-provider` (see below), `--version 0.4.0` (or `F2C_VERSION`) to
pin a release instead of the latest, `--no-firewall`, `--harden` (optional host hardening, off by default), `DRY_RUN=1` to preview.
`F2C_RELEASE_BASE` points the installer at a mirror of the GitHub release layout (`<base>/v<version>/<file>`).
Most options also have an environment form (`F2C_ROLES`, `F2C_WILDCARD_DOMAIN`, `F2C_DNS_PROVIDER`, `F2C_ENGINE`, `F2C_JOIN_TOKEN`,
`F2C_FIREWALL=0|1`); `SKIP_DEPS=1` only checks for Docker and Caddy, `F2C_AGENT_BIN=./f2c-agent` installs a local build (not verified),
and `--reattach` re-registers a server that already has an `agent.json`. The header of `deploy/install.sh` describes every option.

To read the script before running it, or to verify it first, download it instead of piping it (see [Verify a release](#verify-a-release)):

```sh
V=0.4.0   # a release from https://github.com/vinodkumar937/f2c-agent/releases
B=https://github.com/vinodkumar937/f2c-agent/releases/download/v$V
curl -fsSLO $B/install.sh -O $B/SHA256SUMS -O $B/SHA256SUMS.sigs -O $B/SHA256SUMS.sig   # then verify, then:
sudo sh install.sh --roles build,run --version $V
```

DNS-01 wildcard certificates (`--dns-provider cloudflare|digitalocean`) need the f2c Caddy build, which is published as the GitHub release
`caddy-v2.11.7-do1-cf1-ad1` of this repository by the `caddy-binaries.yml` workflow (hashes also listed in the signed `SHA256SUMS`).
Use `--dns-provider other` (stock Caddy, on-demand HTTP-01) instead, or set `F2C_CADDY_URL` (and `F2C_CADDY_TAG`) to your own build.

## Join an engine later

Joining needs the engine's URL and a one-time join token (`f2cj_...`) from the engine's "Add server" screen:

```sh
sudo runuser -u f2c-agent -- /var/lib/f2c-agent/bin/f2c-agent join \
  --state-dir /var/lib/f2c-agent --engine https://engine.example.com --token f2cj_...
sudo systemctl enable --now f2c-agent
```

`join` saves `/var/lib/f2c-agent/agent.json` (mode 0600). The unit has `ConditionPathExists=/var/lib/f2c-agent/agent.json`, so until the
server has joined it is skipped instead of crash-looping. Or join during the install by adding `--engine https://engine.example.com --token f2cj_...`
to the install command: the installer then runs `join` and enables the service. Re-running `install.sh` on a server that already has an
`agent.json` keeps its identity and never uses another token. The engine must be reachable over `https://` (plain `http://` is only
accepted for a loopback engine); the agent connects outbound on 443, there is no inbound agent port.

Manual use of the binary:

```sh
f2c-agent join --engine https://engine.example.com --token f2cj_...    # one-time; saves <state-dir>/agent.json (0600)
f2c-agent run  [--state-dir /var/lib/f2c-agent] [--caddy-admin http://127.0.0.1:2019] [--cert-dir DIR]
f2c-agent reattach [--engine URL]                                      # after the engine lost this server
f2c-agent version
```

`run` also takes `--caddy-certs DIR` (Caddy's certificate storage to watch), `--access-listen` and `--ask-listen` (loopback addresses for
Caddy's access log and on-demand TLS ask; defaults `127.0.0.1:9181` and `127.0.0.1:9180`); `join` takes `--provider` and `--public-ip`.
Environment: `F2C_AGENT_STATE_DIR` (default state dir), `DOCKER_HOST` (a `unix://` socket), `BUILDKIT_HOST` (use this BuildKit instead
of the `f2c-buildkit` container), `F2C_AGENT_SWEEP=0` (no hourly cleanup of stale image uploads and old `f2c/*` images), `F2C_AGENT_NPM_CI=0` (do not switch
npm builds with a lockfile to `npm ci`).

Manual host hardening: `deploy/harden.sh --dry-run --skip-agent-check` previews the changes before a join;
`--apply --skip-agent-check` applies them. To restore a harden backup, run
`deploy/harden.sh --rollback last` (or a backup id). Rollback skips the agent-active and agent-connected checks by
default, so it also works while the agent is stopped; the file, firewall and SSH restore checks still run.
Use `--rollback-agent-check` to opt back into the agent checks for rollback. Apply and dry run are unchanged.

## Verify a release

Every release has `SHA256SUMS` (a signed `# ` header, then `sha256  file` lines), `SHA256SUMS.sigs` (JSON list of ed25519 signatures,
each naming its key by id) and `SHA256SUMS.sig` (the raw 64-byte signature, for older verifiers). The trusted public keys are
[`keys/release-keys.json`](keys/release-keys.json) (also embedded in `deploy/install.sh` and the agent). Download the files of a release
into one directory, then:

```sh
# 1. the signature, against each trusted key until one verifies (release-key.pub: see below)
openssl pkeyutl -verify -pubin -inkey release-key.pub -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig      # OpenSSL 3; prints "Signature Verified Successfully"
#    or, with this repository checked out (raw base64 key from keys/release-keys.json):
go run ./cmd/ed25519tool verify-b64 <public key base64> SHA256SUMS SHA256SUMS.sig
# 2. the files
sha256sum --ignore-missing -c SHA256SUMS
```

`release-key.pub` is a PEM file: `-----BEGIN PUBLIC KEY-----`, the `MCowBQYDK2Vw...` value from the key block of `deploy/install.sh` (one file
per key; the value only, without the key id, the status or the closing `"`), `-----END PUBLIC KEY-----`. A signature by a key that is not in the list, or by one marked `revoked`, must not be trusted.

Release key fingerprints (key id = first 8 bytes of the SHA-256 of the raw 32-byte public key, as 16 hex characters; the fingerprint is that full SHA-256):

| Key | Key id | SHA-256 of the raw public key |
|---|---|---|
| primary | `d5be90e42c884807` | `d5be90e42c884807626d7488bd6a755ada3a8c93c94881e62ad2087e8467bc8f` |
| backup | `3d4fe084d4acbab8` | `3d4fe084d4acbab8f9fe3b4712298e5f5d1f924c1a7fecc5fc8e42a1c718a584` |

Both are listed in `keys/release-keys.json`; check them against that file and against `sh install.sh --print-keys` (ids), and
against the release notes. The release signing key is held offline by the maintainers; a backup key is held separately.

## Supported systems

- Server (agent runtime): Linux, `amd64` and `arm64`, with systemd and Docker. `deploy/install.sh` needs OpenSSL 3
  (Ubuntu 22.04+ / Debian 12+). The agent runs as the non-root user `f2c-agent`.
- Building and testing from source also works on macOS (the agent's Linux-only metrics have a stub).

## Layout

```
cmd/f2c-agent/      the binary: flags, version and wiring only
cmd/ed25519tool/    release signing helper, used by scripts/release.sh
internal/protocol/  wire types (messages, results) and result codes; see docs/protocol.md
internal/agent/     websocket loop, command dispatch, reattach, console
internal/config/    agent.json and the machine inventory
internal/docker/    containers, Compose, volumes, registry login
internal/build/     builds (BuildKit, static sites), image load and transfer
internal/caddy/     Caddy routing (behind the Router interface), access log, certificates, DNS-01 token
internal/databases/ managed database commands
internal/metrics/   host metrics and usage
internal/harden/    server hardening (drives deploy/harden.sh)
internal/update/    signed self-update (testdata/ holds public release artifacts)
internal/sysinfo/   CPU architecture helper
internal/version/   build version (set with -ldflags -X)
internal/util/      small shared helpers
deploy/             install.sh, harden.sh, systemd units and their shell tests
scripts/release.sh  cross-build, sign and package a release
docs/               the protocol specification (protocol.md) and its JSON schemas
```

## Build

```sh
go vet ./...
go build -o bin/f2c-agent ./cmd/f2c-agent                                  # local build
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X github.com/vinodkumar937/f2c-agent/internal/version.Version=0.4.0" \
  -o bin/f2c-agent-linux-amd64 ./cmd/f2c-agent
```

## Test

```sh
go test ./...                         # unit and protocol tests; it also runs the shell tests below
bash deploy/test/harden_test.sh       # deploy/harden.sh helpers (bash only: the script uses bash features)
bash deploy/test/install_fw_test.sh   # install.sh firewall helpers (fake ss/ufw output; changes nothing)
sh deploy/test/install_sig_test.sh    # install.sh signature check with a key list (needs openssl with ed25519, else skipped)
sh deploy/test/install_release_test.sh # install.sh key block, signatures by key id, signed-file gate
sh deploy/test/install_source_test.sh # install.sh download source (GitHub release, latest or pinned), verified over a local file:// release
bash deploy/test/release_test.sh      # scripts/release.sh argument and signing-key checks
shellcheck deploy/*.sh deploy/test/*.sh scripts/release.sh
```

## Releases and signing (overview)

`scripts/release.sh <version>` cross-builds `linux/amd64` and `linux/arm64` into `dist/release/<version>/` and writes `version.json`, then `SHA256SUMS` (a signed `# ` header with the version, build time, Caddy tag and key serial, then the hashes of the install files, binaries, `version.json`, `release-keys.json` and the Caddy binaries), `SHA256SUMS.sig` and `SHA256SUMS.sigs`. The version is required (there is no default). The install files (`install.sh`, `harden.sh`, the systemd units and `caddy-resume.conf`) are copied into the release and listed in the same signed `SHA256SUMS`. At the end it prints the exact list of files to attach to the GitHub release `v<version>` (everything `install.sh` downloads) and never uploads anything itself.
`SHA256SUMS` is signed with an **ed25519 private key that is kept outside this repository** (held offline by the maintainers, with a backup key held separately; never stored in this repository or in CI). A missing key is an error: only `--no-sign` skips signing, and such a build must not be published. Set `F2C_RELEASE_SIGNING_KEY` to the key path. The matching public keys are in `keys/release-keys.json`, which the agent embeds (`keys/`) and from which the key block of `deploy/install.sh` is generated; both the installer and self-update refuse any binary whose `SHA256SUMS` signature does not verify. `--caddy-dir DIR` lists the hashes of the Caddy binaries in `SHA256SUMS`. `--install` copies the artifacts into an agent-bin directory that an engine serves for self-update (`F2C_AGENT_BIN_DIR`). Forks that publish their own builds must replace the public keys in `keys/release-keys.json`.

**Key list.** `keys/release-keys.json` is the single list of trusted ed25519 public keys (raw 32 bytes, base64, each with an id, the first 8 bytes of the SHA-256 of the key as 16 hex characters, and a status: `active`, `retired` or `revoked`). A
`SHA256SUMS` signature is accepted if a trusted key verifies it: `SHA256SUMS.sigs` names the signing key by id, and the raw `SHA256SUMS.sig` is tried against every trusted key so older releases stay valid. To rotate: add the new key, release a build, sign later releases with the new key, and revoke the
old key once no agent still needs it (`docs/protocol.md` section 8.2). After editing the file run `go run ./cmd/ed25519tool sync-install` to refresh the block in `deploy/install.sh`; `go test ./keys/` and `release.sh` fail if they differ. The list is compiled in and is not read from disk or from the engine. Only public keys
belong in the repository.

## Security

Report vulnerabilities privately, not in a public issue: see [SECURITY.md](SECURITY.md) (info@f2c.io, or GitHub's "Report a vulnerability" on this repository).
Never include tokens, join tokens (`f2cj_`), server tokens (`f2cs_`) or private keys in a report.

Notes for operators: the agent runs without root. The optional harden step runs through a root-owned systemd path/service pair
(`f2c-harden.path`, `f2c-harden.service`) that validates every request value again before it acts.

## Contributing

Issues and pull requests are welcome. Before opening a pull request run `gofmt -l .`, `go vet ./...`, `go test ./...` and `shellcheck -S warning deploy/*.sh deploy/test/*.sh scripts/release.sh`
(see Test above). A change to the wire protocol must update `docs/protocol.md` and the schemas in `docs/protocol/schemas/` together. Never commit
secrets, keys or `.env` files. Security problems go to [SECURITY.md](SECURITY.md), not to a public issue.

## Supported versions

Security fixes go into the latest release only; upgrade with the same install command (the agent also updates itself from a signed release served by its engine). The protocol is
version 1 (draft, `docs/protocol.md`); the agent and its engine negotiate it at the handshake.

## Status

This repository is a work in progress. The protocol spec is a draft; the F2C engine (the control plane) is not part of this repository.
