# F2C Agent Protocol: Specification

| | |
|---|---|
| **Specification version** | `1.0-draft` |
| **Protocol version** | `1` (the only version; negotiated on the wire since agent 0.4.0, see [section 3](#3-versioning-and-negotiation)) |
| **Status** | Draft. Derived from the code; [section 11](#11-known-limitations-and-design-notes) lists known limitations and open design points. |
| **Basis** | Agent: `f2c-agent` 0.4.0. |
| **Date** | 2026-11-18 |

Where this document and the code disagree, the code is right and this document has a bug. Where the agent and the engine
disagree, or the behaviour is not defined, this document says so (see [section 11](#11-known-limitations-and-design-notes))
instead of choosing.

## 1. Overview

### 1.1 Purpose

The F2C agent (`f2c-agent run`) is a small Go daemon on each customer server. It keeps one outbound WebSocket to the F2C
engine, reports server and container health, and executes commands the engine sends (run, stop and remove containers, apply a
Caddy configuration, build and load images, take database backups, update itself, and so on). This document specifies that
wire protocol, the enrolment calls around it, and the signed-release flow used to install and update the agent.

### 1.2 Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174). They describe what the **implementation does today** unless a passage is marked
**Proposal**, in which case it describes a suggestion that is not in force. A passage marked **Not implemented** describes
something that is planned and does not exist in the agent or the engine.

Machine-readable definitions are JSON Schema draft 2020-12 files in [`protocol/schemas/`](protocol/schemas/) (index in
[Appendix A](#appendix-a-schema-index)). Examples in this document are checked against those schemas. All tokens, hosts and addresses in
examples are placeholders (`f2cs_EXAMPLE...`, `example.com`, `192.0.2.x`).

### 1.3 Terminology

| Term | Meaning |
|---|---|
| **Engine** | The F2C control plane the agent dials. |
| **Agent** | The `f2c-agent run` process on a server. |
| **Frame** | One WebSocket text message holding one JSON object. |
| **Server token** | `f2cs_...`, the agent's long-lived credential, issued by `join`. |
| **Join token** | `f2cj_...`, a one-time token used once by `join`. |
| **Command** | A `cmd` frame: the engine asks the agent to do something. Identified by its `id`. |
| **Result** | The `result` frame that ends a command. |
| **Capability flag** | An integer field `...V` in the heartbeat telling the engine which features this agent has. |
| **State dir** | `/var/lib/f2c-agent` (or `F2C_AGENT_STATE_DIR`), mode 0700; holds `agent.json`, `done.json` and more. |
| **Managed** | A container, network or volume the agent created and labelled `f2c.agent=1`. |

### 1.4 Versioning of this specification

The specification version has the form `<major>.<minor>[-draft]`. The **protocol version** is the integer `1`. A change that
a receiver written against 1.x cannot tolerate would be protocol 2. Agents up to 0.3.1 send no wire-level version marker; from agent 0.4.0 the dial carries `X-F2C-Protocol: 1`. See
[section 3](#3-versioning-and-negotiation).

### 1.5 Changelog

| Spec version | Date | Changes |
|---|---|---|
| `1.0-draft` | 2026-11-18 | First formal version: the message catalogue with JSON Schemas, error codes, command lifecycle, reconnect rules, release and signature flow (signed `SHA256SUMS` header, key ids and `SHA256SUMS.sigs`, the `self_update` guard, `hb.updateV`), size and truncation limits ([5.4](#54-size-and-truncation-limits-as-implemented)), the managed-database channel ([4.8](#48-managed-database-channel) and `database.json`), security considerations and a list of known limitations. |

## 2. Transport and session

### 2.1 Enrolment (HTTP, outside the WebSocket)

Two plain HTTPS calls exist next to the WebSocket. Both are made by the agent binary on the command line and never by the
running daemon. Schemas: [`http.json`](protocol/schemas/http.json).

**Join** (`f2c-agent join --engine URL --token f2cj_...`), `POST <engine>/agent/join`, JSON body, 30 s client timeout.
The agent reads at most 64 KiB of the answer. The engine answers `201` with `{serverId, serverToken}`; any other status is an
error with `{error, code?}`. The agent then writes `{engine, serverId, token}` to `<state-dir>/agent.json` with mode 0600.
Schemas: [`joinRequest`](protocol/schemas/http.json#/$defs/joinRequest), [`joinResponse`](protocol/schemas/http.json#/$defs/joinResponse),
[`errorResponse`](protocol/schemas/http.json#/$defs/errorResponse).

<!-- example: http.json joinRequest -->
```json
{"token":"f2cj_EXAMPLE_NOT_A_REAL_TOKEN","info":{"cpuCount":2,"memoryMb":3900,"diskGb":80,"agentVersion":"0.3.1+202611181227","provider":"example","publicIp":"192.0.2.20","arch":"amd64"}}
```

<!-- example: http.json joinResponse -->
```json
{"serverId":"srv_EXAMPLE0000001","serverToken":"f2cs_EXAMPLE_NOT_A_REAL_TOKEN"}
```

**Reattach** (`f2c-agent reattach [--engine URL]`), `POST <engine>/agent/reattach`, 60 s client timeout. Used when the engine
has lost the server's record. It sends the existing server token once, an identity block (`tokenFingerprint` is the lower-case hex SHA-256
of the token) and an inventory of managed containers, databases, volumes and Caddy hosts. `200` or `201` means the engine
recorded an orphan awaiting admin approval; `409` with `code` or `status` equal to `already_known` is also treated as success.
Anything else is an error. Reattach is **not** a WebSocket session resume (see [section 7](#7-reconnect-backoff-and-session-reattach)).
Schemas: [`reattachRequest`](protocol/schemas/http.json#/$defs/reattachRequest), [`reattachResponse`](protocol/schemas/http.json#/$defs/reattachResponse).

<!-- example: http.json reattachRequest -->
```json
{"token":"f2cs_EXAMPLE_NOT_A_REAL_TOKEN","identity":{"claimedServerId":"srv_EXAMPLE0000001","tokenFingerprint":"0000000000000000000000000000000000000000000000000000000000000000","hostname":"host1","ips":["192.0.2.10"],"publicIp":"192.0.2.20","arch":"amd64","agentVersion":"0.3.1+202611181227"},"inventory":{"containers":[],"databases":[],"volumes":[],"caddyHosts":["myapp.example.com"]}}
```

### 2.2 Engine URL and configuration

The agent reads `engine`, `serverId` and `token` from `<state-dir>/agent.json`. `f2c-agent run` options that matter to the wire
are `--state-dir`, `--caddy-admin` (default `http://127.0.0.1:2019`), `--ask-listen` (default `127.0.0.1:9180`) and
`--access-listen` (default `127.0.0.1:9181`). The `--insecure` flag is deprecated and has no effect on non-loopback engines.

The engine URL MUST have the form `http(s)://host[:port]`: no path (other than `/`), query, fragment, credentials or whitespace.
Plain `http`/`ws` MUST only be used to a loopback host; any other engine MUST be `https`/`wss`. The agent exits at start-up if the URL violates
this.

### 2.3 Dial

The agent opens `GET <engine-url with https->wss, http->ws>/agent` as a WebSocket upgrade, with exactly one custom header:

```
Authorization: Bearer f2cs_EXAMPLE_NOT_A_REAL_TOKEN
```

- **Path.** Only `/agent` is served; the engine answers `404` for other paths.
- **Authentication.** The bearer token is the only credential, checked by the engine during the upgrade. `401` means the token is unknown, revoked
  or rotated away; the agent logs that a new join is needed and retries on the slow auth schedule ([7.1](#71-backoff-and-retry-schedules)). The engine answers `426` when a request arrives through a
  proxy that does not mark it as `https`.
- **TLS.** `wss` uses the Go TLS stack with the system trust store. There is no certificate pinning and no client certificate.
  Dial timeout: 20 s (covers TCP, TLS and the upgrade).
- **Protocol header.** `X-F2C-Protocol: 1`, the highest protocol version the agent speaks (since agent 0.4.0). Older agents do not send it, so an engine MUST treat a missing header as protocol 0. See [section 3](#3-versioning-and-negotiation).
- **Not sent:** any subprotocol and any agent identity header.
- **Token source.** The token is re-read for every dial, so a rotated token ([4.5](#45-secret-bearing-live-frames)) takes effect on the next connection.

### 2.4 Handshake

The agent sends **no** hello frame. The sequence after a successful upgrade is:

1. Agent: starts the heartbeat goroutine, which sends the first `hb` **immediately**, before `hello_ok` has arrived, and then every 15 s.
2. Engine: sends `{"t":"hello_ok","serverId":...}` as the first frame it writes. It may add `protocol`, `minAgent` and `caps` ([4.2](#42-hello_ok), [section 3](#3-versioning-and-negotiation)).
3. Engine: re-sends every still-pending `cmd` ([section 6](#6-command-lifecycle)).
4. Engine: pushes the server's current Caddy routes as a normal `caddy_apply` command, and pushes registry credentials as `registry_login`.
5. Agent, on `hello_ok`: starts the harden link monitor (a WebSocket ping every 10 s with a 5 s timeout, recorded in `<state-dir>/harden/link-proof`; only when the engine URL is `https`) and
   marks a pending self-update as proven ([section 8.4](#84-self-update-and-rollback)). It also records `protocol` and `caps` for the session and compares `minAgent` with its own version
   ([3.2](#32-negotiation)); this only changes the log.

From agent 0.4.0 the agent compares `serverId` in `hello_ok` with its configured server id and warns on a mismatch ([3.2](#32-negotiation)); older agents ignore it. A repeated `hello_ok` on one connection is processed again; the engine sends one per connection.

### 2.5 Framing

| Property | Value |
|---|---|
| Frame type | WebSocket **text** frames, each holding one UTF-8 JSON object. |
| Compression | Disabled on both sides (no `permessage-deflate`). |
| Maximum size | 16 MiB per message in both directions. The engine closes with `1009` when exceeded; the agent's read limit is the same 16 MiB. |
| Binary frames | The engine closes the connection with `1003`. The agent never sends binary frames; it would parse an incoming binary frame as JSON like a text frame. |
| Unparseable input | A frame that is not valid JSON is **ignored** by both sides. |
| Write timeout | Each agent write has a 15 s timeout. A failed or timed-out write is dropped; the agent does not buffer or retry frames ([section 6.7](#67-ordering-and-delivery-guarantees)). |
| Concurrency | The agent writes from several goroutines; frames are never interleaved but their order across goroutines is unspecified. |

Every frame is a JSON object with a string `t` (type). Most frames also carry an `id` that correlates them to a command, a console session or a database socket.
All field names are case-sensitive and exactly as written in this document.

### 2.6 Keepalive and liveness

| Mechanism | Who | Interval | Effect |
|---|---|---|---|
| `hb` heartbeat frame | Agent | immediately, then every **15 s** | Carries server metrics and capability flags. It is also what keeps the engine's idle timer alive. |
| WebSocket `Ping` | Engine | every 20 s | The agent library answers with `Pong` while its read loop runs. |
| Idle timeout | Engine | checked every 20 s | Any inbound frame or `Pong` counts as activity. If none arrived within 60 s the engine closes with `4001 "idle"`, so a silent link is dropped after 60 to 80 s. |
| WebSocket `Ping` (link monitor) | Agent | every 10 s, 5 s timeout | Only after `hello_ok` and only for `https` engines. A success refreshes `harden/link-proof`; a failure does nothing else (the connection is not closed). |
| WebSocket `Ping` (dead-link check) | Agent | every **20 s**, **10 s** timeout | *Since agent 0.4.0.* Runs next to the read loop for the whole connection. If the engine does not answer within the timeout, the agent closes the connection with `1001 "ping timeout"` and reconnects on the normal schedule ([7.1](#71-backoff-and-retry-schedules)). The engine's WebSocket layer answers every `Ping` with a `Pong` that echoes the payload, so no engine change is needed. |

**Dead-link check (since agent 0.4.0; earlier agents had no timer that closed a silent connection).** A silent link is
detected after at most about 30 s (one ping interval plus the timeout), instead of waiting for the engine's `4001` after 60 to 80 s. A missed pong is
**ignored** (the check is inconclusive and the next ping decides) when the read loop was busy in a synchronous handler (`rotate_token`,
`registry_login`, `dns_token`) or when any frame arrived while the ping was waiting, because the reader cannot return a pong while it is occupied and
arriving data proves the link is alive. The check never starts before the read loop and uses its own pings, separate from the link monitor above, which
is unchanged. Nothing new is sent in any JSON frame.

### 2.7 Close codes

| Code | Sent by | Meaning | Agent behaviour |
|---|---|---|---|
| `1000` | Agent | `"agent stopping"`: a clean shutdown. The agent sends this close and waits up to 2 s for the engine's close reply before dropping the connection (next release). | The process is exiting; it does not reconnect. |
| `1001` | Agent | `"ping timeout"`: the dead-link check got no pong (since agent 0.4.0). | Reconnect on the normal schedule. |
| `1003` | Engine | Binary frame received. | Reconnect on the normal schedule. |
| `1006` | — | The connection ended without a close frame. After the next release a clean agent shutdown uses `1000` instead, so `1006` means an abnormal end. | Reconnect on the normal schedule if the process is still running. |
| `1009` | Engine | Message larger than 16 MiB. | Reconnect on the normal schedule. |
| `4000` | Engine | Replaced by a newer connection for the same server. | Wait a random **30 to 90 s**, then reconnect; the log says another agent may be using this token (since agent 0.4.0; see [7.1](#71-backoff-and-retry-schedules)). |
| `4001` | Engine | Idle for more than 60 s. | Reconnect on the normal schedule. |
| `4004` | Engine | `"protocol_unsupported"`: the engine cannot speak any protocol version the agent offers in `X-F2C-Protocol` (since agent 0.4.0). | Reconnect on the slow **auth schedule** (60 s doubling to 10 min, jittered) with its own log line asking for an agent update; the agent never stops by itself. See [7.1](#71-backoff-and-retry-schedules). |
| `4003` | Engine | Server revoked, or its token rotated away. | Reconnect on the slow **auth schedule**; the agent never stops by itself (since agent 0.4.0; see [7.1](#71-backoff-and-retry-schedules)). |

Any other close or read error is logged and followed by a reconnect on the normal schedule. The engine never sends `403`; the agent treats it like `401` in case a proxy does.

On a clean shutdown (next release) the agent sends `1000 "agent stopping"` and waits up to 2 s for the engine's close reply before dropping the connection. `1006` then means an abnormal end.

## 3. Versioning and negotiation

### 3.1 What exists today

- **Agent version.** `agentVersion` in every `hb` (and in `join` and `reattach`) is `<semver>+<UTC build stamp YYYYMMDDHHMM>`, for example `0.3.1+202611181227`. `agentHash` in `hb` is the SHA-256 of the running executable, or an empty string when it cannot be read. The engine compares `agentHash` with the hash it
  pins for the same architecture to decide whether an update is available ([section 8](#8-update-and-signature-flow)).
- **Capability flags.** Eight integer fields in every `hb`. A missing field means "not supported". All are `1` in this release.

| Flag | Meaning (agent side) | Stored by the engine |
|---|---|---|
| `usageV` | `apps` usage batch in `hb` | yes |
| `consoleV` | `console_*` frames | yes |
| `consoleHelperV` | console helper tar in `console_open` | yes |
| `accessV` | access-log rows in `hb` and the loopback listener | yes |
| `dockerBuildV` | `build` with `buildPack: "dockerfile"` | yes (gates Dockerfile builds) |
| `composeV` | Compose stack options of `run`, `network_rm`, `volume_rm`, `stats` detail | yes (gates stack specs) |
| `proxyV` | per-app proxy routes inside `caddy_apply` config | yes |
| `hardenV` | `hb.harden` summary | an engine may gate `harden` on it |

- **No protocol number in agents up to 0.3.1.** Those agents send no version on the wire. Compatibility there is carried by additive fields, by the capability flags above, and by the
  rule that unknown commands are answered with `unknown_command` ([section 5](#5-error-codes-and-retry-semantics)). Negotiation ([3.2](#32-negotiation)) adds a number without removing any of this.
- **Unknown command types.** An agent that does not know a command type still sends `ack`, then `result` `ok:false` with `code: "unknown_command"` at protocol 0 and `code: "unknown_cmd"` at protocol >= 1 (never both).
  The error text is `unknown command type "<type>"` in both cases and is kept stable because engines that predate `code` match on text; an engine should read `code` first and fall back to the text only for a result without one.
- **Command-specific arguments.** New optional arguments added to a command are silently ignored by an older agent for every command except `run`, which rejects unknown keys ([4.9.2](#492-run)).

### 3.2 Negotiation

> **Since agent 0.4.0.** Agents up to 0.3.1 do none of this, and an engine that predates it sends none of the new `hello_ok` fields. An engine that implements negotiation reads the header, sends `protocol`, `minAgent`, `caps` (`notAfter`, `hardenSummary`, `resultCode`) and `serverId`, and closes `4004` when it can speak no offered version. The design is additive: no existing field changes meaning.

1. **Dial header.** The agent sends `X-F2C-Protocol: 1`, the highest protocol it speaks (constant `protocol.Version`). A missing header means protocol 0 (an older agent).
2. **`hello_ok` answer** ([4.2](#42-hello_ok)), all optional:
   - `protocol` (integer): the session version, set by the engine to min(agent, engine highest). A missing or invalid value means **0**. The agent exposes the result as `SessionProtocol()` so that later features can require protocol >= 1.
   - `minAgent` (semver string): the engine's minimum agent version, from its pinned release. If the agent's own version is lower (semver precedence; `+build` metadata ignored), the agent logs **one warning per session** and **keeps running**. It does **not** self-update because of it.
   - `caps` (array of strings): engine features. Values: `"notAfter"`, `"hardenSummary"` and `"resultCode"` (all three are sent by engines that implement them, at protocol >= 1 only; at protocol 0 the engine sends none of them). The agent exposes `EngineHas(cap)`. Unknown strings are ignored.
   - `serverId` (string): the engine's id for the server. If it is present and **differs** from the server id in the agent's `agent.json`, the agent logs **one warning per session** (naming both ids, which are not secrets) and **keeps the session open**. A missing, empty, non-string or over-long (more than 128 bytes) value, or a match, does nothing.
3. **Close `4004` `"protocol_unsupported"`** ([2.7](#27-close-codes)): the engine's refusal when it cannot speak any offered version. The agent treats it like an auth failure for retry purposes (slow, jittered, never stops; [7.1](#71-backoff-and-retry-schedules)). `4001` (idle) stays on the normal schedule.
4. **What is gated on the result.** Two things: the result-code vocabulary, and the `replayed` marker on re-sent results ([6.3](#63-duplicate-ids-and-replay)). At `SessionProtocol() >= 1` every `ok:false` `result` carries a code from the 27-code list, and the three live reply frames carry `code` on failure ([5.1](#51-resultcode), [5.2](#52-other-error-channels)); at protocol 0 the agent sends exactly what 0.3.1 sends. The `resultCode` capability is advertised by the engine but not consulted by the agent: the gate is the session protocol. Everything else is unchanged by the negotiated protocol and caps, which also feed the log and the two accessors. Unknown `hello_ok` fields are ignored, as before.
5. **Tolerance.** `protocol`, `minAgent` and `caps` are decoded separately from the rest of `hello_ok`, so a field of the wrong type (`"protocol":"1"`, `"caps":"x"`) falls back to 0 / empty and the session carries on.

Rules for the engine: treat a missing `X-F2C-Protocol` as 0; send `protocol` no higher than the header value; never require `minAgent` to be honoured (it is advisory).

**Decided against:** `caps` in `hb`. The agent's own features are already announced by the `*V` capability flags in `hb` (for example `hardenV`), so a second list would only duplicate them. `caps` exists in `hello_ok` only, engine to agent.

Not part of negotiation:

- the downgrade guard is not a negotiation rule: it is the `self_update` guard and signed floor of [8.4](#84-self-update-and-rollback) (agent 0.4.0);
- any rule that makes the agent stop or refuse to connect for an engine it is too old for. `minAgent` only warns.

## 4. Message catalogue

Direction `E>A` is engine to agent; `A>E` is agent to engine. Schemas are in [`frames.json`](protocol/schemas/frames.json) (every frame; `$defs/engineToAgent` and
`$defs/agentToEngine` are the unions) and [`commands.json`](protocol/schemas/commands.json) (command arguments and results).
Receivers MUST ignore unknown fields. A receiver MUST ignore a frame whose `t` it does not know.

### 4.1 Frame index

| `t` | Dir | Purpose | Section | Schema |
|---|---|---|---|---|
| `hello_ok` | E>A | Upgrade accepted | [4.2](#42-hello_ok) | [`helloOk`](protocol/schemas/frames.json#/$defs/helloOk) |
| `hb` | A>E | Heartbeat, metrics, capability flags, harden summary, access rows | [4.3](#43-hb-heartbeat) | [`hb`](protocol/schemas/frames.json#/$defs/hb) |
| `cmd` | E>A | Run a command | [4.4](#44-command-frames) | [`cmd`](protocol/schemas/frames.json#/$defs/cmd) |
| `ack` | A>E | Command accepted and running | 4.4 | [`ack`](protocol/schemas/frames.json#/$defs/ack) |
| `stream` | A>E | Output of a running command | 4.4 | [`stream`](protocol/schemas/frames.json#/$defs/stream) |
| `result` | A>E | Final outcome of a command | 4.4 | [`result`](protocol/schemas/frames.json#/$defs/result) |
| `cancel` | E>A | Cancel a running command | 4.4 | [`cancel`](protocol/schemas/frames.json#/$defs/cancel) |
| `rotate_token` / `token_rotated` | E>A / A>E | Live server-token rotation | [4.5](#45-secret-bearing-live-frames) | [`rotateToken`](protocol/schemas/frames.json#/$defs/rotateToken), [`tokenRotated`](protocol/schemas/frames.json#/$defs/tokenRotated) |
| `registry_login` | E>A and A>E | Docker registry credentials (the reply reuses the type) | 4.5 | [`registryLogin`](protocol/schemas/frames.json#/$defs/registryLogin), [`registryLoginReply`](protocol/schemas/frames.json#/$defs/registryLoginReply) |
| `dns_token` / `dns_token_ok` | E>A / A>E | DNS-01 API token for the wildcard certificate | 4.5 | [`dnsToken`](protocol/schemas/frames.json#/$defs/dnsToken), [`dnsTokenOk`](protocol/schemas/frames.json#/$defs/dnsTokenOk) |
| `cert_issued` | A>E | A certificate was issued or found | [4.6](#46-cert_issued) | [`certIssued`](protocol/schemas/frames.json#/$defs/certIssued) |
| `console_open`, `console_in`, `console_resize`, `console_close` | E>A | Interactive shell session | [4.7](#47-console-session) | `consoleOpen`, `consoleIn`, `consoleResize`, `consoleClose` |
| `console_ready`, `console_out`, `console_exit` | A>E | Console output and lifecycle | 4.7 | `consoleReady`, `consoleOut`, `consoleExit` |
| `db_request` / `db_result` | E>A / A>E | Managed-database operation | [4.8](#48-managed-database-channel) | `dbRequest`, `dbResult` |
| `db_socket_open`, `db_socket_in`, `db_socket_close` | E>A | Raw database socket relay | 4.8 | `dbSocketOpen`, `dbSocketIn`, `dbSocketClose` |
| `db_socket_ready`, `db_socket_out`, `db_socket_end` | A>E | Socket relay output and end | 4.8 | `dbSocketReady`, `dbSocketOut`, `dbSocketEnd` |

Console and database frame schemas are all in [`frames.json`](protocol/schemas/frames.json) under the names in the last column.

### 4.2 `hello_ok`

E>A. Sent once after the upgrade. `serverId` is the engine's id for the server. The other fields below are optional and additive
(since agent 0.4.0). An engine that sends only `serverId` is protocol 0.

| Field | Type | Meaning | Agent when missing or wrong |
|---|---|---|---|
| `protocol` | integer | The session version: min(the agent's `X-F2C-Protocol`, the engine's highest), so `1` today. | Protocol `0`. A fractional, negative, string or `null` value counts as invalid. A value above what the agent speaks is clamped to it. |
| `minAgent` | string, semver | The oldest agent the engine wants, taken from its pinned release. | No check. A value that is not a valid semver is ignored. |
| `serverId` | string | The engine's id for this server (already sent by every engine). | No check. If present and different from the configured id, one warning per session; the session stays open. Empty, non-string and over-long values are treated as missing. |
| `caps` | array of strings | Engine features. Known: `"notAfter"`, `"hardenSummary"` and `"resultCode"` (sent at protocol >= 1 only). | Empty set. Entries that are not strings are skipped and unknown strings are kept and ignored. At most 64 entries of 64 bytes are kept. |

A wrong type in any of these fields (including `serverId`) never drops the frame or the session: the agent decodes them separately from the rest of the frame.

<!-- example: frames.json helloOk -->
```json
{"t":"hello_ok","serverId":"srv_EXAMPLE0000001"}
```

<!-- example: frames.json helloOk -->
```json
{"t":"hello_ok","serverId":"srv_EXAMPLE0000001","protocol":1,"minAgent":"0.4.0","caps":["notAfter","hardenSummary","resultCode"]}
```

### 4.3 `hb` (heartbeat)

A>E. Sent immediately after connecting and every 15 s. If the connection is down the beat is dropped.

| Field | Type | Notes |
|---|---|---|
| `agentVersion`, `agentHash` | string | See [3.1](#31-what-exists-today). |
| `update` | object or `null` | Outcome of the last self-update (`id`, `status` `succeeded` / `rolled_back` / `failed`, `message?`, `from?`, `to?`, `at`, and `fromVersion?`, `toVersion?`, `rollback?`, `reason?` when the update carried them), read from `update-result.json`. |
| `updateV` | integer | `1`: `self_update` honours `version`, `rollback` and `reason` at protocol >= 1 and the agent keeps the signed floor ([8.4](#84-self-update-and-rollback)). The engine sends those arguments only to agents that report it. |
| `cpuCount`, `arch` | integer, string | `arch` is `amd64` or `arm64`. |
| `memoryMb`, `diskGb`, `cpuPct`, `memUsedMb`, `diskUsedGb` | number | Host metrics. |
| `containers` | array or `null` | Managed containers `{name, state, image, status, hostPort?}`. `null` when `docker ps` failed ([section 11](#11-known-limitations-and-design-notes)). |
| `usageV` ... `hardenV` | integer | Capability flags ([3.1](#31-what-exists-today)). |
| `harden` | object | **Harden summary** `{v: 1, runs: [...]}`: the last 5 harden runs, newest first, each `{id, status, finishedAt?, backupId?}` with `status` one of `requested`, `succeeded`, `failed`, `rolled_back`, `unknown`. Omitted if it cannot be built. Not read by the engine. |
| `apps` | array | Per-app usage rows. Present on every 4th beat, starting with the first. |
| `access` | array | Finished access-log minutes (below). Present only when some exist. |

**Access-log rows.** The agent runs a loopback listener (`127.0.0.1:9181`) that Caddy's JSON access log feeds. Requests are bucketed per host and UTC minute. When a minute
has ended it is sent once in `hb.access` and then forgotten (a beat lost while disconnected loses its rows). A row has `host`, `minute` (RFC 3339 start of the minute),
`requests`, `s2xx`, `s3xx`, `s4xx`, `s5xx`, `bytes`, `p50Ms`, `p95Ms` (milliseconds, `null` without samples). For apps that publish more than one domain the agent reports
every domain's traffic under the app's **primary host**, derived from the route `@id` values in the last `caddy_apply` (`app-`, `dom-`, `svcd-dom-`, `redir-` prefixes, with an optional `tls-` prefix); the engine's
host to app map is therefore enough. Schemas: [`accessRow`](protocol/schemas/frames.json#/$defs/accessRow), [`appUsage`](protocol/schemas/frames.json#/$defs/appUsage), [`hbHarden`](protocol/schemas/frames.json#/$defs/hbHarden).

<!-- example: frames.json hb -->
```json
{
  "t": "hb",
  "agentVersion": "0.3.1+202611181227",
  "agentHash": "0000000000000000000000000000000000000000000000000000000000000000",
  "update": null,
  "updateV": 1,
  "cpuCount": 2, "arch": "amd64", "memoryMb": 3900, "diskGb": 80,
  "cpuPct": 3.1, "memUsedMb": 1200, "diskUsedGb": 20,
  "containers": [{"name": "myapp", "state": "running", "image": "f2c/myapp:abc123", "status": "Up 3 hours", "hostPort": 20001}],
  "usageV": 1, "consoleV": 1, "consoleHelperV": 1, "accessV": 1, "dockerBuildV": 1, "composeV": 1, "proxyV": 1, "hardenV": 1,
  "harden": {"v": 1, "runs": [{"id": "harden-abc", "status": "succeeded", "finishedAt": "2026-11-18T10:00:00Z", "backupId": "20261118-100000"}]},
  "access": [{"host": "myapp.example.com", "minute": "2026-11-18T10:00:00Z", "requests": 12, "s2xx": 10, "s3xx": 0, "s4xx": 1, "s5xx": 1, "bytes": 4096, "p50Ms": 3.2, "p95Ms": 40.1}]
}
```

### 4.4 Command frames

**`cmd`** (E>A) `{t, id, type, args?, notAfter?}`. `id` is chosen by the engine and MUST be unique per command; the engine only issues ids matching `^[A-Za-z0-9_.:-]{1,80}$` and the agent accepts any non-empty string. `args` defaults to `{}`.
`notAfter` is an optional absolute RFC 3339 deadline (see [6.4](#64-notafter-and-skew)); an engine should set it on every command ([6.4](#64-notafter-and-skew)). A frame with a missing `id` is dropped silently.
The agent also drops silently any frame whose known fields have the wrong JSON type (for example `args` that is not an object), because the whole frame fails to decode ([section 11](#11-known-limitations-and-design-notes)).

**`ack`** (A>E) `{t, id}`. Sent when the agent has accepted the command and started it. It is also sent again if a `cmd` arrives for an id that is still running. It carries no data.

**`stream`** (A>E) `{t, id, data}`. Zero or more per command while it runs; `data` is text (log lines, build and load output) or base64 (`exec` stdout, see 4.9). Streams are best effort: they are dropped while disconnected and never re-sent ([6.7](#67-ordering-and-delivery-guarantees)).

**`result`** (A>E) is the single final frame of a command. Success: `{t, id, ok: true, data?}`. Failure: `{t, id, ok: false, error, code?}` (`code` always present at protocol >= 1). `error` is human-readable text (the engine keeps the first 4000 characters).
`code` is machine-readable text ([section 5](#5-error-codes-and-retry-semantics)): on every failure at protocol >= 1, and only for the eight legacy codes at protocol 0 (absent on other failures there). `data` is the command's result object (4.9). A result **re-sent for a finished id** carries `replayed: true` on the frame at protocol >= 1 ([6.3](#63-duplicate-ids-and-replay)); below that the frame is byte-identical to the first one. A command-specific failure can also be reported inside a successful result
(`tls_warm`, `http_probe`, `harden`; see 4.9). The `replayed: true` marker is inside `data` of a `harden` result, not on the frame ([6.3](#63-duplicate-ids-and-replay)).

**`cancel`** (E>A) `{t, id}`. Cancels the context of a running command; see [6.6](#66-timeouts-and-cancellation).

<!-- example: frames.json cmd -->
```json
{"t":"cmd","id":"c2","type":"rm","args":{"name":"myapp"},"notAfter":"2026-11-18T10:00:00Z"}
```

<!-- example: frames.json ack -->
```json
{"t":"ack","id":"c2"}
```

<!-- example: frames.json stream -->
```json
{"t":"stream","id":"c1","data":"2026-11-18T10:00:00.000000000Z listening on :3000\n"}
```

<!-- example: frames.json result -->
```json
{"t":"result","id":"c2","ok":true,"data":{"removed":"myapp","existed":true}}
{"t":"result","id":"c3","ok":false,"error":"unknown command type \"frobnicate\"","code":"unknown_cmd"}
{"t":"result","id":"c4","ok":false,"error":"docker pull: Error response from daemon: pull access denied for nginx, repository does not exist or may require 'docker login'","code":"image_not_found"}
```

<!-- example: frames.json cancel -->
```json
{"t":"cancel","id":"c2"}
```

### 4.5 Secret-bearing live frames

These three exchanges are handled on the live connection only. They are never queued by the engine, re-sent, written to `done.json`, or logged by the agent. All are processed
synchronously in the agent's read loop.

- **`rotate_token`** `{t, id, token}` (E>A). `token` MUST start with `f2cs_` and be at most 256 characters; `id` MUST be non-empty. The agent writes the new token to `agent.json` (0600), uses it from the next dial,
  and answers **`token_rotated`** `{t, id, ok, error?}`. The current connection stays up. The engine invalidates the old token only after the confirmation or when the new one is first used.
- **`registry_login`** `{t, id, config: {auths: {<registry host>: {auth}}}}` (E>A). A Docker `config.json` fragment of 1 to 4 registries (at most 16 KiB), stored 0600 in `<state-dir>/docker` and used only for `docker pull`. The agent replies with a frame of the **same** `t`:
  `{t:"registry_login", id, ok, error?}` ([section 11](#11-known-limitations-and-design-notes)). The engine refreshes the credentials periodically and at every connect.
- **`dns_token`** `{t, id, provider, domain, token}` (E>A), `provider` `digitalocean` or `cloudflare` (the agent also accepts `other`). Stored 0600 for the DNS-01 wildcard certificate. The agent replies **`dns_token_ok`** `{t, id, ok, error?}`.

<!-- example: frames.json rotateToken -->
```json
{"t":"rotate_token","id":"rot-EXAMPLE","token":"f2cs_EXAMPLE_NOT_A_REAL_TOKEN"}
```

<!-- example: frames.json tokenRotated -->
```json
{"t":"token_rotated","id":"rot-EXAMPLE","ok":true}
```

<!-- example: frames.json registryLogin -->
```json
{"t":"registry_login","id":"reg-EXAMPLE","config":{"auths":{"registry.example.com":{"auth":"RVhBTVBMRTpFWEFNUExF"}}}}
```

<!-- example: frames.json registryLoginReply -->
```json
{"t":"registry_login","id":"reg-EXAMPLE","ok":true}
```

<!-- example: frames.json dnsToken -->
```json
{"t":"dns_token","id":"dns-EXAMPLE","provider":"cloudflare","domain":"apps.example.com","token":"EXAMPLE_DNS_API_TOKEN"}
```

<!-- example: frames.json dnsTokenOk -->
```json
{"t":"dns_token_ok","id":"dns-EXAMPLE","ok":true}
```

### 4.6 `cert_issued`

A>E `{t, host, issuedAt, expiresAt}`. Sent by the certificate watcher when Caddy has a certificate for a host. A wildcard certificate is reported as `wildcard_.<domain>`. The engine uses it to count issuance against Let's Encrypt limits
and to move a wildcard from "issuing" to "active". There is no acknowledgement.

<!-- example: frames.json certIssued -->
```json
{"t":"cert_issued","host":"app.example.com","issuedAt":"2026-11-18T09:00:00Z","expiresAt":"2027-02-16T09:00:00Z"}
```

### 4.7 Console session

An interactive shell in a managed container, over the Docker Engine API with a TTY. `id` identifies the session and is chosen by the engine. Keystrokes and output are never logged.

| Frame | Dir | Fields | Behaviour |
|---|---|---|---|
| `console_open` | E>A | `id, container, cmd[], cols?, rows?, env?, helperTar?, helperDir?, fallbackCmd?` | Starts the session. `container` must match `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$` and `cmd` must be non-empty, else the agent sends `console_exit` `error`. A container that is not running gives `console_exit` `not_running`. With `helperTar`, the agent injects the helper into the container's `/tmp` (needs `helperDir` of the form `/tmp/.f2c/con_<16 hex>` and `fallbackCmd`); if that fails it runs `fallbackCmd`. |
| `console_ready` | A>E | `id, helper` | The shell is attached. `helper` says whether the helper was injected. |
| `console_in` | E>A | `id, d` (base64) | Keystrokes. Invalid base64 is ignored. |
| `console_out` | A>E | `id, d` (base64) | Terminal output, at most 16 KiB of raw bytes per frame. |
| `console_resize` | E>A | `id, cols (1..500), rows (1..300)` | Resizes the PTY; out-of-range values are ignored. |
| `console_close` | E>A | `id` | Closes the session. |
| `console_exit` | A>E | `id, reason` | `error`, `not_running` or `exited`. Also sent after `console_close` (reason `exited`). |

Console frames have no ack and no dedupe. They are not re-sent. If the WebSocket drops, the agent keeps the exec running until it ends and the frames it produces meanwhile are lost ([7.2](#72-what-survives-a-reconnect)).

<!-- example: frames.json consoleOpen -->
```json
{"t":"console_open","id":"con-1","container":"myapp","cmd":["/bin/sh"],"cols":80,"rows":24}
```

<!-- example: frames.json consoleOut -->
```json
{"t":"console_out","id":"con-1","d":"JCA="}
```

### 4.8 Managed-database channel

*Specification of agent behaviour as implemented. The per-operation schemas are in [`database.json`](protocol/schemas/database.json). The engine's side (timeouts, gating) is informative.*

Used for managed databases: a Postgres or Redis container named `f2c-db-<name>` with a volume `f2c-db-<name>-data`. Frames: `db_request` / `db_result`, and `db_socket_open` / `db_socket_in` / `db_socket_close` with `db_socket_ready` / `db_socket_out` / `db_socket_end`. The engine handles every frame whose `t` starts with `db_` in its database channel, not in the command queue.

**Delivery guarantees: none beyond the WebSocket.**

- A `db_request` is **live-only**: the engine never queues it, never re-sends it on reconnect, and the agent never records it in `done.json` or `running.json`. There is **no `ack`, no dedupe, no replay and no `notAfter`**; a repeated `id` is simply executed again.
- The agent runs every `db_request` and `db_socket_open` on its own goroutine, so requests for different databases run in parallel.
- **A dropped connection does not cancel anything.** The operation runs to its end (or to its own 30 minute deadline) and the agent then tries to send the `db_result`; with no connection the frame is dropped. After its own timeout the engine therefore cannot know the outcome: a `backup_create` may have produced a dump, a `restore` or `delete` may have completed. The engine re-reads state (`backup_list`, `register`) instead of assuming. The table below says which operations are safe to repeat.
- `db_result.id` is the request's `id` (the engine uses a fresh UUID per request). The agent sends exactly one `db_result` per request.

**Per-database lock.** Every operation and every socket takes a non-blocking lock on the container name, and so does the daily backup scheduler. If it is held, the new request fails **immediately** with `operation_busy` (a socket gets `db_socket_end` with `error: "operation_busy"`); nothing is queued. A socket holds the lock for its whole life, so a query blocks backups on that database and the reverse. `capabilities`, `volume_backup_create` and `volume_backup_offsite` take no lock. The identity (`dbSpec`) is validated **before** the lock is taken and pinned **inside** it.

**`db_request`** `{t, id, type, args}` is answered by exactly one **`db_result`**: success `{t, id, ok: true, data}`, or failure `{t, id, ok: false, code, status}` with no `error` text and no `data`. `code` is one of the [`errorCode`](protocol/schemas/database.json#/$defs/errorCode) values below (text that is not `^[a-z_]{1,64}$` is reported as `failed`). `status` is HTTP-like: `400` for `invalid_input` and `invalid_backup`, `403` for `not_allowed`, `404` for `not_found` and `backup_not_found`, `500` for `backup_failed` and `restore_failed`, and `409` for every other code. The agent never sends the underlying message, so nothing in it can be truncated or leak.

| Code | Meaning |
|---|---|
| `invalid_input` | Missing or malformed identity or argument; a download offset or upload chunk that does not follow the previous one; an upload over 2 GiB or a chunk over 180000 characters. |
| `invalid_backup` | The key or `downloadId` is malformed, the archive failed `pg_restore --list`, or its sha256 does not match. |
| `not_allowed` | The container is not ours (labels), its `f2c.org` or volume does not match, or the identity differs from the pinned one. |
| `not_found` | The database was deleted. |
| `backup_not_found` | The dump or upload named by the key does not exist, or a new download starts at an offset other than 0. |
| `backup_failed`, `restore_failed`, `restore_timeout` | The dump, a write, a state file or the restore failed; `restore_timeout` is the 30 minute deadline. A dump over 2 GiB is `backup_failed`. |
| `operation_busy` | The per-database lock is held, 16 downloads are open, or an upload already exists. |
| `database_not_running` | The container is absent or stopped (also needed for dumps, restores, `upload_finish` and sockets). |
| `resource_identity_conflict` | The container's `f2c.generation` label differs, or a name is reused before the old database is completely deleted. |
| `unsupported` | An unknown operation, a Redis database asked for anything but `register` and `delete`, or a Postgres container whose user or database differs from the spec. |
| `insufficient_storage` | Less free space than the operation needs (2 GiB plus 1 GiB for a dump, 1 GiB plus the chunk for an upload). |
| `delete_incomplete` | A step of `delete` failed; repeating the request continues it. |
| `failed` | Anything else (an unreadable pin file, malformed inspect output). |

**Identity and pinning.** Every operation except `capabilities` and the two `volume_backup_*` operations carries the [`dbSpec`](protocol/schemas/frames.json#/$defs/dbSpec) in `args`: `type` is `postgres` or `redis`, `orgId` and `databaseName` match `^[A-Za-z0-9_-]{1,128}$`, `container` is exactly `f2c-db-<databaseName>`, `volume` is exactly `<container>-data`, `generation` has 1 to 80 characters, `user` and `database` 1 to 63. The agent inspects the container and requires the label `f2c.agent=1`, `f2c.db=<databaseName>`, an `f2c.org` that is empty or equal to `orgId`, an `f2c.generation` that is empty or equal to `generation`, the named volume mounted and, for Postgres, `POSTGRES_USER` and `POSTGRES_DB` equal to `user` and `database`.
On first use the identity is **pinned** in `<state>/databases/<org>/<name>/database.json` and `<state>/database-owners/<container>.json` (0600). A later request must match it (`not_allowed`). A **new generation** is accepted only after a completed `delete`, and only when the container carries that generation label (`resource_identity_conflict` otherwise). A deleted database answers `not_found` to everything except `delete`.

**Operations** (`type`). Arguments and results are the schemas `<type>.args` and `<type>.result` in [`database.json`](protocol/schemas/database.json). "Spec" means the `dbSpec` fields are required in `args`. The engine gates `register`, `backup_*`, `volume_backup_*` and `restore` on `capabilities.backups`, `upload_*` on `restoreUpload` and `delete` on `volumeDelete`, and answers `agent_upgrade_required` itself when a flag is missing; the agent does not check the flags.

| Operation | Spec | Arguments | Result | Notes |
|---|---|---|---|---|
| `capabilities` | no | none | `{protocol: 1, volumeDelete, backups, query, writeQuery, restoreUpload, offsitePut, volumeBackup}` | `protocol` is a version of this channel, separate from the session protocol; the engine refuses anything but `1` (`agent_upgrade_required`). |
| `register` | yes | none | `{nextBackupAt}` | Pins the identity and schedules the daily dump. Repeatable. The engine repeats it every minute for every Postgres database. Works for Redis. |
| `backup_list` | yes | none | `{backups[], nextBackupAt, lastBackupAt, lastBackupError}` | Newest first. Read-only. |
| `backup_create` | yes | none | `{key, size, createdAt, location: "server", uploaded: false, pruned[]}` | `pg_dump -Fc` inside the container. Each call is a new dump (the newest 7 are kept), so it is **not** idempotent. |
| `backup_offsite_put` | yes | `key`, `url`, `objectKey`, `headers?` | `{uploaded: true, objectKey, size}` | PUTs an existing dump to the presigned URL. Repeatable. |
| `backup_offsite_restore` | yes | `url`, `objectKey` | `{restored, downloaded: false}` | Downloads (at most 2 GiB) into a new local key, then restores it. Each call stores a new local copy. |
| `backup_read` | yes | `key`, `downloadId`, `offset` | `{data, offset, size, eof}` | One 128 KiB chunk. Resumable by offset. |
| `backup_close` | yes | `downloadId` | `{closed: true}` | Ends a download early. |
| `restore` | yes | `key` | `{restored, downloaded: false}` | **Destructive.** Takes a safety dump first. Repeating a successful restore of the same dump gives the same state, but it also takes another safety dump. |
| `upload_start` | yes | none | `{key}` | One upload at a time. |
| `upload_chunk` | yes | `key`, `offset`, `data` | `{offset}` | The offset must equal the stored size, so a repeated chunk is refused (`invalid_input`) rather than doubled. |
| `upload_finish` | yes | `key`, `sha256` | the backup record | Validates and stores the dump. Does not restore. |
| `upload_abort` | yes | `key` | `{aborted: true, key}` | |
| `delete` | yes | none | `{deleted: true}` | Removes container and volume. **Idempotent and resumable**: a manifest is written before anything is removed. Retained dumps stay. |
| `volume_backup_create` | no | `volume` | `{volume, size, location: "server", uploaded: false}` | Tars any volume named `f2c-*`; the archive is discarded afterwards. |
| `volume_backup_offsite` | no | `volume`, `url`, `objectKey` | `{volume, size, uploaded: true, objectKey, location: "both"}` | Tars and PUTs. |

**Not supported: `volume_backup_offsite_restore`.** An engine may send this operation with `args {volume, url, objectKey}`, but **the agent does not implement it** and it is not in the table above or in `database.json`. The agent answers it like any unknown operation: the frame `{"t":"db_result","id":"<id>","ok":false,"code":"invalid_input","status":400}`, with no `data` and no text. It is `invalid_input` and not `unsupported` because the engine's arguments carry no `dbSpec`, and the agent validates the identity before it looks at the operation name; with a valid `dbSpec` the same request would get `code: "unsupported"`, `status: 409`. The answer is the same at protocol 0 and protocol 1, because the database channel does not depend on the session protocol. An engine should not send it until the operation is specified (see [section 11](#11-known-limitations-and-design-notes)).

**Backups on the server.** Dumps live in `<state>/databases/<org>/<name>/backups/<key>` with a `<key>.json` record `{key, size, createdAt, location, sha256}`; a key is `<UTC YYYYMMDDTHHMMSSZ>-<16 hex>.dump`. A dump is at most **2 GiB** and needs its size limit plus 1 GiB free; the newest **7** are kept (the dump being restored is never pruned). A scheduler wakes every minute and takes one dump per Postgres database per day at **02:00 UTC**; a failure is recorded as `lastBackupError` (`database_not_running` or `backup_failed`) and retried after 15 minutes. `.partial` and `.upload` files older than 24 h are removed. Redis is never dumped.
**Download.** `backup_read` opens the file on the first call (`offset` 0) and keeps a cursor per `downloadId`; each later call must continue at the previous end (`invalid_input` otherwise). At most **16** downloads are open (`operation_busy`); a download is closed at `eof`, on an error, by `backup_close`, or after **15 minutes**.
**Upload.** `upload_start`, any number of `upload_chunk`, then `upload_finish` with the sha256; `upload_abort` removes the partial file.
**Deadlines.** Every operation has a 30 minute deadline in the agent. The engine waits much less for most: 3 s for `capabilities`, 30 s by default, 2 minutes for `delete` and `upload_*`, and **30 minutes** for `backup_create`, `restore`, `backup_offsite_put`, `backup_offsite_restore`, `volume_backup_create` and `volume_backup_offsite`. The other operations (`register`, `backup_list`, `backup_read`, `backup_close`) use the 30 s default.
**Off-site URLs.** `url` and `headers` come from the engine and carry credentials. The agent does not log or store them and does **not** restrict their scheme or host; it relies on the engine, which is trusted ([section 10](#10-security-considerations)).

**Socket relay.** `db_socket_open {t, id, args: dbSpec}` makes the agent connect to the container's loopback port. The port is derived from the inspected `5432/tcp` binding on `127.0.0.1`, never taken from the frame. The agent answers `db_socket_ready`, then relays raw bytes both ways as base64 in the field **`d`** (not `data`): `db_socket_in` carries at most **180000** characters per frame (a larger or undecodable frame closes the socket), and `db_socket_out` carries reads of at most **128 KiB**. The relay ends with `db_socket_end`, which has no `error` after a normal close or the deadline, `error: true` (the spec or identity was refused, the database is deleted, there is no loopback port, or the dial failed), or one of `operation_busy`, `database_not_running`, `query_too_large`.
Limits: dial timeout **5 s**; a **30 s deadline from the dial** for the whole relay (not an idle timer); `query_too_large` after **4 MiB** received from the database. `db_socket_close` closes the connection; a `db_socket_in` or `db_socket_close` for an unknown id is ignored. The engine adds its own limits: a 30 s timer per socket (`query_timeout`), and it destroys the socket with `query_too_large` when one `db_socket_out` carries more than 350000 characters. A socket is **not** resumed after a reconnect; the agent notices the loss only when it next fails to send, or at the deadline ([7.2](#72-what-survives-a-reconnect)). Only Postgres is relayed; a Redis database fails with `error: true`.

<!-- example: frames.json dbRequest -->
```json
{"t":"db_request","id":"db-1","type":"capabilities","args":{}}
```

<!-- example: database.json capabilities.result -->
```json
{"protocol":1,"volumeDelete":true,"backups":true,"query":true,"writeQuery":true,"restoreUpload":true,"offsitePut":true,"volumeBackup":true}
```

<!-- example: frames.json dbRequest -->
```json
{"t":"db_request","id":"db-3","type":"backup_read","args":{"generation":"g1","type":"postgres","orgId":"org_EXAMPLE","databaseName":"db1","container":"f2c-db-db1","volume":"f2c-db-db1-data","user":"app","database":"app","key":"20261118T020000Z-aaaaaaaaaaaaaaaa.dump","downloadId":"dl-1","offset":0}}
```

<!-- example: database.json backup_read.result -->
```json
{"data":"AAAA","offset":0,"size":3,"eof":true}
```

<!-- example: frames.json dbResult -->
```json
{"t":"db_result","id":"db-2","ok":false,"code":"operation_busy","status":409}
```

<!-- example: frames.json dbSocketOut -->
```json
{"t":"db_socket_out","id":"sock-1","d":"AAAA"}
```

<!-- example: frames.json dbSocketOpen -->
```json
{"t":"db_socket_open","id":"sock-1","args":{"generation":"g1","type":"postgres","orgId":"org_EXAMPLE","databaseName":"db1","container":"f2c-db-db1","volume":"f2c-db-db1-data","user":"app","database":"app"}}
```

### 4.9 Command catalogue

There are 21 command types ([`commandType`](protocol/schemas/commands.json#/$defs/commandType)). For each, `args` is validated by `<type>.args` and the result `data` by `<type>.result` in
[`commands.json`](protocol/schemas/commands.json). Each example below is a `cmd` frame followed by the successful `result` frame. Unless stated, a command that fails returns `ok:false` with a text `error` and, at protocol >= 1, a `code` ([5.1](#51-resultcode)); at protocol 0 it has no `code`.
Validation of `args` is done by the agent; unknown keys are ignored except for `run`. Container names must match `^[a-z0-9][a-z0-9_.-]{0,62}$`. The agent runs commands concurrently; see [section 6](#6-command-lifecycle).

#### 4.9.1 `pull`

`{image}` pulls an image (`docker pull`, using the registry credentials from `registry_login`). Result `{image, id}` where `id` is the image ID (may be empty).

<!-- example: pull @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"pull","args":{"image":"registry.example.com/team/app:1.2.3"}}
{"t":"result","id":"c1","ok":true,"data":{"image":"registry.example.com/team/app:1.2.3","id":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}
```

#### 4.9.2 `run`

Starts (or replaces) a managed container. An existing **managed** container with the same name is force-removed first; an unmanaged container with that name is an error. The container is published only on `127.0.0.1` (`hostPort` 0 lets Docker choose, otherwise 20000 to 29999),
unless `noPublish` is true, and gets `PORT` set. **Default-deny**: any argument outside the schema fails the command (named errors exist for `privileged`, host networking and bind mounts). Env values go through a 0600 file, never the command line. The restart policy is `unless-stopped`, or `no` with `oneShot`.
Result `{containerId, hostPort, caps}`; `caps` reports the capability profile (`profile: "stack-v1"` means `--cap-drop ALL` plus `no-new-privileges` plus `capAdd`).

<!-- example: run @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"run","args":{"name":"myapp","image":"f2c/myapp:abc123","env":{"NODE_ENV":"production"},"memoryMb":512,"cpus":0.5,"port":3000,"hostPort":20001,"network":"f2c-net","labels":{"f2c.example":"1"}}}
{"t":"result","id":"c1","ok":true,"data":{"containerId":"4f1c2a9b8d7e","hostPort":20001,"caps":{"profile":"","drop":"","add":[],"noNewPrivileges":false}}}
```

#### 4.9.3 `stop`

`{name, timeout?}` stops a managed container (`timeout` seconds, 1 to 120, default 10; other values mean 10). Fails if the container does not exist or is not managed. Result `{stopped}`.

<!-- example: stop @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"stop","args":{"name":"myapp","timeout":10}}
{"t":"result","id":"c1","ok":true,"data":{"stopped":"myapp"}}
```

#### 4.9.4 `rm`

`{name}` force-removes a managed container. Idempotent: a missing container gives `existed: false`. Result `{removed, existed}`.

<!-- example: rm @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"rm","args":{"name":"myapp"}}
{"t":"result","id":"c1","ok":true,"data":{"removed":"myapp","existed":true}}
```

#### 4.9.5 `logs`

`{name, tail?, follow?, followSeconds?}` streams `docker logs --timestamps` as `stream` frames (batched about every 250 ms or 32 KiB). `tail` is 1 to 5000 (default 100). With `follow`, it keeps streaming until `followSeconds` (1 to 300, default 30) or `cancel`. Result `{lines, bytes, followed}`.

<!-- example: logs @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"logs","args":{"name":"myapp","tail":100,"follow":true,"followSeconds":30}}
{"t":"result","id":"c1","ok":true,"data":{"lines":100,"bytes":8123,"followed":true}}
```

#### 4.9.6 `stats`

`{names?, detail?}` lists managed containers (all, or only `names`; a requested name that does not exist appears with `state: "missing"`). For running containers it adds `cpuPct` and `memUsage` strings from `docker stats`; with `detail` it adds `health`, `restarts`, `exitCode`, `startedAt`
(zero values are omitted). Result `{containers}`.

<!-- example: stats @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"stats","args":{"names":["myapp"],"detail":true}}
{"t":"result","id":"c1","ok":true,"data":{"containers":[{"name":"myapp","state":"running","image":"f2c/myapp:abc123","status":"Up 3 hours","cpuPct":"0.50%","memUsage":"120MiB / 512MiB","health":"healthy","startedAt":"2026-11-18T07:00:00Z"},{"name":"gone","state":"missing"}]}}
```

#### 4.9.7 `exec`

`{name, cmd[], timeoutSeconds?}` runs `docker exec` in a managed container (for example `pg_dump`). Stdout is streamed as base64 `stream` frames of up to 256 KiB raw each. `timeoutSeconds` is 1 to 3600, default 600. A non-zero exit status is still `ok:true`; only failure to run is `ok:false`.
Result `{exitCode, stdoutBytes, stderr (last 4000 characters), encoding: "base64"}`.

<!-- example: exec @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"exec","args":{"name":"f2c-db-db1","cmd":["pg_dump","--version"],"timeoutSeconds":60}}
{"t":"result","id":"c1","ok":true,"data":{"exitCode":0,"stdoutBytes":24,"stderr":"","encoding":"base64"}}
```

#### 4.9.8 `caddy_apply`

`{config, hosts?, wildcard?, issuanceBlocked?}` applies a complete Caddy JSON configuration atomically with `POST /load` on the local admin API (30 s). `config.admin` is added if missing so the agent keeps its admin access. `hosts` replaces the allow-list of the on-demand TLS ask endpoint (`127.0.0.1:9180`, `/tls/ask`; at most 10000 valid host names;
absent or `null` keeps the list; an invalid entry fails the command). `wildcard` `{domain, provider}` (or `null`) configures DNS-01 using the token from `dns_token`; provider `other` adds nothing. `issuanceBlocked` is the list of registered domains at the Let's Encrypt limit.
Route `@id` conventions inside `config` (`app-`, `dom-`, `svcd-dom-`, `redir-`, optional `tls-`) feed the access-log mapping ([4.3](#43-hb-heartbeat)). Each `caddy_apply` is a whole-configuration replacement, and the engine drops older pending ones ([6.5](#65-engine-resend-ttl-and-superseding)).
Result `{applied: true, bytes, hosts, wildcard}`; `wildcard` is the applied subject `*.<domain>` or an empty string.

<!-- example: caddy_apply @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"caddy_apply","args":{"config":{"apps":{"http":{"servers":{"srv0":{"listen":[":80"],"routes":[{"@id":"app-myapp","match":[{"host":["myapp.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:20001"}]}],"terminal":true}]}}}}},"hosts":["myapp.example.com"],"wildcard":null,"issuanceBlocked":[]}}
{"t":"result","id":"c1","ok":true,"data":{"applied":true,"bytes":512,"hosts":1,"wildcard":""}}
```

#### 4.9.9 `cert_install`

`{domain, certPem, keyPem}` validates that the certificate and key form a pair and cover `domain` (a leading `*.` is allowed), then writes `<cert-dir>/<domain>.crt` and `.key` (`*.` becomes `_wildcard.`), key mode 0600. Result `{certPath, keyPath, notAfter}`. The private key is in the request and is never returned.

<!-- example: cert_install @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"cert_install","args":{"domain":"*.apps.example.com","certPem":"-----BEGIN CERTIFICATE-----\nEXAMPLE\n-----END CERTIFICATE-----\n","keyPem":"-----BEGIN PRIVATE KEY-----\nEXAMPLE\n-----END PRIVATE KEY-----\n"}}
{"t":"result","id":"c1","ok":true,"data":{"certPath":"/var/lib/f2c-agent/certs/_wildcard.apps.example.com.crt","keyPath":"/var/lib/f2c-agent/certs/_wildcard.apps.example.com.key","notAfter":"2027-02-16T09:00:00Z"}}
```

#### 4.9.10 `tls_warm`

`{host}` makes one HTTPS request to `127.0.0.1:443` with SNI `host` so Caddy obtains the certificate (30 s per attempt, up to 2 attempts). **Failure is reported inside a successful result**: `data.ok` is false with `error`. Result `{ok, status?, issuer?, attempts, error?}`.

<!-- example: tls_warm @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"tls_warm","args":{"host":"app.example.com"}}
{"t":"result","id":"c1","ok":true,"data":{"ok":true,"status":200,"issuer":"CN=R11,O=Let's Encrypt,C=US","attempts":1}}
```

#### 4.9.11 `http_probe`

`{host, path?, port?}` does `GET http://127.0.0.1:<port><path>` with `Host: <host>`, no redirects, 5 s timeout. `path` starts with `/` (default `/`), `port` defaults to 80. A connection failure is `ok:true` with `status: 0` and `error`. Result `{status, ms}` or `{status: 0, error}`.

<!-- example: http_probe @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"http_probe","args":{"host":"myapp.example.com","path":"/healthz","port":80}}
{"t":"result","id":"c1","ok":true,"data":{"status":200,"ms":4}}
```

#### 4.9.12 `build`

`{artifactUrl, token, sha256, app, tag, ...}` downloads a build context (`GET artifactUrl` with `Authorization: Bearer <token>`, no redirects, at most `maxBytes`, capped at 500 MiB), verifies its SHA-256, unpacks it, builds `f2c/<app>:<tag>` with the railpack or Dockerfile builder, streams the build log as `stream` frames, and optionally uploads the image to `uploadUrl`.
`timeoutS` defaults to 30 minutes and is capped at 2 hours. `buildPack` is `nixpacks` (this selects railpack), `static` or `dockerfile` (needs `dockerBuildV`). The token and secret-looking env values are masked in the streamed log.
`artifactUrl` MUST NOT carry credentials or a query. A failed or cancelled build removes a partial image. Result `{image, id, tool, durationMs, ...}`.

<!-- example: build @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"build","args":{"artifactUrl":"https://engine.example.com/agent/context/srv_EXAMPLE/job1","token":"EXAMPLE_ONE_TIME_TOKEN","sha256":"0000000000000000000000000000000000000000000000000000000000000000","app":"myapp","tag":"abc123","buildPack":"nixpacks"}}
{"t":"result","id":"c1","ok":true,"data":{"image":"f2c/myapp:abc123","id":"sha256:0000000000000000000000000000000000000000000000000000000000000000","tool":"railpack","buildkitHost":"docker-container://f2c-buildkit","durationMs":42000,"contextBytes":123456,"logTail":"built"}}
```

#### 4.9.13 `load`

`{artifactUrl, token, sha256, image, imageId?, size}` downloads an image archive built elsewhere (size 1 byte to 4 GiB), verifies SHA-256, and `docker load`s it as `image` (`f2c/<app>:<tag>`). If `imageId` is already present locally the load is skipped (`skipped: true`). Result `{image, id, bytes, sha256, durationMs}` or `{image, id, skipped, durationMs}`.

<!-- example: load @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"load","args":{"artifactUrl":"https://engine.example.com/agent/transfer/srv_EXAMPLE/job1","token":"EXAMPLE_ONE_TIME_TOKEN","sha256":"0000000000000000000000000000000000000000000000000000000000000000","image":"f2c/myapp:abc123","imageId":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":1048576}}
{"t":"result","id":"c1","ok":true,"data":{"image":"f2c/myapp:abc123","id":"sha256:0000000000000000000000000000000000000000000000000000000000000000","bytes":1048576,"sha256":"0000000000000000000000000000000000000000000000000000000000000000","durationMs":900}}
```

#### 4.9.14 `image_present`

`{image?, imageId?}`, both optional, asks whether an image ID is present locally and, when `image` is also given, tags it. Result `{present, id}`.

<!-- example: image_present @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"image_present","args":{"image":"f2c/myapp:abc123","imageId":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}
{"t":"result","id":"c1","ok":true,"data":{"present":true,"id":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}
```

#### 4.9.15 `self_update`

`{sha256, version?, rollback?, reason?}` replaces the agent binary with the one whose hash the engine names, after verifying it against the signed release and running the downgrade and floor guard ([section 8.4](#84-self-update-and-rollback)). If the running binary already has that hash the result is `{upToDate: true, hash}`. Otherwise the agent returns `{restarting: true, from, to}` (at protocol >= 1 also `fromVersion`, `toVersion`, `rollback`), then exits 3 s later so systemd starts the new binary.
`version` (the signed `# version` the engine expects), `rollback` and `reason` (required with `rollback`, 1 to 200 characters) are read only at protocol >= 1 and only sent to agents that report `hb.updateV`. A downgrade, an older build or a release without a signed version is refused with `not_allowed` unless `rollback` is set; a target below the persisted signed floor is refused even then. The same version and build with different bytes, a `version` that differs from the signed one, or a new binary that reports another version is `integrity_failed`.
Fails with `conflict` if another update is pending.

<!-- example: self_update @cmdpair -->
```json
{"t":"cmd","id":"agentupd-lz3k9","type":"self_update","args":{"sha256":"1111111111111111111111111111111111111111111111111111111111111111","version":"0.4.0+202611190506"}}
{"t":"result","id":"agentupd-lz3k9","ok":true,"data":{"restarting":true,"from":"0000000000000000000000000000000000000000000000000000000000000000","to":"1111111111111111111111111111111111111111111111111111111111111111","fromVersion":"0.3.1+202611181227","toVersion":"0.4.0+202611190506","rollback":false}}
```

A deliberate rollback (the engine's `rollback` path, [8.3](#83-what-an-engine-pins-and-serves)):

<!-- example: self_update @cmdpair -->
```json
{"t":"cmd","id":"agentupd-lz3ka","type":"self_update","args":{"sha256":"1111111111111111111111111111111111111111111111111111111111111111","version":"0.3.1+202611181227","rollback":true,"reason":"0.4.0 breaks caddy_apply on arm64"}}
{"t":"result","id":"agentupd-lz3ka","ok":true,"data":{"restarting":true,"from":"0000000000000000000000000000000000000000000000000000000000000000","to":"1111111111111111111111111111111111111111111111111111111111111111","fromVersion":"0.4.0+202611190506","toVersion":"0.3.1+202611181227","rollback":true}}
```

#### 4.9.16 `rename`

`{name, to}` renames a managed container (used for zero-downtime swaps). `to` must be free and different. Result `{renamed, to}`.

<!-- example: rename @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"rename","args":{"name":"myapp-next","to":"myapp"}}
{"t":"result","id":"c1","ok":true,"data":{"renamed":"myapp-next","to":"myapp"}}
```

#### 4.9.17 `restart_agent`

`{}` answers `{restarting: true}`, then the agent exits (status 0) 2 s later; systemd restarts it.

<!-- example: restart_agent @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"restart_agent","args":{}}
{"t":"result","id":"c1","ok":true,"data":{"restarting":true}}
```

#### 4.9.18 `network_rm`

`{name}` removes a managed stack network. `name` MUST match `f2c-stk-*`. Idempotent. Result `{removed, existed}`.

<!-- example: network_rm @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"network_rm","args":{"name":"f2c-stk-myapp"}}
{"t":"result","id":"c1","ok":true,"data":{"removed":"f2c-stk-myapp","existed":true}}
```

#### 4.9.19 `volume_rm`

`{name}` removes one stack volume. `name` MUST start with `f2c-f2c-`; fails while a container uses it. Idempotent. Result `{removed, existed}`.

<!-- example: volume_rm @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"volume_rm","args":{"name":"f2c-f2c-myapp-data"}}
{"t":"result","id":"c1","ok":true,"data":{"removed":"f2c-f2c-myapp-data","existed":true}}
```

#### 4.9.20 `volumes_list`

`{}` lists the server's Docker volumes with mount point, size (`du`) and the owning app if a managed container mounts it. Result `{volumes: [{name, mountpoint?, sizeBytes?, appName?, appId?}]}`.

<!-- example: volumes_list @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"volumes_list","args":{}}
{"t":"result","id":"c1","ok":true,"data":{"volumes":[{"name":"f2c-f2c-myapp-data","mountpoint":"/var/lib/docker/volumes/f2c-f2c-myapp-data/_data","sizeBytes":4096,"appName":"myapp","appId":"myapp"}]}}
```

#### 4.9.21 `harden`

`{runId, mode, allowIps?, swapGb?, sshKeysOnly?, backupId?}` is the optional "Harden server" feature. `runId` is `harden-` plus 1 to 40 of `[a-z0-9]`; `mode` is `dry_run`, `apply` or `rollback` (`backupId` is `last` or `YYYYMMDD-HHMMSS`, for rollback). `allowIps` has at most 16 IPs or CIDRs, `swapGb` is 0 to 16 (default 2), `sshKeysOnly` defaults to true.
The agent writes a request file; a root `f2c-harden.path` unit starts `f2c-harden.service` (`harden.sh`), which writes a result file that the agent returns. Apply and dry run check the `harden/link-proof` file written by the agent's link monitor ([2.6](#26-keepalive-and-liveness)) before and after their steps. Rollback skips the agent-active and agent-connected checks by default, so restoring a backup does not depend on a running agent; it still verifies restored files, firewall state and SSH. Manual CLI use can opt back into the agent checks with `--rollback-agent-check` (not a protocol field).

- **Exactly once per `runId`.** The agent records each run in `<state-dir>/harden/runs.json` (up to 200). A repeated `runId` is never run again; the agent returns the recorded or fresh outcome with `data.replayed: true` ([6.3](#63-duplicate-ids-and-replay)).
- **Failure shapes.** Failures before the run starts are `ok:false` with a `harden_*` code at every protocol ([section 5](#5-error-codes-and-retry-semantics)). Failures the agent detects while following the run (`harden_running:`, `harden_not_triggered:`, `harden_script_failed:` or an unknown outcome) depend on the session: at **protocol 0** they come back as `ok:true` with `data.status: "failed"`, a `data.message` with that prefix and **no `code`**; at **protocol >= 1** they are `ok:false` with the same message as `error`, **no `data`**, and a code (`conflict`, `harden_failed`, `harden_script_failed`; [5.1](#51-resultcode)). What the **script** reports (`failed`, `rolled_back`) is `ok:true` with the full audit at every protocol, and so is the replay of a recorded result.
- **Waiting.** The agent waits up to 21 minutes for the result, then returns `harden_timeout` and keeps following the run for up to 32 minutes in total so that its outcome is recorded.
- Result `{version, id, mode, status (succeeded/failed/rolled_back), message, startedAt, finishedAt, backupId, sshKeysPresent, sshPorts, warnings, prechecks, postchecks, steps, audit}` plus `replayed?`. The step, check and audit objects are produced by `harden.sh`; this specification only fixes the envelope.

<!-- example: harden @cmdpair -->
```json
{"t":"cmd","id":"c1","type":"harden","args":{"runId":"harden-abc123","mode":"dry_run","allowIps":["192.0.2.10","192.0.2.0/24"],"swapGb":2,"sshKeysOnly":true}}
{"t":"result","id":"c1","ok":true,"data":{"version":1,"id":"harden-abc123","mode":"dry_run","status":"succeeded","message":null,"startedAt":"2026-11-18T10:00:00Z","finishedAt":"2026-11-18T10:00:30Z","backupId":null,"sshKeysPresent":true,"sshPorts":[22],"warnings":[],"prechecks":[],"postchecks":[],"steps":[],"audit":[]}}
```

## 5. Error codes and retry semantics

### 5.1 `result.code`

`code` is a lower-case string (`^[a-z][a-z0-9_]{0,39}$`) on an `ok:false` result. **Which codes the agent sends depends on the session protocol** ([3.2](#32-negotiation); since agent 0.4.0). The gate is `SessionProtocol() >= 1` only; the `resultCode` capability is not consulted.

- **Protocol 0** (an engine that sent no valid `hello_ok.protocol`, or any agent up to 0.3.1): exactly the **eight legacy codes** `unknown_command`, `expired`, `harden_not_installed`, `harden_bad_request`, `harden_state_unreadable`, `harden_script_failed`, `harden_interrupted`, `harden_timeout`. Every other failure is free text with **no `code`**. This is byte-for-byte what 0.3.1 sends (golden tests).
- **Protocol >= 1**: **every `ok:false` carries a `code`** from the 27-code list below (or one of the five kept prefix codes). The `error` text is **unchanged** from protocol 0. The agent never sends both `unknown_command` and `unknown_cmd`: protocol 0 gets the first, protocol >= 1 the second. The fallback is `internal`.
- There is **no `retryable` field**. The Retry column is guidance for engine authors, not wire data. "Retry" means: may the engine send the command again with a **new** `id` ([5.3](#53-retry-semantics)).

The enumeration is [`resultCode`](protocol/schemas/common.json#/$defs/resultCode) (the 27, the kept five, and the legacy `unknown_command`). An engine should read `code` first and match the error text only for a result without one (protocol 0 agents); keep the text stable.

| # | Code | Raised when | Retry |
|---|---|---|---|
| 1 | `bad_request` | The arguments are missing, malformed, out of range, or contain an option the agent does not know. Also a refused container/network/volume name, image reference, port, env key, URL or sha256. | no (fix the request) |
| 2 | `unknown_cmd` | `type` is not one of the 21 commands. Protocol 0 sessions get `unknown_command` instead, never both. | no (update the agent) |
| 3 | `expired` | `notAfter` plus 60 s is in the past on arrival. Not cached. Same string at every protocol. | only with a new `id` and deadline |
| 4 | `not_found` | The named container, network or volume does not exist (including a non-zero docker exit whose stderr says `no such ...`). | no (create it first) |
| 5 | `not_allowed` | A policy refusal: the object is not managed by the agent, or the request asks for something the agent never does (privileged, host network, bind mounts, reserved label, capability, certificate that does not cover the domain), or a `self_update` the update guard refuses (a downgrade, an older build or an unsigned version without `rollback`, or anything below the signed floor; [8.4](#84-self-update-and-rollback)). | no |
| 6 | `conflict` | The target exists or is in use, or another operation of the same kind runs: `rename` target exists, `volume_rm` volume in use, `self_update` already pending or "engine now serves X, expected Y (retry the update)", a harden run is already in progress. | yes, later |
| 7 | `port_in_use` | The host port is already bound (`port is already allocated`, `address already in use`). | yes, with another `hostPort` (0 picks one) |
| 8 | `image_not_found` | The image or tag does not exist, or access is denied (`manifest unknown`, `repository does not exist`, `pull access denied`, `unauthorized`). | no (fix reference or credentials) |
| 9 | `image_pull_failed` | Any other failed `docker pull` (network, DNS, TLS, registry down, rate limit) and the fallback for an unrecognised pull error. | yes |
| 10 | `timeout` | A deadline expired: `build` (`timeoutS`), `load`, `caddy_apply`, `self_update` download, docker calls. **Not** `exec`: its deadline stays `ok:true, exitCode:-1` in protocol 1. | yes, maybe with a longer limit |
| 11 | `cancelled` | The engine cancelled the command or the connection closed it (`build cancelled`, `load`, any docker call on a cancelled context). | yes |
| 12 | `interrupted` | The agent **restarted while the command was running** and the command is UNSAFE to run twice (`run`, `rename`, `build`, `load`, `exec`; [6.3](#63-duplicate-ids-and-replay)). It may have partly run. The text is `interrupted: the agent restarted while <type> was running; it may have partly run, check the state and retry with a new id`, the same at every protocol; the code is sent from protocol >= 1. The engine treats it as **final** (outcome unknown: inspect the state, then use a **new** id); for `harden` the engine maps it to `harden_interrupted`. | after checking the state, with a new `id` |
| 13 | `docker_unavailable` | Docker is not installed, not running, or not reachable by the agent user. | after fix |
| 14 | `no_space` | `no space left on device` from docker, the build unpack, load, or the self-update write. Kept. | after fix |
| 15 | `build_failed` | The build or image load ran and failed: compiler error, bad context or archive, image missing after the build, unpack limits. | no, for the same context |
| 16 | `transfer_failed` | Moving bytes failed: context or release download, image export/upload, engine answered non-2xx, size caps. Also a self-update whose `.sha256` file is unusable. | yes |
| 17 | `integrity_failed` | A checksum or signature did not verify, the signed hash differs from the engine's, the new binary failed its smoke test or reports another version than the signed one, the signed header is malformed or of an unknown format, or the same version and build is offered with different bytes. | no (investigate) |
| 18 | `caddy_unavailable` | The Caddy admin API could not be reached (`caddy admin: ...`). A deadline there becomes `timeout`. | yes |
| 19 | `caddy_rejected` | Caddy refused the configuration (`caddy /load returned <status>`), or the request cannot be applied (no stored DNS token, config without `apps.tls.automation`). | no (fix the config) |
| 20 | `harden_not_installed` | `harden.sh` or the `f2c-harden.path` unit is missing or inactive. Same string at every protocol. | after `install.sh` |
| 21 | `harden_failed` | A harden failure the agent itself detected that has no more specific code: `harden_not_triggered` (the service never picked up the request), an unknown outcome (no result found), and a replay of an unknown outcome. At protocol >= 1 it is `ok:false` with the message as `error` and **no `data`**. | after fix, or a new `runId` |
| 22 | `harden_bad_request` | Harden arguments failed validation. Same string at every protocol (kept). | no |
| 23 | `harden_state_unreadable` | `harden/runs.json` could not be read or written. Same string at every protocol. | after fixing the state directory |
| 24 | `harden_script_failed` | The request file could not be queued, or `f2c-harden.service` ended without writing a result for the run. At protocol >= 1 the second case is `ok:false` with no `data`. A script-reported `failed` or `rolled_back` is **not** this: it stays `ok:true` with the full audit. | new `runId` |
| 25 | `harden_interrupted` | The command was cancelled while waiting; the root run is not interrupted. Same string at every protocol. | re-send the same `runId` to read the outcome |
| 26 | `harden_timeout` | No result within 21 minutes; the agent keeps following. Same string at every protocol. | re-send the same `runId` later |
| 27 | `internal` | Anything unclassified. The fallback of last resort; at protocol >= 1 `code` is never empty on `ok:false`. | maybe (report it) |

Protocol >= 1 also sends five **kept prefix codes** (outside the 27). The engine already matches them as the text prefix of `error` (`dockerfile_not_found: ...`); at protocol >= 1 they are also `code`:

| Code | Raised when | Retry |
|---|---|---|
| `dockerfile_not_found` | `build` with `buildPack:"dockerfile"`: the Dockerfile is not in the context. | no |
| `dockerfile_invalid_path` | `dockerfileLocation` is not a safe relative path. | no |
| `dockerfile_invalid_target` | `dockerfileTarget` is not a valid stage name. | no |
| `dockerfile_target_not_found` | The named build stage does not exist in the Dockerfile. | no |
| `build_arch_mismatch` | `load`: the loaded image is built for another CPU architecture. | no |

**Harden (4.9.21).** At protocol >= 1, a failure the agent detects itself while following a run (`harden_running`, `harden_not_triggered`, `f2c-harden.service` ended without a result, an unknown outcome) is `ok:false` with `error` set to the same message and **no `data`**; the codes are `conflict`, `harden_failed`, `harden_script_failed` and `harden_failed`. At protocol 0 these stay `ok:true` with `data.status:"failed"` as before. A result the **script** reports (`status` `failed` or `rolled_back`) stays `ok:true` with the full audit at every protocol, and so does the replay of a recorded result (`replayed:true`).

**Other changes at protocol >= 1.** A non-zero exit of `docker logs` is `ok:false` with the docker stderr tail as `error` (protocol 0: `ok:true`). An `exec` deadline is **not** a failure in protocol 1: it stays `ok:true` with `exitCode:-1`.

Callers MUST NOT parse error text for anything the codes cover; the text (validation messages, `docker <verb>: <stderr tail, up to 2000 chars>`, `caddy admin: ...`, `build cancelled: ...`) remains for people and for the engine's existing text matching.

Engine-synthesised codes. An engine MAY record two further codes on a command that never got an agent result: `superseded` (a newer lifecycle command for the same target replaced it before delivery, see §6.7) and `expired` (its `notAfter` passed while the agent was offline). `superseded` is engine-only: agents never send it and it is not in the agent code list above. `expired` is also an agent code; the engine may synthesise it for a command the agent never received.

### 5.2 Other error channels

| Channel | Shape |
|---|---|
| `token_rotated`, `registry_login`, `dns_token_ok` replies | `ok: false` with `error` text (the engine reads at most 300 characters of it). At protocol >= 1 the frame also carries a `code` from the list in [5.1](#51-resultcode); below protocol 1 it is exactly as before, with no `code`. |
| `db_result` | `code` and `status` as in [4.8](#48-managed-database-channel). |
| `console_exit` | `reason` is `error`, `not_running` or `exited`. |
| `db_socket_end` | `error: true` or a short code. |
| HTTP enrolment | Non-2xx with `{error, code?}`; for join the agent also prints the `code`. |
| WebSocket upgrade | HTTP `401`, `404`, `426`; after upgrade, close codes ([2.7](#27-close-codes)). |

### 5.3 Retry semantics

- The agent never retries a command and never re-runs one it has finished: a result, success or failure, is final for its `id` (up to the dedupe limit, [6.3](#63-duplicate-ids-and-replay)).
- Re-sending a **finished** id returns the cached result, including a cached failure. To retry after a failure the engine MUST use a new id.
- No result at all (disconnect, agent restart) is the case the engine re-sends for, automatically, with the **same** id ([6.5](#65-engine-resend-ttl-and-superseding)).
- Most commands are designed to be idempotent (`rm`, `network_rm`, `volume_rm`, `run` replacing a container, `caddy_apply` replacing a configuration), so a second execution after an agent restart ([6.3](#63-duplicate-ids-and-replay)) is harmless. Exactly-once handling depends on the command kind (table in [6.3](#63-duplicate-ids-and-replay)): `harden` is exactly-once by `runId`, UNSAFE commands answer `interrupted` after an agent restart instead of running again, and READ and CONVERGE commands may run again.

### 5.4 Size and truncation limits (as implemented)

*These are the limits the code applies today; nothing here is new behaviour. A receiver MUST treat `error` as opaque text for people (decide on `code`, [5.1](#51-resultcode)), MUST accept any frame up to 16 MiB, and MUST NOT rely on the end of a long text being present.*

**Frames.** The WebSocket message limit is **16 MiB** in both directions (agent `SetReadLimit(16<<20)`, engine `MAX_MESSAGE`); a larger message closes the connection with `1009 "too big"`. The agent does not check its own outgoing frames against it, except for the replay stub below.

**Result `error` and `data`.**

| Where | Limit | Behaviour |
|---|---|---|
| Agent, `result.error` | none | The full error text is sent; the components below cut their own text before it gets there. |
| Engine, stored `error` | **4000 UTF-16 code units** | `m.error.slice(0, 4000)`, or `"command failed"` when `error` is empty or missing. Other engine error fields (`dns_token_ok`, `token_rotated`) keep 300. |
| Engine, stored `data` | none | Stored as received (bounded by the 16 MiB frame), with the result for 1 hour (`RES_TTL_S = 3600`). The command record lives 24 hours (`CMD_TTL_S = 86400`). |
| Agent, replay copy of a result over **256 KiB** (`maxStoredFrame`) | stub | A result whose JSON is larger is kept in `done.json` and the journal as a **stub**, so a re-sent id costs little. The frame sent when the command ends is **always the full frame**. |

The stub keeps `ok`, `code` and `error`, with `error` cut to **4000 bytes** (not characters: a cut inside a multi-byte UTF-8 character becomes U+FFFD when the frame is encoded; known, harmless, not changed). For `ok:true` the `data` is replaced by `{"replayStub": true, "reason": "result too large to replay"}`; the engine records that as success without data ([6.3](#63-duplicate-ids-and-replay)). `done.json` is bounded by 500 entries, 8 MiB and 25 hours.

**Text the agent cuts before it reports it** (each keeps the **end** of the output unless noted):

| Source | Limit |
|---|---|
| `docker <verb>` failures (`pull`, `run`, ...) | `docker <verb>: ` plus the last **2000 bytes** of output |
| `logs` failure | the last **4096 bytes** of recent output (rolling buffer of 8192) |
| `exec` | stderr tail **4000 bytes**, in `data` |
| `build` failure | the last **40 log lines**; the success result has `logTail` of 40 lines |
| `docker save` stderr (`image_present`/transfer) | last **400** |
| Caddy `/load` error body | first **4096 bytes** |
| `http_probe` error, certificate-watch `lastErr` | last **300** |
| harden messages | **500** and **300**; the root-unit JSON result is limited to **1 MiB** (`hardenMaxResult`) |

**Streams and chunks.**

| Item | Limit |
|---|---|
| `logs` | a `stream` frame every **32 KiB** or **250 ms**; one line can be 64 KiB to **1 MiB** (the scanner buffer): a longer line stops the scan |
| `exec` stdout | `stream` frames of up to **256 KiB**, base64; `timeoutSeconds` 1 to 3600, default 600 |
| `build` log | at most **4 MiB** in total, then one `truncated` notice |
| console, database sockets | 128 KiB reads (`console_out`, `db_socket_out`); `db_socket_in` at most 180000 characters ([4.7](#47-console-session), [4.8](#48-managed-database-channel)) |
| database dump, download, upload | 2 GiB per dump, 128 KiB per `backup_read`, 180000 characters per `upload_chunk` ([4.8](#48-managed-database-channel)) |

**Input limits** (a value over the limit is refused with `bad_request` or the command's own code):

| Argument | Limit |
|---|---|
| `run`: `volumes`, `labels` | 8 and 32 entries; label values 1024 characters |
| `run`: `cmd`, `entrypoint` | 64 items of at most 4096 characters |
| `run` stack options: `aliases`, health `intervalS` and `timeoutS` | 8 aliases; 1 to 3600 s |
| `build` context | 500 MB compressed (default), 4 GiB unpacked, 200000 entries; Dockerfile 1 MiB; build command 2000 characters |
| `load` (image transfer) | 4 GiB by default |
| `caddy_apply` ask hosts | 10000 |
| `hello_ok.caps` | 64 entries of 64 characters |

**Fetch limits of the agent** (self-update and enrolment): `SHA256SUMS` 1 MiB, `SHA256SUMS.sigs` 64 KiB, a `.sig` 4096 bytes, the binary 256 MiB, a `.sha256` 512 bytes; enrolment replies 64 KiB and 1 MiB.

## 6. Command lifecycle

### 6.1 States

```
engine:  queued --send--> sent --ack--> acked --result--> done | failed
agent:   dedupe check --> journal --> ack --> running --> result (cached, then sent)
```

1. The engine records the command under its id (ids are unique: an engine refuses a new command whose id already exists) and queues it for the server. If the agent is connected it sends the `cmd` frame.
2. The agent decodes the frame, drops it if the `id` is empty, then applies the dedupe rules ([6.3](#63-duplicate-ids-and-replay)) and the `notAfter` check ([6.4](#64-notafter-and-skew)).
3. A new command is registered as running (written to `running.json` before it starts), the agent sends `ack`, and the command runs in its own goroutine (there is no limit on parallel commands).
4. On completion the agent stores the result frame in memory and in `<state-dir>/done.json` (and removes the `running.json` record), then sends it. If the connection is down the send is lost but the cached result remains.
5. The engine, on `result`, records the outcome, removes the command from its queue and wakes the waiters. On `ack` it only marks the command `acked`.

### 6.2 Acknowledgement

`ack` means "accepted and running". It is sent after the command is registered but before it executes, so it does not prove the arguments are valid. There is no negative acknowledgement; invalid arguments produce a `result` `ok:false`.
An `ack` is also sent again for a duplicate of a still-running id.

### 6.3 Duplicate ids and replay

> **Since agent 0.4.0.** Agents up to 0.3.1 only had the finished-id cache and the plain re-ack (last rows of the table).

The engine re-sends a command with the **same id, args and `notAfter`**; the first result wins and later ones are recorded by the engine as `late`. The agent keeps two files so that a re-sent id is never executed twice by accident:

- `done.json` (as before, byte-compatible): finished results. Each entry may now carry `at`, `type` and `argsSha`. Bounds: **25 h** TTL from `at`, **500** entries and **8 MiB** of cached frames (oldest dropped first). A result frame over **256 KiB** is cached as a **stub** (`ok`, `code`, the `error` cut to 4000 bytes, and for `ok:true` a `data` of `{"replayStub":true,"reason":"result too large to replay"}`); the frame sent when the command ends is always the full one.
- `running.json` (new, mode 0600, written atomically **before** the command starts and after it ends): `[{id, type, argsSha, notAfter, startedAt}]`. It stores a SHA-256 of the type and the canonical arguments, **never the arguments**. Entries older than 25 h are dropped. A missing or corrupt file means nothing was in flight.

| An id arrives that is... | Agent does |
|---|---|
| **finished** (in `done.json`) | Sends the cached frame; at protocol >= 1 with `"replayed": true` added to the frame (the cached `ok`, `error`, `code` and `data` are untouched). Below protocol 1 the frame is byte-identical to the first. No `ack`. Checked before `notAfter`. |
| **running** (live goroutine) | Does not start it again; sends `ack`. The one result is sent when it ends (attach). |
| **known with different args or type** | Protocol >= 1: not run, `ok:false`, `code:"bad_request"`, `command id <id> was already used for a different command`; the record is untouched and nothing is cached. Protocol 0: the cached or running command wins silently, as before. Entries written by older agents have no `argsSha` and are not checked. |
| **in `running.json` but with no goroutine** (the agent restarted while it ran) | By class, below. |
| **new** | `notAfter` check, write `running.json`, `ack`, run. |
| **past the 25 h TTL, or evicted** | A new command. |

**After a restart mid-run**, by the idempotency class of the command type:

- **READ** and **CONVERGE**: run again (same id, same args). **UNSAFE**: not run; the answer is `ok:false` with the text `interrupted: ...` and, from protocol >= 1, `code:"interrupted"` ([5.1](#51-resultcode)). The answer is cached (the next resend replays it). `harden` always runs again, its own `runs.json` decides. `restart_agent` answers `ok:true {"restarting":true}` (the restart did happen) and is not run.
- The engine guarantees that no older lifecycle command is still pending when it sends the next (6.7), so rerunning `rm`, `stop`, `network_rm` and `volume_rm` after a restart cannot hit a newer container.

**Idempotency table** (all 21 command types; the class table in `internal/agent/journal.go` is kept equal to the `commandType` schema by a test):

| Type | Class | What a second run does | After a restart mid-run |
|---|---|---|---|
| `logs`, `stats`, `volumes_list`, `image_present`, `tls_warm`, `http_probe` | READ | No side effects (`logs` with `follow` streams again; `tls_warm` and `http_probe` report failure inside `ok:true`). | runs again |
| `pull` | CONVERGE | A present image is a cheap no-op. | runs again |
| `caddy_apply` | CONVERGE | Replaces the whole Caddy config; same args, same state. | runs again |
| `cert_install` | CONVERGE | Rewrites the same files. | runs again |
| `rm` | CONVERGE | A missing container is `existed:false` (idempotent). | runs again |
| `stop` | CONVERGE | A stopped container is fine; a missing one is `not_found`. | runs again |
| `network_rm`, `volume_rm` | CONVERGE | A missing object is `existed:false`. `volume_rm` deletes data on its first run, so the engine sends it only on an explicit delete. | runs again |
| `self_update` | CONVERGE | Guarded: same hash is `upToDate:true`; a pending update marker is `conflict`. | runs again |
| `run` | UNSAFE | Replaces the container (`rm -f`, create): restarts the app. | `interrupted` |
| `rename` | UNSAFE | After success the source is gone (`not_found`); half-done is `conflict`. | `interrupted` |
| `build`, `load` | UNSAFE | Minutes of CPU or a large import, a second image or a partial load. | `interrupted` |
| `exec` | UNSAFE | Not read-only by type: it runs any argv in the container. A timeout is `ok:true`, `exitCode:-1`. | `interrupted` |
| `harden` | own | Exactly-once by `runId` (`runs.json`); a repeat returns the recorded outcome with `data.replayed:true` (an engine should not confuse this marker with the frame-level `replayed` of a re-sent id). | runs again; its record decides |
| `restart_agent` | special | The result is cached before the exit delay. | `ok:true {restarting:true}` |

- **Cancelled and failed commands are cached** like any other result. **`expired` results are not cached.**
- There is **no `hb.running`**: the answer to a resend (`ack`, the cached result, or `interrupted`) already tells the engine the state.

### 6.4 `notAfter` and skew

`notAfter` is an absolute RFC 3339 timestamp (fractional seconds allowed). The agent compares it to its own clock **on arrival only**: the command is refused when `now` is later than `notAfter + 60 s` (the allowed clock skew, `NotAfterSkew`). A refused command
gets `result {ok:false, code:"expired"}`, is not run, and is not cached, so nothing marks the id as executed. A missing `notAfter` means no deadline. A value that does not parse is logged and ignored, and the command runs.
`notAfter` does not stop a command that has already started. An engine should set an absolute `notAfter` on every command, store it, re-send it unchanged and settle an expired command itself with `expired`; an engine that does not leaves a command able to reach the agent long after it was created.

### 6.5 Engine resend, TTL and superseding

- On every (re)connect, after `hello_ok`, the engine reads its server queue in order and re-sends each `cmd` whose record still exists. Entries whose record has expired are removed.
- A command record lives for **24 hours** (`CMD_TTL_S = 86400`); results live **1 hour**. A command not answered within 24 hours disappears and is never re-sent.
- Before resending, and when a new `caddy_apply` is queued, the engine settles every older **pending** `caddy_apply` for that server as failed with `superseded by a later caddy_apply` and does not send it. An engine may use the code `superseded`, and settle an older never-sent lifecycle command (`run`, `rm`, `stop`, `rename`, `network_rm`, `volume_rm`) for the same object the same way when a newer one is queued ([6.7](#67-ordering-and-delivery-guarantees)); other types are not superseded.
- Without `notAfter`, a command could reach the agent up to 24 hours after it was created. An engine should set it (for example 5 to 15 minutes by command type, 24 hours at most) and re-send the stored value, so that a late command is refused as `expired`.

### 6.6 Timeouts and cancellation

The agent has no general command timeout; each command bounds itself:

| Command | Bound |
|---|---|
| `logs` | with `follow`: `followSeconds` (default 30, max 300) |
| `exec` | `timeoutSeconds` (default 600, max 3600) |
| `caddy_apply` | 30 s for the Caddy admin call |
| `tls_warm` | 30 s per attempt, 2 attempts |
| `http_probe` | 5 s |
| `build` | `timeoutS` (default 30 min, max 2 h) |
| `harden` | 21 min wait, 32 min follow |
| `self_update` | 5 min HTTP client timeout for downloads |
| `pull`, `run`, `stop` and the others | none beyond Docker's own |

**Cancellation.** `cancel {id}` calls the cancel function of a **running** command and is otherwise ignored (no reply, no error for an unknown or finished id). A command that honours its context (everything that shells out through `docker`, plus `build`, `load`, `logs`, `exec` and `harden`) stops
and ends with a normal `result` `ok:false` whose text depends on where it stopped (build errors say `cancelled`; `harden` uses `harden_interrupted`). That failure is cached like any other. The engine also settles superseded `caddy_apply` commands itself without cancelling them.

### 6.7 Ordering and delivery guarantees

- **Within a connection** frames are delivered in the order written (TCP and WebSocket order), but the agent writes from several goroutines, so only a single goroutine's frames have a defined order. In practice a command's `ack` precedes its `stream` frames, and `stream` precedes its `result`.
- **Between commands there is no ordering guarantee.** The engine re-sends in queue order, the agent starts each command in its own goroutine, and results can finish in any order. If order matters the engine MUST wait for the earlier result before sending the next command.
- **Delivery.** `cmd` and `result` are at-least-once, de-duplicated by id. `ack`, `stream`, `hb`, `cert_issued`, the console frames and the database frames are at-most-once and are lost when the connection is down; the agent does not queue them.
- **Duplicates.** The engine tolerates duplicate and unknown-id `result` frames (it stores whatever it receives).
- **No older lifecycle command pending.** The engine guarantees that when it sends a command, no older lifecycle command for the same object (`run`, `rm`, `stop`, `rename`, `network_rm`, `volume_rm`) is still pending, which is what makes it safe for the agent to run READ and CONVERGE commands again after a restart ([6.3](#63-duplicate-ids-and-replay)). The engine records a second result for an id as `late` and the first result wins.

## 7. Reconnect, backoff and session reattach

### 7.1 Backoff and retry schedules

> **Since agent 0.4.0.** Agents up to and including 0.3.1 use the older behaviour described at the end of this subsection.

The agent loops forever until it is stopped. Every wait is **jittered** and nothing about retries is visible on the wire. The loop is:

1. Dial and run a session ([section 2](#2-transport-and-session)). It ends on a dial failure, a read error, a close frame or a dead link.
2. Classify the reason (table below).
3. If the session lasted **more than 60 s**, restart the normal schedule. If the engine sent `hello_ok` in this session, restart the auth schedule.
4. Log one line with the reason and the time of the next try (never a token), wait the delay, and dial again.

| Class | Triggers | Base delay | Wait |
|---|---|---|---|
| Normal | Network or TLS error, dial timeout, `404`, `426`, `4001`, `1003`, `1009`, a dead link, any other close | 1 s, doubling to a cap of 30 s (1, 2, 4, 8, 16, 30, 30...) | Equal jitter: a random value in **[base/2, base]** |
| Auth | HTTP `401` or `403` on the dial, close `4003`, close `4004` (`protocol_unsupported`, since agent 0.4.0) | 60 s, doubling to a cap of 10 min (60, 120, 240, 480, 600, 600...) | Equal jitter in **[base/2, base]**, so 30 s at the least and 10 min at the most |
| Replaced | Close `4000` | none | Uniform random **30 to 90 s**, no doubling |

- The three schedules are independent. A normal failure does not advance the auth schedule and the other way round.
- A **successful `hello_ok` restarts the auth schedule** at 60 s. It does **not** restart the normal schedule, so an engine that accepts the connection and drops it again is still backed off; only a session longer than 60 s does that.
- The agent **never stops** on an auth failure. A server whose token was revoked keeps trying slowly, which costs the engine at most one rejected upgrade per delay, and it recovers on its own after a re-join writes a new token (the token is re-read for every dial, [2.3](#23-dial)).
- **Logging is rate limited by construction:** one line per attempt, so at most one per delay. Auth lines name the reason (`401`, `403`, `4003` or `4004` and its reason string) and the next try time and ask for a new join token; `4000` lines say another agent may be using the same token. No token value is ever logged.
- The 20 s dial timeout is not part of the delay.

Two agents sharing one token still close each other with `4000`, but now only about every 30 to 90 s each, at random times, instead of in a tight loop.

*Before agent 0.4.0* (agents up to 0.3.1) the loop doubled a delay from 1 s to a 30 s cap with **no jitter**, reset it after a session over 60 s, and treated `401` and `4003` like any other failure.

### 7.2 What survives a reconnect

| State | After reconnect |
|---|---|
| Finished command results | In `done.json`; re-sent on a duplicate `cmd`. |
| Running commands | Keep running; `ack` and `result` frames written while disconnected are lost, and the result is recovered from the cache on the engine's re-send. |
| Streams, console output, database socket output | Lost for the disconnected period; not re-sent. Console and database sockets stay open on the agent until they end on their own. |
| Heartbeat access rows | Dropped with the beat. |
| Engine state | The engine re-sends pending commands and re-pushes routes and registry credentials. |

### 7.3 There is no WebSocket session resume

The protocol has no session id, no sequence numbers and no resume handshake. Each connection is a fresh session for the engine, which closes the previous one for the same server with `4000`.
**Reattach** ([2.1](#21-enrolment-http-outside-the-websocket)) is a different thing: an HTTP call used when the engine has lost its record of the server. It does not reattach a WebSocket and does not replay anything.

## 8. Update and signature flow

This section describes release format 1 and the behaviour of **agent 0.4.0 and later**. Where a rule is about the engine ("the engine verifies...", the pin, the trust file) it is a specification for any engine that serves self-update, so that other engines can follow it. An agent older than 0.4.0 knows none of the new parts and ignores them: every new header line is a `#` comment to its parser, and the extra files are never looked up by it.

### 8.1 Release layout

A release (built by `scripts/release.sh`, published as GitHub release assets) consists of **15 files**; an engine that pins a release pins exactly these names ([`release.json`](protocol/schemas/release.json)). Releases up to 0.3.1 have the first 13 (format 0, "legacy"); `SHA256SUMS.sigs` and `release-keys.json` are new.

| File | Content |
|---|---|
| `f2c-agent-linux-amd64`, `f2c-agent-linux-arm64` | The static agent binaries, built with `CGO_ENABLED=0 -trimpath`, version stamped by `-ldflags`. |
| `install.sh`, `harden.sh`, `f2c-agent.service`, `f2c-harden.path`, `f2c-harden.service`, `f2c-caddy-dns-env.path`, `f2c-caddy-dns-env.service`, `caddy-resume.conf` | Install and deploy files, copied flat from `deploy/`. |
| `version.json` | Manifest: `name`, `version`, `builtAt`, `artifacts[]` (the two binaries with `goos`, `goarch`, `sha256`, `size`), `files[]` (the eight deploy files and `release-keys.json`), `sumsFile`, `signatureFile`, `signaturesFile`, `keysSerial`, and optionally `floor` and `caddy` (`{tag, sha256{amd64, arm64}}`). **Written first and listed in `SHA256SUMS`, so the signature covers it.** It therefore names the signature files but cannot hold their hashes. |
| `release-keys.json` | A copy of `keys/release-keys.json`, the trusted key list ([8.2](#82-signing-and-the-trusted-key-list)). Listed in `SHA256SUMS`. |
| `SHA256SUMS` | The one signed file: a `# ` header, then `sha256sum`-format lines (hash, two spaces, file name) for the 8 deploy files, the 2 binaries, `version.json`, `release-keys.json` and the Caddy hashes (below). Not itself, not the signatures. |
| `SHA256SUMS.sig` | The raw **64-byte ed25519 signature** of the exact bytes of `SHA256SUMS`. Unchanged; verifiers older than key ids use only this. |
| `SHA256SUMS.sigs` | JSON list of signatures by key id ([`sumsSigs`](protocol/schemas/release.json#/$defs/sumsSigs)): `{v: 1, signatures: [{keyId, alg: "ed25519", sig: <base64 of the 64 bytes>}]}`. |

**The `SHA256SUMS` header.** Every header line starts with `# ` (so every shipped parser, which skips `#` lines and looks files up by name, ignores it) and is covered by the signature. A known key may appear once; unknown keys and free comments are ignored. `release.sh` writes them first, in this order:

| Line | Meaning |
|---|---|
| `# f2c-release 1` | Format major. A major the reader does not know is an error (`integrity_failed`). |
| `# version <semver>+<YYYYMMDDHHMM>` | The release version, with the 12-digit UTC build stamp. The signed source of truth for the update guard ([8.4](#84-self-update-and-rollback)). |
| `# released <RFC 3339>` | Build time. |
| `# caddy-tag <tag>` | The f2c Caddy release `install.sh` installs. |
| `# keys-serial <n>` | Serial of the `release-keys.json` shipped in this release. |
| `# floor <semver>` | Optional. No agent may be moved below it, even by rollback; set only deliberately, because it can never be lowered by a rollback. |

**Caddy is hash-only.** The Caddy binaries are not assets of the agent release (the `caddy-binaries.yml` workflow publishes them as a separate release). `SHA256SUMS` lists `caddy-linux-amd64` and `caddy-linux-arm64` with their hashes (from `release.sh --caddy-dir`), so the engine's served Caddy and the one `install.sh` downloads are checked against a signed value. `release.sh` fails if a line of `SHA256SUMS` is neither a `#` comment nor `<hash>  <name>`.

Schemas: [`versionJson`](protocol/schemas/release.json#/$defs/versionJson), [`agentReleasePin`](protocol/schemas/release.json#/$defs/agentReleasePin).

<!-- example: release.json versionJson -->
```json
{
  "name": "f2c-agent",
  "version": "0.4.0+202611190506",
  "builtAt": "2026-11-19T05:06:14Z",
  "artifacts": [
    {"name": "f2c-agent-linux-amd64", "goos": "linux", "goarch": "amd64", "sha256": "0000000000000000000000000000000000000000000000000000000000000000", "size": 8868000},
    {"name": "f2c-agent-linux-arm64", "goos": "linux", "goarch": "arm64", "sha256": "1111111111111111111111111111111111111111111111111111111111111111", "size": 8192160}
  ],
  "files": [
    {"name": "install.sh", "sha256": "2222222222222222222222222222222222222222222222222222222222222222", "size": 100},
    {"name": "harden.sh", "sha256": "2222222222222222222222222222222222222222222222222222222222222222", "size": 100},
    {"name": "f2c-agent.service", "sha256": "2222222222222222222222222222222222222222222222222222222222222222", "size": 100},
    {"name": "f2c-harden.path", "sha256": "2222222222222222222222222222222222222222222222222222222222222222", "size": 100},
    {"name": "f2c-harden.service", "sha256": "2222222222222222222222222222222222222222222222222222222222222222", "size": 100},
    {"name": "f2c-caddy-dns-env.path", "sha256": "2222222222222222222222222222222222222222222222222222222222222222", "size": 100},
    {"name": "f2c-caddy-dns-env.service", "sha256": "2222222222222222222222222222222222222222222222222222222222222222", "size": 100},
    {"name": "caddy-resume.conf", "sha256": "2222222222222222222222222222222222222222222222222222222222222222", "size": 100},
    {"name": "release-keys.json", "sha256": "2222222222222222222222222222222222222222222222222222222222222222", "size": 100}
  ],
  "sumsFile": "SHA256SUMS",
  "signatureFile": "SHA256SUMS.sig",
  "signaturesFile": "SHA256SUMS.sigs",
  "keysSerial": 2,
  "caddy": {"tag": "caddy-v2.11.7-do1-cf1-ad1", "sha256": {"amd64": "4444444444444444444444444444444444444444444444444444444444444444", "arm64": "5555555555555555555555555555555555555555555555555555555555555555"}}
}
```

A matching `SHA256SUMS` starts like this (placeholder hashes):

```text
# f2c-release 1
# version 0.4.0+202611190506
# released 2026-11-19T05:06:14Z
# caddy-tag caddy-v2.11.7-do1-cf1-ad1
# keys-serial 2
2222222222222222222222222222222222222222222222222222222222222222  install.sh
...
4444444444444444444444444444444444444444444444444444444444444444  caddy-linux-amd64
```

### 8.2 Signing and the trusted key list

- Algorithm: **Ed25519** (raw 32-byte public keys, raw 64-byte signatures). The signature covers the exact bytes of `SHA256SUMS` (no hash-of-hash, no context string).
- **One source of keys: `keys/release-keys.json`** ([`releaseKeys`](protocol/schemas/release.json#/$defs/releaseKeys)), public keys only. The agent embeds it (`keys/` Go package; `internal/update` derives its list from it), `install.sh` carries a block **generated** from it (`go run ./cmd/ed25519tool sync-install`), and an engine keeps its own trust file with the same data ([8.3](#83-what-an-engine-pins-and-serves)). `release.sh` and a Go test (`keys` package) fail if the `install.sh` block differs from the file.
- **Key id** = the first 8 bytes of the SHA-256 of the raw 32-byte public key, as 16 lowercase hex characters. It is only a selector for `SHA256SUMS.sigs`: the signature is always verified against the key the id names, so a wrong id never lets a bad signature through. Each key has a `status`:
  `active` (verifies, and `release.sh` may sign with it), `retired` (verifies only, so older releases stay installable) or `revoked` (never verifies; it stays listed so a signature by it is refused by name).
- **Accepting a signature.** If the release has `SHA256SUMS.sigs`, the agent verifies each entry under the key its `keyId` names; unknown ids are skipped, a revoked id is refused with a message, and **one valid signature by a trusted key is enough**. If `.sigs` is absent or yields nothing, the agent falls back to the raw `SHA256SUMS.sig` and tries **every trusted key** (so releases signed before key ids still verify). The list is deliberately not read from disk or from the engine, and a signature by a key that is revoked in the agent's list is refused even if the signature is valid.
- **Rotation.** Release N is signed by the old key and ships a list that trusts both. Release N+1 is signed by the new key, once the fleet is at N. A later release revokes the old key. An engine should block the cutover release while a server is below the previous release. Revoking a key is described in the next two bullets. No 2-of-N for now: `SHA256SUMS.sigs` is a list, so a `threshold` can be added later without a format break.
- **Revoking a key (normal path).** Ship a release with a **higher `serial`** in which the key is `revoked`, signed by a key that is still trusted and not compromised, and apply it on the engine (an engine should offer a command that takes the `release-keys.json` of a release). The engine takes the new list only because that release verifies under its *current* trust file; it drops the revoked key the moment the list is applied (no fleet wait) and refuses any pin signed only by it. **The engine trust file is never edited by hand**, not even in an emergency: a hand edit would bypass the one rule that makes the file trustworthy.
- **Revoking a key.** If **no uncompromised active key exists**, the normal path (a release signed by an uncompromised key, with a higher `serial`) cannot work: a compromised key cannot sign a trustworthy revocation of itself. Engines should provide an **audited, revoke-only emergency procedure**: it only marks a key `revoked` (the entry stays in the list, so a later release cannot bring the key back), never adds, trusts or un-revokes a key, refuses to leave the engine with no active key unless that is explicit, records every run, and takes effect when the engine next loads its trust file. Adding a new key is never part of it.
- **Recovery when no trusted key is left.** Recovery of trust is **manual and out-of-band**: the new key reaches an engine only through a reviewed change of its trust file, not through a release or a running engine. A fresh release signed by the new key follows, and the engine then serves it under the new trust file.
- **Backup key.** The release signing key is held offline by the maintainers, and a backup signing key, also listed as `active`, is held separately, so that a single revoke never leaves zero active keys and the normal path above stays available.
- **Fleet recovery after a revoke.** Agents and `install.sh` trust a key only if an **agent build embeds it** (`keys/release-keys.json`, the generated `install.sh` block). An agent whose build lacks the new key cannot verify a release signed only by it, and an agent that still trusts the compromised key only fetches through the engine, which has stopped serving anything signed by it. Servers that trust no key therefore get the new key by **reinstalling with `install.sh`** from a release built with the new key list (`install.sh` downloads from the GitHub release and verifies it against its embedded keys); it **never happens through `self_update`**, which cannot verify a release it has no key for.
- **Who may change the list.** An engine's trust file should change **only through a signed release**: the `release-keys.json` of a release is applied only if the release's signature verifies under the *current* trust file and its `serial` is higher. Nothing else writes it.
- **Where the private key lives.** `scripts/release.sh` signs with a key **outside the repository** (its path is given by `F2C_RELEASE_SIGNING_KEY`) through `cmd/ed25519tool sign-release`. The release signing key is held offline by the maintainers, and a backup key is held separately. `sign-release` refuses a key that is not listed as `active`. The private key is never in the repository, and no release tool in the repository generates one. If no key is found, `release.sh` fails; only `--no-sign` builds a release without signatures, and such a release will not install or update.
- **Key fingerprints.** The key ids and fingerprints are published in the README and in the release notes of the first signed release. `install.sh --print-keys` prints the key serial and each key's id and status for comparison; it is not advertised.

<!-- example: release.json releaseKeys -->
```json
{
  "v": 1,
  "serial": 1,
  "keys": [
    {"id": "0123456789abcdef", "alg": "ed25519", "pub": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "status": "active", "added": "2026-11-18", "note": "example key"}
  ]
}
```

<!-- example: release.json sumsSigs -->
```json
{
  "v": 1,
  "signatures": [
    {"keyId": "0123456789abcdef", "alg": "ed25519", "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}
  ]
}
```

### 8.3 What an engine pins and serves

This section specifies what an engine that serves self-update should do; the agent does not read the pin. The engine and a format 2 pin should be released and rolled back together.

- An engine pins one release. The pin is an engine-defined record; the example below shows a suitable shape: `repo`, `tag`, `version` and, for each file, `sha256` and `size`. **Format 1** (no `format` field): exactly 13 files. **Format 2** adds `"format": 2`, the files `SHA256SUMS.sigs` and `release-keys.json` (15 in all), `caddy` (`{amd64, arm64}`, each `{sha256, size}`, hash-only), `keys` (`{serial, sha256}` of the release's `release-keys.json`), and optionally `supersedes` (the previous pin version, the authoritative chain) and `rollback` (`{reason, at}`).
- An engine should not download anything at run time: an operator tool fetches a release, verifies it with the same function the engine runs at start-up, and writes the pin. At start-up, and again periodically while it is failing, the engine verifies its assets. For format 2 the checks are:
  1. the pin shape; 2. each file exists with the pinned size and SHA-256; 3. the signature (`.sigs` by key id, else the legacy `.sig`; the key must be active or retired in the trust file, a revoked key fails);
  4. the signed `SHA256SUMS` lists the pinned hash for every file including `version.json` and `release-keys.json`; 5. the signed header: `# version` equals `pin.version` and `version.json`'s version, the format major is known, `# keys-serial` is not above the trust file's unless the release's own keys file verifies;
  6. `version.json` is consistent with the pin and the signed sums; 7. **monotonic**: `pin.version` is not below the high-water mark (the highest version the engine has verified, persisted after each successful verify; the shared compare of [8.4](#84-self-update-and-rollback), the build stamp breaking ties) unless the pin has `rollback` with a reason and `supersedes` equals the high-water mark; 8. the served Caddy binaries' sha256 equals `pin.caddy[arch]` and the signed `caddy-linux-<arch>` line (failure takes down only the Caddy routes); 9. `pin.version` is not below a signed `# floor`, with or without `rollback`.
  Any failure of 1 to 7 or 9 means the engine **refuses to serve** (HTTP 503 on every `/agent/*` route). **Format 1 pins** run only the old checks (1 to 3 and the old name check), plus a one-time log that the release is legacy.
- Public, unauthenticated GET routes an engine serves for self-update: `/agent/bin/<amd64|arm64>` (the binary), `/agent/bin/<arch>.sha256`, `/agent/bin/SHA256SUMS`, `/agent/bin/SHA256SUMS.sig`, `/agent/bin/SHA256SUMS.sigs`, `/agent/bin/version.json` and `/agent/bin/release-keys.json`. Older engines also serve `/agent/install.sh`, `/agent/files/<deploy file>` and `/agent/bin/caddy-<arch>[.sha256]`; the standalone `install.sh` ([8.5](#85-installsh)) does not use them.
  The engine advertises the latest agent hash for an architecture from the pin; the engine compares it with `hb.agentHash` to tell whether an update is available. `hello_ok.minAgent` may come from `pin.version`. The engine sends `version`, `rollback` and `reason` in `self_update` only to agents that report `hb.updateV` at protocol >= 1.

<!-- example: release.json agentReleasePin -->
```json
{
  "repo": "example-org/f2c-agent",
  "tag": "v0.3.1",
  "version": "0.3.1+202611181227",
  "files": {
    "SHA256SUMS": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "SHA256SUMS.sig": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 64},
    "version.json": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "f2c-agent-linux-amd64": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "f2c-agent-linux-arm64": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "install.sh": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "harden.sh": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "f2c-agent.service": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "f2c-harden.path": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "f2c-harden.service": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "f2c-caddy-dns-env.path": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "f2c-caddy-dns-env.service": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "caddy-resume.conf": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100}
  }
}
```

A format 2 pin (same file names plus the new ones):

<!-- example: release.json agentReleasePin -->
```json
{
  "repo": "example-org/f2c-agent",
  "tag": "v0.4.0",
  "version": "0.4.0+202611190506",
  "format": 2,
  "files": {
    "SHA256SUMS": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "SHA256SUMS.sig": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 64},
    "SHA256SUMS.sigs": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 200},
    "version.json": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "release-keys.json": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "f2c-agent-linux-amd64": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "f2c-agent-linux-arm64": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "install.sh": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "harden.sh": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "f2c-agent.service": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "f2c-harden.path": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "f2c-harden.service": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "f2c-caddy-dns-env.path": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "f2c-caddy-dns-env.service": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100},
    "caddy-resume.conf": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "size": 100}
  },
  "caddy": {"amd64": {"sha256": "4444444444444444444444444444444444444444444444444444444444444444", "size": 100}, "arm64": {"sha256": "5555555555555555555555555555555555555555555555555555555555555555", "size": 100}},
  "keys": {"serial": 2, "sha256": "6666666666666666666666666666666666666666666666666666666666666666"},
  "supersedes": "0.3.1+202611181227"
}
```

### 8.4 Self-update and rollback

Trigger: the engine sends `self_update {sha256, version?, rollback?, reason?}` where `sha256` is the pinned hash for the agent's architecture. `version`, `rollback` and `reason` are **read only at protocol >= 1** (the engine sends them only to agents that report `hb.updateV`); at protocol 0 they are ignored, and the guard below still refuses a downgrade, so an engine that predates them can never roll an agent back. The agent:

**Engine refusal without an agent version.** An engine may answer `409` to a `self_update` request for a server that has not reported an `agentVersion` (it treats an unknown version as a possible downgrade, so only a pin with `rollback` gets through). The agent always sends `hb.agentVersion` (the agent's build version), so this only affects a server that has not sent its first heartbeat; a development build sends `0.1.0-dev`, which compares below `0.1.0`.

1. Returns `{upToDate:true}` if its own executable hash already equals `sha256`. Fails with `bad_request` if `rollback` is set without a `reason` of 1 to 200 characters, and with `conflict` if an update marker already exists.
2. Downloads `<engine>/agent/bin/SHA256SUMS` (at most 1 MiB) and verifies its signature as in [8.2](#82-signing-and-the-trusted-key-list): `SHA256SUMS.sigs` by key id when the engine serves it, else the raw `SHA256SUMS.sig` (at most 4096 bytes, exactly 64) under every trusted key. Failure aborts with `integrity_failed` (`release signature: ...`). The header is parsed from the verified bytes.
3. Looks up `f2c-agent-linux-<arch>` in the signed sums; the value MUST equal the `sha256` the engine asked for. If the engine sent `version` it MUST equal the signed `# version` (`integrity_failed` otherwise). A signed `# floor` above the release's own version is `integrity_failed`.
4. **Runs the guard** (below) with the running version, the signed version, the persisted floor and `rollback`.
5. Fetches `<engine>/agent/bin/<arch>.sha256` and requires the same value (so an engine that changed its pin mid-update is detected).
6. Downloads `<engine>/agent/bin/<arch>` (at most 256 MiB) to `<exe>.new`, hashing while it streams, and requires the hash to match.
7. Runs the new binary with `version` as a smoke test (10 s timeout). When the release has a signed version, the output MUST equal it (`integrity_failed` otherwise), so a binary cannot report a different version than the one that was signed.
8. Copies the current binary to `<exe>.prev`, atomically renames the new one over `<exe>`, writes the update marker `update-pending.json` (`{id, oldHash, newHash, exe, boots, at}` plus `fromVersion`, `toVersion`, `floor`, `rollback`, `reason` when known) into the state dir, replies `{restarting:true, from, to}` (at protocol >= 1 also `fromVersion`, `toVersion`, `rollback`), and exits (status 0) 3 s later. systemd restarts it (`Restart=always`).

**The guard.** Let `cur` be the running version and `tgt` the signed `# version` of the target. Versions compare by semver precedence (build metadata ignored); at equal precedence the 12-digit build stamps compare numerically (`CompareBuild`). The decision order is shared with any engine implementation by the test vectors [`testdata/version-compare.json`](protocol/testdata/version-compare.json) (28 cases; an engine's implementation must pass them):

| # | Condition | Decision | Result |
|---|---|---|---|
| 1 | the target hash equals the running binary | up to date | `{upToDate:true}` |
| 2 | a floor is persisted and `tgt` is below it, or the release has no parseable signed version (while a floor exists) | refuse, **even with `rollback`** | `not_allowed` |
| 3 | `tgt` has higher precedence than `cur` | allow | |
| 4 | equal precedence and the target's build stamp is newer | allow | |
| 5 | equal precedence, the **same** stamp, different bytes | refuse | `integrity_failed` |
| 6 | everything else: a lower version, an older or unordered build (one stamp missing), a missing or unparseable signed version | refuse **unless** `rollback:true` with a reason (then allow, and log it) | `not_allowed` |

A release **without** a signed header (every release up to 0.3.1) is therefore "missing version": an agent at 0.4.0 or later refuses to be moved onto one unless `rollback` is set; the move from 0.3.x to a headered release is unaffected because the guard looks at the target.

**The floor** is persisted in `update-floor.json` in the state dir (`{floor, setBy, at}`, 0600). A release may carry a signed `# floor X`; **only after the update to that release is proven** (the new binary connected: the point where the marker is removed) is the floor raised to `max(floor, X)`. It never goes down; `rollback` cannot lower it, and the engine cannot touch it. A re-install with `install.sh` plus deleting the file (root only) is the way out of a floor set by mistake. At start-up the agent logs a warning if its own version is below the floor; it does not exit.

On start-up the agent reads the marker and does one of:

| Situation | Action | Recorded `update.status` |
|---|---|---|
| Running the new hash, fewer than 3 boots | Increment `boots`; wait for `hello_ok`. If it arrives, the update is proven (the floor is raised) and the marker removed. If **60 s** pass first (counted from process start), restore `.prev` and exit 1. | `succeeded`, or `rolled_back` |
| Running the new hash with 3 boots used | Restore `.prev`, exit 1. | `rolled_back` |
| Running the old hash | A rollback already happened (or the swap never did). | `rolled_back` |
| Running neither | Give up on the marker. | `failed` |
| Restoring `.prev` fails | Keep running the new binary. | `failed` |

The outcome is stored in `update-result.json` and shown in `hb.update` ([4.3](#43-hb-heartbeat)), with `fromVersion`, `toVersion`, `rollback` and `reason` for an update that carried them.

### 8.5 `install.sh`

`install.sh` is itself a release file. It needs no engine: it is downloaded from the GitHub release of this repository (`releases/latest/download/install.sh`, or `releases/download/v<X.Y.Z>/install.sh`) and fetches the other files from the same release directory (`F2C_RELEASE_BASE` selects another base with the same layout, `--version` or `F2C_VERSION` a pinned release). It then:

1. downloads `SHA256SUMS` and verifies its signature: `SHA256SUMS.sigs` by key id (from the generated key block), else the raw `SHA256SUMS.sig` against every trusted key, with `openssl pkeyutl -verify -pubin -rawin` (OpenSSL 3 with Ed25519 support is required). A bad signature, or a signature by a revoked key, aborts the install, and so does a release whose `SHA256SUMS` cannot be downloaded: nothing is installed unverified, except an explicit local binary given with `F2C_AGENT_BIN`;
2. downloads `f2c-agent-linux-<arch>` and requires the signed `SHA256SUMS` to list the same hash for it;
3. checks every **support file** it downloads (`harden.sh`, the units, `caddy-resume.conf`) and the **Caddy binary** (the `caddy-linux-<arch>` hash) against the signed `SHA256SUMS`. **A mismatch is always fatal.** A file the signed sums do not list is fatal for a release with the `# f2c-release` header or with `F2C_REQUIRE_SIGNED=1`, and otherwise (a legacy release) a warning.

Only then does it install the binary and the units. The service is enabled and started only once the agent has joined: with `--engine URL --token f2cj_...` the installer runs `f2c-agent join` as the unprivileged `f2c-agent` user and enables the service; without them it leaves the unit disabled, and the unit's `ConditionPathExists=/var/lib/f2c-agent/agent.json` keeps it from starting (and crash-looping) before a join. The operator joins later with `f2c-agent join` and `systemctl enable --now f2c-agent`. The join is the HTTP enrolment of [2.1](#21-enrolment-http-outside-the-websocket) and uses the system CA roots: https is required for any engine that is not on loopback. It also installs Docker, Caddy and the builders unless told not to. Files next to the script (only when `install.sh` sits beside them: a repository checkout or an unpacked release) are not checked. `install.sh --print-keys` prints the key serial and the id and status of each trusted key. There is no `--allow-downgrade` for a re-run over a newer install (the update guard of 8.4 covers `self_update`; `install.sh` does not compare versions).


## 9. Compatibility rules

### 9.1 In force today

1. **Receivers ignore unknown fields** in frames, `args` and `data`. This holds for the agent's decoding of every frame, and for the engine's handling of agent frames. Exception: `run` rejects unknown `args` keys.
2. **Receivers ignore unknown frame types** (`t`) and non-JSON text. The agent and the engine both do this silently.
3. **Unknown command types** are answered with `unknown_command` (protocol 0) or `unknown_cmd` (protocol >= 1), with the same error text.
4. **Wrong-typed known fields** drop the whole frame on the agent (no reply); do not rely on it.
5. **Capability flags** missing from `hb` mean the feature is unavailable. An engine MUST NOT send a feature to an agent that did not announce it (the engine gates `composeV` and `dockerBuildV`).
6. New optional `data` fields in results are safe because the engine reads only the fields it knows.

### 9.2 Additive-only rule (policy)

Protocol 1 MUST only change additively: new optional fields, new frame types, new command types with a capability flag, new `code` values, and new optional fields in results. A removal, rename, retyping or change in meaning of an existing field, frame type, command, code or enumeration value is a protocol 2 change.
A sender that adds a new `code` MUST keep the existing error text stable for as long as an engine that matches on text is supported.

### 9.3 Deprecation policy (Proposal, not in force)

This is a suggestion:

- A deprecated item is announced in the changelog with a minimum notice of two agent releases.
- The sender keeps accepting and producing the deprecated form until the oldest agent the engine still supports has stopped using it.
- A deprecated item is removed only in a new major protocol version, which needs the negotiation described in [3.2](#32-negotiation) (since agent 0.4.0).

## 10. Security considerations

- **Trust boundary.** The engine is fully trusted by the agent. The command set is effectively root-equivalent on the server: `caddy_apply` takes an arbitrary Caddy JSON configuration (it can proxy to any local service or serve files), `exec` runs any command in a managed container, `harden` changes host SSH and firewall settings,
  and `self_update` replaces the agent binary. Anyone who can send commands as the engine owns the server. The agent narrows only what it can: managed-label scoping for container operations, `f2c-*` names for networks and volumes, a default-deny `run`, no privileged containers, bind mounts or host namespaces, and `cap-drop ALL` for stack containers.
- **Authentication.** One long-lived bearer token (`f2cs_`) over TLS. It is read from `agent.json` (0600, owned by the agent user), sent only in the `Authorization` header, and never logged. Tokens can be rotated live ([4.5](#45-secret-bearing-live-frames)); the engine can revoke with close `4003`. Join tokens are one-time. There is no mutual TLS, no certificate pinning and no request signing.
- **Transport.** TLS is required beyond loopback (an `https` engine, or `wss`). There is no application-layer encryption or signing of frames, so integrity depends entirely on TLS; a TLS-terminating proxy in front of the engine sees all traffic including secrets.
- **Secrets in frames.** `rotate_token`, `registry_login` and `dns_token` are live-only, never queued, never stored in `done.json`, and never logged. `cert_install` (private key) and `build`/`load` (one-time download tokens) are ordinary commands, so the engine stores their arguments until they finish (up to 24 hours) and may re-send them. The agent's `done.json` holds results only, and the build log masks the token and secret-looking env values.
- **Replay and staleness.** The only replay defence is id de-duplication (500 results). `notAfter` limits how stale a command may be when it arrives, if the engine sets it ([6.4](#64-notafter-and-skew)).
- **Local services.** The TLS ask endpoint (`127.0.0.1:9180`), the access-log listener (`127.0.0.1:9181`) and the Caddy admin API are loopback only; the agent refuses a non-loopback listen address for the ask endpoint. Containers are published on `127.0.0.1` only.
- **Release integrity.** Ed25519 over `SHA256SUMS`, which now also lists `version.json`, `release-keys.json` and the Caddy hashes and carries a signed header (version, build time, Caddy tag, key serial, optional floor); one key list (`keys/release-keys.json`) with key ids, retirement and revocation; signature verification in `self_update`, `install.sh` and the engine; a downgrade and floor guard in the agent; and a hash pin in the engine ([section 8](#8-update-and-signature-flow)). Remaining gaps: the release signing key is a file held by the maintainers (a hardware key is not used), and an agent below 0.4.0 does not check headers or the floor. A compromised engine can still ask for `rollback`; only the signed floor, which the engine cannot lower, limits it.
- **Denial of service.** Frame size is capped at 16 MiB; parallel commands are not capped; the engine closes idle connections after 60 s. A flood of `cmd` frames can start unlimited goroutines; the engine is trusted not to do that.
- **Privacy.** Console keystrokes and output, database socket data and secrets are never logged by the agent.

## 11. Known limitations and design notes

What the code does today where a receiver could be surprised, or where behaviour is left undefined. Each note says whether changing it would be a **wire change** (a change to frames, headers or close codes).

1. **Unknown-argument policy differs.** `run` rejects unknown keys (default-deny), every other command ignores them. An engine that adds a `run` option for a newer agent gets a hard error from an older one unless it checks a capability flag. *Wire change: no (policy).*
2. **Malformed frames get no reply.** A `cmd` with an empty `id`, or any frame whose known field has the wrong JSON type (for example `args` as an array, `cols` as a string), is dropped silently, so the engine only sees a timeout. A negative acknowledgement would need a new code or frame. *Wire change: yes (additive).*
3. **Result `error` truncation and size.** Documented in [5.4](#54-size-and-truncation-limits-as-implemented). The agent sends the full text, an engine may keep less, `data` is limited only by the 16 MiB frame, and a result over 256 KiB is replayed as a stub. Known nit: the stub cuts `error` at 4000 bytes, which can split a UTF-8 character. *Wire change: no.*
4. **Cancellation has no acknowledgement.** A cancelled command ends with a failure that is cached and replayed for the same id. At protocol >= 1 it carries `code: "cancelled"` (and a deadline carries `timeout`); `harden` keeps `harden_interrupted` at every protocol. There is no acknowledgement of the cancel itself. *Wire change: an ack would be new.*
5. **The dedupe cache is bounded.** `done.json` holds at most 500 results and drops entries older than 25 h ([6.3](#63-duplicate-ids-and-replay)). An id evicted from the cache and re-sent runs again, so an engine should issue unique ids. *Wire change: no.*
6. **No session semantics for streams, console and database sockets.** These frames are lost while disconnected and never re-sent, `hello_ok` does not say whether the session is new, and an open console or socket on the agent is orphaned when the WebSocket drops. They are live-only by design and end at their own deadline ([4.7](#47-console-session), [4.8](#48-managed-database-channel), [7.2](#72-what-survives-a-reconnect)). *Wire change: yes.*
7. **Reply naming is inconsistent.** `registry_login` is used for both the request and the reply, while the others are `token_rotated` and `dns_token_ok`. The names are kept for compatibility and documented in [4.5](#45-secret-bearing-live-frames). *Wire change: yes.*
8. **The self-update window starts at process start.** The 60 s connect window and the 3-boot limit are measured from agent start, so a slow engine start can cause a rollback of a good binary. *Wire change: no.*
9. **Command id format is only enforced by the engine** (an engine may require `^[A-Za-z0-9_.:-]{1,80}$`); the agent accepts any non-empty string. *Wire change: no.*
10. **`hb.containers` is `null` when `docker ps` fails** instead of an empty list, and `stats` omits zero `restarts` and `exitCode`, so "absent" and "0" cannot be told apart. *Wire change: no (agent behaviour).*
11. **`volume_backup_offsite_restore` is not implemented by the agent.** An engine may send it ([4.8](#48-managed-database-channel)); the agent answers `db_result {ok:false, code:"invalid_input", status:400}` at every protocol. A restore into an existing volume is destructive and needs its own rules before the operation is specified. *Wire change: yes (a new operation, additive).*
12. **Harden replay marker.** A repeated `runId` gets the recorded outcome with `data.replayed:true`; this is not the frame-level `replayed` of a re-sent command id ([6.3](#63-duplicate-ids-and-replay)), and an engine that only reads the frame-level marker handles such an answer like a fresh one. *Wire change: no.*
13. **`install.sh` has no downgrade check.** The update guard of [8.4](#84-self-update-and-rollback) covers `self_update` only; re-running `install.sh` over a newer install does not compare versions (there is no `--allow-downgrade`).

Documentation nits, not protocol issues: the console container-name pattern differs from the run name pattern (upper case, 128 characters); `buildPack: "nixpacks"` selects the railpack builder.

## Appendix A: Schema index

All files are JSON Schema draft 2020-12, with `examples` on the definitions. Relative `$ref`s resolve against each file's `$id`.

| File | Contents |
|---|---|
| [`protocol/schemas/common.json`](protocol/schemas/common.json) | Shared string patterns, result codes. |
| [`protocol/schemas/frames.json`](protocol/schemas/frames.json) | Every WebSocket frame; unions `engineToAgent` and `agentToEngine`. |
| [`protocol/schemas/database.json`](protocol/schemas/database.json) | `<operation>.args` and `<operation>.result` of the 16 managed-database operations, `errorCode`, `backupKey`, `backup`. |
| [`protocol/schemas/commands.json`](protocol/schemas/commands.json) | `<type>.args` and `<type>.result` for the 21 commands; `commandType`. |
| [`protocol/schemas/http.json`](protocol/schemas/http.json) | `join` and `reattach` bodies. |
| [`protocol/schemas/release.json`](protocol/schemas/release.json) | `version.json`, an example engine pin record, `release-keys.json` and `SHA256SUMS.sigs`. |
| [`protocol/testdata/version-compare.json`](protocol/testdata/version-compare.json) | The 28 shared test vectors of the update guard (version and build comparison, decision order). An engine's implementation must pass the same file. |

## Appendix B: Files the agent reads and writes for the protocol

| Path (under the state dir unless absolute) | Purpose | Mode |
|---|---|---|
| `agent.json` | `{engine, serverId, token}` | 0600 |
| `done.json` | Finished command results: 500 entries, 8 MiB, 25 h (6.3) | 0600 |
| `ask-hosts.json` | TLS ask allow-list from `caddy_apply.hosts` | 0600 |
| `dns-token.json` | DNS API token from `dns_token` | 0600 |
| `docker/config.json` | Registry credentials from `registry_login` | 0600 |
| `harden/runs.json`, `harden/request`, `harden/link-proof` | Harden bookkeeping | 0600 |
| `running.json` | Commands in flight (id, type, hash of args; no args), see 6.3 | 0600 |
| `update-pending.json`, `update-result.json` | Self-update marker and last outcome (with `fromVersion`, `toVersion`, `floor`, `rollback`, `reason` when known) | 0600 |
| `update-floor.json` | `{floor, setBy, at}`: the signed floor, raised only after a proven update, never lowered (8.4) | 0600 |
| `certs/` | Certificates from `cert_install` (key 0600) | dir 0700 |
| `databases/<org>/<name>/database.json` | Pinned database identity, next backup time, last backup result, deleted flag (4.8) | 0600 |
| `databases/<org>/<name>/delete-authorized.json` | Manifest written before a `delete` removes anything (4.8) | 0600 |
| `databases/<org>/<name>/backups/` | Dumps `<key>`, records `<key>.json`, `.partial` and `.upload` files (4.8) | dir 0700, files 0600 |
| `database-owners/<container>.json` | Owner pin of a database container (4.8) | 0600 |
| `<exe>.prev`, `<exe>.new` | Self-update binaries | 0755 |
