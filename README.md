# miuturn

A high-performance TURN server written in Rust.

![Admin Console](admin.png)

## Features

- **STUN/TURN Protocol Support**: RFC 5389/5766 compliant
- **Web Admin Console**: Built-in HTTP admin UI with real-time metrics dashboard
- **TURN REST API**: WebRTC credential generation with HMAC authentication
- **Shared-Secret Auth**: coturn-style ephemeral credentials (`expiry:user` + HMAC-SHA1), validated on the TURN port itself
- **User Management**: Fixed, temporary, and API key users with per-user limits
- **ACL Rules**: IP-based access control with priority ordering
- **Real-time Metrics**: Live throughput and active allocations charts
- **Config Persistence**: UI changes auto-save to TOML
- **Session Persistence Across Restarts**: allocations, channel bindings and nonces survive SIGTERM/SIGUSR2 restarts (`[persist]`)
- **Prometheus Metrics**: Built-in metrics export
- **TCP & UDP**: Dual protocol support

## Quick Start

### Binary

```bash
cargo build --release
./target/release/miuturn
```

### Docker

#### Using Pre-built Image (Recommended)

```bash
docker run -p 3478:3478 -p 3478:3478/udp -p 8080:8080 docker.cnb.cool/miuda.ai/miuturn:latest
```

#### Build from Source

```bash
docker build -t miuturn .
docker run -p 3478:3478 -p 3478:3478/udp -p 8080:8080 miuturn
```

## Configuration

Create `miuturn.toml`:

```toml
[server]
realm = "miuturn"
external_ip = "YOUR PUBLIC IP HERE"
relay_bind_ip = "0.0.0.0"
start_port = 49152
end_port = 65535
max_concurrent_allocations = 1000
max_bandwidth_bytes_per_sec = 10485760
max_allocation_duration_secs = 3600

[[server.listening]]
protocol = "udp"
address = "0.0.0.0:3478"

[[server.listening]]
protocol = "tcp"
address = "0.0.0.0:3478"

[http]
address = "0.0.0.0:8080"
# Admin console credentials (separate from TURN users)
admin_username = "admin"
admin_password = "changeme"
turn_rest_enabled = true
turn_rest_default_lifetime = 3600

[auth]
# Shared HMAC secret for ephemeral TURN credentials (see "Agent-issued tokens").
shared_secret = "your-secret-key"
# What happens when an established session outlives its token:
#   "renew"  - token only gates new Allocate requests (default)
#   "strict" - expired tokens are rejected on every request (coturn behavior)
#   "cap"    - allocation lifetime capped at the token expiry
expired_token_policy = "renew"

[[auth.users]]
username = "regular_user"
password = "userpass"
user_type = "fixed"
max_allocations = 5
bandwidth_limit = 1048576  # 1 MB/s limit
ip_whitelist = ["192.168.0.0/16"]

[[auth.users]]
username = "temp_user"
password = "temp123"
user_type = "temporary"
expires_at = 1735689600
max_allocations = 2

[auth.api_keys]
key1 = "admin"

[[auth.acl_rules]]
ip_range = "10.0.0.0/8"
action = "Allow"
priority = 10

[[auth.acl_rules]]
ip_range = "0.0.0.0/0"
action = "Deny"
priority = 1

# Optional: persist sessions across restarts (see "Persistence & Zero-Downtime
# Restarts"). In Docker the state directory MUST be a mounted volume.
# [persist]
# enabled = true
# path = "/var/lib/miuturn/state.json"
# checkpoint_interval_secs = 30
```

With `[auth].use_auth_secret = true` and a nonempty `[auth].secret`,
TURN protocol authentication uses only temporary credentials minted with that secret.
Stored user passwords are not accepted in this mode, including for usernames present
in `[[auth.users]]`. Set `use_auth_secret = false` or omit it to use stored-user authentication.
The optional `auth.lifetime` sets the credential manager's default generation lifetime
in seconds (3600 when omitted). Authentication checks the expiry embedded in the
provided username; this setting does not change credentials issued by RustPBX.
User/API management and ACL checks remain separate from this credential mode.
HTTP configuration is not required. The global password is used only by servers
without an auth manager.
The username is `<expiry Unix timestamp>:<user id>` and the password is the
standard padded Base64 encoding of `HMAC-SHA1(secret, username)`, compatible with
coturn's TURN REST convention. Expired credentials are rejected. TURN authentication
reads these authentication settings at startup; changing them requires restarting miuturn.
The HTTP credential endpoint uses its own `[http].turn_rest_secret` setting. If
you use that endpoint to issue credentials for this server, configure both secrets
with the same value.

This replaces the previous hex output. Update credential issuers together with
miuturn and fetch fresh credentials; previously issued hex passwords no longer work.

For RustPBX, configure its browser `/iceservers` endpoint with:

```toml
[[ice_servers]]
urls = ["turn:turn.example.com:3478", "turn:turn.example.com:3478?transport=tcp"]
secrete = "your-secret-key" # same as miuturn's [auth].secret
username = "rustpbx"
lifetime = 3600
```

Only temporary credentials are returned to the browser. Keep the shared secret
on the servers and fetch fresh ICE configuration before the credentials expire.

`external_ip` is the relay address advertised back to clients.
`relay_bind_ip` is the local interface used to bind relay sockets. If omitted, it defaults to `0.0.0.0`. In NAT deployments, set `external_ip` to the public IP and keep `relay_bind_ip` as `0.0.0.0` (or a specific local interface IP if needed).

## Agent-Issued TURN Tokens (shared secret)

Typical WebRTC deployment: a JS client asks your **agent server** for a TURN
credential; only the agent server can mint valid ones, but **any client IP may
use the relay** with a minted credential.

miuturn supports this with coturn-style ephemeral credentials, and — unlike
minting over HTTP — the credentials are validated on the TURN port itself:

```
JS ──request──> agent server ──HMAC(secret)──> {username, credential}
JS ──TURN Allocate (any IP)──> miuturn:3478 ──verify HMAC──> relay
```

Configuration on the miuturn side:

```toml
[auth]
shared_secret = "same-secret-as-agent-server"
expired_token_policy = "renew"   # renew | strict | cap
```

- `username = "<unix-expiry-secs>:<user-id>"`
- `credential = hex(HMAC-SHA1(shared_secret, username))`

### Generating the shared secret

The secret must be **identical** on miuturn and the agent server, and long
enough to resist brute force (use ≥ 32 bytes of entropy; HMAC-SHA1 input can
be any length, but a short secret weakens the scheme). Generate it once and
distribute it out-of-band (config management / secret store — never commit it):

```bash
# OpenSSL (64 hex chars = 32 bytes of entropy)
openssl rand -hex 32

# Python
python3 -c "import secrets; print(secrets.token_hex(32))"

# Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Put the result in `miuturn.toml` and in the agent server's environment:

```toml
# miuturn.toml
[auth]
shared_secret = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
```

```bash
# agent server
export MIUTURN_SHARED_SECRET="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
```

Rotation: tokens are self-validating HMACs, so there is no server-side token
store to purge. To rotate, deploy the new secret to the agent server and
miuturn (order does not matter — tokens minted with the old secret simply
stop validating on Allocate; established sessions are governed by
`expired_token_policy`). For zero-downtime rotation, run a second miuturn
instance with the new secret, cut traffic over, then retire the old one.

### Minting credentials on the agent server

The agent server mints credentials locally (Node.js example):

```js
const crypto = require("crypto");

const SECRET = process.env.MIUTURN_SHARED_SECRET; // same secret as auth.shared_secret

function issueTurnCredential(userId, ttlSecs = 3600) {
  const expiry = Math.floor(Date.now() / 1000) + ttlSecs;
  const username = `${expiry}:${userId}`;
  const credential = crypto
    .createHmac("sha1", SECRET)
    .update(username)
    .digest("hex");
  return {
    iceServers: [
      {
        urls: [
          "turn:turn.example.com:3478?transport=udp",
          "turn:turn.example.com:3478?transport=tcp",
        ],
        username,
        credential,
      },
    ],
    expiry,
  };
}
```

Equivalent minter in Python (e.g. for a Flask/FastAPI agent):

```python
import hashlib, hmac, os, time

SECRET = os.environ["MIUTURN_SHARED_SECRET"]

def issue_turn_credential(user_id: str, ttl_secs: int = 3600):
    expiry = int(time.time()) + ttl_secs
    username = f"{expiry}:{user_id}"
    credential = hmac.new(SECRET.encode(), username.encode(), hashlib.sha1).hexdigest()
    return {
        "username": username,
        "credential": credential,
        "expiry": expiry,
        "urls": [
            "turn:turn.example.com:3478?transport=udp",
            "turn:turn.example.com:3478?transport=tcp",
        ],
    }
```

Quick sanity check from a shell (server logs in the token username format):

```bash
SECRET="9f86d0..."; EXPIRY=$(( $(date +%s) + 600 )); USER="$EXPIRY:smoke-test"
echo "$USER -> $(printf '%s' "$USER" | openssl dgst -sha1 -hmac "$SECRET" -hex | awk '{print $NF}')"
```

Guidelines for TTL: keep it short (5–60 min). The token only gates the
initial Allocate; how long a session may live after expiry is controlled by
`expired_token_policy`.

The JS client puts the result straight into
`new RTCPeerConnection({ iceServers })`.

Notes:

- The shared secret never leaves the agent server and miuturn. Keep miuturn's
  HTTP port (8080) firewalled off from the public internet in this mode — the
  admin console is not needed for token minting.
- `http.turn_rest_secret` is a deprecated alias for `auth.shared_secret`;
  the `[auth]` key wins when both are set.
- Static users in `[[auth.users]]` continue to work alongside ephemeral
  credentials (exact username match takes precedence).
- There is **no global password fallback**: a username that is neither a
  configured user nor a valid `expiry:user` HMAC credential is rejected.

### Expired-token policies

`expired_token_policy` controls what happens to an established session once
its token expires:

| Policy   | Allocate after expiry | Refresh after expiry                  |
| -------- | --------------------- | ------------------------------------- |
| `renew`  | 401                   | allowed — sessions live until closed  |
| `strict` | 401                   | 401 — sessions die on next Refresh    |
| `cap`    | 401                   | allowed — lifetime clamped to expiry  |

### Reliability notes (long-running calls)

- Stale/expired nonces are answered with **438 Stale Nonce** plus a fresh
  nonce so clients retry transparently instead of tearing down.
- Channel bindings are refreshed by traffic in both directions (like coturn),
  so active media flows do not lose their channels after 600s.
- NAT rebinding (client source port change) still breaks a TURN session by
  design (5-tuple semantics); clients handle it via ICE restart.
- Restarting miuturn drops all in-memory allocations and nonces by default;
  clients re-allocate automatically. Enable `[persist]` to survive restarts
  with sessions intact — see "Persistence & Zero-Downtime Restarts" below.

## Admin Console

Access the web UI at `http://localhost:8080/console`

The admin console provides:
- **Real-time Metrics Dashboard**: Live chart showing throughput and active allocations
- **Statistics Cards**: Active/total allocations, bytes relayed, messages
- **User Management**: Add/edit/delete TURN users with bandwidth and duration limits
- **ACL Rules**: Manage IP-based access control with priority ordering

Configure admin credentials in `[http]` section:
```toml
[http]
admin_username = "admin"
admin_password = "changeme"
```

**Note**: Admin console credentials are separate from TURN service users in `[[auth.users]]`.

## API Endpoints

| Endpoint                   | Method | Description               |
| -------------------------- | ------ | ------------------------- |
| `/health`                  | GET    | Server health and stats   |
| `/metrics`                 | GET    | Prometheus metrics        |
| `/api/v1/stats`            | GET    | Detailed stats + users    |
| `/api/v1/users`            | POST   | Add user                  |
| `/api/v1/users`            | PUT    | Update user               |
| `/api/v1/users`            | DELETE | Delete user               |
| `/api/v1/acl`              | POST   | Add ACL rule              |
| `/api/v1/acl`              | PUT    | Update ACL rule           |
| `/api/v1/acl`              | DELETE | Delete ACL rule           |
| `/api/v1/turn-credentials` | POST   | Generate TURN credentials |

## Persistence & Zero-Downtime Restarts

miuturn can persist live session state (UDP allocations, channel bindings,
auth nonces, lifetime counters) so a restart resumes sessions instead of
dropping them. Clients keep sending to the **same relay addresses** — media
freezes for the restart window (typically 1–3s under Docker) and then
continues, without any re-Allocate or ICE restart on the client side.

> **⚠️ The state file MUST live on a mounted volume in container deployments.**
> Docker/K8s wipes everything outside volumes when a container/pod is
> recreated. If `[persist].path` points at a container-local path (e.g. the
> default `/var/lib/miuturn/state.json` **without** `-v miuturn-data:/var/lib/miuturn`),
> the state dies with the old container and **every restart silently behaves
> like the old drop-everything restart** — miuturn cannot detect this from
> inside the container. Verify the mount once after first launch:
>
> ```bash
> docker inspect -f '{{ range .Mounts }}{{ .Source }} -> {{ .Destination }}{{ "\n" }}{{ end }}' miuturn
> # must include a line ending in -> /var/lib/miuturn
> ```

### Configuration

```toml
[persist]
enabled = true
# MUST be on a persistent volume in container deployments (see warning above).
path = "/var/lib/miuturn/state.json"
# Checkpoint cadence. Unchanged state is not rewritten; a final unconditional
# save always happens on shutdown.
checkpoint_interval_secs = 30
```

Persistence is **disabled by default**; without it a restart drops all
in-memory sessions (pre-0.3 behavior).

### What triggers a state save

| Signal | Source | Behavior |
| ------ | ------ | -------- |
| SIGTERM | `docker stop`, `systemctl stop/restart`, `kill` | graceful save → exit |
| SIGINT  | Ctrl+C | graceful save → exit |
| SIGUSR2 | explicit restart trigger | graceful save → exit (restart policy brings it back) |
| kill -9 / OOM / crash | — | last periodic checkpoint is used (lose at most `checkpoint_interval_secs` of allocations) |

### Restore semantics

On startup, if the state file exists **and** the config fingerprint matches
(listeners, relay port range, external IP, realm, max allocation duration),
sessions are re-attached with their original relay ports before the UDP
receive loop starts. Otherwise the state file is rotated aside
(`state.json.corrupt-*` / `state.json.mismatch-*`) and the server starts
fresh — safe fallback, never a crash.

Only UDP allocations are persisted. TCP/TLS client connections cannot be
re-attached to a new process; those clients reconnect via ICE as before.

### Docker deployment

The state directory **must be a volume** — without it, state dies with the
container and restarts behave like the old drop-everything restart (see the
warning at the top of this section). Mount it explicitly:

```bash
docker run -d --name miuturn \
  --restart unless-stopped \
  -p 3478:3478 -p 3478:3478/udp -p 8080:8080 \
  -v miuturn-data:/var/lib/miuturn \
  docker.cnb.cool/miuda.ai/miuturn:latest
```

Failure modes at a glance:

| Situation | What happens |
| --------- | ------------ |
| Volume mounted | restarts restore sessions, relay ports unchanged |
| **No volume, container recreated** | state wiped with the container → **fresh start every time** |
| Config changed between restarts (fingerprint mismatch) | old state rotated aside (`*.mismatch-*`) → fresh start |
| State file corrupt | rotated aside (`*.corrupt-*`) → fresh start |
| `docker rm` without backing out the volume | named volume survives `docker rm` of the container (only `docker volume rm` deletes it) |

Upgrade flow (binary or image change):

```bash
# docker compose — `up -d` recreates the container; the SIGTERM during
# recreation saves state, and the new container restores from the volume.
docker compose pull && docker compose up -d

# plain docker
docker stop -t 15 miuturn     # SIGTERM → save state → exit
docker rm miuturn
docker run -d --name miuturn ... # same command/volume as before, new image
```

Verify the upgrade:

```bash
# The new container logs the restore summary on boot:
docker logs miuturn 2>&1 | grep "persist:"
# Compare active allocation counts before/after:
curl -s http://localhost:8080/health | jq '.active_allocations'
```

Rollback: run the previous image with the same volume. If the state schema
version changed in the newer release, the old binary starts fresh (documented
in its release notes); sessions are lost but the service is unaffected.

### Upgrade script (standalone docker run style)

```bash
#!/usr/bin/env bash
set -euo pipefail
NAME=miuturn
IMAGE=docker.cnb.cool/miuda.ai/miuturn:NEW_TAG
HEALTH=http://127.0.0.1:8080/health

BEFORE=$(curl -s "$HEALTH" | jq -r '.active_allocations // 0')
docker pull "$IMAGE"
docker stop -t 15 "$NAME"
docker rm "$NAME"
docker run -d --name "$NAME" \
  --restart unless-stopped \
  -p 3478:3478 -p 3478:3478/udp -p 8080:8080 \
  -v miuturn-data:/var/lib/miuturn \
  "$IMAGE"

for i in $(seq 1 30); do curl -sf "$HEALTH" >/dev/null && break; sleep 0.5; done
curl -sf "$HEALTH" >/dev/null || { echo "health check failed"; exit 1; }

AFTER=$(curl -s "$HEALTH" | jq -r '.active_allocations // 0')
echo "active allocations: before=$BEFORE after=$AFTER"
docker logs "$NAME" 2>&1 | grep "persist:"
```


## Environment Variables

- `CONFIG`: Path to config file (default: `miuturn.toml`)

## License

MIT License - Powered by [miuda.ai](https://miuda.ai)
