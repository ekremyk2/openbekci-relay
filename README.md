# openbekci-relay

The OpenBekci push relay. Self-hosted [OpenBekci](https://github.com/ekremyk2/OpenBekci) servers cannot hold the FCM and APNs credentials of a store app, so they send **content-free** push payloads to a relay that does. The relay forwards them to FCM or APNs and tells the server which device tokens are dead. The design is section 4 of `docs/plans/05-infra.md` in the core repository; the wire contract as implemented, with every interpretation made, is [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

- One static Go binary, no CGO, SQLite (pure Go) for enrollments, nonces and quota counters.
- Per-server HMAC authentication, replay protection, token-bucket rate limit, daily quota, per-server kill switch.
- Strict `data` allowlist: `instance_id`, `org_id`, `notification_id`, `type`, `collapse_key`, `badge`. Anything else is rejected, never forwarded.
- FCM HTTP v1 (service account, cached OAuth2 token) and APNs over HTTP/2 (`.p8` token auth). A `log` sender for development.
- Structured logs without tokens or payloads ([`docs/log-schema.md`](docs/log-schema.md)), Prometheus `/metrics`, graceful shutdown.
- Licence: AGPL-3.0 (see `LICENSE`).

## What the relay never sees

The relay sees device tokens, `org_id`, `instance_id`, notification ids and notification types, because those are the payload. It **never** sees:

- notification titles or bodies, names, phone numbers, e-mail addresses, ticket or payment details: the instance does not send them, and the allowlist rejects any extra key;
- the content of the user's account; the app fetches details from its own server after a push arrives;
- a device registry: tokens are not stored, only forwarded. The database holds enrollments, nonces, invite hashes and per-day counters.

Trust model, written down: because the relay holds the store credentials it can push to any device registered through any enrolled server. A compromised relay could spam devices or correlate activity per organization; it could not read notifications. Logs contain server ids, counts, error classes and timings only; client IP addresses are not logged. White-label builds can run their own relay.

## Build

```sh
go build -o bin/openbekci-relay ./cmd/openbekci-relay      # or: go tool task build
go tool task lint test test:race                            # vet, tidy check, golangci-lint, tests
docker build -t openbekci-relay .
```

## Install

Docker Compose (see `deploy/compose.yaml` and `deploy/relay.example.env`):

```sh
cp deploy/relay.example.env deploy/relay.env     # edit
mkdir deploy/secrets                             # fcm-service-account.json, AuthKey_XXXX.p8
docker compose -f deploy/compose.yaml up -d
```

Put a TLS terminator in front (Caddy, nginx, a load balancer): the relay speaks plain HTTP on `RELAY_LISTEN`. Set `RELAY_TRUSTED_PROXIES` to the proxy's CIDR so per-IP enrollment limits see real client addresses.

For a quick look without any provider credentials:

```sh
export RELAY_APP_1_ID=org.openbekci.app RELAY_DEV_LOG_SENDER=true RELAY_DB_PATH=./relay.db
openbekci-relay serve
```

## Configuration

Everything comes from environment variables with the `RELAY_` prefix. Every secret has a `_FILE` variant that reads the value from a file (Docker/Kubernetes secrets); setting both forms is an error. Invalid configuration stops the process at startup with every problem listed.

| Key | Default | Meaning |
| --- | --- | --- |
| `RELAY_LISTEN` | `:8080` | listen address |
| `RELAY_DB_PATH` | `/var/lib/openbekci-relay/relay.db` | SQLite file (also used by `admin` and `healthcheck`) |
| `RELAY_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `RELAY_SHUTDOWN_TIMEOUT` | `20s` | grace period for in-flight requests on SIGTERM/SIGINT |
| `RELAY_ENROLLMENT` | `invite` | `open`, `invite` (one-shot code from the operator) or `closed` |
| `RELAY_RATE_PER_SEC`, `RELAY_BURST` | `60`, `600` | per-server token bucket, per message |
| `RELAY_DAILY_QUOTA` | `100000` | default daily messages for verified servers (`0` or less: unlimited) |
| `RELAY_UNVERIFIED_DAILY_QUOTA` | `1000` | default for manually enrolled (unverified) servers |
| `RELAY_MAX_BODY_BYTES` | `262144` | request body cap for `/v1/send` |
| `RELAY_MAX_BATCH` | `500` | messages per request |
| `RELAY_CLOCK_SKEW` | `5m` | accepted `ts` skew; nonces are kept twice as long |
| `RELAY_ENROLL_PER_MIN_PER_IP` | `10` | enrollment attempts per client IP per minute |
| `RELAY_TRUSTED_PROXIES` | empty | comma-separated CIDRs/addresses whose `X-Forwarded-For` is trusted |
| `RELAY_SEND_TIMEOUT`, `RELAY_SEND_CONCURRENCY` | `10s`, `32` | per-message provider timeout, parallel provider calls |
| `RELAY_REQUEST_TIMEOUT` | `60s` | deadline for a whole `/v1/send` batch; unfinished messages come back as retryable `request_deadline` errors |
| `RELAY_METRICS_TOKEN` / `_FILE` | empty | if set, `/metrics` needs `Authorization: Bearer <token>` |
| `RELAY_DEV_LOG_SENDER` | `false` | route every app to the log sender instead of FCM/APNs |

One block per app (`n` = 1 to 32), so one relay can serve several white-label apps:

| Key | Meaning |
| --- | --- |
| `RELAY_APP_n_ID` | the `app_id` (also the default APNs topic) |
| `RELAY_APP_n_FCM_CREDENTIALS` / `_FILE` | Firebase service account JSON (needs `project_id`, `client_email`, `private_key`) |
| `RELAY_APP_n_APNS_KEY` / `_FILE` | contents of the `.p8` key |
| `RELAY_APP_n_APNS_KEY_ID`, `RELAY_APP_n_APNS_TEAM_ID` | required with the APNs key |
| `RELAY_APP_n_APNS_TOPIC` | bundle id, default `RELAY_APP_n_ID` |
| `RELAY_APP_n_APNS_SANDBOX` | `true` to use the APNs sandbox host |

An app with only FCM credentials answers `provider_not_configured` for `apns` messages, and the other way round.

## Registering an instance

**Self-service enrollment (the normal path).** The operator issues a one-shot invite:

```sh
openbekci-relay admin invites create --note "Sunset Residences" --ttl 168h
```

The instance administrator then runs, on the server (backend 0.4):

```sh
openbekci admin push-relay enroll --relay official --url https://push.example.org --secret-file /run/secrets/relay_secret --invite obk_inv_...
```

Enrollment has two steps. `POST /v1/enrollments/begin` (app id, invite) returns an `enrollment_id`, a secret `enrollment_token` and a relay-generated `challenge`; the server publishes the challenge in its discovery document; `POST /v1/enrollments/complete` (id, token, base URL) makes the relay fetch `https://<server>/.well-known/openbekci.json` under SSRF guards, check the challenge and, only for the holder of the token, return the secret. Knowing the (public) challenge is not enough to enroll. The command writes the returned secret to the file (mode 600) and prints the `OPENBEKCI_PUSH_RELAYS` entry: `relay_id=url;server_id;secret_file;app_id`. For LAN-only instances the relay cannot reach, issue the invite with `--manual` and enroll with `--manual`: the server is stored unverified with the lower default quota.

**Operator-provisioned.** Skip enrollment and issue the credentials directly (the secret is printed once):

```sh
openbekci-relay admin servers create --app-id org.openbekci.app --name "Sunset Residences"
```

To cut an instance off:

```sh
openbekci-relay admin servers disable srv_...     # kill switch: takes effect on the next request
openbekci-relay admin servers enable srv_...
openbekci-relay admin servers revoke srv_...      # final: the secret is destroyed
```

`admin` commands act on the SQLite file directly, so they work while the service runs or is down. In a container: `docker compose exec relay openbekci-relay admin servers list`.

## Operations

- **Health:** `GET /healthz` (also `openbekci-relay healthcheck`, used by the Docker `HEALTHCHECK`).
- **Metrics:** `GET /metrics`, labelled per server id. Alert on provider error ratio (`relay_provider_requests_total`) and per-server error ratio (`relay_messages_total{result="error"}`).
- **Backups:** the SQLite file in `/data` holds enrollments and secrets; back it up and protect it like a credential store. Losing it means servers must re-enroll. Nonces and counters are disposable.
- **Credentials:** rotate the Firebase key or the `.p8` by replacing the secret and restarting; the relay reads them at startup.
- **Scaling:** SQLite means one writer: run a single replica per database. The official deployment's two replicas plus Postgres are a later step; the store is a small package behind a handful of methods.
- **Shutdown:** SIGTERM stops accepting connections and waits up to `RELAY_SHUTDOWN_TIMEOUT` for in-flight sends.
- **Abuse controls:** enrollment is invite-only by default, per-IP enrollment limits, per-server rate and daily quota, kill switch, request size and batch caps, strict allowlist.
- **Log retention:** logs go to stdout; keep request logs 7 days if you follow the official relay's policy.

## API in one screen

`POST /v1/send` with `Authorization: Relay-HMAC <server_id>:<ts>:<nonce>:<hex hmac-sha256(secret, ts "." nonce "." sha256(body))>` and `{"messages":[{push_kind, token, app_id, priority, ttl_seconds, data, apns}]}`; the response is `{"results":[{index, status: ok|invalid_token|rate_limited|error, code?, retryable?}]}`. `POST /v1/enrollments/begin` and `/complete` for enrollment. Details and every interpretation: [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

## Tests

Handler tests use fake senders (allowlist, auth, replay, quota, batch limits, invalid-token reporting, enrollment); FCM and APNs senders are tested against `httptest` servers for request shape, token caching and error mapping. No test calls a real service. `go test -race` needs cgo and a C compiler; CI runs it.
