# Relay protocol (v1)

This is the wire contract between an OpenBekci instance and the relay as implemented in this repository. The source of truth is the infra plan (`docs/plans/05-infra.md` section 4 in the core repository); where that text leaves room, this document records the choice made. **Section 9 lists every interpretation** so the server-side relay client can be reconciled with this implementation.

The relay speaks plain HTTP and expects a TLS terminator in front of it. All bodies are JSON (UTF-8). `Content-Type` is not enforced on requests; responses are `application/json`.

## 1. Authentication of `POST /v1/send`

```
Authorization: Relay-HMAC <server_id>:<ts>:<nonce>:<mac>
```

- `server_id`: the id issued at enrollment (`srv_` + 16 hex chars). No colons.
- `ts`: Unix time in whole seconds, decimal ASCII.
- `nonce`: 16 to 64 characters from `[A-Za-z0-9_-]`, unique per request.
- `mac`: lowercase hex of `HMAC-SHA256(key, ts + "." + nonce + "." + sha256hex(body))`, where `key` is the bytes of the `server_secret` string exactly as issued (including its `obk_rs_` prefix) and `sha256hex(body)` is the lowercase hex SHA-256 of the raw request body bytes as sent. Upper-case hex is accepted.

The relay rejects `|now - ts| > 5 minutes` (`RELAY_CLOCK_SKEW`), a nonce already seen for that `server_id` within the window (nonces are kept for twice the skew), and bodies over 256 KiB (`RELAY_MAX_BODY_BYTES`).

Until the MAC verifies, every failure is the same `401 unauthorized`, so a prober cannot learn which server ids exist. After the MAC verifies the relay answers specifically:

| HTTP | `error.code` | Meaning |
| --- | --- | --- |
| 401 | `unauthorized` | missing/malformed header, unknown server id, wrong MAC, revoked server |
| 401 | `stale_timestamp` | MAC valid, timestamp outside the window (check the instance clock) |
| 401 | `replayed_nonce` | MAC valid, nonce already used |
| 403 | `server_disabled` | the operator disabled this server (kill switch); retry later, do not hammer |
| 413 | `payload_too_large` | body over the cap |
| 400 | `bad_request`, `empty_batch`, `batch_too_large` | malformed JSON, unknown top-level key, no messages, more than `RELAY_MAX_BATCH` (500) messages |
| 500 | `internal` | relay fault; safe to retry with a new nonce |

Error body: `{"error":{"code":"...","message":"..."}}`. Messages never echo request values.

## 2. `POST /v1/send`

Request:

```json
{ "messages": [
    { "push_kind": "fcm" | "apns",
      "token": "<device token>",
      "app_id": "org.openbekci.app",
      "priority": "high" | "normal",
      "ttl_seconds": 3600,
      "data": { "instance_id": "...", "org_id": "...", "notification_id": "...",
                "type": "ticket.updated", "collapse_key": "ticket:...", "badge": 3 },
      "apns": { "mutable_content": true, "generic_title_key": "push.ticket_updated" } } ] }
```

The top level has exactly one key, `messages`. Each message may carry only the keys above; an unknown key rejects that message.

`data` is the **allowlist**: `instance_id`, `org_id`, `notification_id`, `type`, `collapse_key`, `badge`. Any other key rejects the message with code `disallowed_data_key` (the key name is echoed, never a value) and the message is never forwarded. Nothing from the request other than these fields (and `token`) reaches FCM or APNs.

Response, always `200` when the request was authentic and well-formed, even if every message failed:

```json
{ "results": [
    { "index": 0, "status": "ok" },
    { "index": 1, "status": "invalid_token", "code": "unregistered" },
    { "index": 2, "status": "rate_limited", "code": "quota_exceeded", "retryable": true },
    { "index": 3, "status": "error", "code": "provider_unavailable", "retryable": true } ] }
```

`results` has one entry per message, in request order. `status` is one of `ok`, `invalid_token` (the instance should delete or disable that device), `rate_limited`, `error`. `code` is a short machine-readable class and never carries provider text. `retryable` is present (true) only when retrying the same message later can succeed; send it again with a fresh nonce.

Codes by status:

- `invalid_token`: `unregistered` (FCM `UNREGISTERED` error code, which FCM sends with HTTP 404; a bare 404 is `provider_rejected` because a wrong project id also answers 404; APNs 410 `Unregistered` or `BadDeviceToken`), `invalid_argument_token` (FCM 400 naming `message.token`).
- `rate_limited`: `rate_limited` (per-server token bucket, default 60 msg/s with burst 600), `quota_exceeded` (daily quota, UTC day). Both are retryable; the daily quota is retryable after 00:00 UTC.
- `error`, validation: `invalid_message`, `invalid_push_kind`, `invalid_token_format`, `invalid_app_id`, `invalid_priority`, `invalid_ttl`, `invalid_data`, `disallowed_data_key`, `invalid_apns`, `app_not_allowed`, `provider_not_configured`.
- `error`, provider: `provider_throttled` (retryable), `provider_unavailable` (retryable), `provider_unreachable` (retryable), `request_deadline` (retryable: the batch deadline `RELAY_REQUEST_TIMEOUT` passed before this message finished; it may or may not have been delivered), `provider_auth_failed`, `provider_rejected`, `topic_mismatch` (APNs `DeviceTokenNotForTopic`: a relay configuration problem, deliberately not `invalid_token`), `encode_failed`, `request_failed`, `internal`.

## 3. Field semantics

- `push_kind`: `fcm` or `apns`. A message needs a sender configured for its app; otherwise `provider_not_configured`.
- `token`: 1 to 4096 bytes. Never logged, stored or put in a metric label.
- `app_id`: optional; defaults to the app the server enrolled for. It must equal that app id, otherwise `app_not_allowed`.
- `priority`: default `high`.
- `ttl_seconds`: default 3600, range 0 to 2419200 (28 days). 0 means "deliver now or drop".
- `data.instance_id`, `data.notification_id`, `data.type`: required strings. `data.org_id`, `data.collapse_key`: optional strings. All strings at most 256 bytes. `data.badge`: optional integer 0 to 99999.
- `apns.mutable_content` (bool) and `apns.generic_title_key` (a localisation key matching `[A-Za-z0-9_.-]{1,128}`). The object is optional and only meaningful for `push_kind: apns`; it is accepted and ignored for `fcm`.

### FCM mapping (HTTP v1, data-only)

`message.token`, `message.data` (all values strings, badge rendered as a decimal string, only the allowlisted keys that were present), `message.android.priority` (`HIGH`/`NORMAL`), `message.android.ttl` (`<n>s`), `message.android.collapse_key` (from `collapse_key`). No `notification` block: the app builds the notification locally.

### APNs mapping

`POST /3/device/<token>` over HTTP/2 with provider-token auth (ES256 JWT, `kid` = key id, `iss` = team id, refreshed every 50 minutes). Headers: `apns-topic` (configured topic, default the app id), `apns-push-type`, `apns-priority`, `apns-expiration` (now + ttl, or 0), `apns-collapse-id`.

- With `apns.generic_title_key`: `apns-push-type: alert`, priority 10 (5 when `priority` is `normal`), body `aps.alert = {"title-loc-key": <key>}`, `aps.mutable-content = 1` when requested, `aps.badge` when `badge` is present.
- Without it: a silent push, `apns-push-type: background`, priority 5 (required for background pushes), `aps = {"content-available": 1}` (plus `badge` if present), so the app fetches details itself.
- The allowlisted data keys are added as top-level custom keys next to `aps`.
- `apns-collapse-id` is `collapse_key` when it is at most 64 bytes; longer keys are replaced by their SHA-256 in hex (64 characters), which is stable so collapsing still works. The payload `collapse_key` keeps the original value.

## 4. `POST /v1/enrollments`

Request:

```json
{ "base_url": "https://bekci.example.org", "challenge": "<16-256 chars>",
  "app_id": "org.openbekci.app", "invite_code": "obk_inv_...", "manual": false }
```

All keys are optional except `base_url`, `challenge` and `app_id` for a normal enrollment; unknown keys are rejected (`400 bad_request`). `manual: true` is the wire form of `openbekci admin push-relay enroll --manual`.

Flow (infra plan 4.2): rate-limit per client IP (IPv6 clients by /64; default 10 per minute, `RELAY_ENROLL_PER_MIN_PER_IP`; `X-Forwarded-For` is honoured only from `RELAY_TRUSTED_PROXIES`), check the mode (`RELAY_ENROLLMENT=open|invite|closed`, default `invite`), check `app_id` is served, check the invite (exists, unused, unexpired), fetch `<base_url>/.well-known/openbekci.json` under SSRF guards and compare `relay_enrollment.challenge` in constant time, then in one transaction consume the invite, mark the challenge used and create the server. A failed verification does not consume the invite. The challenge cannot be reused (remembered 24 hours, past its 10 minute life).

SSRF guards: HTTPS only; no credentials/query/fragment in `base_url`; DNS is resolved first and **every** answer must be public (loopback, private, link-local incl. cloud metadata 169.254.169.254, CGNAT, multicast, documentation and benchmarking ranges, ULA, IPv4-mapped, IPv4-compatible, NAT64, 6to4 and Teredo forms and zone-scoped addresses are all refused); the connection is made to the checked address, never re-resolved; no redirects; 64 KiB body cap; 5 s total timeout; no proxy.

Manual path: an invite created `--manual` plus `"manual": true` skips the fetch (no challenge needed); the server is stored `verified: false` with the lower `RELAY_UNVERIFIED_DAILY_QUOTA` (default 1000). `manual: true` with a non-manual invite is refused.

Response `201`:

```json
{ "server_id": "srv_...", "server_secret": "obk_rs_...", "verified": true }
```

Shown once; the relay keeps the secret because it needs the HMAC key (see section 9).

Errors: `429 rate_limited` (with `Retry-After: 60`), `403 enrollment_closed`, `403 invite_required`, `403 invite_invalid`, `403 invite_not_manual`, `400 unknown_app_id`, `400 invalid_base_url`, `400 bad_challenge`, `422 base_url_blocked`, `422 discovery_unreachable`, `422 discovery_invalid`, `422 challenge_mismatch`, `409 challenge_used`.

## 5. Other endpoints

- `GET /healthz`: `200 {"status":"ok"}` when the database answers, else `503`.
- `GET /metrics`: Prometheus text. Optional `Authorization: Bearer <RELAY_METRICS_TOKEN>`. Labels: server id (per server only), push kind, result class, route, status code; never tokens or addresses.

## 6. Operator commands (local, against `RELAY_DB_PATH`)

`openbekci-relay admin servers list|create|disable|enable|revoke`, `admin invites create|list|revoke`. `disable` is the per-server kill switch: it takes effect on the next request because authentication reads the server row every time. `revoke` is final: the secret is destroyed.

## 7. Retries and idempotency

The relay does not de-duplicate. An instance that resends after a timeout may deliver twice; `collapse_key` limits the visible effect on the device. Each attempt needs a fresh nonce.

## 8. Versioning

Paths carry `/v1`. New response fields may be added; clients must ignore unknown fields. New `code` values may appear; clients switch on `status`, not `code`.

## 9. Interpretations made (to reconcile with the server-side client)

1. **Task text versus plan.** The assignment mentioned per-instance bearer tokens, `{push_kind, token, payload}` and "issue/revoke instance tokens"; the infra plan specifies Relay-HMAC, `{messages:[{push_kind, token, app_id, priority, ttl_seconds, data, apns}]}` and enrollment. The plan text was followed. SQLite replaces the plan's Postgres as instructed; the table set matches (`server`, `invite`, `nonce`, `quota`) plus `challenge_used`. "Issue instance token" maps to `admin invites create` (self-service enrollment) and `admin servers create` (operator-provisioned); "revoke" to `admin servers revoke`.
2. The plan does not say how `ts`, `nonce`, the MAC key or the body hash are encoded: seconds since the epoch in decimal; nonce charset and length as in section 1; key is the secret string's bytes; body hash is lowercase hex of the raw bytes.
3. The plan lists the statuses `ok`, `invalid_token`, `rate_limited`, `error` but not the response shape: `{"results":[{index,status,code?,retryable?}]}`, 200 for any authentic well-formed request. `code` and `retryable` are additions.
4. Per-message problems (allowlist violation, bad field, wrong app) are reported per message with status `error`, not by failing the whole batch with 4xx, so one bad message cannot block a batch. A request that is not parseable as `{"messages":[...]}` fails whole with 400.
5. Rate limiting is per message, not per request: messages beyond the token bucket or the daily quota get `rate_limited` in the 200 response (no HTTP 429 on `/v1/send`). Messages rejected by validation consume neither bucket nor quota; the quota counts messages handed to a provider, whether or not the provider accepted them.
6. Required `data` keys are `instance_id`, `notification_id`, `type`; `org_id`, `collapse_key`, `badge` are optional (the plan shows all six but does not say which are mandatory).
7. `app_id` in a message is optional and must match the app the server enrolled for; one enrollment binds one app id. A deployment serving several white-label apps enrolls once per app.
8. `generic_title_key` is sent as `aps.alert.title-loc-key`; without it the push is silent (`content-available`). `mutable_content` is honoured only for alerts. The plan does not specify either mapping.
9. Long APNs collapse ids are hashed (64-byte limit). FCM collapse keys are passed as-is.
10. `ttl_seconds` default 3600 (the plan's example) and maximum 28 days; `priority` default `high`.
11. Enrollment wire details not in the plan: the `manual` boolean, `bad_challenge` bounds (16 to 256 chars), error codes, `Retry-After`, the extra `verified` field in the response, and that the challenge sits at `relay_enrollment.challenge` at the top level of `/.well-known/openbekci.json` (backend plan section 8).
12. `base_url` may include a path prefix (`https://host/bekci`), in which case the document is fetched from `<prefix>/.well-known/openbekci.json`; a non-default port is allowed.
13. The relay stores `server_secret` in clear in SQLite because HMAC verification needs the key. Protect the database file like a credential store (mode 600, encrypted volume). A hash-only design would need a different scheme (for example per-request public-key signatures); flagged as an open question.
14. The relay does not know the instance's `relay_id`; that is the instance's local name for an entry in `OPENBEKCI_PUSH_RELAYS`. The `server_id` in that entry is the relay's `server_id`.
15. `invalid_token` is returned only when the provider says the token is dead (see section 2). Configuration faults (wrong topic, rejected credentials, malformed request) are `error`, so a misconfigured relay cannot make instances delete healthy devices.
16. Nonces are scoped per `server_id` and kept for twice the clock skew (10 minutes by default).
17. Daily quota day boundary is UTC.
