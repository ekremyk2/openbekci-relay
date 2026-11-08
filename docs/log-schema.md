# Log schema

The relay logs JSON lines to stdout (Go `log/slog`). Logs are content-free by construction: they contain the server id, counts, error classes and timing, and nothing that identifies a device, a person or a notification. Operators of the official relay keep request logs for 7 days.

Never logged: device tokens, any `data` value (`instance_id`, `org_id`, `notification_id`, `type`, `collapse_key`, `badge`), `apns` options, `server_secret`, invite codes, challenges, client IP addresses, `Authorization` headers, provider response bodies.

Common fields on every line: `time`, `level`, `msg`.

## `msg: "request"` (one per API request; `/healthz` and `/metrics` are not logged)

| Field | Type | Present | Meaning |
| --- | --- | --- | --- |
| `route` | string | always | `send`, `enroll_begin` or `enroll_complete` |
| `status` | int | always | HTTP status returned |
| `duration_ms` | int | always | handling time |
| `server_id` | string | when authenticated or enrolled | `srv_...` |
| `messages` | int | `send` | messages in the batch |
| `ok`, `invalid_token`, `rate_limited`, `error`, `rejected` | int | `send` | per-outcome counts (`rejected` = failed validation, never forwarded) |
| `error_class` | string | on failure | the `error.code` returned, for example `unauthorized`, `replayed_nonce`, `payload_too_large` |

Level: info below 400, warn for 4xx, error for 5xx.

## Other lines

| `msg` | Fields | Notes |
| --- | --- | --- |
| `relay listening` | `addr`, `version`, `apps` (count), `enrollment`, `dev_log_sender` | startup |
| `server enrolled` | `server_id`, `app_id`, `verified` | enrollment succeeded |
| `log sender: message accepted` | `push_kind`, `app_id`, `priority` | only with `RELAY_DEV_LOG_SENDER=true` |
| `quota reserve failed`, `counter update failed`, `purge failed` | `server_id` (first two), `error_class: store_error` | database trouble |
| `shutting down`, `stopped` | `timeout` | graceful shutdown |

## Metrics

`relay_http_requests_total{route,code}`, `relay_http_request_seconds{route}`, `relay_auth_failures_total{reason}`, `relay_messages_total{server_id,push_kind,result}`, `relay_provider_requests_total{provider,outcome}`, `relay_provider_request_seconds{provider}`, `relay_enrollments_total{result}`, plus Go runtime and process collectors. `provider` is `fcm` or `apns`. Suggested alerts: provider error ratio (`outcome="error"` over all) and per-server `result="error"` ratio.
