# ML Alert API GUI Evidence - 2026-06-25

Status: controlled server/API/GUI evidence plus follow-up live telemetry
evidence.

Follow-up live proof now exists:
`apps/tamandua_agent/src/bin/ml_detection_telemetry_smoke.rs` scanned a file
with local ONNX, emitted `DetectionType::Ml`, and sent the event through the
real agent telemetry transport over mTLS.

## What Ran

- A controlled `events` row and linked `alerts` row were created on the lab
  backend for LAB-DC01.
- The alert used `source=ml`, `detection_source=ml`, `detection_type=ml`,
  `rule_name=ML_MALWARE_TROJAN`, `prediction=trojan`, and
  `model_version=malware_smell_knn`.
- Authenticated HTTP probes queried:
  - `GET /api/v1/alerts/:id`
  - `GET /api/v1/alerts?source=ml&per_page=5`
  - `GET /api/v1/events`
  - `GET /api/v1/timeline`
  - `GET /app/alerts`
  - `GET /app/alerts/:id`
  - `GET /app/events`

## Evidence IDs

- Run ID: `20260625T-ml-alert-api-gui-evidence`
- Alert ID: `d9eadbc6-dcc2-41d2-8e4a-1d020665f19f`
- Event ID: `de19458c-3d73-44ab-b2bc-88b394e240ef`
- Agent ID: `c5706989-46e8-4ecb-9feb-75c5f3a42f1a` (`LAB-DC01`)

Follow-up live telemetry:

- Alert ID: `f2c50bfe-665b-45c4-8599-9fc09c3a6bac`
- Event ID: `41eb6303-e267-432b-ad5c-69eb74569809`
- Alert: `ML Detection: ML_MALWARE_TROJAN`
- Severity: `critical`
- Inserted at: `2026-06-25 10:39:18.906371`
- Event created at: `2026-06-25 10:39:20`
- Verdict: `trojan`, confidence `1.0`, `telemetry_sent=true`

Final live source-filter proof:

- Run ID: `20260625T-live-ml-telemetry-mtls-source-filter`
- Alert ID: `67048401-7bbf-4414-8b9c-a2a0b5d8362d`
- Event ID: `5305aa7e-7a7e-432b-970b-979ff9fd7dbf`
- Alert: `ML Detection: ML_MALWARE_TROJAN`
- Severity: `critical`
- Source: `ml`
- Verdict: `trojan`, confidence `1.0`, `telemetry_sent=true`

Post-restart live event evidence:

- Event ID: `33543ce2-2087-4e77-b3cd-43294b8248c1`
- Event type: `ransomware_detected`
- Agent ID: `c5706989-46e8-4ecb-9feb-75c5f3a42f1a`
- Timestamp: `2026-06-25 12:00:30.267`
- Verdict: `trojan`
- Model: `malware_smell_knn.onnx`
- Transport: `wss://192.168.12.146:8443/socket/agent`

Socket probe follow-up:

- `dashboard:lobby` and `alerts:feed` both accepted authenticated joins.
- The raw Phoenix client required heartbeat frames to avoid disconnecting
  during the Cargo-triggered smoke.
- A broadcast payload issue was found and fixed in
  `TamanduaServerWeb.Broadcaster.serialize_alert/1`: `threatScore` is now
  normalized to a JSON number instead of allowing a `Decimal` struct through.
- After that fix, `dashboard:lobby` no longer emitted `phx_error`; however, no
  new ML alert was generated during the post-fix smoke window, so live alert
  socket delivery remains unproven.
- A later non-deduplicated smoke used `--run-id socket-20260625091550` and
  successfully created event `16e5f26c-3dee-4746-972c-9bba78be0c60` plus alert
  `a7e750d0-6566-42ca-acac-f67cd6cf461a`
  (`ML_MALWARE_TROJAN_SOCKET_20260625091550`).
- The socket probe was connected to the dashboard runtime on `:4000`, while the
  mTLS agent ingestion path used `:8443`. The alert was created in the database,
  but no `new_alert` frame reached `alerts:feed`, isolating the remaining issue
  to cross-runtime fanout rather than ML detection, mTLS ingestion, DB
  persistence, or alert creation.
- Code follow-up: `TamanduaServer.Alerts.AlertBroadcastRelay` now emits and
  listens for PostgreSQL `NOTIFY` messages on `tamandua_alert_broadcasts`, so
  dashboard runtimes can rebroadcast alerts created by a separate mTLS runtime.

## Results

| Surface | Result |
| --- | --- |
| `/api/v1/alerts/:id` | `200`, live alert source serialized as `ml` |
| `/api/v1/alerts?source=ml` | `200`, returned the live alert as the first result |
| `/api/v1/events` | `200`, returned event `5305aa7e-7a7e-432b-970b-979ff9fd7dbf` |
| `/api/v1/timeline` | `200`, returned event `5305aa7e-7a7e-432b-970b-979ff9fd7dbf` |
| `/app/alerts` | `200`, page contains live alert ID and `ml` |
| `/app/alerts/:id` | `200`, page contains live alert ID and `ml` |
| `/app/events` | `200`, page contains `ml` |

## Claim Boundary

Proven:

- The server/API can store and serialize an ML alert as `source=ml`.
- The `source=ml` API filter returns the ML alert.
- The GUI alert and event routes load without 500s and include the ML evidence.
- Timeline API loads the linked event without 500s.
- Live agent telemetry over mTLS can create a critical ML alert from
  `DetectionType::Ml`.
- The live ML alert now appears under the `source=ml` API filter after
  metadata backfill for the already-created lab alerts.
- Live agent telemetry over mTLS can persist ML verdict events with
  `ml_verdict=trojan` and `model_version=malware_smell_knn.onnx`.
- A non-deduplicated run ID can force a fresh ML event/alert for repeatable
  socket proof attempts.

Not proven:

- The live `alerts:feed` socket broadcast carried this specific alert.
- End-to-end proof of the PostgreSQL relay delivering that fresh ML alert to a
  live `alerts:feed` subscriber.
- The current bootstrap ML model has acceptable production false-positive rate.
- Browser pixel/screenshot confirmation of the new live alert ID
  `67048401...`.

Next required proof:

1. Rebuild/redeploy the server image with `AlertBroadcastRelay`, trigger a
   non-deduplicated ML alert, and capture `new_alert` or `alert_updated` from
   `alerts:feed`.
2. Persist `source=ml`/`detection_source=ml` at alert creation time for ML
   detections, not only via API inference/backfill.
3. Keep lab port ownership explicit: HTTP probes used `:4000`; mTLS telemetry
   used `:8443`; additional lab containers are also present on `:4002` and
   `:4003`.
