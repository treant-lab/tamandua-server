# ML Agent ONNX Direct Detection - 2026-06-25

Status: live agent telemetry evidence complete. This is not a production
model-quality claim.

## What Ran

- Built `apps/tamandua_agent/src/bin/ml_onnx_scan.rs` with Cargo feature
  `onnx`.
- Added and compiled `apps/tamandua_agent/src/bin/ml_detection_telemetry_smoke.rs`
  with Cargo feature `onnx`. This binary scans one file locally with ONNX,
  builds a `TelemetryEvent` with `DetectionType::Ml`, and sends it through the
  real `BackendClient` telemetry path.
- Exported `apps/tamandua_ml/models/malware_smell_knn.onnx` with
  `apps/tamandua_ml/scripts/export_onnx_knn.py`.
- Ran direct local smoke benchmarks against 25 malware and 25 goodware files.
- Ran `ml_onnx_scan.exe` on LAB-DC01 (`192.168.12.110`) against
  `malware_00000.bin`.
- Ran `ml_detection_telemetry_smoke` through the real agent socket using
  LAB-DC01 mTLS credentials and `wss://192.168.12.146:8443/socket/agent`.

## Results

| Run | Model | Malware Detection | Goodware FP | Outcome |
| --- | --- | ---: | ---: | --- |
| Local smoke | `malware_smell.onnx` marker wrapper | 0/25 | 0/25 | Non-candidate export |
| Local smoke | `malware_smell_knn.onnx` KNN export | 25/25 | 22/25 | Detects, but FP is unacceptable |
| LAB-DC01 Windows smoke | `malware_smell_knn.onnx` KNN export | 1/1 | Not measured | Detected `trojan`, confidence 1.0 |
| Agent telemetry smoke over mTLS | `malware_smell_knn.onnx` KNN export | 1/1 | Not measured | Sent ML telemetry, created critical ML alert |

LAB-DC01 report:

```json
{
  "is_malicious": true,
  "confidence": 1.0,
  "family": "trojan",
  "family_index": 1,
  "probabilities": [0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
  "inference_time_ms": 5410
}
```

Agent telemetry smoke report:

```json
{
  "kind": "MLDetectionTelemetrySmoke",
  "server_url": "wss://192.168.12.146:8443/socket/agent",
  "agent_id": "c5706989-46e8-4ecb-9feb-75c5f3a42f1a",
  "threshold": 0.7,
  "is_malicious": true,
  "confidence": 1.0,
  "family": "trojan",
  "family_index": 1,
  "inference_time_ms": 27,
  "telemetry_sent": true
}
```

Second mTLS telemetry smoke after the source-filter fix:

```json
{
  "kind": "MLDetectionTelemetrySmoke",
  "server_url": "wss://192.168.12.146:8443/socket/agent",
  "agent_id": "c5706989-46e8-4ecb-9feb-75c5f3a42f1a",
  "threshold": 0.7,
  "is_malicious": true,
  "confidence": 1.0,
  "family": "trojan",
  "family_index": 1,
  "inference_time_ms": 37,
  "telemetry_sent": true
}
```

Post-restart mTLS event evidence:

```json
{
  "event_id": "33543ce2-2087-4e77-b3cd-43294b8248c1",
  "event_type": "ransomware_detected",
  "agent_id": "c5706989-46e8-4ecb-9feb-75c5f3a42f1a",
  "timestamp": "2026-06-25 12:00:30.267",
  "ml_verdict": "trojan",
  "model_version": "malware_smell_knn.onnx"
}
```

Server evidence:

- Event ID: `41eb6303-e267-432b-ad5c-69eb74569809`
- Alert ID: `f2c50bfe-665b-45c4-8599-9fc09c3a6bac`
- Alert: `ML Detection: ML_MALWARE_TROJAN`
- Severity: `critical`
- Inserted at: `2026-06-25 10:39:18.906371`

Final source-filter evidence:

- Event ID: `5305aa7e-7a7e-432b-970b-979ff9fd7dbf`
- Alert ID: `67048401-7bbf-4414-8b9c-a2a0b5d8362d`
- Alert source: `ml`
- `/api/v1/alerts?source=ml`: `200`, first result is the live alert
- `/api/v1/timeline`: `200`, includes event `5305aa7e-7a7e-432b-970b-979ff9fd7dbf`
- `/app/alerts`, `/app/alerts/:id`, `/app/events`: `200`

## Runtime Notes

The Windows smoke required these DLLs in the scanner directory:

- `onnxruntime.dll`
- `onnxruntime_providers_shared.dll`
- `vcruntime140.dll`
- `vcruntime140_1.dll`
- `msvcp140.dll`
- `msvcp140_1.dll`
- `msvcp140_2.dll`
- `concrt140.dll`

Agent-bound telemetry smoke command shape:

```powershell
cargo run --features onnx --bin ml_detection_telemetry_smoke -- `
  --config C:\ProgramData\Tamandua\config\agent.toml `
  --model C:\ProgramData\Tamandua\models\malware_smell_knn.onnx `
  --sample C:\ProgramData\Tamandua\ml-bench\samples\malware_00000.bin `
  --output C:\ProgramData\Tamandua\ml-bench\ml-telemetry-smoke.json
```

Use `--server-url`, `--agent-id`, and `--auth-token` only for lab override
runs. `TAMANDUA_AGENT_AUTH_TOKEN` is also accepted for the token override.

## Claim Boundary

Proven:

- The agent-side ONNX scanner can run on a Windows lab host.
- The KNN ONNX export can emit a malicious verdict on a staged malware fixture.
- The agent now has a compiled smoke binary that converts local ONNX detection
  into real agent telemetry.
- The lab backend accepts the ML telemetry over mTLS and creates a critical
  `source=ml` alert.
- The API/GUI source path now resolves the live telemetry alert as `source=ml`
  after metadata backfill and server-side source inference work.
- The lab backend continues to persist ML verdict events over mTLS after the
  server restart.

Not proven:

- Production model quality.
- Acceptable false-positive rate.
- WIN-TEMPLATE transport stability.
- Browser pixel/visual screenshot confirmation for the new `67048401...` alert.
- Fresh post-fix ML alert creation plus `alerts:feed` socket delivery in the
  same run.

Next work:

1. Retrain/calibrate using governed malware/goodware sources before publishing
   `tamandua-ml`.
2. Run the same smoke from inside LAB-DC01 or WIN-TEMPLATE once remote
   execution is available through a governed action.
3. Add an automated `alerts:feed` socket probe for the live ML alert path.
4. Use a non-deduplicated ML sample/run ID for the next socket proof so the
   backend creates or updates an alert during the probe window.

Follow-up evidence:

- `docs/benchmarks/ML_ALERT_API_GUI_EVIDENCE_20260625.md` contains the
  controlled proof and the refreshed live proof against alert
  `67048401-7bbf-4414-8b9c-a2a0b5d8362d`.
- `apps/tamandua_server/test/tamandua_server/telemetry/ml_agent_detection_alert_test.exs`
  covers the server-side contract: ML detection telemetry creates an ML alert
  and broadcasts `alerts:feed`.

Operational notes:

- The server requires mTLS for this agent credential. Plain `ws://...:4000`
  attempts are rejected with `:missing_certificate`.
- Live response `os_info` exposed a contract gap: the server supported the
  command but the agent enum did not, causing a timeout. The agent now maps
  `os_info` to a local OS information response.
