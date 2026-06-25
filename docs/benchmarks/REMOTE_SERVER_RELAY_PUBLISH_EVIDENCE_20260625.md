# Remote Server Relay Publish Evidence - 2026-06-25

## Scope

Published the server image containing the cross-runtime alert relay and agent presence fixes to the remote lab runtime at `192.168.12.146`.

This is server/API/GUI publication evidence. It is not a claim that the current ML model is production-ready.

## Published Runtime

- Container: `tamandua-server-light`
- Image tag: `docker_server:latest`
- Loaded image id: `sha256:9905734f009b93609698c141e7ed18bc1a0a7ed92fcbe42738bce15c2f1ac85a`
- Previous image backup tag: `docker_server:pre-local-relay-20260625T133930`
- Health after recreate:
  - `/health/live`: `200`
  - `/health`: `200`

The remote runtime was verified to include:

- `TamanduaServer.Alerts.AlertBroadcastRelay`
- `TamanduaServer.Alerts.AlertBroadcastRelay.notify_new_alert/1`
- recent persisted heartbeat handling in `AgentController`
- recent persisted presence handling in `Agents`

## Evidence Artifacts

- `.tmp/alerts_feed_socket_probe_remote_after_publish_triggered.json`
- `.tmp/ml_alert_api_gui_probe_remote_after_publish.json`

## Alerts Feed Relay

Probe:

```powershell
python .tmp\alerts_feed_socket_probe.py --server http://192.168.12.146:4000 --output .tmp\alerts_feed_socket_probe_remote_after_publish_triggered.json --timeout 30 --trigger-command 'python .tmp\remote_146_pg_notify_alert.py a7e750d0-6566-42ca-acac-f67cd6cf461a new_alert'
```

Result:

- authenticated dashboard session: yes
- socket token extracted: yes
- joined `alerts:feed`: yes
- received `new_alert`: yes
- alert id: `a7e750d0-6566-42ca-acac-f67cd6cf461a`
- agent id: `c5706989-46e8-4ecb-9feb-75c5f3a42f1a`
- title: `ML Detection: ML_MALWARE_TROJAN_SOCKET_20260625091550`
- verdict: `received_live_ml_alert=true`

Claim boundary: this proves the remote dashboard runtime receives and rebroadcasts alert notifications from PostgreSQL. The trigger used a controlled `pg_notify` for an existing ML alert.

## API, GUI, Events, Timeline

Probe:

```powershell
$env:TAMANDUA_SERVER='http://192.168.12.146:4000'; python .tmp\ml_alert_api_gui_probe.py
```

Result:

- `GET /api/v1/alerts/d9eadbc6-dcc2-41d2-8e4a-1d020665f19f`: `200`
- `GET /api/v1/alerts?source=ml&per_page=5`: `200`
- `GET /api/v1/events?...`: `200`
- `GET /api/v1/timeline?...`: `200`
- `/app/alerts`: `200`
- `/app/alerts/d9eadbc6-dcc2-41d2-8e4a-1d020665f19f`: `200`
- `/app/events`: `200`

Verdict from probe:

- `alert_api_source_ml=true`
- `alerts_filter_source_ml_ok=true`
- `events_api_ok=true`
- `timeline_api_ok=true`
- `gui_alerts_http_ok=true`
- `gui_events_http_ok=true`

## Operational Notes

An attempted in-container hotpatch was rejected as the deployment path because this image runs `mix phx.server --no-compile`; changing source files in a live container can desynchronize source and compiled BEAM files.

An attempted remote Docker build also stalled in `mix compile` on the remote host. The final publish path used the already validated local image:

1. `docker save tamandua-server-current-relay:local`
2. SFTP tar to remote
3. `docker load`
4. `docker tag tamandua-server-current-relay:local docker_server:latest`
5. `docker-compose ... up -d --force-recreate --no-deps server`

## Remaining ML Boundary

The current ONNX smoke still shows unacceptable goodware false positives:

- malware detection: `25/25`
- goodware false positives: `22/25`
- FPR: `88%`

Therefore the server relay/front/API publication is valid, but ML model publication remains blocked for production claims until a real benchmark dataset and threshold/calibration pass are completed.
