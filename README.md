# Tamandua Server

Backend for the [Tamandua EDR](https://github.com/treant-lab) platform. Built with
Elixir / Phoenix and Broadway pipelines. Ingests agent telemetry over WebSocket
channels, runs the detection engine (YARA, Sigma, ML), manages alerts and
response actions, and serves a LiveView dashboard.

## Overview

```
[Agent] --WebSocket--> [Phoenix Channel] --> [Broadway Pipeline]
                                                     |
[YARA/Sigma Rules] <- [Detection Engine] <- [ML Service]
        |                    |
    [Alerts] <----------> [Response Actions] --> [Agent Commands]
        |
   [Dashboard]
```

Key modules (`lib/tamandua_server/`): `telemetry/` (Broadway ingestor),
`detection/` (YARA/Sigma/ML engine + `SigmaAggregator` GenServer),
`response/` (executor), `alerts/`, `agents/` (registry + workers).

The Rust NIF (`apps/tamandua_nif`, YARA scanning and native helpers) ships
**inside** this repository and is compiled via `rustler` during `mix compile`.

## Prerequisites

- Elixir `~> 1.14` and a matching Erlang/OTP.
- A Rust toolchain (for the bundled NIF).
- PostgreSQL, Redis, and RabbitMQ (see `docker-compose.yml`).

> **Build platform:** the canonical build/test gate is **Linux**. The Elixir
> stack (including `bcrypt`) is not built/tested on Windows hosts.

## Build

```bash
mix deps.get
mix compile
```

## Test

```bash
mix test
mix test test/tamandua_server/detection_test.exs   # a single file
mix format --check-formatted                        # formatting
mix dialyzer                                         # type checking
```

CI provisions PostgreSQL + Redis + RabbitMQ as services and runs the suite plus
Dialyzer on a Linux runner.

## Run

```bash
mix phx.server
```

Environment variables:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | e.g. `postgres://localhost/tamandua_dev` |
| `REDIS_URL` | e.g. `redis://localhost:6379` |
| `ML_SERVICE_URL` | e.g. `http://localhost:8000` |

## Detection rules

- YARA rules live in `priv/yara_rules/`.
- Sigma rules live in `priv/sigma_rules/`.
- Reload at runtime via `Detection.reload_rules()`.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Run `mix format`, `mix test`, and
`mix dialyzer` before opening a PR.

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
