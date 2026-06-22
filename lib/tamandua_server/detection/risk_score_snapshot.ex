defmodule TamanduaServer.Detection.RiskScoreSnapshot do
  @moduledoc """
  Normalizer for the agent-side deterministic risk score snapshot
  (event_type = "behavioral_risk_score"), produced when the agent is
  compiled with the `export_risk_score` cargo feature AND runtime flag.

  Wire shape (because `EventPayload` is `#[serde(untagged)]` in
  `apps/tamandua_agent/src/collectors/mod.rs`, snapshot fields flatten
  directly into the JSON `payload`):

      {
        "event_id": "<uuid>",
        "event_type": "behavioral_risk_score",
        "timestamp": 1719000000000,
        "severity": "info",
        "payload": {
          "process_key": "powershell.exe",
          "pid": 12345,
          "score": 47.5,
          "last_update": 1719000000000,
          "snapshot_at": 1719000000010,
          "factors": [
            { "name": "office_shell_spawn", "score": 25.0, ... }
          ]
        }
      }

  Source of truth: `apps/tamandua_agent/src/analyzers/behavioral.rs:449`
  (`RiskScoreSnapshot` struct) and `:2032` (`export_risk_score_events`).

  Important: `score` is 0-100 on the agent. Server uses 0.0-1.0 threat
  scores; we normalize here and clamp to that range.
  """

  @type t :: %{
          process_key: String.t(),
          pid: non_neg_integer() | nil,
          score_0_1: float(),
          score_raw: float(),
          last_update_ms: non_neg_integer(),
          snapshot_at_ms: non_neg_integer(),
          factors: [map()]
        }

  @default_stale_ms 60_000

  @doc """
  Parse a `behavioral_risk_score` telemetry event into a normalized snapshot.

  Accepts both atom-key and string-key payloads (Broadway pipelines mix
  the two). Returns `:error` for malformed payloads — callers MUST
  no-op on `:error` rather than crash.
  """
  @spec from_event(map()) :: {:ok, t()} | :error
  def from_event(%{} = event) do
    payload = event[:payload] || event["payload"] || %{}

    with pk when is_binary(pk) <- payload[:process_key] || payload["process_key"],
         true <- String.trim(pk) != "",
         {:ok, score_raw} <- to_float(payload[:score] || payload["score"]) do
      {:ok,
       %{
         process_key: String.downcase(pk),
         pid: to_int(payload[:pid] || payload["pid"]),
         score_0_1: clamp01(score_raw / 100.0),
         score_raw: score_raw,
         last_update_ms: to_int(payload[:last_update] || payload["last_update"]) || 0,
         snapshot_at_ms: to_int(payload[:snapshot_at] || payload["snapshot_at"]) || 0,
         factors: List.wrap(payload[:factors] || payload["factors"] || [])
       }}
    else
      _ -> :error
    end
  end

  def from_event(_), do: :error

  @doc "Returns true when the snapshot is older than `now_ms - threshold_ms` (default 60s)."
  @spec stale?(t(), non_neg_integer(), non_neg_integer()) :: boolean()
  def stale?(snap, now_ms \\ nil, threshold_ms \\ @default_stale_ms) do
    now = now_ms || System.system_time(:millisecond)
    snap.snapshot_at_ms > 0 and now - snap.snapshot_at_ms > threshold_ms
  end

  @doc "Default staleness threshold in milliseconds."
  def default_stale_ms, do: @default_stale_ms

  defp clamp01(x) when is_float(x), do: max(0.0, min(1.0, x))
  defp clamp01(_), do: 0.0

  defp to_float(x) when is_float(x), do: {:ok, x}
  defp to_float(x) when is_integer(x), do: {:ok, x * 1.0}

  defp to_float(x) when is_binary(x) do
    case Float.parse(x) do
      {f, _} -> {:ok, f}
      _ -> :error
    end
  end

  defp to_float(_), do: :error

  defp to_int(nil), do: nil
  defp to_int(x) when is_integer(x), do: x
  defp to_int(x) when is_float(x), do: trunc(x)

  defp to_int(x) when is_binary(x) do
    case Integer.parse(x) do
      {i, _} -> i
      _ -> nil
    end
  end

  defp to_int(_), do: nil
end
