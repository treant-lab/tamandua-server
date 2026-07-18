defmodule TamanduaServer.Agents.PlatformVisibility do
  @moduledoc """
  Aggregates platform capability evidence into an explicit visibility health view.

  The summary is intentionally conservative: it only reports active visibility
  when an existing capability/data-source contract has observed evidence. Reported
  runtime/config signals degrade the view, and missing evidence remains
  unavailable.
  """

  alias TamanduaServer.Agents.PlatformCapabilities

  @statuses ~w(active degraded unavailable)

  @spec summarize(map(), keyword()) :: map()
  def summarize(agent, opts \\ []) when is_map(agent) do
    capabilities =
      Keyword.get_lazy(opts, :capabilities, fn ->
        PlatformCapabilities.for_agent(agent, opts)
      end)

    platform = platform(capabilities, agent)
    agent_health_visibility = Keyword.get(opts, :agent_health_visibility)
    evidence = evidence(capabilities, opts, agent_health_visibility)
    reasons = reasons(capabilities, evidence, agent_health_visibility)

    %{
      status: status(capabilities, evidence, agent_health_visibility),
      platform: platform,
      source:
        if(normalized_agent_health_status(agent_health_visibility),
          do: "agent_health_platform_visibility",
          else: "platform_capabilities"
        ),
      checked_at: normalize_timestamp(Keyword.get(opts, :checked_at)),
      evidence: evidence,
      reasons: reasons
    }
  end

  def statuses, do: @statuses

  defp status(capabilities, evidence, agent_health_visibility) do
    case normalized_agent_health_status(agent_health_visibility) do
      "active" -> "active"
      "degraded" -> "degraded"
      "unavailable" -> "unavailable"
      _ -> capability_status(capabilities, evidence)
    end
  end

  defp capability_status(_capabilities, %{observed_count: count}) when count > 0,
    do: "active"

  defp capability_status(_capabilities, %{reported_count: count}) when count > 0,
    do: "degraded"

  defp capability_status(capabilities, _evidence) do
    if Enum.any?(
         capabilities,
         &(map_get_any(&1, [:maturity, "maturity"]) in ["supported", "partial", "lab"])
       ) do
      "degraded"
    else
      "unavailable"
    end
  end

  defp evidence(capabilities, opts, agent_health_visibility) do
    observed = matching_capabilities(capabilities, "observed")
    reported = matching_capabilities(capabilities, "reported")

    unavailable =
      Enum.filter(capabilities, &(map_get_any(&1, [:status, "status"]) == "unavailable"))

    %{
      observed_count: length(observed),
      reported_count: length(reported),
      unavailable_count: length(unavailable),
      total_count: length(capabilities),
      observed_capabilities: capability_ids(observed),
      reported_capabilities: capability_ids(reported),
      unavailable_capabilities: capability_ids(unavailable),
      last_observed_at: evidence_timestamp(capabilities, opts),
      sources: evidence_sources(capabilities),
      agent_health_visibility: normalize_agent_health_visibility(agent_health_visibility)
    }
  end

  defp matching_capabilities(capabilities, observed) do
    Enum.filter(capabilities, fn capability ->
      map_get_any(capability, [:observed, "observed"]) == observed and
        map_get_any(capability, [:status, "status"]) != "unavailable"
    end)
  end

  defp capability_ids(capabilities),
    do: Enum.map(capabilities, &map_get_any(&1, [:id, "id"]))

  defp reasons(capabilities, evidence, agent_health_visibility) do
    case normalized_agent_health_status(agent_health_visibility) do
      "active" ->
        ["agent_health_platform_visibility_active"]

      "degraded" ->
        agent_health_reasons(agent_health_visibility, "agent_health_platform_visibility_degraded")

      "unavailable" ->
        agent_health_reasons(
          agent_health_visibility,
          "agent_health_platform_visibility_unavailable"
        )

      _ ->
        capability_reasons(capabilities, evidence)
    end
  end

  defp capability_reasons(_capabilities, %{observed_count: count}) when count > 0,
    do: ["observed_platform_visibility"]

  defp capability_reasons(_capabilities, %{reported_count: count}) when count > 0,
    do: ["reported_without_observed_telemetry"]

  defp capability_reasons(capabilities, _evidence) do
    cond do
      capabilities == [] ->
        ["no_platform_capability_contract"]

      Enum.all?(capabilities, &(map_get_any(&1, [:status, "status"]) == "unavailable")) ->
        ["platform_unavailable"]

      true ->
        ["no_visibility_evidence"]
    end
  end

  defp normalize_agent_health_visibility(nil), do: nil

  defp normalize_agent_health_visibility(value) when is_map(value) do
    %{
      status: normalized_agent_health_status(value),
      evidence_source: map_get_any(value, [:evidence_source, "evidence_source"]),
      active_sensors: map_get_any(value, [:active_sensors, "active_sensors"]) || [],
      degraded_sensors: map_get_any(value, [:degraded_sensors, "degraded_sensors"]) || [],
      unavailable_sensors:
        map_get_any(value, [:unavailable_sensors, "unavailable_sensors"]) || [],
      reasons: map_get_any(value, [:reasons, "reasons"]) || [],
      claim_boundary: map_get_any(value, [:claim_boundary, "claim_boundary"])
    }
  end

  defp normalize_agent_health_visibility(_value), do: nil

  defp normalized_agent_health_status(value) when is_map(value) do
    status = value |> map_get_any([:status, "status"]) |> to_string() |> String.downcase()
    if status in @statuses, do: status, else: nil
  end

  defp normalized_agent_health_status(_value), do: nil

  defp agent_health_reasons(value, fallback) when is_map(value) do
    case map_get_any(value, [:reasons, "reasons"]) do
      reasons when is_list(reasons) and reasons != [] -> Enum.map(reasons, &to_string/1)
      _ -> [fallback]
    end
  end

  defp agent_health_reasons(_value, fallback), do: [fallback]

  defp evidence_sources(capabilities) do
    capabilities
    |> Enum.flat_map(fn capability ->
      signals = map_get_any(capability, [:signals, "signals"]) || []
      Enum.map(signals, &map_get_any(&1, [:source, "source"]))
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp evidence_timestamp(capabilities, opts) do
    [
      Keyword.get(opts, :last_observed_at),
      Keyword.get(opts, :last_telemetry_at),
      Keyword.get(opts, :last_heartbeat_at),
      capability_timestamp(capabilities)
    ]
    |> Enum.find_value(&normalize_timestamp/1)
  end

  defp capability_timestamp(capabilities) do
    capabilities
    |> Enum.flat_map(fn capability ->
      [
        get_in(capability, [:session_broker, :observed_at]),
        get_in(capability, [:session_broker, "observed_at"])
        | signal_timestamps(map_get_any(capability, [:signals, "signals"]) || [])
      ]
    end)
    |> Enum.find(& &1)
  end

  defp signal_timestamps(signals) do
    Enum.flat_map(signals, fn signal ->
      [
        Map.get(signal, :observed_at),
        Map.get(signal, "observed_at"),
        Map.get(signal, :last_seen),
        Map.get(signal, "last_seen")
      ]
    end)
  end

  defp platform([%{platform: platform} | _], _agent), do: platform
  defp platform([%{"platform" => platform} | _], _agent), do: platform

  defp platform(_capabilities, agent) do
    agent
    |> Map.get(:os_type, Map.get(agent, "os_type"))
    |> to_string()
    |> String.downcase()
  end

  defp normalize_timestamp(nil), do: nil
  defp normalize_timestamp(%DateTime{} = timestamp), do: DateTime.to_iso8601(timestamp)
  defp normalize_timestamp(%NaiveDateTime{} = timestamp), do: NaiveDateTime.to_iso8601(timestamp)
  defp normalize_timestamp(timestamp) when is_binary(timestamp), do: timestamp

  defp normalize_timestamp(timestamp) when is_integer(timestamp) do
    unit = if timestamp > 10_000_000_000, do: :millisecond, else: :second

    case DateTime.from_unix(timestamp, unit) do
      {:ok, datetime} -> DateTime.to_iso8601(datetime)
      _ -> nil
    end
  end

  defp normalize_timestamp(_timestamp), do: nil

  defp map_get_any(map, keys) when is_map(map), do: Enum.find_value(keys, &Map.get(map, &1))
  defp map_get_any(_value, _keys), do: nil
end
