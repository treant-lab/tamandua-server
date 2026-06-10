defmodule TamanduaServer.Agents.PlatformCapabilities do
  @moduledoc """
  Conservative server-side platform capability contract for UI/API surfaces.

  This module intentionally does not inspect agent collector internals. It combines
  the agent OS, reported runtime/config, and coarse health signals into a stable
  maturity view that avoids implying full support where the current platform is
  partial, lab-only, or unavailable.
  """

  @levels ~w(supported partial lab unavailable)

  @capabilities [
    %{
      id: "endpoint_telemetry",
      name: "Endpoint telemetry",
      windows: "supported",
      linux: "partial",
      macos: "lab",
      unknown: "unavailable"
    },
    %{
      id: "kernel_sensor",
      name: "Kernel / platform sensor",
      windows: "lab",
      linux: "lab",
      macos: "lab",
      unknown: "unavailable"
    },
    %{
      id: "registry_telemetry",
      name: "Registry telemetry",
      windows: "supported",
      linux: "unavailable",
      macos: "unavailable",
      unknown: "unavailable"
    },
    %{
      id: "live_response",
      name: "Live response shell",
      windows: "partial",
      linux: "partial",
      macos: "lab",
      unknown: "unavailable"
    },
    %{
      id: "network_isolation",
      name: "Network isolation",
      windows: "partial",
      linux: "partial",
      macos: "lab",
      unknown: "unavailable"
    },
    %{
      id: "prevention_policy",
      name: "Prevention policy enforcement",
      windows: "partial",
      linux: "partial",
      macos: "lab",
      unknown: "unavailable"
    }
  ]

  @spec for_agent(map(), keyword()) :: [map()]
  def for_agent(agent, opts \\ []) when is_map(agent) do
    os = normalize_os(Map.get(agent, :os_type) || Map.get(agent, "os_type"))
    health = Keyword.get(opts, :health) || %{}
    agent_status = Keyword.get(opts, :status) || Map.get(agent, :status) || Map.get(agent, "status")
    config = Keyword.get(opts, :config) || Map.get(agent, :config) || Map.get(agent, "config") || %{}
    collectors = Keyword.get(opts, :collectors) || []
    data_sources = Keyword.get(opts, :data_sources) || %{}

    Enum.map(@capabilities, fn capability ->
      maturity = Map.fetch!(capability, os)
      observed =
        observed_state(capability.id, os, health, config, collectors, data_sources, agent_status)

      %{
        id: capability.id,
        name: capability.name,
        platform: Atom.to_string(os),
        maturity: maturity,
        status: capability_status(maturity, observed),
        observed: observed,
        detail: capability_detail(maturity, observed)
      }
    end)
  end

  def levels, do: @levels

  defp normalize_os(os) do
    value = os |> to_string() |> String.downcase()

    cond do
      String.contains?(value, "windows") -> :windows
      String.contains?(value, "linux") -> :linux
      String.contains?(value, "mac") or String.contains?(value, "darwin") -> :macos
      true -> :unknown
    end
  end

  defp observed_state("endpoint_telemetry", _os, health, _config, collectors, data_sources, agent_status) do
    active_collectors = Enum.count(collectors, &collector_active?/1)
    active_sources = Enum.count(data_sources, fn {_source, count} -> numeric?(count) and count > 0 end)

    cond do
      active_sources > 0 -> "observed"
      active_collectors > 0 -> "reported"
      online_runtime?(agent_status, health) -> "reported"
      true -> "not_observed"
    end
  end

  defp observed_state("kernel_sensor", _os, health, _config, _collectors, _data_sources, _agent_status) do
    driver = map_get_any(health, [:driver_status, "driver_status"])
    platform_status = map_get_any(health, [:platform_status, "platform_status"]) || []

    cond do
      driver_connected?(driver) -> "observed"
      Enum.any?(platform_status, &sensor_running?/1) -> "observed"
      not is_nil(driver) or platform_status != [] -> "reported"
      true -> "not_observed"
    end
  end

  defp observed_state("registry_telemetry", _os, _health, _config, collectors, data_sources, _agent_status) do
    source_count = Map.get(data_sources, "registry") || Map.get(data_sources, :registry) || 0

    cond do
      numeric?(source_count) and source_count > 0 -> "observed"
      Enum.any?(collectors, &(collector_name(&1) == "registry" and collector_active?(&1))) -> "reported"
      true -> "not_observed"
    end
  end

  defp observed_state("live_response", _os, health, config, _collectors, _data_sources, agent_status) do
    reported = reported_capabilities(config)

    cond do
      Enum.any?(reported, &(&1 in ["live_response", "remote_shell", "shell"])) -> "reported"
      online_runtime?(agent_status, health) -> "reported"
      true -> "not_observed"
    end
  end

  defp observed_state("network_isolation", _os, _health, config, _collectors, _data_sources, _agent_status) do
    reported = reported_capabilities(config)

    if Enum.any?(reported, &(&1 in ["network_isolation", "isolate", "containment"])),
      do: "reported",
      else: "not_observed"
  end

  defp observed_state("prevention_policy", _os, _health, config, _collectors, _data_sources, _agent_status) do
    response_config = map_get_any(config, ["response", :response]) || %{}
    reported = reported_capabilities(config)

    cond do
      truthy?(map_get_any(response_config, ["auto_response_enabled", :auto_response_enabled])) ->
        "reported"

      Enum.any?(reported, &(&1 in ["prevention", "quarantine", "kill_process", "restore_file"])) ->
        "reported"

      true ->
        "not_observed"
    end
  end

  defp capability_status("unavailable", _observed), do: "unavailable"
  defp capability_status(maturity, "observed"), do: maturity
  defp capability_status(maturity, "reported"), do: maturity
  defp capability_status("supported", "not_observed"), do: "partial"
  defp capability_status(maturity, "not_observed"), do: maturity

  defp capability_detail("unavailable", _observed), do: "Not available for this OS."
  defp capability_detail(maturity, "observed"), do: "Observed from live health or telemetry signals; maturity remains #{maturity}."
  defp capability_detail(maturity, "reported"), do: "Reported by agent runtime/config; maturity remains #{maturity}."
  defp capability_detail(maturity, "not_observed"), do: "No live signal observed; maturity remains #{maturity}."

  defp online_runtime?(agent_status, health) do
    online_status?(agent_status) and not critical_health?(health)
  end

  defp online_status?(status) do
    normalized =
      status
      |> to_string()
      |> String.downcase()

    normalized in ["online", "isolated"]
  end

  defp critical_health?(health) when is_map(health) do
    normalized =
      health
      |> map_get_any([:status, "status"])
      |> to_string()
      |> String.downcase()

    normalized in ["critical", "unknown", "offline"]
  end

  defp critical_health?(_), do: false

  defp collector_active?(collector) when is_map(collector) do
    status =
      collector
      |> map_get_any([:status, "status"])
      |> to_string()
      |> String.downcase()

    events = map_get_any(collector, [:events_collected, "events_collected"]) || 0
    status in ["running", "active", "healthy", "enabled"] or (numeric?(events) and events > 0)
  end

  defp collector_active?(_), do: false

  defp collector_name(collector) when is_map(collector) do
    collector
    |> map_get_any([:name, "name"])
    |> to_string()
    |> String.downcase()
    |> String.replace("-", "_")
  end

  defp collector_name(_), do: ""

  defp driver_connected?(driver) when is_map(driver) do
    truthy?(map_get_any(driver, [:connected, "connected"])) or
      map_get_any(driver, [:state, "state"]) in ["loaded", :loaded]
  end

  defp driver_connected?(_), do: false

  defp sensor_running?(sensor) when is_map(sensor),
    do: truthy?(map_get_any(sensor, [:running, "running"]))

  defp sensor_running?(_), do: false

  defp reported_capabilities(config) do
    case map_get_any(config, ["reported_capabilities", :reported_capabilities]) do
      capabilities when is_list(capabilities) ->
        Enum.map(capabilities, &normalize_capability/1)

      capabilities when is_map(capabilities) ->
        capabilities
        |> Enum.filter(fn {_name, value} -> value not in [false, nil] end)
        |> Enum.map(fn {name, _value} -> normalize_capability(name) end)

      _ ->
        []
    end
  end

  defp normalize_capability(value) do
    value
    |> to_string()
    |> String.downcase()
    |> String.replace("-", "_")
  end

  defp map_get_any(nil, _keys), do: nil

  defp map_get_any(map, keys) when is_map(map) do
    Enum.find_value(keys, &Map.get(map, &1))
  end

  defp map_get_any(_value, _keys), do: nil

  defp truthy?(value) when value in [true, "true", 1, "1"], do: true
  defp truthy?(_), do: false

  defp numeric?(value), do: is_integer(value) or is_float(value)
end
