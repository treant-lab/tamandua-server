defmodule TamanduaServer.Agents.PlatformCapabilities do
  @moduledoc """
  Conservative server-side platform capability contract for UI/API surfaces.

  This module intentionally does not inspect agent collector internals. It combines
  the agent OS, reported runtime/config, and coarse health signals into a stable
  maturity view that avoids implying full support where the current platform is
  partial, lab-only, or unavailable.
  """

  @levels ~w(supported partial lab unavailable)

  alias TamanduaServer.LiveResponse.{ScreenCapturePolicy, ScreenSessionBroker}

  @capabilities [
    %{
      id: "endpoint_telemetry",
      name: "Endpoint telemetry",
      windows: "supported",
      linux: "partial",
      macos: "lab",
      android: "partial",
      ios: "partial",
      unknown: "unavailable"
    },
    %{
      id: "kernel_sensor",
      name: "Kernel / platform sensor",
      windows: "lab",
      linux: "lab",
      macos: "lab",
      android: "unavailable",
      ios: "unavailable",
      unknown: "unavailable"
    },
    %{
      id: "registry_telemetry",
      name: "Registry telemetry",
      windows: "supported",
      linux: "unavailable",
      macos: "unavailable",
      android: "unavailable",
      ios: "unavailable",
      unknown: "unavailable"
    },
    %{
      id: "virtualization_host",
      name: "Virtualization host",
      windows: "unavailable",
      linux: "lab",
      macos: "unavailable",
      android: "unavailable",
      ios: "unavailable",
      unknown: "unavailable"
    },
    %{
      id: "runtime_rx_page_content",
      name: "Runtime RX page-content integrity (Preview)",
      windows: "unavailable",
      linux: "lab",
      macos: "unavailable",
      android: "unavailable",
      ios: "unavailable",
      unknown: "unavailable"
    },
    %{
      id: "mobile_posture",
      name: "Mobile posture",
      windows: "unavailable",
      linux: "unavailable",
      macos: "unavailable",
      android: "supported",
      ios: "supported",
      unknown: "unavailable"
    },
    %{
      id: "app_inventory",
      name: "App inventory",
      windows: "unavailable",
      linux: "unavailable",
      macos: "unavailable",
      android: "partial",
      ios: "partial",
      unknown: "unavailable"
    },
    %{
      id: "app_guard",
      name: "App Guard / RASP",
      windows: "unavailable",
      linux: "unavailable",
      macos: "unavailable",
      android: "partial",
      ios: "partial",
      unknown: "unavailable"
    },
    %{
      id: "commercial_spyware",
      name: "Protected-app risk indicators",
      windows: "unavailable",
      linux: "unavailable",
      macos: "unavailable",
      android: "lab",
      ios: "lab",
      unknown: "unavailable"
    },
    %{
      id: "live_response",
      name: "Live response shell",
      windows: "partial",
      linux: "partial",
      macos: "lab",
      android: "unavailable",
      ios: "unavailable",
      unknown: "unavailable"
    },
    %{
      id: "screen_capture",
      name: "On-demand screen snapshot",
      windows: "lab",
      linux: "lab",
      macos: "lab",
      android: "unavailable",
      ios: "unavailable",
      unknown: "unavailable"
    },
    %{
      id: "network_isolation",
      name: "Network isolation",
      windows: "partial",
      linux: "partial",
      macos: "lab",
      android: "unavailable",
      ios: "unavailable",
      unknown: "unavailable"
    },
    %{
      id: "prevention_policy",
      name: "Prevention policy enforcement",
      windows: "partial",
      linux: "partial",
      macos: "lab",
      android: "partial",
      ios: "partial",
      unknown: "unavailable"
    }
  ]

  @spec for_agent(map(), keyword()) :: [map()]
  def for_agent(agent, opts \\ []) when is_map(agent) do
    os = normalize_os(Map.get(agent, :os_type) || Map.get(agent, "os_type"))
    health = Keyword.get(opts, :health) || %{}

    agent_status =
      Keyword.get(opts, :status) || Map.get(agent, :status) || Map.get(agent, "status")

    config =
      Keyword.get(opts, :config) || Map.get(agent, :config) || Map.get(agent, "config") || %{}

    collectors = Keyword.get(opts, :collectors) || []

    data_sources = Keyword.get(opts, :data_sources) || %{}

    runtime_integrity_preview =
      Keyword.get(opts, :runtime_integrity_preview) ||
        Map.get(data_sources, :runtime_integrity_preview) ||
        Map.get(data_sources, "runtime_integrity_preview")

    data_sources =
      if runtime_integrity_preview do
        Map.put(data_sources, :runtime_integrity_preview, runtime_integrity_preview)
      else
        data_sources
      end

    agent_id = Map.get(agent, :id) || Map.get(agent, "id") || "unknown"

    screen_capture_policy =
      Keyword.get(opts, :screen_capture_policy) ||
        ScreenCapturePolicy.normalize(to_string(agent_id), %{})

    Enum.map(@capabilities, fn capability ->
      maturity = Map.fetch!(capability, os)

      observed =
        observed_state(capability.id, os, health, config, collectors, data_sources, agent_status)

      signals =
        capability_signals(
          capability.id,
          os,
          maturity,
          observed,
          health,
          config,
          collectors,
          data_sources,
          agent_status
        )

      %{
        id: capability.id,
        name: capability.name,
        platform: Atom.to_string(os),
        maturity: maturity,
        status: capability_status(capability.id, maturity, observed),
        observed: observed,
        evidence: %{
          decision: observed,
          signals: signals
        },
        signals: signals,
        detail: capability_detail(maturity, observed)
      }
      |> maybe_put_preview_stage(capability.id)
      |> maybe_put_runtime_preview_contract(
        capability.id,
        os,
        runtime_integrity_preview
      )
      |> maybe_put_screen_capture_contract(capability.id, os, config, screen_capture_policy)
    end)
  end

  def levels, do: @levels

  defp maybe_put_preview_stage(capability, "runtime_rx_page_content"),
    do: Map.put(capability, :release_stage, "preview")

  defp maybe_put_preview_stage(capability, _id), do: capability

  defp maybe_put_runtime_preview_contract(
         capability,
         "runtime_rx_page_content",
         :linux,
         preview
       ) do
    {status, observed} =
      case preview do
        %{schema: schema, status: page_status}
        when schema in [
               "tamandua.runtime_integrity_preview/v1",
               "tamandua.runtime_integrity_preview/v2"
             ] and page_status in ["clean", "partial", "mismatch"] ->
          {"lab", "observed"}

        %{schema: schema, status: "degraded"}
        when schema in [
               "tamandua.runtime_integrity_preview/v1",
               "tamandua.runtime_integrity_preview/v2"
             ] ->
          {"partial", "observed"}

        %{schema: schema, status: page_status}
        when schema in [
               "tamandua.runtime_integrity_preview/v1",
               "tamandua.runtime_integrity_preview/v2"
             ] and page_status in ["disabled", "unsupported"] ->
          {"unavailable", "reported"}

        _ ->
          {"unavailable", "not_observed"}
      end

    capability
    |> Map.put(:status, status)
    |> Map.put(:observed, observed)
    |> put_in([:evidence, :decision], observed)
    |> Map.put(:detail, capability_detail("lab", observed))
  end

  defp maybe_put_runtime_preview_contract(capability, "runtime_rx_page_content", _os, _preview) do
    capability
    |> Map.put(:status, "unavailable")
    |> Map.put(:observed, "not_observed")
    |> put_in([:evidence, :decision], "not_observed")
  end

  defp maybe_put_runtime_preview_contract(capability, _id, _os, _preview), do: capability

  defp maybe_put_screen_capture_contract(capability, "screen_capture", os, config, policy) do
    broker = ScreenSessionBroker.status(os, config)

    operational? =
      broker.state in ["ready", "consent_required"] and policy.mode != "disabled" and
        ScreenCapturePolicy.usable?(policy)

    capability
    |> Map.put(:session_broker, broker)
    |> Map.put(:screen_capture_policy, policy)
    |> Map.put(:status, if(operational?, do: capability.status, else: "unavailable"))
    |> Map.put(
      :detail,
      if(operational?,
        do: capability.detail,
        else: screen_capture_unavailable_detail(broker, policy)
      )
    )
  end

  defp maybe_put_screen_capture_contract(capability, _id, _os, _config, _policy), do: capability

  defp screen_capture_unavailable_detail(_broker, %{mode: "disabled"}),
    do: "Effective screen capture policy is disabled or missing."

  defp screen_capture_unavailable_detail(broker, _policy), do: broker.detail

  defp normalize_os(os) do
    value = os |> to_string() |> String.downcase()

    cond do
      String.contains?(value, "windows") ->
        :windows

      String.contains?(value, "linux") ->
        :linux

      String.contains?(value, "mac") or String.contains?(value, "darwin") ->
        :macos

      String.contains?(value, "android") ->
        :android

      String.contains?(value, "ios") or String.contains?(value, "iphone") or
          String.contains?(value, "ipad") ->
        :ios

      true ->
        :unknown
    end
  end

  defp observed_state(
         "endpoint_telemetry",
         _os,
         health,
         _config,
         collectors,
         data_sources,
         agent_status
       ) do
    active_collectors = Enum.count(collectors, &collector_active?/1)

    active_sources =
      Enum.count(data_sources, fn {_source, count} -> numeric?(count) and count > 0 end)

    cond do
      active_sources > 0 -> "observed"
      active_collectors > 0 -> "reported"
      online_runtime?(agent_status, health) -> "reported"
      true -> "not_observed"
    end
  end

  defp observed_state(
         "kernel_sensor",
         _os,
         health,
         _config,
         _collectors,
         _data_sources,
         _agent_status
       ) do
    driver = map_get_any(health, [:driver_status, "driver_status"])
    platform_status = map_get_any(health, [:platform_status, "platform_status"]) || []

    cond do
      driver_connected?(driver) -> "observed"
      Enum.any?(platform_status, &sensor_running?/1) -> "observed"
      not is_nil(driver) or platform_status != [] -> "reported"
      true -> "not_observed"
    end
  end

  defp observed_state(
         "registry_telemetry",
         _os,
         _health,
         _config,
         collectors,
         data_sources,
         _agent_status
       ) do
    source_count = Map.get(data_sources, "registry") || Map.get(data_sources, :registry) || 0

    cond do
      numeric?(source_count) and source_count > 0 ->
        "observed"

      Enum.any?(collectors, &(collector_name(&1) == "registry" and collector_active?(&1))) ->
        "reported"

      true ->
        "not_observed"
    end
  end

  defp observed_state(
         "virtualization_host",
         :linux,
         _health,
         config,
         collectors,
         data_sources,
         _agent_status
       ) do
    source_count = Map.get(data_sources, "proxmox") || Map.get(data_sources, :proxmox) || 0
    reported = reported_capabilities(config)

    cond do
      numeric?(source_count) and source_count > 0 ->
        "observed"

      Enum.any?(collectors, &(collector_name(&1) == "proxmox" and collector_active?(&1))) ->
        "reported"

      Enum.any?(reported, &(&1 in ["virtualization_host", "proxmox"])) ->
        "reported"

      true ->
        "not_observed"
    end
  end

  defp observed_state(
         "virtualization_host",
         _os,
         _health,
         _config,
         _collectors,
         _data_sources,
         _agent_status
       ),
       do: "not_observed"

  defp observed_state(
         "runtime_rx_page_content",
         :linux,
         _health,
         _config,
         _collectors,
         data_sources,
         _agent_status
       ) do
    case Map.get(data_sources, :runtime_integrity_preview) do
      %{schema: schema, status: status}
      when schema in [
             "tamandua.runtime_integrity_preview/v1",
             "tamandua.runtime_integrity_preview/v2"
           ] and
             status in ["clean", "partial", "mismatch", "degraded"] ->
        "observed"

      %{schema: schema, status: status}
      when schema in [
             "tamandua.runtime_integrity_preview/v1",
             "tamandua.runtime_integrity_preview/v2"
           ] and
             status in ["disabled", "unsupported"] ->
        "reported"

      _ ->
        "not_observed"
    end
  end

  defp observed_state(
         "runtime_rx_page_content",
         _os,
         _health,
         _config,
         _collectors,
         _data_sources,
         _agent_status
       ),
       do: "not_observed"

  defp observed_state(
         "mobile_posture",
         os,
         health,
         config,
         _collectors,
         _data_sources,
         agent_status
       )
       when os in [:android, :ios] do
    cond do
      online_runtime?(agent_status, health) -> "reported"
      mobile_source?(config) -> "reported"
      true -> "not_observed"
    end
  end

  defp observed_state(
         "mobile_posture",
         _os,
         _health,
         _config,
         _collectors,
         _data_sources,
         _agent_status
       ),
       do: "not_observed"

  defp observed_state(
         "app_inventory",
         os,
         _health,
         config,
         collectors,
         data_sources,
         _agent_status
       )
       when os in [:android, :ios] do
    app_sources =
      ["mobile_app_inventory", :mobile_app_inventory, "app_inventory", :app_inventory]
      |> Enum.map(&Map.get(data_sources, &1, 0))
      |> Enum.any?(&(numeric?(&1) and &1 > 0))

    cond do
      app_sources ->
        "observed"

      Enum.any?(
        collectors,
        &(collector_name(&1) in ["app_inventory", "mobile_app_inventory"] and
              collector_active?(&1))
      ) ->
        "reported"

      mobile_source?(config) ->
        "reported"

      true ->
        "not_observed"
    end
  end

  defp observed_state(
         "app_inventory",
         _os,
         _health,
         _config,
         _collectors,
         _data_sources,
         _agent_status
       ),
       do: "not_observed"

  defp observed_state("app_guard", os, _health, config, collectors, data_sources, _agent_status)
       when os in [:android, :ios] do
    app_guard_sources =
      ["mobile_events", :mobile_events, "app_guard", :app_guard]
      |> Enum.map(&Map.get(data_sources, &1, 0))
      |> Enum.any?(&(numeric?(&1) and &1 > 0))

    reported = reported_capabilities(config)

    cond do
      app_guard_sources ->
        "observed"

      Enum.any?(
        collectors,
        &(collector_name(&1) in ["app_guard", "rasp"] and collector_active?(&1))
      ) ->
        "reported"

      Enum.any?(reported, &(&1 in ["app_guard", "rasp", "mobile_rasp"])) ->
        "reported"

      mobile_source?(config) ->
        "reported"

      true ->
        "not_observed"
    end
  end

  defp observed_state(
         "app_guard",
         _os,
         _health,
         _config,
         _collectors,
         _data_sources,
         _agent_status
       ),
       do: "not_observed"

  defp observed_state(
         "commercial_spyware",
         os,
         _health,
         config,
         collectors,
         data_sources,
         _agent_status
       )
       when os in [:android, :ios] do
    spyware_sources =
      [
        "spyware",
        :spyware,
        "commercial_spyware",
        :commercial_spyware,
        "mobile_events",
        :mobile_events
      ]
      |> Enum.map(&Map.get(data_sources, &1, 0))
      |> Enum.any?(&(numeric?(&1) and &1 > 0))

    reported = reported_capabilities(config)

    cond do
      spyware_sources ->
        "observed"

      Enum.any?(
        collectors,
        &(collector_name(&1) in ["commercial_spyware", "spyware"] and collector_active?(&1))
      ) ->
        "reported"

      Enum.any?(reported, &(&1 in ["commercial_spyware", "spyware", "pegasus", "predator"])) ->
        "reported"

      true ->
        "not_observed"
    end
  end

  defp observed_state(
         "commercial_spyware",
         _os,
         _health,
         _config,
         _collectors,
         _data_sources,
         _agent_status
       ),
       do: "not_observed"

  defp observed_state(
         "live_response",
         _os,
         health,
         config,
         _collectors,
         _data_sources,
         agent_status
       ) do
    reported = reported_capabilities(config)

    cond do
      Enum.any?(
        reported,
        &(&1 in ["live_response", "remote_shell", "shell", "remote_query", "osquery_query"])
      ) ->
        "reported"

      online_runtime?(agent_status, health) ->
        "reported"

      true ->
        "not_observed"
    end
  end

  defp observed_state(
         "screen_capture",
         _os,
         _health,
         config,
         _collectors,
         _data_sources,
         _agent_status
       ) do
    reported = reported_capabilities(config)

    if Enum.any?(reported, &(&1 in ["screen_capture", "screen_snapshot"])),
      do: "reported",
      else: "not_observed"
  end

  defp observed_state(
         "network_isolation",
         _os,
         _health,
         config,
         _collectors,
         _data_sources,
         _agent_status
       ) do
    reported = reported_capabilities(config)

    if Enum.any?(reported, &(&1 in ["network_isolation", "isolate", "containment"])),
      do: "reported",
      else: "not_observed"
  end

  defp observed_state(
         "prevention_policy",
         _os,
         _health,
         config,
         _collectors,
         _data_sources,
         _agent_status
       ) do
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

  # Screen capture is privacy-sensitive and must fail closed. Platform maturity
  # alone never enables the action; a compatible runtime has to advertise it.
  defp capability_status("screen_capture", _maturity, "not_observed"), do: "unavailable"
  defp capability_status(_capability_id, "unavailable", _observed), do: "unavailable"
  defp capability_status(_capability_id, maturity, "observed"), do: maturity
  defp capability_status(_capability_id, maturity, "reported"), do: maturity
  defp capability_status(_capability_id, "supported", "not_observed"), do: "partial"
  defp capability_status(_capability_id, maturity, "not_observed"), do: maturity

  defp capability_detail("unavailable", _observed), do: "Not available for this OS."

  defp capability_detail(maturity, "observed"),
    do: "Observed from live health or telemetry signals; maturity remains #{maturity}."

  defp capability_detail(maturity, "reported"),
    do: "Reported by agent runtime/config; maturity remains #{maturity}."

  defp capability_detail(maturity, "not_observed"),
    do: "No live signal observed; maturity remains #{maturity}."

  defp capability_signals(
         capability_id,
         os,
         maturity,
         observed,
         health,
         config,
         collectors,
         data_sources,
         agent_status
       ) do
    [
      platform_default_signal(capability_id, os, maturity),
      decision_signals(capability_id, os, health, config, collectors, data_sources, agent_status),
      fallback_signal(observed)
    ]
    |> List.flatten()
    |> Enum.reject(&is_nil/1)
  end

  defp platform_default_signal(capability_id, os, maturity) do
    %{
      type: "platform_default",
      source: "server_capability_matrix",
      capability_id: capability_id,
      platform: Atom.to_string(os),
      value: maturity,
      signal: "default"
    }
  end

  defp decision_signals(
         "endpoint_telemetry",
         _os,
         health,
         _config,
         collectors,
         data_sources,
         agent_status
       ) do
    [
      data_source_signals(:all, data_sources),
      collector_signals(:active, collectors),
      runtime_signal(agent_status, health)
    ]
  end

  defp decision_signals(
         "kernel_sensor",
         _os,
         health,
         _config,
         _collectors,
         _data_sources,
         _agent_status
       ) do
    health_signal("kernel_sensor", health)
  end

  defp decision_signals(
         "registry_telemetry",
         _os,
         _health,
         _config,
         collectors,
         data_sources,
         _agent_status
       ) do
    [
      data_source_signals(["registry"], data_sources),
      collector_signals(["registry"], collectors)
    ]
  end

  defp decision_signals(
         "virtualization_host",
         :linux,
         _health,
         config,
         collectors,
         data_sources,
         _agent_status
       ) do
    [
      data_source_signals(["proxmox"], data_sources),
      collector_signals(["proxmox"], collectors),
      reported_capability_signals(["virtualization_host", "proxmox"], config)
    ]
  end

  defp decision_signals(
         "virtualization_host",
         _os,
         _health,
         _config,
         _collectors,
         _data_sources,
         _agent_status
       ),
       do: []

  defp decision_signals(
         "runtime_rx_page_content",
         :linux,
         _health,
         _config,
         _collectors,
         data_sources,
         _agent_status
       ) do
    case Map.get(data_sources, :runtime_integrity_preview) do
      %{schema: schema, status: status}
      when schema in [
             "tamandua.runtime_integrity_preview/v1",
             "tamandua.runtime_integrity_preview/v2"
           ] ->
        %{
          type: "preview_observation",
          source: "runtime_integrity_preview",
          value: status,
          signal: if(status in ["disabled", "unsupported"], do: "reported", else: "observed")
        }

      _ ->
        []
    end
  end

  defp decision_signals(
         "runtime_rx_page_content",
         _os,
         _health,
         _config,
         _collectors,
         _data_sources,
         _agent_status
       ),
       do: []

  defp decision_signals(
         "mobile_posture",
         os,
         health,
         config,
         _collectors,
         _data_sources,
         agent_status
       )
       when os in [:android, :ios] do
    [
      runtime_signal(agent_status, health),
      mobile_source_signal(config)
    ]
  end

  defp decision_signals(
         "mobile_posture",
         _os,
         _health,
         _config,
         _collectors,
         _data_sources,
         _agent_status
       ),
       do: []

  defp decision_signals(
         "app_inventory",
         os,
         _health,
         config,
         collectors,
         data_sources,
         _agent_status
       )
       when os in [:android, :ios] do
    [
      data_source_signals(["mobile_app_inventory", "app_inventory"], data_sources),
      collector_signals(["app_inventory", "mobile_app_inventory"], collectors),
      mobile_source_signal(config)
    ]
  end

  defp decision_signals(
         "app_inventory",
         _os,
         _health,
         _config,
         _collectors,
         _data_sources,
         _agent_status
       ),
       do: []

  defp decision_signals("app_guard", os, _health, config, collectors, data_sources, _agent_status)
       when os in [:android, :ios] do
    [
      data_source_signals(["mobile_events", "app_guard"], data_sources),
      collector_signals(["app_guard", "rasp"], collectors),
      reported_capability_signals(["app_guard", "rasp", "mobile_rasp"], config),
      mobile_source_signal(config)
    ]
  end

  defp decision_signals(
         "app_guard",
         _os,
         _health,
         _config,
         _collectors,
         _data_sources,
         _agent_status
       ),
       do: []

  defp decision_signals(
         "commercial_spyware",
         os,
         _health,
         config,
         collectors,
         data_sources,
         _agent_status
       )
       when os in [:android, :ios] do
    [
      data_source_signals(["spyware", "commercial_spyware", "mobile_events"], data_sources),
      collector_signals(["commercial_spyware", "spyware"], collectors),
      reported_capability_signals(
        ["commercial_spyware", "spyware", "pegasus", "predator"],
        config
      )
    ]
  end

  defp decision_signals(
         "commercial_spyware",
         _os,
         _health,
         _config,
         _collectors,
         _data_sources,
         _agent_status
       ),
       do: []

  defp decision_signals(
         "live_response",
         _os,
         health,
         config,
         _collectors,
         _data_sources,
         agent_status
       ) do
    [
      reported_capability_signals(
        ["live_response", "remote_shell", "shell", "remote_query", "osquery_query"],
        config
      ),
      runtime_signal(agent_status, health)
    ]
  end

  defp decision_signals(
         "screen_capture",
         os,
         _health,
         config,
         _collectors,
         _data_sources,
         _agent_status
       ) do
    broker = ScreenSessionBroker.status(os, config)

    [
      reported_capability_signals(["screen_capture", "screen_snapshot"], config),
      %{
        type: "session_broker",
        source: "config.screen_session_broker",
        value: broker.state,
        capabilities: broker.capabilities,
        signal: if(broker.ready, do: "reported", else: "not_observed")
      }
    ]
  end

  defp decision_signals(
         "network_isolation",
         _os,
         _health,
         config,
         _collectors,
         _data_sources,
         _agent_status
       ) do
    reported_capability_signals(["network_isolation", "isolate", "containment"], config)
  end

  defp decision_signals(
         "prevention_policy",
         _os,
         _health,
         config,
         _collectors,
         _data_sources,
         _agent_status
       ) do
    [
      response_policy_signal(config),
      reported_capability_signals(
        ["prevention", "quarantine", "kill_process", "restore_file"],
        config
      )
    ]
  end

  defp decision_signals(
         _capability_id,
         _os,
         _health,
         _config,
         _collectors,
         _data_sources,
         _agent_status
       ),
       do: []

  defp runtime_signal(agent_status, health) do
    status =
      agent_status
      |> to_string()
      |> String.downcase()

    cond do
      online_runtime?(agent_status, health) ->
        %{
          type: "runtime_status",
          source: "agent_status",
          value: status,
          signal: "reported"
        }

      status not in ["", "nil"] ->
        %{
          type: "runtime_status",
          source: "agent_status",
          value: status,
          signal: "not_observed"
        }

      true ->
        nil
    end
  end

  defp health_signal("kernel_sensor", health) do
    driver = map_get_any(health, [:driver_status, "driver_status"])
    platform_status = map_get_any(health, [:platform_status, "platform_status"]) || []

    cond do
      driver_connected?(driver) ->
        %{
          type: "observed_telemetry",
          source: "health.driver_status",
          value: compact_value(driver),
          signal: "observed"
        }

      Enum.any?(platform_status, &sensor_running?/1) ->
        %{
          type: "observed_telemetry",
          source: "health.platform_status",
          value: compact_value(platform_status),
          signal: "observed"
        }

      not is_nil(driver) or platform_status != [] ->
        %{
          type: "observed_telemetry",
          source: "health.platform_status",
          value: compact_value(platform_status),
          signal: "reported"
        }

      true ->
        nil
    end
  end

  defp health_signal(_capability_id, _health), do: nil

  defp mobile_source_signal(config) do
    if mobile_source?(config) do
      %{
        type: "reported_capability",
        source: "config.source",
        value: "tamandua_mobile",
        signal: "reported"
      }
    end
  end

  defp response_policy_signal(config) do
    response_config = map_get_any(config, ["response", :response]) || %{}

    if truthy?(map_get_any(response_config, ["auto_response_enabled", :auto_response_enabled])) do
      %{
        type: "reported_capability",
        source: "config.response.auto_response_enabled",
        value: true,
        signal: "reported"
      }
    end
  end

  defp data_source_signals(:all, data_sources) do
    data_sources
    |> Enum.filter(fn {_source, count} -> numeric?(count) and count > 0 end)
    |> Enum.map(fn {source, count} ->
      %{
        type: "data_source",
        source: "data_sources.#{source}",
        value: count,
        signal: "observed"
      }
    end)
  end

  defp data_source_signals([], _data_sources), do: []

  defp data_source_signals(names, data_sources) when is_list(names) do
    names
    |> Enum.flat_map(fn name ->
      [name, String.to_atom(name)]
      |> Enum.uniq()
      |> Enum.map(fn key -> {key, Map.get(data_sources, key, 0)} end)
    end)
    |> Enum.filter(fn {_key, count} -> numeric?(count) and count > 0 end)
    |> Enum.map(fn {key, count} ->
      %{
        type: "data_source",
        source: "data_sources.#{key}",
        value: count,
        signal: "observed"
      }
    end)
  end

  defp collector_signals(:active, collectors) do
    collectors
    |> Enum.filter(&collector_active?/1)
    |> Enum.map(fn collector ->
      %{
        type: "collector",
        source: "collectors",
        value: collector_name(collector),
        signal: "reported"
      }
    end)
  end

  defp collector_signals([], _collectors), do: []

  defp collector_signals(names, collectors) when is_list(names) do
    collectors
    |> Enum.filter(&(collector_name(&1) in names and collector_active?(&1)))
    |> Enum.map(fn collector ->
      %{
        type: "collector",
        source: "collectors",
        value: collector_name(collector),
        signal: "reported"
      }
    end)
  end

  defp reported_capability_signals([], _config), do: []

  defp reported_capability_signals(names, config) do
    config
    |> reported_capabilities()
    |> Enum.filter(&(&1 in names))
    |> Enum.map(fn capability ->
      %{
        type: "reported_capability",
        source: "config.reported_capabilities",
        value: capability,
        signal: "reported"
      }
    end)
  end

  defp fallback_signal(observed) when observed in ["observed", "reported"], do: nil

  defp fallback_signal(_observed) do
    %{
      type: "fallback",
      source: "server_default",
      value: "no matching telemetry, collector, or reported capability signal",
      signal: "not_observed"
    }
  end

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

  defp mobile_source?(config) do
    source =
      config
      |> map_get_any([:source, "source"])
      |> to_string()
      |> String.downcase()

    source in ["tamandua_mobile", "tamandua_mobile_v2"]
  end

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

  defp compact_value(value) when is_map(value),
    do: Map.take(value, [:connected, "connected", :state, "state"])

  defp compact_value(value), do: value
end
