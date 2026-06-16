defmodule TamanduaServer.AISecurity.AIInventory do
  @moduledoc """
  Enterprise AI Asset Inventory - aggregates AI discovery data from all agents.

  Maintains a real-time inventory of all AI/ML components across the enterprise:
  - What AI components exist (LLMs, frameworks, SDKs, model files, MCP servers)
  - Where they are deployed (agent, device, location)
  - Who installed them (user, process)
  - What data they access
  - Risk classification per component
  - Shadow AI detection (unapproved AI tools)
  - Policy enforcement (allowlist/blocklist)
  - Integration with Knowledge Graph (add AI nodes and edges)

  ETS-backed for performance with periodic PostgreSQL persistence.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Graph.KnowledgeGraph

  @inventory_table :ai_inventory
  @policy_table :ai_inventory_policy
  @stats_table :ai_inventory_stats

  # Cleanup interval: 1 hour
  @cleanup_interval_ms 3_600_000
  # Persistence interval: 5 minutes
  @persist_interval_ms 300_000
  # Component stale threshold: 48 hours without update
  @stale_threshold_seconds 172_800

  @default_policy %{
    # Components matching these names are always allowed
    allowlist: [],
    # Components matching these names are always blocked / alerting
    blocklist: [],
    # Default action for unknown components: :allow, :alert, :block
    default_action: :alert,
    # Auto-approve IDE extensions
    auto_approve_ide: true,
    # Maximum number of LLM instances per device
    max_llm_per_device: 2,
    # Alert on model files over this size (bytes)
    large_model_threshold_bytes: 10_737_418_240 # 10 GB
  }

  # Risk weights by component type
  @risk_weights %{
    "llm" => 40,
    "framework" => 20,
    "ide_extension" => 10,
    "mcp_server" => 35,
    "model_file" => 15,
    "sdk" => 10,
    "gpu_workload" => 25
  }

  # ------------------------------------------------------------------
  # Client API
  # ------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Ingest AI discovery data from an agent. Called when an agent sends
  AI component telemetry events.
  """
  @spec ingest_discovery(String.t(), map()) :: :ok
  def ingest_discovery(agent_id, discovery_event) do
    GenServer.cast(__MODULE__, {:ingest, agent_id, discovery_event})
  end

  @doc """
  Get all AI components for a specific agent.
  """
  @spec get_agent_components(String.t()) :: {:ok, [map()]}
  def get_agent_components(agent_id) do
    components = :ets.tab2list(@inventory_table)
    |> Enum.filter(fn {_key, comp} -> comp.agent_id == agent_id end)
    |> Enum.map(fn {_key, comp} -> comp end)
    |> Enum.sort_by(& &1.discovered_at, {:desc, DateTime})

    {:ok, components}
  end

  @doc """
  Get enterprise-wide AI inventory with optional filters.

  Options:
  - `:type` - Filter by component type (e.g., "llm", "mcp_server")
  - `:risk_level` - Filter by risk level ("low", "medium", "high", "critical")
  - `:shadow_only` - Only return unapproved/shadow AI (true/false)
  - `:limit` - Maximum results (default 500)
  """
  @spec list_inventory(keyword()) :: {:ok, [map()]}
  def list_inventory(opts \\ []) do
    type_filter = Keyword.get(opts, :type)
    risk_filter = Keyword.get(opts, :risk_level)
    shadow_only = Keyword.get(opts, :shadow_only, false)
    limit = Keyword.get(opts, :limit, 500)

    components = :ets.tab2list(@inventory_table)
    |> Enum.map(fn {_key, comp} -> comp end)
    |> maybe_filter_type(type_filter)
    |> maybe_filter_risk(risk_filter)
    |> maybe_filter_shadow(shadow_only)
    |> Enum.sort_by(& &1.risk_score, :desc)
    |> Enum.take(limit)

    {:ok, components}
  end

  @doc """
  Get shadow AI detections (unapproved AI tools).
  """
  @spec get_shadow_ai() :: {:ok, [map()]}
  def get_shadow_ai do
    list_inventory(shadow_only: true)
  end

  @doc """
  Get inventory statistics.
  """
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  @doc """
  Update AI policy (allowlist/blocklist).
  """
  @spec update_policy(map()) :: :ok
  def update_policy(policy_updates) do
    GenServer.call(__MODULE__, {:update_policy, policy_updates})
  end

  @doc """
  Get current AI policy.
  """
  @spec get_policy() :: map()
  def get_policy do
    GenServer.call(__MODULE__, :get_policy)
  end

  @doc """
  Approve a specific AI component (add to allowlist).
  """
  @spec approve_component(String.t()) :: :ok
  def approve_component(component_id) do
    GenServer.cast(__MODULE__, {:approve, component_id})
  end

  @doc """
  Block a specific AI component (add to blocklist).
  """
  @spec block_component(String.t()) :: :ok
  def block_component(component_id) do
    GenServer.cast(__MODULE__, {:block, component_id})
  end

  @doc """
  Get risk assessment for a specific component.
  """
  @spec assess_risk(String.t()) :: {:ok, map()} | {:error, :not_found}
  def assess_risk(component_id) do
    case :ets.lookup(@inventory_table, component_id) do
      [{^component_id, comp}] ->
        {:ok, %{
          component: comp,
          risk_score: comp.risk_score,
          risk_level: risk_level(comp.risk_score),
          risk_factors: comp.risk_factors,
          policy_status: comp.policy_status,
          recommendations: generate_recommendations(comp)
        }}

      [] ->
        {:error, :not_found}
    end
  end

  # ------------------------------------------------------------------
  # Server Callbacks
  # ------------------------------------------------------------------

  @impl true
  def init(opts) do
    :ets.new(@inventory_table, [:set, :public, :named_table, read_concurrency: true])
    :ets.new(@policy_table, [:set, :public, :named_table, read_concurrency: true])
    :ets.new(@stats_table, [:set, :public, :named_table, read_concurrency: true])

    # Load policy
    policy = Keyword.get(opts, :policy, @default_policy)
    :ets.insert(@policy_table, {:current_policy, policy})

    # Initialize stats
    :ets.insert(@stats_table, {:counters, %{
      total_ingested: 0,
      total_components: 0,
      shadow_ai_count: 0,
      alerts_created: 0,
      policy_violations: 0
    }})

    # Subscribe to AI discovery events
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "telemetry:events")
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "ai_security:discovery")

    # Schedule periodic tasks
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
    Process.send_after(self(), :persist, @persist_interval_ms)

    Logger.info("[AIInventory] AI Asset Inventory started")

    {:ok, %{policy: policy}}
  end

  @impl true
  def handle_cast({:ingest, agent_id, discovery_event}, state) do
    process_discovery(agent_id, discovery_event, state.policy)
    {:noreply, state}
  end

  @impl true
  def handle_cast({:approve, component_id}, state) do
    case :ets.lookup(@inventory_table, component_id) do
      [{^component_id, comp}] ->
        updated = %{comp | policy_status: :approved}
        :ets.insert(@inventory_table, {component_id, updated})

        # Add to allowlist
        new_policy = Map.update!(state.policy, :allowlist, fn list ->
          [comp.name | list] |> Enum.uniq()
        end)
        :ets.insert(@policy_table, {:current_policy, new_policy})
        {:noreply, %{state | policy: new_policy}}

      [] ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_cast({:block, component_id}, state) do
    case :ets.lookup(@inventory_table, component_id) do
      [{^component_id, comp}] ->
        updated = %{comp | policy_status: :blocked}
        :ets.insert(@inventory_table, {component_id, updated})

        # Add to blocklist
        new_policy = Map.update!(state.policy, :blocklist, fn list ->
          [comp.name | list] |> Enum.uniq()
        end)
        :ets.insert(@policy_table, {:current_policy, new_policy})
        {:noreply, %{state | policy: new_policy}}

      [] ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_call(:stats, _from, state) do
    counters = case :ets.lookup(@stats_table, :counters) do
      [{:counters, c}] -> c
      [] -> %{}
    end

    type_counts = :ets.tab2list(@inventory_table)
    |> Enum.group_by(fn {_key, comp} -> comp.component_type end)
    |> Enum.map(fn {type, entries} -> {type, length(entries)} end)
    |> Map.new()

    stats = %{
      counters: counters,
      total_components: :ets.info(@inventory_table, :size),
      components_by_type: type_counts,
      policy: state.policy,
      computed_at: DateTime.utc_now()
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_call({:update_policy, updates}, _from, state) do
    new_policy = Map.merge(state.policy, updates)
    :ets.insert(@policy_table, {:current_policy, new_policy})

    # Re-evaluate all components against new policy
    :ets.tab2list(@inventory_table)
    |> Enum.each(fn {key, comp} ->
      new_status = evaluate_policy(comp, new_policy)
      :ets.insert(@inventory_table, {key, %{comp | policy_status: new_status}})
    end)

    {:reply, :ok, %{state | policy: new_policy}}
  end

  @impl true
  def handle_call(:get_policy, _from, state) do
    {:reply, state.policy, state}
  end

  # PubSub event handling
  @impl true
  def handle_info({:telemetry_event, event}, state) do
    # Check if this is an AI discovery event
    payload = event[:payload] || event["payload"] || %{}
    if payload[:ai_discovery] || payload["ai_discovery"] do
      agent_id = event[:agent_id] || event["agent_id"]
      if agent_id do
        process_discovery(agent_id, event, state.policy)
      end
    end
    {:noreply, state}
  end

  @impl true
  def handle_info({:ai_component_discovered, component}, state) do
    agent_id = component[:agent_id]
    if agent_id do
      process_single_component(agent_id, component, state.policy)
    end
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_stale_components()
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
    {:noreply, state}
  end

  @impl true
  def handle_info(:persist, state) do
    persist_inventory()
    Process.send_after(self(), :persist, @persist_interval_ms)
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ------------------------------------------------------------------
  # Discovery Processing
  # ------------------------------------------------------------------

  defp process_discovery(agent_id, event, policy) do
    payload = event[:payload] || event["payload"] || %{}
    discovery = payload[:ai_discovery] || payload["ai_discovery"]

    components =
      cond do
        is_list(discovery) ->
          discovery

        is_map(discovery) ->
          discovery[:components] || discovery["components"] || []

        true ->
          payload[:components] || payload["components"] || []
      end

    Enum.each(components, fn component ->
      process_single_component(agent_id, component, policy)
    end)

    update_counter(:total_ingested, 1)
  end

  defp process_single_component(agent_id, component, policy) do
    name = component[:name] || component["name"] || "unknown"
    comp_type = component[:component_type] || component["component_type"] || component[:type] || component["type"] || "unknown"

    component_id = generate_component_id(agent_id, name, comp_type)

    # Calculate risk score
    {risk_score, risk_factors} = calculate_risk(component, agent_id)

    # Evaluate policy
    policy_status = evaluate_policy_for_component(name, comp_type, policy)

    # Determine if this is shadow AI
    is_shadow = policy_status == :unknown and comp_type in ["llm", "mcp_server", "framework"]

    inventory_entry = %{
      id: component_id,
      agent_id: agent_id,
      organization_id: get_agent_org_id(agent_id),
      name: name,
      component_type: comp_type,
      version: component[:version] || component["version"],
      process_id: component[:process_id] || component["process_id"],
      install_path: component[:install_path] || component["install_path"],
      config_path: component[:config_path] || component["config_path"],
      file_hash: component[:file_hash] || component["file_hash"],
      artifact_type: component[:artifact_type] || component["artifact_type"],
      redacted_preview: component[:redacted_preview] || component["redacted_preview"],
      matched_patterns: component[:matched_patterns] || component["matched_patterns"] || [],
      network_endpoints: component[:network_endpoints] || component["network_endpoints"] || [],
      risk_indicators: component[:risk_indicators] || component["risk_indicators"] || [],
      risk_score: risk_score,
      risk_level: risk_level(risk_score),
      risk_factors: risk_factors,
      policy_status: policy_status,
      is_shadow: is_shadow,
      discovered_at: DateTime.utc_now(),
      last_seen_at: DateTime.utc_now(),
      hostname: get_agent_hostname(agent_id)
    }

    :ets.insert(@inventory_table, {component_id, inventory_entry})

    # Update Knowledge Graph
    update_knowledge_graph(inventory_entry)

    # Create alerts if necessary
    if policy_status == :blocked do
      create_policy_violation_alert(agent_id, inventory_entry)
      update_counter(:policy_violations, 1)
    end

    if is_shadow do
      create_shadow_ai_alert(agent_id, inventory_entry)
      update_counter(:shadow_ai_count, 1)
    end

    # Broadcast discovery
    Phoenix.PubSub.broadcast_from(
      TamanduaServer.PubSub,
      self(),
      "ai_security:discovery",
      {:ai_component_discovered, inventory_entry}
    )
  rescue
    _ -> :ok
  end

  # ------------------------------------------------------------------
  # Risk Calculation
  # ------------------------------------------------------------------

  defp calculate_risk(component, _agent_id) do
    comp_type = to_string(component[:component_type] || component["component_type"] || component[:type] || component["type"] || "unknown")
    risk_indicators = component[:risk_indicators] || component["risk_indicators"] || []
    endpoints = component[:network_endpoints] || component["network_endpoints"] || []

    base_risk = Map.get(@risk_weights, comp_type, 10)
    factors = []

    # Risk from indicators
    {indicator_risk, indicator_factors} = Enum.reduce(risk_indicators, {0, []}, fn indicator, {r, f} ->
      indicator_str = to_string(indicator)
      cond do
        String.contains?(indicator_str, "admin") or String.contains?(indicator_str, "elevated") ->
          {r + 20, ["elevated_privileges" | f]}
        String.contains?(indicator_str, "all_interfaces") or String.contains?(indicator_str, "network_exposed") ->
          {r + 25, ["network_exposed" | f]}
        String.contains?(indicator_str, "auth") ->
          {r + 30, ["no_authentication" | f]}
        String.contains?(indicator_str, "api_key") or String.contains?(indicator_str, "KEY") ->
          {r + 15, ["exposed_credentials" | f]}
        String.contains?(indicator_str, "large_model") ->
          {r + 5, ["large_model_file" | f]}
        true ->
          {r + 5, [indicator_str | f]}
      end
    end)

    # Risk from network exposure
    network_risk = if length(endpoints) > 0, do: 10, else: 0

    total_risk = min(base_risk + indicator_risk + network_risk, 100)
    all_factors = (factors ++ indicator_factors) |> Enum.uniq()

    {total_risk, all_factors}
  end

  defp risk_level(score) when score >= 75, do: "critical"
  defp risk_level(score) when score >= 50, do: "high"
  defp risk_level(score) when score >= 25, do: "medium"
  defp risk_level(_score), do: "low"

  # ------------------------------------------------------------------
  # Policy Evaluation
  # ------------------------------------------------------------------

  defp evaluate_policy(comp, policy) do
    evaluate_policy_for_component(comp.name, comp.component_type, policy)
  end

  defp evaluate_policy_for_component(name, comp_type, policy) do
    name_lower = String.downcase(to_string(name))

    cond do
      # Check blocklist
      Enum.any?(policy.blocklist, fn blocked ->
        String.contains?(name_lower, String.downcase(to_string(blocked)))
      end) ->
        :blocked

      # Check allowlist
      Enum.any?(policy.allowlist, fn allowed ->
        String.contains?(name_lower, String.downcase(to_string(allowed)))
      end) ->
        :approved

      # Auto-approve IDE extensions if configured
      policy.auto_approve_ide and to_string(comp_type) == "ide_extension" ->
        :approved

      # Default action
      true ->
        case policy.default_action do
          :allow -> :approved
          :block -> :blocked
          _ -> :unknown
        end
    end
  end

  # ------------------------------------------------------------------
  # Knowledge Graph Integration
  # ------------------------------------------------------------------

  defp update_knowledge_graph(entry) do
    node_type = case entry.component_type do
      "mcp_server" -> :mcp_server
      _ -> :ai_model
    end

    KnowledgeGraph.upsert_node(node_type, entry.id, %{
      name: entry.name,
      component_type: entry.component_type,
      version: entry.version,
      risk_score: entry.risk_score,
      install_path: entry.install_path,
      network_endpoints: entry.network_endpoints,
      policy_status: entry.policy_status,
      is_shadow: entry.is_shadow
    })

    # Link to device
    if entry.agent_id do
      KnowledgeGraph.add_edge(
        {node_type, entry.id},
        {:device, entry.agent_id},
        :deployed_on,
        %{}
      )
    end
  rescue
    _ -> :ok
  end

  # ------------------------------------------------------------------
  # Alerting
  # ------------------------------------------------------------------

  defp create_policy_violation_alert(agent_id, entry) do
    TamanduaServer.Alerts.create_alert(%{
      agent_id: agent_id,
      organization_id: TamanduaServer.Agents.OrgLookup.get_org_id(agent_id),
      severity: "high",
      title: "AI Policy Violation: #{entry.name}",
      description: """
      A blocked AI component was detected on this endpoint.

      Component: #{entry.name}
      Type: #{entry.component_type}
      Path: #{entry.install_path || "N/A"}
      Risk Score: #{entry.risk_score}
      """,
      source: "ai_inventory",
      mitre_tactics: ["execution"],
      mitre_techniques: ["T1518"],
      threat_score: entry.risk_score / 100.0
    })

    update_counter(:alerts_created, 1)
  rescue
    _ -> :ok
  end

  defp create_shadow_ai_alert(agent_id, entry) do
    TamanduaServer.Alerts.create_alert(%{
      agent_id: agent_id,
      organization_id: TamanduaServer.Agents.OrgLookup.get_org_id(agent_id),
      severity: "medium",
      title: "Shadow AI Detected: #{entry.name}",
      description: """
      An unapproved AI component was detected on this endpoint.

      Component: #{entry.name}
      Type: #{entry.component_type}
      Path: #{entry.install_path || "N/A"}
      Risk Score: #{entry.risk_score}

      This component is not in the organization's approved AI tools list.
      Review and either approve or block this component.
      """,
      source: "ai_inventory",
      mitre_tactics: ["collection", "exfiltration"],
      mitre_techniques: ["T1567"],
      threat_score: entry.risk_score / 100.0
    })

    update_counter(:alerts_created, 1)
  rescue
    _ -> :ok
  end

  # ------------------------------------------------------------------
  # Cleanup & Persistence
  # ------------------------------------------------------------------

  defp cleanup_stale_components do
    now = DateTime.utc_now()

    stale_keys = :ets.tab2list(@inventory_table)
    |> Enum.filter(fn {_key, comp} ->
      DateTime.diff(now, comp.last_seen_at, :second) > @stale_threshold_seconds
    end)
    |> Enum.map(fn {key, _comp} -> key end)

    Enum.each(stale_keys, fn key -> :ets.delete(@inventory_table, key) end)

    if length(stale_keys) > 0 do
      Logger.info("[AIInventory] Cleaned up #{length(stale_keys)} stale components")
    end
  end

  defp persist_inventory do
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      try do
        components = :ets.tab2list(@inventory_table)
        |> Enum.map(fn {_key, comp} -> comp end)

        # Persist to database (upsert)
        now = DateTime.utc_now()
        records = Enum.map(components, fn comp ->
          %{
            id: comp.id,
            agent_id: comp.agent_id,
            organization_id: Map.get(comp, :organization_id),
            name: comp.name,
            component_type: comp.component_type,
            version: comp.version,
            install_path: comp.install_path,
            risk_score: comp.risk_score,
            risk_level: comp.risk_level,
            policy_status: to_string(comp.policy_status),
            is_shadow: comp.is_shadow,
            data: Map.drop(comp, [:id, :agent_id, :organization_id, :name, :component_type, :version, :install_path]),
            inserted_at: now,
            updated_at: now
          }
        end)

        if length(records) > 0 do
          TamanduaServer.Repo.insert_all("ai_inventory", records,
            on_conflict: {:replace, [:organization_id, :name, :version, :risk_score, :risk_level, :policy_status, :is_shadow, :data, :updated_at]},
            conflict_target: [:id]
          )
        end

        Logger.debug("[AIInventory] Persisted #{length(records)} components")
      rescue
        e -> Logger.debug("[AIInventory] Persistence skipped: #{inspect(e)}")
      end
    end)
  end

  # ------------------------------------------------------------------
  # Helpers
  # ------------------------------------------------------------------

  defp generate_component_id(agent_id, name, type) do
    hash = :crypto.hash(:sha256, "#{agent_id}:#{name}:#{type}")
    |> Base.encode16(case: :lower)
    |> String.slice(0, 16)
    "ai_#{hash}"
  end

  defp get_agent_hostname(agent_id) do
    case TamanduaServer.Agents.Registry.get_agent(agent_id) do
      {:ok, agent} -> agent[:hostname]
      _ -> nil
    end
  rescue
    _ -> nil
  end

  defp get_agent_org_id(agent_id) do
    TamanduaServer.Agents.OrgLookup.get_org_id(agent_id)
  rescue
    _ -> nil
  end

  defp generate_recommendations(comp) do
    recs = []

    recs = if comp.is_shadow do
      ["Review this AI component and either approve or block it via policy" | recs]
    else
      recs
    end

    recs = if comp.risk_score > 50 do
      ["This component has a high risk score - consider restricting access" | recs]
    else
      recs
    end

    recs = if "no_authentication" in (comp.risk_factors || []) do
      ["Enable authentication for this AI service" | recs]
    else
      recs
    end

    recs = if "network_exposed" in (comp.risk_factors || []) do
      ["Restrict network binding to localhost only" | recs]
    else
      recs
    end

    recs = if "elevated_privileges" in (comp.risk_factors || []) do
      ["Run this AI component with reduced privileges" | recs]
    else
      recs
    end

    if Enum.empty?(recs), do: ["No immediate action required"], else: recs
  end

  defp update_counter(key, increment) do
    case :ets.lookup(@stats_table, :counters) do
      [{:counters, counters}] ->
        updated = Map.update(counters, key, increment, &(&1 + increment))
        :ets.insert(@stats_table, {:counters, updated})
      [] ->
        :ets.insert(@stats_table, {:counters, %{key => increment}})
    end
  end

  defp maybe_filter_type(components, nil), do: components
  defp maybe_filter_type(components, type) do
    Enum.filter(components, &(&1.component_type == type))
  end

  defp maybe_filter_risk(components, nil), do: components
  defp maybe_filter_risk(components, level) do
    Enum.filter(components, &(&1.risk_level == level))
  end

  defp maybe_filter_shadow(components, false), do: components
  defp maybe_filter_shadow(components, true) do
    Enum.filter(components, &(&1.is_shadow == true))
  end
end
