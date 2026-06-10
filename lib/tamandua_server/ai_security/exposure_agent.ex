defmodule TamanduaServer.AISecurity.ExposureAgent do
  @moduledoc """
  Exposure Prioritization Agent

  An AI-driven security agent that provides comprehensive attack surface management,
  vulnerability prioritization, and risk-based remediation guidance. This agent
  continuously analyzes the organization's security posture to identify and
  prioritize exposures based on real-world exploitability and business impact.

  ## Key Capabilities

  - **Attack Surface Mapping**: Discovers and maps all exposed assets, services,
    and potential entry points across the environment.

  - **Vulnerability Prioritization**: Uses EPSS (Exploit Prediction Scoring System)
    and threat intelligence to prioritize vulnerabilities by actual exploitability
    rather than just CVSS scores.

  - **Asset Criticality Scoring**: Evaluates asset importance based on business
    function, data sensitivity, and interdependencies.

  - **Breach Probability Calculation**: Estimates likelihood of successful breach
    based on attack paths, controls, and threat landscape.

  - **Crown Jewel Identification**: Identifies and protects the organization's
    most critical assets and data.

  - **Remediation Impact Analysis**: Quantifies the risk reduction achieved by
    specific remediation actions to optimize resource allocation.

  ## Architecture

  The agent maintains an internal graph of assets, vulnerabilities, and attack
  paths, continuously updated by telemetry from endpoints and external threat
  intelligence feeds.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Cache
  alias TamanduaServer.Inventory.AssetManager

  # Attack surface categories
  @surface_categories [:network, :endpoint, :application, :identity, :cloud, :supply_chain]

  # EPSS threshold for "likely exploited" classification
  @epss_high_threshold 0.7
  @epss_medium_threshold 0.3

  # Risk calculation weights
  @risk_weights %{
    epss_score: 0.30,
    cvss_score: 0.15,
    asset_criticality: 0.25,
    exposure_level: 0.15,
    active_exploitation: 0.15
  }

  # Criticality levels for assets
  @criticality_levels %{
    crown_jewel: 100,
    critical: 80,
    high: 60,
    medium: 40,
    low: 20,
    minimal: 10
  }

  # State structure
  defstruct [
    :attack_surface,
    :vulnerability_graph,
    :asset_criticality_matrix,
    :crown_jewels,
    :attack_paths,
    :remediation_queue,
    :epss_cache,
    :risk_history,
    :last_analysis,
    :analysis_interval,
    :stats
  ]

  # Attack path node
  defmodule AttackPath do
    @moduledoc false
    defstruct [
      :id,
      :source,
      :target,
      :steps,
      :probability,
      :impact,
      :risk_score,
      :mitigations,
      :techniques
    ]
  end

  # Exposure record
  defmodule Exposure do
    @moduledoc false
    defstruct [
      :id,
      :type,
      :asset_id,
      :cve_id,
      :epss_score,
      :cvss_score,
      :cvss_vector,
      :description,
      :affected_component,
      :attack_vector,
      :exploitability,
      :impact_score,
      :breach_probability,
      :risk_score,
      :priority_rank,
      :remediation_actions,
      :risk_reduction,
      :discovered_at,
      :last_seen,
      :status
    ]
  end

  # Remediation action
  defmodule RemediationAction do
    @moduledoc false
    defstruct [
      :id,
      :exposure_id,
      :action_type,
      :description,
      :effort_hours,
      :risk_reduction,
      :roi_score,
      :dependencies,
      :status,
      :assigned_to,
      :due_date,
      :completed_at
    ]
  end

  ## Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Perform a full attack surface analysis.
  Returns a comprehensive view of the organization's exposure.
  """
  @spec analyze_attack_surface() :: {:ok, map()} | {:error, term()}
  def analyze_attack_surface do
    GenServer.call(__MODULE__, :analyze_attack_surface, 60_000)
  end

  @doc """
  Get prioritized list of vulnerabilities based on exploitability and impact.
  """
  @spec get_prioritized_vulnerabilities(keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_prioritized_vulnerabilities(opts \\ []) do
    GenServer.call(__MODULE__, {:get_prioritized_vulns, opts})
  end

  @doc """
  Calculate and return asset criticality scores.
  """
  @spec get_asset_criticality(String.t() | nil) :: {:ok, map() | [map()]} | {:error, term()}
  def get_asset_criticality(asset_id \\ nil) do
    GenServer.call(__MODULE__, {:get_asset_criticality, asset_id})
  end

  @doc """
  Calculate breach probability for a given asset or the entire organization.
  """
  @spec calculate_breach_probability(String.t() | nil) :: {:ok, float()} | {:error, term()}
  def calculate_breach_probability(asset_id \\ nil) do
    GenServer.call(__MODULE__, {:breach_probability, asset_id})
  end

  @doc """
  Identify and return crown jewel assets.
  """
  @spec identify_crown_jewels() :: {:ok, [map()]} | {:error, term()}
  def identify_crown_jewels do
    GenServer.call(__MODULE__, :identify_crown_jewels)
  end

  @doc """
  Get attack path analysis showing potential compromise routes.
  """
  @spec get_attack_paths(keyword()) :: {:ok, [AttackPath.t()]} | {:error, term()}
  def get_attack_paths(opts \\ []) do
    GenServer.call(__MODULE__, {:get_attack_paths, opts})
  end

  @doc """
  Analyze remediation impact for a specific vulnerability or action.
  """
  @spec analyze_remediation_impact(String.t()) :: {:ok, map()} | {:error, term()}
  def analyze_remediation_impact(exposure_id) do
    GenServer.call(__MODULE__, {:remediation_impact, exposure_id})
  end

  @doc """
  Get the prioritized remediation queue.
  """
  @spec get_remediation_queue(keyword()) :: {:ok, [RemediationAction.t()]} | {:error, term()}
  def get_remediation_queue(opts \\ []) do
    GenServer.call(__MODULE__, {:get_remediation_queue, opts})
  end

  @doc """
  Update EPSS scores from external feed.
  """
  @spec update_epss_scores([map()]) :: :ok
  def update_epss_scores(scores) do
    GenServer.cast(__MODULE__, {:update_epss, scores})
  end

  @doc """
  Register an exposure from vulnerability scan or detection.
  """
  @spec register_exposure(map()) :: {:ok, Exposure.t()} | {:error, term()}
  def register_exposure(exposure_data) do
    GenServer.call(__MODULE__, {:register_exposure, exposure_data})
  end

  @doc """
  Mark an exposure as remediated.
  """
  @spec mark_remediated(String.t(), map()) :: :ok | {:error, term()}
  def mark_remediated(exposure_id, details \\ %{}) do
    GenServer.call(__MODULE__, {:mark_remediated, exposure_id, details})
  end

  @doc """
  Get risk reduction tracking metrics.
  """
  @spec get_risk_reduction_metrics(keyword()) :: {:ok, map()} | {:error, term()}
  def get_risk_reduction_metrics(opts \\ []) do
    GenServer.call(__MODULE__, {:risk_reduction_metrics, opts})
  end

  @doc """
  Get exposure statistics and summary.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Generate an attack surface map for an asset or organization.
  Wrapper for analyze_attack_surface/0 for controller compatibility.
  """
  @spec generate_attack_surface_map(String.t() | nil) :: {:ok, map()} | {:error, term()}
  def generate_attack_surface_map(_asset_id \\ nil) do
    analyze_attack_surface()
  end

  @doc """
  Get the current attack surface map.
  Returns cached analysis if available, otherwise performs a new analysis.
  """
  @spec get_attack_surface_map() :: {:ok, map()} | {:error, term()}
  def get_attack_surface_map do
    analyze_attack_surface()
  end

  @doc """
  Generate a remediation plan based on current exposures.
  Returns prioritized remediation actions.
  """
  @spec generate_remediation_plan(String.t() | nil) :: {:ok, map()} | {:error, term()}
  def generate_remediation_plan(_asset_id \\ nil) do
    case get_remediation_queue(limit: 50) do
      {:ok, queue} ->
        # Group by action type and calculate totals
        by_type = Enum.group_by(queue, & &1.action_type)
        total_effort = Enum.sum(Enum.map(queue, & &1.effort_hours || 0))
        total_risk_reduction = Enum.sum(Enum.map(queue, & &1.risk_reduction || 0))

        plan = %{
          actions: queue,
          total_actions: length(queue),
          total_effort_hours: Float.round(total_effort, 1),
          total_risk_reduction: Float.round(total_risk_reduction, 2),
          actions_by_type: Enum.map(by_type, fn {type, actions} ->
            {type, %{
              count: length(actions),
              effort_hours: Enum.sum(Enum.map(actions, & &1.effort_hours || 0)),
              risk_reduction: Enum.sum(Enum.map(actions, & &1.risk_reduction || 0))
            }}
          end) |> Map.new(),
          priority_summary: %{
            critical: Enum.count(queue, &(&1.status == :pending and (&1.roi_score || 0) > 10)),
            high: Enum.count(queue, &(&1.status == :pending and (&1.roi_score || 0) > 5)),
            medium: Enum.count(queue, &(&1.status == :pending and (&1.roi_score || 0) > 1)),
            low: Enum.count(queue, &(&1.status == :pending and (&1.roi_score || 0) <= 1))
          },
          generated_at: DateTime.utc_now()
        }

        {:ok, plan}

      {:error, reason} ->
        {:error, reason}
    end
  end

  ## Server Callbacks

  @impl true
  def init(_opts) do
    Logger.info("Starting Exposure Prioritization Agent")

    state = %__MODULE__{
      attack_surface: initialize_attack_surface(),
      vulnerability_graph: %{},
      asset_criticality_matrix: %{},
      crown_jewels: [],
      attack_paths: [],
      remediation_queue: [],
      epss_cache: load_epss_cache(),
      risk_history: [],
      last_analysis: nil,
      analysis_interval: :timer.hours(1),
      stats: initialize_stats()
    }

    # Schedule periodic analysis
    schedule_analysis()

    # Schedule EPSS cache refresh
    schedule_epss_refresh()

    {:ok, state}
  end

  @impl true
  def handle_call(:analyze_attack_surface, _from, state) do
    Logger.info("Performing attack surface analysis")

    {surface_analysis, new_state} = perform_attack_surface_analysis(state)
    {:reply, {:ok, surface_analysis}, new_state}
  end

  @impl true
  def handle_call({:get_prioritized_vulns, opts}, _from, state) do
    limit = Keyword.get(opts, :limit, 100)
    min_epss = Keyword.get(opts, :min_epss, 0.0)
    asset_id = Keyword.get(opts, :asset_id)

    vulnerabilities = state.vulnerability_graph
      |> Map.values()
      |> filter_by_asset(asset_id)
      |> Enum.filter(fn v -> v.epss_score >= min_epss end)
      |> prioritize_vulnerabilities(state)
      |> Enum.take(limit)

    {:reply, {:ok, vulnerabilities}, state}
  end

  @impl true
  def handle_call({:get_asset_criticality, nil}, _from, state) do
    criticality_list = state.asset_criticality_matrix
      |> Map.values()
      |> Enum.sort_by(& &1.score, :desc)

    {:reply, {:ok, criticality_list}, state}
  end

  @impl true
  def handle_call({:get_asset_criticality, asset_id}, _from, state) do
    case Map.get(state.asset_criticality_matrix, asset_id) do
      nil -> {:reply, {:error, :not_found}, state}
      criticality -> {:reply, {:ok, criticality}, state}
    end
  end

  @impl true
  def handle_call({:breach_probability, asset_id}, _from, state) do
    probability = calculate_breach_prob(asset_id, state)
    {:reply, {:ok, probability}, state}
  end

  @impl true
  def handle_call(:identify_crown_jewels, _from, state) do
    crown_jewels = identify_crown_jewel_assets(state)
    new_state = %{state | crown_jewels: crown_jewels}
    {:reply, {:ok, crown_jewels}, new_state}
  end

  @impl true
  def handle_call({:get_attack_paths, opts}, _from, state) do
    target_id = Keyword.get(opts, :target)
    max_depth = Keyword.get(opts, :max_depth, 5)
    min_probability = Keyword.get(opts, :min_probability, 0.1)

    paths = state.attack_paths
      |> filter_attack_paths(target_id, min_probability)
      |> Enum.filter(fn p -> length(p.steps) <= max_depth end)
      |> Enum.sort_by(& &1.risk_score, :desc)

    {:reply, {:ok, paths}, state}
  end

  @impl true
  def handle_call({:remediation_impact, exposure_id}, _from, state) do
    case Map.get(state.vulnerability_graph, exposure_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      exposure ->
        impact = analyze_remediation(exposure, state)
        {:reply, {:ok, impact}, state}
    end
  end

  @impl true
  def handle_call({:get_remediation_queue, opts}, _from, state) do
    limit = Keyword.get(opts, :limit, 50)
    status = Keyword.get(opts, :status, :pending)

    queue = state.remediation_queue
      |> Enum.filter(fn r -> status == :all or r.status == status end)
      |> Enum.sort_by(& &1.roi_score, :desc)
      |> Enum.take(limit)

    {:reply, {:ok, queue}, state}
  end

  @impl true
  def handle_call({:register_exposure, data}, _from, state) do
    exposure = create_exposure(data, state)
    new_vuln_graph = Map.put(state.vulnerability_graph, exposure.id, exposure)

    # Update remediation queue
    new_queue = update_remediation_queue(state.remediation_queue, exposure, state)

    # Update stats
    new_stats = update_stats(state.stats, :exposure_registered)

    new_state = %{state |
      vulnerability_graph: new_vuln_graph,
      remediation_queue: new_queue,
      stats: new_stats
    }

    {:reply, {:ok, exposure}, new_state}
  end

  @impl true
  def handle_call({:mark_remediated, exposure_id, details}, _from, state) do
    case Map.get(state.vulnerability_graph, exposure_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      exposure ->
        # Update exposure status
        updated_exposure = %{exposure |
          status: :remediated,
          last_seen: DateTime.utc_now()
        }

        # Record risk reduction
        risk_reduction = calculate_risk_reduction(exposure, state)
        history_entry = %{
          exposure_id: exposure_id,
          risk_reduction: risk_reduction,
          remediated_at: DateTime.utc_now(),
          details: details
        }

        new_state = %{state |
          vulnerability_graph: Map.put(state.vulnerability_graph, exposure_id, updated_exposure),
          risk_history: [history_entry | state.risk_history],
          stats: update_stats(state.stats, :exposure_remediated)
        }

        {:reply, :ok, new_state}
    end
  end

  @impl true
  def handle_call({:risk_reduction_metrics, opts}, _from, state) do
    days = Keyword.get(opts, :days, 30)
    cutoff = DateTime.add(DateTime.utc_now(), -days * 24 * 3600, :second)

    recent_history = Enum.filter(state.risk_history, fn h ->
      DateTime.compare(h.remediated_at, cutoff) == :gt
    end)

    metrics = %{
      total_risk_reduced: Enum.sum(Enum.map(recent_history, & &1.risk_reduction)),
      exposures_remediated: length(recent_history),
      average_risk_per_exposure: calculate_average(recent_history, :risk_reduction),
      trend: calculate_risk_trend(state.risk_history, days),
      top_remediations: recent_history
        |> Enum.sort_by(& &1.risk_reduction, :desc)
        |> Enum.take(10)
    }

    {:reply, {:ok, metrics}, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = Map.merge(state.stats, %{
      total_exposures: map_size(state.vulnerability_graph),
      active_exposures: count_active_exposures(state.vulnerability_graph),
      crown_jewels_count: length(state.crown_jewels),
      attack_paths_count: length(state.attack_paths),
      pending_remediations: count_pending_remediations(state.remediation_queue),
      last_analysis: state.last_analysis
    })

    {:reply, stats, state}
  end

  @impl true
  def handle_cast({:update_epss, scores}, state) do
    Logger.info("Updating EPSS scores: #{length(scores)} entries")

    new_cache = Enum.reduce(scores, state.epss_cache, fn score, cache ->
      Map.put(cache, score["cve"], %{
        epss: score["epss"],
        percentile: score["percentile"],
        updated_at: DateTime.utc_now()
      })
    end)

    # Re-score existing vulnerabilities
    new_vuln_graph = rescore_vulnerabilities(state.vulnerability_graph, new_cache, state)

    {:noreply, %{state | epss_cache: new_cache, vulnerability_graph: new_vuln_graph}}
  end

  @impl true
  def handle_info(:periodic_analysis, state) do
    Logger.debug("Running periodic exposure analysis")

    {_analysis, new_state} = perform_attack_surface_analysis(state)
    schedule_analysis()

    {:noreply, new_state}
  end

  @impl true
  def handle_info(:refresh_epss, state) do
    # In production, this would fetch from FIRST EPSS API
    spawn(fn -> fetch_epss_updates() end)
    schedule_epss_refresh()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  ## Private Functions - Initialization

  defp initialize_attack_surface do
    %{
      network: %{exposed_services: [], open_ports: [], external_ips: []},
      endpoint: %{vulnerable_hosts: [], unpatched_systems: [], misconfigurations: []},
      application: %{web_apps: [], apis: [], vulnerable_components: []},
      identity: %{privileged_accounts: [], weak_credentials: [], stale_accounts: []},
      cloud: %{public_buckets: [], exposed_instances: [], misconfigurations: []},
      supply_chain: %{vulnerable_dependencies: [], third_party_risks: []}
    }
  end

  defp initialize_stats do
    %{
      analyses_performed: 0,
      exposures_registered: 0,
      exposures_remediated: 0,
      attack_paths_identified: 0,
      started_at: DateTime.utc_now()
    }
  end

  defp load_epss_cache do
    case Cache.get("epss_scores") do
      nil -> %{}
      cache -> cache
    end
  end

  ## Private Functions - Attack Surface Analysis

  defp perform_attack_surface_analysis(state) do
    # Gather data from all sources
    assets = get_all_assets()
    vulnerabilities = gather_vulnerabilities(assets, state)
    criticality_matrix = build_criticality_matrix(assets)
    attack_paths = model_attack_paths(assets, vulnerabilities, criticality_matrix)
    crown_jewels = identify_crown_jewel_assets_internal(criticality_matrix)

    # Calculate organization-wide breach probability
    org_breach_prob = calculate_org_breach_probability(attack_paths, criticality_matrix)

    # Build remediation queue
    remediation_queue = build_remediation_queue(vulnerabilities, criticality_matrix, state)

    analysis = %{
      timestamp: DateTime.utc_now(),
      attack_surface: summarize_attack_surface(state.attack_surface, assets),
      total_assets: length(assets),
      total_vulnerabilities: map_size(vulnerabilities),
      critical_exposures: count_critical_exposures(vulnerabilities),
      high_risk_assets: count_high_risk_assets(criticality_matrix),
      crown_jewels: length(crown_jewels),
      attack_paths: length(attack_paths),
      org_breach_probability: org_breach_prob,
      top_risks: get_top_risks(vulnerabilities, 10),
      risk_by_category: categorize_risks(vulnerabilities),
      remediation_summary: summarize_remediation_queue(remediation_queue)
    }

    new_state = %{state |
      vulnerability_graph: vulnerabilities,
      asset_criticality_matrix: criticality_matrix,
      crown_jewels: crown_jewels,
      attack_paths: attack_paths,
      remediation_queue: remediation_queue,
      last_analysis: DateTime.utc_now(),
      stats: update_stats(state.stats, :analysis_performed)
    }

    {analysis, new_state}
  end

  defp get_all_assets do
    case AssetManager.list_assets() do
      {:ok, assets} -> assets
      _ -> []
    end
  rescue
    _ -> []
  end

  defp gather_vulnerabilities(assets, state) do
    assets
    |> Enum.flat_map(fn asset ->
      (asset.vulnerabilities || [])
      |> Enum.map(fn vuln ->
        exposure = build_exposure_from_vuln(vuln, asset, state)
        {exposure.id, exposure}
      end)
    end)
    |> Map.new()
  end

  defp build_exposure_from_vuln(vuln, asset, state) do
    cve_id = vuln[:cve_id] || vuln["cve_id"]
    epss_data = Map.get(state.epss_cache, cve_id, %{epss: 0.0})

    cvss_score = vuln[:cvss_score] || vuln["cvss_score"] || 0.0
    epss_score = epss_data[:epss] || 0.0

    %Exposure{
      id: generate_exposure_id(asset.id, cve_id),
      type: :vulnerability,
      asset_id: asset.id,
      cve_id: cve_id,
      epss_score: epss_score,
      cvss_score: cvss_score,
      cvss_vector: vuln[:cvss_vector],
      description: vuln[:description],
      affected_component: vuln[:affected_software],
      attack_vector: extract_attack_vector(vuln),
      exploitability: calculate_exploitability(epss_score, cvss_score, vuln),
      impact_score: calculate_impact_score(cvss_score, asset),
      breach_probability: calculate_single_breach_prob(epss_score, cvss_score, asset),
      risk_score: 0.0,  # Will be calculated
      priority_rank: 0,
      remediation_actions: generate_remediation_actions(vuln, asset),
      risk_reduction: 0.0,  # Will be calculated
      discovered_at: vuln[:discovered_at] || DateTime.utc_now(),
      last_seen: DateTime.utc_now(),
      status: :active
    }
    |> calculate_exposure_risk_score(state)
  end

  defp generate_exposure_id(asset_id, cve_id) do
    :crypto.hash(:sha256, "#{asset_id}:#{cve_id}")
    |> Base.encode16(case: :lower)
    |> String.slice(0, 32)
  end

  defp extract_attack_vector(vuln) do
    case vuln[:cvss_vector] do
      nil -> :unknown
      vector when is_binary(vector) ->
        cond do
          String.contains?(vector, "AV:N") -> :network
          String.contains?(vector, "AV:A") -> :adjacent
          String.contains?(vector, "AV:L") -> :local
          String.contains?(vector, "AV:P") -> :physical
          true -> :unknown
        end
      _ -> :unknown
    end
  end

  defp calculate_exploitability(epss_score, cvss_score, vuln) do
    base = epss_score * 0.6 + (cvss_score / 10.0) * 0.3

    # Boost if exploit is known
    boost = cond do
      vuln[:exploit_in_wild] == true -> 0.3
      vuln[:exploit_available] == true -> 0.15
      true -> 0.0
    end

    min(base + boost, 1.0)
  end

  defp calculate_impact_score(cvss_score, asset) do
    base_impact = cvss_score / 10.0

    criticality_multiplier = case asset.criticality do
      "critical" -> 1.5
      "high" -> 1.25
      "medium" -> 1.0
      "low" -> 0.75
      _ -> 1.0
    end

    env_multiplier = case asset.environment do
      "production" -> 1.3
      "staging" -> 1.0
      "development" -> 0.7
      _ -> 1.0
    end

    min(base_impact * criticality_multiplier * env_multiplier, 1.0)
  end

  defp calculate_single_breach_prob(epss_score, cvss_score, asset) do
    # Combine EPSS with asset exposure
    exposure_factor = if asset.security_posture do
      posture = asset.security_posture
      factors = [
        if(posture["rdp_exposed"], do: 0.15, else: 0),
        if(posture["ssh_exposed"], do: 0.1, else: 0),
        if(!posture["antivirus_enabled"], do: 0.1, else: 0),
        if(!posture["disk_encrypted"], do: 0.05, else: 0)
      ]
      Enum.sum(factors)
    else
      0.1
    end

    base_prob = epss_score * 0.7 + (cvss_score / 10.0) * 0.3
    min(base_prob + exposure_factor, 1.0)
  end

  defp calculate_exposure_risk_score(exposure, state) do
    asset_criticality = get_asset_criticality_score(exposure.asset_id, state)

    # Weighted risk calculation
    risk = @risk_weights.epss_score * exposure.epss_score +
           @risk_weights.cvss_score * (exposure.cvss_score / 10.0) +
           @risk_weights.asset_criticality * (asset_criticality / 100.0) +
           @risk_weights.exposure_level * exposure.exploitability +
           @risk_weights.active_exploitation * (if exposure.epss_score > @epss_high_threshold, do: 1.0, else: 0.0)

    risk_score = min(risk * 100, 100.0) |> Float.round(2)

    # Calculate risk reduction if remediated
    risk_reduction = risk_score * exposure.breach_probability

    %{exposure | risk_score: risk_score, risk_reduction: risk_reduction}
  end

  defp get_asset_criticality_score(asset_id, state) do
    case Map.get(state.asset_criticality_matrix, asset_id) do
      nil -> @criticality_levels.medium
      %{score: score} -> score
    end
  end

  ## Private Functions - Asset Criticality

  defp build_criticality_matrix(assets) do
    assets
    |> Enum.map(fn asset ->
      criticality = calculate_asset_criticality(asset)
      {asset.id, criticality}
    end)
    |> Map.new()
  end

  defp calculate_asset_criticality(asset) do
    # Base score from asset classification
    base_score = @criticality_levels[String.to_existing_atom(asset.criticality || "medium")]

    # Adjustments based on asset properties
    adjustments = []

    # Environment adjustment
    env_adj = case asset.environment do
      "production" -> 15
      "staging" -> 5
      "development" -> -10
      _ -> 0
    end
    adjustments = [env_adj | adjustments]

    # Data sensitivity (inferred from tags/type)
    data_adj = cond do
      "pii" in (asset.tags || []) -> 20
      "financial" in (asset.tags || []) -> 25
      "healthcare" in (asset.tags || []) -> 25
      "secrets" in (asset.tags || []) -> 30
      true -> 0
    end
    adjustments = [data_adj | adjustments]

    # Asset type adjustment
    type_adj = case asset.asset_type do
      "domain_controller" -> 30
      "database_server" -> 25
      "web_server" -> 15
      "file_server" -> 10
      "workstation" -> 0
      _ -> 0
    end
    adjustments = [type_adj | adjustments]

    final_score = min(base_score + Enum.sum(adjustments), 100)

    %{
      asset_id: asset.id,
      hostname: asset.hostname,
      score: final_score,
      level: score_to_level(final_score),
      factors: %{
        base: base_score,
        environment: env_adj,
        data_sensitivity: data_adj,
        asset_type: type_adj
      },
      is_crown_jewel: final_score >= @criticality_levels.crown_jewel
    }
  end

  defp score_to_level(score) do
    cond do
      score >= @criticality_levels.crown_jewel -> :crown_jewel
      score >= @criticality_levels.critical -> :critical
      score >= @criticality_levels.high -> :high
      score >= @criticality_levels.medium -> :medium
      score >= @criticality_levels.low -> :low
      true -> :minimal
    end
  end

  ## Private Functions - Crown Jewels

  defp identify_crown_jewel_assets(state) do
    identify_crown_jewel_assets_internal(state.asset_criticality_matrix)
  end

  defp identify_crown_jewel_assets_internal(criticality_matrix) do
    criticality_matrix
    |> Map.values()
    |> Enum.filter(& &1.is_crown_jewel)
    |> Enum.sort_by(& &1.score, :desc)
  end

  ## Private Functions - Attack Path Modeling

  defp model_attack_paths(assets, vulnerabilities, criticality_matrix) do
    # Identify entry points (externally accessible vulnerabilities)
    entry_points = identify_entry_points(vulnerabilities)

    # Identify targets (crown jewels and critical assets)
    targets = criticality_matrix
      |> Map.values()
      |> Enum.filter(fn c -> c.level in [:crown_jewel, :critical] end)
      |> Enum.map(& &1.asset_id)

    # Build attack paths from entry points to targets
    entry_points
    |> Enum.flat_map(fn entry ->
      targets
      |> Enum.map(fn target ->
        build_attack_path(entry, target, assets, vulnerabilities, criticality_matrix)
      end)
      |> Enum.reject(&is_nil/1)
    end)
    |> Enum.sort_by(& &1.risk_score, :desc)
    |> Enum.take(100)  # Limit to top 100 paths
  end

  defp identify_entry_points(vulnerabilities) do
    vulnerabilities
    |> Map.values()
    |> Enum.filter(fn v ->
      v.attack_vector == :network and v.epss_score > @epss_medium_threshold
    end)
  end

  defp build_attack_path(entry_exposure, target_id, _assets, vulnerabilities, criticality_matrix) do
    # Simplified path building - in production would use graph traversal
    if entry_exposure.asset_id == target_id do
      nil
    else
      target_criticality = Map.get(criticality_matrix, target_id, %{score: 50})

      steps = [
        %{type: :initial_access, exposure: entry_exposure, technique: "T1190"},
        %{type: :execution, description: "Execute payload", technique: "T1059"},
        %{type: :lateral_movement, description: "Move to target", technique: "T1021"},
        %{type: :impact, description: "Compromise target", technique: "T1486"}
      ]

      probability = entry_exposure.breach_probability * 0.7  # Decay for multi-step
      impact = target_criticality.score / 100.0

      %AttackPath{
        id: generate_path_id(entry_exposure.id, target_id),
        source: entry_exposure.asset_id,
        target: target_id,
        steps: steps,
        probability: Float.round(probability, 3),
        impact: Float.round(impact, 3),
        risk_score: Float.round(probability * impact * 100, 2),
        mitigations: suggest_path_mitigations(steps, vulnerabilities),
        techniques: Enum.map(steps, & &1.technique)
      }
    end
  end

  defp generate_path_id(source_id, target_id) do
    :crypto.hash(:sha256, "path:#{source_id}:#{target_id}")
    |> Base.encode16(case: :lower)
    |> String.slice(0, 16)
  end

  defp suggest_path_mitigations(steps, _vulnerabilities) do
    steps
    |> Enum.map(fn step ->
      %{
        step: step.type,
        mitigation: get_mitigation_for_technique(step.technique)
      }
    end)
  end

  defp get_mitigation_for_technique(technique) do
    mitigations = %{
      "T1190" => "Patch vulnerable public-facing applications; implement WAF",
      "T1059" => "Enable application whitelisting; restrict script execution",
      "T1021" => "Implement network segmentation; enforce MFA",
      "T1486" => "Maintain offline backups; implement ransomware protection"
    }
    Map.get(mitigations, technique, "Implement defense-in-depth controls")
  end

  ## Private Functions - Breach Probability

  defp calculate_breach_prob(nil, state) do
    calculate_org_breach_probability(state.attack_paths, state.asset_criticality_matrix)
  end

  defp calculate_breach_prob(asset_id, state) do
    asset_vulns = state.vulnerability_graph
      |> Map.values()
      |> Enum.filter(& &1.asset_id == asset_id)

    if Enum.empty?(asset_vulns) do
      0.0
    else
      # Probability of at least one successful breach
      # P(at least one) = 1 - P(none) = 1 - product(1 - p_i)
      none_prob = Enum.reduce(asset_vulns, 1.0, fn v, acc ->
        acc * (1.0 - v.breach_probability)
      end)

      Float.round(1.0 - none_prob, 4)
    end
  end

  defp calculate_org_breach_probability(attack_paths, _criticality_matrix) do
    if Enum.empty?(attack_paths) do
      0.0
    else
      # Use top attack paths to estimate org breach probability
      top_paths = Enum.take(attack_paths, 10)

      none_prob = Enum.reduce(top_paths, 1.0, fn path, acc ->
        acc * (1.0 - path.probability)
      end)

      Float.round(1.0 - none_prob, 4)
    end
  end

  ## Private Functions - Remediation

  defp generate_remediation_actions(vuln, asset) do
    actions = []

    # Patch action
    actions = if vuln[:patch_available] do
      [%RemediationAction{
        id: Ecto.UUID.generate(),
        action_type: :patch,
        description: "Apply security patch for #{vuln[:cve_id] || "vulnerability"}",
        effort_hours: estimate_patch_effort(asset),
        status: :pending
      } | actions]
    else
      actions
    end

    # Workaround if no patch
    actions = if !vuln[:patch_available] do
      [%RemediationAction{
        id: Ecto.UUID.generate(),
        action_type: :workaround,
        description: "Implement compensating controls",
        effort_hours: 4.0,
        status: :pending
      } | actions]
    else
      actions
    end

    # Network isolation for critical vulnerabilities
    actions = if vuln[:severity] == "critical" do
      [%RemediationAction{
        id: Ecto.UUID.generate(),
        action_type: :isolate,
        description: "Isolate affected system until patched",
        effort_hours: 1.0,
        status: :pending
      } | actions]
    else
      actions
    end

    actions
  end

  defp estimate_patch_effort(asset) do
    base = 2.0

    multiplier = case asset.environment do
      "production" -> 2.0
      "staging" -> 1.5
      _ -> 1.0
    end

    base * multiplier
  end

  defp build_remediation_queue(vulnerabilities, _criticality_matrix, _state) do
    vulnerabilities
    |> Map.values()
    |> Enum.filter(& &1.status == :active)
    |> Enum.flat_map(fn exposure ->
      Enum.map(exposure.remediation_actions, fn action ->
        risk_reduction = exposure.risk_reduction
        roi = calculate_roi(risk_reduction, action.effort_hours)

        %{action |
          exposure_id: exposure.id,
          risk_reduction: risk_reduction,
          roi_score: roi
        }
      end)
    end)
    |> Enum.sort_by(& &1.roi_score, :desc)
  end

  defp calculate_roi(risk_reduction, effort_hours) do
    if effort_hours > 0 do
      Float.round(risk_reduction / effort_hours, 2)
    else
      risk_reduction
    end
  end

  defp update_remediation_queue(queue, exposure, _state) do
    new_actions = Enum.map(exposure.remediation_actions, fn action ->
      roi = calculate_roi(exposure.risk_reduction, action.effort_hours)
      %{action | exposure_id: exposure.id, risk_reduction: exposure.risk_reduction, roi_score: roi}
    end)

    (queue ++ new_actions)
    |> Enum.sort_by(& &1.roi_score, :desc)
  end

  defp analyze_remediation(exposure, state) do
    # Calculate impact of remediating this exposure
    affected_paths = Enum.filter(state.attack_paths, fn path ->
      path.source == exposure.asset_id or path.target == exposure.asset_id
    end)

    paths_disrupted = length(affected_paths)
    total_path_risk = Enum.sum(Enum.map(affected_paths, & &1.risk_score))

    %{
      exposure_id: exposure.id,
      cve_id: exposure.cve_id,
      current_risk_score: exposure.risk_score,
      risk_reduction: exposure.risk_reduction,
      breach_probability_reduction: exposure.breach_probability,
      attack_paths_disrupted: paths_disrupted,
      total_path_risk_eliminated: total_path_risk,
      recommended_actions: exposure.remediation_actions,
      estimated_effort: Enum.sum(Enum.map(exposure.remediation_actions, & &1.effort_hours || 0)),
      roi_score: calculate_total_roi(exposure)
    }
  end

  defp calculate_total_roi(exposure) do
    total_effort = Enum.sum(Enum.map(exposure.remediation_actions, & &1.effort_hours || 0))
    calculate_roi(exposure.risk_reduction, total_effort)
  end

  defp calculate_risk_reduction(exposure, _state) do
    exposure.risk_reduction
  end

  ## Private Functions - Vulnerability Management

  defp prioritize_vulnerabilities(vulnerabilities, state) do
    vulnerabilities
    |> Enum.map(fn v -> calculate_exposure_risk_score(v, state) end)
    |> Enum.sort_by(& &1.risk_score, :desc)
    |> Enum.with_index(1)
    |> Enum.map(fn {v, rank} -> %{v | priority_rank: rank} end)
  end

  defp rescore_vulnerabilities(vuln_graph, epss_cache, state) do
    vuln_graph
    |> Map.new(fn {id, exposure} ->
      epss_data = Map.get(epss_cache, exposure.cve_id, %{epss: exposure.epss_score})
      updated = %{exposure | epss_score: epss_data[:epss] || exposure.epss_score}
      rescored = calculate_exposure_risk_score(updated, state)
      {id, rescored}
    end)
  end

  defp create_exposure(data, state) do
    %Exposure{
      id: data[:id] || Ecto.UUID.generate(),
      type: data[:type] || :vulnerability,
      asset_id: data[:asset_id],
      cve_id: data[:cve_id],
      epss_score: get_epss_score(data[:cve_id], state),
      cvss_score: data[:cvss_score] || 0.0,
      cvss_vector: data[:cvss_vector],
      description: data[:description],
      affected_component: data[:affected_component],
      attack_vector: data[:attack_vector] || :unknown,
      exploitability: 0.0,
      impact_score: 0.0,
      breach_probability: 0.0,
      risk_score: 0.0,
      priority_rank: 0,
      remediation_actions: data[:remediation_actions] || [],
      risk_reduction: 0.0,
      discovered_at: DateTime.utc_now(),
      last_seen: DateTime.utc_now(),
      status: :active
    }
    |> then(fn e ->
      %{e |
        exploitability: calculate_exploitability(e.epss_score, e.cvss_score, %{}),
        breach_probability: e.epss_score * 0.8 + (e.cvss_score / 10.0) * 0.2
      }
    end)
    |> calculate_exposure_risk_score(state)
  end

  defp get_epss_score(nil, _state), do: 0.0
  defp get_epss_score(cve_id, state) do
    case Map.get(state.epss_cache, cve_id) do
      nil -> 0.0
      data -> data[:epss] || 0.0
    end
  end

  ## Private Functions - Helpers

  defp filter_by_asset(vulnerabilities, nil), do: vulnerabilities
  defp filter_by_asset(vulnerabilities, asset_id) do
    Enum.filter(vulnerabilities, & &1.asset_id == asset_id)
  end

  defp filter_attack_paths(paths, nil, min_prob) do
    Enum.filter(paths, & &1.probability >= min_prob)
  end
  defp filter_attack_paths(paths, target_id, min_prob) do
    paths
    |> Enum.filter(& &1.target == target_id)
    |> Enum.filter(& &1.probability >= min_prob)
  end

  defp summarize_attack_surface(surface, assets) do
    %{
      categories: @surface_categories,
      network: %{
        exposed_services: length(surface.network.exposed_services),
        external_ips: count_external_ips(assets)
      },
      endpoint: %{
        total: length(assets),
        vulnerable: Enum.count(assets, & &1.vulnerability_count > 0)
      },
      identity: surface.identity,
      cloud: surface.cloud
    }
  end

  defp count_external_ips(assets) do
    assets
    |> Enum.flat_map(& &1.ip_addresses || [])
    |> Enum.filter(&is_public_ip?/1)
    |> Enum.uniq()
    |> length()
  end

  defp is_public_ip?(ip) when is_binary(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, {a, _, _, _}} when a in [10, 127] -> false
      {:ok, {172, b, _, _}} when b >= 16 and b <= 31 -> false
      {:ok, {192, 168, _, _}} -> false
      {:ok, _} -> true
      _ -> false
    end
  end
  defp is_public_ip?(_), do: false

  defp count_critical_exposures(vulnerabilities) do
    vulnerabilities
    |> Map.values()
    |> Enum.count(fn v -> v.cvss_score >= 9.0 or v.epss_score >= @epss_high_threshold end)
  end

  defp count_high_risk_assets(criticality_matrix) do
    criticality_matrix
    |> Map.values()
    |> Enum.count(fn c -> c.level in [:crown_jewel, :critical, :high] end)
  end

  defp get_top_risks(vulnerabilities, limit) do
    vulnerabilities
    |> Map.values()
    |> Enum.sort_by(& &1.risk_score, :desc)
    |> Enum.take(limit)
    |> Enum.map(fn v ->
      %{
        cve_id: v.cve_id,
        risk_score: v.risk_score,
        epss_score: v.epss_score,
        asset_id: v.asset_id
      }
    end)
  end

  defp categorize_risks(vulnerabilities) do
    vulnerabilities
    |> Map.values()
    |> Enum.group_by(fn v ->
      cond do
        v.risk_score >= 80 -> :critical
        v.risk_score >= 60 -> :high
        v.risk_score >= 40 -> :medium
        v.risk_score >= 20 -> :low
        true -> :minimal
      end
    end)
    |> Enum.map(fn {level, vulns} -> {level, length(vulns)} end)
    |> Map.new()
  end

  defp summarize_remediation_queue(queue) do
    %{
      total_pending: Enum.count(queue, & &1.status == :pending),
      total_effort_hours: Enum.sum(Enum.map(queue, & &1.effort_hours || 0)),
      total_risk_reduction: Enum.sum(Enum.map(queue, & &1.risk_reduction || 0)),
      by_action_type: Enum.group_by(queue, & &1.action_type)
        |> Enum.map(fn {type, actions} -> {type, length(actions)} end)
        |> Map.new()
    }
  end

  defp count_active_exposures(vuln_graph) do
    vuln_graph
    |> Map.values()
    |> Enum.count(& &1.status == :active)
  end

  defp count_pending_remediations(queue) do
    Enum.count(queue, & &1.status == :pending)
  end

  defp calculate_average([], _key), do: 0.0
  defp calculate_average(list, key) do
    sum = Enum.sum(Enum.map(list, &Map.get(&1, key, 0)))
    Float.round(sum / length(list), 2)
  end

  defp calculate_risk_trend(history, days) do
    recent = Enum.take(history, days)
    older = history |> Enum.drop(days) |> Enum.take(days)

    recent_sum = Enum.sum(Enum.map(recent, & &1.risk_reduction))
    older_sum = Enum.sum(Enum.map(older, & &1.risk_reduction))

    cond do
      older_sum == 0 -> :stable
      recent_sum > older_sum -> :improving
      recent_sum < older_sum -> :declining
      true -> :stable
    end
  end

  defp update_stats(stats, :analysis_performed) do
    Map.update(stats, :analyses_performed, 1, &(&1 + 1))
  end
  defp update_stats(stats, :exposure_registered) do
    Map.update(stats, :exposures_registered, 1, &(&1 + 1))
  end
  defp update_stats(stats, :exposure_remediated) do
    Map.update(stats, :exposures_remediated, 1, &(&1 + 1))
  end

  ## Private Functions - Scheduling

  defp schedule_analysis do
    Process.send_after(self(), :periodic_analysis, :timer.hours(1))
  end

  defp schedule_epss_refresh do
    Process.send_after(self(), :refresh_epss, :timer.hours(24))
  end

  defp fetch_epss_updates do
    # In production, this would fetch from https://api.first.org/data/v1/epss
    Logger.debug("EPSS update check - would fetch from FIRST API")
    :ok
  end
end
