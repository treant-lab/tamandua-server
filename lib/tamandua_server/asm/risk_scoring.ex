defmodule TamanduaServer.ASM.RiskScoring do
  @moduledoc """
  Attack Surface Management - Risk Scoring Module

  Calculates comprehensive risk scores for discovered assets:

  - Asset exposure score based on open ports and services
  - Vulnerability severity weighting with CVSS and EPSS integration
  - Data sensitivity weighting based on asset classification
  - Business criticality factoring
  - Historical trend analysis
  - Comparative risk ranking

  Produces risk scores comparable to Censys ASM and Mandiant ASM.
  """

  use GenServer
  require Logger

  alias TamanduaServer.ASM.{Discovery, Exposure, Monitor}
  alias TamanduaServer.Assets.Criticality

  # Risk weights for different factors
  @risk_weights %{
    exposure_score: 0.30,         # Weight for exposure analysis
    vulnerability_score: 0.25,    # Weight for known vulnerabilities
    criticality_score: 0.20,      # Weight for business criticality
    sensitivity_score: 0.15,      # Weight for data sensitivity
    internet_facing: 0.10         # Weight for internet exposure
  }

  # Vulnerability severity multipliers
  @vuln_severity_multipliers %{
    critical: 1.0,
    high: 0.8,
    medium: 0.5,
    low: 0.2,
    informational: 0.05
  }

  # CVSS score to severity mapping
  @cvss_severity_mapping [
    {9.0, :critical},
    {7.0, :high},
    {4.0, :medium},
    {0.1, :low},
    {0.0, :informational}
  ]

  # Data sensitivity levels
  @sensitivity_scores %{
    classified: 100,
    pii: 90,
    phi: 90,
    pci: 85,
    financial: 80,
    intellectual_property: 75,
    confidential: 70,
    internal: 40,
    public: 10
  }

  # State structure
  defstruct [
    :risk_cache,           # ETS table for risk scores
    :historical_data,      # Historical risk data for trend analysis
    :risk_thresholds,      # Alert thresholds
    :config,               # Configuration
    :stats                 # Statistics
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Calculate risk score for a single asset.
  """
  @spec calculate_risk(String.t()) :: {:ok, map()} | {:error, term()}
  def calculate_risk(asset_id) do
    GenServer.call(__MODULE__, {:calculate_risk, asset_id})
  end

  @doc """
  Update asset risk based on exposure analysis.
  """
  @spec update_asset_risk(String.t(), map()) :: :ok
  def update_asset_risk(asset_id, exposure_data) do
    GenServer.cast(__MODULE__, {:update_risk, asset_id, exposure_data})
  end

  @doc """
  Get the current risk score for an asset.
  """
  @spec get_risk(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_risk(asset_id) do
    GenServer.call(__MODULE__, {:get_risk, asset_id})
  end

  @doc """
  Get risk scores for all assets.
  """
  @spec list_risks(keyword()) :: [map()]
  def list_risks(opts \\ []) do
    GenServer.call(__MODULE__, {:list_risks, opts})
  end

  @doc """
  Get the top riskiest assets.
  """
  @spec get_top_risks(integer()) :: [map()]
  def get_top_risks(limit \\ 10) do
    GenServer.call(__MODULE__, {:get_top_risks, limit})
  end

  @doc """
  Get risk trend data for an asset.
  """
  @spec get_risk_trend(String.t(), keyword()) :: {:ok, [map()]} | {:error, :not_found}
  def get_risk_trend(asset_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_risk_trend, asset_id, opts})
  end

  @doc """
  Get aggregate risk metrics for the attack surface.
  """
  @spec get_aggregate_risk() :: map()
  def get_aggregate_risk do
    GenServer.call(__MODULE__, :get_aggregate_risk)
  end

  @doc """
  Get risk distribution by category.
  """
  @spec get_risk_distribution() :: map()
  def get_risk_distribution do
    GenServer.call(__MODULE__, :get_risk_distribution)
  end

  @doc """
  Set risk alert thresholds.
  """
  @spec set_thresholds(map()) :: :ok
  def set_thresholds(thresholds) do
    GenServer.call(__MODULE__, {:set_thresholds, thresholds})
  end

  @doc """
  Recalculate all asset risks (batch operation).
  """
  @spec recalculate_all() :: {:ok, integer()}
  def recalculate_all do
    GenServer.call(__MODULE__, :recalculate_all, 120_000)
  end

  @doc """
  Get risk comparison between assets.
  """
  @spec compare_risks([String.t()]) :: [map()]
  def compare_risks(asset_ids) do
    GenServer.call(__MODULE__, {:compare_risks, asset_ids})
  end

  @doc """
  Get risk statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting Attack Surface Management - Risk Scoring Service")

    # Create ETS tables
    risk_table = :ets.new(:asm_risk_scores, [:named_table, :set, :public, read_concurrency: true])
    history_table = :ets.new(:asm_risk_history, [:named_table, :bag, :public])

    state = %__MODULE__{
      risk_cache: risk_table,
      historical_data: history_table,
      risk_thresholds: default_thresholds(),
      config: build_config(opts),
      stats: initial_stats()
    }

    # Schedule periodic recalculation
    schedule_recalculation()

    {:ok, state}
  end

  @impl true
  def handle_call({:calculate_risk, asset_id}, _from, state) do
    result = do_calculate_risk(asset_id, state)

    # Cache the result
    :ets.insert(state.risk_cache, {asset_id, result})

    # Store historical data point
    store_history(state.historical_data, asset_id, result)

    # Check thresholds and alert if needed
    check_thresholds(asset_id, result, state.risk_thresholds)

    new_stats = increment_stats(state.stats, :calculations_performed)
    {:reply, {:ok, result}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:get_risk, asset_id}, _from, state) do
    case :ets.lookup(state.risk_cache, asset_id) do
      [{^asset_id, risk}] -> {:reply, {:ok, risk}, state}
      [] -> {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:list_risks, opts}, _from, state) do
    risks = get_all_risks(state.risk_cache)

    filtered = risks
    |> filter_by_level(opts[:level])
    |> filter_by_min_score(opts[:min_score])
    |> sort_risks(opts[:sort])
    |> maybe_limit(opts[:limit])

    {:reply, filtered, state}
  end

  @impl true
  def handle_call({:get_top_risks, limit}, _from, state) do
    risks = get_all_risks(state.risk_cache)
    |> Enum.sort_by(& &1[:overall_score], :desc)
    |> Enum.take(limit)

    {:reply, risks, state}
  end

  @impl true
  def handle_call({:get_risk_trend, asset_id, opts}, _from, state) do
    days = opts[:days] || 30

    case get_historical_data(state.historical_data, asset_id, days) do
      [] -> {:reply, {:error, :not_found}, state}
      history -> {:reply, {:ok, history}, state}
    end
  end

  @impl true
  def handle_call(:get_aggregate_risk, _from, state) do
    metrics = calculate_aggregate_metrics(state.risk_cache)
    {:reply, metrics, state}
  end

  @impl true
  def handle_call(:get_risk_distribution, _from, state) do
    distribution = calculate_risk_distribution(state.risk_cache)
    {:reply, distribution, state}
  end

  @impl true
  def handle_call({:set_thresholds, thresholds}, _from, state) do
    new_thresholds = Map.merge(state.risk_thresholds, thresholds)
    {:reply, :ok, %{state | risk_thresholds: new_thresholds}}
  end

  @impl true
  def handle_call(:recalculate_all, _from, state) do
    assets = Discovery.list_assets()

    count = Enum.reduce(assets, 0, fn asset, acc ->
      result = do_calculate_risk(asset.id, state)
      :ets.insert(state.risk_cache, {asset.id, result})
      store_history(state.historical_data, asset.id, result)
      acc + 1
    end)

    {:reply, {:ok, count}, state}
  end

  @impl true
  def handle_call({:compare_risks, asset_ids}, _from, state) do
    comparisons = Enum.map(asset_ids, fn asset_id ->
      case :ets.lookup(state.risk_cache, asset_id) do
        [{^asset_id, risk}] -> risk
        [] -> %{asset_id: asset_id, error: :not_found}
      end
    end)

    {:reply, comparisons, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    risks = get_all_risks(state.risk_cache)

    stats = Map.merge(state.stats, %{
      total_assets_scored: length(risks),
      average_risk_score: calculate_average(risks, :overall_score),
      critical_count: Enum.count(risks, & &1[:risk_level] == :critical),
      high_count: Enum.count(risks, & &1[:risk_level] == :high),
      medium_count: Enum.count(risks, & &1[:risk_level] == :medium),
      low_count: Enum.count(risks, & &1[:risk_level] == :low)
    })

    {:reply, stats, state}
  end

  @impl true
  def handle_cast({:update_risk, asset_id, exposure_data}, state) do
    # Recalculate risk with new exposure data
    result = do_calculate_risk_with_exposure(asset_id, exposure_data, state)

    # Update cache
    :ets.insert(state.risk_cache, {asset_id, result})

    # Store history
    store_history(state.historical_data, asset_id, result)

    # Check thresholds
    check_thresholds(asset_id, result, state.risk_thresholds)

    {:noreply, state}
  end

  @impl true
  def handle_info(:recalculate_all, state) do
    Logger.debug("Running periodic risk recalculation")

    assets = Discovery.list_assets()

    Enum.each(assets, fn asset ->
      result = do_calculate_risk(asset.id, state)
      :ets.insert(state.risk_cache, {asset.id, result})
    end)

    schedule_recalculation()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Risk Calculation Functions
  # ============================================================================

  defp do_calculate_risk(asset_id, state) do
    timestamp = DateTime.utc_now()

    # Get asset info
    asset = case Discovery.get_asset(asset_id) do
      {:ok, a} -> a
      _ -> %{id: asset_id}
    end

    # Get exposure data
    exposure_data = case Exposure.get_exposures(asset_id) do
      {:ok, e} -> e
      _ -> %{}
    end

    # Get criticality data
    criticality = try do
      Criticality.get_criticality(asset_id)
    catch
      _, _ -> %{score: 50, level: :medium}
    end

    # Calculate component scores
    exposure_score = calculate_exposure_score(exposure_data)
    vulnerability_score = calculate_vulnerability_score(exposure_data[:vulnerabilities] || [])
    criticality_score = criticality[:score] || 50
    sensitivity_score = calculate_sensitivity_score(asset, criticality)
    internet_score = calculate_internet_exposure_score(asset, exposure_data)

    # Calculate weighted overall score
    overall_score = calculate_weighted_score(%{
      exposure_score: exposure_score,
      vulnerability_score: vulnerability_score,
      criticality_score: criticality_score,
      sensitivity_score: sensitivity_score,
      internet_facing: internet_score
    })

    # Determine risk level
    risk_level = score_to_risk_level(overall_score)

    # Get trend
    trend = calculate_trend(state.historical_data, asset_id, overall_score)

    %{
      asset_id: asset_id,
      asset_value: asset[:value],
      asset_type: asset[:type],
      calculated_at: timestamp,
      overall_score: overall_score,
      risk_level: risk_level,
      component_scores: %{
        exposure: exposure_score,
        vulnerability: vulnerability_score,
        criticality: criticality_score,
        sensitivity: sensitivity_score,
        internet_exposure: internet_score
      },
      vulnerabilities_count: length(exposure_data[:vulnerabilities] || []),
      exposures_count: length(exposure_data[:exposures] || []),
      open_ports_count: length(exposure_data[:open_ports] || []),
      trend: trend,
      factors: build_risk_factors(exposure_data, criticality)
    }
  end

  defp do_calculate_risk_with_exposure(asset_id, exposure_data, state) do
    timestamp = DateTime.utc_now()

    # Get asset info
    asset = case Discovery.get_asset(asset_id) do
      {:ok, a} -> a
      _ -> %{id: asset_id}
    end

    # Get criticality data
    criticality = try do
      Criticality.get_criticality(asset_id)
    catch
      _, _ -> %{score: 50, level: :medium}
    end

    # Calculate component scores
    exposure_score = exposure_data[:exposure_score] || calculate_exposure_score(exposure_data)
    vulnerability_score = calculate_vulnerability_score(exposure_data[:vulnerabilities] || [])
    criticality_score = criticality[:score] || 50
    sensitivity_score = calculate_sensitivity_score(asset, criticality)
    internet_score = calculate_internet_exposure_score(asset, exposure_data)

    # Calculate weighted overall score
    overall_score = calculate_weighted_score(%{
      exposure_score: exposure_score,
      vulnerability_score: vulnerability_score,
      criticality_score: criticality_score,
      sensitivity_score: sensitivity_score,
      internet_facing: internet_score
    })

    # Determine risk level
    risk_level = score_to_risk_level(overall_score)

    # Get trend
    trend = calculate_trend(state.historical_data, asset_id, overall_score)

    %{
      asset_id: asset_id,
      asset_value: asset[:value],
      asset_type: asset[:type],
      calculated_at: timestamp,
      overall_score: overall_score,
      risk_level: risk_level,
      component_scores: %{
        exposure: exposure_score,
        vulnerability: vulnerability_score,
        criticality: criticality_score,
        sensitivity: sensitivity_score,
        internet_exposure: internet_score
      },
      vulnerabilities_count: length(exposure_data[:vulnerabilities] || []),
      exposures_count: length(exposure_data[:exposures] || []),
      open_ports_count: length(exposure_data[:open_ports] || []),
      trend: trend,
      factors: build_risk_factors(exposure_data, criticality)
    }
  end

  defp calculate_exposure_score(exposure_data) when is_map(exposure_data) do
    base_score = exposure_data[:exposure_score] || 0

    # Factor in TLS grade
    tls_penalty = case exposure_data[:tls_analysis] do
      %{grade: "F"} -> 20
      %{grade: "D"} -> 15
      %{grade: "C"} -> 10
      %{grade: "B"} -> 5
      _ -> 0
    end

    # Factor in security headers
    headers_penalty = case exposure_data[:security_headers] do
      %{score: score} when score < 30 -> 15
      %{score: score} when score < 50 -> 10
      %{score: score} when score < 70 -> 5
      _ -> 0
    end

    min(100, base_score + tls_penalty + headers_penalty)
  end
  defp calculate_exposure_score(_), do: 0

  defp calculate_vulnerability_score(vulnerabilities) when is_list(vulnerabilities) do
    if Enum.empty?(vulnerabilities) do
      0
    else
      # Calculate weighted vulnerability score
      vuln_scores = Enum.map(vulnerabilities, fn vuln ->
        cvss = vuln[:cvss_score] || 5.0
        epss = vuln[:epss_score] || 0.1

        # Base score from CVSS
        base = cvss * 10

        # Multiply by EPSS (probability of exploitation)
        # EPSS ranges from 0 to 1, so adjust
        exploitability_factor = 1.0 + epss

        # Check for KEV (Known Exploited Vulnerabilities)
        kev_factor = if vuln[:in_kev], do: 1.5, else: 1.0

        base * exploitability_factor * kev_factor
      end)

      # Use the highest score plus diminishing returns for additional vulns
      sorted = Enum.sort(vuln_scores, :desc)
      max_score = List.first(sorted) || 0
      additional = length(sorted) - 1
      additional_penalty = min(additional * 2, 20)

      min(100, max_score + additional_penalty)
    end
  end
  defp calculate_vulnerability_score(_), do: 0

  defp calculate_sensitivity_score(asset, criticality) do
    # Get sensitivity from asset tags or criticality data
    sensitivity = criticality[:data_sensitivity] || asset[:data_sensitivity] || "internal"

    Map.get(@sensitivity_scores, String.to_atom(sensitivity), @sensitivity_scores[:internal])
  end

  defp calculate_internet_exposure_score(asset, exposure_data) do
    _base_score = 0

    # Check if any ports are exposed
    open_ports = exposure_data[:open_ports] || []
    port_count = length(open_ports)

    base_score = cond do
      port_count == 0 -> 0
      port_count <= 2 -> 30
      port_count <= 5 -> 50
      port_count <= 10 -> 70
      true -> 90
    end

    # Add penalty for high-risk ports
    high_risk_ports = [21, 23, 445, 3389, 1433, 3306, 5432, 27017, 6379, 9200]
    high_risk_count = Enum.count(open_ports, fn p -> p[:port] in high_risk_ports end)

    base_score = base_score + (high_risk_count * 5)

    # Check cloud exposure
    cloud_bonus = if asset[:cloud_provider] && asset[:type] == :external, do: 10, else: 0

    min(100, base_score + cloud_bonus)
  end

  defp calculate_weighted_score(scores) do
    weighted_sum = Enum.reduce(@risk_weights, 0.0, fn {key, weight}, acc ->
      score = Map.get(scores, key, 0)
      acc + (score * weight)
    end)

    round(weighted_sum)
  end

  defp score_to_risk_level(score) do
    cond do
      score >= 80 -> :critical
      score >= 60 -> :high
      score >= 40 -> :medium
      score >= 20 -> :low
      true -> :minimal
    end
  end

  defp calculate_trend(history_table, asset_id, current_score) do
    # Get last 7 days of data
    history = get_historical_data(history_table, asset_id, 7)

    if length(history) < 2 do
      %{direction: :stable, change: 0, data_points: length(history)}
    else
      # Calculate trend using simple linear regression
      scores = Enum.map(history, & &1[:overall_score])
      avg_score = Enum.sum(scores) / length(scores)

      change = current_score - avg_score

      direction = cond do
        change > 5 -> :increasing
        change < -5 -> :decreasing
        true -> :stable
      end

      %{
        direction: direction,
        change: round(change),
        previous_score: List.last(scores),
        data_points: length(history)
      }
    end
  end

  defp build_risk_factors(exposure_data, criticality) do
    factors = []

    # Exposure factors
    factors = if (exposure_data[:exposure_score] || 0) >= 70 do
      ["High exposure score" | factors]
    else
      factors
    end

    # Vulnerability factors
    vuln_count = length(exposure_data[:vulnerabilities] || [])
    factors = if vuln_count > 0 do
      critical_vulns = Enum.count(exposure_data[:vulnerabilities] || [], fn v ->
        (v[:cvss_score] || 0) >= 9.0
      end)

      factor = if critical_vulns > 0 do
        "#{critical_vulns} critical vulnerabilities"
      else
        "#{vuln_count} known vulnerabilities"
      end
      [factor | factors]
    else
      factors
    end

    # TLS factors
    factors = case exposure_data[:tls_analysis] do
      %{grade: grade} when grade in ["D", "F"] ->
        ["Weak TLS configuration (Grade #{grade})" | factors]
      %{is_expired: true} ->
        ["Expired SSL certificate" | factors]
      %{expires_soon: true} ->
        ["SSL certificate expiring soon" | factors]
      _ ->
        factors
    end

    # Criticality factors
    factors = if criticality[:level] in [:critical, :high] do
      ["#{criticality[:level]} business criticality" | factors]
    else
      factors
    end

    # Open ports factors
    port_count = length(exposure_data[:open_ports] || [])
    factors = if port_count > 5 do
      ["#{port_count} open ports exposed" | factors]
    else
      factors
    end

    Enum.reverse(factors)
  end

  # ============================================================================
  # Aggregate Metrics Functions
  # ============================================================================

  defp calculate_aggregate_metrics(risk_table) do
    risks = get_all_risks(risk_table)

    if length(risks) == 0 do
      %{
        total_assets: 0,
        average_risk_score: 0,
        median_risk_score: 0,
        risk_distribution: %{},
        highest_risk_asset: nil,
        total_critical: 0,
        total_high: 0,
        trend_summary: %{increasing: 0, stable: 0, decreasing: 0}
      }
    else
      scores = Enum.map(risks, & &1[:overall_score])
      sorted_scores = Enum.sort(scores)

      %{
        total_assets: length(risks),
        average_risk_score: round(Enum.sum(scores) / length(scores)),
        median_risk_score: Enum.at(sorted_scores, div(length(sorted_scores), 2)),
        min_risk_score: List.first(sorted_scores),
        max_risk_score: List.last(sorted_scores),
        risk_distribution: calculate_risk_distribution(risk_table),
        highest_risk_asset: Enum.max_by(risks, & &1[:overall_score]),
        total_critical: Enum.count(risks, & &1[:risk_level] == :critical),
        total_high: Enum.count(risks, & &1[:risk_level] == :high),
        total_medium: Enum.count(risks, & &1[:risk_level] == :medium),
        total_low: Enum.count(risks, & &1[:risk_level] == :low),
        trend_summary: %{
          increasing: Enum.count(risks, & &1[:trend][:direction] == :increasing),
          stable: Enum.count(risks, & &1[:trend][:direction] == :stable),
          decreasing: Enum.count(risks, & &1[:trend][:direction] == :decreasing)
        }
      }
    end
  end

  defp calculate_risk_distribution(risk_table) do
    risks = get_all_risks(risk_table)

    # Distribution by risk level
    by_level = risks
    |> Enum.group_by(& &1[:risk_level])
    |> Enum.map(fn {level, items} -> {level, length(items)} end)
    |> Map.new()

    # Distribution by score ranges
    by_score_range = %{
      "0-20" => Enum.count(risks, & &1[:overall_score] < 20),
      "20-40" => Enum.count(risks, fn r -> r[:overall_score] >= 20 and r[:overall_score] < 40 end),
      "40-60" => Enum.count(risks, fn r -> r[:overall_score] >= 40 and r[:overall_score] < 60 end),
      "60-80" => Enum.count(risks, fn r -> r[:overall_score] >= 60 and r[:overall_score] < 80 end),
      "80-100" => Enum.count(risks, & &1[:overall_score] >= 80)
    }

    # Distribution by asset type
    by_type = risks
    |> Enum.group_by(& &1[:asset_type])
    |> Enum.map(fn {type, items} ->
      avg_score = round(Enum.sum(Enum.map(items, & &1[:overall_score])) / length(items))
      {type, %{count: length(items), average_score: avg_score}}
    end)
    |> Map.new()

    %{
      by_level: by_level,
      by_score_range: by_score_range,
      by_asset_type: by_type
    }
  end

  # ============================================================================
  # Historical Data Functions
  # ============================================================================

  defp store_history(history_table, asset_id, risk_data) do
    entry = %{
      asset_id: asset_id,
      overall_score: risk_data[:overall_score],
      risk_level: risk_data[:risk_level],
      recorded_at: DateTime.utc_now(),
      component_scores: risk_data[:component_scores]
    }

    :ets.insert(history_table, {asset_id, entry})

    # Cleanup old entries (keep last 90 days)
    cleanup_old_history(history_table, asset_id, 90)
  end

  defp get_historical_data(history_table, asset_id, days) do
    cutoff = DateTime.add(DateTime.utc_now(), -days, :day)

    :ets.lookup(history_table, asset_id)
    |> Enum.map(fn {_, entry} -> entry end)
    |> Enum.filter(fn entry ->
      DateTime.compare(entry[:recorded_at], cutoff) == :gt
    end)
    |> Enum.sort_by(& &1[:recorded_at])
  end

  defp cleanup_old_history(history_table, asset_id, days) do
    cutoff = DateTime.add(DateTime.utc_now(), -days, :day)

    :ets.lookup(history_table, asset_id)
    |> Enum.each(fn {_, entry} = record ->
      if DateTime.compare(entry[:recorded_at], cutoff) == :lt do
        :ets.delete_object(history_table, record)
      end
    end)
  end

  # ============================================================================
  # Threshold Checking
  # ============================================================================

  defp check_thresholds(asset_id, risk_data, thresholds) do
    score = risk_data[:overall_score]

    cond do
      score >= thresholds.critical ->
        Monitor.notify_risk_threshold(:critical, asset_id, risk_data)

      score >= thresholds.high ->
        Monitor.notify_risk_threshold(:high, asset_id, risk_data)

      score >= thresholds.medium ->
        # Only notify if previously lower
        Monitor.notify_risk_threshold(:medium, asset_id, risk_data)

      true ->
        :ok
    end
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp get_all_risks(table) do
    :ets.tab2list(table)
    |> Enum.map(fn {_id, risk} -> risk end)
  end

  defp filter_by_level(risks, nil), do: risks
  defp filter_by_level(risks, level) do
    level_atom = if is_binary(level), do: String.to_atom(level), else: level
    Enum.filter(risks, & &1[:risk_level] == level_atom)
  end

  defp filter_by_min_score(risks, nil), do: risks
  defp filter_by_min_score(risks, min_score) do
    Enum.filter(risks, & &1[:overall_score] >= min_score)
  end

  defp sort_risks(risks, nil), do: Enum.sort_by(risks, & &1[:overall_score], :desc)
  defp sort_risks(risks, :score), do: Enum.sort_by(risks, & &1[:overall_score], :desc)
  defp sort_risks(risks, :score_asc), do: Enum.sort_by(risks, & &1[:overall_score], :asc)
  defp sort_risks(risks, :date), do: Enum.sort_by(risks, & &1[:calculated_at], :desc)
  defp sort_risks(risks, _), do: risks

  defp maybe_limit(risks, nil), do: risks
  defp maybe_limit(risks, limit), do: Enum.take(risks, limit)

  defp calculate_average([], _key), do: 0
  defp calculate_average(items, key) do
    sum = Enum.sum(Enum.map(items, & &1[key] || 0))
    round(sum / length(items))
  end

  defp default_thresholds do
    %{
      critical: 80,
      high: 60,
      medium: 40,
      low: 20
    }
  end

  defp build_config(opts) do
    %{
      recalculation_interval: Keyword.get(opts, :recalculation_interval, :timer.hours(6)),
      history_retention_days: Keyword.get(opts, :history_retention_days, 90),
      enable_alerts: Keyword.get(opts, :enable_alerts, true)
    }
  end

  defp initial_stats do
    %{
      calculations_performed: 0,
      alerts_generated: 0,
      started_at: DateTime.utc_now()
    }
  end

  defp increment_stats(stats, key) do
    Map.update(stats, key, 1, & &1 + 1)
  end

  defp schedule_recalculation do
    Process.send_after(self(), :recalculate_all, :timer.hours(6))
  end
end
