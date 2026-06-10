defmodule TamanduaServer.ThreatIntel.FeedAnalytics do
  @moduledoc """
  Feed Performance Analytics System.

  Provides comprehensive analytics and insights about threat intelligence feeds:
  - IOC overlap analysis across feeds
  - Feed performance comparison (accuracy, latency, coverage)
  - Cost per IOC calculation
  - ROI metrics per feed
  - Detection rate analysis
  - Feed correlation matrix
  - Trending analysis

  ## Metrics Tracked

  - **Coverage**: Unique vs shared IOCs
  - **Accuracy**: True positive vs false positive rates
  - **Latency**: Time from threat emergence to feed inclusion
  - **Cost Efficiency**: Cost per unique IOC, cost per detection
  - **Reliability**: Uptime, error rates, data freshness
  - **Value**: Detections attributed to each feed

  ## Usage

      # Get feed performance report
      FeedAnalytics.get_feed_performance("recorded_future")

      # Compare feeds
      FeedAnalytics.compare_feeds(["recorded_future", "crowdstrike"])

      # Get overlap analysis
      FeedAnalytics.analyze_ioc_overlap()

      # Calculate ROI
      FeedAnalytics.calculate_feed_roi("recorded_future")
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.IOCs
  alias TamanduaServer.Alerts
  alias TamanduaServer.ThreatIntel.Aggregator

  @analysis_interval :timer.hours(6)

  # Feed cost estimates (annual USD) - configurable per deployment
  @feed_costs %{
    "recorded_future" => 50_000,
    "crowdstrike" => 40_000,
    "mandiant" => 45_000,
    "palo_alto_autofocus" => 35_000,
    "anomali" => 38_000,
    "ibm_xforce" => 30_000,
    "cisco_talos" => 25_000,
    "proofpoint" => 32_000,
    "emerging_threats" => 10_000,
    "greynoise" => 15_000
  }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get comprehensive performance metrics for a feed.
  """
  @spec get_feed_performance(String.t()) :: {:ok, map()} | {:error, term()}
  def get_feed_performance(feed_name) do
    GenServer.call(__MODULE__, {:get_feed_performance, feed_name}, 30_000)
  end

  @doc """
  Compare multiple feeds across key metrics.
  """
  @spec compare_feeds([String.t()]) :: {:ok, map()} | {:error, term()}
  def compare_feeds(feed_names) when is_list(feed_names) do
    GenServer.call(__MODULE__, {:compare_feeds, feed_names}, 60_000)
  end

  @doc """
  Analyze IOC overlap across all feeds.

  Returns overlap matrix showing how many IOCs are shared between feeds.
  """
  @spec analyze_ioc_overlap() :: {:ok, map()}
  def analyze_ioc_overlap do
    GenServer.call(__MODULE__, :analyze_ioc_overlap, 60_000)
  end

  @doc """
  Calculate ROI for a specific feed.
  """
  @spec calculate_feed_roi(String.t()) :: {:ok, map()} | {:error, term()}
  def calculate_feed_roi(feed_name) do
    GenServer.call(__MODULE__, {:calculate_feed_roi, feed_name}, 30_000)
  end

  @doc """
  Get cost efficiency metrics.
  """
  @spec get_cost_efficiency() :: {:ok, map()}
  def get_cost_efficiency do
    GenServer.call(__MODULE__, :get_cost_efficiency, 30_000)
  end

  @doc """
  Get detection attribution analysis.

  Shows which feeds contributed to actual threat detections.
  """
  @spec get_detection_attribution(keyword()) :: {:ok, [map()]}
  def get_detection_attribution(opts \\ []) do
    GenServer.call(__MODULE__, {:get_detection_attribution, opts}, 30_000)
  end

  @doc """
  Get trending threats across feeds.
  """
  @spec get_trending_threats(keyword()) :: {:ok, [map()]}
  def get_trending_threats(opts \\ []) do
    GenServer.call(__MODULE__, {:get_trending_threats, opts}, 30_000)
  end

  @doc """
  Get feed correlation matrix.

  Shows how often feeds agree on IOC risk/classification.
  """
  @spec get_correlation_matrix() :: {:ok, map()}
  def get_correlation_matrix do
    GenServer.call(__MODULE__, :get_correlation_matrix, 60_000)
  end

  @doc """
  Trigger analytics refresh.
  """
  @spec refresh_analytics() :: :ok
  def refresh_analytics do
    GenServer.cast(__MODULE__, :refresh_analytics)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(_opts) do
    # Schedule periodic analytics generation
    schedule_analysis()

    state = %{
      last_analysis: nil,
      cached_overlap: nil,
      cached_correlation: nil,
      performance_cache: %{}
    }

    Logger.info("[FeedAnalytics] Initialized analytics engine")

    {:ok, state}
  end

  @impl true
  def handle_call({:get_feed_performance, feed_name}, _from, state) do
    performance = calculate_feed_performance(feed_name)
    new_state = %{state | performance_cache: Map.put(state.performance_cache, feed_name, performance)}
    {:reply, {:ok, performance}, new_state}
  end

  @impl true
  def handle_call({:compare_feeds, feed_names}, _from, state) do
    comparison = do_compare_feeds(feed_names)
    {:reply, {:ok, comparison}, state}
  end

  @impl true
  def handle_call(:analyze_ioc_overlap, _from, state) do
    overlap = if state.cached_overlap do
      state.cached_overlap
    else
      calculate_ioc_overlap()
    end

    {:reply, {:ok, overlap}, %{state | cached_overlap: overlap}}
  end

  @impl true
  def handle_call({:calculate_feed_roi, feed_name}, _from, state) do
    roi = calculate_roi(feed_name)
    {:reply, {:ok, roi}, state}
  end

  @impl true
  def handle_call(:get_cost_efficiency, _from, state) do
    efficiency = calculate_cost_efficiency()
    {:reply, {:ok, efficiency}, state}
  end

  @impl true
  def handle_call({:get_detection_attribution, opts}, _from, state) do
    attribution = calculate_detection_attribution(opts)
    {:reply, {:ok, attribution}, state}
  end

  @impl true
  def handle_call({:get_trending_threats, opts}, _from, state) do
    trends = calculate_trending_threats(opts)
    {:reply, {:ok, trends}, state}
  end

  @impl true
  def handle_call(:get_correlation_matrix, _from, state) do
    correlation = if state.cached_correlation do
      state.cached_correlation
    else
      calculate_correlation_matrix()
    end

    {:reply, {:ok, correlation}, %{state | cached_correlation: correlation}}
  end

  @impl true
  def handle_cast(:refresh_analytics, state) do
    Task.start(fn -> do_refresh_analytics() end)
    {:noreply, state}
  end

  @impl true
  def handle_info(:periodic_analysis, state) do
    Logger.info("[FeedAnalytics] Running periodic analytics refresh...")
    do_refresh_analytics()
    schedule_analysis()
    {:noreply, %{state | last_analysis: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - Performance Metrics
  # ============================================================================

  defp calculate_feed_performance(feed_name) do
    # Get IOC statistics
    ioc_stats = get_feed_ioc_stats(feed_name)

    # Get detection statistics
    detection_stats = get_feed_detection_stats(feed_name)

    # Get freshness metrics
    freshness = get_feed_freshness(feed_name)

    # Get cost metrics
    cost_metrics = get_feed_cost_metrics(feed_name, ioc_stats)

    %{
      feed_name: feed_name,
      ioc_stats: ioc_stats,
      detection_stats: detection_stats,
      freshness: freshness,
      cost_metrics: cost_metrics,
      overall_score: calculate_overall_score(ioc_stats, detection_stats, freshness),
      timestamp: DateTime.utc_now()
    }
  end

  defp get_feed_ioc_stats(feed_name) do
    # Get IOCs from this feed
    total_iocs = IOCs.count_by_source(feed_name)

    # Get unique IOCs (not in other feeds)
    unique_iocs = IOCs.count_unique_by_source(feed_name)

    # Get multi-source IOCs
    multi_source = Aggregator.get_multi_source_iocs(min_sources: 2)
    |> Enum.filter(fn ioc ->
      feed_name in ioc.sources
    end)
    |> length()

    %{
      total: total_iocs,
      unique: unique_iocs,
      shared: multi_source,
      uniqueness_ratio: if(total_iocs > 0, do: unique_iocs / total_iocs, else: 0)
    }
  end

  defp get_feed_detection_stats(feed_name) do
    # Get alerts where this feed contributed
    thirty_days_ago = DateTime.add(DateTime.utc_now(), -30, :day)

    alerts = Alerts.list_alerts(%{
      since: thirty_days_ago,
      ioc_source: feed_name
    })

    total_detections = length(alerts)

    # Calculate true positive rate (requires manual classification)
    # For now, use placeholder
    true_positives = 0
    false_positives = 0

    %{
      total_detections: total_detections,
      true_positives: true_positives,
      false_positives: false_positives,
      accuracy: if(total_detections > 0, do: true_positives / total_detections, else: 0)
    }
  end

  defp get_feed_freshness(feed_name) do
    # Get most recent IOC timestamp
    most_recent = IOCs.get_most_recent_by_source(feed_name)

    if most_recent do
      age_hours = DateTime.diff(DateTime.utc_now(), most_recent.inserted_at, :second) / 3600

      %{
        most_recent_ioc: most_recent.inserted_at,
        age_hours: Float.round(age_hours, 1),
        freshness_score: calculate_freshness_score(age_hours)
      }
    else
      %{
        most_recent_ioc: nil,
        age_hours: nil,
        freshness_score: 0
      }
    end
  end

  defp get_feed_cost_metrics(feed_name, ioc_stats) do
    annual_cost = Map.get(@feed_costs, feed_name, 0)

    cost_per_ioc = if ioc_stats.total > 0 do
      annual_cost / ioc_stats.total
    else
      0
    end

    cost_per_unique_ioc = if ioc_stats.unique > 0 do
      annual_cost / ioc_stats.unique
    else
      0
    end

    %{
      annual_cost_usd: annual_cost,
      cost_per_ioc: Float.round(cost_per_ioc, 2),
      cost_per_unique_ioc: Float.round(cost_per_unique_ioc, 2)
    }
  end

  defp calculate_overall_score(ioc_stats, detection_stats, freshness) do
    # Weighted score: 40% uniqueness, 30% detections, 30% freshness
    uniqueness_score = ioc_stats.uniqueness_ratio * 40
    detection_score = detection_stats.accuracy * 30
    freshness_score = freshness.freshness_score * 30

    Float.round(uniqueness_score + detection_score + freshness_score, 1)
  end

  defp calculate_freshness_score(age_hours) do
    cond do
      age_hours < 1 -> 1.0
      age_hours < 6 -> 0.9
      age_hours < 24 -> 0.7
      age_hours < 48 -> 0.5
      age_hours < 168 -> 0.3
      true -> 0.1
    end
  end

  # ============================================================================
  # Private Functions - Comparison
  # ============================================================================

  defp do_compare_feeds(feed_names) do
    performances = Enum.map(feed_names, fn feed_name ->
      {feed_name, calculate_feed_performance(feed_name)}
    end)
    |> Map.new()

    # Build comparison matrix
    %{
      feeds: performances,
      summary: build_comparison_summary(performances),
      recommendations: generate_recommendations(performances)
    }
  end

  defp build_comparison_summary(performances) do
    feeds = Map.values(performances)

    %{
      total_iocs: Enum.sum(Enum.map(feeds, & &1.ioc_stats.total)),
      total_unique_iocs: Enum.sum(Enum.map(feeds, & &1.ioc_stats.unique)),
      avg_uniqueness: avg(Enum.map(feeds, & &1.ioc_stats.uniqueness_ratio)),
      avg_freshness_score: avg(Enum.map(feeds, & &1.freshness.freshness_score)),
      total_annual_cost: Enum.sum(Enum.map(feeds, & &1.cost_metrics.annual_cost_usd)),
      best_performing: find_best_performing(performances),
      most_cost_efficient: find_most_cost_efficient(performances)
    }
  end

  defp generate_recommendations(performances) do
    recommendations = []

    # Find feeds with low uniqueness
    low_uniqueness = Enum.filter(performances, fn {_name, perf} ->
      perf.ioc_stats.uniqueness_ratio < 0.3
    end)

    recommendations = if length(low_uniqueness) > 0 do
      names = Enum.map(low_uniqueness, fn {name, _} -> name end)
      [
        %{
          type: :low_uniqueness,
          severity: :warning,
          message: "Feeds #{Enum.join(names, ", ")} have low uniqueness (<30%). Consider consolidation."
        }
        | recommendations
      ]
    else
      recommendations
    end

    # Find feeds with poor cost efficiency
    high_cost = Enum.filter(performances, fn {_name, perf} ->
      perf.cost_metrics.cost_per_unique_ioc > 5.0
    end)

    recommendations = if length(high_cost) > 0 do
      names = Enum.map(high_cost, fn {name, _} -> name end)
      [
        %{
          type: :high_cost,
          severity: :info,
          message: "Feeds #{Enum.join(names, ", ")} have high cost per unique IOC (>$5). Review ROI."
        }
        | recommendations
      ]
    else
      recommendations
    end

    recommendations
  end

  defp find_best_performing(performances) do
    Enum.max_by(performances, fn {_name, perf} -> perf.overall_score end, fn -> nil end)
    |> case do
      {name, perf} -> %{feed: name, score: perf.overall_score}
      nil -> nil
    end
  end

  defp find_most_cost_efficient(performances) do
    Enum.min_by(performances, fn {_name, perf} ->
      perf.cost_metrics.cost_per_unique_ioc
    end, fn -> nil end)
    |> case do
      {name, perf} -> %{feed: name, cost_per_unique_ioc: perf.cost_metrics.cost_per_unique_ioc}
      nil -> nil
    end
  end

  # ============================================================================
  # Private Functions - Overlap Analysis
  # ============================================================================

  defp calculate_ioc_overlap do
    Logger.info("[FeedAnalytics] Calculating IOC overlap matrix...")

    # Get all feeds
    feeds = Map.keys(@feed_costs)

    # Build overlap matrix
    matrix = Enum.map(feeds, fn feed1 ->
      overlaps = Enum.map(feeds, fn feed2 ->
        if feed1 == feed2 do
          %{feed: feed2, overlap_count: 0, overlap_percent: 100.0}
        else
          calculate_feed_overlap(feed1, feed2)
        end
      end)

      {feed1, overlaps}
    end)
    |> Map.new()

    %{
      matrix: matrix,
      generated_at: DateTime.utc_now()
    }
  end

  defp calculate_feed_overlap(feed1, feed2) do
    # Get IOCs from both feeds
    feed1_iocs = IOCs.get_by_source(feed1) |> MapSet.new(& &1.value)
    feed2_iocs = IOCs.get_by_source(feed2) |> MapSet.new(& &1.value)

    # Calculate overlap
    overlap = MapSet.intersection(feed1_iocs, feed2_iocs)
    overlap_count = MapSet.size(overlap)

    overlap_percent = if MapSet.size(feed1_iocs) > 0 do
      overlap_count / MapSet.size(feed1_iocs) * 100
    else
      0
    end

    %{
      feed: feed2,
      overlap_count: overlap_count,
      overlap_percent: Float.round(overlap_percent, 1)
    }
  end

  # ============================================================================
  # Private Functions - ROI Calculation
  # ============================================================================

  defp calculate_roi(feed_name) do
    # Get costs
    annual_cost = Map.get(@feed_costs, feed_name, 0)

    # Get benefits (detections)
    detection_stats = get_feed_detection_stats(feed_name)

    # Estimate value per detection (configurable)
    value_per_detection = 1000  # USD

    total_value = detection_stats.total_detections * value_per_detection

    roi = if annual_cost > 0 do
      (total_value - annual_cost) / annual_cost * 100
    else
      0
    end

    %{
      feed_name: feed_name,
      annual_cost: annual_cost,
      total_detections: detection_stats.total_detections,
      estimated_value: total_value,
      roi_percent: Float.round(roi, 1),
      payback_period_months: if(total_value > 0, do: Float.round(annual_cost / (total_value / 12), 1), else: nil)
    }
  end

  defp calculate_cost_efficiency do
    all_feeds = Map.keys(@feed_costs)

    efficiency = Enum.map(all_feeds, fn feed_name ->
      ioc_stats = get_feed_ioc_stats(feed_name)
      cost_metrics = get_feed_cost_metrics(feed_name, ioc_stats)

      %{
        feed: feed_name,
        cost_per_unique_ioc: cost_metrics.cost_per_unique_ioc,
        total_unique_iocs: ioc_stats.unique,
        annual_cost: cost_metrics.annual_cost_usd
      }
    end)
    |> Enum.sort_by(& &1.cost_per_unique_ioc)

    %{
      by_feed: efficiency,
      most_efficient: List.first(efficiency),
      least_efficient: List.last(efficiency)
    }
  end

  # ============================================================================
  # Private Functions - Detection Attribution
  # ============================================================================

  defp calculate_detection_attribution(opts) do
    days = Keyword.get(opts, :days, 30)
    since = DateTime.add(DateTime.utc_now(), -days, :day)

    # Get all alerts with IOC source attribution
    alerts = Alerts.list_alerts(%{since: since})

    # Group by feed
    attribution = Enum.reduce(alerts, %{}, fn alert, acc ->
      sources = extract_ioc_sources(alert)

      Enum.reduce(sources, acc, fn source, inner_acc ->
        Map.update(inner_acc, source, 1, &(&1 + 1))
      end)
    end)
    |> Enum.map(fn {feed, count} ->
      %{
        feed: feed,
        detection_count: count,
        percentage: if(length(alerts) > 0, do: count / length(alerts) * 100, else: 0)
      }
    end)
    |> Enum.sort_by(& &1.detection_count, :desc)

    attribution
  end

  defp extract_ioc_sources(alert) do
    # Extract IOC sources from alert metadata
    get_in(alert, [:metadata, "ioc_sources"]) || []
  end

  # ============================================================================
  # Private Functions - Trending
  # ============================================================================

  defp calculate_trending_threats(opts) do
    days = Keyword.get(opts, :days, 7)
    limit = Keyword.get(opts, :limit, 20)

    since = DateTime.add(DateTime.utc_now(), -days, :day)

    # Get recent IOCs grouped by value/type
    recent_iocs = IOCs.list_recent(since: since, limit: 10000)

    # Count frequency across feeds
    trending = Enum.reduce(recent_iocs, %{}, fn ioc, acc ->
      key = "#{ioc.type}:#{ioc.value}"
      Map.update(acc, key, %{
        type: ioc.type,
        value: ioc.value,
        count: 1,
        sources: [ioc.source],
        first_seen: ioc.inserted_at,
        severity: ioc.severity
      }, fn existing ->
        %{existing |
          count: existing.count + 1,
          sources: [ioc.source | existing.sources] |> Enum.uniq(),
          first_seen: min_datetime(existing.first_seen, ioc.inserted_at)
        }
      end)
    end)
    |> Map.values()
    |> Enum.sort_by(& &1.count, :desc)
    |> Enum.take(limit)

    trending
  end

  # ============================================================================
  # Private Functions - Correlation
  # ============================================================================

  defp calculate_correlation_matrix do
    Logger.info("[FeedAnalytics] Calculating feed correlation matrix...")

    feeds = Map.keys(@feed_costs)

    # Build correlation matrix based on shared IOCs
    matrix = Enum.map(feeds, fn feed1 ->
      correlations = Enum.map(feeds, fn feed2 ->
        if feed1 == feed2 do
          %{feed: feed2, correlation: 1.0}
        else
          calculate_feed_correlation(feed1, feed2)
        end
      end)

      {feed1, correlations}
    end)
    |> Map.new()

    %{
      matrix: matrix,
      generated_at: DateTime.utc_now()
    }
  end

  defp calculate_feed_correlation(feed1, feed2) do
    # Get shared IOCs
    overlap = calculate_feed_overlap(feed1, feed2)

    # Correlation score based on overlap and agreement on severity
    correlation_score = overlap.overlap_percent / 100.0

    %{
      feed: feed2,
      correlation: Float.round(correlation_score, 3),
      shared_iocs: overlap.overlap_count
    }
  end

  # ============================================================================
  # Private Functions - Utilities
  # ============================================================================

  defp do_refresh_analytics do
    # Refresh cached analytics
    calculate_ioc_overlap()
    calculate_correlation_matrix()
  end

  defp schedule_analysis do
    Process.send_after(self(), :periodic_analysis, @analysis_interval)
  end

  defp avg([]), do: 0
  defp avg(list) do
    Enum.sum(list) / length(list)
  end

  defp min_datetime(dt1, dt2) do
    case DateTime.compare(dt1, dt2) do
      :lt -> dt1
      _ -> dt2
    end
  end
end
