defmodule TamanduaServer.Integrations.AISIEM do
  @moduledoc """
  AI-Native SIEM (Security Information and Event Management) Module

  Implements next-generation SIEM capabilities powered by AI/ML:
  - AI-powered log analysis and enrichment
  - Automatic pattern discovery via clustering
  - Intelligent alert correlation and grouping
  - Noise reduction via ML-based scoring
  - Automated investigation kickoff
  - Natural language log queries
  - Anomaly detection across log streams
  - Retention policy management

  This module acts as a central intelligence layer that processes
  security events, learns patterns, and reduces analyst fatigue
  through intelligent automation.
  """

  use GenServer
  require Logger

  alias TamanduaServer.{Repo, Alerts}
  alias TamanduaServer.Alerts.Alert

  # Configuration constants
  @pattern_mining_interval_ms 300_000  # 5 minutes
  @correlation_window_ms 60_000        # 1 minute correlation window
  @auto_investigate_threshold 0.85     # Above this, auto-start investigation
  @max_pattern_cache_size 10_000
  @log_retention_days 90
  @hot_retention_days 7
  @warm_retention_days 30

  # Pattern types for discovery

  # Embedded structs for internal state management

  defmodule LogEntry do
    @moduledoc "Normalized log entry structure"
    defstruct [
      :id,
      :timestamp,
      :source,
      :event_type,
      :severity,
      :agent_id,
      :hostname,
      :user,
      :process,
      :raw_data,
      :normalized_data,
      :embeddings,
      :noise_score,
      :cluster_id,
      :tags,
      :enrichments
    ]
  end

  defmodule Pattern do
    @moduledoc "Discovered pattern structure"
    defstruct [
      :id,
      :type,
      :name,
      :description,
      :signature,
      :frequency,
      :last_seen,
      :first_seen,
      :confidence,
      :examples,
      :mitre_mapping,
      :is_noise,
      :suppression_count
    ]
  end

  defmodule CorrelationGroup do
    @moduledoc "Correlated alert group"
    defstruct [
      :id,
      :root_alert_id,
      :alert_ids,
      :correlation_type,
      :confidence,
      :timeline,
      :entities,
      :attack_narrative,
      :recommended_actions,
      :created_at,
      :updated_at
    ]
  end

  defmodule Investigation do
    @moduledoc "Automated investigation state"
    defstruct [
      :id,
      :trigger_alert_id,
      :status,
      :findings,
      :timeline,
      :affected_entities,
      :risk_score,
      :recommended_actions,
      :started_at,
      :completed_at
    ]
  end

  defmodule NLQuery do
    @moduledoc "Natural language query result"
    defstruct [
      :original_query,
      :parsed_intent,
      :filters,
      :time_range,
      :aggregations,
      :generated_query,
      :results,
      :explanation
    ]
  end

  # Main GenServer state
  defstruct [
    :log_buffer,
    :pattern_cache,
    :correlation_groups,
    :active_investigations,
    :noise_model,
    :entity_graph,
    :stats,
    :retention_policy
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Ingest a log entry for AI-powered analysis.
  """
  @spec ingest_log(map()) :: {:ok, String.t()} | {:error, term()}
  def ingest_log(log_data) do
    GenServer.call(__MODULE__, {:ingest_log, log_data})
  end

  @doc """
  Ingest a batch of log entries.
  """
  @spec ingest_batch([map()]) :: {:ok, integer()} | {:error, term()}
  def ingest_batch(logs) when is_list(logs) do
    GenServer.call(__MODULE__, {:ingest_batch, logs}, 30_000)
  end

  @doc """
  Execute a natural language query against logs.
  """
  @spec nl_query(String.t(), keyword()) :: {:ok, NLQuery.t()} | {:error, term()}
  def nl_query(query_text, opts \\ []) do
    GenServer.call(__MODULE__, {:nl_query, query_text, opts}, 60_000)
  end

  @doc """
  Get discovered patterns.
  """
  @spec get_patterns(keyword()) :: {:ok, [Pattern.t()]}
  def get_patterns(opts \\ []) do
    GenServer.call(__MODULE__, {:get_patterns, opts})
  end

  @doc """
  Get correlation groups for an alert.
  """
  @spec get_correlations(String.t()) :: {:ok, [CorrelationGroup.t()]}
  def get_correlations(alert_id) do
    GenServer.call(__MODULE__, {:get_correlations, alert_id})
  end

  @doc """
  Manually trigger an investigation.
  """
  @spec start_investigation(String.t(), keyword()) :: {:ok, Investigation.t()} | {:error, term()}
  def start_investigation(alert_id, opts \\ []) do
    GenServer.call(__MODULE__, {:start_investigation, alert_id, opts}, 120_000)
  end

  @doc """
  Get noise score for an alert.
  """
  @spec get_noise_score(map()) :: {:ok, float()}
  def get_noise_score(alert_data) do
    GenServer.call(__MODULE__, {:get_noise_score, alert_data})
  end

  @doc """
  Suppress a pattern as noise.
  """
  @spec suppress_pattern(String.t()) :: :ok
  def suppress_pattern(pattern_id) do
    GenServer.cast(__MODULE__, {:suppress_pattern, pattern_id})
  end

  @doc """
  Get SIEM statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Configure retention policy.
  """
  @spec set_retention_policy(map()) :: :ok
  def set_retention_policy(policy) do
    GenServer.cast(__MODULE__, {:set_retention_policy, policy})
  end

  @doc """
  Get dashboard data for AI SIEM.
  """
  @spec get_dashboard_data() :: map()
  def get_dashboard_data do
    GenServer.call(__MODULE__, :get_dashboard_data)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("Starting AI-Native SIEM Engine")

    # Schedule periodic tasks
    schedule_pattern_mining()
    schedule_correlation_sweep()
    schedule_retention_cleanup()

    state = %__MODULE__{
      log_buffer: :queue.new(),
      pattern_cache: %{},
      correlation_groups: %{},
      active_investigations: %{},
      noise_model: initialize_noise_model(),
      entity_graph: initialize_entity_graph(),
      stats: initialize_stats(),
      retention_policy: %{
        hot_days: @hot_retention_days,
        warm_days: @warm_retention_days,
        cold_days: @log_retention_days
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:ingest_log, log_data}, _from, state) do
    case normalize_log(log_data) do
      {:ok, log_entry} ->
        # Enrich with AI analysis
        enriched = enrich_log_entry(log_entry, state)

        # Calculate noise score
        noise_score = calculate_noise_score(enriched, state)
        enriched = %{enriched | noise_score: noise_score}

        # Add to buffer
        new_buffer = :queue.in(enriched, state.log_buffer)

        # Update entity graph
        new_graph = update_entity_graph(state.entity_graph, enriched)

        # Check for auto-correlation
        {_correlations, updated_groups} = correlate_log(enriched, state)

        # Potentially trigger investigation
        if noise_score >= @auto_investigate_threshold do
          spawn(fn -> auto_investigate(enriched) end)
        end

        # Update stats
        new_stats = update_stats(state.stats, :logs_ingested)

        new_state = %{state |
          log_buffer: trim_buffer(new_buffer),
          entity_graph: new_graph,
          correlation_groups: updated_groups,
          stats: new_stats
        }

        {:reply, {:ok, enriched.id}, new_state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:ingest_batch, logs}, _from, state) do
    {processed, new_state} = Enum.reduce(logs, {0, state}, fn log_data, {count, acc_state} ->
      case normalize_log(log_data) do
        {:ok, log_entry} ->
          enriched = enrich_log_entry(log_entry, acc_state)
          noise_score = calculate_noise_score(enriched, acc_state)
          enriched = %{enriched | noise_score: noise_score}

          new_buffer = :queue.in(enriched, acc_state.log_buffer)
          new_graph = update_entity_graph(acc_state.entity_graph, enriched)

          {count + 1, %{acc_state |
            log_buffer: trim_buffer(new_buffer),
            entity_graph: new_graph
          }}

        {:error, _} ->
          {count, acc_state}
      end
    end)

    new_stats = Map.update!(new_state.stats, :logs_ingested, &(&1 + processed))
    {:reply, {:ok, processed}, %{new_state | stats: new_stats}}
  end

  @impl true
  def handle_call({:nl_query, query_text, opts}, _from, state) do
    result = process_nl_query(query_text, opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_patterns, opts}, _from, state) do
    patterns = filter_patterns(state.pattern_cache, opts)
    {:reply, {:ok, Map.values(patterns)}, state}
  end

  # Alert ids are binary UUIDs. The guard keeps this clause from swallowing
  # the map-based `{:get_correlations, opts}` calls issued by
  # `alert_correlations/1`, which are handled by a later clause.
  @impl true
  def handle_call({:get_correlations, alert_id}, _from, state) when is_binary(alert_id) do
    correlations = state.correlation_groups
    |> Map.values()
    |> Enum.filter(fn group ->
      alert_id in group.alert_ids or group.root_alert_id == alert_id
    end)

    {:reply, {:ok, correlations}, state}
  end

  @impl true
  def handle_call({:start_investigation, alert_id, opts}, _from, state) do
    case run_investigation(alert_id, opts, state) do
      {:ok, investigation} ->
        new_investigations = Map.put(state.active_investigations, investigation.id, investigation)
        new_stats = update_stats(state.stats, :investigations_started)

        {:reply, {:ok, investigation}, %{state |
          active_investigations: new_investigations,
          stats: new_stats
        }}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_noise_score, alert_data}, _from, state) do
    score = calculate_noise_score(alert_data, state)
    {:reply, {:ok, score}, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_call(:get_dashboard_data, _from, state) do
    dashboard = %{
      stats: state.stats,
      active_patterns: map_size(state.pattern_cache),
      correlation_groups: map_size(state.correlation_groups),
      active_investigations: map_size(state.active_investigations),
      top_patterns: get_top_patterns(state.pattern_cache, 10),
      recent_correlations: get_recent_correlations(state.correlation_groups, 5),
      noise_reduction_rate: calculate_noise_reduction_rate(state),
      entity_hotspots: get_entity_hotspots(state.entity_graph, 5)
    }

    {:reply, dashboard, state}
  end

  @impl true
  def handle_call({:get_correlations, opts}, _from, state) when is_map(opts) do
    # Filter correlation groups based on opts (time range, severity, etc.)
    correlations = state.correlation_groups
    |> Map.values()
    |> filter_correlations_by_opts(opts)

    {:reply, {:ok, correlations}, state}
  end

  @impl true
  def handle_call({:noise_metrics, opts}, _from, state) do
    # Calculate noise reduction metrics
    metrics = %{
      noise_reduction_rate: calculate_noise_reduction_rate(state),
      suppressed_patterns: Enum.count(state.pattern_cache, fn {_id, p} -> p && p.is_noise end),
      total_patterns: map_size(state.pattern_cache),
      alerts_processed: state.stats[:alerts_processed] || 0,
      alerts_suppressed: state.stats[:alerts_suppressed] || 0,
      noise_categories: categorize_noise_patterns(state.pattern_cache),
      time_range: Map.get(opts, :time_range, :last_24h)
    }

    {:reply, {:ok, metrics}, state}
  end

  defp filter_correlations_by_opts(correlations, opts) do
    correlations
    |> maybe_filter_by_time_range(Map.get(opts, :time_range))
    |> maybe_filter_by_severity(Map.get(opts, :severity))
    |> maybe_limit_results(Map.get(opts, :limit, 100))
  end

  defp maybe_filter_by_time_range(correlations, nil), do: correlations
  defp maybe_filter_by_time_range(correlations, :last_hour) do
    cutoff = DateTime.add(DateTime.utc_now(), -3600, :second)
    Enum.filter(correlations, &(DateTime.compare(&1.created_at, cutoff) == :gt))
  end
  defp maybe_filter_by_time_range(correlations, :last_24h) do
    cutoff = DateTime.add(DateTime.utc_now(), -86400, :second)
    Enum.filter(correlations, &(DateTime.compare(&1.created_at, cutoff) == :gt))
  end
  defp maybe_filter_by_time_range(correlations, _), do: correlations

  defp maybe_filter_by_severity(correlations, nil), do: correlations
  defp maybe_filter_by_severity(correlations, severity) do
    Enum.filter(correlations, &(&1.severity == severity))
  end

  defp maybe_limit_results(correlations, limit) do
    Enum.take(correlations, limit)
  end

  defp categorize_noise_patterns(pattern_cache) do
    pattern_cache
    |> Map.values()
    |> Enum.filter(& &1 && &1.is_noise)
    |> Enum.group_by(& &1.pattern_type)
    |> Enum.map(fn {type, patterns} -> {type, length(patterns)} end)
    |> Map.new()
  end

  @impl true
  def handle_cast({:suppress_pattern, pattern_id}, state) do
    new_cache = Map.update(state.pattern_cache, pattern_id, nil, fn pattern ->
      if pattern, do: %{pattern | is_noise: true}, else: nil
    end)

    {:noreply, %{state | pattern_cache: new_cache}}
  end

  @impl true
  def handle_cast({:set_retention_policy, policy}, state) do
    new_policy = Map.merge(state.retention_policy, policy)
    {:noreply, %{state | retention_policy: new_policy}}
  end

  @impl true
  def handle_info(:mine_patterns, state) do
    Logger.debug("Running pattern mining cycle")

    # Extract logs from buffer for analysis
    logs = :queue.to_list(state.log_buffer)

    # Run pattern discovery algorithms
    new_patterns = discover_patterns(logs, state.pattern_cache)

    new_stats = update_stats(state.stats, :pattern_mining_cycles)

    schedule_pattern_mining()
    {:noreply, %{state | pattern_cache: new_patterns, stats: new_stats}}
  end

  @impl true
  def handle_info(:correlation_sweep, state) do
    Logger.debug("Running correlation sweep")

    # Consolidate and update correlation groups
    updated_groups = sweep_correlations(state.correlation_groups, state)

    schedule_correlation_sweep()
    {:noreply, %{state | correlation_groups: updated_groups}}
  end

  @impl true
  def handle_info(:retention_cleanup, state) do
    Logger.debug("Running retention cleanup")

    spawn(fn -> run_retention_cleanup(state.retention_policy) end)

    schedule_retention_cleanup()
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Log Processing Functions
  # ============================================================================

  defp normalize_log(log_data) do
    try do
      entry = %LogEntry{
        id: generate_id(),
        timestamp: parse_timestamp(log_data["timestamp"] || log_data[:timestamp]),
        source: log_data["source"] || log_data[:source] || "unknown",
        event_type: log_data["event_type"] || log_data[:event_type],
        severity: normalize_severity(log_data["severity"] || log_data[:severity]),
        agent_id: log_data["agent_id"] || log_data[:agent_id],
        hostname: log_data["hostname"] || log_data[:hostname],
        user: extract_user(log_data),
        process: extract_process(log_data),
        raw_data: log_data,
        normalized_data: normalize_fields(log_data),
        embeddings: nil,
        noise_score: 0.0,
        cluster_id: nil,
        tags: extract_tags(log_data),
        enrichments: %{}
      }

      {:ok, entry}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  defp enrich_log_entry(entry, state) do
    enrichments = %{}

    # Entity resolution
    enrichments = Map.put(enrichments, :entity_context,
      resolve_entity_context(entry, state.entity_graph))

    # Historical context
    enrichments = Map.put(enrichments, :historical_frequency,
      calculate_historical_frequency(entry, state))

    # Pattern matching
    enrichments = Map.put(enrichments, :matching_patterns,
      find_matching_patterns(entry, state.pattern_cache))

    # Threat intelligence enrichment (if available)
    enrichments = Map.put(enrichments, :threat_intel,
      lookup_threat_intel(entry))

    # Generate embeddings for ML operations
    embeddings = generate_embeddings(entry)

    %{entry |
      enrichments: enrichments,
      embeddings: embeddings
    }
  end

  defp calculate_noise_score(entry, state) do
    scores = []

    # Factor 1: Historical frequency (high frequency = likely noise)
    freq_score = case entry.enrichments[:historical_frequency] do
      freq when is_number(freq) and freq > 100 -> 0.8
      freq when is_number(freq) and freq > 50 -> 0.5
      freq when is_number(freq) and freq > 10 -> 0.3
      _ -> 0.1
    end
    scores = [freq_score | scores]

    # Factor 2: Pattern-based noise
    pattern_score = case entry.enrichments[:matching_patterns] do
      patterns when is_list(patterns) ->
        noise_patterns = Enum.filter(patterns, & &1.is_noise)
        if length(noise_patterns) > 0, do: 0.9, else: 0.1
      _ -> 0.5
    end
    scores = [pattern_score | scores]

    # Factor 3: Severity (low severity = more likely noise)
    severity_score = case entry.severity do
      :info -> 0.7
      :low -> 0.5
      :medium -> 0.3
      :high -> 0.1
      :critical -> 0.0
    end
    scores = [severity_score | scores]

    # Factor 4: Entity reputation
    entity_score = calculate_entity_reputation_score(entry, state.entity_graph)
    scores = [entity_score | scores]

    # Weighted average
    Enum.sum(scores) / length(scores)
  end

  # ============================================================================
  # Pattern Discovery Functions
  # ============================================================================

  defp discover_patterns(logs, existing_patterns) do
    new_patterns = existing_patterns

    # Temporal pattern mining
    temporal_patterns = mine_temporal_patterns(logs)
    new_patterns = merge_patterns(new_patterns, temporal_patterns)

    # Behavioral clustering
    behavioral_patterns = mine_behavioral_patterns(logs)
    new_patterns = merge_patterns(new_patterns, behavioral_patterns)

    # Entity co-occurrence patterns
    entity_patterns = mine_entity_patterns(logs)
    new_patterns = merge_patterns(new_patterns, entity_patterns)

    # Attack chain detection
    attack_chains = detect_attack_chains(logs)
    new_patterns = merge_patterns(new_patterns, attack_chains)

    # Prune old/irrelevant patterns
    prune_patterns(new_patterns)
  end

  defp mine_temporal_patterns(logs) do
    # Group logs by time buckets
    time_buckets = Enum.group_by(logs, fn log ->
      DateTime.truncate(log.timestamp, :second)
      |> DateTime.to_unix()
      |> div(60)  # 1-minute buckets
    end)

    # Find recurring patterns
    time_buckets
    |> Enum.filter(fn {_bucket, bucket_logs} -> length(bucket_logs) > 3 end)
    |> Enum.flat_map(fn {bucket, bucket_logs} ->
      event_types = Enum.map(bucket_logs, & &1.event_type) |> Enum.frequencies()

      Enum.filter(event_types, fn {_type, count} -> count > 2 end)
      |> Enum.map(fn {event_type, count} ->
        pattern_id = "temporal_#{event_type}_#{bucket}"
        {pattern_id, %Pattern{
          id: pattern_id,
          type: :temporal,
          name: "Temporal burst: #{event_type}",
          description: "#{count} occurrences of #{event_type} in 1-minute window",
          signature: %{event_type: event_type, time_bucket: bucket},
          frequency: count,
          last_seen: DateTime.utc_now(),
          first_seen: DateTime.utc_now(),
          confidence: min(count / 10, 1.0),
          examples: Enum.take(bucket_logs, 3),
          mitre_mapping: nil,
          is_noise: false,
          suppression_count: 0
        }}
      end)
    end)
    |> Map.new()
  end

  defp mine_behavioral_patterns(logs) do
    # Group by entity (user/hostname)
    entity_groups = Enum.group_by(logs, fn log ->
      {log.hostname, log.user}
    end)

    entity_groups
    |> Enum.filter(fn {_entity, entity_logs} -> length(entity_logs) > 5 end)
    |> Enum.flat_map(fn {{hostname, user}, entity_logs} ->
      # Analyze event sequence
      event_sequence = Enum.map(entity_logs, & &1.event_type)
      sequence_signature = :erlang.phash2(event_sequence)

      pattern_id = "behavioral_#{hostname}_#{user}_#{sequence_signature}"
      [{pattern_id, %Pattern{
        id: pattern_id,
        type: :behavioral,
        name: "Behavioral pattern: #{hostname}/#{user}",
        description: "Repeated behavior pattern from #{hostname} by #{user || "system"}",
        signature: %{hostname: hostname, user: user, sequence_hash: sequence_signature},
        frequency: length(entity_logs),
        last_seen: DateTime.utc_now(),
        first_seen: DateTime.utc_now(),
        confidence: min(length(entity_logs) / 20, 1.0),
        examples: Enum.take(entity_logs, 3),
        mitre_mapping: nil,
        is_noise: false,
        suppression_count: 0
      }}]
    end)
    |> Map.new()
  end

  defp mine_entity_patterns(logs) do
    # Find entities that appear together frequently
    entity_pairs = logs
    |> Enum.flat_map(fn log ->
      entities = extract_entities(log)
      for e1 <- entities, e2 <- entities, e1 < e2, do: {e1, e2}
    end)
    |> Enum.frequencies()
    |> Enum.filter(fn {_pair, count} -> count > 3 end)

    entity_pairs
    |> Enum.map(fn {{e1, e2}, count} ->
      pattern_id = "entity_cooccur_#{:erlang.phash2({e1, e2})}"
      {pattern_id, %Pattern{
        id: pattern_id,
        type: :entity,
        name: "Entity co-occurrence: #{e1} <-> #{e2}",
        description: "#{e1} and #{e2} frequently appear together",
        signature: %{entities: [e1, e2]},
        frequency: count,
        last_seen: DateTime.utc_now(),
        first_seen: DateTime.utc_now(),
        confidence: min(count / 10, 1.0),
        examples: [],
        mitre_mapping: nil,
        is_noise: false,
        suppression_count: 0
      }}
    end)
    |> Map.new()
  end

  defp detect_attack_chains(logs) do
    # Look for MITRE ATT&CK chain patterns
    attack_sequences = [
      [:reconnaissance, :initial_access, :execution],
      [:initial_access, :persistence, :privilege_escalation],
      [:credential_access, :lateral_movement, :collection],
      [:execution, :defense_evasion, :exfiltration]
    ]

    # Map logs to potential attack stages
    staged_logs = Enum.map(logs, fn log ->
      stage = infer_attack_stage(log)
      {log, stage}
    end)
    |> Enum.filter(fn {_log, stage} -> stage != nil end)

    # Detect chains
    attack_sequences
    |> Enum.flat_map(fn sequence ->
      if chain_detected?(staged_logs, sequence) do
        pattern_id = "attack_chain_#{:erlang.phash2(sequence)}"
        [{pattern_id, %Pattern{
          id: pattern_id,
          type: :attack_chain,
          name: "Attack chain: #{Enum.join(sequence, " -> ")}",
          description: "Potential attack chain detected matching MITRE sequence",
          signature: %{sequence: sequence},
          frequency: 1,
          last_seen: DateTime.utc_now(),
          first_seen: DateTime.utc_now(),
          confidence: 0.7,
          examples: [],
          mitre_mapping: sequence,
          is_noise: false,
          suppression_count: 0
        }}]
      else
        []
      end
    end)
    |> Map.new()
  end

  # ============================================================================
  # Alert Correlation Functions
  # ============================================================================

  defp correlate_log(log_entry, state) do
    correlations = []

    # Time-based correlation
    time_correlated = find_time_correlated(log_entry, state)
    correlations = correlations ++ time_correlated

    # Entity-based correlation
    entity_correlated = find_entity_correlated(log_entry, state)
    correlations = correlations ++ entity_correlated

    # Pattern-based correlation
    pattern_correlated = find_pattern_correlated(log_entry, state)
    correlations = correlations ++ pattern_correlated

    # Update or create correlation groups
    updated_groups = update_correlation_groups(correlations, state.correlation_groups, log_entry)

    {correlations, updated_groups}
  end

  defp find_time_correlated(log_entry, state) do
    window_start = DateTime.add(log_entry.timestamp, -@correlation_window_ms, :millisecond)

    :queue.to_list(state.log_buffer)
    |> Enum.filter(fn entry ->
      entry.id != log_entry.id and
      DateTime.compare(entry.timestamp, window_start) == :gt and
      entry.hostname == log_entry.hostname
    end)
    |> Enum.map(fn entry -> {:time, entry.id, 0.6} end)
  end

  defp find_entity_correlated(log_entry, state) do
    log_entities = extract_entities(log_entry)

    :queue.to_list(state.log_buffer)
    |> Enum.filter(fn entry ->
      if entry.id != log_entry.id do
        entry_entities = extract_entities(entry)
        length(log_entities -- (log_entities -- entry_entities)) > 0
      else
        false
      end
    end)
    |> Enum.map(fn entry -> {:entity, entry.id, 0.7} end)
  end

  defp find_pattern_correlated(log_entry, state) do
    matching = log_entry.enrichments[:matching_patterns] || []

    if length(matching) > 0 do
      pattern_ids = Enum.map(matching, & &1.id)

      :queue.to_list(state.log_buffer)
      |> Enum.filter(fn entry ->
        if entry.id != log_entry.id do
          entry_patterns = entry.enrichments[:matching_patterns] || []
          entry_pattern_ids = Enum.map(entry_patterns, & &1.id)
          length(pattern_ids -- (pattern_ids -- entry_pattern_ids)) > 0
        else
          false
        end
      end)
      |> Enum.map(fn entry -> {:pattern, entry.id, 0.8} end)
    else
      []
    end
  end

  defp update_correlation_groups(correlations, groups, log_entry) do
    if length(correlations) > 0 do
      # Find existing group or create new one
      group_id = find_matching_group(correlations, groups) || generate_id()

      existing = Map.get(groups, group_id, %CorrelationGroup{
        id: group_id,
        root_alert_id: log_entry.id,
        alert_ids: [],
        correlation_type: :mixed,
        confidence: 0.5,
        timeline: [],
        entities: [],
        attack_narrative: nil,
        recommended_actions: [],
        created_at: DateTime.utc_now(),
        updated_at: DateTime.utc_now()
      })

      correlated_ids = Enum.map(correlations, fn {_type, id, _score} -> id end)
      avg_confidence = Enum.map(correlations, fn {_type, _id, score} -> score end)
                       |> then(fn scores -> Enum.sum(scores) / length(scores) end)

      updated = %{existing |
        alert_ids: Enum.uniq([log_entry.id | existing.alert_ids] ++ correlated_ids),
        confidence: (existing.confidence + avg_confidence) / 2,
        entities: Enum.uniq(existing.entities ++ extract_entities(log_entry)),
        updated_at: DateTime.utc_now()
      }

      Map.put(groups, group_id, updated)
    else
      groups
    end
  end

  # ============================================================================
  # Natural Language Query Processing
  # ============================================================================

  defp process_nl_query(query_text, opts, state) do
    # Parse intent from natural language
    intent = parse_query_intent(query_text)

    # Extract filters
    filters = extract_query_filters(query_text)

    # Determine time range
    time_range = extract_time_range(query_text, opts)

    # Generate database query
    generated_query = build_query(intent, filters, time_range)

    # Execute query
    results = execute_query(generated_query, state)

    # Generate explanation
    explanation = generate_query_explanation(intent, filters, results)

    {:ok, %NLQuery{
      original_query: query_text,
      parsed_intent: intent,
      filters: filters,
      time_range: time_range,
      aggregations: intent[:aggregations],
      generated_query: generated_query,
      results: results,
      explanation: explanation
    }}
  end

  defp parse_query_intent(query_text) do
    query_lower = String.downcase(query_text)

    intent = %{
      action: :search,
      aggregations: []
    }

    # Detect action type
    intent = cond do
      String.contains?(query_lower, ["count", "how many"]) ->
        %{intent | action: :count}
      String.contains?(query_lower, ["show", "list", "find", "get"]) ->
        %{intent | action: :search}
      String.contains?(query_lower, ["trend", "over time"]) ->
        %{intent | action: :trend, aggregations: [:time_bucket]}
      String.contains?(query_lower, ["top", "most common"]) ->
        %{intent | action: :top, aggregations: [:group_by]}
      true ->
        intent
    end

    intent
  end

  defp extract_query_filters(query_text) do
    filters = %{}
    query_lower = String.downcase(query_text)

    # Severity filter
    filters = cond do
      String.contains?(query_lower, "critical") -> Map.put(filters, :severity, :critical)
      String.contains?(query_lower, "high") -> Map.put(filters, :severity, :high)
      String.contains?(query_lower, "medium") -> Map.put(filters, :severity, :medium)
      String.contains?(query_lower, "low") -> Map.put(filters, :severity, :low)
      true -> filters
    end

    # Event type filter
    filters = cond do
      String.contains?(query_lower, "process") -> Map.put(filters, :event_type, :process)
      String.contains?(query_lower, "file") -> Map.put(filters, :event_type, :file)
      String.contains?(query_lower, "network") -> Map.put(filters, :event_type, :network)
      String.contains?(query_lower, "dns") -> Map.put(filters, :event_type, :dns)
      String.contains?(query_lower, "login") -> Map.put(filters, :event_type, :auth)
      true -> filters
    end

    # Extract hostname/IP patterns
    filters = case Regex.run(~r/(?:host|hostname|server)\s+(\S+)/i, query_text) do
      [_, hostname] -> Map.put(filters, :hostname, hostname)
      _ -> filters
    end

    filters = case Regex.run(~r/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/, query_text) do
      [_, ip] -> Map.put(filters, :ip, ip)
      _ -> filters
    end

    filters
  end

  defp extract_time_range(query_text, opts) do
    query_lower = String.downcase(query_text)

    default_range = opts[:time_range] || :last_24h

    cond do
      String.contains?(query_lower, "last hour") -> :last_1h
      String.contains?(query_lower, "last 24 hours") -> :last_24h
      String.contains?(query_lower, "last 7 days") or String.contains?(query_lower, "last week") -> :last_7d
      String.contains?(query_lower, "last 30 days") or String.contains?(query_lower, "last month") -> :last_30d
      String.contains?(query_lower, "today") -> :today
      String.contains?(query_lower, "yesterday") -> :yesterday
      true -> default_range
    end
  end

  defp build_query(intent, filters, time_range) do
    %{
      intent: intent,
      filters: filters,
      time_range: time_range,
      limit: if(intent.action == :search, do: 100, else: nil)
    }
  end

  defp execute_query(query, state) do
    # For now, query the in-memory buffer
    # In production, this would query the database
    logs = :queue.to_list(state.log_buffer)

    filtered = logs
    |> filter_by_time_range(query.time_range)
    |> filter_by_filters(query.filters)

    case query.intent.action do
      :count ->
        %{count: length(filtered)}

      :search ->
        %{results: Enum.take(filtered, query.limit || 100)}

      :trend ->
        trend_data = filtered
        |> Enum.group_by(fn log ->
          DateTime.to_date(log.timestamp)
        end)
        |> Enum.map(fn {date, logs} -> %{date: date, count: length(logs)} end)
        |> Enum.sort_by(& &1.date)

        %{trend: trend_data}

      :top ->
        top_data = filtered
        |> Enum.group_by(& &1.event_type)
        |> Enum.map(fn {type, logs} -> %{type: type, count: length(logs)} end)
        |> Enum.sort_by(& &1.count, :desc)
        |> Enum.take(10)

        %{top: top_data}

      _ ->
        %{results: filtered}
    end
  end

  defp generate_query_explanation(intent, filters, results) do
    filter_desc = filters
    |> Enum.map(fn {k, v} -> "#{k}=#{v}" end)
    |> Enum.join(", ")

    result_desc = case results do
      %{count: count} -> "Found #{count} matching entries"
      %{results: list} -> "Returned #{length(list)} entries"
      %{trend: data} -> "Generated trend with #{length(data)} data points"
      %{top: data} -> "Found top #{length(data)} categories"
      _ -> "Query executed"
    end

    "Action: #{intent.action}, Filters: #{filter_desc}. #{result_desc}"
  end

  # ============================================================================
  # Investigation Functions
  # ============================================================================

  defp run_investigation(alert_id, _opts, state) do
    # Gather context
    alert_context = gather_alert_context(alert_id, state)

    # Build timeline
    timeline = build_investigation_timeline(alert_context, state)

    # Identify affected entities
    affected = identify_affected_entities(alert_context, state)

    # Calculate risk score
    risk_score = calculate_investigation_risk(alert_context, timeline)

    # Generate recommendations
    recommendations = generate_investigation_recommendations(alert_context, timeline)

    investigation = %Investigation{
      id: generate_id(),
      trigger_alert_id: alert_id,
      status: :completed,
      findings: %{
        context: alert_context,
        related_alerts: length(timeline),
        attack_stage: infer_attack_stage(alert_context)
      },
      timeline: timeline,
      affected_entities: affected,
      risk_score: risk_score,
      recommended_actions: recommendations,
      started_at: DateTime.utc_now(),
      completed_at: DateTime.utc_now()
    }

    {:ok, investigation}
  end

  defp auto_investigate(log_entry) do
    Logger.info("Auto-starting investigation for high-confidence alert: #{log_entry.id}")

    case run_investigation(log_entry.id, [], %__MODULE__{
      log_buffer: :queue.new(),
      pattern_cache: %{},
      correlation_groups: %{},
      active_investigations: %{},
      noise_model: %{},
      entity_graph: %{},
      stats: %{},
      retention_policy: %{}
    }) do
      {:ok, investigation} ->
        Logger.info("Auto-investigation completed: #{investigation.id}, risk_score: #{investigation.risk_score}")

        if investigation.risk_score >= 0.8 do
          # Create high-priority alert
          # Auto-investigations aggregate multiple signals - source_event_id is the original trigger
          source_event_id = log_entry[:event_id] || log_entry.id

          # Build evidence for auto-investigation alerts
          evidence = %{
            file_hashes: [],
            network: [],
            process: %{},
            registry: [],
            detection: %{
              rule_name: "Auto-Investigation",
              rule_type: "ai_siem",
              confidence: investigation.risk_score,
              matched_pattern: "high_risk_investigation"
            }
          }

          Alerts.create_alert(%{
            title: "Auto-Investigation: High Risk Detected",
            description: "Automated investigation found significant risk. Review immediately.",
            severity: :critical,
            status: "new",
            source_event_id: source_event_id,
            event_ids: List.wrap(source_event_id),
            evidence: evidence,
            threat_score: investigation.risk_score
          })
        end

      {:error, reason} ->
        Logger.error("Auto-investigation failed: #{inspect(reason)}")
    end
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp generate_id, do: :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)

  defp parse_timestamp(nil), do: DateTime.utc_now()
  defp parse_timestamp(%DateTime{} = dt), do: dt
  defp parse_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp parse_timestamp(ts) when is_integer(ts), do: DateTime.from_unix!(ts)
  defp parse_timestamp(_), do: DateTime.utc_now()

  defp normalize_severity(nil), do: :info
  defp normalize_severity(s) when is_atom(s), do: s
  defp normalize_severity("critical"), do: :critical
  defp normalize_severity("high"), do: :high
  defp normalize_severity("medium"), do: :medium
  defp normalize_severity("low"), do: :low
  defp normalize_severity(_), do: :info

  defp extract_user(data) do
    data["user"] || data[:user] ||
    data["username"] || data[:username] ||
    get_in(data, ["payload", "user"]) ||
    get_in(data, [:payload, :user])
  end

  defp extract_process(data) do
    data["process"] || data[:process] ||
    data["process_name"] || data[:process_name] ||
    get_in(data, ["payload", "process_name"]) ||
    get_in(data, [:payload, :process_name])
  end

  defp normalize_fields(data) do
    # Flatten and normalize field names
    data
    |> Enum.map(fn {k, v} -> {String.downcase(to_string(k)), v} end)
    |> Map.new()
  end

  defp extract_tags(data) do
    data["tags"] || data[:tags] || []
  end

  defp extract_entities(log) when is_map(log) do
    entities = []
    entities = if log.hostname, do: ["host:#{log.hostname}" | entities], else: entities
    entities = if log.user, do: ["user:#{log.user}" | entities], else: entities
    entities = if log.process, do: ["process:#{log.process}" | entities], else: entities

    # Extract IPs from normalized data
    if ip = get_in(log.normalized_data, ["remote_ip"]) || get_in(log.normalized_data, ["source_ip"]) do
      ["ip:#{ip}" | entities]
    else
      entities
    end
  end
  defp extract_entities(_), do: []

  defp initialize_noise_model, do: %{patterns: %{}, thresholds: %{}}
  defp initialize_entity_graph, do: %{nodes: %{}, edges: []}
  defp initialize_stats do
    %{
      logs_ingested: 0,
      patterns_discovered: 0,
      correlations_created: 0,
      investigations_started: 0,
      noise_suppressed: 0,
      pattern_mining_cycles: 0,
      nl_queries_processed: 0
    }
  end

  defp update_stats(stats, key), do: Map.update(stats, key, 1, &(&1 + 1))

  defp trim_buffer(buffer) do
    if :queue.len(buffer) > @max_pattern_cache_size do
      {_, new_buffer} = :queue.out(buffer)
      trim_buffer(new_buffer)
    else
      buffer
    end
  end

  defp update_entity_graph(graph, log_entry) do
    entities = extract_entities(log_entry)

    new_nodes = Enum.reduce(entities, graph.nodes, fn entity, nodes ->
      Map.update(nodes, entity, %{count: 1, last_seen: DateTime.utc_now()}, fn node ->
        %{node | count: node.count + 1, last_seen: DateTime.utc_now()}
      end)
    end)

    # Add edges between co-occurring entities
    new_edges = for e1 <- entities, e2 <- entities, e1 < e2 do
      {e1, e2, DateTime.utc_now()}
    end

    %{graph | nodes: new_nodes, edges: graph.edges ++ new_edges}
  end

  # Resolves context for an entity by querying related events.
  # Returns context map with related hosts, users, IPs, and recent events.
  # (Comment, not @doc: the compiler discards @doc on private functions.)
  defp resolve_entity_context(entry, graph) do
    import Ecto.Query
    alias TamanduaServer.Repo
    alias TamanduaServer.Telemetry.Event

    # Extract entity identifiers from the entry
    hostname = entry.hostname
    user = entry.user
    agent_id = entry.agent_id

    # Time window for related events (last 24 hours)
    cutoff = DateTime.add(DateTime.utc_now(), -86400, :second)

    # Query related events from database
    related_events = try do
      base_query = from(e in Event,
        where: e.timestamp >= ^cutoff,
        order_by: [desc: e.timestamp],
        limit: 50
      )

      # Build OR conditions for entity matches
      query = cond do
        agent_id && hostname ->
          from(e in base_query,
            where: e.agent_id == ^agent_id or
                   fragment("?->>'hostname' = ?", e.payload, ^hostname)
          )
        agent_id ->
          from(e in base_query, where: e.agent_id == ^agent_id)
        true ->
          base_query
      end

      Repo.all(query)
    rescue
      _ -> []
    end

    # Extract related entities from the events
    related_hosts = related_events
    |> Enum.map(fn e -> e.payload["hostname"] || e.payload[:hostname] end)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()

    related_users = related_events
    |> Enum.map(fn e -> e.payload["user"] || e.payload[:user] end)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()

    related_ips = related_events
    |> Enum.flat_map(fn e ->
      payload = e.payload || %{}
      [payload["remote_ip"], payload["local_ip"], payload["source_ip"]]
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()

    # Get entity connections from the graph
    entity_key = cond do
      hostname -> "host:#{hostname}"
      user -> "user:#{user}"
      true -> nil
    end

    graph_neighbors = if entity_key && is_map(graph) do
      edges = Map.get(graph, :edges, [])
      edges
      |> Enum.filter(fn {e1, e2, _} -> e1 == entity_key || e2 == entity_key end)
      |> Enum.map(fn {e1, e2, _} -> if e1 == entity_key, do: e2, else: e1 end)
      |> Enum.uniq()
    else
      []
    end

    %{
      related_hosts: related_hosts,
      related_users: related_users,
      related_ips: related_ips,
      recent_events: Enum.take(related_events, 10),
      event_count: length(related_events),
      graph_neighbors: graph_neighbors,
      resolved_at: DateTime.utc_now()
    }
  end

  # Calculates historical frequency of an event type for an entity.
  # Returns frequency stats for 24h, 7d, and 30d windows.
  defp calculate_historical_frequency(entry, _state) do
    import Ecto.Query
    alias TamanduaServer.Repo
    alias TamanduaServer.Telemetry.Event

    event_type = entry.event_type
    agent_id = entry.agent_id

    # Skip if we don't have enough info
    if is_nil(event_type) or is_nil(agent_id) do
      %{
        count_24h: 0,
        count_7d: 0,
        count_30d: 0,
        avg_daily: 0.0
      }
    else
      now = DateTime.utc_now()
      cutoff_24h = DateTime.add(now, -86400, :second)
      cutoff_7d = DateTime.add(now, -7 * 86400, :second)
      cutoff_30d = DateTime.add(now, -30 * 86400, :second)

      event_type_str = to_string(event_type)

      try do
        # Count for each time window
        count_24h = Repo.aggregate(
          from(e in Event,
            where: e.agent_id == ^agent_id and
                   e.event_type == ^event_type_str and
                   e.timestamp >= ^cutoff_24h
          ),
          :count, :id
        )

        count_7d = Repo.aggregate(
          from(e in Event,
            where: e.agent_id == ^agent_id and
                   e.event_type == ^event_type_str and
                   e.timestamp >= ^cutoff_7d
          ),
          :count, :id
        )

        count_30d = Repo.aggregate(
          from(e in Event,
            where: e.agent_id == ^agent_id and
                   e.event_type == ^event_type_str and
                   e.timestamp >= ^cutoff_30d
          ),
          :count, :id
        )

        avg_daily = if count_30d > 0, do: count_30d / 30.0, else: 0.0

        %{
          count_24h: count_24h || 0,
          count_7d: count_7d || 0,
          count_30d: count_30d || 0,
          avg_daily: Float.round(avg_daily, 2)
        }
      rescue
        _ ->
          %{count_24h: 0, count_7d: 0, count_30d: 0, avg_daily: 0.0}
      end
    end
  end

  # Finds patterns matching the log entry using string similarity and
  # signature matching.
  defp find_matching_patterns(_entry, patterns) when map_size(patterns) == 0, do: []
  defp find_matching_patterns(entry, patterns) do
    entry_event_type = entry.event_type
    entry_hostname = entry.hostname
    entry_user = entry.user

    patterns
    |> Map.values()
    |> Enum.filter(fn pattern ->
      pattern != nil && pattern_matches?(pattern, entry_event_type, entry_hostname, entry_user)
    end)
    |> Enum.map(fn pattern ->
      confidence = calculate_pattern_confidence(pattern, entry)
      Map.put(pattern, :match_confidence, confidence)
    end)
    |> Enum.filter(fn p -> p.match_confidence > 0.3 end)
    |> Enum.sort_by(& &1.match_confidence, :desc)
    |> Enum.take(5)
  end

  defp pattern_matches?(pattern, event_type, hostname, user) do
    signature = pattern.signature || %{}

    cond do
      # Temporal pattern - match by event type
      pattern.type == :temporal ->
        signature[:event_type] == event_type

      # Behavioral pattern - match by hostname/user
      pattern.type == :behavioral ->
        (signature[:hostname] == hostname) ||
        (signature[:user] == user && user != nil)

      # Entity pattern - check if any entity matches
      pattern.type == :entity ->
        entities = signature[:entities] || []
        host_entity = if hostname, do: "host:#{hostname}", else: nil
        user_entity = if user, do: "user:#{user}", else: nil
        Enum.any?(entities, fn e -> e == host_entity || e == user_entity end)

      # Attack chain - check event type mapping
      pattern.type == :attack_chain ->
        stage = infer_attack_stage(%{event_type: event_type})
        sequence = signature[:sequence] || []
        stage != nil && stage in sequence

      # Default - no match
      true ->
        false
    end
  end

  defp calculate_pattern_confidence(pattern, _entry) do
    base_confidence = pattern.confidence || 0.5

    # Boost confidence based on frequency
    freq_boost = cond do
      pattern.frequency > 100 -> 0.2
      pattern.frequency > 50 -> 0.1
      pattern.frequency > 10 -> 0.05
      true -> 0.0
    end

    # Boost if recently seen
    recency_boost = if pattern.last_seen do
      seconds_ago = DateTime.diff(DateTime.utc_now(), pattern.last_seen, :second)
      cond do
        seconds_ago < 3600 -> 0.1    # Within 1 hour
        seconds_ago < 86400 -> 0.05  # Within 1 day
        true -> 0.0
      end
    else
      0.0
    end

    min(base_confidence + freq_boost + recency_boost, 1.0)
  end

  # Looks up threat intelligence for IOCs extracted from the log entry.
  defp lookup_threat_intel(entry) do
    alias TamanduaServer.ThreatIntel

    # Extract potential IOCs from the entry
    iocs = extract_iocs_from_entry(entry)

    # Look up each IOC
    matches = iocs
    |> Enum.map(fn {type, value} ->
      case ThreatIntel.lookup(type, value) do
        {:ok, ioc_data} -> {type, value, ioc_data}
        :not_found -> nil
      end
    end)
    |> Enum.reject(&is_nil/1)

    if length(matches) > 0 do
      %{
        matched_iocs: Enum.map(matches, fn {type, value, data} ->
          %{
            type: type,
            value: value,
            source: data[:source],
            severity: data[:severity],
            confidence: data[:confidence],
            tags: data[:tags] || [],
            description: data[:description]
          }
        end),
        total_matches: length(matches),
        highest_severity: get_highest_severity(matches),
        lookup_time: DateTime.utc_now()
      }
    else
      %{matched_iocs: [], total_matches: 0, highest_severity: nil, lookup_time: DateTime.utc_now()}
    end
  rescue
    _ -> %{matched_iocs: [], total_matches: 0, highest_severity: nil, lookup_time: DateTime.utc_now()}
  end

  defp extract_iocs_from_entry(entry) do
    iocs = []
    normalized = entry.normalized_data || %{}
    raw = entry.raw_data || %{}

    # Extract IPs
    ip_fields = ["remote_ip", "source_ip", "destination_ip", "local_ip"]
    iocs = Enum.reduce(ip_fields, iocs, fn field, acc ->
      case normalized[field] || raw[field] do
        nil -> acc
        ip when is_binary(ip) -> [{:ip, ip} | acc]
        _ -> acc
      end
    end)

    # Extract domains
    domain_fields = ["domain", "hostname", "query", "url"]
    iocs = Enum.reduce(domain_fields, iocs, fn field, acc ->
      case normalized[field] || raw[field] do
        nil -> acc
        domain when is_binary(domain) ->
          # Extract domain from URL if needed
          extracted = extract_domain_from_value(domain)
          if extracted, do: [{:domain, extracted} | acc], else: acc
        _ -> acc
      end
    end)

    # Extract hashes
    hash_fields = [{"sha256", :hash_sha256}, {"sha1", :hash_sha1}, {"md5", :hash_md5}]
    iocs = Enum.reduce(hash_fields, iocs, fn {field, type}, acc ->
      case normalized[field] || raw[field] do
        nil -> acc
        hash when is_binary(hash) and byte_size(hash) > 0 -> [{type, String.downcase(hash)} | acc]
        _ -> acc
      end
    end)

    Enum.uniq(iocs)
  end

  defp extract_domain_from_value(value) when is_binary(value) do
    cond do
      String.starts_with?(value, "http") ->
        case URI.parse(value) do
          %URI{host: host} when is_binary(host) and host != "" -> host
          _ -> nil
        end
      String.contains?(value, ".") && !String.contains?(value, "/") ->
        value
      true ->
        nil
    end
  end
  defp extract_domain_from_value(_), do: nil

  defp get_highest_severity(matches) do
    severity_order = [:critical, :high, :medium, :low, :info]

    matches
    |> Enum.map(fn {_, _, data} -> data[:severity] end)
    |> Enum.reject(&is_nil/1)
    |> Enum.min_by(fn sev ->
      Enum.find_index(severity_order, &(&1 == sev)) || 999
    end, fn -> nil end)
  end

  # Generates vector embeddings for the log entry by sending its text
  # representation to the ML service via `TamanduaServer.Detection.ML.Client`.
  #
  # The entry's key fields (event_type, hostname, user, process, severity)
  # are concatenated into a text string and forwarded to the ML encoder,
  # which returns a compact latent-space vector suitable for cosine-similarity
  # comparisons.
  #
  # Returns a list of floats (the embedding vector) on success, or `nil`
  # if the ML service is unavailable.
  defp generate_embeddings(entry) do
    alias TamanduaServer.Detection.ML.Client, as: MLClient

    # Build a text representation from the entry's key fields
    text = [
      entry.event_type,
      entry.hostname,
      entry.user,
      entry.process,
      entry.severity && to_string(entry.severity)
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.map(&to_string/1)
    |> Enum.join(" ")

    if text == "" do
      nil
    else
      case MLClient.generate_embeddings(text) do
        {:ok, embeddings} when is_list(embeddings) ->
          embeddings

        {:error, reason} ->
          Logger.debug("Failed to generate embeddings for log entry: #{inspect(reason)}")
          nil
      end
    end
  end

  @doc """
  Computes cosine similarity between two embedding vectors.

  Returns a float in the range [-1.0, 1.0], where 1.0 means identical
  direction, 0.0 means orthogonal, and -1.0 means opposite direction.

  Returns 0.0 if either vector is nil or empty, or if both have zero magnitude.
  """
  @spec cosine_similarity([float()] | nil, [float()] | nil) :: float()
  def cosine_similarity(nil, _), do: 0.0
  def cosine_similarity(_, nil), do: 0.0
  def cosine_similarity([], _), do: 0.0
  def cosine_similarity(_, []), do: 0.0

  def cosine_similarity(vec_a, vec_b) when is_list(vec_a) and is_list(vec_b) do
    if length(vec_a) != length(vec_b) do
      0.0
    else
      dot_product =
        Enum.zip(vec_a, vec_b)
        |> Enum.reduce(0.0, fn {a, b}, acc -> acc + a * b end)

      magnitude_a = :math.sqrt(Enum.reduce(vec_a, 0.0, fn x, acc -> acc + x * x end))
      magnitude_b = :math.sqrt(Enum.reduce(vec_b, 0.0, fn x, acc -> acc + x * x end))

      if magnitude_a == 0.0 or magnitude_b == 0.0 do
        0.0
      else
        dot_product / (magnitude_a * magnitude_b)
      end
    end
  end

  @doc """
  Performs semantic matching between two alerts using their embedding vectors.

  Generates embeddings for each alert's text representation (if not already
  present), then computes cosine similarity to determine how related they are.

  Returns `{:ok, similarity_score}` where score is a float in [0.0, 1.0],
  or `{:error, reason}` if embeddings cannot be generated for either alert.

  A similarity score above 0.7 typically indicates strong semantic correlation.
  """
  @spec semantic_match(map(), map()) :: {:ok, float()} | {:error, term()}
  def semantic_match(alert_a, alert_b) do
    alias TamanduaServer.Detection.ML.Client, as: MLClient

    with {:ok, emb_a} <- get_or_generate_embedding(alert_a, MLClient),
         {:ok, emb_b} <- get_or_generate_embedding(alert_b, MLClient) do
      similarity = cosine_similarity(emb_a, emb_b)
      # Normalize to [0, 1] range (cosine similarity can be negative)
      normalized = (similarity + 1.0) / 2.0
      {:ok, normalized}
    end
  end

  defp get_or_generate_embedding(%{embeddings: emb}, _client) when is_list(emb) and emb != [] do
    {:ok, emb}
  end

  defp get_or_generate_embedding(alert, client) do
    text = [
      alert[:title] || alert["title"],
      alert[:description] || alert["description"],
      alert[:event_type] || alert["event_type"],
      alert[:hostname] || alert["hostname"],
      alert[:severity] || alert["severity"]
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.map(&to_string/1)
    |> Enum.join(" ")

    if text == "" do
      {:error, :no_text_content}
    else
      client.generate_embeddings(text)
    end
  end

  # Calculates entity reputation score based on alert history.
  # Returns 0.0 (bad) to 1.0 (good) score.
  defp calculate_entity_reputation_score(entry, graph) do
    import Ecto.Query
    alias TamanduaServer.Repo
    alias TamanduaServer.Alerts.Alert

    agent_id = entry.agent_id
    hostname = entry.hostname

    # Default neutral score
    base_score = 0.5

    # Skip if no identifying info
    if is_nil(agent_id) && is_nil(hostname) do
      base_score
    else
      try do
        # Query alert history for this entity (last 30 days)
        cutoff = DateTime.add(DateTime.utc_now(), -30 * 86400, :second)

        query = from(a in Alert,
          where: a.inserted_at >= ^cutoff,
          select: %{severity: a.severity, status: a.status}
        )

        query = if agent_id do
          from(a in query, where: a.agent_id == ^agent_id)
        else
          query
        end

        alerts = Repo.all(query)
        alert_count = length(alerts)

        if alert_count == 0 do
          # No alerts = good reputation
          0.9
        else
          # Calculate penalty based on alert severity
          severity_penalties = alerts
          |> Enum.map(fn alert ->
            case alert.severity do
              "critical" -> 0.3
              "high" -> 0.2
              "medium" -> 0.1
              "low" -> 0.05
              _ -> 0.02
            end
          end)
          |> Enum.sum()

          # Reduce penalty for resolved alerts
          resolved_count = Enum.count(alerts, &(&1.status == "resolved"))
          resolved_bonus = resolved_count * 0.02

          # Check graph for suspicious neighbors
          graph_penalty = calculate_graph_reputation_penalty(entry, graph)

          # Calculate final score (clamped to 0.0-1.0)
          score = base_score - severity_penalties + resolved_bonus - graph_penalty
          max(0.0, min(1.0, score))
        end
      rescue
        _ -> base_score
      end
    end
  end

  defp calculate_graph_reputation_penalty(entry, graph) when is_map(graph) do
    hostname = entry.hostname
    entity_key = if hostname, do: "host:#{hostname}", else: nil

    if entity_key && map_size(Map.get(graph, :nodes, %{})) > 0 do
      nodes = graph.nodes
      edges = graph.edges || []

      # Find connected entities
      connected = edges
      |> Enum.filter(fn {e1, e2, _} -> e1 == entity_key || e2 == entity_key end)
      |> Enum.map(fn {e1, e2, _} -> if e1 == entity_key, do: e2, else: e1 end)

      # Check if connected to any high-activity entities
      suspicious_connections = connected
      |> Enum.count(fn entity ->
        case Map.get(nodes, entity) do
          %{count: count} when count > 100 -> true
          _ -> false
        end
      end)

      # Small penalty per suspicious connection
      min(suspicious_connections * 0.05, 0.2)
    else
      0.0
    end
  end
  defp calculate_graph_reputation_penalty(_, _), do: 0.0

  defp merge_patterns(existing, new), do: Map.merge(existing, new)

  defp prune_patterns(patterns) do
    # Remove patterns older than 24 hours with low frequency
    cutoff = DateTime.add(DateTime.utc_now(), -86400, :second)

    patterns
    |> Enum.filter(fn {_id, pattern} ->
      DateTime.compare(pattern.last_seen, cutoff) == :gt or pattern.frequency > 10
    end)
    |> Map.new()
  end

  defp infer_attack_stage(log) when is_map(log) do
    event_type = log.event_type || log[:event_type]

    case event_type do
      t when t in [:dns_query, :network_scan] -> :reconnaissance
      t when t in [:process_create, :file_execute] -> :execution
      t when t in [:registry_modify, :scheduled_task] -> :persistence
      t when t in [:credential_dump, :mimikatz] -> :credential_access
      t when t in [:lateral_movement, :psexec] -> :lateral_movement
      t when t in [:file_upload, :data_compress] -> :exfiltration
      _ -> nil
    end
  end
  defp infer_attack_stage(_), do: nil

  defp chain_detected?(staged_logs, sequence) do
    stages = Enum.map(staged_logs, fn {_log, stage} -> stage end)
    Enum.all?(sequence, fn stage -> stage in stages end)
  end

  defp find_matching_group(correlations, groups) do
    correlated_ids = Enum.map(correlations, fn {_type, id, _score} -> id end) |> MapSet.new()

    groups
    |> Enum.find(fn {_id, group} ->
      group_ids = MapSet.new(group.alert_ids)
      MapSet.size(MapSet.intersection(correlated_ids, group_ids)) > 0
    end)
    |> case do
      {id, _} -> id
      nil -> nil
    end
  end

  defp sweep_correlations(groups, _state) do
    # Remove stale groups (no updates in 1 hour)
    cutoff = DateTime.add(DateTime.utc_now(), -3600, :second)

    groups
    |> Enum.filter(fn {_id, group} ->
      DateTime.compare(group.updated_at, cutoff) == :gt
    end)
    |> Map.new()
  end

  defp filter_patterns(patterns, opts) do
    type_filter = opts[:type]
    noise_filter = opts[:include_noise]

    patterns
    |> Enum.filter(fn {_id, pattern} ->
      type_ok = if type_filter, do: pattern.type == type_filter, else: true
      noise_ok = if noise_filter == false, do: !pattern.is_noise, else: true
      type_ok and noise_ok
    end)
    |> Map.new()
  end

  defp filter_by_time_range(logs, time_range) do
    now = DateTime.utc_now()

    cutoff = case time_range do
      :last_1h -> DateTime.add(now, -3600, :second)
      :last_24h -> DateTime.add(now, -86400, :second)
      :last_7d -> DateTime.add(now, -604800, :second)
      :last_30d -> DateTime.add(now, -2592000, :second)
      :today -> DateTime.utc_now() |> DateTime.to_date() |> DateTime.new!(~T[00:00:00])
      :yesterday ->
        DateTime.utc_now()
        |> DateTime.to_date()
        |> Date.add(-1)
        |> DateTime.new!(~T[00:00:00])
      _ -> DateTime.add(now, -86400, :second)
    end

    Enum.filter(logs, fn log ->
      DateTime.compare(log.timestamp, cutoff) == :gt
    end)
  end

  defp filter_by_filters(logs, filters) do
    Enum.filter(logs, fn log ->
      Enum.all?(filters, fn {key, value} ->
        case key do
          :severity -> log.severity == value
          :event_type -> log.event_type == value
          :hostname -> log.hostname == value
          :ip -> get_in(log.normalized_data, ["remote_ip"]) == value
          _ -> true
        end
      end)
    end)
  end

  defp get_top_patterns(patterns, limit) do
    patterns
    |> Map.values()
    |> Enum.sort_by(& &1.frequency, :desc)
    |> Enum.take(limit)
  end

  defp get_recent_correlations(groups, limit) do
    groups
    |> Map.values()
    |> Enum.sort_by(& &1.updated_at, {:desc, DateTime})
    |> Enum.take(limit)
  end

  defp calculate_noise_reduction_rate(state) do
    total = state.stats.logs_ingested
    suppressed = state.stats.noise_suppressed

    if total > 0, do: suppressed / total, else: 0.0
  end

  defp get_entity_hotspots(graph, limit) do
    graph.nodes
    |> Enum.sort_by(fn {_entity, data} -> data.count end, :desc)
    |> Enum.take(limit)
    |> Enum.map(fn {entity, data} -> %{entity: entity, count: data.count} end)
  end

  # Gathers context for an alert including preloaded associations and
  # related events.
  defp gather_alert_context(alert_id, _state) do
    alias TamanduaServer.Alerts
    alias TamanduaServer.Telemetry

    try do
      # Get alert with preloads
      case Alerts.get_alert_with_evidence(alert_id) do
        {:ok, alert} ->
          # Get related events from same agent within timeframe
          agent_id = alert.agent_id
          timestamp = alert.inserted_at

          related_events = if agent_id && timestamp do
            # Get events 30 minutes before and after the alert
            time_window_minutes = 30
            Telemetry.list_events_for_agent(agent_id, 100)
            |> Enum.filter(fn event ->
              case event.timestamp do
                nil -> false
                event_ts ->
                  diff_seconds = abs(DateTime.diff(event_ts, timestamp, :second))
                  diff_seconds <= time_window_minutes * 60
              end
            end)
          else
            []
          end

          # Get related alerts from Alerts context
          related_alerts = Alerts.get_related_alerts(alert_id)

          %{
            alert: alert,
            alert_id: alert.id,
            agent_id: alert.agent_id,
            organization_id: alert.organization_id,
            severity: alert.severity,
            title: alert.title,
            evidence: alert.evidence || %{},
            process_chain: alert.process_chain || [],
            mitre_tactics: alert.mitre_tactics || [],
            mitre_techniques: alert.mitre_techniques || [],
            related_events: related_events,
            related_alerts: related_alerts,
            event_count: length(related_events),
            gathered_at: DateTime.utc_now()
          }

        {:error, _} ->
          %{alert_id: alert_id, error: :not_found, gathered_at: DateTime.utc_now()}
      end
    rescue
      _ -> %{alert_id: alert_id, error: :failed, gathered_at: DateTime.utc_now()}
    end
  end

  # Builds a chronological investigation timeline from alert context.
  # Groups events by type and orders by timestamp.
  defp build_investigation_timeline(context, _state) do
    import Ecto.Query
    alias TamanduaServer.Repo
    alias TamanduaServer.Telemetry.Event

    alert = context[:alert]
    agent_id = context[:agent_id]

    if is_nil(alert) || is_nil(agent_id) do
      []
    else
      try do
        alert_time = alert.inserted_at || DateTime.utc_now()

        # Time window: 1 hour before to 30 minutes after the alert
        start_time = DateTime.add(alert_time, -3600, :second)
        end_time = DateTime.add(alert_time, 1800, :second)

        # Query events in the time window
        events = Repo.all(
          from(e in Event,
            where: e.agent_id == ^agent_id and
                   e.timestamp >= ^start_time and
                   e.timestamp <= ^end_time,
            order_by: [asc: e.timestamp],
            limit: 200
          )
        )

        # Build timeline entries
        timeline = events
        |> Enum.map(fn event ->
          %{
            timestamp: event.timestamp,
            event_id: event.id,
            event_type: event.event_type,
            severity: event.severity,
            payload_summary: summarize_payload(event.payload),
            is_alert_trigger: event.id == alert.source_event_id,
            time_relative_to_alert: calculate_relative_time(event.timestamp, alert_time)
          }
        end)

        # Group by event type for analysis
        groups = Enum.group_by(timeline, & &1.event_type)

        # Add grouping metadata
        timeline
        |> Enum.map(fn entry ->
          group = Map.get(groups, entry.event_type, [])
          Map.put(entry, :group_count, length(group))
        end)
      rescue
        _ -> []
      end
    end
  end

  defp summarize_payload(nil), do: %{}
  defp summarize_payload(payload) when is_map(payload) do
    # Extract key fields for timeline display
    important_keys = ["name", "path", "pid", "remote_ip", "query", "cmdline", "user", "sha256"]

    payload
    |> Enum.filter(fn {k, v} ->
      to_string(k) in important_keys && !is_nil(v)
    end)
    |> Enum.take(5)
    |> Map.new()
  end
  defp summarize_payload(_), do: %{}

  defp calculate_relative_time(nil, _), do: nil
  defp calculate_relative_time(_, nil), do: nil
  defp calculate_relative_time(event_time, alert_time) do
    diff_seconds = DateTime.diff(event_time, alert_time, :second)
    cond do
      diff_seconds < -60 -> "#{abs(div(diff_seconds, 60))} min before"
      diff_seconds < 0 -> "#{abs(diff_seconds)} sec before"
      diff_seconds == 0 -> "at alert time"
      diff_seconds < 60 -> "#{diff_seconds} sec after"
      true -> "#{div(diff_seconds, 60)} min after"
    end
  end

  # Identifies all affected entities from the alert and related events.
  # Returns deduplicated list of hosts, users, and IPs.
  defp identify_affected_entities(context, _state) do
    alert = context[:alert]
    related_events = context[:related_events] || []
    evidence = context[:evidence] || %{}

    entities = []

    # Extract from alert evidence
    entities = if evidence[:process] do
      process = evidence[:process]
      entities
      |> maybe_add_entity(:host, process[:hostname] || process["hostname"])
      |> maybe_add_entity(:user, process[:user] || process["user"])
    else
      entities
    end

    # Extract from related events
    entities = Enum.reduce(related_events, entities, fn event, acc ->
      payload = event.payload || %{}

      acc
      |> maybe_add_entity(:host, payload["hostname"] || payload[:hostname])
      |> maybe_add_entity(:user, payload["user"] || payload[:user])
      |> maybe_add_entity(:ip, payload["remote_ip"] || payload[:remote_ip])
      |> maybe_add_entity(:ip, payload["local_ip"] || payload[:local_ip])
      |> maybe_add_entity(:process, payload["name"] || payload[:name])
    end)

    # Extract from alert itself
    entities = if alert do
      entities
      |> maybe_add_entity(:agent, alert.agent_id)
    else
      entities
    end

    # Deduplicate and format
    entities
    |> Enum.uniq()
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
    |> Enum.map(fn {type, values} ->
      %{
        entity_type: type,
        values: Enum.uniq(values),
        count: length(Enum.uniq(values))
      }
    end)
  end

  defp maybe_add_entity(entities, _type, nil), do: entities
  defp maybe_add_entity(entities, _type, ""), do: entities
  defp maybe_add_entity(entities, type, value), do: [{type, value} | entities]

  # Calculates investigation risk score based on context and timeline.
  defp calculate_investigation_risk(context, timeline) do
    risk = 0.0

    # Factor 1: Alert severity
    severity_risk = case context[:severity] do
      "critical" -> 0.4
      "high" -> 0.3
      "medium" -> 0.2
      "low" -> 0.1
      _ -> 0.05
    end
    risk = risk + severity_risk

    # Factor 2: Number of related events (more events = potentially more serious)
    event_risk = min(length(timeline) * 0.01, 0.2)
    risk = risk + event_risk

    # Factor 3: MITRE technique coverage
    techniques = context[:mitre_techniques] || []
    technique_risk = min(length(techniques) * 0.05, 0.15)
    risk = risk + technique_risk

    # Factor 4: Related alerts
    related_alerts = context[:related_alerts] || []
    related_risk = min(length(related_alerts) * 0.05, 0.15)
    risk = risk + related_risk

    # Factor 5: Evidence quality
    evidence = context[:evidence] || %{}
    evidence_risk = if map_size(evidence) > 3, do: 0.1, else: 0.0
    risk = risk + evidence_risk

    # Clamp to 0.0-1.0
    min(risk, 1.0)
  end

  # Generates investigation recommendations based on context and timeline.
  defp generate_investigation_recommendations(context, timeline) do
    recommendations = []

    # Based on severity
    recommendations = case context[:severity] do
      "critical" ->
        ["IMMEDIATE: Isolate affected system",
         "Notify security team immediately",
         "Preserve forensic evidence" | recommendations]
      "high" ->
        ["Review affected systems within 1 hour",
         "Check for data exfiltration indicators" | recommendations]
      _ ->
        recommendations
    end

    # Based on MITRE techniques
    techniques = context[:mitre_techniques] || []
    recommendations = cond do
      Enum.any?(techniques, &String.starts_with?(to_string(&1), "T1003")) ->
        ["Check for credential theft - review lsass access" | recommendations]

      Enum.any?(techniques, &String.starts_with?(to_string(&1), "T1055")) ->
        ["Investigate process injection - dump process memory" | recommendations]

      Enum.any?(techniques, &String.starts_with?(to_string(&1), "T1021")) ->
        ["Check for lateral movement - review network connections" | recommendations]

      Enum.any?(techniques, &String.starts_with?(to_string(&1), "T1486")) ->
        ["RANSOMWARE INDICATOR - isolate and check backups" | recommendations]

      true ->
        recommendations
    end

    # Based on timeline patterns
    file_events = Enum.count(timeline, &(&1[:event_type] in ["file_create", "file_modify"]))
    recommendations = if file_events > 20 do
      ["High file activity detected - check for ransomware or data staging" | recommendations]
    else
      recommendations
    end

    network_events = Enum.count(timeline, &(&1[:event_type] in ["network_connect", "dns_query"]))
    recommendations = if network_events > 10 do
      ["Elevated network activity - review C2 indicators" | recommendations]
    else
      recommendations
    end

    # Default recommendations
    default_recs = [
      "Review affected systems",
      "Check for lateral movement",
      "Verify user activity legitimacy",
      "Document findings in incident report"
    ]

    # Combine and deduplicate
    (recommendations ++ default_recs)
    |> Enum.uniq()
    |> Enum.take(10)
  end

  defp run_retention_cleanup(policy) do
    Logger.info("Running retention cleanup with policy: #{inspect(policy)}")
    # In production, this would delete old logs from database
    :ok
  end

  defp schedule_pattern_mining do
    Process.send_after(self(), :mine_patterns, @pattern_mining_interval_ms)
  end

  defp schedule_correlation_sweep do
    Process.send_after(self(), :correlation_sweep, 60_000)
  end

  defp schedule_retention_cleanup do
    # Run daily
    Process.send_after(self(), :retention_cleanup, 86_400_000)
  end

  # ============================================================================
  # Public API Wrapper Functions
  # ============================================================================

  @doc """
  Get alert correlations for a specific alert or time range.
  """
  def alert_correlations(opts \\ %{}) do
    GenServer.call(__MODULE__, {:get_correlations, opts})
  end

  @doc """
  Get discovered patterns from pattern mining.
  """
  def discovered_patterns(opts \\ %{}) do
    GenServer.call(__MODULE__, {:get_patterns, opts})
  end

  @doc """
  Execute a natural language log query.
  """
  def natural_language_log_query(query_text, opts \\ %{}) do
    GenServer.call(__MODULE__, {:nl_query, query_text, opts}, 60_000)
  end

  @doc """
  Get noise reduction metrics and statistics.
  """
  def noise_metrics(opts \\ %{}) do
    GenServer.call(__MODULE__, {:noise_metrics, opts})
  end

  @doc """
  List SIEM connections.
  Returns configured SIEM integrations and their status.
  """
  @spec list_connections() :: {:ok, [map()]}
  def list_connections do
    # Check for configured connections in application config
    configured_connections = Application.get_env(:tamandua_server, :siem_connections, [])

    # Default connections that are always available
    default_connections = [
      %{
        id: "internal",
        name: "Internal Event Store",
        type: :internal,
        status: :connected,
        description: "PostgreSQL-based internal event storage",
        events_per_day: get_daily_event_count(),
        last_activity: DateTime.utc_now()
      },
      %{
        id: "threat_intel",
        name: "Threat Intelligence Feeds",
        type: :threat_intel,
        status: get_threat_intel_status(),
        description: "IOC feeds from OTX, AbuseIPDB, URLhaus, MalwareBazaar",
        feeds_active: get_active_feed_count(),
        last_update: get_last_feed_update()
      }
    ]

    # Merge configured connections with defaults
    connections = configured_connections
    |> Enum.map(&normalize_connection/1)
    |> Kernel.++(default_connections)

    {:ok, connections}
  end

  defp get_daily_event_count do
    try do
      TamanduaServer.Telemetry.count_events_today()
    rescue
      _ -> 0
    end
  end

  defp get_threat_intel_status do
    try do
      stats = TamanduaServer.ThreatIntel.get_stats()
      if stats.feeds_active > 0, do: :connected, else: :disconnected
    rescue
      _ -> :unknown
    end
  end

  defp get_active_feed_count do
    try do
      stats = TamanduaServer.ThreatIntel.get_stats()
      stats.feeds_active
    rescue
      _ -> 0
    end
  end

  defp get_last_feed_update do
    try do
      stats = TamanduaServer.ThreatIntel.get_stats()
      stats.last_update
    rescue
      _ -> nil
    end
  end

  defp normalize_connection(conn) when is_map(conn) do
    %{
      id: conn[:id] || conn["id"] || generate_id(),
      name: conn[:name] || conn["name"] || "Unknown",
      type: conn[:type] || conn["type"] || :custom,
      status: conn[:status] || conn["status"] || :unknown,
      description: conn[:description] || conn["description"],
      config: conn[:config] || conn["config"] || %{}
    }
  end

  @doc """
  List correlation rules.
  Returns built-in and configured correlation rules.
  """
  @spec list_correlation_rules() :: {:ok, [map()]}
  def list_correlation_rules do
    # Built-in correlation rules
    built_in_rules = [
      %{
        id: "time_based",
        name: "Temporal Correlation",
        description: "Correlates events occurring within a configurable time window",
        type: :temporal,
        enabled: true,
        window_ms: @correlation_window_ms,
        parameters: %{
          window_ms: @correlation_window_ms,
          same_host_required: true
        }
      },
      %{
        id: "entity_based",
        name: "Entity Correlation",
        description: "Correlates events sharing common entities (hosts, users, IPs)",
        type: :entity,
        enabled: true,
        parameters: %{
          entity_types: [:host, :user, :ip, :process]
        }
      },
      %{
        id: "pattern_based",
        name: "Pattern Correlation",
        description: "Correlates events matching discovered patterns",
        type: :pattern,
        enabled: true,
        parameters: %{
          min_confidence: 0.5
        }
      },
      %{
        id: "attack_chain",
        name: "Attack Chain Detection",
        description: "Detects MITRE ATT&CK kill chain progressions",
        type: :attack_chain,
        enabled: true,
        parameters: %{
          sequences: [
            [:reconnaissance, :initial_access, :execution],
            [:initial_access, :persistence, :privilege_escalation],
            [:credential_access, :lateral_movement, :collection],
            [:execution, :defense_evasion, :exfiltration]
          ]
        }
      },
      %{
        id: "cross_endpoint",
        name: "Cross-Endpoint Correlation",
        description: "Detects patterns across multiple endpoints (lateral movement)",
        type: :cross_endpoint,
        enabled: true,
        parameters: %{
          min_endpoints: 2,
          indicators: [:hash, :ip, :domain, :user]
        }
      },
      %{
        id: "rapid_activity",
        name: "Rapid Activity Detection",
        description: "Detects bursts of activity from single process (ransomware indicator)",
        type: :behavioral,
        enabled: true,
        parameters: %{
          window_seconds: 60,
          threshold: 50
        }
      }
    ]

    # Get any custom rules from configuration
    custom_rules = Application.get_env(:tamandua_server, :correlation_rules, [])
    |> Enum.map(&normalize_correlation_rule/1)

    {:ok, built_in_rules ++ custom_rules}
  end

  defp normalize_correlation_rule(rule) when is_map(rule) do
    %{
      id: rule[:id] || rule["id"] || generate_id(),
      name: rule[:name] || rule["name"] || "Custom Rule",
      description: rule[:description] || rule["description"],
      type: rule[:type] || rule["type"] || :custom,
      enabled: rule[:enabled] != false,
      parameters: rule[:parameters] || rule["parameters"] || %{}
    }
  end

  @doc """
  List enrichment sources.
  Returns configured data enrichment sources and their status.
  """
  @spec list_enrichment_sources() :: {:ok, [map()]}
  def list_enrichment_sources do
    # Built-in enrichment sources
    enrichment_sources = [
      %{
        id: "entity_context",
        name: "Entity Context Resolution",
        description: "Resolves related hosts, users, and IPs from event history",
        type: :internal,
        enabled: true,
        status: :active,
        data_source: "PostgreSQL events table"
      },
      %{
        id: "historical_frequency",
        name: "Historical Frequency Analysis",
        description: "Calculates event frequency over 24h, 7d, and 30d windows",
        type: :internal,
        enabled: true,
        status: :active,
        data_source: "PostgreSQL events table"
      },
      %{
        id: "pattern_matching",
        name: "Pattern Matching",
        description: "Matches events against discovered behavioral patterns",
        type: :internal,
        enabled: true,
        status: :active,
        data_source: "In-memory pattern cache"
      },
      %{
        id: "threat_intel",
        name: "Threat Intelligence Lookup",
        description: "Enriches IOCs with threat intelligence data",
        type: :threat_intel,
        enabled: true,
        status: get_threat_intel_enrichment_status(),
        data_source: "ThreatIntel ETS cache",
        feeds: ["OTX", "AbuseIPDB", "URLhaus", "MalwareBazaar"]
      },
      %{
        id: "entity_reputation",
        name: "Entity Reputation Scoring",
        description: "Calculates reputation score based on alert history",
        type: :internal,
        enabled: true,
        status: :active,
        data_source: "PostgreSQL alerts table"
      },
      %{
        id: "geoip",
        name: "GeoIP Enrichment",
        description: "Adds geographic location data to IP addresses",
        type: :external,
        enabled: geoip_enabled?(),
        status: get_geoip_status(),
        data_source: "MaxMind GeoLite2"
      },
      %{
        id: "mitre_mapping",
        name: "MITRE ATT&CK Mapping",
        description: "Maps events and detections to MITRE techniques",
        type: :internal,
        enabled: true,
        status: :active,
        data_source: "Sigma rules metadata"
      }
    ]

    # Get any custom enrichment sources from configuration
    custom_sources = Application.get_env(:tamandua_server, :enrichment_sources, [])
    |> Enum.map(&normalize_enrichment_source/1)

    {:ok, enrichment_sources ++ custom_sources}
  end

  defp get_threat_intel_enrichment_status do
    try do
      stats = TamanduaServer.ThreatIntel.get_stats()
      if stats.total_iocs > 0, do: :active, else: :no_data
    rescue
      _ -> :unavailable
    end
  end

  defp geoip_enabled? do
    # Check if GeoIP module is available and configured
    Code.ensure_loaded?(TamanduaServer.Enrichment.GeoIP) &&
      Application.get_env(:tamandua_server, :geoip_enabled, false)
  end

  defp get_geoip_status do
    if geoip_enabled?() do
      try do
        # Check if GeoIP database is loaded
        if function_exported?(TamanduaServer.Enrichment.GeoIP, :lookup, 1) do
          :active
        else
          :unavailable
        end
      rescue
        _ -> :unavailable
      end
    else
      :disabled
    end
  end

  defp normalize_enrichment_source(source) when is_map(source) do
    %{
      id: source[:id] || source["id"] || generate_id(),
      name: source[:name] || source["name"] || "Custom Source",
      description: source[:description] || source["description"],
      type: source[:type] || source["type"] || :custom,
      enabled: source[:enabled] != false,
      status: source[:status] || source["status"] || :unknown,
      data_source: source[:data_source] || source["data_source"]
    }
  end
end
