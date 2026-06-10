defmodule TamanduaServer.Detection.ModelExtractionDetector do
  @moduledoc """
  Detects model extraction attacks by analyzing query patterns per client/user.

  Model extraction attacks attempt to steal model weights/behavior by systematically
  querying the model to train a "clone" model. This module detects such attacks by
  identifying suspicious query patterns.

  ## Detection Signals

  - **High query volume**: >1000 queries/hour sustained
  - **Systematic input variation**: Grid search patterns in input space
  - **Boundary probing**: Inputs near decision boundaries
  - **Dataset-like distribution**: Diverse queries covering input space
  - **Low-entropy output requests**: Always requesting logits/confidence

  ## Countermeasures

  - Output perturbation (add noise to confidence values)
  - Rate limiting with exponential backoff
  - Query watermarking (embed trackable patterns in responses)

  ## Usage

      {:ok, result} = ModelExtractionDetector.analyze_session("client-123", queries)
      if result.extraction_risk > 0.7 do
        ModelExtractionDetector.should_throttle?("client-123")
      end
  """

  use GenServer
  require Logger
  alias Phoenix.PubSub

  @ets_table :extraction_detector
  @ets_embeddings :query_embeddings
  @garbage_collection_interval :timer.minutes(5)
  @session_ttl_seconds 3600  # 1 hour
  @high_volume_threshold 1000  # queries per hour
  @extraction_risk_threshold 0.7
  @coverage_detection_threshold 0.3  # 30% of input space covered

  # ============================================================================
  # Types
  # ============================================================================

  @type query :: %{
    input: String.t() | list(),
    output_type: :text | :logits | :confidence | :embeddings,
    timestamp: DateTime.t(),
    input_embedding: list(float()) | nil,
    metadata: map()
  }

  @type client_state :: %{
    client_id: String.t(),
    query_count: non_neg_integer(),
    hour_start: DateTime.t(),
    queries: list(query()),
    embedding_coverage: float(),
    risk_scores: list(float()),
    throttle_until: DateTime.t() | nil,
    throttle_count: non_neg_integer(),
    watermark_seed: binary(),
    last_updated: DateTime.t()
  }

  @type analysis_result :: %{
    extraction_risk: float(),
    signals: list(atom()),
    signal_details: map(),
    recommended_action: :allow | :throttle | :block | :watermark,
    countermeasures: list(atom())
  }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Analyze a session's query patterns for extraction attack indicators.

  ## Parameters
    - session_id: Client/user identifier
    - queries: List of queries to analyze (or single query)

  ## Returns
    `{:ok, analysis_result}` with risk score, detected signals, and recommended actions.
  """
  @spec analyze_session(String.t(), list(query()) | query()) ::
          {:ok, analysis_result()} | {:error, term()}
  def analyze_session(session_id, queries) when is_list(queries) do
    GenServer.call(__MODULE__, {:analyze_session, session_id, queries})
  end

  def analyze_session(session_id, query) when is_map(query) do
    analyze_session(session_id, [query])
  end

  @doc """
  Detect extraction patterns in a list of queries.

  Performs pattern analysis without updating client state.

  ## Returns
    Boolean indicating if extraction pattern is detected.
  """
  @spec detect_extraction_pattern(list(query())) :: boolean()
  def detect_extraction_pattern(queries) do
    GenServer.call(__MODULE__, {:detect_extraction_pattern, queries})
  end

  @doc """
  Check if a client should be throttled based on extraction risk.

  ## Returns
    Boolean indicating if rate limiting should be applied.
  """
  @spec should_throttle?(String.t()) :: boolean()
  def should_throttle?(client_id) do
    GenServer.call(__MODULE__, {:should_throttle, client_id})
  end

  @doc """
  Record a query for a client.

  Updates client state and returns analysis result.
  """
  @spec record_query(String.t(), query()) :: {:ok, analysis_result()}
  def record_query(client_id, query) do
    GenServer.call(__MODULE__, {:record_query, client_id, query})
  end

  @doc """
  Get current risk assessment for a client.
  """
  @spec get_client_risk(String.t()) :: {:ok, float()} | {:error, :not_found}
  def get_client_risk(client_id) do
    GenServer.call(__MODULE__, {:get_client_risk, client_id})
  end

  @doc """
  Apply output perturbation to a response.

  Adds controlled noise to confidence values to make extraction harder.

  ## Parameters
    - client_id: Client identifier (for watermark tracking)
    - response: Original response with confidence values
    - perturbation_level: :low | :medium | :high

  ## Returns
    Perturbed response with noise added to confidence values.
  """
  @spec apply_perturbation(String.t(), map(), atom()) :: map()
  def apply_perturbation(client_id, response, perturbation_level \\ :low) do
    GenServer.call(__MODULE__, {:apply_perturbation, client_id, response, perturbation_level})
  end

  @doc """
  Generate a watermark for a response.

  Embeds trackable patterns in the response that can be detected if the
  extracted model is discovered elsewhere.

  ## Parameters
    - client_id: Client identifier
    - response: Original response

  ## Returns
    Watermarked response with embedded tracking pattern.
  """
  @spec apply_watermark(String.t(), map()) :: map()
  def apply_watermark(client_id, response) do
    GenServer.call(__MODULE__, {:apply_watermark, client_id, response})
  end

  @doc """
  Reset client state (for testing or administrative purposes).
  """
  @spec reset_client(String.t()) :: :ok
  def reset_client(client_id) do
    GenServer.cast(__MODULE__, {:reset_client, client_id})
  end

  @doc """
  Get extraction statistics for monitoring.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Main client state table
    table = :ets.new(@ets_table, [
      :set,
      :named_table,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    # Query embedding fingerprints table (for coverage tracking)
    embeddings_table = :ets.new(@ets_embeddings, [
      :set,
      :named_table,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    # Schedule garbage collection
    Process.send_after(self(), :garbage_collect, @garbage_collection_interval)

    # Subscribe to inference events for automatic tracking
    PubSub.subscribe(TamanduaServer.PubSub, "inference:all")

    Logger.info("[ModelExtractionDetector] Started")

    {:ok, %{
      table: table,
      embeddings_table: embeddings_table,
      stats: %{
        total_queries_analyzed: 0,
        extractions_detected: 0,
        clients_throttled: 0,
        watermarks_applied: 0
      }
    }}
  end

  @impl true
  def handle_call({:analyze_session, session_id, queries}, _from, state) do
    start_time = System.monotonic_time(:millisecond)

    client_state = get_or_create_client_state(session_id)
    updated_state = add_queries_to_state(client_state, queries)

    result = perform_analysis(updated_state)

    # Update client state with new risk scores
    final_state = %{updated_state |
      risk_scores: [result.extraction_risk | Enum.take(updated_state.risk_scores, 99)],
      last_updated: DateTime.utc_now()
    }

    :ets.insert(@ets_table, {session_id, final_state})

    # Update stats
    new_stats = %{state.stats |
      total_queries_analyzed: state.stats.total_queries_analyzed + length(queries),
      extractions_detected:
        if result.extraction_risk >= @extraction_risk_threshold do
          state.stats.extractions_detected + 1
        else
          state.stats.extractions_detected
        end
    }

    elapsed = System.monotonic_time(:millisecond) - start_time

    # Emit telemetry
    :telemetry.execute(
      [:tamandua, :model_extraction, :analyze],
      %{latency_ms: elapsed},
      %{
        client_id: session_id,
        extraction_risk: result.extraction_risk,
        signals: result.signals,
        action: result.recommended_action
      }
    )

    {:reply, {:ok, result}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:detect_extraction_pattern, queries}, _from, state) do
    # Create temporary state for analysis
    temp_state = %{
      client_id: "temp",
      query_count: length(queries),
      hour_start: DateTime.utc_now(),
      queries: normalize_queries(queries),
      embedding_coverage: 0.0,
      risk_scores: [],
      throttle_until: nil,
      throttle_count: 0,
      watermark_seed: :crypto.strong_rand_bytes(16),
      last_updated: DateTime.utc_now()
    }

    result = perform_analysis(temp_state)
    is_extraction = result.extraction_risk >= @extraction_risk_threshold

    {:reply, is_extraction, state}
  end

  @impl true
  def handle_call({:should_throttle, client_id}, _from, state) do
    result = case :ets.lookup(@ets_table, client_id) do
      [{^client_id, client_state}] ->
        now = DateTime.utc_now()
        cond do
          # Check if actively throttled
          client_state.throttle_until != nil and
          DateTime.compare(now, client_state.throttle_until) == :lt ->
            true

          # Check recent risk scores
          avg_risk = calculate_average_risk(client_state.risk_scores) ->
            avg_risk >= @extraction_risk_threshold

          true ->
            false
        end

      [] ->
        false
    end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:record_query, client_id, query}, _from, state) do
    client_state = get_or_create_client_state(client_id)
    normalized_query = normalize_query(query)

    # Add to queries (keep last 1000)
    updated_queries = [normalized_query | Enum.take(client_state.queries, 999)]

    # Update query count for current hour
    now = DateTime.utc_now()
    {query_count, hour_start} =
      if DateTime.diff(now, client_state.hour_start, :second) > 3600 do
        {1, now}
      else
        {client_state.query_count + 1, client_state.hour_start}
      end

    # Update embedding coverage
    embedding_coverage = calculate_embedding_coverage(client_id, normalized_query)

    updated_state = %{client_state |
      queries: updated_queries,
      query_count: query_count,
      hour_start: hour_start,
      embedding_coverage: embedding_coverage,
      last_updated: now
    }

    result = perform_analysis(updated_state)

    # Apply throttling if needed
    final_state =
      if result.extraction_risk >= @extraction_risk_threshold and result.recommended_action in [:throttle, :block] do
        backoff_seconds = calculate_backoff(updated_state.throttle_count)
        throttle_until = DateTime.add(now, backoff_seconds, :second)

        Logger.warning(
          "[ModelExtractionDetector] Throttling client #{client_id}: risk=#{Float.round(result.extraction_risk, 2)}, " <>
          "backoff=#{backoff_seconds}s"
        )

        %{updated_state |
          throttle_until: throttle_until,
          throttle_count: updated_state.throttle_count + 1,
          risk_scores: [result.extraction_risk | Enum.take(updated_state.risk_scores, 99)]
        }
      else
        %{updated_state |
          risk_scores: [result.extraction_risk | Enum.take(updated_state.risk_scores, 99)]
        }
      end

    :ets.insert(@ets_table, {client_id, final_state})

    # Update stats
    new_stats = %{state.stats |
      total_queries_analyzed: state.stats.total_queries_analyzed + 1,
      clients_throttled:
        if final_state.throttle_until != nil and client_state.throttle_until == nil do
          state.stats.clients_throttled + 1
        else
          state.stats.clients_throttled
        end
    }

    {:reply, {:ok, result}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:get_client_risk, client_id}, _from, state) do
    result = case :ets.lookup(@ets_table, client_id) do
      [{^client_id, client_state}] ->
        {:ok, calculate_average_risk(client_state.risk_scores)}

      [] ->
        {:error, :not_found}
    end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:apply_perturbation, client_id, response, level}, _from, state) do
    perturbed = add_perturbation(response, level, get_watermark_seed(client_id))
    {:reply, perturbed, state}
  end

  @impl true
  def handle_call({:apply_watermark, client_id, response}, _from, state) do
    seed = get_watermark_seed(client_id)
    watermarked = embed_watermark(response, seed)

    new_stats = %{state.stats |
      watermarks_applied: state.stats.watermarks_applied + 1
    }

    {:reply, watermarked, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    # Count active clients
    active_clients = :ets.info(@ets_table, :size)

    # Count currently throttled clients
    now = DateTime.utc_now()
    throttled_count = :ets.foldl(fn {_id, client_state}, acc ->
      if client_state.throttle_until != nil and
         DateTime.compare(now, client_state.throttle_until) == :lt do
        acc + 1
      else
        acc
      end
    end, 0, @ets_table)

    stats = Map.merge(state.stats, %{
      active_clients: active_clients,
      currently_throttled: throttled_count
    })

    {:reply, stats, state}
  end

  @impl true
  def handle_cast({:reset_client, client_id}, state) do
    :ets.delete(@ets_table, client_id)
    :ets.delete(@ets_embeddings, client_id)
    {:noreply, state}
  end

  @impl true
  def handle_info(:garbage_collect, state) do
    now = DateTime.utc_now()
    cutoff = DateTime.add(now, -@session_ttl_seconds, :second)

    # Find and remove stale client states
    stale_keys = :ets.foldl(fn {key, client_state}, acc ->
      if DateTime.compare(client_state.last_updated, cutoff) == :lt do
        [key | acc]
      else
        acc
      end
    end, [], @ets_table)

    Enum.each(stale_keys, fn key ->
      :ets.delete(@ets_table, key)
      :ets.delete(@ets_embeddings, key)
    end)

    if length(stale_keys) > 0 do
      Logger.debug("[ModelExtractionDetector] Garbage collected #{length(stale_keys)} stale clients")
    end

    Process.send_after(self(), :garbage_collect, @garbage_collection_interval)
    {:noreply, state}
  end

  @impl true
  def handle_info({:inference_complete, session}, state) do
    # Auto-track inference completions
    if session.request && session.response do
      query = %{
        input: session.request[:prompt_preview] || "",
        output_type: infer_output_type(session.request),
        timestamp: session.updated_at || DateTime.utc_now(),
        input_embedding: nil,
        metadata: %{
          model: session.request[:model],
          api_provider: session.request[:api_provider]
        }
      }

      # Non-blocking record
      Task.start(fn ->
        try do
          record_query(session.agent_id, query)
        rescue
          _ -> :ok
        end
      end)
    end

    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ============================================================================
  # Analysis Functions
  # ============================================================================

  defp perform_analysis(client_state) do
    signals = []
    signal_details = %{}

    # Signal 1: High query volume
    {signals, signal_details} =
      analyze_query_volume(client_state, signals, signal_details)

    # Signal 2: Systematic input variation (grid search patterns)
    {signals, signal_details} =
      analyze_systematic_variation(client_state, signals, signal_details)

    # Signal 3: Boundary probing detection
    {signals, signal_details} =
      analyze_boundary_probing(client_state, signals, signal_details)

    # Signal 4: Dataset-like query distribution
    {signals, signal_details} =
      analyze_distribution_coverage(client_state, signals, signal_details)

    # Signal 5: Low-entropy output requests
    {signals, signal_details} =
      analyze_output_requests(client_state, signals, signal_details)

    # Calculate overall extraction risk
    extraction_risk = calculate_extraction_risk(signals, signal_details)

    # Determine recommended action
    recommended_action = determine_action(extraction_risk, signals)

    # Determine countermeasures
    countermeasures = determine_countermeasures(extraction_risk, signals)

    %{
      extraction_risk: extraction_risk,
      signals: signals,
      signal_details: signal_details,
      recommended_action: recommended_action,
      countermeasures: countermeasures
    }
  end

  defp analyze_query_volume(client_state, signals, details) do
    queries_per_hour = client_state.query_count

    if queries_per_hour >= @high_volume_threshold do
      {
        [:high_volume | signals],
        Map.put(details, :high_volume, %{
          queries_per_hour: queries_per_hour,
          threshold: @high_volume_threshold,
          severity: min(queries_per_hour / @high_volume_threshold, 3.0)
        })
      }
    else
      {signals, details}
    end
  end

  defp analyze_systematic_variation(client_state, signals, details) do
    queries = client_state.queries

    if length(queries) < 10 do
      {signals, details}
    else
      # Analyze input patterns for grid-like behavior
      inputs = Enum.map(queries, & &1.input)

      # Check for systematic numeric variations
      numeric_pattern_score = detect_numeric_patterns(inputs)

      # Check for systematic string variations
      string_pattern_score = detect_string_patterns(inputs)

      pattern_score = max(numeric_pattern_score, string_pattern_score)

      if pattern_score > 0.5 do
        {
          [:systematic_variation | signals],
          Map.put(details, :systematic_variation, %{
            numeric_score: numeric_pattern_score,
            string_score: string_pattern_score,
            overall_score: pattern_score
          })
        }
      else
        {signals, details}
      end
    end
  end

  defp analyze_boundary_probing(client_state, signals, details) do
    queries = client_state.queries

    if length(queries) < 20 do
      {signals, details}
    else
      # Look for inputs that seem designed to probe decision boundaries
      # (e.g., slight variations around specific values)

      boundary_score = calculate_boundary_probing_score(queries)

      if boundary_score > 0.4 do
        {
          [:boundary_probing | signals],
          Map.put(details, :boundary_probing, %{
            score: boundary_score,
            sample_count: length(queries)
          })
        }
      else
        {signals, details}
      end
    end
  end

  defp analyze_distribution_coverage(client_state, signals, details) do
    coverage = client_state.embedding_coverage

    if coverage >= @coverage_detection_threshold do
      {
        [:high_coverage | signals],
        Map.put(details, :high_coverage, %{
          coverage_percentage: coverage * 100,
          threshold: @coverage_detection_threshold * 100
        })
      }
    else
      {signals, details}
    end
  end

  defp analyze_output_requests(client_state, signals, details) do
    queries = client_state.queries

    if length(queries) < 5 do
      {signals, details}
    else
      # Calculate proportion of queries requesting logits/confidence
      logit_requests = Enum.count(queries, fn q ->
        q.output_type in [:logits, :confidence, :embeddings]
      end)

      total = length(queries)
      ratio = logit_requests / total

      # High ratio of logit/confidence requests is suspicious
      if ratio > 0.7 do
        {
          [:low_entropy_outputs | signals],
          Map.put(details, :low_entropy_outputs, %{
            logit_request_ratio: ratio,
            logit_requests: logit_requests,
            total_queries: total
          })
        }
      else
        {signals, details}
      end
    end
  end

  # ============================================================================
  # Pattern Detection Helpers
  # ============================================================================

  defp detect_numeric_patterns(inputs) do
    # Extract numeric values from inputs
    numbers = inputs
    |> Enum.flat_map(fn input ->
      case input do
        s when is_binary(s) ->
          Regex.scan(~r/-?\d+\.?\d*/, s)
          |> List.flatten()
          |> Enum.map(&parse_number/1)
          |> Enum.filter(& &1)

        n when is_number(n) -> [n]
        l when is_list(l) -> Enum.filter(l, &is_number/1)
        _ -> []
      end
    end)

    if length(numbers) < 10 do
      0.0
    else
      # Check for arithmetic progressions (grid patterns)
      sorted = Enum.sort(numbers)
      differences = sorted
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.map(fn [a, b] -> b - a end)
      |> Enum.filter(& &1 > 0)

      if length(differences) < 5 do
        0.0
      else
        # Calculate coefficient of variation of differences
        mean_diff = Enum.sum(differences) / length(differences)
        variance = differences
        |> Enum.map(fn d -> :math.pow(d - mean_diff, 2) end)
        |> Enum.sum()
        |> Kernel./(length(differences))

        stddev = :math.sqrt(variance)
        cv = if mean_diff > 0, do: stddev / mean_diff, else: 1.0

        # Low CV indicates regular spacing (grid pattern)
        if cv < 0.2 do
          1.0 - cv * 5
        else
          max(0.0, 0.5 - cv * 0.5)
        end
      end
    end
  end

  defp detect_string_patterns(inputs) do
    strings = inputs
    |> Enum.filter(&is_binary/1)
    |> Enum.map(&String.downcase/1)

    if length(strings) < 10 do
      0.0
    else
      # Check for common prefixes/suffixes indicating templated queries
      prefix_groups = strings
      |> Enum.map(fn s -> String.slice(s, 0, min(20, String.length(s))) end)
      |> Enum.frequencies()

      # If many strings share the same prefix, it's suspicious
      max_prefix_count = prefix_groups |> Map.values() |> Enum.max()
      prefix_ratio = max_prefix_count / length(strings)

      if prefix_ratio > 0.3 do
        min(prefix_ratio * 1.5, 1.0)
      else
        0.0
      end
    end
  end

  defp calculate_boundary_probing_score(queries) do
    inputs = Enum.map(queries, & &1.input)

    # Look for clusters of similar inputs
    similarity_scores = inputs
    |> Enum.chunk_every(5, 1, :discard)
    |> Enum.map(fn chunk ->
      pairs = for a <- chunk, b <- chunk, a != b, do: {a, b}
      if length(pairs) > 0 do
        similarities = pairs |> Enum.map(fn {a, b} -> input_similarity(a, b) end)
        Enum.sum(similarities) / length(similarities)
      else
        0.0
      end
    end)

    if length(similarity_scores) > 0 do
      avg_similarity = Enum.sum(similarity_scores) / length(similarity_scores)
      # High similarity within windows indicates probing
      if avg_similarity > 0.8 do
        min(avg_similarity, 1.0)
      else
        0.0
      end
    else
      0.0
    end
  end

  defp input_similarity(a, b) when is_binary(a) and is_binary(b) do
    # Jaccard similarity on character trigrams
    trigrams_a = string_to_trigrams(a)
    trigrams_b = string_to_trigrams(b)

    intersection = MapSet.intersection(trigrams_a, trigrams_b) |> MapSet.size()
    union = MapSet.union(trigrams_a, trigrams_b) |> MapSet.size()

    if union > 0, do: intersection / union, else: 0.0
  end

  defp input_similarity(_, _), do: 0.0

  defp string_to_trigrams(s) do
    s
    |> String.graphemes()
    |> Enum.chunk_every(3, 1, :discard)
    |> Enum.map(&Enum.join/1)
    |> MapSet.new()
  end

  # ============================================================================
  # Risk Calculation
  # ============================================================================

  defp calculate_extraction_risk(signals, signal_details) do
    signal_weights = %{
      high_volume: 0.25,
      systematic_variation: 0.30,
      boundary_probing: 0.25,
      high_coverage: 0.15,
      low_entropy_outputs: 0.20
    }

    # Calculate weighted sum
    base_risk = signals
    |> Enum.map(fn signal ->
      weight = Map.get(signal_weights, signal, 0.1)
      severity = get_signal_severity(signal, signal_details)
      weight * severity
    end)
    |> Enum.sum()

    # Amplify if multiple signals present
    signal_multiplier = case length(signals) do
      0 -> 1.0
      1 -> 1.0
      2 -> 1.2
      3 -> 1.5
      _ -> 2.0
    end

    min(base_risk * signal_multiplier, 1.0)
  end

  defp get_signal_severity(signal, details) do
    case Map.get(details, signal) do
      %{severity: s} -> min(s, 1.0)
      %{score: s} -> s
      %{overall_score: s} -> s
      %{coverage_percentage: p} -> p / 100.0
      %{logit_request_ratio: r} -> r
      _ -> 0.5
    end
  end

  defp determine_action(risk, signals) do
    cond do
      risk >= 0.9 -> :block
      risk >= 0.7 -> :throttle
      risk >= 0.5 or :high_coverage in signals -> :watermark
      true -> :allow
    end
  end

  defp determine_countermeasures(risk, signals) do
    measures = []

    measures = if risk >= 0.3, do: [:perturbation | measures], else: measures
    measures = if risk >= 0.5, do: [:watermark | measures], else: measures
    measures = if risk >= 0.7, do: [:rate_limit | measures], else: measures
    measures = if :systematic_variation in signals, do: [:randomize_order | measures], else: measures
    measures = if :low_entropy_outputs in signals, do: [:restrict_logits | measures], else: measures

    measures
  end

  # ============================================================================
  # Client State Management
  # ============================================================================

  defp get_or_create_client_state(client_id) do
    case :ets.lookup(@ets_table, client_id) do
      [{^client_id, state}] ->
        state

      [] ->
        %{
          client_id: client_id,
          query_count: 0,
          hour_start: DateTime.utc_now(),
          queries: [],
          embedding_coverage: 0.0,
          risk_scores: [],
          throttle_until: nil,
          throttle_count: 0,
          watermark_seed: :crypto.strong_rand_bytes(16),
          last_updated: DateTime.utc_now()
        }
    end
  end

  defp add_queries_to_state(state, queries) do
    normalized = normalize_queries(queries)
    now = DateTime.utc_now()

    # Reset hour counter if needed
    {new_count, hour_start} =
      if DateTime.diff(now, state.hour_start, :second) > 3600 do
        {length(normalized), now}
      else
        {state.query_count + length(normalized), state.hour_start}
      end

    %{state |
      queries: Enum.take(normalized ++ state.queries, 1000),
      query_count: new_count,
      hour_start: hour_start,
      last_updated: now
    }
  end

  defp normalize_queries(queries) do
    Enum.map(queries, &normalize_query/1)
  end

  defp normalize_query(query) when is_map(query) do
    %{
      input: query[:input] || query["input"] || "",
      output_type: normalize_output_type(query[:output_type] || query["output_type"]),
      timestamp: parse_timestamp(query[:timestamp] || query["timestamp"]),
      input_embedding: query[:input_embedding] || query["input_embedding"],
      metadata: query[:metadata] || query["metadata"] || %{}
    }
  end

  defp normalize_output_type(:logits), do: :logits
  defp normalize_output_type("logits"), do: :logits
  defp normalize_output_type(:confidence), do: :confidence
  defp normalize_output_type("confidence"), do: :confidence
  defp normalize_output_type(:embeddings), do: :embeddings
  defp normalize_output_type("embeddings"), do: :embeddings
  defp normalize_output_type(_), do: :text

  defp parse_timestamp(%DateTime{} = dt), do: dt
  defp parse_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp parse_timestamp(_), do: DateTime.utc_now()

  defp infer_output_type(request) do
    endpoint = request[:api_endpoint] || ""
    cond do
      String.contains?(endpoint, "embeddings") -> :embeddings
      String.contains?(endpoint, "logits") -> :logits
      true -> :text
    end
  end

  # ============================================================================
  # Coverage Tracking
  # ============================================================================

  defp calculate_embedding_coverage(client_id, query) do
    # Hash the input to create a fingerprint
    input_hash = hash_input(query.input)

    # Store in embeddings table
    key = {client_id, :embeddings}
    existing = case :ets.lookup(@ets_embeddings, key) do
      [{^key, hashes}] -> hashes
      [] -> MapSet.new()
    end

    updated = MapSet.put(existing, input_hash)
    :ets.insert(@ets_embeddings, {key, updated})

    # Estimate coverage (using hash space bucketing)
    # Divide 256-bit hash space into 1000 buckets
    buckets = MapSet.size(updated)
    min(buckets / 1000.0, 1.0)
  end

  defp hash_input(input) when is_binary(input) do
    :crypto.hash(:sha256, input) |> Base.encode16(case: :lower) |> String.slice(0, 8)
  end

  defp hash_input(input) when is_list(input) do
    hash_input(inspect(input))
  end

  defp hash_input(input) do
    hash_input(to_string(input))
  end

  # ============================================================================
  # Countermeasures Implementation
  # ============================================================================

  defp calculate_backoff(throttle_count) do
    # Exponential backoff: 60s, 120s, 240s, 480s, max 3600s
    base = 60
    max_backoff = 3600
    min(base * :math.pow(2, throttle_count) |> round(), max_backoff)
  end

  defp calculate_average_risk([]), do: 0.0
  defp calculate_average_risk(scores) do
    Enum.sum(scores) / length(scores)
  end

  defp get_watermark_seed(client_id) do
    case :ets.lookup(@ets_table, client_id) do
      [{^client_id, state}] -> state.watermark_seed
      [] -> :crypto.strong_rand_bytes(16)
    end
  end

  defp add_perturbation(response, level, seed) do
    noise_level = case level do
      :low -> 0.01
      :medium -> 0.05
      :high -> 0.1
    end

    # Use seed for deterministic but unique perturbation
    :rand.seed(:exsss, :binary.decode_unsigned(seed))

    perturb_values(response, noise_level)
  end

  defp perturb_values(response, noise_level) when is_map(response) do
    Enum.reduce(response, %{}, fn {k, v}, acc ->
      perturbed = case k do
        key when key in ["confidence", "score", "probability", :confidence, :score, :probability] ->
          perturb_number(v, noise_level)

        key when key in ["logits", :logits] and is_list(v) ->
          Enum.map(v, &perturb_number(&1, noise_level))

        _ when is_map(v) ->
          perturb_values(v, noise_level)

        _ when is_list(v) ->
          Enum.map(v, fn
            item when is_map(item) -> perturb_values(item, noise_level)
            item -> item
          end)

        _ ->
          v
      end

      Map.put(acc, k, perturbed)
    end)
  end

  defp perturb_values(response, _), do: response

  defp perturb_number(n, noise_level) when is_number(n) do
    noise = (:rand.uniform() - 0.5) * 2 * noise_level
    n + noise
  end

  defp perturb_number(n, _), do: n

  defp embed_watermark(response, seed) do
    # Create watermark signature
    watermark = :crypto.hash(:sha256, seed) |> Base.encode16(case: :lower) |> String.slice(0, 8)

    # Embed in response metadata
    case response do
      %{} = map ->
        metadata = Map.get(map, :metadata, Map.get(map, "metadata", %{}))
        updated_metadata = Map.put(metadata, :_wm, watermark)

        map
        |> Map.put(:metadata, updated_metadata)
        |> Map.put("metadata", updated_metadata)

      other ->
        other
    end
  end

  defp parse_number(s) do
    case Float.parse(s) do
      {n, _} -> n
      :error ->
        case Integer.parse(s) do
          {n, _} -> n * 1.0
          :error -> nil
        end
    end
  end
end
