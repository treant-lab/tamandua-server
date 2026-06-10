defmodule TamanduaServer.Detection.OrchestrationDetector do
  @moduledoc """
  Detects attack patterns in multi-LLM orchestration systems.

  Multi-agent systems (CrewAI, AutoGen, LangChain agents) can be abused to:
  1. Chain LLM calls to bypass single-inference detection
  2. Use one LLM to craft prompts for another (prompt laundering)
  3. Escalate privileges across agent boundaries

  ## Detection Patterns

  ### Prompt Laundering
  LLM1 generates a prompt that LLM2 executes, bypassing direct input guards.
  Detection: Track prompt similarity between outputs and subsequent inputs.

  ### Privilege Escalation
  Low-privilege agent uses tool calls to invoke high-privilege agents.
  Detection: Track permission levels across inference chain.

  ### Extraction Chains
  Multiple small queries aggregated to extract model knowledge.
  Detection: Track cumulative information extraction across session.

  ### Recursive Jailbreak
  Agent modifies its own system prompt over multiple turns.
  Detection: Track system prompt drift within session.

  ## Usage

      {:ok, session_id} = OrchestrationDetector.track_inference_chain(
        "session-123",
        "inference-abc",
        "inference-parent"
      )

      {:ok, analysis} = OrchestrationDetector.analyze_chain("session-123")
      # => {:suspicious, [:prompt_laundering, :privilege_escalation]}

  ## Architecture

  - ETS-backed state for high-concurrency chain tracking
  - Inference graph reconstruction per session
  - Real-time pattern matching with configurable thresholds
  """

  use GenServer
  require Logger
  alias Phoenix.PubSub

  @ets_table :orchestration_detector
  @ets_chains :inference_chains
  @garbage_collection_interval :timer.minutes(5)
  @session_ttl_seconds 1800  # 30 minutes
  @similarity_threshold 0.7  # Cosine similarity for prompt laundering
  @privilege_escalation_threshold 2  # Level difference to flag
  @extraction_token_threshold 50_000  # Cumulative tokens for extraction alert
  @prompt_drift_threshold 0.5  # System prompt change threshold

  # ============================================================================
  # Types
  # ============================================================================

  @type inference_node :: %{
    inference_id: String.t(),
    parent_id: String.t() | nil,
    session_id: String.t(),
    timestamp: DateTime.t(),
    process_context: map(),
    privilege_level: non_neg_integer(),
    input_hash: String.t() | nil,
    output_hash: String.t() | nil,
    input_preview: String.t() | nil,
    output_preview: String.t() | nil,
    token_count: non_neg_integer(),
    model: String.t() | nil,
    api_provider: atom(),
    system_prompt_hash: String.t() | nil,
    tool_calls: list(map()),
    metadata: map()
  }

  @type chain_analysis :: %{
    session_id: String.t(),
    status: :safe | :suspicious,
    patterns: list(atom()),
    pattern_details: map(),
    chain_depth: non_neg_integer(),
    total_inferences: non_neg_integer(),
    total_tokens: non_neg_integer(),
    risk_score: float(),
    recommendations: list(String.t())
  }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Track an inference in a multi-agent chain.

  Records parent-child relationships between inferences for chain reconstruction.

  ## Parameters
    - session_id: Session/conversation identifier
    - inference_id: Unique ID for this inference
    - parent_id: Parent inference ID (nil for root)
    - opts: Additional inference metadata

  ## Options
    - `:process_context` - Process info (pid, name, path)
    - `:privilege_level` - Permission level (0=lowest)
    - `:input` - Input prompt preview
    - `:output` - Output response preview
    - `:token_count` - Token usage
    - `:model` - Model name
    - `:api_provider` - Provider (:openai, :anthropic, etc.)
    - `:system_prompt` - System prompt (for drift detection)
    - `:tool_calls` - List of tool invocations

  ## Returns
    {:ok, inference_id}
  """
  @spec track_inference_chain(String.t(), String.t(), String.t() | nil, keyword()) :: {:ok, String.t()}
  def track_inference_chain(session_id, inference_id, parent_id, opts \\ []) do
    GenServer.call(__MODULE__, {:track_inference, session_id, inference_id, parent_id, opts})
  end

  @doc """
  Analyze a session's inference chain for attack patterns.

  ## Returns
    {:ok, :safe} | {:suspicious, patterns}
  """
  @spec analyze_chain(String.t()) :: {:ok, :safe} | {:suspicious, list(atom())} | {:ok, chain_analysis()}
  def analyze_chain(session_id) do
    GenServer.call(__MODULE__, {:analyze_chain, session_id})
  end

  @doc """
  Detect prompt laundering pattern in a chain.

  Prompt laundering occurs when LLM1's output becomes LLM2's input,
  effectively using LLM1 to craft prompts that bypass LLM2's guards.

  ## Returns
    Boolean indicating if prompt laundering is detected.
  """
  @spec detect_prompt_laundering(String.t()) :: boolean()
  def detect_prompt_laundering(session_id) do
    GenServer.call(__MODULE__, {:detect_prompt_laundering, session_id})
  end

  @doc """
  Detect privilege escalation across agent boundaries.

  Occurs when a low-privilege agent triggers a high-privilege agent
  via tool calls or chained inference.

  ## Returns
    Boolean indicating if privilege escalation is detected.
  """
  @spec detect_privilege_escalation(String.t()) :: boolean()
  def detect_privilege_escalation(session_id) do
    GenServer.call(__MODULE__, {:detect_privilege_escalation, session_id})
  end

  @doc """
  Detect extraction chain pattern.

  Multiple small queries that together extract significant model knowledge.

  ## Returns
    Boolean indicating if extraction chain is detected.
  """
  @spec detect_extraction_chain(String.t()) :: boolean()
  def detect_extraction_chain(session_id) do
    GenServer.call(__MODULE__, {:detect_extraction_chain, session_id})
  end

  @doc """
  Detect recursive jailbreak attempts.

  Agent modifies its own system prompt over multiple turns.

  ## Returns
    Boolean indicating if recursive jailbreak is detected.
  """
  @spec detect_recursive_jailbreak(String.t()) :: boolean()
  def detect_recursive_jailbreak(session_id) do
    GenServer.call(__MODULE__, {:detect_recursive_jailbreak, session_id})
  end

  @doc """
  Get the full inference chain for a session.

  ## Returns
    List of inference nodes in chronological order.
  """
  @spec get_chain(String.t()) :: {:ok, list(inference_node())} | {:error, :not_found}
  def get_chain(session_id) do
    GenServer.call(__MODULE__, {:get_chain, session_id})
  end

  @doc """
  Get statistics for monitoring.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Clear session data (for testing or cleanup).
  """
  @spec clear_session(String.t()) :: :ok
  def clear_session(session_id) do
    GenServer.cast(__MODULE__, {:clear_session, session_id})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Main session state table
    table = :ets.new(@ets_table, [
      :set,
      :named_table,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    # Inference chain relationships table
    chains_table = :ets.new(@ets_chains, [
      :bag,
      :named_table,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    # Schedule garbage collection
    Process.send_after(self(), :garbage_collect, @garbage_collection_interval)

    # Subscribe to inference events for automatic tracking
    PubSub.subscribe(TamanduaServer.PubSub, "inference:all")

    Logger.info("[OrchestrationDetector] Started")

    {:ok, %{
      table: table,
      chains_table: chains_table,
      stats: %{
        sessions_tracked: 0,
        inferences_tracked: 0,
        prompt_laundering_detected: 0,
        privilege_escalation_detected: 0,
        extraction_chains_detected: 0,
        recursive_jailbreaks_detected: 0
      }
    }}
  end

  @impl true
  def handle_call({:track_inference, session_id, inference_id, parent_id, opts}, _from, state) do
    now = DateTime.utc_now()

    # Build inference node
    node = %{
      inference_id: inference_id,
      parent_id: parent_id,
      session_id: session_id,
      timestamp: now,
      process_context: Keyword.get(opts, :process_context, %{}),
      privilege_level: Keyword.get(opts, :privilege_level, 0),
      input_hash: hash_content(Keyword.get(opts, :input)),
      output_hash: hash_content(Keyword.get(opts, :output)),
      input_preview: truncate(Keyword.get(opts, :input), 500),
      output_preview: truncate(Keyword.get(opts, :output), 500),
      token_count: Keyword.get(opts, :token_count, 0),
      model: Keyword.get(opts, :model),
      api_provider: Keyword.get(opts, :api_provider, :unknown),
      system_prompt_hash: hash_content(Keyword.get(opts, :system_prompt)),
      tool_calls: Keyword.get(opts, :tool_calls, []),
      metadata: Keyword.get(opts, :metadata, %{})
    }

    # Get or create session state
    session_state = get_or_create_session(session_id)

    # Add node to session
    updated_nodes = [node | session_state.nodes]
    updated_session = %{session_state |
      nodes: updated_nodes,
      last_updated: now,
      total_tokens: session_state.total_tokens + node.token_count
    }

    # Update ETS tables
    :ets.insert(@ets_table, {session_id, updated_session})
    :ets.insert(@ets_chains, {session_id, inference_id, parent_id, now})

    # Broadcast new inference
    PubSub.broadcast(
      TamanduaServer.PubSub,
      "orchestration:#{session_id}",
      {:inference_tracked, node}
    )

    # Update stats
    new_stats = %{state.stats |
      inferences_tracked: state.stats.inferences_tracked + 1,
      sessions_tracked: count_sessions()
    }

    Logger.debug(
      "[OrchestrationDetector] Tracked inference: session=#{session_id}, " <>
      "inference=#{inference_id}, parent=#{parent_id || "root"}"
    )

    {:reply, {:ok, inference_id}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:analyze_chain, session_id}, _from, state) do
    case :ets.lookup(@ets_table, session_id) do
      [{^session_id, session_state}] ->
        analysis = perform_chain_analysis(session_state)

        # Update detection stats
        new_stats = update_detection_stats(state.stats, analysis.patterns)

        # Broadcast analysis result
        PubSub.broadcast(
          TamanduaServer.PubSub,
          "orchestration:#{session_id}",
          {:chain_analysis, analysis}
        )

        result = if analysis.status == :safe do
          {:ok, :safe}
        else
          {:suspicious, analysis.patterns}
        end

        {:reply, result, %{state | stats: new_stats}}

      [] ->
        {:reply, {:ok, :safe}, state}
    end
  end

  @impl true
  def handle_call({:detect_prompt_laundering, session_id}, _from, state) do
    result = case :ets.lookup(@ets_table, session_id) do
      [{^session_id, session_state}] ->
        check_prompt_laundering(session_state.nodes)
      [] ->
        false
    end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:detect_privilege_escalation, session_id}, _from, state) do
    result = case :ets.lookup(@ets_table, session_id) do
      [{^session_id, session_state}] ->
        check_privilege_escalation(session_state.nodes)
      [] ->
        false
    end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:detect_extraction_chain, session_id}, _from, state) do
    result = case :ets.lookup(@ets_table, session_id) do
      [{^session_id, session_state}] ->
        check_extraction_chain(session_state)
      [] ->
        false
    end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:detect_recursive_jailbreak, session_id}, _from, state) do
    result = case :ets.lookup(@ets_table, session_id) do
      [{^session_id, session_state}] ->
        check_recursive_jailbreak(session_state.nodes)
      [] ->
        false
    end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_chain, session_id}, _from, state) do
    result = case :ets.lookup(@ets_table, session_id) do
      [{^session_id, session_state}] ->
        # Return nodes sorted by timestamp
        sorted_nodes = Enum.sort_by(session_state.nodes, & &1.timestamp, {:asc, DateTime})
        {:ok, sorted_nodes}
      [] ->
        {:error, :not_found}
    end

    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = Map.merge(state.stats, %{
      active_sessions: count_sessions(),
      total_chain_nodes: count_chain_nodes()
    })

    {:reply, stats, state}
  end

  @impl true
  def handle_cast({:clear_session, session_id}, state) do
    :ets.delete(@ets_table, session_id)
    :ets.match_delete(@ets_chains, {session_id, :_, :_, :_})
    {:noreply, state}
  end

  @impl true
  def handle_info(:garbage_collect, state) do
    now = DateTime.utc_now()
    cutoff = DateTime.add(now, -@session_ttl_seconds, :second)

    # Find and remove stale sessions
    stale_keys = :ets.foldl(fn {key, session_state}, acc ->
      if DateTime.compare(session_state.last_updated, cutoff) == :lt do
        [key | acc]
      else
        acc
      end
    end, [], @ets_table)

    Enum.each(stale_keys, fn key ->
      :ets.delete(@ets_table, key)
      :ets.match_delete(@ets_chains, {key, :_, :_, :_})
    end)

    if length(stale_keys) > 0 do
      Logger.debug("[OrchestrationDetector] Garbage collected #{length(stale_keys)} stale sessions")
    end

    Process.send_after(self(), :garbage_collect, @garbage_collection_interval)
    {:noreply, state}
  end

  @impl true
  def handle_info({:inference_complete, session}, state) do
    # Auto-track from InferenceTracker events
    if session.session_id && session.request do
      opts = [
        process_context: %{
          pid: session.request[:pid],
          process_name: session.request[:process_name],
          process_path: session.request[:process_path]
        },
        input: session.request[:prompt_preview],
        output: session.response && session.response[:response_preview],
        token_count: extract_total_tokens(session.metrics),
        model: session.request[:model],
        api_provider: session.request[:api_provider],
        metadata: %{source: :inference_tracker}
      ]

      # Generate inference ID if not present
      inference_id = session.session_id <> "-" <> generate_id()

      # Non-blocking track
      Task.start(fn ->
        try do
          track_inference_chain(session.agent_id, inference_id, nil, opts)
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

  defp perform_chain_analysis(session_state) do
    nodes = session_state.nodes
    patterns = []
    pattern_details = %{}

    # Check for prompt laundering
    {patterns, pattern_details} =
      if check_prompt_laundering(nodes) do
        details = analyze_prompt_laundering_details(nodes)
        {[:prompt_laundering | patterns], Map.put(pattern_details, :prompt_laundering, details)}
      else
        {patterns, pattern_details}
      end

    # Check for privilege escalation
    {patterns, pattern_details} =
      if check_privilege_escalation(nodes) do
        details = analyze_privilege_escalation_details(nodes)
        {[:privilege_escalation | patterns], Map.put(pattern_details, :privilege_escalation, details)}
      else
        {patterns, pattern_details}
      end

    # Check for extraction chain
    {patterns, pattern_details} =
      if check_extraction_chain(session_state) do
        details = analyze_extraction_chain_details(session_state)
        {[:extraction_chain | patterns], Map.put(pattern_details, :extraction_chain, details)}
      else
        {patterns, pattern_details}
      end

    # Check for recursive jailbreak
    {patterns, pattern_details} =
      if check_recursive_jailbreak(nodes) do
        details = analyze_recursive_jailbreak_details(nodes)
        {[:recursive_jailbreak | patterns], Map.put(pattern_details, :recursive_jailbreak, details)}
      else
        {patterns, pattern_details}
      end

    # Calculate chain depth
    chain_depth = calculate_chain_depth(nodes)

    # Calculate risk score
    risk_score = calculate_risk_score(patterns, pattern_details, chain_depth)

    # Generate recommendations
    recommendations = generate_recommendations(patterns, pattern_details)

    %{
      session_id: session_state.session_id,
      status: if(length(patterns) > 0, do: :suspicious, else: :safe),
      patterns: patterns,
      pattern_details: pattern_details,
      chain_depth: chain_depth,
      total_inferences: length(nodes),
      total_tokens: session_state.total_tokens,
      risk_score: risk_score,
      recommendations: recommendations
    }
  end

  # ============================================================================
  # Pattern Detection: Prompt Laundering
  # ============================================================================

  defp check_prompt_laundering(nodes) when length(nodes) < 2, do: false

  defp check_prompt_laundering(nodes) do
    # Sort by timestamp
    sorted = Enum.sort_by(nodes, & &1.timestamp, {:asc, DateTime})

    # Check if any output becomes a similar input in subsequent inference
    sorted
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.any?(fn [prev, curr] ->
      # Check hash match first (exact)
      exact_match = prev.output_hash != nil and prev.output_hash == curr.input_hash

      # Check content similarity if hashes don't match exactly
      similarity_match = if prev.output_preview && curr.input_preview do
        similarity = calculate_similarity(prev.output_preview, curr.input_preview)
        similarity >= @similarity_threshold
      else
        false
      end

      exact_match or similarity_match
    end)
  end

  defp analyze_prompt_laundering_details(nodes) do
    sorted = Enum.sort_by(nodes, & &1.timestamp, {:asc, DateTime})

    laundering_pairs = sorted
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.filter(fn [prev, curr] ->
      prev.output_hash == curr.input_hash or
      (prev.output_preview && curr.input_preview &&
       calculate_similarity(prev.output_preview, curr.input_preview) >= @similarity_threshold)
    end)
    |> Enum.map(fn [prev, curr] ->
      %{
        source_inference: prev.inference_id,
        target_inference: curr.inference_id,
        source_model: prev.model,
        target_model: curr.model,
        similarity: if(prev.output_preview && curr.input_preview,
          do: calculate_similarity(prev.output_preview, curr.input_preview),
          else: 1.0)
      }
    end)

    %{
      pairs_detected: length(laundering_pairs),
      details: laundering_pairs,
      risk_level: cond do
        length(laundering_pairs) >= 3 -> :high
        length(laundering_pairs) >= 1 -> :medium
        true -> :low
      end
    }
  end

  # ============================================================================
  # Pattern Detection: Privilege Escalation
  # ============================================================================

  defp check_privilege_escalation(nodes) when length(nodes) < 2, do: false

  defp check_privilege_escalation(nodes) do
    # Build parent-child relationships
    id_to_node = Map.new(nodes, fn n -> {n.inference_id, n} end)

    # Check for privilege level increases across parent-child
    Enum.any?(nodes, fn node ->
      if node.parent_id do
        parent = Map.get(id_to_node, node.parent_id)
        if parent do
          # Child has higher privilege than parent
          node.privilege_level - parent.privilege_level >= @privilege_escalation_threshold
        else
          false
        end
      else
        false
      end
    end)
  end

  defp analyze_privilege_escalation_details(nodes) do
    id_to_node = Map.new(nodes, fn n -> {n.inference_id, n} end)

    escalations = nodes
    |> Enum.filter(fn node ->
      if node.parent_id do
        parent = Map.get(id_to_node, node.parent_id)
        parent && node.privilege_level - parent.privilege_level >= @privilege_escalation_threshold
      else
        false
      end
    end)
    |> Enum.map(fn node ->
      parent = Map.get(id_to_node, node.parent_id)
      %{
        from_inference: parent.inference_id,
        to_inference: node.inference_id,
        from_level: parent.privilege_level,
        to_level: node.privilege_level,
        level_jump: node.privilege_level - parent.privilege_level,
        via_tool_call: length(parent.tool_calls) > 0
      }
    end)

    max_jump = escalations
    |> Enum.map(& &1.level_jump)
    |> Enum.max(fn -> 0 end)

    %{
      escalations_detected: length(escalations),
      max_level_jump: max_jump,
      details: escalations,
      risk_level: cond do
        max_jump >= 3 -> :critical
        max_jump >= 2 -> :high
        true -> :medium
      end
    }
  end

  # ============================================================================
  # Pattern Detection: Extraction Chain
  # ============================================================================

  defp check_extraction_chain(session_state) do
    session_state.total_tokens >= @extraction_token_threshold
  end

  defp analyze_extraction_chain_details(session_state) do
    nodes = session_state.nodes

    # Analyze query patterns
    unique_queries = nodes
    |> Enum.map(& &1.input_hash)
    |> Enum.filter(& &1)
    |> Enum.uniq()
    |> length()

    total_queries = length(nodes)

    # High diversity with high volume indicates extraction
    diversity_ratio = if total_queries > 0, do: unique_queries / total_queries, else: 0

    # Calculate token extraction rate
    duration_seconds = calculate_session_duration(nodes)
    tokens_per_minute = if duration_seconds > 60 do
      session_state.total_tokens / (duration_seconds / 60)
    else
      session_state.total_tokens
    end

    %{
      total_tokens: session_state.total_tokens,
      threshold: @extraction_token_threshold,
      unique_queries: unique_queries,
      total_queries: total_queries,
      diversity_ratio: Float.round(diversity_ratio, 2),
      tokens_per_minute: Float.round(tokens_per_minute, 1),
      risk_level: cond do
        session_state.total_tokens >= @extraction_token_threshold * 2 -> :critical
        diversity_ratio > 0.9 -> :high
        true -> :medium
      end
    }
  end

  # ============================================================================
  # Pattern Detection: Recursive Jailbreak
  # ============================================================================

  defp check_recursive_jailbreak(nodes) when length(nodes) < 2, do: false

  defp check_recursive_jailbreak(nodes) do
    # Get unique system prompt hashes in order
    system_prompts = nodes
    |> Enum.sort_by(& &1.timestamp, {:asc, DateTime})
    |> Enum.map(& &1.system_prompt_hash)
    |> Enum.filter(& &1)
    |> Enum.uniq()

    # Multiple different system prompts indicate drift
    length(system_prompts) > 1
  end

  defp analyze_recursive_jailbreak_details(nodes) do
    sorted = Enum.sort_by(nodes, & &1.timestamp, {:asc, DateTime})

    system_prompts = sorted
    |> Enum.filter(& &1.system_prompt_hash)
    |> Enum.map(fn n -> {n.inference_id, n.system_prompt_hash, n.timestamp} end)

    unique_prompts = system_prompts
    |> Enum.map(fn {_, hash, _} -> hash end)
    |> Enum.uniq()

    # Calculate drift rate
    drift_rate = if length(system_prompts) > 1 do
      (length(unique_prompts) - 1) / (length(system_prompts) - 1)
    else
      0.0
    end

    %{
      unique_system_prompts: length(unique_prompts),
      total_prompts_seen: length(system_prompts),
      drift_rate: Float.round(drift_rate, 2),
      prompt_changes: system_prompts |> Enum.chunk_every(2, 1, :discard) |> Enum.count(fn [{_, h1, _}, {_, h2, _}] -> h1 != h2 end),
      risk_level: cond do
        drift_rate >= 0.5 -> :critical
        drift_rate >= 0.3 -> :high
        length(unique_prompts) > 2 -> :medium
        true -> :low
      end
    }
  end

  # ============================================================================
  # Risk Calculation
  # ============================================================================

  defp calculate_risk_score(patterns, pattern_details, chain_depth) do
    pattern_weights = %{
      prompt_laundering: 0.25,
      privilege_escalation: 0.35,
      extraction_chain: 0.20,
      recursive_jailbreak: 0.30
    }

    # Base risk from patterns
    base_risk = patterns
    |> Enum.map(fn pattern ->
      weight = Map.get(pattern_weights, pattern, 0.1)
      severity = get_pattern_severity(pattern, pattern_details)
      weight * severity
    end)
    |> Enum.sum()

    # Amplify for deep chains
    depth_multiplier = case chain_depth do
      d when d >= 5 -> 1.5
      d when d >= 3 -> 1.2
      _ -> 1.0
    end

    # Amplify for multiple patterns
    pattern_multiplier = case length(patterns) do
      0 -> 1.0
      1 -> 1.0
      2 -> 1.3
      _ -> 1.6
    end

    min(base_risk * depth_multiplier * pattern_multiplier, 1.0)
  end

  defp get_pattern_severity(pattern, details) do
    case Map.get(details, pattern) do
      %{risk_level: :critical} -> 1.0
      %{risk_level: :high} -> 0.8
      %{risk_level: :medium} -> 0.5
      %{risk_level: :low} -> 0.2
      _ -> 0.5
    end
  end

  defp generate_recommendations(patterns, _pattern_details) do
    recommendations = []

    recommendations = if :prompt_laundering in patterns do
      ["Enable prompt content validation between chained LLM calls" | recommendations]
    else
      recommendations
    end

    recommendations = if :privilege_escalation in patterns do
      ["Review and restrict cross-agent tool call permissions" | recommendations]
    else
      recommendations
    end

    recommendations = if :extraction_chain in patterns do
      ["Implement per-session token limits and query rate limiting" | recommendations]
    else
      recommendations
    end

    recommendations = if :recursive_jailbreak in patterns do
      ["Lock system prompts to prevent modification during session" | recommendations]
    else
      recommendations
    end

    recommendations
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp get_or_create_session(session_id) do
    case :ets.lookup(@ets_table, session_id) do
      [{^session_id, state}] ->
        state

      [] ->
        %{
          session_id: session_id,
          nodes: [],
          total_tokens: 0,
          created_at: DateTime.utc_now(),
          last_updated: DateTime.utc_now()
        }
    end
  end

  defp hash_content(nil), do: nil
  defp hash_content(content) when is_binary(content) do
    :crypto.hash(:sha256, content) |> Base.encode16(case: :lower) |> String.slice(0, 16)
  end
  defp hash_content(content), do: hash_content(inspect(content))

  defp truncate(nil, _max), do: nil
  defp truncate(s, max) when is_binary(s) do
    if String.length(s) > max do
      String.slice(s, 0, max) <> "..."
    else
      s
    end
  end
  defp truncate(content, max), do: truncate(inspect(content), max)

  defp calculate_similarity(s1, s2) when is_binary(s1) and is_binary(s2) do
    # Jaccard similarity on word tokens
    words1 = s1 |> String.downcase() |> String.split(~r/\s+/, trim: true) |> MapSet.new()
    words2 = s2 |> String.downcase() |> String.split(~r/\s+/, trim: true) |> MapSet.new()

    intersection = MapSet.intersection(words1, words2) |> MapSet.size()
    union = MapSet.union(words1, words2) |> MapSet.size()

    if union > 0, do: intersection / union, else: 0.0
  end

  defp calculate_similarity(_, _), do: 0.0

  defp calculate_chain_depth(nodes) do
    # Build parent-child relationships and find max depth
    id_to_node = Map.new(nodes, fn n -> {n.inference_id, n} end)

    nodes
    |> Enum.map(fn node -> depth_from_root(node, id_to_node, 0) end)
    |> Enum.max(fn -> 0 end)
  end

  defp depth_from_root(node, id_map, current_depth) do
    if node.parent_id do
      case Map.get(id_map, node.parent_id) do
        nil -> current_depth + 1
        parent -> depth_from_root(parent, id_map, current_depth + 1)
      end
    else
      current_depth + 1
    end
  end

  defp calculate_session_duration(nodes) do
    timestamps = Enum.map(nodes, & &1.timestamp)

    if length(timestamps) >= 2 do
      {min_t, max_t} = Enum.min_max_by(timestamps, &DateTime.to_unix/1)
      DateTime.diff(max_t, min_t, :second)
    else
      0
    end
  end

  defp extract_total_tokens(nil), do: 0
  defp extract_total_tokens(%{token_count: %{total_tokens: t}}) when is_integer(t), do: t
  defp extract_total_tokens(%{token_count: tc}) when is_map(tc) do
    (tc[:input_tokens] || tc["input_tokens"] || 0) +
    (tc[:output_tokens] || tc["output_tokens"] || 0)
  end
  defp extract_total_tokens(_), do: 0

  defp generate_id do
    :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
  end

  defp count_sessions do
    :ets.info(@ets_table, :size)
  end

  defp count_chain_nodes do
    :ets.info(@ets_chains, :size)
  end

  defp update_detection_stats(stats, patterns) do
    stats
    |> maybe_increment(:prompt_laundering_detected, :prompt_laundering in patterns)
    |> maybe_increment(:privilege_escalation_detected, :privilege_escalation in patterns)
    |> maybe_increment(:extraction_chains_detected, :extraction_chain in patterns)
    |> maybe_increment(:recursive_jailbreaks_detected, :recursive_jailbreak in patterns)
  end

  defp maybe_increment(stats, key, true), do: Map.update!(stats, key, & &1 + 1)
  defp maybe_increment(stats, _key, false), do: stats
end
