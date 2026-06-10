defmodule TamanduaServer.Detection.InferenceTracker do
  @moduledoc """
  Tracks ML inference request/response pairs for security monitoring.

  Stores inference sessions (request + response correlation) with:
  - Session ID correlation
  - Parent inference tracking (for multi-agent chains)
  - Latency measurement
  - Token usage tracking
  - Extraction risk assessment
  - Real-time PubSub broadcasts

  Sessions are tracked in ETS with a 300-second TTL and periodic cleanup.

  ## Extraction Risk Integration

  Each session tracks extraction risk from ModelExtractionDetector:
  - `extraction_risk`: Float 0.0-1.0 indicating model extraction attack likelihood
  - Risk is updated on session completion based on query patterns

  High extraction risk (>0.7) triggers countermeasures in response handling.

  ## Multi-Agent Chain Tracking

  Sessions can reference a parent inference via `parent_inference_id`, enabling
  chain reconstruction for multi-LLM orchestration security analysis.
  The OrchestrationDetector uses this to detect:
  - Prompt laundering (output -> input chains)
  - Privilege escalation across agents
  - Extraction chains (cumulative knowledge extraction)
  - Recursive jailbreak attempts
  """

  use GenServer
  require Logger
  alias Phoenix.PubSub
  alias TamanduaServer.Detection.ModelExtractionDetector
  alias TamanduaServer.Detection.OrchestrationDetector

  @ets_table :inference_tracker
  @garbage_collection_interval :timer.minutes(1)
  @session_ttl_seconds 300  # 5 minutes

  # ============================================================================
  # Session Struct
  # ============================================================================

  defmodule Session do
    @moduledoc "Inference session tracking request/response pairs"
    defstruct [
      :session_id,
      :agent_id,
      :parent_inference_id,  # For multi-agent chain tracking
      :request,
      :response,
      :status,          # :pending | :complete | :timeout | :error
      :created_at,
      :updated_at,
      :metrics,
      :extraction_risk,  # Float 0.0-1.0 from ModelExtractionDetector
      :orchestration_context  # Additional context for chain analysis
    ]

    @type t :: %__MODULE__{
      session_id: String.t(),
      agent_id: String.t(),
      parent_inference_id: String.t() | nil,
      request: map() | nil,
      response: map() | nil,
      status: :pending | :complete | :timeout | :error,
      created_at: DateTime.t(),
      updated_at: DateTime.t(),
      metrics: map() | nil,
      extraction_risk: float() | nil,
      orchestration_context: map() | nil
    }
  end

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Track an inference request event.

  Creates a new session with status :pending and stores the request data.

  ## Parameters
    - agent_id: The agent identifier
    - event: Inference request event map containing:
      - session_id: Unique session identifier
      - parent_inference_id: Parent inference for chain tracking (optional)
      - pid, process_name, process_path: Process context
      - api_provider, api_endpoint: LLM provider info
      - prompt_preview, full_prompt_hash: Prompt data
      - model: Model name (optional)
      - timestamp: Event timestamp
      - privilege_level: Agent privilege level for escalation detection (optional)
      - system_prompt: System prompt for drift detection (optional)
      - tool_calls: List of tool invocations (optional)

  ## Returns
    {:ok, session_id}
  """
  @spec track_request(String.t(), map()) :: {:ok, String.t()}
  def track_request(agent_id, event) do
    GenServer.call(__MODULE__, {:track_request, agent_id, event})
  end

  @doc """
  Track an inference response event.

  Correlates the response with an existing request session, computes metrics,
  and updates the session status to :complete.

  ## Parameters
    - agent_id: The agent identifier
    - session_id: Session ID to correlate with
    - event: Inference response event map containing:
      - response_preview: First 512 chars of response
      - response_hash: SHA256 of full response
      - latency_ms: Time between request and response
      - token_count: Token usage info
      - finish_reason: Completion reason (stop, length, error)

  ## Returns
    {:ok, session} | {:error, :session_not_found}
  """
  @spec track_response(String.t(), String.t(), map()) :: {:ok, Session.t()} | {:error, :session_not_found}
  def track_response(agent_id, session_id, event) do
    GenServer.call(__MODULE__, {:track_response, agent_id, session_id, event})
  end

  @doc """
  Get a specific session by ID.

  ## Returns
    {:ok, session} | {:error, :not_found}
  """
  @spec get_session(String.t(), String.t()) :: {:ok, Session.t()} | {:error, :not_found}
  def get_session(agent_id, session_id) do
    GenServer.call(__MODULE__, {:get_session, agent_id, session_id})
  end

  @doc """
  Get all pending sessions (awaiting response) for an agent.

  ## Returns
    [Session.t()]
  """
  @spec get_pending_sessions(String.t()) :: [Session.t()]
  def get_pending_sessions(agent_id) do
    GenServer.call(__MODULE__, {:get_pending_sessions, agent_id})
  end

  @doc """
  Get recent complete sessions within a time window.

  ## Parameters
    - agent_id: The agent identifier
    - window_seconds: Time window in seconds (default: 300)

  ## Returns
    [Session.t()]
  """
  @spec get_recent_sessions(String.t(), non_neg_integer()) :: [Session.t()]
  def get_recent_sessions(agent_id, window_seconds \\ 300) do
    GenServer.call(__MODULE__, {:get_recent_sessions, agent_id, window_seconds})
  end

  @doc """
  Get session count and stats for an agent.

  ## Returns
    %{total: integer, pending: integer, complete: integer, avg_latency_ms: float | nil}
  """
  @spec get_stats(String.t()) :: map()
  def get_stats(agent_id) do
    GenServer.call(__MODULE__, {:get_stats, agent_id})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    table = :ets.new(@ets_table, [
      :set,
      :named_table,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    # Schedule garbage collection
    Process.send_after(self(), :garbage_collect, @garbage_collection_interval)

    Logger.info("[InferenceTracker] Started")
    {:ok, %{table: table}}
  end

  @impl true
  def handle_call({:track_request, agent_id, event}, _from, state) do
    session_id = event[:session_id] || event["session_id"] || generate_session_id()
    parent_inference_id = event[:parent_inference_id] || event["parent_inference_id"]
    now = DateTime.utc_now()

    request = %{
      pid: event[:pid] || event["pid"],
      process_name: event[:process_name] || event["process_name"],
      process_path: event[:process_path] || event["process_path"],
      api_provider: normalize_provider(event[:api_provider] || event["api_provider"]),
      api_endpoint: event[:api_endpoint] || event["api_endpoint"],
      prompt_preview: event[:prompt_preview] || event["prompt_preview"],
      full_prompt_hash: event[:full_prompt_hash] || event["full_prompt_hash"],
      model: event[:model] || event["model"],
      timestamp: parse_timestamp(event[:timestamp] || event["timestamp"])
    }

    # Extract orchestration context for chain analysis
    orchestration_context = %{
      privilege_level: event[:privilege_level] || event["privilege_level"] || 0,
      system_prompt: event[:system_prompt] || event["system_prompt"],
      tool_calls: event[:tool_calls] || event["tool_calls"] || []
    }

    session = %Session{
      session_id: session_id,
      agent_id: agent_id,
      parent_inference_id: parent_inference_id,
      request: request,
      response: nil,
      status: :pending,
      created_at: now,
      updated_at: now,
      metrics: nil,
      extraction_risk: nil,
      orchestration_context: orchestration_context
    }

    # Store in ETS
    :ets.insert(@ets_table, {{agent_id, session_id}, session})

    Logger.debug("[InferenceTracker] New inference request: agent=#{agent_id}, session=#{session_id}, parent=#{parent_inference_id || "none"}")

    # Broadcast new request
    PubSub.broadcast(
      TamanduaServer.PubSub,
      "inference:#{agent_id}",
      {:inference_request, session}
    )

    PubSub.broadcast(
      TamanduaServer.PubSub,
      "inference:all",
      {:inference_request, session}
    )

    # Track in OrchestrationDetector for multi-agent chain analysis
    track_in_orchestration_detector(agent_id, session_id, parent_inference_id, session)

    {:reply, {:ok, session_id}, state}
  end

  @impl true
  def handle_call({:track_response, agent_id, session_id, event}, _from, state) do
    key = {agent_id, session_id}

    case :ets.lookup(@ets_table, key) do
      [{^key, session}] ->
        now = DateTime.utc_now()

        response = %{
          response_preview: event[:response_preview] || event["response_preview"],
          response_hash: event[:response_hash] || event["response_hash"],
          finish_reason: event[:finish_reason] || event["finish_reason"],
          error_message: event[:error_message] || event["error_message"],
          timestamp: parse_timestamp(event[:timestamp] || event["timestamp"])
        }

        # Extract token count
        token_count = extract_token_count(event)

        # Calculate metrics
        latency_ms = event[:latency_ms] || event["latency_ms"] ||
          compute_latency(session.request[:timestamp], response.timestamp)

        metrics = %{
          latency_ms: latency_ms,
          token_count: token_count,
          token_efficiency: compute_token_efficiency(token_count),
          response_size: String.length(response.response_preview || "")
        }

        # Determine status based on finish_reason
        status = case response.finish_reason do
          "error" -> :error
          nil when response.error_message != nil -> :error
          _ -> :complete
        end

        # Calculate extraction risk from ModelExtractionDetector
        extraction_risk = compute_extraction_risk(agent_id, session.request)

        updated_session = %{session |
          response: response,
          status: status,
          updated_at: now,
          metrics: metrics,
          extraction_risk: extraction_risk
        }

        # Update in ETS
        :ets.insert(@ets_table, {key, updated_session})

        Logger.debug(
          "[InferenceTracker] Inference response: agent=#{agent_id}, session=#{session_id}, " <>
          "latency=#{latency_ms}ms, status=#{status}"
        )

        # Broadcast completion
        PubSub.broadcast(
          TamanduaServer.PubSub,
          "inference:#{agent_id}",
          {:inference_complete, updated_session}
        )

        PubSub.broadcast(
          TamanduaServer.PubSub,
          "inference:all",
          {:inference_complete, updated_session}
        )

        {:reply, {:ok, updated_session}, state}

      [] ->
        Logger.warning("[InferenceTracker] Response for unknown session: #{session_id}")
        {:reply, {:error, :session_not_found}, state}
    end
  end

  @impl true
  def handle_call({:get_session, agent_id, session_id}, _from, state) do
    key = {agent_id, session_id}

    result = case :ets.lookup(@ets_table, key) do
      [{^key, session}] -> {:ok, session}
      [] -> {:error, :not_found}
    end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_pending_sessions, agent_id}, _from, state) do
    sessions = :ets.foldl(fn {{a_id, _}, session}, acc ->
      if a_id == agent_id && session.status == :pending do
        [session | acc]
      else
        acc
      end
    end, [], @ets_table)

    # Sort by created_at (oldest first, since they've been waiting longest)
    sorted = Enum.sort_by(sessions, & &1.created_at, {:asc, DateTime})

    {:reply, sorted, state}
  end

  @impl true
  def handle_call({:get_recent_sessions, agent_id, window_seconds}, _from, state) do
    cutoff = DateTime.add(DateTime.utc_now(), -window_seconds, :second)

    sessions = :ets.foldl(fn {{a_id, _}, session}, acc ->
      if a_id == agent_id &&
         session.status == :complete &&
         DateTime.compare(session.updated_at, cutoff) == :gt do
        [session | acc]
      else
        acc
      end
    end, [], @ets_table)

    # Sort by updated_at (most recent first)
    sorted = Enum.sort_by(sessions, & &1.updated_at, {:desc, DateTime})

    {:reply, sorted, state}
  end

  @impl true
  def handle_call({:get_stats, agent_id}, _from, state) do
    stats = :ets.foldl(fn {{a_id, _}, session}, acc ->
      if a_id == agent_id do
        acc = Map.update(acc, :total, 1, & &1 + 1)

        acc = case session.status do
          :pending -> Map.update(acc, :pending, 1, & &1 + 1)
          :complete -> Map.update(acc, :complete, 1, & &1 + 1)
          :timeout -> Map.update(acc, :timeout, 1, & &1 + 1)
          :error -> Map.update(acc, :error, 1, & &1 + 1)
          _ -> acc
        end

        # Accumulate latencies for average calculation
        acc = if session.metrics && session.metrics.latency_ms do
          Map.update(acc, :latencies, [session.metrics.latency_ms], fn l ->
            [session.metrics.latency_ms | l]
          end)
        else
          acc
        end

        # Accumulate extraction risks for statistics
        acc = if session.extraction_risk != nil do
          acc
          |> Map.update(:extraction_risks, [session.extraction_risk], fn r ->
            [session.extraction_risk | r]
          end)
          |> (fn a ->
            if session.extraction_risk >= 0.7 do
              Map.update(a, :high_extraction_risk_count, 1, & &1 + 1)
            else
              a
            end
          end).()
        else
          acc
        end

        acc
      else
        acc
      end
    end, %{total: 0, pending: 0, complete: 0, timeout: 0, error: 0, high_extraction_risk_count: 0}, @ets_table)

    # Calculate average latency
    avg_latency = case Map.get(stats, :latencies, []) do
      [] -> nil
      latencies ->
        sum = Enum.sum(latencies)
        count = length(latencies)
        Float.round(sum / count, 2)
    end

    # Calculate average and max extraction risk
    {avg_extraction_risk, max_extraction_risk} = case Map.get(stats, :extraction_risks, []) do
      [] -> {nil, nil}
      risks ->
        sum = Enum.sum(risks)
        count = length(risks)
        {Float.round(sum / count, 4), Float.round(Enum.max(risks), 4)}
    end

    stats = stats
    |> Map.delete(:latencies)
    |> Map.delete(:extraction_risks)
    |> Map.put(:avg_latency_ms, avg_latency)
    |> Map.put(:avg_extraction_risk, avg_extraction_risk)
    |> Map.put(:max_extraction_risk, max_extraction_risk)

    {:reply, stats, state}
  end

  @impl true
  def handle_info(:garbage_collect, state) do
    now = DateTime.utc_now()
    cutoff = DateTime.add(now, -@session_ttl_seconds, :second)

    # Find and remove expired sessions
    stale_keys = :ets.foldl(fn {key, session}, acc ->
      if DateTime.compare(session.updated_at, cutoff) == :lt do
        # Mark pending sessions as timeout before removal
        if session.status == :pending do
          updated = %{session | status: :timeout, updated_at: now}
          :ets.insert(@ets_table, {key, updated})
        end
        [key | acc]
      else
        acc
      end
    end, [], @ets_table)

    # Actually delete the stale entries (after marking timeouts)
    # Wait a bit for any final updates, then delete
    stale_keys
    |> Enum.filter(fn key ->
      case :ets.lookup(@ets_table, key) do
        [{^key, session}] -> session.status in [:complete, :timeout, :error]
        [] -> true
      end
    end)
    |> Enum.each(fn key -> :ets.delete(@ets_table, key) end)

    if length(stale_keys) > 0 do
      Logger.debug("[InferenceTracker] Garbage collected #{length(stale_keys)} stale sessions")
    end

    # Schedule next garbage collection
    Process.send_after(self(), :garbage_collect, @garbage_collection_interval)
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp generate_session_id do
    Ecto.UUID.generate()
  end

  defp normalize_provider(provider) when is_atom(provider), do: provider
  defp normalize_provider("openai"), do: :openai
  defp normalize_provider("OpenAI"), do: :openai
  defp normalize_provider("anthropic"), do: :anthropic
  defp normalize_provider("Anthropic"), do: :anthropic
  defp normalize_provider("ollama"), do: :ollama
  defp normalize_provider("Ollama"), do: :ollama
  defp normalize_provider("huggingface"), do: :huggingface
  defp normalize_provider("HuggingFace"), do: :huggingface
  defp normalize_provider(_), do: :other

  defp parse_timestamp(%DateTime{} = dt), do: dt
  defp parse_timestamp(timestamp) when is_binary(timestamp) do
    case DateTime.from_iso8601(timestamp) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp parse_timestamp(timestamp) when is_integer(timestamp) do
    # Handle milliseconds or seconds
    ts = if timestamp > 1_000_000_000_000, do: div(timestamp, 1000), else: timestamp
    case DateTime.from_unix(ts) do
      {:ok, dt} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp parse_timestamp(_), do: DateTime.utc_now()

  defp extract_token_count(event) do
    token_count = event[:token_count] || event["token_count"]

    cond do
      is_map(token_count) ->
        %{
          input_tokens: token_count[:input_tokens] || token_count["input_tokens"],
          output_tokens: token_count[:output_tokens] || token_count["output_tokens"],
          total_tokens: token_count[:total_tokens] || token_count["total_tokens"]
        }
      true ->
        nil
    end
  end

  defp compute_latency(nil, _), do: nil
  defp compute_latency(_, nil), do: nil
  defp compute_latency(%DateTime{} = request_time, %DateTime{} = response_time) do
    DateTime.diff(response_time, request_time, :millisecond)
  end
  defp compute_latency(_, _), do: nil

  defp compute_token_efficiency(nil), do: nil
  defp compute_token_efficiency(%{input_tokens: nil}), do: nil
  defp compute_token_efficiency(%{output_tokens: nil}), do: nil
  defp compute_token_efficiency(%{input_tokens: 0}), do: nil
  defp compute_token_efficiency(%{input_tokens: input, output_tokens: output}) do
    Float.round(output / input, 4)
  end
  defp compute_token_efficiency(_), do: nil

  # Compute extraction risk using ModelExtractionDetector
  defp compute_extraction_risk(agent_id, request) do
    # Build query from request data
    query = %{
      input: request[:prompt_preview] || "",
      output_type: infer_output_type(request),
      timestamp: request[:timestamp] || DateTime.utc_now(),
      input_embedding: nil,
      metadata: %{
        model: request[:model],
        api_provider: request[:api_provider],
        api_endpoint: request[:api_endpoint]
      }
    }

    # Try to get risk from ModelExtractionDetector
    # This is non-blocking - if detector not available, return nil
    try do
      case GenServer.whereis(ModelExtractionDetector) do
        nil ->
          nil

        _pid ->
          case ModelExtractionDetector.record_query(agent_id, query) do
            {:ok, result} -> result.extraction_risk
            _ -> nil
          end
      end
    rescue
      _ -> nil
    catch
      :exit, _ -> nil
    end
  end

  defp infer_output_type(request) do
    endpoint = request[:api_endpoint] || ""
    cond do
      String.contains?(endpoint, "embeddings") -> :embeddings
      String.contains?(endpoint, "logits") -> :logits
      true -> :text
    end
  end

  # Track inference in OrchestrationDetector for multi-agent chain analysis
  defp track_in_orchestration_detector(agent_id, session_id, parent_inference_id, session) do
    # Non-blocking - don't fail if OrchestrationDetector isn't running
    Task.start(fn ->
      try do
        case GenServer.whereis(OrchestrationDetector) do
          nil ->
            :ok

          _pid ->
            opts = [
              process_context: %{
                pid: session.request[:pid],
                process_name: session.request[:process_name],
                process_path: session.request[:process_path]
              },
              privilege_level: session.orchestration_context[:privilege_level] || 0,
              input: session.request[:prompt_preview],
              model: session.request[:model],
              api_provider: session.request[:api_provider],
              system_prompt: session.orchestration_context[:system_prompt],
              tool_calls: session.orchestration_context[:tool_calls] || [],
              metadata: %{source: :inference_tracker, agent_id: agent_id}
            ]

            OrchestrationDetector.track_inference_chain(agent_id, session_id, parent_inference_id, opts)
        end
      rescue
        _ -> :ok
      catch
        :exit, _ -> :ok
      end
    end)
  end
end
