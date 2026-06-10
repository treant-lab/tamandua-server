defmodule TamanduaServer.Detection.LLMRequestTracker do
  @moduledoc """
  Tracks LLM API requests per agent for security monitoring.

  Stores intercepted LLM requests with process correlation, enabling
  Phase 27 runtime behavior analysis to detect prompt injection,
  data exfiltration, and other AI-specific threats.
  """

  use GenServer
  require Logger
  alias Phoenix.PubSub
  alias TamanduaServer.Detection.MLProcessTracker

  @ets_table :llm_request_tracker
  @garbage_collection_interval :timer.minutes(5)
  @request_ttl_seconds 3600  # 1 hour

  # Struct for tracked request
  defstruct [
    :id,
    :agent_id,
    :pid,
    :process_name,
    :process_path,
    :api_provider,     # :openai | :anthropic | :ollama | :huggingface | :other
    :api_endpoint,
    :prompt_preview,   # First 512 chars
    :full_prompt_hash,
    :model,
    :ml_context,       # From MLProcessTracker if available
    :timestamp
  ]

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Track an LLM request event from agent telemetry.

  ## Parameters
    - agent_id: The agent identifier
    - event: LLM request event map with keys:
      - pid: Process ID
      - process_name: Process name
      - process_path: Process executable path
      - api_provider: :openai | :anthropic | :ollama | :huggingface | :other
      - api_endpoint: Full endpoint URL
      - prompt_preview: First 512 chars of prompt
      - full_prompt_hash: SHA256 of full prompt
      - model: Model name (optional)
      - timestamp: Event timestamp

  ## Returns
    :ok
  """
  def track_request(agent_id, event) do
    GenServer.call(__MODULE__, {:track_request, agent_id, event})
  end

  @doc """
  Get all tracked LLM requests for an agent.

  ## Options
    - :provider - Filter by API provider (:openai, :anthropic, :ollama, etc.)
    - :since - Only return requests since timestamp
    - :limit - Maximum number of requests to return (default: 100)
  """
  def get_requests(agent_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_requests, agent_id, opts})
  end

  @doc """
  Get LLM requests made by a specific process.
  """
  def get_requests_for_process(agent_id, pid) do
    GenServer.call(__MODULE__, {:get_requests_for_process, agent_id, pid})
  end

  @doc """
  Get recent requests within time window (default: 5 minutes).
  """
  def get_recent_requests(agent_id, window_seconds \\ 300) do
    GenServer.call(__MODULE__, {:get_recent_requests, agent_id, window_seconds})
  end

  # Server callbacks

  @impl true
  def init(_opts) do
    table = :ets.new(@ets_table, [
      :set,
      :named_table,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    Process.send_after(self(), :garbage_collect, @garbage_collection_interval)

    Logger.info("[LLMRequestTracker] Started")
    {:ok, %{table: table}}
  end

  @impl true
  def handle_call({:track_request, agent_id, event}, _from, state) do
    # Generate unique ID for this request
    request_id = generate_id(agent_id, event)

    # Parse event data
    pid = event[:pid] || event["pid"]
    process_name = event[:process_name] || event["process_name"]
    process_path = event[:process_path] || event["process_path"]
    api_provider = normalize_provider(event[:api_provider] || event["api_provider"])
    api_endpoint = event[:api_endpoint] || event["api_endpoint"]
    prompt_preview = event[:prompt_preview] || event["prompt_preview"]
    full_prompt_hash = event[:full_prompt_hash] || event["full_prompt_hash"]
    model = event[:model] || event["model"]
    timestamp = parse_timestamp(event[:timestamp] || event["timestamp"])

    # Get ML context if this process is tracked
    ml_context = if pid do
      try do
        MLProcessTracker.get_process_context(agent_id, pid)
      rescue
        _ -> nil
      catch
        :exit, _ -> nil
      end
    else
      nil
    end

    # Build request struct
    request = %__MODULE__{
      id: request_id,
      agent_id: agent_id,
      pid: pid,
      process_name: process_name,
      process_path: process_path,
      api_provider: api_provider,
      api_endpoint: api_endpoint,
      prompt_preview: prompt_preview,
      full_prompt_hash: full_prompt_hash,
      model: model,
      ml_context: ml_context,
      timestamp: timestamp
    }

    # Store in ETS
    :ets.insert(@ets_table, {{agent_id, request_id}, request})

    Logger.debug("[LLMRequestTracker] Tracked LLM request: agent=#{agent_id}, provider=#{api_provider}, pid=#{pid}")

    # Broadcast new request tracking
    PubSub.broadcast(
      TamanduaServer.PubSub,
      "llm_request:#{agent_id}",
      {:llm_request_update, :new, request}
    )

    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:get_requests, agent_id, opts}, _from, state) do
    provider_filter = Keyword.get(opts, :provider)
    since_filter = Keyword.get(opts, :since)
    limit = Keyword.get(opts, :limit, 100)

    requests = :ets.foldl(fn {{a_id, _id}, request}, acc ->
      if a_id == agent_id do
        if should_include_request?(request, provider_filter, since_filter) do
          [request | acc]
        else
          acc
        end
      else
        acc
      end
    end, [], @ets_table)

    # Sort by timestamp (most recent first) and limit
    sorted_requests = requests
    |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
    |> Enum.take(limit)

    {:reply, sorted_requests, state}
  end

  @impl true
  def handle_call({:get_requests_for_process, agent_id, pid}, _from, state) do
    requests = :ets.foldl(fn {{a_id, _id}, request}, acc ->
      if a_id == agent_id && request.pid == pid do
        [request | acc]
      else
        acc
      end
    end, [], @ets_table)

    # Sort by timestamp (most recent first)
    sorted_requests = Enum.sort_by(requests, & &1.timestamp, {:desc, DateTime})

    {:reply, sorted_requests, state}
  end

  @impl true
  def handle_call({:get_recent_requests, agent_id, window_seconds}, _from, state) do
    cutoff = DateTime.add(DateTime.utc_now(), -window_seconds, :second)

    requests = :ets.foldl(fn {{a_id, _id}, request}, acc ->
      if a_id == agent_id && DateTime.compare(request.timestamp, cutoff) == :gt do
        [request | acc]
      else
        acc
      end
    end, [], @ets_table)

    # Sort by timestamp (most recent first)
    sorted_requests = Enum.sort_by(requests, & &1.timestamp, {:desc, DateTime})

    {:reply, sorted_requests, state}
  end

  @impl true
  def handle_info(:garbage_collect, state) do
    # Remove requests older than TTL
    cutoff = DateTime.add(DateTime.utc_now(), -@request_ttl_seconds, :second)

    stale_keys = :ets.foldl(fn {key, request}, acc ->
      if DateTime.compare(request.timestamp, cutoff) == :lt do
        [key | acc]
      else
        acc
      end
    end, [], @ets_table)

    Enum.each(stale_keys, fn key ->
      :ets.delete(@ets_table, key)
    end)

    if length(stale_keys) > 0 do
      Logger.debug("[LLMRequestTracker] Garbage collected #{length(stale_keys)} stale requests")
    end

    # Schedule next garbage collection
    Process.send_after(self(), :garbage_collect, @garbage_collection_interval)
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # Private functions

  defp generate_id(agent_id, event) do
    # Generate unique ID based on agent_id, timestamp, and event data
    timestamp = event[:timestamp] || event["timestamp"] || DateTime.utc_now()
    pid = event[:pid] || event["pid"] || "0"
    hash = event[:full_prompt_hash] || event["full_prompt_hash"] || :crypto.strong_rand_bytes(8) |> Base.encode16()

    "#{agent_id}-#{DateTime.to_unix(parse_timestamp(timestamp))}-#{pid}-#{String.slice(hash, 0..7)}"
  end

  defp normalize_provider(provider) when is_atom(provider), do: provider
  defp normalize_provider("openai"), do: :openai
  defp normalize_provider("anthropic"), do: :anthropic
  defp normalize_provider("ollama"), do: :ollama
  defp normalize_provider("huggingface"), do: :huggingface
  defp normalize_provider(_), do: :other

  defp should_include_request?(request, nil, nil), do: true
  defp should_include_request?(request, provider_filter, nil) when not is_nil(provider_filter) do
    request.api_provider == provider_filter
  end
  defp should_include_request?(request, nil, since_filter) when not is_nil(since_filter) do
    DateTime.compare(request.timestamp, since_filter) == :gt
  end
  defp should_include_request?(request, provider_filter, since_filter) do
    request.api_provider == provider_filter &&
      DateTime.compare(request.timestamp, since_filter) == :gt
  end

  defp parse_timestamp(%DateTime{} = dt), do: dt
  defp parse_timestamp(timestamp) when is_binary(timestamp) do
    case DateTime.from_iso8601(timestamp) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp parse_timestamp(timestamp) when is_integer(timestamp) do
    case DateTime.from_unix(timestamp) do
      {:ok, dt} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp parse_timestamp(_), do: DateTime.utc_now()
end
