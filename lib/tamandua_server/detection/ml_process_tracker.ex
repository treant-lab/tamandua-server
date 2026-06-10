defmodule TamanduaServer.Detection.MLProcessTracker do
  @moduledoc """
  Tracks ML process state per agent for runtime context.

  Identifies and tracks machine learning processes (Python, Ollama, llama.cpp, vLLM)
  on each monitored agent, extracting runtime metadata like framework, model files
  accessed, and process lifecycle.

  Designed to provide context for Phase 26 (LLM Request Interceptor) and Phase 27
  (Runtime Behavior Analysis).
  """

  use GenServer
  require Logger
  alias Phoenix.PubSub

  @ml_process_patterns %{
    # Python patterns
    python: ~r/^python[0-9.]*$/i,
    # Ollama patterns
    ollama: ~r/^ollama$/i,
    # llama.cpp patterns
    llama_cpp: ~r/^(llama-server|llama-cli|main)$/i,
    # vLLM patterns
    vllm: ~r/vllm/i
  }

  @framework_patterns [
    {"torch", ~r/torch|pytorch/i},
    {"tensorflow", ~r/tensorflow|tf\./i},
    {"transformers", ~r/transformers|huggingface/i},
    {"langchain", ~r/langchain/i}
  ]

  @garbage_collection_interval :timer.minutes(5)

  # Client API

  @doc """
  Start the MLProcessTracker GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Track a process creation event as a potential ML process.

  ## Parameters
    - agent_id: The agent identifier
    - event: Process creation event map

  ## Returns
    :ok
  """
  def track_process(agent_id, event) do
    GenServer.call(__MODULE__, {:track_process, agent_id, event})
  end

  @doc """
  Handle process termination and remove from tracking.

  ## Parameters
    - agent_id: The agent identifier
    - pid: Process ID

  ## Returns
    :ok
  """
  def process_terminated(agent_id, pid) do
    GenServer.call(__MODULE__, {:process_terminated, agent_id, pid})
  end

  @doc """
  Get all tracked ML processes for an agent.

  ## Parameters
    - agent_id: The agent identifier

  ## Returns
    List of process context maps
  """
  def get_ml_processes(agent_id) do
    GenServer.call(__MODULE__, {:get_ml_processes, agent_id})
  end

  @doc """
  Get ML context for a specific process.

  ## Parameters
    - agent_id: The agent identifier
    - pid: Process ID

  ## Returns
    Process context map or nil if not found
  """
  def get_process_context(agent_id, pid) do
    GenServer.call(__MODULE__, {:get_process_context, agent_id, pid})
  end

  @doc """
  Add a model file to a tracked process (called by ModelFileCorrelator).

  ## Parameters
    - agent_id: The agent identifier
    - pid: Process ID
    - file_path: Path to model file

  ## Returns
    :ok
  """
  def add_model_file(agent_id, pid, file_path) do
    GenServer.call(__MODULE__, {:add_model_file, agent_id, pid, file_path})
  end

  # Server callbacks

  @impl true
  def init(_opts) do
    # Create ETS table for ML process tracking
    table = :ets.new(:ml_process_tracker, [
      :set,
      :named_table,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    # Schedule garbage collection
    Process.send_after(self(), :garbage_collect, @garbage_collection_interval)

    Logger.info("[MLProcessTracker] Started")
    {:ok, %{table: table}}
  end

  @impl true
  def handle_call({:track_process, agent_id, event}, _from, state) do
    payload = event["payload"] || event[:payload] || event
    pid = payload["pid"] || payload[:pid]
    image = payload["image"] || payload[:image] || ""
    path = payload["path"] || payload[:path] || ""
    cmdline = payload["cmdline"] || payload[:cmdline] || ""
    timestamp = payload["timestamp"] || payload[:timestamp]

    # Detect if this is an ML process
    case detect_ml_runtime(image, path, cmdline) do
      nil ->
        {:reply, :ok, state}

      runtime_type ->
        framework = detect_framework(cmdline)
        now = parse_timestamp(timestamp)

        process_context = %{
          agent_id: agent_id,
          pid: pid,
          name: extract_name(image, path),
          path: path,
          cmdline: cmdline,
          runtime_type: runtime_type,
          framework: framework,
          model_files: [],
          started_at: now,
          last_seen: now
        }

        :ets.insert(:ml_process_tracker, {{agent_id, pid}, process_context})
        Logger.debug("[MLProcessTracker] Tracking #{runtime_type} process: agent=#{agent_id}, pid=#{pid}")

        # Broadcast new ML process detection
        PubSub.broadcast(
          TamanduaServer.PubSub,
          "ml_process:#{agent_id}",
          {:ml_process_update, :new, process_context}
        )

        {:reply, :ok, state}
    end
  end

  @impl true
  def handle_call({:process_terminated, agent_id, pid}, _from, state) do
    :ets.delete(:ml_process_tracker, {agent_id, pid})
    Logger.debug("[MLProcessTracker] Process terminated: agent=#{agent_id}, pid=#{pid}")

    # Broadcast process termination
    PubSub.broadcast(
      TamanduaServer.PubSub,
      "ml_process:#{agent_id}",
      {:ml_process_update, :terminated, pid}
    )

    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:get_ml_processes, agent_id}, _from, state) do
    processes = :ets.foldl(fn {{a_id, _pid}, context}, acc ->
      if a_id == agent_id do
        [context | acc]
      else
        acc
      end
    end, [], :ml_process_tracker)

    {:reply, processes, state}
  end

  @impl true
  def handle_call({:get_process_context, agent_id, pid}, _from, state) do
    result = case :ets.lookup(:ml_process_tracker, {agent_id, pid}) do
      [{{^agent_id, ^pid}, context}] -> context
      [] -> nil
    end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:add_model_file, agent_id, pid, file_path}, _from, state) do
    case :ets.lookup(:ml_process_tracker, {agent_id, pid}) do
      [{{^agent_id, ^pid}, context}] ->
        updated_context = Map.update!(context, :model_files, fn files ->
          if file_path in files do
            files
          else
            [file_path | files]
          end
        end)

        :ets.insert(:ml_process_tracker, {{agent_id, pid}, updated_context})
        Logger.debug("[MLProcessTracker] Added model file to pid #{pid}: #{file_path}")

        # Broadcast model file addition
        PubSub.broadcast(
          TamanduaServer.PubSub,
          "ml_process:#{agent_id}",
          {:ml_process_update, :model_file, %{pid: pid, file: file_path}}
        )

      [] ->
        Logger.debug("[MLProcessTracker] Process not tracked: agent=#{agent_id}, pid=#{pid}")
    end

    {:reply, :ok, state}
  end

  @impl true
  def handle_info(:garbage_collect, state) do
    # Remove processes not seen in 5 minutes
    cutoff = DateTime.add(DateTime.utc_now(), -300, :second)

    stale_keys = :ets.foldl(fn {key, context}, acc ->
      if DateTime.compare(context.last_seen, cutoff) == :lt do
        [key | acc]
      else
        acc
      end
    end, [], :ml_process_tracker)

    Enum.each(stale_keys, fn key ->
      :ets.delete(:ml_process_tracker, key)
    end)

    if length(stale_keys) > 0 do
      Logger.debug("[MLProcessTracker] Garbage collected #{length(stale_keys)} stale processes")
    end

    # Schedule next garbage collection
    Process.send_after(self(), :garbage_collect, @garbage_collection_interval)
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # Private functions

  defp detect_ml_runtime(image, path, cmdline) do
    image_name = extract_name(image, path)
    cmdline_lower = String.downcase(cmdline)

    cond do
      # Python detection
      Regex.match?(@ml_process_patterns.python, image_name) ->
        :python

      # Ollama detection
      Regex.match?(@ml_process_patterns.ollama, image_name) or String.contains?(cmdline_lower, "ollama") ->
        :ollama

      # llama.cpp detection
      Regex.match?(@ml_process_patterns.llama_cpp, image_name) and
        (String.contains?(path, "llama") or String.contains?(cmdline_lower, "gguf") or String.contains?(cmdline_lower, "ggml")) ->
        :llama_cpp

      # vLLM detection
      String.contains?(cmdline_lower, "vllm") or String.contains?(cmdline_lower, "-m vllm") ->
        :vllm

      true ->
        nil
    end
  end

  defp detect_framework(cmdline) do
    cmdline_lower = String.downcase(cmdline)

    Enum.find_value(@framework_patterns, fn {name, pattern} ->
      if Regex.match?(pattern, cmdline_lower), do: name
    end)
  end

  defp extract_name(image, path) when is_binary(image) and image != "" do
    Path.basename(image)
  end

  defp extract_name(_image, path) when is_binary(path) and path != "" do
    Path.basename(path)
  end

  defp extract_name(_image, _path), do: "unknown"

  defp parse_timestamp(timestamp) when is_binary(timestamp) do
    case DateTime.from_iso8601(timestamp) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end

  defp parse_timestamp(%DateTime{} = dt), do: dt
  defp parse_timestamp(_), do: DateTime.utc_now()
end
