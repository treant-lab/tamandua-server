defmodule TamanduaServer.Detection.ModelFileCorrelator do
  @moduledoc """
  Correlates model file access events with ML processes.

  Tracks which processes access which model files, providing critical context
  for understanding ML runtime behavior and detecting anomalies in model loading.

  Designed to integrate with MLProcessTracker and provide data for Phase 26-27.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.MLProcessTracker

  @model_extensions %{
    ".gguf" => {:gguf, :low},
    ".ggml" => {:ggml, :low},
    ".safetensors" => {:safetensors, :low},
    ".onnx" => {:onnx, :low},
    ".pt" => {:pytorch, :high},
    ".pth" => {:pytorch, :high},
    ".pkl" => {:pickle, :high},
    ".bin" => {:bin, :medium},
    ".h5" => {:keras, :medium},
    ".keras" => {:keras, :medium}
  }

  @ttl_seconds 3600  # 1 hour

  # Client API

  @doc """
  Start the ModelFileCorrelator GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Correlate a file access event with ML processes.

  ## Parameters
    - agent_id: The agent identifier
    - file_event: File access/read/open/create event map

  ## Returns
    Correlation map if model file detected, nil otherwise
  """
  def correlate(agent_id, file_event) do
    GenServer.call(__MODULE__, {:correlate, agent_id, file_event})
  end

  @doc """
  Get model access history for a specific process.

  ## Parameters
    - agent_id: The agent identifier
    - pid: Process ID

  ## Returns
    List of model file paths accessed by this process
  """
  def get_model_access_history(agent_id, pid) do
    GenServer.call(__MODULE__, {:get_model_access_history, agent_id, pid})
  end

  @doc """
  Get list of processes that accessed a specific model file.

  ## Parameters
    - agent_id: The agent identifier
    - file_path: Path to model file

  ## Returns
    List of PIDs that accessed this model
  """
  def get_processes_for_model(agent_id, file_path) do
    GenServer.call(__MODULE__, {:get_processes_for_model, agent_id, file_path})
  end

  @doc """
  Check if a file path is a model file.

  ## Parameters
    - path: File path string

  ## Returns
    Boolean
  """
  def is_model_file?(path) when is_binary(path) do
    ext = Path.extname(path) |> String.downcase()
    Map.has_key?(@model_extensions, ext)
  end

  def is_model_file?(_), do: false

  # Server callbacks

  @impl true
  def init(_opts) do
    # Two ETS tables for bidirectional lookups
    # :model_file_access - {agent_id, file_path} -> list of PIDs
    # :process_model_files - {agent_id, pid} -> list of file paths
    model_file_access = :ets.new(:model_file_access, [
      :set,
      :named_table,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    process_model_files = :ets.new(:process_model_files, [
      :set,
      :named_table,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    # Schedule TTL cleanup
    Process.send_after(self(), :cleanup_expired, :timer.minutes(10))

    Logger.info("[ModelFileCorrelator] Started")
    {:ok, %{model_file_access: model_file_access, process_model_files: process_model_files}}
  end

  @impl true
  def handle_call({:correlate, agent_id, file_event}, _from, state) do
    payload = file_event["payload"] || file_event[:payload] || file_event
    file_path = payload["path"] || payload[:path]
    pid = payload["pid"] || payload[:pid]
    event_type_str = file_event["event_type"] || file_event[:event_type] || ""
    timestamp = file_event["timestamp"] || file_event[:timestamp]

    # Check if this is a model file
    case detect_model_file(file_path) do
      nil ->
        {:reply, nil, state}

      {model_format, risk_level} ->
        # Determine event type category
        event_type = categorize_event_type(event_type_str)

        # Build correlation struct
        correlation = %{
          file_path: file_path,
          model_format: model_format,
          risk_level: risk_level,
          accessing_pid: pid,
          agent_id: agent_id,
          event_type: event_type,
          timestamp: parse_timestamp(timestamp)
        }

        # Record in both ETS tables
        record_file_access(agent_id, file_path, pid, state)
        record_process_file(agent_id, pid, file_path, state)

        # Notify MLProcessTracker to add model file to process context
        if pid do
          try do
            MLProcessTracker.add_model_file(agent_id, pid, file_path)
          rescue
            _ -> :ok
          catch
            :exit, _ -> :ok
          end
        end

        Logger.debug("[ModelFileCorrelator] Correlated model access: #{file_path} by pid #{pid} (#{model_format}, #{risk_level})")

        {:reply, correlation, state}
    end
  end

  @impl true
  def handle_call({:get_model_access_history, agent_id, pid}, _from, state) do
    result = case :ets.lookup(:process_model_files, {agent_id, pid}) do
      [{{^agent_id, ^pid}, file_paths}] -> file_paths
      [] -> []
    end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_processes_for_model, agent_id, file_path}, _from, state) do
    result = case :ets.lookup(:model_file_access, {agent_id, file_path}) do
      [{{^agent_id, ^file_path}, pids}] -> pids
      [] -> []
    end

    {:reply, result, state}
  end

  @impl true
  def handle_info(:cleanup_expired, state) do
    # In a production system, we'd track timestamps and remove old entries.
    # For now, we rely on the TTL being reasonable (1 hour) and bounded by
    # the number of active processes.

    # Schedule next cleanup
    Process.send_after(self(), :cleanup_expired, :timer.minutes(10))
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # Private functions

  defp detect_model_file(path) when is_binary(path) do
    ext = Path.extname(path) |> String.downcase()
    Map.get(@model_extensions, ext)
  end

  defp detect_model_file(_), do: nil

  defp categorize_event_type(event_type) when is_binary(event_type) do
    cond do
      String.contains?(event_type, "read") or String.contains?(event_type, "access") or String.contains?(event_type, "open") ->
        :read
      String.contains?(event_type, "write") or String.contains?(event_type, "modify") ->
        :write
      String.contains?(event_type, "create") ->
        :create
      true ->
        :read
    end
  end

  defp categorize_event_type(_), do: :read

  defp record_file_access(agent_id, file_path, pid, _state) do
    key = {agent_id, file_path}

    case :ets.lookup(:model_file_access, key) do
      [{^key, existing_pids}] ->
        if pid not in existing_pids do
          :ets.insert(:model_file_access, {key, [pid | existing_pids]})
        end

      [] ->
        :ets.insert(:model_file_access, {key, [pid]})
    end
  end

  defp record_process_file(agent_id, pid, file_path, _state) do
    key = {agent_id, pid}

    case :ets.lookup(:process_model_files, key) do
      [{^key, existing_files}] ->
        if file_path not in existing_files do
          :ets.insert(:process_model_files, {key, [file_path | existing_files]})
        end

      [] ->
        :ets.insert(:process_model_files, {key, [file_path]})
    end
  end

  defp parse_timestamp(timestamp) when is_binary(timestamp) do
    case DateTime.from_iso8601(timestamp) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end

  defp parse_timestamp(%DateTime{} = dt), do: dt
  defp parse_timestamp(_), do: DateTime.utc_now()
end
