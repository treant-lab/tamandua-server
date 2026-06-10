defmodule TamanduaServer.Registries.OllamaWatcher do
  @moduledoc """
  GenServer that monitors Ollama for new model pulls.

  Periodically polls Ollama's /api/tags endpoint to detect when new models
  are downloaded. When a new model is detected, triggers security scanning
  via DownloadHook and broadcasts PubSub events.

  ## Features

  - Configurable polling interval (default: 30 seconds)
  - Tracks models by {name, digest} to detect both new models and updates
  - Skips triggering hooks on initial model list (only detects changes)
  - Gracefully handles Ollama unavailability
  - Broadcasts to PubSub on model pull detection

  ## Configuration

  - `:poll_interval` - Polling interval in milliseconds (default: 30_000)
  - `:initial_delay` - Delay before first poll (default: 10_000)
  - `:ollama_url` - Ollama API URL (default: from env or http://localhost:11434)
  - `:pubsub` - PubSub server name (default: TamanduaServer.PubSub)
  - `:name` - GenServer name (default: __MODULE__)

  ## Example

      # Start watcher
      {:ok, pid} = OllamaWatcher.start_link(poll_interval: 30_000)

      # Get current status
      OllamaWatcher.get_status()
      # => %{last_check: ~U[...], model_count: 3, last_error: nil, initialized: true}

  ## PubSub Events

  Events are broadcast to the `"registries:ollama"` topic:
  - `{:model_pulled, model_id, model_metadata}` - New model detected
  """

  use GenServer

  require Logger

  alias TamanduaServer.Registries.Ollama
  alias TamanduaServer.Registries.DownloadHook

  @default_poll_interval 30_000  # 30 seconds
  @default_initial_delay 10_000  # 10 seconds before first check

  defstruct [
    :poll_interval,
    :ollama_url,
    :pubsub,
    :known_models,
    :last_check,
    :last_error,
    :initialized
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the OllamaWatcher GenServer.

  ## Options

  - `:poll_interval` - Polling interval in milliseconds (default: 30_000)
  - `:initial_delay` - Delay before first poll (default: 10_000)
  - `:ollama_url` - Ollama API URL (default: http://localhost:11434)
  - `:pubsub` - PubSub server name (default: TamanduaServer.PubSub)
  - `:name` - GenServer name (default: __MODULE__)
  """
  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Returns the current watcher status.

  ## Returns

  Map with:
  - `:last_check` - DateTime of last successful poll (or nil)
  - `:model_count` - Number of known models
  - `:last_error` - Last error encountered (or nil)
  - `:initialized` - Whether initial poll has completed
  """
  @spec get_status(atom() | pid()) :: map()
  def get_status(server \\ __MODULE__) do
    GenServer.call(server, :get_status)
  end

  @doc """
  Triggers an immediate poll of Ollama.

  Returns `:ok` after poll completes.
  """
  @spec poll_now(atom() | pid()) :: :ok
  def poll_now(server \\ __MODULE__) do
    GenServer.call(server, :poll_now, 60_000)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    poll_interval = Keyword.get(opts, :poll_interval, @default_poll_interval)
    initial_delay = Keyword.get(opts, :initial_delay, @default_initial_delay)

    ollama_url =
      Keyword.get(opts, :ollama_url) ||
        System.get_env("OLLAMA_URL") ||
        "http://localhost:11434"

    pubsub = Keyword.get(opts, :pubsub, TamanduaServer.PubSub)

    state = %__MODULE__{
      poll_interval: poll_interval,
      ollama_url: ollama_url,
      pubsub: pubsub,
      known_models: MapSet.new(),
      last_check: nil,
      last_error: nil,
      initialized: false
    }

    # Schedule initial check after delay
    Process.send_after(self(), :poll, initial_delay)

    Logger.info("[OllamaWatcher] Started with poll_interval=#{poll_interval}ms, url=#{ollama_url}")

    {:ok, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      last_check: state.last_check,
      model_count: MapSet.size(state.known_models),
      last_error: state.last_error,
      initialized: state.initialized
    }

    {:reply, status, state}
  end

  @impl true
  def handle_call(:poll_now, _from, state) do
    new_state = do_poll(state)
    {:reply, :ok, new_state}
  end

  @impl true
  def handle_info(:poll, state) do
    new_state = do_poll(state)

    # Schedule next poll
    Process.send_after(self(), :poll, state.poll_interval)

    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp do_poll(state) do
    config = %{base_url: state.ollama_url}

    case Ollama.list_models(config) do
      {:ok, models} ->
        handle_models(state, models)

      {:error, reason} ->
        handle_error(state, reason)
    end
  end

  defp handle_models(state, models) do
    now = DateTime.utc_now()

    # Create set of current models as {name, digest} tuples
    current_models =
      models
      |> Enum.map(fn model ->
        {model.id, model.sha}
      end)
      |> MapSet.new()

    # Find new models (not in known_models)
    new_models = MapSet.difference(current_models, state.known_models)

    # Only trigger hooks if we've been initialized
    # (skip first poll to avoid triggering on existing models)
    if state.initialized and MapSet.size(new_models) > 0 do
      handle_new_models(state, models, new_models)
    end

    # Update state
    %{state |
      known_models: current_models,
      last_check: now,
      last_error: nil,
      initialized: true
    }
  end

  defp handle_new_models(state, models, new_model_tuples) do
    # Map of id -> full model data
    model_map = Enum.into(models, %{}, fn m -> {m.id, m} end)

    Enum.each(new_model_tuples, fn {model_id, _digest} ->
      model = Map.get(model_map, model_id)

      if model do
        Logger.info("[OllamaWatcher] New model detected: #{model_id}")

        # Trigger DownloadHook for automatic scanning
        spawn_download_hook(model)

        # Broadcast PubSub event
        broadcast_model_pulled(state.pubsub, model)
      end
    end)
  end

  defp spawn_download_hook(model) do
    # Use Task.Supervisor if available, otherwise spawn directly
    task_supervisor = Application.get_env(:tamandua_server, :task_supervisor, TamanduaServer.TaskSupervisor)

    task_fn = fn ->
      try do
        DownloadHook.handle_download(model.id, Ollama, %{})
      rescue
        error ->
          Logger.error("[OllamaWatcher] DownloadHook failed for #{model.id}: #{inspect(error)}")
      end
    end

    case Process.whereis(task_supervisor) do
      nil ->
        # Supervisor not available, spawn directly
        Task.start(task_fn)

      _pid ->
        Task.Supervisor.start_child(task_supervisor, task_fn)
    end
  end

  defp broadcast_model_pulled(pubsub, model) do
    event = {:model_pulled, model.id, %{
      name: model.name,
      sha: model.sha,
      last_modified: model.last_modified,
      metadata: model.metadata
    }}

    Phoenix.PubSub.broadcast(pubsub, "registries:ollama", event)
  rescue
    error ->
      Logger.warning("[OllamaWatcher] Failed to broadcast PubSub event: #{inspect(error)}")
  end

  defp handle_error(state, reason) do
    Logger.warning("[OllamaWatcher] Poll failed: #{inspect(reason)}")

    %{state |
      last_error: reason,
      initialized: true  # Mark initialized even on error to prevent retrigger on recovery
    }
  end
end
