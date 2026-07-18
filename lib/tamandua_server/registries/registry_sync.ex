defmodule TamanduaServer.Registries.RegistrySync do
  @moduledoc """
  GenServer for periodic synchronization of model registry metadata.

  Maintains an ETS cache of model metadata from configured registries
  (HuggingFace, MLflow, W&B, Ollama) and refreshes it on a configurable schedule.

  ## Configuration

  Configure in config.exs:

      config :tamandua_server, TamanduaServer.Registries.RegistrySync,
        enabled: true,
        sync_interval_ms: 3_600_000,  # 1 hour
        registries: [
          {TamanduaServer.Registries.HuggingFace, %{limit: 100}},
          {TamanduaServer.Registries.MLflow, %{}}
        ]

  ## ETS Cache

  Cache table: `:registry_model_cache`
  Key format: `{registry_name, model_id}`
  Value: Model metadata map from registry

  ## Examples

      # Start the GenServer
      {:ok, pid} = RegistrySync.start_link([])

      # Trigger immediate sync
      :ok = RegistrySync.sync_now(:huggingface)

      # Get sync status
      %{registries: [...], last_sync: %{}, errors: %{}} = RegistrySync.get_status()

      # Query ETS cache
      :ets.lookup(:registry_model_cache, {"huggingface", "meta-llama/Llama-2-7b"})
  """

  use GenServer
  require Logger

  alias TamanduaServer.Registries.HuggingFace

  defstruct [
    :sync_interval_ms,
    :registries,
    :last_sync,
    :sync_errors,
    :sync_in_progress
  ]

  @default_interval_ms 3_600_000  # 1 hour
  @initial_delay_ms 5_000          # 5 seconds after boot

  # Client API

  @doc """
  Starts the RegistrySync GenServer.

  ## Options

  - `:sync_interval_ms` - Sync interval in milliseconds (default: 1 hour)
  - `:registries` - List of {registry_module, config} tuples
  - `:name` - GenServer name (default: __MODULE__)
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Triggers immediate sync for a specific registry.

  ## Parameters

  - `registry` - Registry name atom (`:huggingface`, `:mlflow`, `:wandb`, `:ollama`)

  ## Returns

  - `:ok` - Sync initiated
  - `{:error, :unknown_registry}` - Registry not configured
  """
  @spec sync_now(atom()) :: :ok | {:error, :unknown_registry}
  def sync_now(registry) when is_atom(registry) do
    GenServer.call(__MODULE__, {:sync_now, registry})
  end

  @doc """
  Gets the current sync status.

  Returns a map with:
  - `:registries` - List of configured registry names
  - `:last_sync` - Map of registry_name => DateTime.t()
  - `:errors` - Map of registry_name => {error, DateTime.t()}
  """
  @spec get_status() :: map()
  def get_status do
    GenServer.call(__MODULE__, :get_status)
  end

  # Server Callbacks

  @impl true
  def init(opts) do
    sync_interval_ms = Keyword.get(opts, :sync_interval_ms, @default_interval_ms)

    # Get registries from opts or application config
    registries =
      Keyword.get(opts, :registries) ||
        Application.get_env(:tamandua_server, __MODULE__, [])
        |> Keyword.get(:registries, default_registries())

    state = %__MODULE__{
      sync_interval_ms: sync_interval_ms,
      registries: registries,
      last_sync: %{},
      sync_errors: %{},
      sync_in_progress: false
    }

    # Create ETS table for model cache
    create_ets_cache()

    # Schedule first sync after initial delay
    schedule_sync(@initial_delay_ms)

    Logger.info("RegistrySync started with #{length(registries)} registries, interval: #{sync_interval_ms}ms")

    {:ok, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      registries: Enum.map(state.registries, fn {mod, _config} -> registry_module_to_name(mod) end),
      last_sync: state.last_sync,
      errors: state.sync_errors,
      sync_in_progress: state.sync_in_progress
    }

    {:reply, status, state}
  end

  @impl true
  def handle_call({:sync_now, registry}, _from, state) do
    registry_name = Atom.to_string(registry)

    case find_registry(state.registries, registry_name) do
      nil ->
        {:reply, {:error, :unknown_registry}, state}

      {registry_module, config} ->
        # Perform sync synchronously for this registry
        new_state = sync_single_registry(state, registry_name, registry_module, config)
        {:reply, :ok, new_state}
    end
  end

  @impl true
  def handle_info(:sync, state) do
    Logger.debug("RegistrySync: Starting scheduled sync")

    # Mark sync in progress
    state = %{state | sync_in_progress: true}

    # Sync all registries
    new_state = sync_all_registries(state)

    # Schedule next sync
    schedule_sync(state.sync_interval_ms)

    # Mark sync complete
    new_state = %{new_state | sync_in_progress: false}

    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp create_ets_cache do
    # Create ETS table if it doesn't exist
    case :ets.whereis(:registry_model_cache) do
      :undefined ->
        :ets.new(:registry_model_cache, [
          :set,
          :public,
          :named_table,
          read_concurrency: true,
          write_concurrency: true
        ])

      _ref ->
        :ok
    end
  end

  defp schedule_sync(delay_ms) do
    Process.send_after(self(), :sync, delay_ms)
  end

  defp sync_all_registries(state) do
    Enum.reduce(state.registries, state, fn {registry_module, config}, acc_state ->
      registry_name = registry_module_to_name(registry_module)
      sync_single_registry(acc_state, registry_name, registry_module, config)
    end)
  end

  defp sync_single_registry(state, registry_name, registry_module, config) do
    Logger.debug("Syncing registry: #{registry_name}")

    case registry_module.list_models(config) do
      {:ok, models} ->
        # Update ETS cache
        update_cache(registry_name, models)

        # Record successful sync
        new_last_sync = Map.put(state.last_sync, registry_name, DateTime.utc_now())
        new_errors = Map.delete(state.sync_errors, registry_name)

        Logger.info("Successfully synced #{length(models)} models from #{registry_name}")

        %{state | last_sync: new_last_sync, sync_errors: new_errors}

      {:error, reason} ->
        # Record error
        error_entry = {reason, DateTime.utc_now()}
        new_errors = Map.put(state.sync_errors, registry_name, error_entry)

        Logger.error("Failed to sync #{registry_name}: #{inspect(reason)}")

        %{state | sync_errors: new_errors}
    end
  rescue
    error ->
      Logger.error("Exception during #{registry_name} sync: #{inspect(error)}")

      error_entry = {error, DateTime.utc_now()}
      new_errors = Map.put(state.sync_errors, registry_name, error_entry)

      %{state | sync_errors: new_errors}
  end

  defp update_cache(registry_name, models) when is_list(models) do
    # Delete old entries for this registry
    :ets.match_delete(:registry_model_cache, {{registry_name, :_}, :_})

    # Insert new entries
    entries =
      Enum.map(models, fn model ->
        key = {registry_name, model.id}
        {key, model}
      end)

    :ets.insert(:registry_model_cache, entries)

    Logger.debug("Updated ETS cache with #{length(entries)} models from #{registry_name}")
  end

  defp find_registry(registries, registry_name) do
    Enum.find(registries, fn {module, _config} ->
      registry_module_to_name(module) == registry_name
    end)
  end

  defp registry_module_to_name(TamanduaServer.Registries.HuggingFace), do: "huggingface"
  defp registry_module_to_name(TamanduaServer.Registries.MLflow), do: "mlflow"
  defp registry_module_to_name(TamanduaServer.Registries.WandB), do: "wandb"
  defp registry_module_to_name(TamanduaServer.Registries.Ollama), do: "ollama"

  defp registry_module_to_name(module) do
    module
    |> to_string()
    |> String.split(".")
    |> List.last()
    |> String.downcase()
  end

  defp default_registries do
    [
      {HuggingFace, %{limit: 100}}
    ]
  end
end
