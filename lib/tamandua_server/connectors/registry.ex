defmodule TamanduaServer.Connectors.Registry do
  @moduledoc """
  Registry for dynamically loaded connectors.

  Manages connector lifecycle:
  - Discovery and registration
  - Version compatibility checks
  - Instance lifecycle (init, start, stop)
  - Health monitoring
  """

  use GenServer
  require Logger

  alias TamanduaServer.Connectors.Behaviour

  @registry_table :connector_registry
  @instance_table :connector_instances

  defmodule ConnectorInfo do
    @moduledoc "Connector metadata and state"
    defstruct [
      :module,
      :metadata,
      :config,
      :state,
      :pid,
      :status,
      :health,
      :registered_at,
      :started_at,
      :stats
    ]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Register a connector module.

  ## Example:
      Registry.register(MyApp.MISPConnector)
  """
  def register(module) when is_atom(module) do
    GenServer.call(__MODULE__, {:register, module})
  end

  @doc """
  Unregister a connector.
  """
  def unregister(name) when is_binary(name) do
    GenServer.call(__MODULE__, {:unregister, name})
  end

  @doc """
  Start a connector instance with configuration.

  ## Example:
      Registry.start_connector("misp", %{
        url: "https://misp.example.com",
        api_key: "secret"
      })
  """
  def start_connector(name, config) when is_binary(name) do
    GenServer.call(__MODULE__, {:start_connector, name, config}, 30_000)
  end

  @doc """
  Stop a running connector instance.
  """
  def stop_connector(name) when is_binary(name) do
    GenServer.call(__MODULE__, {:stop_connector, name})
  end

  @doc """
  Get health status for a connector.
  """
  def health(name) when is_binary(name) do
    GenServer.call(__MODULE__, {:health, name})
  end

  @doc """
  List all registered connectors.
  """
  def list_connectors do
    GenServer.call(__MODULE__, :list_connectors)
  end

  @doc """
  List running connector instances.
  """
  def list_instances do
    GenServer.call(__MODULE__, :list_instances)
  end

  @doc """
  Get connector info by name.
  """
  def get_connector(name) when is_binary(name) do
    case :ets.lookup(@instance_table, name) do
      [{^name, info}] -> {:ok, info}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Route an event to a connector.
  """
  def route_event(name, event, direction \\ :inbound) do
    GenServer.call(__MODULE__, {:route_event, name, event, direction}, 30_000)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Create ETS tables for registry and instances
    :ets.new(@registry_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@instance_table, [:named_table, :set, :public, read_concurrency: true])

    Logger.info("[Connectors.Registry] Started connector registry")

    # Auto-discover built-in connectors
    discover_connectors()

    {:ok, %{}}
  end

  @impl true
  def handle_call({:register, module}, _from, state) do
    case validate_and_register(module) do
      {:ok, metadata} ->
        Logger.info("[Connectors.Registry] Registered connector: #{metadata.name} v#{metadata.version}")
        {:reply, {:ok, metadata}, state}

      {:error, reason} = error ->
        Logger.error("[Connectors.Registry] Failed to register #{inspect(module)}: #{inspect(reason)}")
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:unregister, name}, _from, state) do
    case :ets.lookup(@registry_table, name) do
      [{^name, _}] ->
        # Stop instance if running
        stop_instance(name)
        :ets.delete(@registry_table, name)
        Logger.info("[Connectors.Registry] Unregistered connector: #{name}")
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:start_connector, name, config}, _from, state) do
    case :ets.lookup(@registry_table, name) do
      [{^name, module}] ->
        result = start_instance(name, module, config)
        {:reply, result, state}

      [] ->
        {:reply, {:error, :connector_not_registered}, state}
    end
  end

  @impl true
  def handle_call({:stop_connector, name}, _from, state) do
    result = stop_instance(name)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:health, name}, _from, state) do
    case :ets.lookup(@instance_table, name) do
      [{^name, info}] ->
        module = info.module
        connector_state = info.state

        case module.health(connector_state) do
          {:ok, health_data} ->
            # Update health in ETS
            updated_info = %{info | health: health_data}
            :ets.insert(@instance_table, {name, updated_info})
            {:reply, {:ok, health_data}, state}

          {:error, _reason} = error ->
            {:reply, error, state}
        end

      [] ->
        {:reply, {:error, :not_running}, state}
    end
  end

  @impl true
  def handle_call(:list_connectors, _from, state) do
    connectors = :ets.tab2list(@registry_table)
    |> Enum.map(fn {name, module} ->
      metadata = module.metadata()
      %{name: name, module: module, metadata: metadata}
    end)

    {:reply, connectors, state}
  end

  @impl true
  def handle_call(:list_instances, _from, state) do
    instances = :ets.tab2list(@instance_table)
    |> Enum.map(fn {name, info} ->
      %{
        name: name,
        status: info.status,
        metadata: info.metadata,
        health: info.health,
        started_at: info.started_at,
        stats: info.stats
      }
    end)

    {:reply, instances, state}
  end

  @impl true
  def handle_call({:route_event, name, event, direction}, _from, state) do
    case :ets.lookup(@instance_table, name) do
      [{^name, info}] ->
        module = info.module
        connector_state = info.state

        result = case direction do
          :inbound ->
            transformed = module.transform_inbound(event)
            module.handle_inbound(transformed, connector_state)

          :outbound ->
            transformed = module.transform_outbound(event)
            module.handle_outbound(transformed, connector_state)
        end

        # Update stats
        stats = Map.update(info.stats, :"#{direction}_count", 1, &(&1 + 1))
        updated_info = %{info | stats: stats}
        :ets.insert(@instance_table, {name, updated_info})

        {:reply, result, state}

      [] ->
        {:reply, {:error, :connector_not_running}, state}
    end
  end

  # Private Functions

  defp validate_and_register(module) do
    with :ok <- ensure_loaded(module),
         :ok <- validate_behaviour(module),
         metadata <- module.metadata(),
         :ok <- validate_metadata(metadata) do

      name = metadata.name
      :ets.insert(@registry_table, {name, module})
      {:ok, metadata}
    end
  end

  defp ensure_loaded(module) do
    case Code.ensure_loaded?(module) do
      true -> :ok
      false -> {:error, :module_not_found}
    end
  end

  defp validate_behaviour(module) do
    behaviours = module.__info__(:attributes)
    |> Keyword.get_values(:behaviour)
    |> List.flatten()

    if Behaviour in behaviours do
      :ok
    else
      {:error, :invalid_behaviour}
    end
  end

  defp validate_metadata(metadata) do
    required_keys = [:name, :version, :type, :description]

    missing = Enum.filter(required_keys, fn key ->
      not Map.has_key?(metadata, key)
    end)

    if Enum.empty?(missing) do
      :ok
    else
      {:error, {:missing_metadata, missing}}
    end
  end

  defp start_instance(name, module, config) do
    # Check if already running
    case :ets.lookup(@instance_table, name) do
      [{^name, %{status: :running}}] ->
        {:error, :already_running}

      _ ->
        # Validate config
        case module.validate_config(config) do
          :ok ->
            do_start_instance(name, module, config)

          {:error, _} = error ->
            error
        end
    end
  end

  defp do_start_instance(name, module, config) do
    try do
      metadata = module.metadata()

      with {:ok, connector_state} <- module.init(config),
           :ok <- module.start(connector_state) do

        info = %ConnectorInfo{
          module: module,
          metadata: metadata,
          config: sanitize_config(config),
          state: connector_state,
          status: :running,
          registered_at: DateTime.utc_now(),
          started_at: DateTime.utc_now(),
          stats: %{inbound_count: 0, outbound_count: 0}
        }

        :ets.insert(@instance_table, {name, info})
        Logger.info("[Connectors.Registry] Started connector instance: #{name}")
        {:ok, info}
      end
    rescue
      e ->
        Logger.error("[Connectors.Registry] Failed to start #{name}: #{Exception.message(e)}")
        {:error, {:start_failed, Exception.message(e)}}
    end
  end

  defp stop_instance(name) do
    case :ets.lookup(@instance_table, name) do
      [{^name, info}] ->
        module = info.module
        connector_state = info.state

        :ok = module.stop(connector_state)
        :ets.delete(@instance_table, name)

        Logger.info("[Connectors.Registry] Stopped connector instance: #{name}")
        :ok

      [] ->
        {:error, :not_running}
    end
  end

  defp sanitize_config(config) do
    # Remove sensitive keys from stored config
    sensitive_keys = [:api_key, :password, :secret, :token, :private_key]

    Enum.reduce(sensitive_keys, config, fn key, acc ->
      if Map.has_key?(acc, key) do
        Map.put(acc, key, "[REDACTED]")
      else
        acc
      end
    end)
  end

  defp discover_connectors do
    # Auto-discover built-in connectors
    # Note: Called directly from init, so use validate_and_register instead of
    # the GenServer.call to avoid self-call deadlock
    connectors = [
      TamanduaServer.Connectors.MISP,
      TamanduaServer.Connectors.TheHive,
      TamanduaServer.Connectors.CrowdStrike,
      TamanduaServer.Connectors.VirusTotal
    ]

    Enum.each(connectors, fn module ->
      if Code.ensure_loaded?(module) do
        case validate_and_register(module) do
          {:ok, metadata} ->
            Logger.info("[Connectors.Registry] Auto-registered connector: #{metadata.name} v#{metadata.version}")
          {:error, reason} ->
            Logger.warning("[Connectors.Registry] Failed to auto-register #{inspect(module)}: #{inspect(reason)}")
        end
      end
    end)
  end
end
