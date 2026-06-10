defmodule TamanduaServer.ThreatIntel.TaxiiPoller do
  @moduledoc """
  Scheduled TAXII 2.1 collection poller.

  Periodically polls configured TAXII servers for new STIX indicators,
  converts them to internal IOCs, stores in the database, and triggers
  retroactive scanning for historical matches.

  Configuration is read from application env:

      config :tamandua_server, TamanduaServer.ThreatIntel.TaxiiPoller,
        enabled: true,
        poll_interval_minutes: 60,
        servers: [
          %{
            name: "my_taxii_server",
            url: "https://taxii.example.com",
            api_root: "https://taxii.example.com/api/v21",
            collection_id: "collection--uuid",
            auth: %{type: :basic, username: "user", password: "pass"},
            poll_types: ["indicator"],
            enabled: true
          }
        ]
  """

  use GenServer
  require Logger

  alias TamanduaServer.ThreatIntel.StixTaxii

  @ets_table :taxii_poller_state

  # ── Public API ──────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Manually trigger a poll of all configured servers.
  """
  @spec poll_all_now() :: :ok
  def poll_all_now do
    GenServer.cast(__MODULE__, :poll_all)
  end

  @doc """
  Manually trigger a poll of a specific server by name.
  """
  @spec poll_server(String.t()) :: :ok
  def poll_server(server_name) do
    GenServer.cast(__MODULE__, {:poll_server, server_name})
  end

  @doc """
  Get the status of all configured TAXII servers and their poll history.
  """
  @spec get_status() :: map()
  def get_status do
    GenServer.call(__MODULE__, :get_status)
  end

  @doc """
  Add a TAXII server configuration at runtime.
  """
  @spec add_server(map()) :: :ok | {:error, term()}
  def add_server(server_config) do
    GenServer.call(__MODULE__, {:add_server, server_config})
  end

  @doc """
  Remove a TAXII server configuration by name.
  """
  @spec remove_server(String.t()) :: :ok | {:error, :not_found}
  def remove_server(server_name) do
    GenServer.call(__MODULE__, {:remove_server, server_name})
  end

  # ── GenServer Callbacks ─────────────────────────────────────────────

  @impl true
  def init(_opts) do
    :ets.new(@ets_table, [:named_table, :set, :public, read_concurrency: true])

    config = Application.get_env(:tamandua_server, __MODULE__, [])
    enabled = Keyword.get(config, :enabled, false)
    poll_interval_minutes = Keyword.get(config, :poll_interval_minutes, 60)
    poll_interval = :timer.minutes(poll_interval_minutes)
    servers = Keyword.get(config, :servers, [])

    state = %{
      enabled: enabled,
      poll_interval: poll_interval,
      servers: servers,
      stats: %{
        total_polls: 0,
        total_iocs_imported: 0,
        last_poll: nil,
        errors: 0
      }
    }

    # Initialize ETS entries for each server
    Enum.each(servers, fn server ->
      name = server[:name] || server["name"]
      :ets.insert(@ets_table, {name, %{
        last_poll: nil,
        last_added_after: nil,
        iocs_imported: 0,
        status: :pending,
        error: nil
      }})
    end)

    if enabled and length(servers) > 0 do
      Logger.info("[TaxiiPoller] Started with #{length(servers)} server(s), polling every #{poll_interval_minutes}m")
      # Initial poll after 60s startup delay
      Process.send_after(self(), :scheduled_poll, :timer.seconds(60))
    else
      Logger.info("[TaxiiPoller] Disabled or no servers configured")
    end

    {:ok, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    server_statuses = state.servers
    |> Enum.map(fn server ->
      name = server[:name] || server["name"]
      poll_state = case :ets.lookup(@ets_table, name) do
        [{^name, ps}] -> ps
        [] -> %{status: :unknown}
      end
      {name, Map.merge(server, %{poll_state: poll_state})}
    end)
    |> Map.new()

    status = %{
      enabled: state.enabled,
      poll_interval: state.poll_interval,
      server_count: length(state.servers),
      servers: server_statuses,
      stats: state.stats
    }

    {:reply, status, state}
  end

  @impl true
  def handle_call({:add_server, server_config}, _from, state) do
    name = server_config[:name] || server_config["name"]
    if name do
      :ets.insert(@ets_table, {name, %{
        last_poll: nil,
        last_added_after: nil,
        iocs_imported: 0,
        status: :pending,
        error: nil
      }})
      new_servers = state.servers ++ [server_config]
      {:reply, :ok, %{state | servers: new_servers}}
    else
      {:reply, {:error, :missing_name}, state}
    end
  end

  @impl true
  def handle_call({:remove_server, server_name}, _from, state) do
    case Enum.find(state.servers, fn s -> (s[:name] || s["name"]) == server_name end) do
      nil ->
        {:reply, {:error, :not_found}, state}
      _ ->
        :ets.delete(@ets_table, server_name)
        new_servers = Enum.reject(state.servers, fn s -> (s[:name] || s["name"]) == server_name end)
        {:reply, :ok, %{state | servers: new_servers}}
    end
  end

  @impl true
  def handle_cast(:poll_all, state) do
    do_poll_all(state)
    {:noreply, state}
  end

  @impl true
  def handle_cast({:poll_server, server_name}, state) do
    case Enum.find(state.servers, fn s -> (s[:name] || s["name"]) == server_name end) do
      nil -> Logger.warning("[TaxiiPoller] Server not found: #{server_name}")
      server -> do_poll_server(server)
    end
    {:noreply, state}
  end

  @impl true
  def handle_info(:scheduled_poll, state) do
    if state.enabled do
      do_poll_all(state)
      Process.send_after(self(), :scheduled_poll, state.poll_interval)
    end
    {:noreply, update_in(state, [:stats, :total_polls], &(&1 + 1))}
  end

  @impl true
  def handle_info({:poll_result, server_name, result}, state) do
    case result do
      {:ok, summary} ->
        :ets.insert(@ets_table, {server_name, %{
          last_poll: DateTime.utc_now(),
          last_added_after: summary[:last_added_after],
          iocs_imported: summary[:iocs_inserted] || 0,
          status: :ok,
          error: nil
        }})
        new_state = update_in(state, [:stats, :total_iocs_imported], &(&1 + (summary[:iocs_inserted] || 0)))
        new_state = put_in(new_state, [:stats, :last_poll], DateTime.utc_now())
        Logger.info("[TaxiiPoller] #{server_name}: imported #{summary[:iocs_inserted] || 0} IOCs")
        {:noreply, new_state}

      {:error, reason} ->
        :ets.insert(@ets_table, {server_name, %{
          last_poll: DateTime.utc_now(),
          status: :error,
          error: inspect(reason),
          iocs_imported: 0
        }})
        new_state = update_in(state, [:stats, :errors], &(&1 + 1))
        Logger.error("[TaxiiPoller] #{server_name} failed: #{inspect(reason)}")
        {:noreply, new_state}
    end
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ── Private ─────────────────────────────────────────────────────────

  defp do_poll_all(state) do
    parent = self()

    Enum.each(state.servers, fn server ->
      enabled = server[:enabled] || server["enabled"] || true
      if enabled do
        Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
          result = do_poll_server(server)
          name = server[:name] || server["name"]
          send(parent, {:poll_result, name, result})
        end)
      end
    end)
  end

  defp do_poll_server(server) do
    name = server[:name] || server["name"]
    api_root = server[:api_root] || server["api_root"]
    collection_id = server[:collection_id] || server["collection_id"]
    auth = server[:auth] || server["auth"] || %{}

    Logger.info("[TaxiiPoller] Polling #{name}...")

    # Get last_added_after from ETS for incremental polling
    added_after = case :ets.lookup(@ets_table, name) do
      [{^name, %{last_added_after: dt}}] when not is_nil(dt) -> dt
      _ -> nil
    end

    opts = []
    opts = if added_after, do: Keyword.put(opts, :added_after, added_after), else: opts

    case StixTaxii.import_from_collection(api_root, collection_id, auth, opts) do
      {:ok, result} ->
        {:ok, Map.put(result, :last_added_after, DateTime.utc_now())}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("[TaxiiPoller] Error polling #{server[:name]}: #{Exception.message(e)}")
      {:error, Exception.message(e)}
  end
end
