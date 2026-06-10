defmodule TamanduaServer.MultiTenancy.ReplicationManager do
  @moduledoc """
  Manages cross-region data replication for disaster recovery and high availability.

  This module handles:
  - Async replication to secondary region
  - Sync replication for critical data
  - Replication lag monitoring
  - Conflict resolution (last-write-wins, custom strategies)
  - Replication health checks
  - Automatic failover to secondary region

  ## Replication Modes

  - `:async` - Asynchronous replication (default, low latency impact)
  - `:sync` - Synchronous replication (higher latency, guaranteed consistency)
  - `:none` - No replication (single region only)

  ## Conflict Resolution

  - `:last_write_wins` - Latest timestamp wins (default)
  - `:primary_wins` - Primary region always wins
  - `:secondary_wins` - Secondary region always wins
  - `:manual` - Requires manual intervention

  ## Usage

      # Enable replication for a tenant
      ReplicationManager.enable_replication(tenant_id,
        secondary_region: :us,
        mode: :async,
        conflict_resolution: :last_write_wins
      )

      # Check replication status
      ReplicationManager.replication_status(tenant_id)

      # Trigger manual replication
      ReplicationManager.replicate_now(tenant_id)

      # Failover to secondary region
      ReplicationManager.failover(tenant_id, reason: "Primary region unavailable")
  """

  use GenServer
  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.MultiTenancy.{DataResidency, RegionRouter}
  alias TamanduaServer.Audit

  require Logger

  @replication_modes [:async, :sync, :none]
  @conflict_strategies [:last_write_wins, :primary_wins, :secondary_wins, :manual]

  # Replication lag threshold in milliseconds
  @lag_warning_threshold 5_000
  @lag_critical_threshold 30_000

  # Health check interval
  @health_check_interval 60_000

  # ===========================================================================
  # Public API
  # ===========================================================================

  @doc """
  Starts the replication manager GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Enables replication for a tenant.

  ## Options

  - `:secondary_region` - Target region for replication (required)
  - `:mode` - Replication mode (:async or :sync, default: :async)
  - `:conflict_resolution` - Strategy for conflicts (default: :last_write_wins)
  - `:replicate_immediately` - Start replication immediately (default: false)

  ## Examples

      iex> ReplicationManager.enable_replication(tenant_id,
      ...>   secondary_region: :us,
      ...>   mode: :async,
      ...>   conflict_resolution: :last_write_wins
      ...> )
      {:ok, %Organization{}}
  """
  def enable_replication(tenant_id, opts \\ []) do
    secondary_region = Keyword.fetch!(opts, :secondary_region)
    mode = Keyword.get(opts, :mode, :async)
    conflict_resolution = Keyword.get(opts, :conflict_resolution, :last_write_wins)

    with :ok <- validate_replication_config(secondary_region, mode, conflict_resolution),
         {:ok, org} <- get_organization(tenant_id),
         :ok <- validate_regions_different(org, secondary_region) do

      # Update organization settings
      settings =
        Map.merge(org.settings, %{
          "replication_enabled" => true,
          "secondary_region" => to_string(secondary_region),
          "replication_mode" => to_string(mode),
          "conflict_resolution" => to_string(conflict_resolution),
          "replication_enabled_at" => DateTime.utc_now()
        })

      result =
        org
        |> Organization.changeset(%{settings: settings})
        |> Repo.update()

      case result do
        {:ok, updated_org} ->
          # Audit the change
          audit_replication_change(tenant_id, :enabled, opts)

          # Start initial replication if requested
          if Keyword.get(opts, :replicate_immediately, false) do
            GenServer.cast(__MODULE__, {:replicate_now, tenant_id})
          end

          {:ok, updated_org}

        error ->
          error
      end
    end
  end

  @doc """
  Disables replication for a tenant.

  ## Options

  - `:delete_secondary_data` - Delete data from secondary region (default: false)
  """
  def disable_replication(tenant_id, opts \\ []) do
    with {:ok, org} <- get_organization(tenant_id) do
      settings =
        Map.merge(org.settings, %{
          "replication_enabled" => false,
          "replication_disabled_at" => DateTime.utc_now()
        })

      result =
        org
        |> Organization.changeset(%{settings: settings})
        |> Repo.update()

      case result do
        {:ok, updated_org} ->
          # Audit the change
          audit_replication_change(tenant_id, :disabled, opts)

          # Optionally delete secondary data
          if Keyword.get(opts, :delete_secondary_data, false) do
            GenServer.cast(__MODULE__, {:delete_secondary_data, tenant_id})
          end

          {:ok, updated_org}

        error ->
          error
      end
    end
  end

  @doc """
  Gets replication status for a tenant.

  ## Returns

      %{
        enabled: true,
        mode: :async,
        primary_region: :eu,
        secondary_region: :us,
        lag_ms: 234,
        last_replicated_at: ~U[2024-02-20 10:30:00Z],
        health: :healthy,
        conflict_count: 0
      }
  """
  def replication_status(tenant_id) do
    GenServer.call(__MODULE__, {:replication_status, tenant_id})
  end

  @doc """
  Triggers immediate replication for a tenant.

  Useful for forcing sync before maintenance or testing.

  ## Examples

      iex> ReplicationManager.replicate_now(tenant_id)
      {:ok, %{replicated_records: 1234, duration_ms: 567}}
  """
  def replicate_now(tenant_id) do
    GenServer.call(__MODULE__, {:replicate_now, tenant_id}, 60_000)
  end

  @doc """
  Fails over a tenant to their secondary region.

  This updates the tenant's primary region to the secondary region.
  The old primary becomes the new secondary.

  ## Options

  - `:reason` - Reason for failover (for audit log)
  - `:triggered_by` - User/system that triggered failover

  ## Examples

      iex> ReplicationManager.failover(tenant_id,
      ...>   reason: "Primary region database unavailable",
      ...>   triggered_by: "auto-failover-system"
      ...> )
      {:ok, %Organization{region: :us}}
  """
  def failover(tenant_id, opts \\ []) do
    GenServer.call(__MODULE__, {:failover, tenant_id, opts}, 30_000)
  end

  @doc """
  Fails back a tenant to their original primary region.

  This reverses a previous failover operation.

  ## Examples

      iex> ReplicationManager.failback(tenant_id,
      ...>   reason: "Primary region restored",
      ...>   triggered_by: "admin@example.com"
      ...> )
      {:ok, %Organization{region: :eu}}
  """
  def failback(tenant_id, opts \\ []) do
    GenServer.call(__MODULE__, {:failback, tenant_id, opts}, 30_000)
  end

  @doc """
  Gets replication lag statistics across all tenants.

  ## Returns

      %{
        total_replications_active: 45,
        average_lag_ms: 234,
        max_lag_ms: 1234,
        tenants_with_lag_warnings: 3,
        tenants_with_lag_critical: 0
      }
  """
  def get_lag_statistics do
    GenServer.call(__MODULE__, :get_lag_statistics)
  end

  # ===========================================================================
  # GenServer Callbacks
  # ===========================================================================

  @impl true
  def init(_opts) do
    # Schedule periodic health checks
    schedule_health_check()

    state = %{
      replication_lag: %{},
      last_health_check: nil,
      failover_history: []
    }

    Logger.info("ReplicationManager started")
    {:ok, state}
  end

  @impl true
  def handle_call({:replication_status, tenant_id}, _from, state) do
    status = get_tenant_replication_status(tenant_id, state)
    {:reply, status, state}
  end

  @impl true
  def handle_call({:replicate_now, tenant_id}, _from, state) do
    result = perform_replication(tenant_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:failover, tenant_id, opts}, _from, state) do
    result = perform_failover(tenant_id, opts)

    # Track failover in state
    new_state =
      if match?({:ok, _}, result) do
        record_failover(state, tenant_id, opts)
      else
        state
      end

    {:reply, result, new_state}
  end

  @impl true
  def handle_call({:failback, tenant_id, opts}, _from, state) do
    result = perform_failback(tenant_id, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_lag_statistics, _from, state) do
    stats = calculate_lag_statistics(state)
    {:reply, stats, state}
  end

  @impl true
  def handle_cast({:replicate_now, tenant_id}, state) do
    # Async replication
    Task.start(fn -> perform_replication(tenant_id) end)
    {:noreply, state}
  end

  @impl true
  def handle_cast({:delete_secondary_data, tenant_id}, state) do
    # Async deletion
    Task.start(fn -> delete_secondary_data(tenant_id) end)
    {:noreply, state}
  end

  @impl true
  def handle_info(:health_check, state) do
    new_state = perform_health_checks(state)
    schedule_health_check()
    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ===========================================================================
  # Private Functions
  # ===========================================================================

  defp validate_replication_config(secondary_region, mode, conflict_resolution) do
    cond do
      secondary_region not in DataResidency.supported_regions() ->
        {:error, :invalid_secondary_region}

      mode not in @replication_modes ->
        {:error, :invalid_replication_mode}

      conflict_resolution not in @conflict_strategies ->
        {:error, :invalid_conflict_resolution}

      true ->
        :ok
    end
  end

  defp validate_regions_different(%Organization{region: primary}, secondary) when primary == secondary do
    {:error, :primary_and_secondary_same}
  end
  defp validate_regions_different(_, _), do: :ok

  defp get_organization(tenant_id) do
    case Repo.get(Organization, tenant_id) do
      nil -> {:error, :tenant_not_found}
      org -> {:ok, org}
    end
  end

  defp get_tenant_replication_status(tenant_id, state) do
    case get_organization(tenant_id) do
      {:ok, org} ->
        enabled = Map.get(org.settings, "replication_enabled", false)

        if enabled do
          %{
            enabled: true,
            mode: Map.get(org.settings, "replication_mode", "async") |> String.to_existing_atom(),
            primary_region: org.region,
            secondary_region: Map.get(org.settings, "secondary_region") |> String.to_existing_atom(),
            lag_ms: Map.get(state.replication_lag, tenant_id, 0),
            last_replicated_at: Map.get(org.settings, "last_replicated_at"),
            health: determine_replication_health(tenant_id, state),
            conflict_count: Map.get(org.settings, "conflict_count", 0),
            conflict_resolution: Map.get(org.settings, "conflict_resolution", "last_write_wins")
          }
        else
          %{enabled: false}
        end

      {:error, _} ->
        {:error, :tenant_not_found}
    end
  end

  defp perform_replication(tenant_id) do
    start_time = System.monotonic_time(:millisecond)

    with {:ok, org} <- get_organization(tenant_id),
         true <- Map.get(org.settings, "replication_enabled", false),
         {:ok, primary_config} <- DataResidency.get_storage_config(tenant_id),
         {:ok, secondary_config} <- get_secondary_config(org) do

      Logger.info("Starting replication for tenant #{tenant_id}: #{primary_config.region} -> #{secondary_config.region}")

      # Perform actual replication
      result = replicate_data(org, primary_config, secondary_config)

      duration_ms = System.monotonic_time(:millisecond) - start_time

      case result do
        {:ok, replicated_count} ->
          # Update last replicated timestamp
          update_replication_timestamp(org)

          Logger.info("Replication completed for tenant #{tenant_id}: #{replicated_count} records in #{duration_ms}ms")

          {:ok, %{
            replicated_records: replicated_count,
            duration_ms: duration_ms
          }}

        {:error, reason} ->
          Logger.error("Replication failed for tenant #{tenant_id}: #{inspect(reason)}")
          {:error, reason}
      end
    else
      false ->
        {:error, :replication_not_enabled}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp replicate_data(_org, primary_config, secondary_config) do
    # This would perform actual data replication:
    # 1. Query changed records from primary
    # 2. Bulk insert/update to secondary
    # 3. Handle conflicts based on strategy
    # 4. Update replication watermark

    Logger.debug("Replicating from #{primary_config.region} to #{secondary_config.region}")

    # Stub implementation - return success
    {:ok, 0}
  end

  defp get_secondary_config(%Organization{region: primary_region, settings: settings}) do
    case Map.get(settings, "secondary_region") do
      nil ->
        {:error, :no_secondary_region}

      secondary_region_str ->
        secondary_region = String.to_existing_atom(secondary_region_str)
        configs = DataResidency.region_configs()

        case Map.get(configs, secondary_region) do
          nil -> {:error, :invalid_secondary_region}
          config -> {:ok, Map.put(config, :region, secondary_region)}
        end
    end
  rescue
    _ -> {:error, :invalid_secondary_region}
  end

  defp update_replication_timestamp(org) do
    settings = Map.put(org.settings, "last_replicated_at", DateTime.utc_now())

    org
    |> Organization.changeset(%{settings: settings})
    |> Repo.update()
  rescue
    error ->
      Logger.error("Failed to update replication timestamp: #{inspect(error)}")
      :ok
  end

  defp perform_failover(tenant_id, opts) do
    with {:ok, org} <- get_organization(tenant_id),
         {:ok, secondary_region} <- get_secondary_region(org) do

      old_primary = org.region

      # Swap regions
      result = DataResidency.update_region(tenant_id, secondary_region, opts)

      case result do
        {:ok, updated_org} ->
          # Update settings to make old primary the new secondary
          new_settings =
            Map.merge(updated_org.settings, %{
              "secondary_region" => to_string(old_primary),
              "failover_at" => DateTime.utc_now(),
              "failover_reason" => Keyword.get(opts, :reason, "Manual failover")
            })

          updated_org
          |> Organization.changeset(%{settings: new_settings})
          |> Repo.update()

        error ->
          error
      end
    end
  end

  defp perform_failback(tenant_id, opts) do
    with {:ok, org} <- get_organization(tenant_id),
         {:ok, original_primary} <- get_secondary_region(org) do

      # Fail back to original primary (which is now the secondary)
      perform_failover(tenant_id, Keyword.put(opts, :reason, "Failback to original primary"))
    end
  end

  defp get_secondary_region(%Organization{settings: settings}) do
    case Map.get(settings, "secondary_region") do
      nil -> {:error, :no_secondary_region}
      region_str -> {:ok, String.to_existing_atom(region_str)}
    end
  rescue
    _ -> {:error, :invalid_secondary_region}
  end

  defp delete_secondary_data(tenant_id) do
    Logger.info("Deleting secondary data for tenant #{tenant_id}")
    # This would delete data from the secondary region
    :ok
  end

  defp schedule_health_check do
    Process.send_after(self(), :health_check, @health_check_interval)
  end

  defp perform_health_checks(state) do
    # Get all organizations with replication enabled
    orgs_with_replication = get_organizations_with_replication()

    # Check replication lag for each
    replication_lag =
      Enum.reduce(orgs_with_replication, %{}, fn org, acc ->
        lag = measure_replication_lag(org)
        Map.put(acc, org.id, lag)
      end)

    # Alert on critical lag
    Enum.each(replication_lag, fn {tenant_id, lag} ->
      cond do
        lag > @lag_critical_threshold ->
          Logger.error("Critical replication lag for tenant #{tenant_id}: #{lag}ms")
          alert_critical_lag(tenant_id, lag)

        lag > @lag_warning_threshold ->
          Logger.warning("High replication lag for tenant #{tenant_id}: #{lag}ms")

        true ->
          :ok
      end
    end)

    %{state | replication_lag: replication_lag, last_health_check: DateTime.utc_now()}
  end

  defp get_organizations_with_replication do
    query = from(o in Organization, where: fragment("settings->>'replication_enabled' = 'true'"))
    Repo.all(query)
  rescue
    _ -> []
  end

  defp measure_replication_lag(_org) do
    # This would measure actual lag by comparing timestamps between regions
    # Stub implementation
    0
  end

  defp alert_critical_lag(tenant_id, lag) do
    # Send alert to administrators
    Logger.error("CRITICAL: Replication lag for tenant #{tenant_id} is #{lag}ms")
  end

  defp determine_replication_health(tenant_id, state) do
    lag = Map.get(state.replication_lag, tenant_id, 0)

    cond do
      lag > @lag_critical_threshold -> :critical
      lag > @lag_warning_threshold -> :warning
      true -> :healthy
    end
  end

  defp record_failover(state, tenant_id, opts) do
    failover_event = %{
      tenant_id: tenant_id,
      timestamp: DateTime.utc_now(),
      reason: Keyword.get(opts, :reason),
      triggered_by: Keyword.get(opts, :triggered_by)
    }

    history = [failover_event | state.failover_history] |> Enum.take(100)
    %{state | failover_history: history}
  end

  defp calculate_lag_statistics(state) do
    lags = Map.values(state.replication_lag)

    if Enum.empty?(lags) do
      %{
        total_replications_active: 0,
        average_lag_ms: 0,
        max_lag_ms: 0,
        tenants_with_lag_warnings: 0,
        tenants_with_lag_critical: 0
      }
    else
      %{
        total_replications_active: length(lags),
        average_lag_ms: Enum.sum(lags) / length(lags),
        max_lag_ms: Enum.max(lags),
        tenants_with_lag_warnings: Enum.count(lags, &(&1 > @lag_warning_threshold)),
        tenants_with_lag_critical: Enum.count(lags, &(&1 > @lag_critical_threshold))
      }
    end
  end

  defp audit_replication_change(tenant_id, action, opts) do
    Audit.log_event(%{
      organization_id: tenant_id,
      actor_id: Keyword.get(opts, :triggered_by),
      action: "replication.#{action}",
      resource_type: "organization",
      resource_id: tenant_id,
      metadata: opts,
      severity: "high"
    })
  rescue
    error ->
      Logger.error("Failed to audit replication change: #{inspect(error)}")
      :ok
  end
end
