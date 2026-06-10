defmodule TamanduaServer.Integrations.HealthCheckScheduler do
  @moduledoc """
  Periodic Health Check Scheduler

  Automatically runs health checks on all enabled integrations:
  - Every 1 minute: Connectivity checks
  - Every 5 minutes: Authentication validation
  - Every 15 minutes: Synthetic transactions
  - Every 30 minutes: Data sync verification

  Uses Oban for reliable job scheduling and retry logic.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Integrations.{Config, HealthCheck}

  @connectivity_interval :timer.minutes(1)
  @auth_interval :timer.minutes(5)
  @synthetic_interval :timer.minutes(15)
  @sync_interval :timer.minutes(30)

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Manually trigger health checks for all integrations.
  """
  def trigger_all_checks do
    GenServer.cast(__MODULE__, :trigger_all)
  end

  @doc """
  Manually trigger health check for a specific integration.
  """
  def trigger_check(integration_id, check_type \\ :connectivity) do
    GenServer.cast(__MODULE__, {:trigger_check, integration_id, check_type})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Schedule initial checks
    schedule_connectivity_checks()
    schedule_auth_checks()
    schedule_synthetic_checks()
    schedule_sync_checks()

    Logger.info("[HealthCheckScheduler] Started")

    state = %{
      last_connectivity_check: DateTime.utc_now(),
      last_auth_check: DateTime.utc_now(),
      last_synthetic_check: DateTime.utc_now(),
      last_sync_check: DateTime.utc_now()
    }

    {:ok, state}
  end

  @impl true
  def handle_cast(:trigger_all, state) do
    run_all_checks()
    {:noreply, state}
  end

  @impl true
  def handle_cast({:trigger_check, integration_id, check_type}, state) do
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      HealthCheck.perform_health_check(integration_id, check_type)
    end)

    {:noreply, state}
  end

  @impl true
  def handle_info(:connectivity_check, state) do
    run_connectivity_checks()

    schedule_connectivity_checks()
    {:noreply, Map.put(state, :last_connectivity_check, DateTime.utc_now())}
  end

  @impl true
  def handle_info(:auth_check, state) do
    run_auth_checks()

    schedule_auth_checks()
    {:noreply, Map.put(state, :last_auth_check, DateTime.utc_now())}
  end

  @impl true
  def handle_info(:synthetic_check, state) do
    run_synthetic_checks()

    schedule_synthetic_checks()
    {:noreply, Map.put(state, :last_synthetic_check, DateTime.utc_now())}
  end

  @impl true
  def handle_info(:sync_check, state) do
    run_sync_checks()

    schedule_sync_checks()
    {:noreply, Map.put(state, :last_sync_check, DateTime.utc_now())}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp schedule_connectivity_checks do
    Process.send_after(self(), :connectivity_check, @connectivity_interval)
  end

  defp schedule_auth_checks do
    Process.send_after(self(), :auth_check, @auth_interval)
  end

  defp schedule_synthetic_checks do
    Process.send_after(self(), :synthetic_check, @synthetic_interval)
  end

  defp schedule_sync_checks do
    Process.send_after(self(), :sync_check, @sync_interval)
  end

  defp run_all_checks do
    run_connectivity_checks()
    run_auth_checks()
    run_synthetic_checks()
    run_sync_checks()
  end

  defp run_connectivity_checks do
    integrations = Config.list_integrations(enabled: true)

    Enum.each(integrations, fn integration ->
      Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
        HealthCheck.check_connectivity(integration.id)
      end)
    end)

    Logger.debug("[HealthCheckScheduler] Connectivity checks started for #{length(integrations)} integrations")
  end

  defp run_auth_checks do
    integrations = Config.list_integrations(enabled: true)

    Enum.each(integrations, fn integration ->
      Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
        HealthCheck.check_authentication(integration.id)
      end)
    end)

    Logger.debug("[HealthCheckScheduler] Authentication checks started for #{length(integrations)} integrations")
  end

  defp run_synthetic_checks do
    integrations = Config.list_integrations(enabled: true)

    Enum.each(integrations, fn integration ->
      Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
        HealthCheck.check_synthetic_transaction(integration.id)
      end)
    end)

    Logger.debug("[HealthCheckScheduler] Synthetic checks started for #{length(integrations)} integrations")
  end

  defp run_sync_checks do
    integrations = Config.list_integrations(enabled: true)

    Enum.each(integrations, fn integration ->
      Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
        HealthCheck.check_data_sync(integration.id)
      end)
    end)

    Logger.debug("[HealthCheckScheduler] Sync checks started for #{length(integrations)} integrations")
  end
end
