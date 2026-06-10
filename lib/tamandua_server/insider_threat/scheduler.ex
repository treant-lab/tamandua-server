defmodule TamanduaServer.InsiderThreat.Scheduler do
  @moduledoc """
  Scheduled tasks for insider threat detection.
  Runs periodic analysis, baseline calculations, and cleanup.
  """

  use GenServer
  require Logger

  alias TamanduaServer.InsiderThreat
  alias TamanduaServer.Repo

  import Ecto.Query

  @analysis_interval :timer.hours(1)
  @baseline_calculation_interval :timer.hours(24)
  @cleanup_interval :timer.hours(6)

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Trigger immediate analysis for an organization.
  """
  @spec trigger_analysis(Ecto.UUID.t()) :: :ok
  def trigger_analysis(organization_id) do
    GenServer.cast(__MODULE__, {:analyze, organization_id})
  end

  @doc """
  Trigger baseline calculation for an organization.
  """
  @spec trigger_baseline_calculation(Ecto.UUID.t()) :: :ok
  def trigger_baseline_calculation(organization_id) do
    GenServer.cast(__MODULE__, {:calculate_baselines, organization_id})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Schedule periodic tasks
    schedule_analysis()
    schedule_baseline_calculation()
    schedule_cleanup()

    Logger.info("InsiderThreat.Scheduler started")

    {:ok, %{}}
  end

  @impl true
  def handle_info(:run_analysis, state) do
    Logger.info("Running scheduled insider threat analysis")

    # Get all active organizations
    organization_ids = get_active_organizations()

    # Run analysis for each organization
    Enum.each(organization_ids, fn org_id ->
      Task.start(fn ->
        run_analysis_for_organization(org_id)
      end)
    end)

    # Schedule next run
    schedule_analysis()

    {:noreply, state}
  end

  @impl true
  def handle_info(:calculate_baselines, state) do
    Logger.info("Running scheduled baseline calculation")

    organization_ids = get_active_organizations()

    Enum.each(organization_ids, fn org_id ->
      Task.start(fn ->
        calculate_baselines_for_organization(org_id)
      end)
    end)

    schedule_baseline_calculation()

    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    Logger.info("Running insider threat cleanup")

    # Clean up old resolved alerts (older than 90 days)
    cleanup_old_alerts()

    # Clean up old investigation data
    cleanup_old_investigations()

    schedule_cleanup()

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def handle_cast({:analyze, organization_id}, state) do
    Logger.info("Triggering immediate analysis for organization: #{organization_id}")

    Task.start(fn ->
      run_analysis_for_organization(organization_id)
    end)

    {:noreply, state}
  end

  @impl true
  def handle_cast({:calculate_baselines, organization_id}, state) do
    Logger.info("Triggering baseline calculation for organization: #{organization_id}")

    Task.start(fn ->
      calculate_baselines_for_organization(organization_id)
    end)

    {:noreply, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp schedule_analysis do
    Process.send_after(self(), :run_analysis, @analysis_interval)
  end

  defp schedule_baseline_calculation do
    Process.send_after(self(), :calculate_baselines, @baseline_calculation_interval)
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  defp get_active_organizations do
    from(o in "organizations",
      select: o.id
    )
    |> Repo.all()
  end

  defp run_analysis_for_organization(organization_id) do
    case InsiderThreat.run_scheduled_analysis(organization_id) do
      {:ok, result} ->
        Logger.info(
          "Insider threat analysis completed for org #{organization_id}: #{result.users_analyzed} users, #{result.alerts_created} alerts"
        )

      {:error, reason} ->
        Logger.error(
          "Insider threat analysis failed for org #{organization_id}: #{inspect(reason)}"
        )
    end
  rescue
    e ->
      Logger.error(
        "Exception during insider threat analysis for org #{organization_id}: #{Exception.message(e)}"
      )
  end

  defp calculate_baselines_for_organization(organization_id) do
    case InsiderThreat.auto_calculate_baselines(organization_id) do
      {:ok, results} ->
        successful_count = results |> Enum.count(fn {_id, baseline} -> !is_nil(baseline) end)

        Logger.info(
          "Baseline calculation completed for org #{organization_id}: #{successful_count} peer groups"
        )

      {:error, reason} ->
        Logger.error(
          "Baseline calculation failed for org #{organization_id}: #{inspect(reason)}"
        )
    end
  rescue
    e ->
      Logger.error(
        "Exception during baseline calculation for org #{organization_id}: #{Exception.message(e)}"
      )
  end

  defp cleanup_old_alerts do
    ninety_days_ago = DateTime.add(DateTime.utc_now(), -90 * 24 * 3600, :second)

    {count, _} =
      from(a in "insider_threat_alerts",
        where: a.status == "resolved" and a.resolved_at < ^ninety_days_ago
      )
      |> Repo.delete_all()

    if count > 0 do
      Logger.info("Cleaned up #{count} old insider threat alerts")
    end
  end

  defp cleanup_old_investigations do
    one_year_ago = DateTime.add(DateTime.utc_now(), -365 * 24 * 3600, :second)

    {count, _} =
      from(i in "insider_threat_investigations",
        where: i.status == "closed" and i.investigation_completed_at < ^one_year_ago
      )
      |> Repo.delete_all()

    if count > 0 do
      Logger.info("Cleaned up #{count} old insider threat investigations")
    end
  end
end
