defmodule TamanduaServer.UBA.AnomalyDetector do
  @moduledoc """
  Detects behavioral anomalies using statistical analysis and ML models.

  Detects:
  - Statistical outliers (>3σ from mean)
  - Unusual login times
  - New locations
  - Excessive data access
  - Privilege creep
  - Application anomalies
  - Behavioral drift
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.UBA.{UserBehavior, UserBaseline, UserAnomaly, BaselineLearner, RiskScorer}
  import Ecto.Query

  # Statistical thresholds
  @outlier_threshold 3.0  # Standard deviations
  @impossible_travel_kmh 1000  # Max travel speed in km/h

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    Logger.info("AnomalyDetector started")

    # Schedule periodic anomaly checks (every 5 minutes)
    schedule_check()

    {:ok, %{}}
  end

  ## Public API

  @doc """
  Checks for anomalies in recent user behavior.
  """
  def check_anomalies(user_id, behavior_type) do
    GenServer.cast(__MODULE__, {:check, user_id, behavior_type})
  end

  @doc """
  Checks all recent behaviors for anomalies.
  """
  def check_all_anomalies do
    GenServer.cast(__MODULE__, :check_all)
  end

  @doc """
  Gets anomalies for a user.
  """
  def get_user_anomalies(user_id, opts \\ []) do
    days = Keyword.get(opts, :days, 7)
    severity = Keyword.get(opts, :severity)

    cutoff = DateTime.utc_now() |> DateTime.add(-days * 24 * 3600, :second)

    query = from(a in UserAnomaly,
      where: a.user_id == ^user_id,
      where: a.timestamp >= ^cutoff,
      order_by: [desc: a.timestamp]
    )

    query = if severity do
      from(a in query, where: a.severity == ^severity)
    else
      query
    end

    Repo.all(query)
  end

  @doc """
  Gets unacknowledged anomalies.
  """
  def get_unacknowledged_anomalies(organization_id) do
    from(a in UserAnomaly,
      where: a.organization_id == ^organization_id,
      where: a.is_acknowledged == false,
      order_by: [desc: a.timestamp]
    )
    |> Repo.all()
  end

  @doc """
  Acknowledges an anomaly.
  """
  def acknowledge_anomaly(anomaly_id, user_id, notes \\ nil) do
    case Repo.get(UserAnomaly, anomaly_id) do
      nil ->
        {:error, :not_found}

      anomaly ->
        anomaly
        |> UserAnomaly.changeset(%{
          is_acknowledged: true,
          acknowledged_by: user_id,
          acknowledged_at: DateTime.utc_now(),
          notes: notes
        })
        |> Repo.update()
    end
  end

  ## GenServer Callbacks

  @impl true
  def handle_cast({:check, user_id, behavior_type}, state) do
    Task.start(fn ->
      check_behavior_anomalies(user_id, behavior_type)
    end)

    {:noreply, state}
  end

  @impl true
  def handle_cast(:check_all, state) do
    Task.start(fn ->
      check_all_anomalies_async()
    end)

    {:noreply, state}
  end

  @impl true
  def handle_info(:check, state) do
    check_all_anomalies()
    schedule_check()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  ## Private Functions

  defp schedule_check do
    # Check every 5 minutes
    Process.send_after(self(), :check, 5 * 60 * 1000)
  end

  defp check_all_anomalies_async do
    Logger.info("Checking for anomalies in recent behaviors...")

    # Check behaviors from last hour
    cutoff = DateTime.utc_now() |> DateTime.add(-60 * 60, :second)

    query = from(b in UserBehavior,
      where: b.timestamp >= ^cutoff,
      select: {b.user_id, b.behavior_type},
      distinct: true
    )

    Repo.all(query)
    |> Enum.each(fn {user_id, behavior_type} ->
      check_behavior_anomalies(user_id, behavior_type)
    end)

    Logger.info("Anomaly check complete")
  end

  defp check_behavior_anomalies(user_id, behavior_type) do
    baseline = BaselineLearner.get_baseline(user_id, behavior_type)

    if baseline && baseline.is_complete do
      # Get recent behaviors (last 24 hours)
      cutoff = DateTime.utc_now() |> DateTime.add(-24 * 3600, :second)

      behaviors = from(b in UserBehavior,
        where: b.user_id == ^user_id,
        where: b.behavior_type == ^behavior_type,
        where: b.timestamp >= ^cutoff,
        order_by: [desc: b.timestamp]
      )
      |> Repo.all()

      Enum.each(behaviors, fn behavior ->
        check_statistical_outlier(behavior, baseline)
        check_time_anomaly(behavior, baseline)
        check_location_anomaly(behavior, baseline)
        check_device_anomaly(behavior, baseline)
      end)

      # Check for behavioral drift
      check_behavioral_drift(user_id, behavior_type, baseline)
    end
  end

  defp check_statistical_outlier(behavior, baseline) do
    if behavior.value && baseline.mean && baseline.stddev && baseline.stddev > 0 do
      z_score = (behavior.value - baseline.mean) / baseline.stddev

      if abs(z_score) > @outlier_threshold do
        severity = cond do
          abs(z_score) > 5 -> "critical"
          abs(z_score) > 4 -> "high"
          abs(z_score) > 3 -> "medium"
          true -> "low"
        end

        create_anomaly(%{
          user_id: behavior.user_id,
          behavior_type: behavior.behavior_type,
          timestamp: behavior.timestamp,
          organization_id: behavior.organization_id,
          anomaly_type: "statistical_outlier",
          severity: severity,
          score: z_score,
          baseline_value: baseline.mean,
          observed_value: behavior.value,
          deviation: z_score,
          metadata: %{
            z_score: z_score,
            stddev: baseline.stddev,
            threshold: @outlier_threshold
          }
        })

        # Update risk score
        RiskScorer.update_risk_score(behavior.user_id)
      end
    end
  end

  defp check_time_anomaly(behavior, baseline) do
    hour = behavior.timestamp.hour
    day_of_week = Date.day_of_week(behavior.timestamp)

    # Check if this is an unusual time based on baseline patterns
    hourly_avg = Map.get(baseline.hourly_pattern, to_string(hour), 0)
    overall_avg = baseline.mean || 0

    if overall_avg > 0 && hourly_avg < overall_avg * 0.1 do
      # This hour is less than 10% of average activity
      create_anomaly(%{
        user_id: behavior.user_id,
        behavior_type: behavior.behavior_type,
        timestamp: behavior.timestamp,
        organization_id: behavior.organization_id,
        anomaly_type: "time_anomaly",
        severity: "medium",
        score: (overall_avg - hourly_avg) / overall_avg,
        baseline_value: hourly_avg,
        observed_value: behavior.value,
        metadata: %{
          hour: hour,
          day_of_week: day_of_week,
          hourly_avg: hourly_avg,
          overall_avg: overall_avg
        }
      })

      RiskScorer.update_risk_score(behavior.user_id)
    end
  end

  defp check_location_anomaly(behavior, baseline) do
    if behavior.location && baseline.common_locations do
      if behavior.location not in baseline.common_locations do
        # New location detected
        severity = if length(baseline.common_locations) > 0 do
          "high"
        else
          "medium"
        end

        create_anomaly(%{
          user_id: behavior.user_id,
          behavior_type: behavior.behavior_type,
          timestamp: behavior.timestamp,
          organization_id: behavior.organization_id,
          anomaly_type: "location_anomaly",
          severity: severity,
          score: 1.0,
          metadata: %{
            new_location: behavior.location,
            known_locations: baseline.common_locations
          }
        })

        # Check for impossible travel
        check_impossible_travel(behavior)

        RiskScorer.update_risk_score(behavior.user_id)
      end
    end
  end

  defp check_device_anomaly(behavior, baseline) do
    if behavior.device && baseline.common_devices do
      if behavior.device not in baseline.common_devices do
        # New device detected
        create_anomaly(%{
          user_id: behavior.user_id,
          behavior_type: behavior.behavior_type,
          timestamp: behavior.timestamp,
          organization_id: behavior.organization_id,
          anomaly_type: "device_anomaly",
          severity: "medium",
          score: 1.0,
          metadata: %{
            new_device: behavior.device,
            known_devices: baseline.common_devices
          }
        })

        RiskScorer.update_risk_score(behavior.user_id)
      end
    end
  end

  defp check_impossible_travel(behavior) do
    if behavior.location do
      # Get previous location within last 2 hours
      cutoff = DateTime.add(behavior.timestamp, -2 * 3600, :second)

      previous_behavior = from(b in UserBehavior,
        where: b.user_id == ^behavior.user_id,
        where: b.timestamp < ^behavior.timestamp,
        where: b.timestamp >= ^cutoff,
        where: not is_nil(b.location),
        where: b.location != ^behavior.location,
        order_by: [desc: b.timestamp],
        limit: 1
      )
      |> Repo.one()

      if previous_behavior do
        time_diff = DateTime.diff(behavior.timestamp, previous_behavior.timestamp, :second)
        # Simplified impossible travel check (would need geo distance calculation in production)
        if time_diff < 30 * 60 do  # Less than 30 minutes
          create_anomaly(%{
            user_id: behavior.user_id,
            behavior_type: "login",
            timestamp: behavior.timestamp,
            organization_id: behavior.organization_id,
            anomaly_type: "impossible_travel",
            severity: "critical",
            score: 1.0,
            metadata: %{
              location_1: previous_behavior.location,
              location_2: behavior.location,
              time_diff_minutes: div(time_diff, 60)
            }
          })

          RiskScorer.update_risk_score(behavior.user_id)
        end
      end
    end
  end

  defp check_behavioral_drift(user_id, behavior_type, baseline) do
    # Get recent average (last 7 days) and compare to baseline
    recent_cutoff = DateTime.utc_now() |> DateTime.add(-7 * 24 * 3600, :second)

    recent_stats = from(b in UserBehavior,
      where: b.user_id == ^user_id,
      where: b.behavior_type == ^behavior_type,
      where: b.timestamp >= ^recent_cutoff,
      where: not is_nil(b.value),
      select: %{
        avg: avg(b.value),
        count: count(b.id)
      }
    )
    |> Repo.one()

    if recent_stats && recent_stats.count > 10 && baseline.mean && baseline.stddev && baseline.stddev > 0 do
      drift = abs(recent_stats.avg - baseline.mean) / baseline.stddev

      if drift > 2.0 do
        # Significant drift detected
        severity = cond do
          drift > 4 -> "high"
          drift > 3 -> "medium"
          true -> "low"
        end

        create_anomaly(%{
          user_id: user_id,
          behavior_type: behavior_type,
          timestamp: DateTime.utc_now(),
          organization_id: baseline.organization_id,
          anomaly_type: "behavioral_drift",
          severity: severity,
          score: drift,
          baseline_value: baseline.mean,
          observed_value: recent_stats.avg,
          deviation: drift,
          metadata: %{
            drift: drift,
            recent_avg: recent_stats.avg,
            baseline_avg: baseline.mean,
            recent_count: recent_stats.count
          }
        })

        RiskScorer.update_risk_score(user_id)
      end
    end
  end

  defp create_anomaly(attrs) do
    # Check if similar anomaly already exists (prevent duplicates)
    recent_cutoff = DateTime.utc_now() |> DateTime.add(-60 * 60, :second)

    existing = from(a in UserAnomaly,
      where: a.user_id == ^attrs.user_id,
      where: a.behavior_type == ^attrs.behavior_type,
      where: a.anomaly_type == ^attrs.anomaly_type,
      where: a.timestamp >= ^recent_cutoff,
      limit: 1
    )
    |> Repo.one()

    if is_nil(existing) do
      case UserAnomaly.changeset(%UserAnomaly{}, attrs) |> Repo.insert() do
        {:ok, anomaly} ->
          Logger.info("Anomaly detected: #{anomaly.anomaly_type} for user #{anomaly.user_id} (severity: #{anomaly.severity})")
          {:ok, anomaly}

        {:error, changeset} ->
          Logger.error("Failed to create anomaly: #{inspect(changeset.errors)}")
          {:error, changeset}
      end
    else
      {:ok, existing}
    end
  end
end
