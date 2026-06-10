defmodule TamanduaServer.UBA.BaselineLearner do
  @moduledoc """
  Learns behavioral baselines for users over a 30-day period.

  Calculates statistical baselines (mean, stddev, percentiles) and
  identifies patterns by time of day and day of week.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.UBA.{UserBehavior, UserBaseline}
  import Ecto.Query

  # Baseline learning period (30 days)
  @baseline_days 30

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    Logger.info("BaselineLearner started")

    # Schedule periodic baseline updates (every 6 hours)
    schedule_update()

    {:ok, %{}}
  end

  ## Public API

  @doc """
  Updates baseline for a specific user and behavior type.
  """
  def update_baseline(user_id, behavior_type) do
    GenServer.cast(__MODULE__, {:update, user_id, behavior_type})
  end

  @doc """
  Calculates baselines for all users.
  """
  def calculate_all_baselines do
    GenServer.cast(__MODULE__, :calculate_all)
  end

  @doc """
  Gets baseline for a user and behavior type.
  """
  def get_baseline(user_id, behavior_type) do
    Repo.get_by(UserBaseline, user_id: user_id, behavior_type: behavior_type)
  end

  @doc """
  Checks if baseline learning is complete for a user.
  """
  def baseline_complete?(user_id, behavior_type) do
    case get_baseline(user_id, behavior_type) do
      nil -> false
      baseline -> baseline.is_complete
    end
  end

  ## GenServer Callbacks

  @impl true
  def handle_cast({:update, user_id, behavior_type}, state) do
    Task.start(fn ->
      calculate_baseline(user_id, behavior_type)
    end)

    {:noreply, state}
  end

  @impl true
  def handle_cast(:calculate_all, state) do
    Task.start(fn ->
      calculate_all_baselines_async()
    end)

    {:noreply, state}
  end

  @impl true
  def handle_info(:update, state) do
    calculate_all_baselines()
    schedule_update()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  ## Private Functions

  defp schedule_update do
    # Update every 6 hours
    Process.send_after(self(), :update, 6 * 60 * 60 * 1000)
  end

  defp calculate_all_baselines_async do
    Logger.info("Calculating baselines for all users...")

    # Get all unique user/behavior combinations
    query = from(b in UserBehavior,
      select: {b.user_id, b.behavior_type},
      distinct: true
    )

    Repo.all(query)
    |> Enum.each(fn {user_id, behavior_type} ->
      calculate_baseline(user_id, behavior_type)
    end)

    Logger.info("Baseline calculation complete")
  end

  defp calculate_baseline(user_id, behavior_type) do
    now = DateTime.utc_now()
    baseline_start = DateTime.add(now, -@baseline_days * 24 * 3600, :second)

    # Get behavior data for baseline period
    behaviors = from(b in UserBehavior,
      where: b.user_id == ^user_id,
      where: b.behavior_type == ^behavior_type,
      where: b.timestamp >= ^baseline_start,
      where: b.timestamp <= ^now,
      order_by: [asc: b.timestamp]
    )
    |> Repo.all()

    if length(behaviors) < 10 do
      # Not enough data for baseline
      Logger.debug("Insufficient data for baseline: #{behavior_type} for user #{user_id} (#{length(behaviors)} events)")
      nil
    else
      # Calculate statistics
      values = behaviors |> Enum.map(& &1.value) |> Enum.reject(&is_nil/1)

      stats = if length(values) > 0 do
        calculate_statistics(values)
      else
        %{mean: 0, stddev: 0, median: 0, p95: 0, p99: 0, min: 0, max: 0}
      end

      # Calculate time patterns
      hourly_pattern = calculate_hourly_pattern(behaviors)
      daily_pattern = calculate_daily_pattern(behaviors)

      # Get common locations and devices
      common_locations = behaviors
        |> Enum.map(& &1.location)
        |> Enum.reject(&is_nil/1)
        |> Enum.frequencies()
        |> Enum.sort_by(fn {_, count} -> -count end)
        |> Enum.take(10)
        |> Enum.map(fn {loc, _} -> loc end)

      common_devices = behaviors
        |> Enum.map(& &1.device)
        |> Enum.reject(&is_nil/1)
        |> Enum.frequencies()
        |> Enum.sort_by(fn {_, count} -> -count end)
        |> Enum.take(10)
        |> Enum.map(fn {dev, _} -> dev end)

      # Determine if baseline is complete (enough data collected)
      is_complete = length(behaviors) >= 30 and
        DateTime.diff(now, List.first(behaviors).timestamp, :day) >= @baseline_days

      # Create or update baseline
      attrs = %{
        user_id: user_id,
        behavior_type: behavior_type,
        organization_id: get_user_organization(user_id),
        mean: stats.mean,
        stddev: stats.stddev,
        median: stats.median,
        p95: stats.p95,
        p99: stats.p99,
        min: stats.min,
        max: stats.max,
        count: length(behaviors),
        hourly_pattern: hourly_pattern,
        daily_pattern: daily_pattern,
        common_locations: common_locations,
        common_devices: common_devices,
        baseline_start: baseline_start,
        baseline_end: now,
        is_complete: is_complete,
        last_updated: now
      }

      case Repo.get_by(UserBaseline, user_id: user_id, behavior_type: behavior_type) do
        nil ->
          %UserBaseline{}
          |> UserBaseline.changeset(attrs)
          |> Repo.insert()

        baseline ->
          baseline
          |> UserBaseline.changeset(attrs)
          |> Repo.update()
      end
      |> case do
        {:ok, baseline} ->
          Logger.debug("Updated baseline for #{behavior_type} (user #{user_id}): mean=#{Float.round(baseline.mean || 0, 2)}, stddev=#{Float.round(baseline.stddev || 0, 2)}")
          baseline

        {:error, changeset} ->
          Logger.error("Failed to update baseline: #{inspect(changeset.errors)}")
          nil
      end
    end
  end

  defp calculate_statistics(values) when length(values) > 0 do
    sorted = Enum.sort(values)
    count = length(sorted)

    mean = Enum.sum(sorted) / count
    variance = Enum.map(sorted, fn x -> :math.pow(x - mean, 2) end) |> Enum.sum() |> Kernel./(count)
    stddev = :math.sqrt(variance)

    median = percentile(sorted, 0.5)
    p95 = percentile(sorted, 0.95)
    p99 = percentile(sorted, 0.99)
    min = List.first(sorted)
    max = List.last(sorted)

    %{
      mean: mean,
      stddev: stddev,
      median: median,
      p95: p95,
      p99: p99,
      min: min,
      max: max
    }
  end

  defp calculate_statistics([]), do: %{mean: 0, stddev: 0, median: 0, p95: 0, p99: 0, min: 0, max: 0}

  defp percentile(sorted_values, p) do
    count = length(sorted_values)
    index = trunc(p * count)
    index = max(0, min(index, count - 1))
    Enum.at(sorted_values, index)
  end

  defp calculate_hourly_pattern(behaviors) do
    behaviors
    |> Enum.reject(fn b -> is_nil(b.value) end)
    |> Enum.group_by(fn b -> b.timestamp.hour end)
    |> Enum.map(fn {hour, events} ->
      avg_value = events |> Enum.map(& &1.value) |> Enum.sum() |> Kernel./(length(events))
      {to_string(hour), avg_value}
    end)
    |> Map.new()
  end

  defp calculate_daily_pattern(behaviors) do
    behaviors
    |> Enum.reject(fn b -> is_nil(b.value) end)
    |> Enum.group_by(fn b -> Date.day_of_week(b.timestamp) end)
    |> Enum.map(fn {day, events} ->
      avg_value = events |> Enum.map(& &1.value) |> Enum.sum() |> Kernel./(length(events))
      day_name = day_of_week_name(day)
      {day_name, avg_value}
    end)
    |> Map.new()
  end

  defp day_of_week_name(1), do: "Monday"
  defp day_of_week_name(2), do: "Tuesday"
  defp day_of_week_name(3), do: "Wednesday"
  defp day_of_week_name(4), do: "Thursday"
  defp day_of_week_name(5), do: "Friday"
  defp day_of_week_name(6), do: "Saturday"
  defp day_of_week_name(7), do: "Sunday"

  defp get_user_organization(user_id) do
    from(u in TamanduaServer.Accounts.User,
      where: u.id == ^user_id,
      select: u.organization_id
    )
    |> Repo.one()
  end
end
