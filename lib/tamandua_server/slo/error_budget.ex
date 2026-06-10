defmodule TamanduaServer.SLO.ErrorBudget do
  @moduledoc """
  Error budget tracking and burn rate monitoring for Tamandua EDR.

  Error budget is the allowed amount of unreliability (100% - SLO).
  For 99.9% availability SLO:
  - Error budget = 0.1% = 43.2 minutes/month
  - Tracks how fast the budget is being consumed (burn rate)
  - Alerts when burn rate exceeds thresholds

  Burn rate thresholds:
  - Fast burn: 14.4x (exhausts budget in 2 hours)
  - Slow burn: 1x (exhausts budget in 30 days)
  """

  use GenServer
  require Logger

  alias TamanduaServer.SLO.Calculator

  @slo_targets Calculator.targets()

  # Burn rate alert thresholds
  @fast_burn_multiplier 14.4  # Exhausts budget in 2 hours
  @medium_burn_multiplier 6.0  # Exhausts budget in 5 hours
  @slow_burn_multiplier 3.0    # Exhausts budget in 10 hours

  # Time windows for burn rate calculation
  @short_window_minutes 5
  @long_window_minutes 60

  defstruct [
    :slo_target,
    :time_window_days,
    :budget_remaining_percent,
    :budget_consumed_percent,
    :budget_consumed_minutes,
    :budget_total_minutes,
    :burn_rate_short,
    :burn_rate_long,
    :alert_status,
    :alerts,
    :historical_burn_rates,
    :last_updated
  ]

  # Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Calculate current error budget status.

  ## Parameters
  - `uptime_samples` - Recent uptime samples (1 = up, 0 = down)
  - `time_window_days` - Time window for budget calculation (default: 30 days)

  ## Returns
  %{
    slo_target: 99.9,
    budget_remaining_percent: 0.08,
    budget_consumed_percent: 0.02,
    budget_consumed_minutes: 8.64,
    budget_total_minutes: 43.2,
    status: :healthy  # :healthy | :warning | :critical
  }
  """
  @spec calculate_budget([0 | 1], pos_integer()) :: map()
  def calculate_budget(uptime_samples, time_window_days \\ 30) do
    GenServer.call(__MODULE__, {:calculate_budget, uptime_samples, time_window_days})
  end

  @doc """
  Calculate burn rate (how fast error budget is being consumed).

  Burn rate = actual error rate / allowed error rate
  - 1x = consuming budget at expected rate
  - >1x = consuming budget faster than expected
  - <1x = consuming budget slower than expected

  ## Parameters
  - `uptime_samples_short` - Recent samples (5 minute window)
  - `uptime_samples_long` - Long-term samples (1 hour window)

  ## Returns
  %{
    short_window: %{burn_rate: 2.5, window_minutes: 5},
    long_window: %{burn_rate: 1.2, window_minutes: 60},
    alert_status: :warning,  # :ok | :warning | :critical
    projected_budget_exhaustion: ~U[2026-02-20 15:30:00Z]
  }
  """
  @spec calculate_burn_rate([0 | 1], [0 | 1]) :: map()
  def calculate_burn_rate(uptime_samples_short, uptime_samples_long) do
    GenServer.call(__MODULE__, {:calculate_burn_rate, uptime_samples_short, uptime_samples_long})
  end

  @doc """
  Get current error budget status.
  """
  @spec current_status() :: map()
  def current_status do
    GenServer.call(__MODULE__, :current_status)
  end

  @doc """
  Get error budget alerts.
  """
  @spec get_alerts() :: [map()]
  def get_alerts do
    GenServer.call(__MODULE__, :get_alerts)
  end

  @doc """
  Record a violation (downtime or error event).
  """
  @spec record_violation(atom(), map()) :: :ok
  def record_violation(type, metadata \\ %{}) do
    GenServer.cast(__MODULE__, {:record_violation, type, metadata})
  end

  @doc """
  Reset error budget (start of new period).
  """
  @spec reset_budget() :: :ok
  def reset_budget do
    GenServer.cast(__MODULE__, :reset_budget)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    state = %__MODULE__{
      slo_target: @slo_targets.availability_percent,
      time_window_days: 30,
      budget_remaining_percent: 100.0 - @slo_targets.availability_percent,
      budget_consumed_percent: 0.0,
      budget_consumed_minutes: 0.0,
      budget_total_minutes: calculate_total_budget_minutes(30),
      burn_rate_short: 0.0,
      burn_rate_long: 0.0,
      alert_status: :ok,
      alerts: [],
      historical_burn_rates: [],
      last_updated: DateTime.utc_now()
    }

    # Schedule periodic budget check
    schedule_budget_check()

    Logger.info("Error Budget Monitor initialized with SLO target: #{@slo_targets.availability_percent}%")
    {:ok, state}
  end

  @impl true
  def handle_call({:calculate_budget, uptime_samples, time_window_days}, _from, state) do
    budget = do_calculate_budget(uptime_samples, time_window_days)
    {:reply, budget, %{state | last_updated: DateTime.utc_now()}}
  end

  @impl true
  def handle_call({:calculate_burn_rate, uptime_samples_short, uptime_samples_long}, _from, state) do
    burn_rate = do_calculate_burn_rate(uptime_samples_short, uptime_samples_long)

    # Update state
    state = %{state |
      burn_rate_short: burn_rate.short_window.burn_rate,
      burn_rate_long: burn_rate.long_window.burn_rate,
      alert_status: burn_rate.alert_status,
      last_updated: DateTime.utc_now()
    }

    # Check for new alerts
    state = check_and_generate_alerts(state, burn_rate)

    {:reply, burn_rate, state}
  end

  @impl true
  def handle_call(:current_status, _from, state) do
    status = %{
      slo_target: state.slo_target,
      budget_remaining_percent: state.budget_remaining_percent,
      budget_consumed_percent: state.budget_consumed_percent,
      budget_consumed_minutes: state.budget_consumed_minutes,
      budget_total_minutes: state.budget_total_minutes,
      burn_rate_short: state.burn_rate_short,
      burn_rate_long: state.burn_rate_long,
      alert_status: state.alert_status,
      time_window_days: state.time_window_days,
      last_updated: DateTime.to_iso8601(state.last_updated)
    }

    {:reply, status, state}
  end

  @impl true
  def handle_call(:get_alerts, _from, state) do
    {:reply, state.alerts, state}
  end

  @impl true
  def handle_cast({:record_violation, type, metadata}, state) do
    # Calculate impact of this violation
    violation_impact = calculate_violation_impact(type, metadata)

    # Update consumed budget
    new_consumed = state.budget_consumed_minutes + violation_impact.duration_minutes

    state = %{state |
      budget_consumed_minutes: new_consumed,
      budget_consumed_percent: (new_consumed / state.budget_total_minutes) * 100,
      budget_remaining_percent: ((state.budget_total_minutes - new_consumed) / state.budget_total_minutes) * 100,
      last_updated: DateTime.utc_now()
    }

    # Log violation
    Logger.warning("Error budget violation recorded: #{type}, impact: #{violation_impact.duration_minutes} minutes")

    {:noreply, state}
  end

  @impl true
  def handle_cast(:reset_budget, state) do
    state = %{state |
      budget_consumed_percent: 0.0,
      budget_consumed_minutes: 0.0,
      budget_remaining_percent: 100.0 - state.slo_target,
      burn_rate_short: 0.0,
      burn_rate_long: 0.0,
      alert_status: :ok,
      alerts: [],
      historical_burn_rates: [],
      last_updated: DateTime.utc_now()
    }

    Logger.info("Error budget reset for new period")
    {:noreply, state}
  end

  @impl true
  def handle_info(:check_budget, state) do
    # Periodic budget health check
    state = perform_budget_check(state)

    schedule_budget_check()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp do_calculate_budget(uptime_samples, time_window_days) do
    total_budget_minutes = calculate_total_budget_minutes(time_window_days)

    # Calculate actual downtime
    total_samples = length(uptime_samples)
    down_samples = Enum.count(uptime_samples, &(&1 == 0))

    # Assume samples are taken every minute
    actual_downtime_minutes = down_samples * 1.0

    consumed_percent = if total_budget_minutes > 0 do
      (actual_downtime_minutes / total_budget_minutes) * 100
    else
      0.0
    end

    remaining_percent = 100.0 - consumed_percent

    status = cond do
      remaining_percent < 10 -> :critical
      remaining_percent < 25 -> :warning
      true -> :healthy
    end

    %{
      slo_target: @slo_targets.availability_percent,
      budget_total_minutes: Float.round(total_budget_minutes, 2),
      budget_consumed_minutes: Float.round(actual_downtime_minutes, 2),
      budget_consumed_percent: Float.round(consumed_percent, 4),
      budget_remaining_percent: Float.round(remaining_percent, 4),
      time_window_days: time_window_days,
      status: status
    }
  end

  defp do_calculate_burn_rate(uptime_samples_short, uptime_samples_long) do
    # Calculate error rate for short window
    short_error_rate = calculate_error_rate(uptime_samples_short)

    # Calculate error rate for long window
    long_error_rate = calculate_error_rate(uptime_samples_long)

    # Allowed error rate from SLO
    allowed_error_rate = 100.0 - @slo_targets.availability_percent

    # Calculate burn rates
    burn_rate_short = if allowed_error_rate > 0 do
      short_error_rate / allowed_error_rate
    else
      0.0
    end

    burn_rate_long = if allowed_error_rate > 0 do
      long_error_rate / allowed_error_rate
    else
      0.0
    end

    # Determine alert status
    alert_status = cond do
      burn_rate_short > @fast_burn_multiplier -> :critical
      burn_rate_long > @medium_burn_multiplier -> :warning
      burn_rate_long > @slow_burn_multiplier -> :watch
      true -> :ok
    end

    # Project when budget will be exhausted
    projected_exhaustion = if burn_rate_long > 0 do
      # Remaining budget / burn rate = time until exhaustion
      hours_until_exhaustion = (100.0 / burn_rate_long) * 720  # 30 days in hours
      DateTime.add(DateTime.utc_now(), round(hours_until_exhaustion * 3600), :second)
    else
      nil
    end

    %{
      short_window: %{
        burn_rate: Float.round(burn_rate_short, 4),
        error_rate: Float.round(short_error_rate, 4),
        window_minutes: @short_window_minutes
      },
      long_window: %{
        burn_rate: Float.round(burn_rate_long, 4),
        error_rate: Float.round(long_error_rate, 4),
        window_minutes: @long_window_minutes
      },
      alert_status: alert_status,
      projected_budget_exhaustion: projected_exhaustion,
      thresholds: %{
        fast_burn: @fast_burn_multiplier,
        medium_burn: @medium_burn_multiplier,
        slow_burn: @slow_burn_multiplier
      }
    }
  end

  defp calculate_error_rate(uptime_samples) do
    total = length(uptime_samples)

    if total == 0 do
      0.0
    else
      down_count = Enum.count(uptime_samples, &(&1 == 0))
      (down_count / total) * 100
    end
  end

  defp calculate_total_budget_minutes(time_window_days) do
    # Total minutes in the window
    total_minutes = time_window_days * 24 * 60

    # Error budget = (100 - SLO) % of total time
    error_budget_percent = 100.0 - @slo_targets.availability_percent

    total_minutes * (error_budget_percent / 100.0)
  end

  defp calculate_violation_impact(type, metadata) do
    # Default to 1 minute impact
    duration = Map.get(metadata, :duration_minutes, 1.0)

    %{
      type: type,
      duration_minutes: duration,
      timestamp: DateTime.utc_now()
    }
  end

  defp check_and_generate_alerts(state, burn_rate) do
    new_alerts = []

    # Fast burn alert
    new_alerts = if burn_rate.short_window.burn_rate > @fast_burn_multiplier do
      alert = %{
        id: UUID.uuid4(),
        type: :fast_burn,
        severity: :critical,
        burn_rate: burn_rate.short_window.burn_rate,
        threshold: @fast_burn_multiplier,
        message: "Critical: Error budget burning at #{Float.round(burn_rate.short_window.burn_rate, 2)}x (exhausts in ~2 hours)",
        timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
      }

      [alert | new_alerts]
    else
      new_alerts
    end

    # Medium burn alert
    new_alerts = if burn_rate.long_window.burn_rate > @medium_burn_multiplier do
      alert = %{
        id: UUID.uuid4(),
        type: :medium_burn,
        severity: :warning,
        burn_rate: burn_rate.long_window.burn_rate,
        threshold: @medium_burn_multiplier,
        message: "Warning: Error budget burning at #{Float.round(burn_rate.long_window.burn_rate, 2)}x (exhausts in ~5 hours)",
        timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
      }

      [alert | new_alerts]
    else
      new_alerts
    end

    if length(new_alerts) > 0 do
      Logger.warning("Error budget burn rate alerts: #{inspect(new_alerts)}")

      # Broadcast alerts
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "system:slo",
        {:error_budget_alert, new_alerts}
      )

      # Keep last 50 alerts
      %{state | alerts: (new_alerts ++ state.alerts) |> Enum.take(50)}
    else
      state
    end
  end

  defp perform_budget_check(state) do
    # Check if budget is critically low
    if state.budget_remaining_percent < 10 do
      Logger.error("Critical: Error budget critically low at #{Float.round(state.budget_remaining_percent, 2)}%")

      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "system:slo",
        {:error_budget_critical, state.budget_remaining_percent}
      )
    end

    state
  end

  defp schedule_budget_check do
    # Check every 5 minutes
    Process.send_after(self(), :check_budget, :timer.minutes(5))
  end
end
