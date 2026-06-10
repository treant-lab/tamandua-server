defmodule TamanduaServer.Alerts.HealthAwareSuppression do
  @moduledoc """
  Health-aware alert suppression.

  Adjusts alert severity and suppression behavior based on the health status
  of the reporting agent. When an agent is degraded (high CPU, stale heartbeat,
  memory pressure, event drops), its telemetry may be unreliable and produce
  false-positive alerts. This module reduces noise by:

  - **Degraded agent**: Reduces alert severity by one level and annotates
    the alert with health context.
  - **Critical agent**: Suppresses low/medium alerts entirely, and reduces
    high/critical alerts by two severity levels.

  Additionally, tracks per-agent alert rates. When an agent that is also
  degraded/critical shows a sudden spike in alert volume, suppression
  becomes more aggressive. Normal thresholds are restored when the agent
  recovers to healthy.

  ## Integration

  Called from `TamanduaServer.Detection.Engine` after policy evaluation
  and before alert creation. Does NOT replace rule-based or contextual
  suppression -- it runs alongside them as an additional tuning layer.
  """

  require Logger

  alias TamanduaServer.Agents.Registry

  # ETS table for per-agent alert rate tracking
  @rate_table :health_suppression_alert_rates

  # Alert rate spike: if an agent produces this many alerts within the
  # window AND is degraded/critical, increase suppression aggressiveness.
  @spike_threshold 20
  @spike_window_seconds 300  # 5 minutes

  # Severity ordering (lowest to highest)
  @severity_order ["info", "low", "medium", "high", "critical"]

  # -------------------------------------------------------------------------
  # Public API
  # -------------------------------------------------------------------------

  @doc """
  Initialize the ETS table for alert rate tracking.

  Called once at application startup (from the Suppression GenServer or
  the Application supervisor).
  """
  @spec init_rate_table() :: :ok
  def init_rate_table do
    if :ets.whereis(@rate_table) == :undefined do
      :ets.new(@rate_table, [
        :named_table, :set, :public,
        read_concurrency: true, write_concurrency: true
      ])
    end

    :ok
  end

  @doc """
  Apply health-aware alert tuning to a provisional alert.

  Returns one of:
  - `{:allow, alert_data}` -- alert should be created (possibly with modified severity)
  - `{:suppress, reason}` -- alert should be suppressed entirely

  The returned `alert_data` map will have:
  - `:severity` potentially adjusted
  - `:agent_health_context` added to `:detection_metadata`
  - `:description` annotated if severity was changed

  ## Parameters

  - `alert_data` -- the provisional alert map (pre-insertion)
  - `agent_id`   -- the reporting agent's ID (may be nil)
  """
  @spec apply_health_tuning(map(), String.t() | nil) ::
          {:allow, map()} | {:suppress, String.t()}
  def apply_health_tuning(alert_data, nil), do: {:allow, alert_data}

  def apply_health_tuning(alert_data, agent_id) do
    health_status = Registry.get_agent_health_status(agent_id)

    case health_status do
      :healthy ->
        # No modification needed; just tag the context
        alert_data = put_health_context(alert_data, :healthy, [])
        {:allow, alert_data}

      :degraded ->
        apply_degraded_tuning(alert_data, agent_id)

      :critical ->
        apply_critical_tuning(alert_data, agent_id)

      :unknown ->
        # Agent not found -- treat as healthy to avoid blocking alerts
        alert_data = put_health_context(alert_data, :unknown, [])
        {:allow, alert_data}
    end
  end

  @doc """
  Record an alert occurrence for per-agent rate tracking.

  Call this after an alert is created (or after a health-tuned alert
  passes through). The rate data is used to detect alert volume spikes
  from degraded agents.
  """
  @spec record_alert(String.t()) :: :ok
  def record_alert(agent_id) when is_binary(agent_id) do
    ensure_rate_table()
    now = System.system_time(:second)

    case :ets.lookup(@rate_table, agent_id) do
      [{^agent_id, timestamps}] ->
        # Append current timestamp and prune old entries
        cutoff = now - @spike_window_seconds
        updated = Enum.filter(timestamps, &(&1 > cutoff)) ++ [now]
        :ets.insert(@rate_table, {agent_id, updated})

      [] ->
        :ets.insert(@rate_table, {agent_id, [now]})
    end

    :ok
  end

  def record_alert(_), do: :ok

  @doc """
  Check whether the given agent is experiencing an alert volume spike.

  Returns `{true, count}` if the agent produced >= @spike_threshold alerts
  within the spike window, or `false` otherwise.
  """
  @spec alert_spike?(String.t()) :: {true, non_neg_integer()} | false
  def alert_spike?(agent_id) when is_binary(agent_id) do
    ensure_rate_table()
    now = System.system_time(:second)
    cutoff = now - @spike_window_seconds

    case :ets.lookup(@rate_table, agent_id) do
      [{^agent_id, timestamps}] ->
        recent = Enum.count(timestamps, &(&1 > cutoff))

        if recent >= @spike_threshold do
          {true, recent}
        else
          false
        end

      [] ->
        false
    end
  end

  def alert_spike?(_), do: false

  @doc """
  Clean up stale rate tracking entries (older than the spike window).

  Should be called periodically (e.g., every 5-10 minutes).
  """
  @spec cleanup_rate_table() :: non_neg_integer()
  def cleanup_rate_table do
    ensure_rate_table()
    now = System.system_time(:second)
    cutoff = now - @spike_window_seconds * 2

    entries = :ets.tab2list(@rate_table)
    deleted =
      Enum.reduce(entries, 0, fn {agent_id, timestamps}, acc ->
        recent = Enum.filter(timestamps, &(&1 > cutoff))

        if recent == [] do
          :ets.delete(@rate_table, agent_id)
          acc + 1
        else
          if length(recent) < length(timestamps) do
            :ets.insert(@rate_table, {agent_id, recent})
          end

          acc
        end
      end)

    if deleted > 0 do
      Logger.debug("HealthAwareSuppression: cleaned #{deleted} stale rate entries")
    end

    deleted
  end

  # -------------------------------------------------------------------------
  # Degraded agent tuning
  # -------------------------------------------------------------------------

  defp apply_degraded_tuning(alert_data, agent_id) do
    severity = get_severity(alert_data)
    reasons = ["agent_degraded"]

    # Check for alert spike which increases suppression aggressiveness
    {spiking, spike_reasons} = check_spike(agent_id)

    if spiking do
      # Degraded + spiking: suppress low/medium, reduce high/critical by two
      apply_spike_degraded_tuning(alert_data, agent_id, severity, reasons ++ spike_reasons)
    else
      # Normal degraded: reduce severity by one level
      new_severity = reduce_severity(severity, 1)

      if new_severity != severity do
        Logger.info(
          "Health-aware tuning: agent #{agent_id} degraded, " <>
            "severity #{severity} -> #{new_severity}"
        )
      end

      alert_data =
        alert_data
        |> put_severity(new_severity)
        |> put_health_context(:degraded, reasons)
        |> annotate_description(:degraded, severity, new_severity)

      {:allow, alert_data}
    end
  end

  # Degraded + alert spike: more aggressive suppression
  defp apply_spike_degraded_tuning(alert_data, agent_id, severity, reasons) do
    case severity do
      s when s in ["low", "info"] ->
        reason =
          "Suppressed: agent #{agent_id} is degraded with alert spike -- " <>
            "#{severity} severity alert suppressed"

        Logger.info("Health-aware suppression: #{reason}")
        {:suppress, reason}

      _ ->
        new_severity = reduce_severity(severity, 2)

        Logger.info(
          "Health-aware tuning: agent #{agent_id} degraded+spike, " <>
            "severity #{severity} -> #{new_severity}"
        )

        alert_data =
          alert_data
          |> put_severity(new_severity)
          |> put_health_context(:degraded, reasons ++ ["alert_spike"])
          |> annotate_description(:degraded_spike, severity, new_severity)

        {:allow, alert_data}
    end
  end

  # -------------------------------------------------------------------------
  # Critical agent tuning
  # -------------------------------------------------------------------------

  defp apply_critical_tuning(alert_data, agent_id) do
    severity = get_severity(alert_data)
    reasons = ["agent_critical"]

    case severity do
      s when s in ["low", "medium", "info"] ->
        reason =
          "Suppressed: agent #{agent_id} is critical -- " <>
            "#{severity} severity alert suppressed"

        Logger.info("Health-aware suppression: #{reason}")
        {:suppress, reason}

      _ ->
        # High/critical: reduce by two levels
        new_severity = reduce_severity(severity, 2)

        Logger.info(
          "Health-aware tuning: agent #{agent_id} critical, " <>
            "severity #{severity} -> #{new_severity}"
        )

        alert_data =
          alert_data
          |> put_severity(new_severity)
          |> put_health_context(:critical, reasons)
          |> annotate_description(:critical, severity, new_severity)

        {:allow, alert_data}
    end
  end

  # -------------------------------------------------------------------------
  # Severity manipulation helpers
  # -------------------------------------------------------------------------

  defp get_severity(alert_data) do
    sev = alert_data[:severity] || alert_data["severity"] || "medium"
    to_string(sev)
  end

  defp put_severity(alert_data, new_severity) do
    Map.put(alert_data, :severity, new_severity)
  end

  @doc """
  Reduce a severity string by `levels` steps.

  ## Examples

      iex> reduce_severity("critical", 1)
      "high"

      iex> reduce_severity("high", 2)
      "low"

      iex> reduce_severity("low", 1)
      "info"

      iex> reduce_severity("info", 1)
      "info"
  """
  @spec reduce_severity(String.t(), non_neg_integer()) :: String.t()
  def reduce_severity(severity, levels) when is_integer(levels) and levels >= 0 do
    idx = Enum.find_index(@severity_order, &(&1 == severity)) || 2
    new_idx = max(idx - levels, 0)
    Enum.at(@severity_order, new_idx)
  end

  # -------------------------------------------------------------------------
  # Alert metadata helpers
  # -------------------------------------------------------------------------

  defp put_health_context(alert_data, health_status, reasons) do
    context = %{
      "agent_health_status" => to_string(health_status),
      "health_check_time" => System.system_time(:millisecond),
      "degraded_reasons" => reasons
    }

    detection_meta =
      (alert_data[:detection_metadata] || alert_data["detection_metadata"] || %{})
      |> Map.put("agent_health_context", context)

    Map.put(alert_data, :detection_metadata, detection_meta)
  end

  defp annotate_description(alert_data, tuning_type, original_severity, new_severity) do
    note =
      case tuning_type do
        :degraded ->
          "[Health Tuning] Agent degraded -- severity reduced from #{original_severity} to #{new_severity}"

        :degraded_spike ->
          "[Health Tuning] Agent degraded with alert spike -- severity reduced from #{original_severity} to #{new_severity}"

        :critical ->
          "[Health Tuning] Agent critical -- severity reduced from #{original_severity} to #{new_severity}"
      end

    existing_desc = alert_data[:description] || alert_data["description"] || ""

    Map.put(alert_data, :description, "#{existing_desc}\n#{note}")
  end

  # -------------------------------------------------------------------------
  # Spike detection helpers
  # -------------------------------------------------------------------------

  defp check_spike(agent_id) do
    case alert_spike?(agent_id) do
      {true, count} ->
        {true, ["alert_spike:#{count}_in_#{@spike_window_seconds}s"]}

      false ->
        {false, []}
    end
  end

  defp ensure_rate_table do
    if :ets.whereis(@rate_table) == :undefined do
      init_rate_table()
    end
  end
end
