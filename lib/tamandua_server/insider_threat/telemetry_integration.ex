defmodule TamanduaServer.InsiderThreat.TelemetryIntegration do
  @moduledoc """
  Integration module for insider threat detection with telemetry pipeline.
  Automatically analyzes events as they are ingested.
  """

  alias TamanduaServer.InsiderThreat.Detector
  alias TamanduaServer.InsiderThreat.Alert
  alias TamanduaServer.Telemetry.Event

  require Logger

  @doc """
  Process an event for insider threat detection.
  Should be called from Broadway pipeline after event persistence.
  """
  @spec process_event(Event.t()) :: :ok | {:error, any()}
  def process_event(%Event{payload: %{"user_id" => nil}} = _event) do
    # Skip events without user_id
    :ok
  end

  def process_event(%Event{payload: %{"user_id" => _user_id}} = event) do
    Task.start(fn ->
      analyze_event_async(event)
    end)

    :ok
  end

  def process_event(%Event{} = _event) do
    # Skip events without user_id in payload
    :ok
  end

  @doc """
  Batch process multiple events.
  More efficient for large volumes.
  """
  @spec process_events([Event.t()]) :: :ok
  def process_events(events) do
    events_with_user = Enum.filter(events, fn e -> get_in(e.payload, ["user_id"]) != nil end)

    Task.start(fn ->
      Enum.each(events_with_user, &analyze_event_async/1)
    end)

    :ok
  end

  # Private Functions

  defp analyze_event_async(event) do
    case Detector.analyze_event(event) do
      {:ok, indicators} when indicators != [] ->
        handle_indicators(event, indicators)

      {:ok, []} ->
        # No indicators found
        :ok

      {:error, reason} ->
        Logger.error(
          "Failed to analyze event #{event.id} for insider threats: #{inspect(reason)}"
        )

        :ok
    end
  rescue
    e ->
      Logger.error(
        "Exception during insider threat analysis of event #{event.id}: #{Exception.message(e)}"
      )

      :ok
  end

  defp handle_indicators(event, indicators) do
    # Check if we should create an alert
    # Only create if high-severity indicators or multiple indicators
    should_alert =
      Enum.any?(indicators, &TamanduaServer.InsiderThreat.Indicator.high_severity?/1) or
        length(indicators) >= 3

    if should_alert do
      create_alert_from_indicators(event, indicators)
    end
  end

  defp create_alert_from_indicators(event, indicators) do
    # Calculate risk score
    risk_score =
      TamanduaServer.InsiderThreat.RiskScorer.calculate_score(
        event.user_id,
        indicators,
        %{}
      )

    # Only create alert if threshold exceeded
    if risk_score.threshold_exceeded do
      Alert.create(%{
        user_id: event.user_id,
        organization_id: event.organization_id,
        risk_score: risk_score.total,
        severity: risk_score.severity,
        indicators: Enum.map(indicators, &Map.from_struct/1),
        risk_breakdown: risk_score.components,
        user_metrics: %{},
        trend: risk_score.trend,
        status: "open",
        requires_investigation: risk_score.severity in [:critical, :high]
      })

      Logger.info(
        "Insider threat alert created for user #{event.user_id}, risk score: #{risk_score.total}"
      )
    end
  end
end
