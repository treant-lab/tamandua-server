defmodule TamanduaServer.Telemetry.EventSampler do
  @moduledoc """
  Event sampling logic for long-term storage optimization.

  Determines which events to keep and which to drop based on:
  - Event type (high-value vs low-value)
  - Age of the event
  - Detection results
  - Configured sampling rate

  ## High-Value Events (Always Keep)

  - Process lifecycle: process_creation, process_termination, process_injection
  - Network activity: network_connection, network_listen
  - File operations: file_modification, file_creation, file_deletion
  - Registry operations: registry_modification, registry_deletion (Windows)
  - Security: privilege_escalation, authentication_failure
  - Any event with detections or alerts

  ## Low-Value Events (Candidate for Sampling)

  - DNS queries (unless to suspicious domains)
  - File reads (without modifications)
  - Registry reads (without modifications)
  - System health metrics
  - Benign network connections
  """

  alias TamanduaServer.Telemetry.Event

  @high_value_event_types [
    "process_creation",
    "process_termination",
    "process_injection",
    "network_connection",
    "network_listen",
    "file_modification",
    "file_creation",
    "file_deletion",
    "registry_modification",
    "registry_deletion",
    "privilege_escalation",
    "authentication_failure",
    "driver_load",
    "service_creation",
    "scheduled_task_creation",
    "wmi_event",
    "powershell_execution",
    "script_execution"
  ]

  @low_value_event_types [
    "dns_query",
    "file_read",
    "registry_read",
    "system_health",
    "heartbeat"
  ]

  @doc """
  Determine if an event is high-value and should always be kept.

  Returns true if:
  - Event type is in high-value list
  - Event has detections
  - Event has high severity (critical, high)
  - Event is associated with an alert
  """
  @spec high_value_event?(Event.t() | map()) :: boolean()
  def high_value_event?(%Event{} = event) do
    high_value_event_map?(event)
  end

  def high_value_event?(event) when is_map(event) do
    high_value_event_map?(event)
  end

  defp high_value_event_map?(event) do
    event_type = get_event_type(event)
    severity = get_severity(event)
    detections = get_detections(event)
    enrichment = get_enrichment(event)

    cond do
      # Has detections - always keep
      is_list(detections) and length(detections) > 0 ->
        true

      # Has analysis with alerts - always keep
      has_alerts?(enrichment) ->
        true

      # High severity - always keep
      severity in ["critical", "high"] ->
        true

      # High-value event type - always keep
      event_type in @high_value_event_types ->
        true

      # Special case: DNS to suspicious domains
      event_type == "dns_query" and suspicious_dns?(event) ->
        true

      # Special case: Network connection to unusual ports
      event_type == "network_connection" and unusual_port?(event) ->
        true

      # Everything else is low-value
      true ->
        false
    end
  end

  @doc """
  Sample a list of events according to the sampling rate.

  Returns {events_to_keep, events_to_drop}.

  Uses deterministic sampling based on event ID to ensure
  consistent sampling across runs (same event always gets
  same decision).
  """
  @spec sample_events([Event.t()], float()) :: {[Event.t()], [Event.t()]}
  def sample_events(events, sampling_rate) when is_list(events) and is_float(sampling_rate) do
    Enum.split_with(events, fn event ->
      should_keep_event?(event, sampling_rate)
    end)
  end

  @doc """
  Determine if a single event should be kept based on sampling rate.

  Uses deterministic hash-based sampling for consistency.
  """
  @spec should_keep_event?(Event.t() | map(), float()) :: boolean()
  def should_keep_event?(event, sampling_rate) do
    # Use event ID to deterministically decide
    event_id = get_event_id(event)

    if is_binary(event_id) do
      # Hash the event ID and use modulo to get deterministic sampling
      hash = :erlang.phash2(event_id, 1000)
      threshold = round(sampling_rate * 1000)
      hash < threshold
    else
      # If no event ID, use random sampling
      :rand.uniform() < sampling_rate
    end
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp get_event_type(%Event{event_type: type}), do: type
  defp get_event_type(%{event_type: type}), do: type
  defp get_event_type(%{"event_type" => type}), do: type
  defp get_event_type(_), do: nil

  defp get_severity(%Event{severity: severity}), do: severity
  defp get_severity(%{severity: severity}), do: severity
  defp get_severity(%{"severity" => severity}), do: severity
  defp get_severity(_), do: "info"

  defp get_detections(%Event{} = event) do
    Map.get(event, :detections, [])
  end

  defp get_detections(%{detections: detections}), do: detections
  defp get_detections(%{"detections" => detections}), do: detections
  defp get_detections(_), do: []

  defp get_enrichment(%Event{enrichment: enrichment}), do: enrichment
  defp get_enrichment(%{enrichment: enrichment}), do: enrichment
  defp get_enrichment(%{"enrichment" => enrichment}), do: enrichment
  defp get_enrichment(_), do: %{}

  defp get_event_id(%Event{id: id}), do: id
  defp get_event_id(%{id: id}), do: id
  defp get_event_id(%{"id" => id}), do: id
  defp get_event_id(%{event_id: id}), do: id
  defp get_event_id(%{"event_id" => id}), do: id
  defp get_event_id(_), do: nil

  defp has_alerts?(enrichment) when is_map(enrichment) do
    case Map.get(enrichment, :analysis) || Map.get(enrichment, "analysis") do
      nil -> false
      analysis when is_map(analysis) ->
        alerts = Map.get(analysis, :alerts) || Map.get(analysis, "alerts") || []
        is_list(alerts) and length(alerts) > 0
      _ -> false
    end
  end

  defp has_alerts?(_), do: false

  defp suspicious_dns?(%Event{} = event) do
    suspicious_dns_map?(event)
  end

  defp suspicious_dns?(event) when is_map(event) do
    suspicious_dns_map?(event)
  end

  defp suspicious_dns_map?(event) do
    payload = Map.get(event, :payload) || Map.get(event, "payload") || %{}
    query = Map.get(payload, :query) || Map.get(payload, "query") || ""

    # Check for suspicious TLDs or patterns
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"]
    dga_like = String.length(query) > 20 and String.match?(query, ~r/[0-9]{5,}/)

    Enum.any?(suspicious_tlds, fn tld -> String.ends_with?(query, tld) end) or dga_like
  end

  defp unusual_port?(%Event{} = event) do
    unusual_port_map?(event)
  end

  defp unusual_port?(event) when is_map(event) do
    unusual_port_map?(event)
  end

  defp unusual_port_map?(event) do
    payload = Map.get(event, :payload) || Map.get(event, "payload") || %{}
    remote_port = Map.get(payload, :remote_port) || Map.get(payload, "remote_port")

    if is_integer(remote_port) do
      # Common ports are low-value, unusual ports are high-value
      common_ports = [80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 3389, 5900]
      remote_port not in common_ports
    else
      false
    end
  end
end
