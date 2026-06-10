defmodule TamanduaServer.Detection.EventContext do
  @moduledoc """
  Normalizes collector, profile, and telemetry quality context for detection.

  The detection engine consumes events from many collectors across operating
  systems. This module keeps the collector/profile contract centralized so
  scoring, alert metadata, and future routing can use the same context.
  """

  alias TamanduaServer.Agents.CollectorCatalog

  @expected_fields %{
    "process" => ~w(pid process_name command_line),
    "file" => ~w(path),
    "network" => ~w(src_ip dest_ip protocol),
    "dns" => ~w(query domain),
    "registry" => ~w(key path),
    "authentication" => ~w(user outcome),
    "ai_runtime" => ~w(provider model operation)
  }

  @high_signal_collectors ~w(
    amsi etw ebpf auditd network_dpi ja3 certificate credential_theft lateral_movement
    defense_evasion memory script_block command_line_dna identity
  )

  @doc "Attach normalized detection context under `:_detection_context`."
  @spec attach(map()) :: map()
  def attach(event) when is_map(event) do
    Map.put(event, :_detection_context, build(event))
  end

  @doc "Build normalized detection context without mutating the event."
  @spec build(map()) :: map()
  def build(event) when is_map(event) do
    payload = payload(event)
    event_type = normalize_string(first_present([event[:event_type], event["event_type"], payload[:event_type], payload["event_type"]]))
    family = family_for(event_type)
    collector = collector_for(event, payload, event_type, family)
    profile = profile_for(event, payload)
    missing_fields = missing_expected_fields(family, payload)
    quality = quality_score(family, missing_fields)

    %{
      event_type: event_type,
      family: family,
      collector: collector,
      source: source_for(event, payload, collector),
      profile: profile,
      quality: quality,
      missing_fields: missing_fields,
      risk_multiplier: risk_multiplier(profile, collector, quality)
    }
  end

  defp payload(event) do
    case event[:payload] || event["payload"] do
      payload when is_map(payload) -> payload
      _ -> %{}
    end
  end

  defp collector_for(event, payload, event_type, family) do
    explicit =
      first_present([
        event[:collector],
        event["collector"],
        event[:collector_id],
        event["collector_id"],
        payload[:collector],
        payload["collector"],
        payload[:collector_id],
        payload["collector_id"],
        payload[:source],
        payload["source"]
      ])

    normalize_collector(explicit) || collector_from_type(event_type, family)
  end

  defp profile_for(event, payload) do
    first_present([
      event[:profile],
      event["profile"],
      event[:performance_profile],
      event["performance_profile"],
      payload[:profile],
      payload["profile"],
      payload[:performance_profile],
      payload["performance_profile"]
    ])
    |> normalize_profile()
  end

  defp source_for(event, payload, collector) do
    first_present([
      event[:source],
      event["source"],
      payload[:source],
      payload["source"],
      collector
    ])
    |> normalize_string()
  end

  defp normalize_profile(value) do
    profile = normalize_string(value)
    if profile in CollectorCatalog.profiles(), do: profile, else: "balanced"
  end

  defp normalize_collector(nil), do: nil

  defp normalize_collector(value) do
    case CollectorCatalog.normalize_collector(value) do
      "" -> nil
      collector -> collector
    end
  end

  defp collector_from_type(event_type, family) do
    cond do
      String.contains?(event_type, "ja3") -> "ja3"
      String.contains?(event_type, "certificate") -> "certificate"
      String.contains?(event_type, "amsi") -> "amsi"
      String.contains?(event_type, "etw") -> "etw"
      String.contains?(event_type, "ebpf") -> "ebpf"
      true -> family
    end
  end

  defp family_for(event_type) do
    cond do
      String.starts_with?(event_type, "process") -> "process"
      String.starts_with?(event_type, "file") -> "file"
      String.starts_with?(event_type, "network") -> "network"
      String.starts_with?(event_type, "dns") -> "dns"
      String.starts_with?(event_type, "registry") -> "registry"
      event_type in ~w(authentication logon auth_event logon_event kerberos_tgt kerberos_tgs account_logon logon_failure directory_replication) -> "authentication"
      event_type in ~w(llm_request llm_api_request inference_request inference_response llm_response llm_api_response) -> "ai_runtime"
      true -> "unknown"
    end
  end

  defp missing_expected_fields("unknown", _payload), do: []

  defp missing_expected_fields(family, payload) do
    expected = Map.get(@expected_fields, family, [])

    Enum.reject(expected, fn field ->
      has_value?(payload, field) || has_value?(payload, String.to_atom(field))
    end)
  end

  defp quality_score("unknown", _missing_fields), do: 0.75

  defp quality_score(family, missing_fields) do
    expected_count = @expected_fields |> Map.get(family, []) |> length()

    cond do
      expected_count == 0 -> 0.75
      missing_fields == [] -> 1.0
      true -> max(0.4, 1.0 - length(missing_fields) / expected_count * 0.45)
    end
  end

  defp risk_multiplier(profile, collector, quality) do
    profile_multiplier =
      case profile do
        "high_value_asset" -> 1.20
        "forensic_burst" -> 1.15
        "aggressive" -> 1.10
        "lightweight" -> 0.95
        "vdi_safe" -> 0.95
        _ -> 1.0
      end

    collector_multiplier = if collector in @high_signal_collectors, do: 1.05, else: 1.0
    quality_multiplier = if quality < 0.65, do: 0.90, else: 1.0

    Float.round(profile_multiplier * collector_multiplier * quality_multiplier, 4)
  end

  defp first_present(values) do
    Enum.find(values, fn
      value when is_binary(value) -> String.trim(value) != ""
      nil -> false
      _ -> true
    end)
  end

  defp normalize_string(nil), do: ""

  defp normalize_string(value) do
    value
    |> to_string()
    |> String.trim()
    |> String.downcase()
  end

  defp has_value?(map, key) do
    case Map.get(map, key) do
      nil -> false
      "" -> false
      [] -> false
      _ -> true
    end
  end
end
