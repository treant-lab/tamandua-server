defmodule TamanduaServer.Detection.EtwTamperingHandler do
  @moduledoc """
  Handler for ETW (Event Tracing for Windows) tampering events.

  This module processes ETW tampering events from the agent, extracts relevant
  information, and creates high-severity alerts. ETW tampering is a defense
  evasion technique used by malware to blind EDR telemetry collection.

  MITRE ATT&CK: T1562.006 - Impair Defenses: Indicator Blocking

  ## Event Types Handled

  - `etw_tampering` - Generic ETW tampering detection
  - `etw_prologue_patched` - Function prologue has been patched
  - `ntdll_stub_modified` - ntdll syscall stub modification
  - `fresh_ntdll_mapping` - Detection of fresh ntdll.dll mapping (unhooking)
  - `ntdll_write_detected` - Write operation to ntdll .text section
  - `syscall_region_tampered` - Syscall region modification

  ## Patch Patterns

  - `ret` - Simple return (0xC3)
  - `xor_eax_ret` - XOR EAX, EAX; RET (0x31 0xC0 0xC3)
  - `jmp_rel32` - Relative jump (0xE9 XX XX XX XX)
  - `jmp_abs` - Absolute jump via register
  - `nop_sled` - NOP slide followed by return
  - `int3_trap` - Breakpoint trap
  - `ud2` - Undefined instruction
  """

  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Detection.EventTypes
  alias TamanduaServer.Detection.EtwConstants

  @etw_event_types EventTypes.etw_tampering_subtypes()

  # String-keyed versions for backward compatibility with event payloads
  @patch_patterns %{
    "ret" => "Simple return instruction (0xC3)",
    "xor_eax_ret" => "XOR EAX, EAX; RET - Returns zero status (0x31 0xC0 0xC3)",
    "jmp_rel32" => "Relative 32-bit jump (0xE9)",
    "jmp_abs" => "Absolute jump via register",
    "nop_sled" => "NOP sled followed by return",
    "int3_trap" => "Breakpoint trap (0xCC)",
    "ud2" => "Undefined instruction",
    "unknown" => "Unclassified patch pattern"
  }

  @target_regions %{
    "syscall_stub" => "ntdll syscall stub",
    "etw_function" => "ETW-related function",
    "ntdll_text" => "ntdll .text section",
    "kernel32_text" => "kernel32 .text section",
    "amsi_function" => "AMSI-related function",
    "other" => "Other memory region"
  }

  @doc """
  Check if the given event type is an ETW tampering event.
  """
  @spec etw_tampering_event?(String.t() | atom()) :: boolean()
  def etw_tampering_event?(event_type) when is_atom(event_type) do
    Atom.to_string(event_type) in @etw_event_types
  end

  def etw_tampering_event?(event_type) when is_binary(event_type) do
    String.downcase(event_type) in @etw_event_types
  end

  def etw_tampering_event?(_), do: false

  @doc """
  Process an ETW tampering event and create an alert.

  Returns `{:ok, alert}` if an alert was created, or `{:error, reason}` on failure.
  """
  @spec process_event(map()) :: {:ok, map()} | {:error, term()}
  def process_event(%{agent_id: nil} = _event), do: {:error, :missing_agent_id}
  def process_event(%{"agent_id" => nil} = _event), do: {:error, :missing_agent_id}

  def process_event(event) do
    agent_id = event[:agent_id] || event["agent_id"]
    payload = event[:payload] || event["payload"] || %{}

    if agent_id do
      alert_attrs = build_alert_attrs(event, agent_id, payload)

      case Alerts.create_alert(alert_attrs) do
        {:ok, alert} ->
          broadcast_alert(alert)
          Logger.info("[EtwTamperingHandler] Created alert for agent #{agent_id}: #{alert.title}")
          {:ok, alert}

        {:error, changeset} ->
          Logger.error("[EtwTamperingHandler] Failed to create alert: #{inspect(changeset)}")
          {:error, changeset}
      end
    else
      {:error, :missing_agent_id}
    end
  end

  @doc """
  Extract ETW tampering details from an event payload.

  Returns a map with normalized ETW tampering information.
  """
  @spec extract_details(map()) :: map()
  def extract_details(payload) do
    %{
      target_function: get_string(payload, "target_function", "function"),
      original_bytes: get_binary(payload, "original_bytes"),
      patched_bytes: get_binary(payload, "patched_bytes", "current_bytes"),
      patch_pattern: classify_patch_pattern(payload),
      target_region: classify_target_region(payload),
      detection_method: get_string(payload, "detection_method"),
      process_name: get_string(payload, "process_name"),
      process_id: get_integer(payload, "process_id", "pid"),
      timestamp: get_timestamp(payload)
    }
  end

  @doc """
  Build detection entries for ETW tampering events.

  Returns a list of detection maps for the detection engine.
  """
  @spec build_detections(map()) :: [map()]
  def build_detections(event) do
    payload = event[:payload] || event["payload"] || %{}
    details = extract_details(payload)
    event_type = to_string(event[:event_type] || event["event_type"] || "etw_tampering")

    [
      %{
        type: :etw_tampering,
        rule_id: "tamandua-etw-patch-001",
        rule_name: build_rule_name(event_type, details),
        severity: EtwConstants.severity_critical(),
        confidence: calculate_confidence(details),
        description: build_description(details),
        mitre_tactics: ["defense-evasion"],
        mitre_techniques: EtwConstants.mitre_techniques(),
        details: details
      }
    ]
  end

  # ── Private Functions ────────────────────────────────────────────────

  defp build_alert_attrs(event, agent_id, payload) do
    details = extract_details(payload)
    event_type = to_string(event[:event_type] || event["event_type"] || "etw_tampering")

    %{
      agent_id: agent_id,
      severity: EtwConstants.severity_critical(),
      title: build_alert_title(event_type, details),
      description: build_alert_description(details),
      mitre_tactics: ["Defense Evasion"],
      mitre_techniques: EtwConstants.mitre_techniques(),
      threat_score: EtwConstants.etw_tampering_threat_score(),
      # ETW-specific fields
      target_function: details.target_function,
      original_bytes: details.original_bytes,
      patched_bytes: details.patched_bytes,
      patch_pattern: details.patch_pattern,
      target_region: details.target_region,
      # Evidence and metadata
      evidence: %{
        "etw_tampering" => %{
          "target_function" => details.target_function,
          "patch_pattern" => details.patch_pattern,
          "target_region" => details.target_region,
          "detection_method" => details.detection_method,
          "process_name" => details.process_name,
          "process_id" => details.process_id
        }
      },
      detection_metadata: %{
        "event_type" => event_type,
        "detection_source" => "etw_tampering_monitor",
        "original_bytes_hex" => encode_hex(details.original_bytes),
        "patched_bytes_hex" => encode_hex(details.patched_bytes),
        "patch_pattern_description" => Map.get(@patch_patterns, details.patch_pattern, "Unknown"),
        "target_region_description" => Map.get(@target_regions, details.target_region, "Unknown")
      },
      raw_event: event
    }
  end

  defp build_alert_title(event_type, details) do
    function_name = details.target_function || "unknown function"
    pattern = details.patch_pattern || "unknown"

    case event_type do
      "etw_prologue_patched" ->
        "ETW Function Patched: #{function_name} (#{pattern})"
      "ntdll_stub_modified" ->
        "NTDLL Syscall Stub Modified: #{function_name}"
      "fresh_ntdll_mapping" ->
        "Fresh NTDLL Mapping Detected (Unhooking Attempt)"
      "ntdll_write_detected" ->
        "NTDLL .text Section Write Detected"
      "syscall_region_tampered" ->
        "Syscall Region Tampered: #{function_name}"
      _ ->
        "ETW Tampering Detected: #{function_name}"
    end
  end

  defp build_alert_description(details) do
    function_desc = if details.target_function do
      "Target function: #{details.target_function}"
    else
      "Target function: unknown"
    end

    pattern_desc = if details.patch_pattern do
      pattern_explanation = Map.get(@patch_patterns, details.patch_pattern, "Unknown pattern")
      "Patch pattern: #{details.patch_pattern} (#{pattern_explanation})"
    else
      ""
    end

    region_desc = if details.target_region do
      region_explanation = Map.get(@target_regions, details.target_region, "Unknown region")
      "Target region: #{details.target_region} (#{region_explanation})"
    else
      ""
    end

    process_desc = if details.process_name do
      "Process: #{details.process_name} (PID: #{details.process_id || "unknown"})"
    else
      ""
    end

    [
      "ETW tampering detected - a process has attempted to patch critical Windows tracing functions to evade EDR telemetry collection.",
      "",
      function_desc,
      pattern_desc,
      region_desc,
      process_desc,
      "",
      "This is a critical defense evasion technique (MITRE ATT&CK #{EtwConstants.mitre_etw_tampering()}) commonly used by advanced malware and attack tools to blind security monitoring."
    ]
    |> Enum.reject(&(&1 == ""))
    |> Enum.join("\n")
  end

  defp build_rule_name(event_type, details) do
    function = details.target_function || "Unknown"
    case event_type do
      "etw_prologue_patched" -> "ETW Prologue Patched: #{function}"
      "ntdll_stub_modified" -> "NTDLL Stub Modified: #{function}"
      "fresh_ntdll_mapping" -> "Fresh NTDLL Mapping Detected"
      "ntdll_write_detected" -> "NTDLL Write Detected"
      "syscall_region_tampered" -> "Syscall Region Tampered: #{function}"
      _ -> "ETW Tampering: #{function}"
    end
  end

  defp build_description(details) do
    function = details.target_function || "unknown"
    pattern = details.patch_pattern || "unknown"
    "Detected #{pattern} patch on #{function} - defense evasion attempt"
  end

  defp calculate_confidence(details) do
    base = EtwConstants.base_confidence()

    # Higher confidence if we have both original and patched bytes
    bytes_confidence = cond do
      details.original_bytes && details.patched_bytes -> EtwConstants.partial_bytes_bonus()
      details.original_bytes || details.patched_bytes -> EtwConstants.pattern_bonus()
      true -> 0.0
    end

    # Higher confidence for known patch patterns
    pattern_confidence = if details.patch_pattern in ["ret", "xor_eax_ret", "jmp_rel32"] do
      EtwConstants.pattern_bonus()
    else
      0.0
    end

    min(1.0, base + bytes_confidence + pattern_confidence)
  end

  defp classify_patch_pattern(payload) do
    explicit_pattern = get_string(payload, "patch_pattern", "pattern")

    if explicit_pattern do
      explicit_pattern
    else
      # Attempt to classify based on patched bytes
      patched = get_binary(payload, "patched_bytes", "current_bytes")
      classify_bytes_pattern(patched)
    end
  end

  # Byte pattern constants from EtwConstants for compile-time matching
  @byte_ret EtwConstants.patch_ret()
  @byte_jmp EtwConstants.patch_jmp()
  @byte_int3 EtwConstants.patch_int3()

  defp classify_bytes_pattern(nil), do: "unknown"
  defp classify_bytes_pattern(<<@byte_ret, _rest::binary>>), do: "ret"
  defp classify_bytes_pattern(<<0x31, 0xC0, 0xC3, _rest::binary>>), do: "xor_eax_ret"
  defp classify_bytes_pattern(<<@byte_jmp, _rel32::binary-size(4), _rest::binary>>), do: "jmp_rel32"
  defp classify_bytes_pattern(<<@byte_int3, _rest::binary>>), do: "int3_trap"
  defp classify_bytes_pattern(<<0x0F, 0x0B, _rest::binary>>), do: "ud2"
  defp classify_bytes_pattern(<<0x90, 0x90, _rest::binary>>), do: "nop_sled"
  defp classify_bytes_pattern(_), do: "unknown"

  defp classify_target_region(payload) do
    explicit_region = get_string(payload, "target_region", "region")

    if explicit_region do
      explicit_region
    else
      function = get_string(payload, "target_function", "function") || ""
      module = get_string(payload, "module", "module_name") || ""

      cond do
        String.contains?(function, EtwConstants.syscall_prefixes()) -> "syscall_stub"
        String.contains?(function, EtwConstants.etw_prefixes() ++ ["ETW"]) -> "etw_function"
        String.contains?(function, EtwConstants.amsi_prefixes() ++ ["AMSI"]) -> "amsi_function"
        String.contains?(String.downcase(module), "ntdll") -> "ntdll_text"
        String.contains?(String.downcase(module), "kernel32") -> "kernel32_text"
        true -> "other"
      end
    end
  end

  # Helper functions for extracting values from payload

  defp get_string(payload, key1, key2 \\ nil) do
    value = payload[key1] || payload[String.to_atom(key1)]

    value = if is_nil(value) && key2 do
      payload[key2] || payload[String.to_atom(key2)]
    else
      value
    end

    if is_binary(value), do: value, else: nil
  end

  defp get_binary(payload, key1, key2 \\ nil) do
    value = payload[key1] || payload[String.to_atom(key1)]

    value = if is_nil(value) && key2 do
      payload[key2] || payload[String.to_atom(key2)]
    else
      value
    end

    case value do
      nil -> nil
      v when is_binary(v) -> v
      v when is_list(v) ->
        try do
          :erlang.list_to_binary(v)
        rescue
          ArgumentError -> nil
        end
      _ -> nil
    end
  end

  defp get_integer(payload, key1, key2 \\ nil) do
    value = payload[key1] || payload[String.to_atom(key1)]

    value = if is_nil(value) && key2 do
      payload[key2] || payload[String.to_atom(key2)]
    else
      value
    end

    cond do
      is_integer(value) -> value
      is_binary(value) ->
        case Integer.parse(value) do
          {int, _} -> int
          :error -> nil
        end
      true -> nil
    end
  end

  defp get_timestamp(payload) do
    ts = payload["timestamp"] || payload[:timestamp]

    cond do
      is_integer(ts) -> DateTime.from_unix!(ts, :millisecond)
      is_binary(ts) ->
        case DateTime.from_iso8601(ts) do
          {:ok, dt, _} -> dt
          _ -> DateTime.utc_now()
        end
      true -> DateTime.utc_now()
    end
  end

  defp encode_hex(nil), do: nil
  defp encode_hex(binary) when is_binary(binary) do
    Base.encode16(binary, case: :lower)
  end

  defp broadcast_alert(alert) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alerts:new",
      {:new_alert, alert}
    )

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "agent:#{alert.agent_id}:alerts",
      {:new_alert, alert}
    )
  end
end
