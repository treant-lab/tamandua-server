defmodule TamanduaServer.Detection.EtwConstants do
  @moduledoc """
  Constants for ETW tampering detection.
  Centralizes MITRE IDs, severity levels, confidence scores, and byte patterns.
  """

  # MITRE ATT&CK Technique IDs
  @mitre_etw_tampering "T1562.006"
  @mitre_defense_evasion "T1562.001"

  def mitre_etw_tampering, do: @mitre_etw_tampering
  def mitre_defense_evasion, do: @mitre_defense_evasion
  def mitre_techniques, do: [@mitre_etw_tampering]

  # Severity levels
  @severity_critical "critical"
  @severity_high "high"

  def severity_critical, do: @severity_critical
  def severity_high, do: @severity_high

  # Confidence scoring
  @base_confidence 0.70
  @bytes_match_bonus 0.15
  @partial_bytes_bonus 0.10
  @pattern_bonus 0.05

  def base_confidence, do: @base_confidence
  def bytes_match_bonus, do: @bytes_match_bonus
  def partial_bytes_bonus, do: @partial_bytes_bonus
  def pattern_bonus, do: @pattern_bonus

  # Threat scores
  @etw_tampering_threat_score 0.95

  def etw_tampering_threat_score, do: @etw_tampering_threat_score

  # Patch pattern byte sequences
  @patch_ret 0xC3
  @patch_xor_eax_ret [0x31, 0xC0, 0xC3]
  @patch_jmp 0xE9
  @patch_int3 0xCC
  @patch_ud2 [0x0F, 0x0B]
  @patch_nop [0x90, 0x90]

  def patch_ret, do: @patch_ret
  def patch_xor_eax_ret, do: @patch_xor_eax_ret
  def patch_jmp, do: @patch_jmp
  def patch_int3, do: @patch_int3
  def patch_ud2, do: @patch_ud2
  def patch_nop, do: @patch_nop

  # Patch pattern names
  @patch_patterns %{
    ret: "Single RET instruction",
    xor_eax_ret: "XOR EAX, EAX + RET",
    jmp_rel32: "JMP relative (hook redirect)",
    jmp_abs: "JMP absolute (trampoline)",
    nop_sled: "NOP sled (code cave)",
    int3_trap: "INT3 trap",
    ud2: "UD2 undefined instruction",
    unknown: "Unknown patch pattern"
  }

  def patch_patterns, do: @patch_patterns
  def patch_pattern_name(pattern), do: Map.get(@patch_patterns, pattern, "Unknown")

  # Target regions
  @target_regions %{
    syscall_stub: "Syscall stub (Nt*/Zw*)",
    etw_function: "ETW function",
    ntdll_text: "NTDLL .text section",
    kernel32_text: "Kernel32 .text section",
    amsi_function: "AMSI function",
    other: "Other region"
  }

  def target_regions, do: @target_regions
  def target_region_name(region), do: Map.get(@target_regions, region, "Unknown region")

  # Function prefixes for classification
  @syscall_prefixes ["Nt", "Zw"]
  @etw_prefixes ["Etw", "NtTrace", "ZwTrace"]
  @amsi_prefixes ["Amsi"]

  def syscall_prefixes, do: @syscall_prefixes
  def etw_prefixes, do: @etw_prefixes
  def amsi_prefixes, do: @amsi_prefixes
end
