defmodule TamanduaServer.Detection.MitreCoverage do
  @moduledoc """
  MITRE ATT&CK Coverage Tracker.

  Maintains a mapping of which MITRE techniques are covered by detection rules
  (YARA, Sigma, behavioral, ML) and tracks detection efficacy per technique.

  ## Key Features

  - Maps every active detection rule to its MITRE technique(s)
  - Computes a coverage heatmap across all 14 tactics
  - Identifies detection gaps (techniques with zero coverage)
  - Tracks historical detection counts per technique
  - Provides API data for the dashboard coverage visualization

  ## Data Sources

  - Sigma rules (mitre_attack_id field)
  - YARA rules (mitre_technique metadata)
  - Behavioral detection rules (hardcoded technique mappings)
  - Alert history (which techniques have actually fired)
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo

  import Ecto.Query

  # Refresh coverage data every 10 minutes
  @refresh_interval_ms 600_000

  # ---------------------------------------------------------------------------
  # MITRE ATT&CK Enterprise Matrix (v15) — Complete Tactic/Technique Catalog
  # ---------------------------------------------------------------------------

  @tactics %{
    "TA0043" => %{name: "Reconnaissance", order: 1},
    "TA0042" => %{name: "Resource Development", order: 2},
    "TA0001" => %{name: "Initial Access", order: 3},
    "TA0002" => %{name: "Execution", order: 4},
    "TA0003" => %{name: "Persistence", order: 5},
    "TA0004" => %{name: "Privilege Escalation", order: 6},
    "TA0005" => %{name: "Defense Evasion", order: 7},
    "TA0006" => %{name: "Credential Access", order: 8},
    "TA0007" => %{name: "Discovery", order: 9},
    "TA0008" => %{name: "Lateral Movement", order: 10},
    "TA0009" => %{name: "Collection", order: 11},
    "TA0011" => %{name: "Command and Control", order: 12},
    "TA0010" => %{name: "Exfiltration", order: 13},
    "TA0040" => %{name: "Impact", order: 14}
  }

  # Technique-to-tactic mapping for the most important techniques.
  # This covers the MITRE Top 15 + all techniques commonly seen in EDR detections.
  @technique_to_tactic %{
    # Initial Access (TA0001)
    "T1190" => "TA0001", "T1566" => "TA0001", "T1566.001" => "TA0001",
    "T1566.002" => "TA0001", "T1133" => "TA0001", "T1078" => "TA0001",
    "T1189" => "TA0001", "T1195" => "TA0001", "T1195.002" => "TA0001",
    "T1199" => "TA0001", "T1200" => "TA0001",

    # Execution (TA0002)
    "T1059" => "TA0002", "T1059.001" => "TA0002", "T1059.003" => "TA0002",
    "T1059.005" => "TA0002", "T1059.006" => "TA0002", "T1059.007" => "TA0002",
    "T1204" => "TA0002", "T1204.001" => "TA0002", "T1204.002" => "TA0002",
    "T1053" => "TA0002", "T1053.005" => "TA0002", "T1569" => "TA0002",
    "T1569.002" => "TA0002", "T1047" => "TA0002", "T1203" => "TA0002",
    "T1106" => "TA0002", "T1559" => "TA0002", "T1559.001" => "TA0002",

    # Persistence (TA0003)
    "T1547" => "TA0003", "T1547.001" => "TA0003", "T1547.004" => "TA0003",
    "T1547.012" => "TA0003", "T1543" => "TA0003", "T1543.003" => "TA0003",
    "T1136" => "TA0003", "T1136.001" => "TA0003", "T1053.005_p" => "TA0003",
    "T1546" => "TA0003", "T1546.001" => "TA0003", "T1546.003" => "TA0003",
    "T1546.015" => "TA0003", "T1574" => "TA0003", "T1574.001" => "TA0003",
    "T1574.002" => "TA0003", "T1574.011" => "TA0003", "T1197" => "TA0003",
    "T1505" => "TA0003", "T1505.003" => "TA0003",

    # Privilege Escalation (TA0004)
    "T1548" => "TA0004", "T1548.002" => "TA0004", "T1134" => "TA0004",
    "T1134.001" => "TA0004", "T1068" => "TA0004", "T1055" => "TA0004",
    "T1055.001" => "TA0004", "T1055.002" => "TA0004", "T1055.003" => "TA0004",
    "T1055.012" => "TA0004",

    # Defense Evasion (TA0005)
    "T1027" => "TA0005", "T1027.002" => "TA0005", "T1027.005" => "TA0005",
    "T1562" => "TA0005", "T1562.001" => "TA0005", "T1562.002" => "TA0005",
    "T1562.006" => "TA0005", "T1070" => "TA0005", "T1070.001" => "TA0005",
    "T1070.004" => "TA0005", "T1036" => "TA0005", "T1036.005" => "TA0005",
    "T1218" => "TA0005", "T1218.001" => "TA0005", "T1218.003" => "TA0005",
    "T1218.005" => "TA0005", "T1218.010" => "TA0005", "T1218.011" => "TA0005",
    "T1112" => "TA0005", "T1140" => "TA0005", "T1620" => "TA0005",
    "T1014" => "TA0005", "T1564" => "TA0005",

    # Credential Access (TA0006)
    "T1003" => "TA0006", "T1003.001" => "TA0006", "T1003.002" => "TA0006",
    "T1003.003" => "TA0006", "T1003.006" => "TA0006", "T1558" => "TA0006",
    "T1558.003" => "TA0006", "T1110" => "TA0006", "T1110.001" => "TA0006",
    "T1110.003" => "TA0006", "T1555" => "TA0006", "T1555.003" => "TA0006",
    "T1552" => "TA0006", "T1552.001" => "TA0006", "T1556" => "TA0006",
    "T1539" => "TA0006", "T1187" => "TA0006", "T1557" => "TA0006",

    # Discovery (TA0007)
    "T1087" => "TA0007", "T1087.002" => "TA0007", "T1082" => "TA0007",
    "T1083" => "TA0007", "T1057" => "TA0007", "T1018" => "TA0007",
    "T1049" => "TA0007", "T1016" => "TA0007", "T1135" => "TA0007",
    "T1069" => "TA0007", "T1069.002" => "TA0007", "T1012" => "TA0007",
    "T1518" => "TA0007", "T1007" => "TA0007",

    # Lateral Movement (TA0008)
    "T1021" => "TA0008", "T1021.001" => "TA0008", "T1021.002" => "TA0008",
    "T1021.003" => "TA0008", "T1021.004" => "TA0008", "T1021.006" => "TA0008",
    "T1570" => "TA0008", "T1563" => "TA0008", "T1550" => "TA0008",
    "T1550.002" => "TA0008", "T1550.003" => "TA0008",

    # Collection (TA0009)
    "T1005" => "TA0009", "T1039" => "TA0009", "T1074" => "TA0009",
    "T1115" => "TA0009", "T1056" => "TA0009", "T1056.001" => "TA0009",
    "T1113" => "TA0009", "T1560" => "TA0009",

    # Command and Control (TA0011)
    "T1071" => "TA0011", "T1071.001" => "TA0011", "T1071.004" => "TA0011",
    "T1573" => "TA0011", "T1573.001" => "TA0011", "T1573.002" => "TA0011",
    "T1568" => "TA0011", "T1568.002" => "TA0011", "T1090" => "TA0011",
    "T1090.004" => "TA0011", "T1095" => "TA0011", "T1105" => "TA0011",
    "T1572" => "TA0011", "T1001" => "TA0011", "T1219" => "TA0011",
    "T1132" => "TA0011",

    # Exfiltration (TA0010)
    "T1041" => "TA0010", "T1048" => "TA0010", "T1567" => "TA0010",
    "T1011" => "TA0010", "T1052" => "TA0010",

    # Impact (TA0040)
    "T1486" => "TA0040", "T1490" => "TA0040", "T1489" => "TA0040",
    "T1485" => "TA0040", "T1491" => "TA0040", "T1529" => "TA0040",
    "T1496" => "TA0040", "T1498" => "TA0040", "T1561" => "TA0040"
  }

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get the full coverage heatmap: per-tactic coverage percentages and per-technique details.
  """
  def get_coverage do
    GenServer.call(__MODULE__, :get_coverage, 10_000)
  end

  @doc """
  Get gaps: techniques with zero detection rules mapped.
  """
  def get_gaps do
    GenServer.call(__MODULE__, :get_gaps, 10_000)
  end

  @doc """
  Get the coverage summary: high-level stats.
  """
  def get_summary do
    GenServer.call(__MODULE__, :get_summary, 10_000)
  end

  @doc """
  Force a refresh of coverage data.
  """
  def refresh do
    GenServer.cast(__MODULE__, :refresh)
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    Logger.info("[MitreCoverage] Starting coverage tracker")
    send(self(), :refresh)
    {:ok, %{coverage: nil, last_refresh: nil}}
  end

  @impl true
  def handle_info(:refresh, state) do
    coverage = build_coverage_data()
    schedule_refresh()
    {:noreply, %{state | coverage: coverage, last_refresh: DateTime.utc_now()}}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def handle_cast(:refresh, state) do
    coverage = build_coverage_data()
    {:noreply, %{state | coverage: coverage, last_refresh: DateTime.utc_now()}}
  end

  @impl true
  def handle_call(:get_coverage, _from, %{coverage: nil} = state) do
    coverage = build_coverage_data()
    {:reply, coverage, %{state | coverage: coverage, last_refresh: DateTime.utc_now()}}
  end

  def handle_call(:get_coverage, _from, state) do
    {:reply, state.coverage, state}
  end

  @impl true
  def handle_call(:get_gaps, _from, %{coverage: nil} = state) do
    coverage = build_coverage_data()
    gaps = extract_gaps(coverage)
    {:reply, gaps, %{state | coverage: coverage, last_refresh: DateTime.utc_now()}}
  end

  def handle_call(:get_gaps, _from, state) do
    {:reply, extract_gaps(state.coverage), state}
  end

  @impl true
  def handle_call(:get_summary, _from, %{coverage: nil} = state) do
    coverage = build_coverage_data()
    summary = build_summary(coverage)
    {:reply, summary, %{state | coverage: coverage, last_refresh: DateTime.utc_now()}}
  end

  def handle_call(:get_summary, _from, state) do
    {:reply, build_summary(state.coverage), state}
  end

  # ---------------------------------------------------------------------------
  # Build coverage data
  # ---------------------------------------------------------------------------

  defp build_coverage_data do
    # 1. Collect technique-to-rule mappings from all detection sources
    rule_mappings = collect_rule_mappings()

    # 2. Collect historical alert counts per technique
    alert_counts = collect_alert_technique_counts()

    # 3. Build per-technique coverage info
    techniques =
      @technique_to_tactic
      |> Enum.map(fn {technique_id, tactic_id} ->
        rules = Map.get(rule_mappings, technique_id, [])
        detections = Map.get(alert_counts, technique_id, 0)

        {technique_id,
         %{
           technique_id: technique_id,
           tactic_id: tactic_id,
           tactic_name: get_in(@tactics, [tactic_id, :name]) || "Unknown",
           rule_count: length(rules),
           rules: rules,
           detection_count: detections,
           coverage_level: coverage_level(length(rules), detections),
           has_detection: length(rules) > 0,
           has_fired: detections > 0
         }}
      end)
      |> Map.new()

    # 4. Build per-tactic summary
    tactics =
      @tactics
      |> Enum.map(fn {tactic_id, tactic_info} ->
        tactic_techniques =
          techniques
          |> Enum.filter(fn {_, t} -> t.tactic_id == tactic_id end)
          |> Enum.map(fn {_, t} -> t end)

        total = length(tactic_techniques)
        covered = Enum.count(tactic_techniques, & &1.has_detection)
        fired = Enum.count(tactic_techniques, & &1.has_fired)

        {tactic_id,
         %{
           tactic_id: tactic_id,
           name: tactic_info.name,
           order: tactic_info.order,
           total_techniques: total,
           covered_techniques: covered,
           fired_techniques: fired,
           coverage_percentage: if(total > 0, do: Float.round(covered / total * 100, 1), else: 0.0)
         }}
      end)
      |> Map.new()

    %{
      techniques: techniques,
      tactics: tactics,
      generated_at: DateTime.utc_now()
    }
  end

  # ---------------------------------------------------------------------------
  # Rule mapping collection
  # ---------------------------------------------------------------------------

  defp collect_rule_mappings do
    sigma_mappings = collect_sigma_mappings()
    yara_mappings = collect_yara_mappings()
    behavioral_mappings = get_behavioral_mappings()

    # Merge all mappings: technique_id => [%{rule_id, rule_name, source}]
    [sigma_mappings, yara_mappings, behavioral_mappings]
    |> Enum.reduce(%{}, fn mapping, acc ->
      Map.merge(acc, mapping, fn _k, v1, v2 -> v1 ++ v2 end)
    end)
  end

  defp collect_sigma_mappings do
    # Query sigma rules that have mitre technique tags
    try do
      rules = TamanduaServer.Detection.list_sigma_rules()

      rules
      |> Enum.flat_map(fn rule ->
        techniques = extract_sigma_techniques(rule)
        Enum.map(techniques, fn tech ->
          {tech, %{rule_id: rule.id || rule.name, rule_name: rule.name, source: "sigma"}}
        end)
      end)
      |> Enum.group_by(fn {tech, _} -> tech end, fn {_, rule} -> rule end)
    rescue
      _ -> %{}
    end
  end

  defp extract_sigma_techniques(rule) do
    tags = Map.get(rule, :tags, []) ++ Map.get(rule, "tags", [])

    tags
    |> List.wrap()
    |> Enum.filter(fn tag ->
      tag = to_string(tag)
      String.starts_with?(tag, "attack.t") or String.match?(tag, ~r/^T\d{4}/i)
    end)
    |> Enum.map(fn tag ->
      tag
      |> to_string()
      |> String.replace_leading("attack.", "")
      |> String.upcase()
    end)
  end

  defp collect_yara_mappings do
    try do
      rules = TamanduaServer.Detection.list_yara_rules()

      rules
      |> Enum.flat_map(fn rule ->
        techniques = extract_yara_techniques(rule)
        Enum.map(techniques, fn tech ->
          {tech, %{rule_id: rule.name, rule_name: rule.name, source: "yara"}}
        end)
      end)
      |> Enum.group_by(fn {tech, _} -> tech end, fn {_, rule} -> rule end)
    rescue
      _ -> %{}
    end
  end

  defp extract_yara_techniques(rule) do
    metadata = Map.get(rule, :metadata, %{}) || Map.get(rule, "metadata", %{}) || %{}

    # YARA rules may have mitre_technique or mitre_attack metadata
    [
      Map.get(metadata, "mitre_technique", ""),
      Map.get(metadata, "mitre_attack", ""),
      Map.get(metadata, :mitre_technique, ""),
      Map.get(metadata, :mitre_attack, "")
    ]
    |> Enum.flat_map(fn val ->
      val
      |> to_string()
      |> String.split([",", " ", ";"], trim: true)
      |> Enum.map(&String.trim/1)
      |> Enum.filter(&String.match?(&1, ~r/^T\d{4}/i))
      |> Enum.map(&String.upcase/1)
    end)
    |> Enum.uniq()
  end

  # Behavioral detections — hardcoded mappings from our detection modules
  defp get_behavioral_mappings do
    %{
      # Execution (TA0002)
      "T1059" => [%{rule_id: "cmd_shell", rule_name: "Shell Command Execution", source: "behavioral"}],
      "T1059.001" => [%{rule_id: "powershell_exec", rule_name: "PowerShell Script Execution", source: "behavioral"}],
      "T1059.003" => [%{rule_id: "cmd_exec", rule_name: "CMD.EXE Command Execution", source: "behavioral"}],
      "T1203" => [%{rule_id: "exploit_public", rule_name: "Exploitation of Public Vulnerability", source: "behavioral"}],
      "T1559.001" => [%{rule_id: "com_invoke", rule_name: "COM Object Execution", source: "behavioral"}],

      # Persistence (TA0003)
      "T1547.001" => [%{rule_id: "registry_run", rule_name: "Registry Run Key Modification", source: "behavioral"}],
      "T1547.004" => [%{rule_id: "winlogon_notify", rule_name: "Winlogon Notification", source: "behavioral"}],
      "T1543.003" => [%{rule_id: "service_install", rule_name: "Service Installation", source: "behavioral"}],
      "T1136.001" => [%{rule_id: "local_account", rule_name: "Local Account Creation", source: "behavioral"}],
      "T1546.001" => [%{rule_id: "hook_winlogon", rule_name: "Winlogon Hook", source: "behavioral"}],
      "T1574.001" => [%{rule_id: "dll_hijack", rule_name: "DLL Hijacking", source: "behavioral"}],
      "T1574.011" => [%{rule_id: "cwd_dll_load", rule_name: "CWD DLL Loading", source: "behavioral"}],

      # Privilege Escalation (TA0004)
      "T1548.002" => [%{rule_id: "runas_exec", rule_name: "RunAs Token Elevation", source: "behavioral"}],
      "T1134.001" => [%{rule_id: "token_impersonate", rule_name: "Token Impersonation", source: "behavioral"}],
      "T1068" => [%{rule_id: "exploit_privesc", rule_name: "Privilege Escalation Exploit", source: "behavioral"}],
      "T1055" => [%{rule_id: "process_inject", rule_name: "Process Injection", source: "behavioral"}],
      "T1055.001" => [%{rule_id: "dll_inject", rule_name: "DLL Injection", source: "behavioral"}],
      "T1055.002" => [%{rule_id: "portable_executable_inject", rule_name: "Portable Executable Injection", source: "behavioral"}],
      "T1055.012" => [%{rule_id: "process_hollow", rule_name: "Process Hollowing", source: "behavioral"}],

      # Defense Evasion (TA0005)
      "T1027" => [%{rule_id: "obfuscated_code", rule_name: "Obfuscated Code Detection", source: "behavioral"}],
      "T1027.005" => [%{rule_id: "indicator_removal", rule_name: "Indicator Removal", source: "behavioral"}],
      "T1562.001" => [%{rule_id: "amsi_bypass", rule_name: "AMSI Bypass", source: "behavioral"}],
      "T1562.006" => [%{rule_id: "etw_tamper", rule_name: "ETW Tampering", source: "behavioral"}],
      "T1070.001" => [%{rule_id: "eventlog_tamper", rule_name: "Event Log Tampering", source: "behavioral"}],
      "T1036" => [%{rule_id: "masquerading", rule_name: "Masquerading Detection", source: "behavioral"}],
      "T1218.001" => [%{rule_id: "compcache", rule_name: "Compiled HTML Abuse", source: "behavioral"}],
      "T1218.003" => [%{rule_id: "wmic_exec", rule_name: "WMIC Execution", source: "behavioral"}],
      "T1218.005" => [%{rule_id: "mshta_exec", rule_name: "MSHTA Execution", source: "behavioral"}],
      "T1218.011" => [%{rule_id: "rundll32_exec", rule_name: "Rundll32 Execution", source: "behavioral"}],
      "T1112" => [%{rule_id: "registry_modify", rule_name: "Registry Modification", source: "behavioral"}],
      "T1140" => [%{rule_id: "deobfuscate", rule_name: "Deobfuscation Detection", source: "behavioral"}],
      "T1620" => [%{rule_id: "reflective_load", rule_name: "Reflective Code Loading", source: "behavioral"}],
      "T1564" => [%{rule_id: "hide_artifacts", rule_name: "Hidden Files/Artifacts", source: "behavioral"}],

      # Credential Access (TA0006)
      "T1003" => [%{rule_id: "credential_dump", rule_name: "Credential Dumping", source: "behavioral"}],
      "T1003.001" => [%{rule_id: "lsass_dump", rule_name: "LSASS Memory Dump", source: "behavioral"}],
      "T1003.002" => [%{rule_id: "sam_access", rule_name: "SAM Database Access", source: "behavioral"}],
      "T1003.003" => [%{rule_id: "ntds_dump", rule_name: "NTDS.DIT Dump", source: "behavioral"}],
      "T1110.003" => [%{rule_id: "password_spray", rule_name: "Password Spraying", source: "behavioral"}],
      "T1557" => [%{rule_id: "mitm_relay", rule_name: "MITM/Relay Attack", source: "behavioral"}],
      "T1558.003" => [%{rule_id: "kerberoast", rule_name: "Kerberoasting", source: "behavioral"}],
      "T1555" => [%{rule_id: "browser_cred", rule_name: "Browser Credential Theft", source: "behavioral"}],
      "T1056.001" => [%{rule_id: "keylogger", rule_name: "Keylogger Detection", source: "behavioral"}],

      # Discovery (TA0007)
      "T1087" => [%{rule_id: "account_enum", rule_name: "Account Enumeration", source: "behavioral"}],
      "T1082" => [%{rule_id: "system_info", rule_name: "System Information Discovery", source: "behavioral"}],
      "T1083" => [%{rule_id: "file_enum", rule_name: "File and Directory Discovery", source: "behavioral"}],
      "T1057" => [%{rule_id: "process_enum", rule_name: "Process Discovery", source: "behavioral"}],
      "T1018" => [%{rule_id: "remote_system_enum", rule_name: "Remote System Discovery", source: "behavioral"}],
      "T1049" => [%{rule_id: "network_enum", rule_name: "Network Enumeration", source: "behavioral"}],
      "T1016" => [%{rule_id: "network_config", rule_name: "Network Configuration Discovery", source: "behavioral"}],
      "T1135" => [%{rule_id: "network_share_enum", rule_name: "Network Share Discovery", source: "behavioral"}],
      "T1069" => [%{rule_id: "group_enum", rule_name: "Group Enumeration", source: "behavioral"}],
      "T1012" => [%{rule_id: "query_registry", rule_name: "Query Registry", source: "behavioral"}],

      # Lateral Movement (TA0008)
      "T1021.001" => [%{rule_id: "lateral_rdp", rule_name: "Lateral Movement via RDP", source: "behavioral"}],
      "T1021.002" => [%{rule_id: "lateral_smb", rule_name: "Lateral Movement via SMB", source: "behavioral"}],
      "T1021.006" => [%{rule_id: "lateral_winrm", rule_name: "Lateral Movement via WinRM", source: "behavioral"}],
      "T1570" => [%{rule_id: "remote_file_copy", rule_name: "Remote File Copy", source: "behavioral"}],
      "T1570" => [%{rule_id: "remote_file_copy", rule_name: "Remote File Copy via Network", source: "behavioral"}],

      # Collection (TA0009)
      "T1005" => [%{rule_id: "honeyfile", rule_name: "Honeyfile Access (Deception)", source: "deception"}],
      "T1039" => [%{rule_id: "data_stage", rule_name: "Data Staging", source: "behavioral"}],
      "T1074" => [%{rule_id: "data_collect", rule_name: "Data Collection", source: "behavioral"}],
      "T1115" => [%{rule_id: "clipboard", rule_name: "Clipboard Access", source: "behavioral"}],
      "T1123" => [%{rule_id: "audio_capture", rule_name: "Audio Capture", source: "behavioral"}],
      "T1119" => [%{rule_id: "screen_capture", rule_name: "Screen Capture", source: "behavioral"}],
      "T1113" => [%{rule_id: "screen_capture2", rule_name: "Screenshot", source: "behavioral"}],
      "T1005" => [%{rule_id: "data_local", rule_name: "Data from Local System", source: "behavioral"}],

      # Command and Control (TA0011)
      "T1071" => [%{rule_id: "c2_beacon", rule_name: "C2 Beacon Detection", source: "behavioral"}],
      "T1071.001" => [%{rule_id: "c2_http", rule_name: "C2 over HTTP/S", source: "behavioral"}],
      "T1071.004" => [%{rule_id: "c2_dns", rule_name: "C2 over DNS", source: "behavioral"}],
      "T1092" => [%{rule_id: "c2_multi_stage", rule_name: "Multi-stage Channels", source: "behavioral"}],
      "T1571" => [%{rule_id: "c2_non_standard", rule_name: "Non-Standard Port C2", source: "behavioral"}],
      "T1573" => [%{rule_id: "c2_encrypted", rule_name: "Encrypted C2 Channel", source: "behavioral"}],
      "T1573.001" => [%{rule_id: "c2_symmetric", rule_name: "Symmetric C2 Encryption", source: "behavioral"}],
      "T1568" => [%{rule_id: "c2_dynamic", rule_name: "Dynamic C2 Resolution", source: "behavioral"}],
      "T1568.002" => [%{rule_id: "c2_dga", rule_name: "DGA Detection", source: "behavioral"}],
      "T1008" => [%{rule_id: "c2_fallback", rule_name: "C2 Fallback Channels", source: "behavioral"}],
      "T1090" => [%{rule_id: "proxy_traffic", rule_name: "Proxy Usage", source: "behavioral"}],
      "T1090.004" => [%{rule_id: "c2_domain_fronting", rule_name: "Domain Fronting", source: "behavioral"}],
      "T1219" => [%{rule_id: "remote_access", rule_name: "Remote Access Tool", source: "behavioral"}],

      # Exfiltration (TA0010)
      "T1020" => [%{rule_id: "data_exfil", rule_name: "Data Exfiltration", source: "behavioral"}],
      "T1041" => [%{rule_id: "exfil_c2", rule_name: "Exfiltration over C2", source: "behavioral"}],
      "T1048" => [%{rule_id: "exfil_covert", rule_name: "Covert Exfiltration", source: "behavioral"}],
      "T1567" => [%{rule_id: "exfil_web_svc", rule_name: "Exfiltration to Web Service", source: "behavioral"}],

      # Impact (TA0040)
      "T1486" => [%{rule_id: "ransomware", rule_name: "Ransomware Detection", source: "behavioral"}],
      "T1561" => [%{rule_id: "disk_wipe", rule_name: "Disk Wipe", source: "behavioral"}],
      "T1485" => [%{rule_id: "data_destroy", rule_name: "Data Destruction", source: "behavioral"}],
      "T1490" => [%{rule_id: "vss_delete", rule_name: "Shadow Copy Deletion", source: "behavioral"}],
      "T1529" => [%{rule_id: "system_shutdown", rule_name: "System Shutdown/Reboot", source: "behavioral"}],
      "T1491" => [%{rule_id: "defacement", rule_name: "Website Defacement", source: "behavioral"}],

      # Identity Threats (Credential Access sub-techniques)
      "T1550.002" => [%{rule_id: "pass_the_hash", rule_name: "Pass-the-Hash", source: "behavioral"}],
      "T1550.003" => [%{rule_id: "pass_the_ticket", rule_name: "Pass-the-Ticket", source: "behavioral"}]
    }
  end

  # ---------------------------------------------------------------------------
  # Alert counts per technique
  # ---------------------------------------------------------------------------

  defp collect_alert_technique_counts do
    try do
      # Query alerts and extract MITRE techniques from their metadata
      query =
        from a in "alerts",
          where: not is_nil(a.mitre_techniques),
          select: a.mitre_techniques

      Repo.all(query)
      |> Enum.flat_map(fn techniques ->
        case techniques do
          list when is_list(list) -> list
          str when is_binary(str) -> String.split(str, [",", ";"], trim: true)
          _ -> []
        end
      end)
      |> Enum.map(&String.trim(&1))
      |> Enum.filter(&String.match?(&1, ~r/^T\d{4}/i))
      |> Enum.map(&String.upcase/1)
      |> Enum.frequencies()
    rescue
      _ -> %{}
    end
  end

  # ---------------------------------------------------------------------------
  # Coverage level classification
  # ---------------------------------------------------------------------------

  defp coverage_level(rule_count, detection_count) do
    cond do
      rule_count >= 3 and detection_count > 0 -> "excellent"
      rule_count >= 2 and detection_count > 0 -> "good"
      rule_count >= 1 and detection_count > 0 -> "active"
      rule_count >= 1 -> "covered"
      true -> "gap"
    end
  end

  # ---------------------------------------------------------------------------
  # Extract gaps
  # ---------------------------------------------------------------------------

  defp extract_gaps(nil), do: []

  defp extract_gaps(coverage) do
    coverage.techniques
    |> Enum.filter(fn {_, t} -> t.coverage_level == "gap" end)
    |> Enum.map(fn {_, t} ->
      %{
        technique_id: t.technique_id,
        tactic_id: t.tactic_id,
        tactic_name: t.tactic_name
      }
    end)
    |> Enum.sort_by(& &1.tactic_id)
  end

  # ---------------------------------------------------------------------------
  # Summary
  # ---------------------------------------------------------------------------

  defp build_summary(nil), do: %{total: 0, covered: 0, gaps: 0, coverage_pct: 0.0}

  defp build_summary(coverage) do
    total = map_size(coverage.techniques)
    covered = Enum.count(coverage.techniques, fn {_, t} -> t.has_detection end)
    fired = Enum.count(coverage.techniques, fn {_, t} -> t.has_fired end)
    gaps = total - covered

    tactic_summary =
      coverage.tactics
      |> Enum.sort_by(fn {_, t} -> t.order end)
      |> Enum.map(fn {_, t} ->
        %{
          tactic_id: t.tactic_id,
          name: t.name,
          coverage: t.coverage_percentage,
          covered: t.covered_techniques,
          total: t.total_techniques
        }
      end)

    %{
      total_techniques: total,
      covered_techniques: covered,
      active_techniques: fired,
      gap_techniques: gaps,
      overall_coverage_pct: if(total > 0, do: Float.round(covered / total * 100, 1), else: 0.0),
      active_coverage_pct: if(total > 0, do: Float.round(fired / total * 100, 1), else: 0.0),
      tactics: tactic_summary,
      generated_at: coverage.generated_at
    }
  end

  # ---------------------------------------------------------------------------
  # Scheduling
  # ---------------------------------------------------------------------------

  defp schedule_refresh do
    Process.send_after(self(), :refresh, @refresh_interval_ms)
  end
end
