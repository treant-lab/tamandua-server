defmodule TamanduaServer.Detection.Correlator do
  @moduledoc """
  Behavioral correlation engine for detecting attack patterns.

  Builds and analyzes:
  - Process trees (parent-child relationships)
  - Attack graphs (event sequences)
  - Temporal correlations

  Uses libgraph for graph operations and ETS for fast lookups.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Detection.{Config, EventTypes, Evidence, TemporalScorer}
  alias TamanduaServer.Agents.OrgLookup

  @table_name :correlation_events
  @process_tree_table :process_trees
  @cross_endpoint_table :cross_endpoint_correlations
  @correlation_cache_table :correlation_cache

  # Maximum entries in the correlation cache before eviction
  @correlation_cache_max_entries 100_000
  # Safety valve: per-agent process tree graphs are never pruned on process exit,
  # so they grow for the life of an agent connection. Evict an agent's whole tree
  # if its vertex count exceeds this generous bound (well above any normal
  # workload) to prevent unbounded memory growth on long-lived/high-churn agents.
  @process_tree_max_vertices 50_000
  # TTL for correlation cache entries: 1 hour in milliseconds
  @correlation_cache_ttl_ms :timer.hours(1)

  # Weighted scoring system for behavioral correlation
  @correlation_weights %{
    same_process: 100,        # Same PID on same agent
    parent_child: 80,         # Direct parent-child relationship
    same_file_hash: 70,       # Same file involved
    same_network_dest: 50,    # Same destination IP/domain
    same_user_session: 30,    # Same user account
    sibling_process: 25,      # Same parent PID
    temporal_5s: 20,          # Within 5 seconds
    temporal_30s: 15,         # Within 30 seconds
    temporal_1m: 10,          # Within 1 minute
    temporal_5m: 5            # Within 5 minutes
  }

  # Suspicious process chains (LOLBAS patterns)
  # NOTE: These patterns are common in legitimate enterprise automation (e.g.,
  # Office macros launching scripts for data processing, browser-based installers,
  # IT admin tooling). They are kept for detection but should be correlated with
  # additional context (e.g., user role, time of day, script content) before
  # escalating to high-severity alerts.
  #
  # Each chain pattern maps to MITRE ATT&CK techniques and tactics for accurate
  # detection classification.

  # MITRE ATT&CK mapping for process chain patterns
  # Key: {parent_pattern, child_pattern} -> %{techniques: [...], tactics: [...], description: "..."}
  @chain_to_mitre %{
    # Office macros spawning shells - Initial Access via Spearphishing + Execution
    {:office_shell, {~r/(?:WINWORD|EXCEL|POWERPNT|OUTLOOK)\.EXE$/i, ~r/(?:cmd|powershell|pwsh)\.exe$/i}} =>
      %{
        techniques: ["T1059.001", "T1204.002"],
        tactics: ["execution", "initial_access"],
        description: "Office application spawned command shell (possible macro execution)"
      },

    # Office spawning script hosts - Execution via scripting
    {:office_script, {~r/(?:WINWORD|EXCEL|POWERPNT|OUTLOOK)\.EXE$/i, ~r/(?:wscript|cscript)\.exe$/i}} =>
      %{
        techniques: ["T1059.005", "T1204.002"],
        tactics: ["execution", "initial_access"],
        description: "Office application spawned script host (possible VBScript/JScript execution)"
      },

    # Browser exploits - Drive-by Compromise + Execution
    {:browser_shell, {~r/(?:chrome|firefox|msedge|iexplore)\.exe$/i, ~r/(?:cmd|powershell|pwsh)\.exe$/i}} =>
      %{
        techniques: ["T1189", "T1059.001"],
        tactics: ["initial_access", "execution"],
        description: "Browser spawned command shell (possible drive-by compromise)"
      },

    # Shell -> Certutil (LOLBin for download and decode)
    {:shell_certutil, {~r/(?:cmd|powershell)\.exe$/i, ~r/certutil\.exe$/i}} =>
      %{
        techniques: ["T1105", "T1140"],
        tactics: ["command_and_control", "defense_evasion"],
        description: "Shell spawned certutil (possible file download or decode)"
      },

    # Shell -> BitsAdmin (LOLBin for download and persistence)
    {:shell_bitsadmin, {~r/(?:cmd|powershell)\.exe$/i, ~r/bitsadmin\.exe$/i}} =>
      %{
        techniques: ["T1105", "T1197"],
        tactics: ["command_and_control", "persistence"],
        description: "Shell spawned bitsadmin (possible BITS job for download/persistence)"
      },

    # Shell -> MSHTA (Signed binary proxy execution)
    {:shell_mshta, {~r/(?:cmd|powershell)\.exe$/i, ~r/mshta\.exe$/i}} =>
      %{
        techniques: ["T1218.005"],
        tactics: ["defense_evasion"],
        description: "Shell spawned mshta (possible HTA script execution)"
      },

    # Shell -> Rundll32 (Signed binary proxy execution)
    {:shell_rundll32, {~r/(?:cmd|powershell)\.exe$/i, ~r/rundll32\.exe$/i}} =>
      %{
        techniques: ["T1218.011"],
        tactics: ["defense_evasion"],
        description: "Shell spawned rundll32 (possible DLL proxy execution)"
      },

    # Shell -> Regsvr32 (Squiblydoo - Signed binary proxy execution)
    {:shell_regsvr32, {~r/(?:cmd|powershell)\.exe$/i, ~r/regsvr32\.exe$/i}} =>
      %{
        techniques: ["T1218.010"],
        tactics: ["defense_evasion"],
        description: "Shell spawned regsvr32 (possible COM scriptlet execution)"
      },

    # Shell -> WMIC (WMI execution)
    {:shell_wmic, {~r/(?:cmd|powershell)\.exe$/i, ~r/wmic\.exe$/i}} =>
      %{
        techniques: ["T1047"],
        tactics: ["execution"],
        description: "Shell spawned wmic (possible WMI command execution)"
      },

    # Any -> Rundll32 (generic - less specific pattern)
    {:any_rundll32, {~r/.*/, ~r/rundll32\.exe$/i}} =>
      %{
        techniques: ["T1218.011"],
        tactics: ["defense_evasion"],
        description: "Process spawned rundll32 (possible DLL proxy execution)"
      },

    # Any -> Regsvr32 (generic - less specific pattern)
    {:any_regsvr32, {~r/.*/, ~r/regsvr32\.exe$/i}} =>
      %{
        techniques: ["T1218.010"],
        tactics: ["defense_evasion"],
        description: "Process spawned regsvr32 (possible COM scriptlet execution)"
      },

    # Credential access tools
    {:any_mimikatz, {~r/.*/, ~r/mimikatz\.exe$/i}} =>
      %{
        techniques: ["T1003.001"],
        tactics: ["credential_access"],
        description: "Mimikatz execution detected (credential dumping)"
      },

    {:any_procdump, {~r/.*/, ~r/procdump(?:64)?\.exe$/i}} =>
      %{
        techniques: ["T1003.001"],
        tactics: ["credential_access"],
        description: "ProcDump execution detected (possible LSASS memory dump)"
      },

    # Lateral movement tools
    {:any_psexec, {~r/.*/, ~r/psexec(?:64)?\.exe$/i}} =>
      %{
        techniques: ["T1570", "T1021.002"],
        tactics: ["lateral_movement"],
        description: "PsExec execution detected (possible lateral movement)"
      },

    {:any_wmiexec, {~r/.*/, ~r/wmiexec\.exe$/i}} =>
      %{
        techniques: ["T1047", "T1021.003"],
        tactics: ["execution", "lateral_movement"],
        description: "WMIExec execution detected (possible lateral movement)"
      },

    # Remote access tools via shell
    {:shell_mstsc, {~r/(?:cmd|powershell)\.exe$/i, ~r/mstsc\.exe$/i}} =>
      %{
        techniques: ["T1021.001"],
        tactics: ["lateral_movement"],
        description: "Shell spawned RDP client (possible lateral movement)"
      },

    # Scheduled task creation for persistence
    {:shell_schtasks, {~r/(?:cmd|powershell)\.exe$/i, ~r/schtasks\.exe$/i}} =>
      %{
        techniques: ["T1053.005"],
        tactics: ["persistence", "execution"],
        description: "Shell spawned schtasks (possible scheduled task persistence)"
      },

    # Service creation for persistence
    {:shell_sc, {~r/(?:cmd|powershell)\.exe$/i, ~r/sc\.exe$/i}} =>
      %{
        techniques: ["T1543.003"],
        tactics: ["persistence", "privilege_escalation"],
        description: "Shell spawned sc.exe (possible service creation)"
      },

    # Registry modification for persistence
    {:shell_reg, {~r/(?:cmd|powershell)\.exe$/i, ~r/reg\.exe$/i}} =>
      %{
        techniques: ["T1547.001", "T1112"],
        tactics: ["persistence", "defense_evasion"],
        description: "Shell spawned reg.exe (possible registry modification)"
      },

    # Network discovery
    {:shell_net, {~r/(?:cmd|powershell)\.exe$/i, ~r/net\.exe$/i}} =>
      %{
        techniques: ["T1087.001", "T1087.002"],
        tactics: ["discovery"],
        description: "Shell spawned net.exe (possible account/group enumeration)"
      },

    # Archive creation for data staging
    {:shell_archive, {~r/(?:cmd|powershell)\.exe$/i, ~r/(?:7z|rar|zip|tar)\.exe$/i}} =>
      %{
        techniques: ["T1560.001"],
        tactics: ["collection"],
        description: "Shell spawned archive utility (possible data staging)"
      }
  }

  # Extract just the patterns for backwards compatibility with existing chain checks
  @suspicious_chains (
    @chain_to_mitre
    |> Enum.map(fn {_key, %{techniques: _, tactics: _}} = entry ->
      {key, _mitre} = entry
      {_name, {parent_pattern, child_pattern}} = key
      {parent_pattern, child_pattern}
    end)
    |> Enum.uniq()
  )

  # Multi-hop attack sequences (2+ processes in a chain)
  # These detect common attack patterns that span multiple process generations.
  # Each pattern is a list of regexes that must match consecutively in a process chain.
  # Unlike @suspicious_chains which only checks parent->child pairs, these patterns
  # can match across multiple generations (e.g., grandparent->parent->child).
  @attack_sequences [
    # Office macro execution chain - classic malicious document attack (3-hop)
    %{
      pattern: [~r/(?:WINWORD|EXCEL|POWERPNT)\.EXE$/i, ~r/cmd\.exe$/i, ~r/powershell\.exe$/i],
      mitre: ["T1059.001", "T1204.002"],
      severity: :critical,
      description: "Office spawned cmd then PowerShell (macro execution chain)"
    },
    # Office to shell to download utility - document-based payload delivery (3-hop)
    %{
      pattern: [~r/(?:WINWORD|EXCEL|POWERPNT)\.EXE$/i, ~r/(?:cmd|powershell)\.exe$/i, ~r/(?:certutil|bitsadmin|curl|wget)\.exe$/i],
      mitre: ["T1105", "T1204.002", "T1218"],
      severity: :critical,
      description: "Office spawned shell then download utility (payload delivery)"
    },
    # Explorer to cmd to reconnaissance tools (3-hop)
    %{
      pattern: [~r/explorer\.exe$/i, ~r/cmd\.exe$/i, ~r/(?:whoami|net|ipconfig|systeminfo|nltest|quser|query)\.exe$/i],
      mitre: ["T1059.003", "T1082", "T1016", "T1033"],
      severity: :high,
      description: "Explorer spawned cmd then reconnaissance tool"
    },
    # Shell to PowerShell to LOLBin execution (3-hop)
    %{
      pattern: [~r/cmd\.exe$/i, ~r/powershell\.exe$/i, ~r/(?:certutil|rundll32|regsvr32|mshta)\.exe$/i],
      mitre: ["T1059.001", "T1218"],
      severity: :critical,
      description: "cmd spawned PowerShell then LOLBin (evasion chain)"
    },
    # Browser exploit chain - drive-by download attack (3-hop)
    %{
      pattern: [~r/(?:chrome|firefox|msedge|iexplore)\.exe$/i, ~r/(?:cmd|powershell)\.exe$/i, ~r/(?:certutil|bitsadmin|mshta|rundll32)\.exe$/i],
      mitre: ["T1189", "T1105", "T1218"],
      severity: :critical,
      description: "Browser spawned shell then download/execution utility"
    },
    # Outlook email attachment attack chain - phishing (3-hop)
    %{
      pattern: [~r/OUTLOOK\.EXE$/i, ~r/(?:WINWORD|EXCEL|POWERPNT)\.EXE$/i, ~r/(?:cmd|powershell)\.exe$/i],
      mitre: ["T1566.001", "T1204.002", "T1059"],
      severity: :critical,
      description: "Outlook opened Office doc that spawned shell (phishing chain)"
    },
    # Full phishing chain with payload download (4-hop)
    %{
      pattern: [~r/OUTLOOK\.EXE$/i, ~r/(?:WINWORD|EXCEL|POWERPNT)\.EXE$/i, ~r/(?:cmd|powershell)\.exe$/i, ~r/(?:certutil|bitsadmin|curl)\.exe$/i],
      mitre: ["T1566.001", "T1204.002", "T1059", "T1105"],
      severity: :critical,
      description: "Outlook -> Office -> shell -> download (full phishing chain)"
    },
    # WMI lateral movement chain (2-hop)
    %{
      pattern: [~r/wmiprvse\.exe$/i, ~r/(?:cmd|powershell)\.exe$/i],
      mitre: ["T1047", "T1059"],
      severity: :high,
      description: "WMI provider spawned shell (lateral movement indicator)"
    },
    # Service-based persistence chain (2-hop)
    %{
      pattern: [~r/services\.exe$/i, ~r/(?:cmd|powershell)\.exe$/i],
      mitre: ["T1543.003", "T1059"],
      severity: :high,
      description: "Service spawned shell (persistence mechanism)"
    },
    # Scheduled task execution chain (2-hop)
    %{
      pattern: [~r/(?:taskeng|schtasks|taskhost)\.exe$/i, ~r/(?:cmd|powershell)\.exe$/i],
      mitre: ["T1053.005", "T1059"],
      severity: :high,
      description: "Scheduled task spawned shell (persistence)"
    },
    # MSHTA script execution chain (2-hop)
    %{
      pattern: [~r/mshta\.exe$/i, ~r/(?:cmd|powershell|wscript|cscript)\.exe$/i],
      mitre: ["T1218.005", "T1059"],
      severity: :high,
      description: "MSHTA spawned script interpreter"
    },
    # MSHTA to shell to payload (3-hop)
    %{
      pattern: [~r/mshta\.exe$/i, ~r/(?:cmd|powershell)\.exe$/i, ~r/(?:certutil|bitsadmin|rundll32)\.exe$/i],
      mitre: ["T1218.005", "T1059", "T1105"],
      severity: :critical,
      description: "MSHTA spawned shell then download utility"
    },
    # WScript/CScript to shell to payload (3-hop)
    %{
      pattern: [~r/(?:wscript|cscript)\.exe$/i, ~r/(?:cmd|powershell)\.exe$/i, ~r/(?:certutil|bitsadmin|rundll32)\.exe$/i],
      mitre: ["T1059.005", "T1059.001", "T1105"],
      severity: :critical,
      description: "Script host spawned shell then download utility"
    }
  ]

  # ============================================================================
  # Command-line Argument Analysis Patterns
  # ============================================================================
  #
  # These patterns analyze BOTH the process name AND command-line arguments
  # to detect known attack techniques with higher confidence. Each pattern
  # includes a risk score boost that increases the overall threat assessment
  # when combined with parent-child chain analysis.
  #
  # The boost values represent the additional risk score added when a pattern
  # matches (0.0 to 1.0 scale, where 1.0 = maximum risk).

  @cmdline_suspicious_patterns [
    # PowerShell Encoded Command - T1059.001/T1027
    %{
      process: ~r/powershell\.exe$/i,
      cmdline: ~r/-(?:enc|encodedcommand)\s/i,
      boost: 0.3,
      mitre: ["T1059.001", "T1027"],
      description: "Encoded PowerShell execution"
    },
    # PowerShell Hidden Window - T1059.001/T1564.003
    %{
      process: ~r/powershell\.exe$/i,
      cmdline: ~r/-(?:nop|noprofile)\s.*-(?:w|window)\s*(?:hidden|1)/i,
      boost: 0.25,
      mitre: ["T1059.001", "T1564.003"],
      description: "Hidden PowerShell execution"
    },
    # PowerShell Download Cradle - T1059.001/T1105
    %{
      process: ~r/powershell\.exe$/i,
      cmdline: ~r/(?:iex|invoke-expression|downloadstring|downloadfile|webclient|bitstransfer|invoke-webrequest|curl|wget)/i,
      boost: 0.3,
      mitre: ["T1059.001", "T1105"],
      description: "PowerShell download cradle"
    },
    # PowerShell Execution Policy Bypass - T1059.001/T1562.001
    %{
      process: ~r/powershell\.exe$/i,
      cmdline: ~r/(?:-ep\s*(?:bypass|unrestricted)|-executionpolicy\s*(?:bypass|unrestricted))/i,
      boost: 0.2,
      mitre: ["T1059.001", "T1562.001"],
      description: "PowerShell execution policy bypass"
    },
    # PowerShell AMSI Bypass - T1562.001
    %{
      process: ~r/powershell\.exe$/i,
      cmdline: ~r/(?:amsiutils|amsiinitfailed|amsi\.dll|setpreference.*disable)/i,
      boost: 0.35,
      mitre: ["T1562.001"],
      description: "Potential AMSI bypass attempt"
    },
    # Certutil Download - T1105/T1218
    %{
      process: ~r/certutil\.exe$/i,
      cmdline: ~r/-(?:urlcache|split)\s.*-f\s/i,
      boost: 0.25,
      mitre: ["T1105", "T1218"],
      description: "Certutil file download"
    },
    # Certutil Base64 Decode - T1140/T1218
    %{
      process: ~r/certutil\.exe$/i,
      cmdline: ~r/-(?:decode|decodehex)\s/i,
      boost: 0.25,
      mitre: ["T1140", "T1218"],
      description: "Certutil base64 decode"
    },
    # MSHTA Script/URL Execution - T1218.005
    %{
      process: ~r/mshta\.exe$/i,
      cmdline: ~r/(?:javascript|vbscript|http|https|file:)/i,
      boost: 0.35,
      mitre: ["T1218.005"],
      description: "MSHTA script/URL execution"
    },
    # Rundll32 Suspicious DLL - T1218.011
    %{
      process: ~r/rundll32\.exe$/i,
      cmdline: ~r/(?:javascript|vbscript|shell32.*shellexec|url\.dll|zipfldr|advpack)/i,
      boost: 0.3,
      mitre: ["T1218.011"],
      description: "Rundll32 suspicious DLL/script"
    },
    # Regsvr32 Scriptlet (Squiblydoo) - T1218.010
    %{
      process: ~r/regsvr32\.exe$/i,
      cmdline: ~r/(?:\/s.*\/i:http|\/s.*\/i:https|\/s.*\/n.*\/i:|scrobj\.dll)/i,
      boost: 0.3,
      mitre: ["T1218.010"],
      description: "Regsvr32 scriptlet execution (Squiblydoo)"
    },
    # WMIC Process Creation - T1047
    %{
      process: ~r/wmic\.exe$/i,
      cmdline: ~r/(?:process\s+call\s+create|\/node:|\/format:)/i,
      boost: 0.25,
      mitre: ["T1047", "T1218"],
      description: "WMIC process creation or remote execution"
    },
    # BitsAdmin Transfer - T1197/T1105
    %{
      process: ~r/bitsadmin\.exe$/i,
      cmdline: ~r/(?:\/transfer|\/create|\/addfile|\/setnotifycmdline|\/resume)/i,
      boost: 0.25,
      mitre: ["T1197", "T1105"],
      description: "BitsAdmin file transfer or persistence"
    },
    # System Reconnaissance - T1033/T1082/T1016
    %{
      process: ~r/(?:cmd|powershell)\.exe$/i,
      cmdline: ~r/(?:whoami\s*\/|net\s+user|net\s+group|net\s+localgroup|systeminfo|ipconfig\s+\/all|hostname|quser|query\s+user)/i,
      boost: 0.15,
      mitre: ["T1033", "T1082", "T1016"],
      description: "System reconnaissance commands"
    },
    # Registry Query/Modification - T1012/T1112
    %{
      process: ~r/(?:cmd|powershell|reg)\.exe$/i,
      cmdline: ~r/(?:reg\s+(?:query|add|delete|export|save)|regedit\s+\/s)/i,
      boost: 0.2,
      mitre: ["T1012", "T1112"],
      description: "Registry query/modification"
    },
    # Scheduled Task Creation - T1053.005
    %{
      process: ~r/(?:cmd|powershell|schtasks)\.exe$/i,
      cmdline: ~r/schtasks\s+.*(?:\/create|\/change|\/run)/i,
      boost: 0.2,
      mitre: ["T1053.005"],
      description: "Scheduled task creation/modification"
    },
    # Service Creation/Modification - T1543.003
    %{
      process: ~r/(?:cmd|powershell|sc)\.exe$/i,
      cmdline: ~r/sc\s+.*(?:create|config|start|delete)\s/i,
      boost: 0.2,
      mitre: ["T1543.003"],
      description: "Service creation/modification"
    },
    # Shadow Copy Deletion - T1490 (Ransomware indicator)
    %{
      process: ~r/(?:cmd|powershell|vssadmin|wmic|wbadmin)\.exe$/i,
      cmdline: ~r/(?:vssadmin\s+.*delete|wmic\s+.*shadowcopy|wbadmin\s+.*delete)/i,
      boost: 0.4,
      mitre: ["T1490"],
      description: "Shadow copy/backup deletion (ransomware indicator)"
    },
    # Boot/Recovery Configuration - T1490
    %{
      process: ~r/(?:cmd|powershell|bcdedit)\.exe$/i,
      cmdline: ~r/bcdedit\s+.*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)/i,
      boost: 0.4,
      mitre: ["T1490"],
      description: "Boot/recovery configuration modification"
    },
    # Credential Dumping - T1003
    %{
      process: ~r/.*$/i,
      cmdline: ~r/(?:sekurlsa::logonpasswords|lsadump::sam|privilege::debug.*sekurlsa|mimikatz|procdump.*-ma.*lsass)/i,
      boost: 0.45,
      mitre: ["T1003.001", "T1003.002"],
      description: "Credential dumping activity"
    },
    # Firewall Modification - T1562.004
    %{
      process: ~r/(?:cmd|powershell|netsh)\.exe$/i,
      cmdline: ~r/(?:netsh\s+(?:advfirewall|firewall)\s+.*(?:set|add|delete)|set-netfirewallprofile.*-enabled\s+false)/i,
      boost: 0.25,
      mitre: ["T1562.004"],
      description: "Firewall modification"
    },
    # Windows Defender Exclusion - T1562.001
    %{
      process: ~r/(?:cmd|powershell)\.exe$/i,
      cmdline: ~r/(?:add-mppreference\s+.*-exclusion|set-mppreference\s+.*-disablerealtimemonitoring)/i,
      boost: 0.35,
      mitre: ["T1562.001"],
      description: "Windows Defender exclusion/disable"
    }
  ]

  defstruct [:stats, timelines: %{}]

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Add an event to the correlation engine.
  """
  @spec add_event(map()) :: :ok
  def add_event(event) do
    GenServer.cast(__MODULE__, {:add_event, event})
  end

  @doc """
  Get process tree for an agent.
  """
  @spec get_process_tree(String.t()) :: {:ok, Graph.t()} | {:error, :not_found}
  def get_process_tree(agent_id) do
    # Read directly from ETS (public, read_concurrency: true) to avoid
    # GenServer mailbox congestion during high-volume event ingestion.
    case :ets.lookup(@process_tree_table, agent_id) do
      [{^agent_id, graph}] -> {:ok, graph}
      [] -> {:error, :not_found}
    end
  rescue
    ArgumentError -> {:error, :not_found}
  end

  @doc """
  Get events for a process.
  """
  @spec get_process_events(String.t(), integer()) :: [map()]
  def get_process_events(agent_id, pid) do
    # Read directly from ETS to avoid GenServer mailbox congestion.
    :ets.lookup(@table_name, {agent_id, pid})
    |> Enum.map(fn {_key, event} -> event end)
  rescue
    ArgumentError -> []
  end

  @doc """
  Analyze process chain for suspicious patterns.
  Includes both single-hop (parent->child) and multi-hop attack sequence detection.
  """
  @spec analyze_chain(String.t(), integer()) :: {:ok, [map()]} | {:error, term()}
  def analyze_chain(agent_id, pid) do
    # Bypass GenServer — reads only from ETS (public, read_concurrency: true).
    do_analyze_chain(agent_id, pid)
  rescue
    ArgumentError -> {:error, :not_found}
  end

  @doc """
  Detect multi-hop attack sequences in a process chain.

  This is a specialized function for detecting attack patterns that span
  multiple process generations. It can identify complex attack chains like:
  - cmd -> powershell -> certutil (3-hop)
  - Office -> cmd -> powershell (3-hop macro execution)
  - Outlook -> Office -> cmd -> certutil (4-hop phishing chain)

  Returns a list of matched attack sequences with full chain information.
  """
  @spec analyze_attack_sequences(String.t(), integer()) :: {:ok, [map()]} | {:error, term()}
  def analyze_attack_sequences(agent_id, pid) do
    case get_process_tree(agent_id) do
      {:ok, graph} ->
        ancestors = get_process_ancestry(graph, pid)
        detections = detect_attack_sequences(graph, ancestors, agent_id)
        {:ok, detections}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Get correlation statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Build a storyline (attack timeline) for an agent and process.
  Returns a chronological view of events leading to the current state.
  """
  @spec build_storyline(String.t(), integer()) :: {:ok, map()} | {:error, term()}
  def build_storyline(agent_id, pid) do
    case get_process_tree(agent_id) do
      {:ok, graph} ->
        # Get the process chain (ancestors and the process itself)
        ancestors = get_process_ancestry(graph, pid)

        # Get events for all processes in the chain
        timeline = ancestors
        |> Enum.flat_map(fn process_pid ->
          get_process_events(agent_id, process_pid)
        end)
        |> Enum.sort_by(fn event -> event[:timestamp] || 0 end)

        # Build process info for the chain
        process_chain = ancestors
        |> Enum.map(fn process_pid ->
          labels = Graph.vertex_labels(graph, process_pid)
          info = List.first(labels) || %{}
          Map.put(info, :pid, process_pid)
        end)

        # Analyze the chain for suspicious patterns. analyze_chain/2 can return
        # {:error, :not_found} (ETS read race / missing table); detections are
        # non-critical to the storyline, so degrade to [] instead of crashing.
        detections =
          case analyze_chain(agent_id, pid) do
            {:ok, dets} -> dets
            {:error, _reason} -> []
          end

        storyline = %{
          agent_id: agent_id,
          target_pid: pid,
          process_chain: process_chain,
          timeline: timeline,
          event_count: length(timeline),
          detections: detections,
          suspicious: length(detections) > 0,
          built_at: DateTime.utc_now()
        }

        {:ok, storyline}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Correlate events across multiple processes and agents.
  Finds related events based on temporal proximity and shared attributes.
  """
  @spec correlate_events(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def correlate_events(agent_id, opts \\ []) do
    time_window_ms = Keyword.get(opts, :time_window_ms, :timer.minutes(5))
    limit = Keyword.get(opts, :limit, 100)

    # Get all recent events for this agent from ETS
    all_events = :ets.tab2list(@table_name)
    |> Enum.filter(fn {{a_id, _pid}, _event} -> a_id == agent_id end)
    |> Enum.map(fn {_key, event} -> event end)
    |> Enum.sort_by(fn e -> e[:timestamp] || 0 end, :desc)
    |> Enum.take(limit)

    now = System.system_time(:millisecond)

    # Group events by time windows
    time_groups = all_events
    |> Enum.filter(fn e ->
      ts = e[:timestamp] || 0
      now - ts < time_window_ms
    end)
    |> Enum.group_by(fn e ->
      ts = e[:timestamp] || 0
      div(ts, time_window_ms)
    end)

    # Find correlations within each time window
    correlations = time_groups
    |> Enum.flat_map(fn {_window, events} ->
      find_event_correlations(events)
    end)
    |> Enum.uniq_by(fn c -> {c.event_a_id, c.event_b_id} end)

    # Enrich correlations with temporal proximity scores
    enriched_correlations =
      Enum.map(correlations, fn corr ->
        # Look up timestamps from the events for temporal classification
        e_a = Enum.find(all_events, fn e -> e[:event_id] == corr.event_a_id end)
        e_b = Enum.find(all_events, fn e -> e[:event_id] == corr.event_b_id end)

        ts_a = event_ts_ms(e_a)
        ts_b = event_ts_ms(e_b)

        temporal_proximity = TemporalScorer.classify_proximity(ts_a, ts_b)
        decay_weight = TemporalScorer.time_decay_weight(abs(ts_a - ts_b))

        corr
        |> Map.put(:temporal_proximity, temporal_proximity)
        |> Map.put(:temporal_decay_weight, Float.round(decay_weight, 4))
      end)

    # Compute overall temporal anomaly summary for this agent
    temporal_anomalies = TemporalScorer.detect_temporal_anomalies(agent_id,
      window_ms: time_window_ms)

    result = %{
      agent_id: agent_id,
      total_events: length(all_events),
      time_window_ms: time_window_ms,
      correlations: enriched_correlations,
      correlation_count: length(enriched_correlations),
      time_groups: map_size(time_groups),
      temporal_anomalies: temporal_anomalies,
      analyzed_at: DateTime.utc_now()
    }

    {:ok, result}
  end

  # Private helper to get process ancestry
  defp get_process_ancestry(graph, pid) do
    do_get_ancestry(graph, pid, [pid])
  end

  defp do_get_ancestry(graph, pid, acc) do
    case Graph.in_neighbors(graph, pid) do
      [parent | _] ->
        do_get_ancestry(graph, parent, [parent | acc])
      [] ->
        acc
    end
  end

  # Private helper to find correlations between events
  defp find_event_correlations([]) do
    []
  end

  defp find_event_correlations([single_event]) do
    # For a single event, correlate against the existing ETS correlation window
    # and recent alert history rather than requiring a second event in the same bucket.
    agent_id = single_event[:agent_id]
    payload = single_event[:payload] || %{}
    event_id = single_event[:event_id]
    now = single_event[:timestamp] || System.system_time(:millisecond)
    window_ms = :timer.minutes(5)

    correlations = []

    # 1. Check event IOCs against threat intel cache
    ioc_correlations = check_single_event_iocs(single_event, payload)
    correlations = correlations ++ ioc_correlations

    # 2. Check if the event's source/destination appears in recent correlated groups
    #    by scanning the cross-endpoint ETS table for matching indicators
    cross_correlations = check_against_cross_endpoint_groups(single_event, payload, now, window_ms)
    correlations = correlations ++ cross_correlations

    # 3. Check against other events in the main ETS table from any agent
    #    within the time window that share IOCs with this event
    ets_correlations = check_against_ets_window(single_event, agent_id, payload, event_id, now, window_ms)
    correlations = correlations ++ ets_correlations

    correlations
    |> Enum.uniq_by(fn c ->
      ids = Enum.sort([c.event_a_id, c.event_b_id])
      {ids, c.correlation_type}
    end)
  end

  defp find_event_correlations(events) do
    # Compare pairs of events for correlation indicators
    for e1 <- events,
        e2 <- events,
        e1 != e2,
        correlation = check_event_correlation(e1, e2),
        correlation != nil do
      correlation
    end
    |> Enum.uniq_by(fn c ->
      # Normalize order for deduplication
      ids = Enum.sort([c.event_a_id, c.event_b_id])
      {ids, c.correlation_type}
    end)
  end

  defp check_event_correlation(e1, e2) do
    e1_type = EventTypes.normalize(e1[:event_type])
    e2_type = EventTypes.normalize(e2[:event_type])
    e1_payload = e1[:payload] || %{}
    e2_payload = e2[:payload] || %{}

    cond do
      # Process creates network connection
      e1_type == :process_create and e2_type == :network_connect and
        e1_payload[:pid] == e2_payload[:pid] ->
        %{
          event_a_id: e1[:event_id],
          event_b_id: e2[:event_id],
          correlation_type: :process_network,
          description: "Process spawned and made network connection",
          strength: 0.8
        }

      # Process creates file
      e1_type == :process_create and e2_type == :file_create and
        e1_payload[:pid] == e2_payload[:pid] ->
        %{
          event_a_id: e1[:event_id],
          event_b_id: e2[:event_id],
          correlation_type: :process_file,
          description: "Process spawned and created file",
          strength: 0.7
        }

      # Same parent process
      e1_payload[:ppid] == e2_payload[:ppid] and
        e1_payload[:ppid] != nil and e1_payload[:ppid] > 0 ->
        %{
          event_a_id: e1[:event_id],
          event_b_id: e2[:event_id],
          correlation_type: :sibling_process,
          description: "Events from sibling processes",
          strength: 0.5
        }

      # Same target file/path
      e1_payload[:path] == e2_payload[:path] and
        e1_payload[:path] != nil ->
        %{
          event_a_id: e1[:event_id],
          event_b_id: e2[:event_id],
          correlation_type: :same_target,
          description: "Events targeting same path",
          strength: 0.6
        }

      true ->
        nil
    end
  end

  # ---------------------------------------------------------------------------
  # Single-event correlation helpers
  # ---------------------------------------------------------------------------
  # These functions support find_event_correlations/1 for the single-event case,
  # checking the event against threat intel, cross-endpoint groups, and the
  # main ETS correlation window.

  # Check event IOCs (hash, IP, domain) against the threat intel cache.
  defp check_single_event_iocs(event, payload) do
    sha256 = payload[:sha256] || payload["sha256"]
    remote_ip = payload[:remote_ip] || payload["remote_ip"]
    domain = payload[:domain] || payload["domain"]
    event_id = event[:event_id]

    ioc_checks = [
      {sha256, :hash_sha256, "File hash matched threat intelligence"},
      {remote_ip, :ip, "Remote IP matched threat intelligence"},
      {domain, :domain, "Domain matched threat intelligence"}
    ]

    Enum.flat_map(ioc_checks, fn {value, ioc_type, description} ->
      if value do
        case TamanduaServer.ThreatIntel.lookup(ioc_type, to_string(value)) do
          {:ok, ioc} ->
            [%{
              event_a_id: event_id,
              event_b_id: "threat_intel:#{ioc_type}:#{value}",
              correlation_type: :threat_intel_match,
              description: "#{description} (source: #{ioc[:source] || "threat_intel"}, severity: #{ioc[:severity] || "unknown"})",
              strength: 0.9
            }]

          _ ->
            []
        end
      else
        []
      end
    end)
  end

  # Check if the event's IOCs appear in existing cross-endpoint correlation groups.
  defp check_against_cross_endpoint_groups(event, payload, now, window_ms) do
    sha256 = payload[:sha256] || payload["sha256"]
    remote_ip = payload[:remote_ip] || payload["remote_ip"]
    domain = payload[:domain] || payload["domain"]
    event_id = event[:event_id]

    indicator_values =
      [sha256, remote_ip, domain]
      |> Enum.reject(&is_nil/1)
      |> MapSet.new()

    if MapSet.size(indicator_values) == 0 do
      []
    else
      :ets.tab2list(@cross_endpoint_table)
      |> Enum.filter(fn {_key, entry} ->
        ts = entry[:timestamp] || 0
        now - ts < window_ms
      end)
      |> Enum.flat_map(fn {_key, entry} ->
        entry_ioc = entry[:indicator_value] || entry[:ioc_value]

        if entry_ioc && MapSet.member?(indicator_values, entry_ioc) do
          [%{
            event_a_id: event_id,
            event_b_id: "cross_endpoint:#{entry[:correlation_id] || entry_ioc}",
            correlation_type: :cross_endpoint_ioc,
            description: "Event IOC (#{entry_ioc}) found in cross-endpoint correlation group",
            strength: 0.85
          }]
        else
          []
        end
      end)
      |> Enum.uniq_by(fn c -> c.event_b_id end)
    end
  end

  # Check the event against other events in the main ETS table that share IOCs.
  # Scans all agents' events, not just the source agent, to find cross-agent correlations.
  defp check_against_ets_window(_event, _agent_id, payload, event_id, now, window_ms) do
    sha256 = payload[:sha256] || payload["sha256"]
    remote_ip = payload[:remote_ip] || payload["remote_ip"]
    domain = payload[:domain] || payload["domain"]
    pid = payload[:pid] || payload["pid"]
    ppid = payload[:ppid] || payload["ppid"]

    :ets.tab2list(@table_name)
    |> Enum.map(fn {_key, e} -> e end)
    |> Enum.filter(fn e ->
      e_ts = e[:timestamp] || 0
      e_id = e[:event_id]
      e_id != event_id && now - e_ts < window_ms
    end)
    |> Enum.flat_map(fn other_event ->
      other_payload = other_event[:payload] || %{}
      other_id = other_event[:event_id]

      matches = []

      # Same hash across events (even different agents)
      other_sha256 = other_payload[:sha256] || other_payload["sha256"]
      matches =
        if sha256 && other_sha256 && sha256 == other_sha256 do
          [%{
            event_a_id: event_id,
            event_b_id: other_id,
            correlation_type: :shared_hash,
            description: "Shared file hash #{sha256}",
            strength: 0.8
          } | matches]
        else
          matches
        end

      # Same remote IP
      other_ip = other_payload[:remote_ip] || other_payload["remote_ip"]
      matches =
        if remote_ip && other_ip && remote_ip == other_ip do
          [%{
            event_a_id: event_id,
            event_b_id: other_id,
            correlation_type: :shared_network_dest,
            description: "Shared network destination #{remote_ip}",
            strength: 0.7
          } | matches]
        else
          matches
        end

      # Same domain
      other_domain = other_payload[:domain] || other_payload["domain"]
      matches =
        if domain && other_domain && domain == other_domain do
          [%{
            event_a_id: event_id,
            event_b_id: other_id,
            correlation_type: :shared_domain,
            description: "Shared domain #{domain}",
            strength: 0.7
          } | matches]
        else
          matches
        end

      # Parent-child relationship across events
      other_pid = other_payload[:pid] || other_payload["pid"]
      other_ppid = other_payload[:ppid] || other_payload["ppid"]
      matches =
        cond do
          pid && other_ppid && pid == other_ppid ->
            [%{
              event_a_id: event_id,
              event_b_id: other_id,
              correlation_type: :parent_child,
              description: "Parent-child process relationship (PID #{pid})",
              strength: 0.85
            } | matches]

          ppid && other_pid && ppid == other_pid ->
            [%{
              event_a_id: event_id,
              event_b_id: other_id,
              correlation_type: :parent_child,
              description: "Child-parent process relationship (PPID #{ppid})",
              strength: 0.85
            } | matches]

          true ->
            matches
        end

      matches
    end)
  end

  # Server callbacks

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@table_name, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@process_tree_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@cross_endpoint_table, [:named_table, :bag, :public, read_concurrency: true])
    :ets.new(@correlation_cache_table, [:named_table, :set, :public, read_concurrency: true])

    schedule_cleanup()

    state = %__MODULE__{
      stats: %{
        events_correlated: 0,
        suspicious_chains: 0,
        alerts_generated: 0
      }
    }

    Logger.info("Correlation Engine started")
    {:ok, state}
  end

  @impl true
  def handle_cast({:add_event, event}, state) do
    # Store event
    store_event(event)

    # Update process tree if it's a process event
    event_type = EventTypes.normalize(event[:event_type] || event["event_type"])
    agent_id = event[:agent_id] || event["agent_id"]

    if event_type in [:process_create, :process_terminate] do
      Logger.debug("Correlator: Processing #{event_type} for agent #{agent_id}")
      update_process_tree(event)
    end

    # Check for suspicious patterns (spatial correlation)
    detections = check_patterns(event)

    # Enrich with temporal anomaly detections when we have an agent_id
    temporal_detections = if agent_id do
      detect_temporal_patterns(agent_id, event)
    else
      []
    end

    all_detections = detections ++ temporal_detections

    # Create alerts if needed
    new_state = if length(all_detections) > 0 do
      create_correlation_alerts(event, all_detections)
      update_stats(state, [:suspicious_chains, :alerts_generated])
    else
      state
    end

    {:noreply, update_stats(new_state, [:events_correlated])}
  end

  @impl true
  def handle_call({:get_process_tree, agent_id}, _from, state) do
    result = case :ets.lookup(@process_tree_table, agent_id) do
      [{^agent_id, graph}] -> {:ok, graph}
      [] -> {:error, :not_found}
    end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_process_events, agent_id, pid}, _from, state) do
    events = :ets.lookup(@table_name, {agent_id, pid})
    |> Enum.map(fn {_key, event} -> event end)

    {:reply, events, state}
  end

  @impl true
  def handle_call({:analyze_chain, agent_id, pid}, _from, state) do
    result = do_analyze_chain(agent_id, pid)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_call({:correlate_by_criteria, events, criteria}, _from, state) do
    # Correlate events based on specified criteria
    correlated = do_correlate_by_criteria(events, criteria)
    new_state = update_stats(state, [:correlations_performed])
    {:reply, {:ok, correlated}, new_state}
  end

  @impl true
  def handle_call({:get_timeline, timeline_id}, _from, state) do
    result = case Map.get(state.timelines, timeline_id) do
      nil -> {:error, :not_found}
      timeline -> {:ok, timeline}
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:list_timelines, opts}, _from, state) do
    timelines = state.timelines
    |> Map.values()
    |> filter_timelines(opts)
    |> Enum.sort_by(& &1.created_at, {:desc, DateTime})
    |> maybe_take(Map.get(opts, :limit, 100))

    {:reply, {:ok, timelines}, state}
  end

  @impl true
  def handle_call({:correlate_cross_endpoint, opts}, _from, state) do
    result = do_cross_endpoint_correlation(opts)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:find_shared_iocs, opts}, _from, state) do
    result = do_find_shared_iocs(opts)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:detect_lateral_movement, opts}, _from, state) do
    result = do_detect_lateral_movement(opts)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_old_events()
    schedule_cleanup()
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages (stale PubSub broadcasts, monitor
  # :DOWN, late task replies) instead of crashing the GenServer.
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # Private functions

  defp do_correlate_by_criteria(events, criteria) do
    # Group events based on criteria
    grouping_key = Map.get(criteria, :group_by, :agent_id)
    time_window = Map.get(criteria, :time_window_seconds, 300)

    events
    |> Enum.group_by(&get_grouping_key(&1, grouping_key))
    |> Enum.map(fn {key, group_events} ->
      %{
        group_key: key,
        events: Enum.sort_by(group_events, & &1[:timestamp]),
        count: length(group_events),
        time_span: calculate_time_span(group_events),
        correlation_score: calculate_correlation_score(group_events, time_window)
      }
    end)
    |> Enum.filter(&(&1.count > 1))
  end

  defp get_grouping_key(event, :agent_id), do: event[:agent_id] || event["agent_id"]
  defp get_grouping_key(event, :process_id) do
    payload = event[:payload] || event["payload"] || %{}
    payload[:pid] || payload["pid"]
  end
  defp get_grouping_key(event, :source_ip) do
    payload = event[:payload] || event["payload"] || %{}
    payload[:remote_ip] || payload["remote_ip"]
  end
  defp get_grouping_key(event, _), do: event[:agent_id] || event["agent_id"]

  defp calculate_time_span([]), do: 0
  defp calculate_time_span(events) do
    timestamps = Enum.map(events, & &1[:timestamp])
    |> Enum.filter(& &1)
    |> Enum.sort()

    case {List.first(timestamps), List.last(timestamps)} do
      {nil, _} -> 0
      {_, nil} -> 0
      {first, last} -> DateTime.diff(last, first, :second)
    end
  end

  defp calculate_correlation_score(events, time_window) do
    time_span = calculate_time_span(events)
    count = length(events)

    cond do
      time_span == 0 -> 0.5
      time_span <= time_window and count >= 5 -> 0.9
      time_span <= time_window and count >= 3 -> 0.7
      time_span <= time_window -> 0.5
      true -> 0.3
    end
  end

  defp filter_timelines(timelines, opts) do
    timelines
    |> maybe_filter_by_agent(Map.get(opts, :agent_id))
    |> maybe_filter_by_date_range(Map.get(opts, :start_date), Map.get(opts, :end_date))
  end

  defp maybe_filter_by_agent(timelines, nil), do: timelines
  defp maybe_filter_by_agent(timelines, agent_id) do
    Enum.filter(timelines, &(&1.agent_id == agent_id))
  end

  defp maybe_filter_by_date_range(timelines, nil, nil), do: timelines
  defp maybe_filter_by_date_range(timelines, start_date, nil) do
    Enum.filter(timelines, &(DateTime.compare(&1.created_at, start_date) != :lt))
  end
  defp maybe_filter_by_date_range(timelines, nil, end_date) do
    Enum.filter(timelines, &(DateTime.compare(&1.created_at, end_date) != :gt))
  end
  defp maybe_filter_by_date_range(timelines, start_date, end_date) do
    Enum.filter(timelines, fn t ->
      DateTime.compare(t.created_at, start_date) != :lt and
      DateTime.compare(t.created_at, end_date) != :gt
    end)
  end

  defp maybe_take(timelines, limit), do: Enum.take(timelines, limit)

  defp store_event(event) do
    # Handle both atom and string keys (agent sends string keys)
    agent_id = event[:agent_id] || event["agent_id"]
    payload = event[:payload] || event["payload"] || %{}
    pid = payload[:pid] || payload["pid"]
    timestamp = event[:timestamp] || event["timestamp"]

    if agent_id && pid do
      entry = {
        {agent_id, pid},
        %{
          event_id: event[:event_id] || event["event_id"],
          event_type: event[:event_type] || event["event_type"],
          timestamp: timestamp,
          payload: payload
        }
      }

      :ets.insert(@table_name, entry)
    end
  end

  defp update_process_tree(event) do
    # Handle both atom and string keys (agent sends string keys)
    agent_id = event[:agent_id] || event["agent_id"]
    event_type = EventTypes.normalize(event[:event_type] || event["event_type"])
    payload = event[:payload] || event["payload"] || %{}
    pid = payload[:pid] || payload["pid"]
    ppid = payload[:ppid] || payload["ppid"]
    name = payload[:name] || payload["name"] || ""
    path = payload[:path] || payload["path"] || ""

    # Accept any process_create event with a valid PID
    # Even processes with empty name/path are valid - they get a PID-based fallback name
    has_useful_info = event_type == :process_create &&
                      pid && pid > 0

    if agent_id && has_useful_info do
      # Get or create graph for this agent
      graph = case :ets.lookup(@process_tree_table, agent_id) do
        [{^agent_id, g}] -> g
        [] -> Graph.new(type: :directed)
      end

      # Add process node - use PID-based name when name is empty
      display_name = if name == "" and path == "", do: "Process_#{pid}", else: name

      process_info = %{
        pid: pid,
        name: display_name,
        path: path,
        cmdline: payload[:cmdline] || payload["cmdline"],
        user: payload[:user] || payload["user"],
        sha256: payload[:sha256] || payload["sha256"],
        start_time: payload[:start_time] || payload["start_time"],
        is_elevated: payload[:is_elevated] || payload["is_elevated"] || false,
        is_signed: payload[:is_signed] || payload["is_signed"] || false,
        signer: payload[:signer] || payload["signer"],
        cpu_usage: payload[:cpu_usage] || payload["cpu_usage"],
        memory_bytes: payload[:memory_bytes] || payload["memory_bytes"],
        entropy: payload[:entropy] || payload["entropy"],
        company_name: payload[:company_name] || payload["company_name"],
        file_description: payload[:file_description] || payload["file_description"],
        product_name: payload[:product_name] || payload["product_name"],
        file_version: payload[:file_version] || payload["file_version"],
        ppid: ppid,
        parent_name: payload[:parent_name] || payload["parent_name"],
        parent_path: payload[:parent_path] || payload["parent_path"]
      }

      graph = Graph.add_vertex(graph, pid, process_info)

      # Add edge from parent if exists
      graph = if ppid && ppid > 0 do
        Graph.add_edge(graph, ppid, pid)
      else
        graph
      end

      :ets.insert(@process_tree_table, {agent_id, graph})
      Logger.debug("Added process #{pid} (#{name}) to tree for agent #{agent_id}")
    end
  end

  defp check_patterns(event) do
    detections = []

    # Get event type via structured normalization
    event_type = EventTypes.normalize(event[:event_type] || event["event_type"])

    # Check for suspicious process chains
    if event_type == :process_create do
      chain_detections = check_process_chain(event)
      detections = detections ++ chain_detections
    end

    # Check for rapid file operations (potential ransomware)
    if event_type in [:file_modify, :file_create] do
      rapid_detections = check_rapid_file_ops(event)
      detections = detections ++ rapid_detections
    end

    detections
  end

  defp check_process_chain(event) do
    payload = event[:payload] || event["payload"] || %{}
    parent_path = payload[:parent_path] || payload["parent_path"] || ""
    child_path = payload[:path] || payload["path"] || ""
    cmdline = payload[:cmdline] || payload["cmdline"] || ""

    # 1. Check parent-child chain patterns
    chain_detections = check_parent_child_chain(parent_path, child_path)

    # 2. Check command-line argument patterns
    cmdline_detections = check_cmdline_patterns(child_path, cmdline)

    # 3. Combine detections, boosting confidence when both chain AND cmdline match
    combined_detections = combine_chain_and_cmdline_detections(
      chain_detections,
      cmdline_detections,
      parent_path,
      child_path,
      cmdline
    )

    combined_detections
  end

  # Check parent-child process chain patterns
  defp check_parent_child_chain(parent_path, child_path) do
    @chain_to_mitre
    |> Enum.flat_map(fn {{_name, {parent_pattern, child_pattern}}, mitre_info} ->
      if Regex.match?(parent_pattern, parent_path) && Regex.match?(child_pattern, child_path) do
        [%{
          type: :suspicious_chain,
          description: mitre_info.description,
          parent: parent_path,
          child: child_path,
          mitre_tactics: mitre_info.tactics,
          mitre_techniques: mitre_info.techniques,
          base_score: 0.5
        }]
      else
        []
      end
    end)
    # Take the most specific match (prefer more specific parent patterns over generic .*)
    |> Enum.sort_by(fn detection ->
      parent = detection.parent
      is_generic = String.length(parent) < 5
      if is_generic, do: 1, else: 0
    end)
    |> Enum.take(1)
  end

  # Process-agnostic command-line patterns that match purely on argument content.
  # These complement @cmdline_suspicious_patterns (which require both process and
  # cmdline matches) by detecting technique indicators regardless of the binary name.
  @cmdline_agnostic_patterns [
    # Encoded PowerShell - T1059.001 / T1027
    %{
      cmdline: ~r/(?:-enc\s|-encodedcommand\s|frombase64string)/i,
      technique: "T1059.001",
      description: "Encoded PowerShell command detected",
      confidence: 0.8
    },
    # Credential access tools - T1003.001 / T1003.002
    %{
      cmdline: ~r/(?:sekurlsa|lsadump|mimikatz|procdump.*lsass)/i,
      technique: "T1003.001",
      description: "Credential dumping tool arguments detected",
      confidence: 0.9
    },
    # Discovery - account and group enumeration - T1087.001
    %{
      cmdline: ~r/(?:net\s+user|net\s+group|net\s+localgroup)/i,
      technique: "T1087.001",
      description: "Account/group enumeration via net command",
      confidence: 0.6
    },
    # Discovery - domain trust enumeration - T1482
    %{
      cmdline: ~r/(?:nltest|dsquery)/i,
      technique: "T1482",
      description: "Domain trust or directory enumeration detected",
      confidence: 0.7
    },
    # Lateral movement - PsExec - T1570
    %{
      cmdline: ~r/psexec/i,
      technique: "T1570",
      description: "PsExec lateral movement tool detected",
      confidence: 0.8
    },
    # Lateral movement - WMI remote process creation - T1047
    %{
      cmdline: ~r/wmic\s+.*process\s+.*call/i,
      technique: "T1047",
      description: "WMI remote process creation detected",
      confidence: 0.8
    },
    # Lateral movement - WinRM / Invoke-Command - T1021.006
    %{
      cmdline: ~r/(?:winrm|invoke-command)/i,
      technique: "T1021.006",
      description: "WinRM remote command execution detected",
      confidence: 0.7
    },
    # Defense evasion - AMSI bypass - T1562.001
    %{
      cmdline: ~r/amsi\s*.*bypass/i,
      technique: "T1562.001",
      description: "AMSI bypass attempt detected",
      confidence: 0.85
    },
    # Defense evasion - Disable Defender via Set-MpPreference - T1562.001
    %{
      cmdline: ~r/set-mppreference\s+.*-disable/i,
      technique: "T1562.001",
      description: "Windows Defender disable attempt via Set-MpPreference",
      confidence: 0.85
    },
    # Defense evasion - Disable AntiSpyware via registry - T1562.001
    %{
      cmdline: ~r/reg\s+.*add\s+.*disableantispyware/i,
      technique: "T1562.001",
      description: "AntiSpyware disable via registry modification",
      confidence: 0.9
    },
    # Persistence - Scheduled task creation - T1053.005
    %{
      cmdline: ~r/schtasks\s+.*\/create/i,
      technique: "T1053.005",
      description: "Scheduled task creation for persistence",
      confidence: 0.7
    },
    # Persistence - Registry Run key - T1547.001
    %{
      cmdline: ~r/reg\s+.*add\s+.*\\run\b/i,
      technique: "T1547.001",
      description: "Registry Run key persistence detected",
      confidence: 0.75
    },
    # Persistence - WMI startup entry - T1546.003
    %{
      cmdline: ~r/wmic\s+.*startup/i,
      technique: "T1546.003",
      description: "WMI startup persistence detected",
      confidence: 0.75
    },
    # Exfiltration - curl POST data - T1048
    %{
      cmdline: ~r/curl\s+.*-d\s/i,
      technique: "T1048",
      description: "Data exfiltration via curl POST detected",
      confidence: 0.6
    },
    # Exfiltration - wget POST data - T1048
    %{
      cmdline: ~r/wget\s+.*--post/i,
      technique: "T1048",
      description: "Data exfiltration via wget POST detected",
      confidence: 0.6
    },
    # Exfiltration/Evasion - certutil encode - T1027
    %{
      cmdline: ~r/certutil\s+.*-encode/i,
      technique: "T1027",
      description: "Data encoding via certutil detected",
      confidence: 0.7
    }
  ]

  # Check command-line argument patterns for suspicious execution
  defp check_cmdline_patterns(process_path, cmdline) when is_binary(cmdline) and byte_size(cmdline) > 0 do
    # 1. Check process-specific patterns (require both process and cmdline match)
    process_specific =
      @cmdline_suspicious_patterns
      |> Enum.flat_map(fn pattern ->
        process_matches = Regex.match?(pattern.process, process_path)
        cmdline_matches = Regex.match?(pattern.cmdline, cmdline)

        if process_matches && cmdline_matches do
          [%{
            type: :suspicious_cmdline,
            description: pattern.description,
            process: process_path,
            cmdline: cmdline,
            boost: pattern.boost,
            mitre_techniques: pattern.mitre,
            mitre_tactics: mitre_techniques_to_tactics(pattern.mitre)
          }]
        else
          []
        end
      end)

    # 2. Check process-agnostic patterns (match purely on cmdline content)
    agnostic =
      @cmdline_agnostic_patterns
      |> Enum.flat_map(fn pattern ->
        if Regex.match?(pattern.cmdline, cmdline) do
          [%{
            type: :suspicious_cmdline,
            description: pattern.description,
            process: process_path,
            cmdline: cmdline,
            boost: pattern.confidence * 0.5,
            mitre_techniques: [pattern.technique],
            mitre_tactics: mitre_techniques_to_tactics([pattern.technique]),
            confidence: pattern.confidence
          }]
        else
          []
        end
      end)

    # Combine and deduplicate -- prefer process-specific matches (higher fidelity)
    # by deduplicating on the primary MITRE technique
    seen_techniques =
      process_specific
      |> Enum.flat_map(& &1.mitre_techniques)
      |> MapSet.new()

    unique_agnostic =
      agnostic
      |> Enum.reject(fn det ->
        Enum.any?(det.mitre_techniques, &MapSet.member?(seen_techniques, &1))
      end)

    process_specific ++ unique_agnostic
  end

  defp check_cmdline_patterns(_process_path, _cmdline), do: []

  # Map MITRE techniques to their primary tactics
  defp mitre_techniques_to_tactics(techniques) do
    technique_to_tactic = %{
      "T1059.001" => "execution",
      "T1059.005" => "execution",
      "T1059.007" => "execution",
      "T1027" => "defense_evasion",
      "T1105" => "command_and_control",
      "T1140" => "defense_evasion",
      "T1218" => "defense_evasion",
      "T1218.005" => "defense_evasion",
      "T1218.010" => "defense_evasion",
      "T1218.011" => "defense_evasion",
      "T1047" => "execution",
      "T1197" => "persistence",
      "T1033" => "discovery",
      "T1082" => "discovery",
      "T1016" => "discovery",
      "T1012" => "discovery",
      "T1112" => "defense_evasion",
      "T1053.005" => "persistence",
      "T1543.003" => "persistence",
      "T1490" => "impact",
      "T1003.001" => "credential_access",
      "T1003.002" => "credential_access",
      "T1135" => "discovery",
      "T1021.001" => "lateral_movement",
      "T1021.002" => "lateral_movement",
      "T1021.006" => "lateral_movement",
      "T1048" => "exfiltration",
      "T1087.001" => "discovery",
      "T1482" => "discovery",
      "T1546.003" => "persistence",
      "T1547.001" => "persistence",
      "T1570" => "lateral_movement",
      "T1562.001" => "defense_evasion",
      "T1562.004" => "defense_evasion",
      "T1564.003" => "defense_evasion"
    }

    techniques
    |> Enum.map(&Map.get(technique_to_tactic, &1, "unknown"))
    |> Enum.uniq()
  end

  # Combine chain and cmdline detections with confidence boosting
  defp combine_chain_and_cmdline_detections(chain_detections, cmdline_detections, parent_path, child_path, cmdline) do
    cond do
      # Both chain AND cmdline match - highest confidence
      length(chain_detections) > 0 && length(cmdline_detections) > 0 ->
        chain = List.first(chain_detections)
        cmdline_det = List.first(cmdline_detections)

        # Merge MITRE mappings and boost confidence
        merged_techniques = Enum.uniq(chain.mitre_techniques ++ cmdline_det.mitre_techniques)
        merged_tactics = Enum.uniq(chain.mitre_tactics ++ cmdline_det.mitre_tactics)
        combined_score = min(1.0, (chain.base_score || 0.5) + cmdline_det.boost)

        [%{
          type: :suspicious_chain_with_cmdline,
          description: "#{chain.description} with #{cmdline_det.description}",
          parent: parent_path,
          child: child_path,
          cmdline: cmdline,
          mitre_tactics: merged_tactics,
          mitre_techniques: merged_techniques,
          confidence: combined_score,
          chain_detection: chain.description,
          cmdline_detection: cmdline_det.description
        }]

      # Only chain matches
      length(chain_detections) > 0 ->
        chain_detections

      # Only cmdline matches - still report it as suspicious
      length(cmdline_detections) > 0 ->
        cmdline_det = List.first(cmdline_detections)
        [%{
          type: :suspicious_cmdline,
          description: cmdline_det.description,
          parent: parent_path,
          child: child_path,
          cmdline: cmdline,
          mitre_tactics: cmdline_det.mitre_tactics,
          mitre_techniques: cmdline_det.mitre_techniques,
          confidence: cmdline_det.boost
        }]

      # No matches
      true ->
        []
    end
  end

  defp check_rapid_file_ops(event) do
    # Handle both atom and string keys
    agent_id = event[:agent_id] || event["agent_id"]
    payload = event[:payload] || event["payload"] || %{}
    pid = payload[:pid] || payload["pid"]
    now = event[:timestamp] || event["timestamp"] || System.system_time(:millisecond)

    if agent_id && pid do
      # Get recent file events from this process
      window_seconds = Config.rapid_file_ops_window_seconds()
      threshold = Config.rapid_file_ops_threshold()

      events = :ets.lookup(@table_name, {agent_id, pid})
      |> Enum.map(fn {_key, e} -> e end)
      |> Enum.filter(fn e ->
        et = EventTypes.normalize(e[:event_type])
        et in [:file_modify, :file_create] &&
        (now - (e[:timestamp] || 0)) < :timer.seconds(window_seconds)
      end)

      # If more than threshold file ops in window, suspicious
      if length(events) > threshold do
        [%{
          type: :rapid_file_ops,
          description: "Rapid file operations detected (potential ransomware)",
          count: length(events),
          window_seconds: window_seconds,
          mitre_tactics: ["impact"],
          mitre_techniques: ["T1486"]
        }]
      else
        []
      end
    else
      []
    end
  end

  defp do_analyze_chain(agent_id, pid) do
    case :ets.lookup(@process_tree_table, agent_id) do
      [{^agent_id, graph}] ->
        # Get ancestors (root to leaf order)
        ancestors = get_ancestors(graph, pid, [])

        # Check each parent-child pair (single-hop detection)
        single_hop_detections = ancestors
        |> Enum.chunk_every(2, 1, :discard)
        |> Enum.flat_map(fn [parent, child] ->
          parent_info = Graph.vertex_labels(graph, parent) |> List.first() || %{}
          child_info = Graph.vertex_labels(graph, child) |> List.first() || %{}

          check_pair_suspicious(parent_info, child_info)
        end)

        # Multi-hop attack sequence detection
        multi_hop_detections = detect_attack_sequences(graph, ancestors, agent_id)

        # Combine detections, prioritizing multi-hop (more specific) over single-hop
        all_detections = multi_hop_detections ++ single_hop_detections
        |> Enum.uniq_by(fn d -> d[:description] end)

        {:ok, all_detections}

      [] ->
        {:error, :not_found}
    end
  end

  defp get_ancestors(graph, pid, acc) do
    case Graph.in_neighbors(graph, pid) do
      [parent | _] ->
        get_ancestors(graph, parent, [pid | acc])
      [] ->
        [pid | acc]
    end
  end

  defp check_pair_suspicious(parent_info, child_info) do
    parent_path = parent_info[:path] || ""
    child_path = child_info[:path] || ""
    child_cmdline = child_info[:cmdline] || ""

    # 1. Check parent-child chain patterns
    chain_detections = @chain_to_mitre
    |> Enum.flat_map(fn {{_name, {parent_pattern, child_pattern}}, mitre_info} ->
      if Regex.match?(parent_pattern, parent_path) && Regex.match?(child_pattern, child_path) do
        [%{
          type: :suspicious_chain,
          description: mitre_info.description,
          parent_path: parent_path,
          child_path: child_path,
          mitre_tactics: mitre_info.tactics,
          mitre_techniques: mitre_info.techniques,
          base_score: 0.5
        }]
      else
        []
      end
    end)
    |> Enum.sort_by(fn detection ->
      parent = detection.parent_path
      is_generic = String.length(parent) < 5
      if is_generic, do: 1, else: 0
    end)
    |> Enum.take(1)

    # 2. Check command-line argument patterns on the child process
    cmdline_detections = check_cmdline_patterns(child_path, child_cmdline)

    # 3. Combine detections with confidence boosting
    cond do
      # Both chain AND cmdline match - highest confidence
      length(chain_detections) > 0 && length(cmdline_detections) > 0 ->
        chain = List.first(chain_detections)
        cmdline_det = List.first(cmdline_detections)

        merged_techniques = Enum.uniq(chain.mitre_techniques ++ cmdline_det.mitre_techniques)
        merged_tactics = Enum.uniq(chain.mitre_tactics ++ cmdline_det.mitre_tactics)
        combined_score = min(1.0, (chain.base_score || 0.5) + cmdline_det.boost)

        [%{
          type: :suspicious_chain_with_cmdline,
          description: "#{chain.description} with #{cmdline_det.description}",
          parent_path: parent_path,
          child_path: child_path,
          cmdline: child_cmdline,
          mitre_tactics: merged_tactics,
          mitre_techniques: merged_techniques,
          confidence: combined_score
        }]

      # Only chain matches
      length(chain_detections) > 0 ->
        chain_detections

      # Only cmdline matches
      length(cmdline_detections) > 0 ->
        cmdline_det = List.first(cmdline_detections)
        [%{
          type: :suspicious_cmdline,
          description: cmdline_det.description,
          parent_path: parent_path,
          child_path: child_path,
          cmdline: child_cmdline,
          mitre_tactics: cmdline_det.mitre_tactics,
          mitre_techniques: cmdline_det.mitre_techniques,
          confidence: cmdline_det.boost
        }]

      true ->
        []
    end
  end

  # Detect multi-hop attack sequences in the process chain
  # Matches patterns from @attack_sequences that span multiple process generations
  defp detect_attack_sequences(graph, ancestors, _agent_id) do
    # Build a list of process paths in order (root to leaf)
    process_paths = ancestors
    |> Enum.map(fn pid ->
      labels = Graph.vertex_labels(graph, pid) |> List.first() || %{}
      labels[:path] || ""
    end)

    # Try to match each attack sequence pattern
    @attack_sequences
    |> Enum.flat_map(fn sequence_def ->
      pattern = sequence_def.pattern
      pattern_length = length(pattern)

      # Slide a window of pattern_length over the process chain
      if length(process_paths) >= pattern_length do
        process_paths
        |> Enum.chunk_every(pattern_length, 1, :discard)
        |> Enum.flat_map(fn window ->
          # Check if this window matches the pattern
          matches = Enum.zip(pattern, window)
          |> Enum.all?(fn {regex, path} -> Regex.match?(regex, path) end)

          if matches do
            [%{
              type: :attack_sequence,
              description: sequence_def.description,
              process_chain: window,
              chain_length: pattern_length,
              mitre_tactics: infer_tactics_from_techniques(sequence_def.mitre),
              mitre_techniques: sequence_def.mitre,
              severity: sequence_def.severity
            }]
          else
            []
          end
        end)
      else
        []
      end
    end)
    |> Enum.uniq_by(fn d -> d.description end)
  end

  # Infer MITRE tactics from technique IDs
  defp infer_tactics_from_techniques(techniques) do
    techniques
    |> Enum.flat_map(fn technique ->
      case technique do
        "T1059" <> _ -> ["execution"]
        "T1204" <> _ -> ["execution", "initial_access"]
        "T1189" <> _ -> ["initial_access"]
        "T1566" <> _ -> ["initial_access"]
        "T1218" <> _ -> ["defense_evasion"]
        "T1027" <> _ -> ["defense_evasion"]
        "T1562" <> _ -> ["defense_evasion"]
        "T1105" <> _ -> ["command_and_control"]
        "T1082" <> _ -> ["discovery"]
        "T1016" <> _ -> ["discovery"]
        "T1033" <> _ -> ["discovery"]
        "T1087" <> _ -> ["discovery"]
        "T1482" <> _ -> ["discovery"]
        "T1003" <> _ -> ["credential_access"]
        "T1047" <> _ -> ["execution"]
        "T1048" <> _ -> ["exfiltration"]
        "T1053" <> _ -> ["persistence", "execution"]
        "T1543" <> _ -> ["persistence", "privilege_escalation"]
        "T1546" <> _ -> ["persistence"]
        "T1547" <> _ -> ["persistence"]
        "T1021" <> _ -> ["lateral_movement"]
        "T1570" <> _ -> ["lateral_movement"]
        _ -> []
      end
    end)
    |> Enum.uniq()
  end

  defp create_correlation_alerts(event, detections) do
    agent_id = event[:agent_id] || event["agent_id"]
    payload = event[:payload] || event["payload"] || %{}
    pid = payload[:pid] || payload["pid"]

    # Build process chain if we have agent_id and PID
    process_chain = if agent_id && pid do
      case build_storyline(agent_id, pid) do
        {:ok, storyline} -> storyline.process_chain
        _ -> []
      end
    else
      []
    end

    Enum.each(detections, fn detection ->
      # Build evidence using the Evidence module for consistency
      base_evidence = Evidence.extract(event, [detection])

      # Enhance with correlation-specific detection info
      evidence = Map.put(base_evidence, :detection, %{
        rule_name: "Correlation: #{detection[:type]}",
        rule_type: "correlation",
        confidence: 0.65,
        matched_pattern: detection[:description],
        parent_path: detection[:parent_path],
        child_path: detection[:child_path]
      })

      # Enhance with correlation-specific process chain context
      evidence = if detection[:parent_path] || detection[:child_path] do
        Map.put(evidence, :correlation_context, %{
          parent_path: detection[:parent_path],
          child_path: detection[:child_path],
          chain_type: detection[:type]
        })
      else
        evidence
      end

      # Generate contextual title using the centralized Evidence module builder
      title = Evidence.build_contextual_title(event, [detection], detection[:mitre_techniques])

      # Build detection_metadata for investigator context
      detection_metadata = %{
        "rule_name" => "Correlation: #{detection[:type]}",
        "rule_type" => "correlation",
        "confidence" => 0.65,
        "correlation_type" => to_string(detection[:type]),
        "parent_path" => detection[:parent_path],
        "child_path" => detection[:child_path],
        "event_type" => to_string(event[:event_type] || event["event_type"] || "")
      }

      Alerts.create_alert(%{
        agent_id: agent_id,
        organization_id: event[:organization_id] || OrgLookup.get_org_id(agent_id),
        severity: :high,
        title: title,
        description: detection[:description],
        source_event_id: event[:event_id],
        event_ids: [event[:event_id]],
        evidence: evidence,
        process_chain: process_chain,
        raw_event: event[:payload] || event["payload"] || %{},
        detection_metadata: detection_metadata,
        mitre_tactics: detection[:mitre_tactics] || [],
        mitre_techniques: detection[:mitre_techniques] || [],
        threat_score: 0.65
      })
    end)
  end

  # Map MITRE techniques or detection type to human-readable categories
  defp correlation_mitre_to_category(nil, detection_type), do: correlation_type_to_category(detection_type)

  defp correlation_mitre_to_category(technique, detection_type) do
    case technique do
      # Execution techniques
      "T1059" <> _ -> "Command Execution"
      "T1047" <> _ -> "WMI Execution"
      "T1053" <> _ -> "Scheduled Task"
      # Defense Evasion techniques
      "T1218" <> _ -> "Signed Binary Proxy Execution"
      "T1140" <> _ -> "Deobfuscation"
      "T1112" <> _ -> "Registry Modification"
      # Credential Access techniques
      "T1003" <> _ -> "Credential Dumping"
      # Lateral Movement techniques
      "T1021" <> _ -> "Lateral Movement"
      "T1570" <> _ -> "Lateral Tool Transfer"
      # Persistence techniques
      "T1547" <> _ -> "Boot/Logon Autostart"
      "T1543" <> _ -> "Service Creation"
      "T1197" <> _ -> "BITS Jobs"
      # Initial Access techniques
      "T1189" <> _ -> "Drive-by Compromise"
      "T1204" <> _ -> "User Execution"
      "T1566" <> _ -> "Phishing"
      # Command and Control techniques
      "T1105" <> _ -> "Remote File Copy"
      # Discovery techniques
      "T1087" <> _ -> "Account Discovery"
      "T1082" <> _ -> "System Discovery"
      "T1016" <> _ -> "Network Discovery"
      "T1033" <> _ -> "User Discovery"
      # Collection techniques
      "T1560" <> _ -> "Data Staging"
      # Impact techniques
      "T1486" <> _ -> "Ransomware"
      # Process Injection
      "T1055" <> _ -> "Process Injection"
      # Fallback
      _ -> correlation_type_to_category(detection_type)
    end
  end

  defp correlation_type_to_category(:suspicious_chain), do: "Suspicious Process Chain"
  defp correlation_type_to_category(:rapid_file_ops), do: "Ransomware Indicator"
  defp correlation_type_to_category(_), do: "Behavioral Correlation"

  # ============================================================================
  # Cross-Endpoint Correlation Logic
  # ============================================================================

  defp do_cross_endpoint_correlation(opts) do
    time_window_ms = Keyword.get(opts, :time_window_ms, :timer.minutes(10))
    min_endpoints = Keyword.get(opts, :min_endpoints, 2)
    now = System.system_time(:millisecond)

    # Collect all recent events across all agents
    all_events =
      :ets.tab2list(@table_name)
      |> Enum.map(fn {_key, event} -> event end)
      |> Enum.filter(fn e ->
        ts = e[:timestamp] || 0
        now - ts < time_window_ms
      end)

    # 1. Shared hash correlation — same binary hash on multiple endpoints
    hash_groups = group_by_indicator(all_events, :sha256)
    shared_hashes = filter_multi_endpoint(hash_groups, min_endpoints)

    # 2. Shared IP correlation — same remote IP contacted by multiple endpoints
    ip_groups = group_by_indicator(all_events, :remote_ip)
    shared_ips = filter_multi_endpoint(ip_groups, min_endpoints)

    # 3. Shared domain correlation
    domain_groups = group_by_indicator(all_events, :domain)
    shared_domains = filter_multi_endpoint(domain_groups, min_endpoints)

    # 4. Same user across endpoints (potential lateral movement)
    user_groups = group_by_indicator(all_events, :user)
    cross_user = filter_multi_endpoint(user_groups, min_endpoints)

    # 5. Temporal clustering — similar event types across agents in tight windows
    temporal = detect_temporal_clustering(all_events, time_window_ms, min_endpoints)

    %{
      time_window_ms: time_window_ms,
      total_events_analyzed: length(all_events),
      shared_hashes: format_cross_endpoint_group(shared_hashes, :hash),
      shared_ips: format_cross_endpoint_group(shared_ips, :ip),
      shared_domains: format_cross_endpoint_group(shared_domains, :domain),
      cross_user_activity: format_cross_endpoint_group(cross_user, :user),
      temporal_clusters: temporal,
      analyzed_at: DateTime.utc_now()
    }
  end

  defp do_find_shared_iocs(opts) do
    time_window_ms = Keyword.get(opts, :time_window_ms, :timer.hours(1))
    min_endpoints = Keyword.get(opts, :min_endpoints, 2)
    now = System.system_time(:millisecond)

    all_events =
      :ets.tab2list(@table_name)
      |> Enum.map(fn {_key, event} -> event end)
      |> Enum.filter(fn e -> now - (e[:timestamp] || 0) < time_window_ms end)

    ioc_types = [:sha256, :remote_ip, :domain, :path]

    Enum.flat_map(ioc_types, fn ioc_type ->
      group_by_indicator(all_events, ioc_type)
      |> filter_multi_endpoint(min_endpoints)
      |> Enum.map(fn {indicator, agent_events} ->
        agents = agent_events |> Enum.map(& &1.agent_id) |> Enum.uniq()
        %{
          ioc_type: ioc_type,
          ioc_value: indicator,
          endpoints: agents,
          endpoint_count: length(agents),
          event_count: length(agent_events),
          first_seen: agent_events |> Enum.map(& &1.timestamp) |> Enum.min(),
          last_seen: agent_events |> Enum.map(& &1.timestamp) |> Enum.max()
        }
      end)
    end)
    |> Enum.sort_by(& &1.endpoint_count, :desc)
  end

  defp do_detect_lateral_movement(opts) do
    time_window_ms = Keyword.get(opts, :time_window_ms, :timer.minutes(30))
    now = System.system_time(:millisecond)

    all_events =
      :ets.tab2list(@table_name)
      |> Enum.map(fn {_key, event} -> event end)
      |> Enum.filter(fn e -> now - (e[:timestamp] || 0) < time_window_ms end)

    # Pattern 1: Same credentials used on multiple endpoints
    auth_events =
      all_events
      |> Enum.filter(fn e ->
        et = EventTypes.normalize(e[:event_type])
        et in [:logon, :authentication, :network_connect]
      end)

    user_spread =
      auth_events
      |> Enum.group_by(fn e ->
        payload = e[:payload] || %{}
        payload[:user] || payload["user"]
      end)
      |> Enum.filter(fn {user, events} ->
        user != nil &&
          events
          |> Enum.map(fn e -> e[:payload][:agent_id] || e[:agent_id] end)
          |> Enum.uniq()
          |> length() >= 2
      end)
      |> Enum.map(fn {user, events} ->
        agents = events |> Enum.map(fn e -> e[:payload][:agent_id] || e[:agent_id] end) |> Enum.uniq()
        timestamps = events |> Enum.map(& &1[:timestamp]) |> Enum.sort()

        %{
          pattern: :credential_spread,
          user: user,
          agents: agents,
          agent_count: length(agents),
          event_count: length(events),
          first_seen: List.first(timestamps),
          last_seen: List.last(timestamps),
          severity: if(length(agents) >= Config.lateral_movement_threshold(), do: :high, else: :medium)
        }
      end)

    # Pattern 2: Sequential network connections between internal endpoints
    network_events =
      all_events
      |> Enum.filter(fn e ->
        EventTypes.normalize(e[:event_type]) == :network_connect
      end)

    sequential_connections = detect_sequential_connections(network_events)

    # Pattern 3: Same executable hash appearing on new endpoints over time
    process_events =
      all_events
      |> Enum.filter(fn e -> EventTypes.normalize(e[:event_type]) == :process_create end)

    hash_spread = detect_hash_propagation(process_events)

    (user_spread ++ sequential_connections ++ hash_spread)
    |> Enum.sort_by(fn m -> m[:severity] end, :desc)
  end

  defp group_by_indicator(events, indicator_key) do
    events
    |> Enum.map(fn event ->
      payload = event[:payload] || %{}
      value = payload[indicator_key] || payload[to_string(indicator_key)]
      agent_id = event[:agent_id] || event[:payload][:agent_id]

      if value && agent_id do
        {value, %{agent_id: agent_id, timestamp: event[:timestamp] || 0, event: event}}
      else
        nil
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
  end

  defp filter_multi_endpoint(groups, min_endpoints) do
    groups
    |> Enum.filter(fn {_indicator, entries} ->
      entries
      |> Enum.map(& &1.agent_id)
      |> Enum.uniq()
      |> length() >= min_endpoints
    end)
  end

  defp format_cross_endpoint_group(groups, ioc_type) do
    Enum.map(groups, fn {indicator, entries} ->
      agents = entries |> Enum.map(& &1.agent_id) |> Enum.uniq()
      %{
        indicator_type: ioc_type,
        indicator_value: indicator,
        endpoints: agents,
        endpoint_count: length(agents),
        event_count: length(entries),
        first_seen: entries |> Enum.min_by(& &1.timestamp) |> Map.get(:timestamp),
        last_seen: entries |> Enum.max_by(& &1.timestamp) |> Map.get(:timestamp)
      }
    end)
  end

  defp detect_temporal_clustering(events, time_window_ms, min_endpoints) do
    # Group events into time buckets and find clusters with multiple agents
    bucket_size = div(time_window_ms, 10)

    events
    |> Enum.group_by(fn e ->
      ts = e[:timestamp] || 0
      event_type = to_string(e[:event_type] || "")
      {div(ts, bucket_size), event_type}
    end)
    |> Enum.filter(fn {_key, bucket_events} ->
      bucket_events
      |> Enum.map(fn e -> e[:agent_id] end)
      |> Enum.uniq()
      |> length() >= min_endpoints
    end)
    |> Enum.map(fn {{bucket, event_type}, bucket_events} ->
      agents = bucket_events |> Enum.map(fn e -> e[:agent_id] end) |> Enum.uniq()
      %{
        time_bucket: bucket * bucket_size,
        event_type: event_type,
        endpoints: agents,
        endpoint_count: length(agents),
        event_count: length(bucket_events)
      }
    end)
  end

  defp detect_sequential_connections(network_events) do
    # Find chains: Agent A connects to Agent B's IP, then Agent B connects to Agent C
    # Group by source agent
    by_agent =
      network_events
      |> Enum.group_by(fn e -> e[:agent_id] end)

    # For each agent, check if destinations match other agent IPs
    agent_ips =
      network_events
      |> Enum.flat_map(fn e ->
        payload = e[:payload] || %{}
        local_ip = payload[:local_ip] || payload["local_ip"]
        agent_id = e[:agent_id]
        if local_ip && agent_id, do: [{local_ip, agent_id}], else: []
      end)
      |> Map.new()

    by_agent
    |> Enum.flat_map(fn {src_agent, agent_events} ->
      agent_events
      |> Enum.flat_map(fn e ->
        payload = e[:payload] || %{}
        remote_ip = payload[:remote_ip] || payload["remote_ip"]
        dst_agent = Map.get(agent_ips, remote_ip)

        if dst_agent && dst_agent != src_agent do
          [%{
            pattern: :sequential_connection,
            source_agent: src_agent,
            destination_agent: dst_agent,
            remote_ip: remote_ip,
            timestamp: e[:timestamp],
            severity: :high
          }]
        else
          []
        end
      end)
    end)
    |> Enum.uniq_by(fn m -> {m.source_agent, m.destination_agent} end)
  end

  defp detect_hash_propagation(process_events) do
    # Group by hash, sorted by time, check if same hash appears on new endpoints over time
    process_events
    |> Enum.map(fn e ->
      payload = e[:payload] || %{}
      hash = payload[:sha256] || payload["sha256"]
      agent_id = e[:agent_id]
      ts = e[:timestamp] || 0
      if hash && agent_id, do: {hash, agent_id, ts}, else: nil
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.group_by(&elem(&1, 0))
    |> Enum.filter(fn {_hash, entries} ->
      entries |> Enum.map(&elem(&1, 1)) |> Enum.uniq() |> length() >= 2
    end)
    |> Enum.map(fn {hash, entries} ->
      sorted = Enum.sort_by(entries, &elem(&1, 2))
      agents = sorted |> Enum.map(&elem(&1, 1)) |> Enum.uniq()
      timestamps = sorted |> Enum.map(&elem(&1, 2))

      %{
        pattern: :hash_propagation,
        sha256: hash,
        agents: agents,
        agent_count: length(agents),
        propagation_order: agents,
        first_seen: List.first(timestamps),
        last_seen: List.last(timestamps),
        spread_time_ms: List.last(timestamps) - List.first(timestamps),
        severity: if(length(agents) >= 3, do: :critical, else: :high)
      }
    end)
  end

  defp cleanup_old_events do
    now = System.system_time(:millisecond)
    threshold = now - Config.event_ttl()

    # Clean up old events
    :ets.tab2list(@table_name)
    |> Enum.each(fn {key, event} ->
      if (event[:timestamp] || 0) < threshold do
        :ets.delete_object(@table_name, {key, event})
      end
    end)

    # Clean up cross-endpoint correlations
    :ets.tab2list(@cross_endpoint_table)
    |> Enum.each(fn {key, entry} ->
      if (entry[:timestamp] || 0) < threshold do
        :ets.delete_object(@cross_endpoint_table, {key, entry})
      end
    end)

    # Clean up expired correlation cache entries
    cache_threshold = now - @correlation_cache_ttl_ms
    :ets.tab2list(@correlation_cache_table)
    |> Enum.each(fn {key, entry} ->
      if (entry[:cached_at] || 0) < cache_threshold do
        :ets.delete(@correlation_cache_table, key)
      end
    end)

    # Enforce max size on correlation cache (evict oldest entries)
    cache_size = :ets.info(@correlation_cache_table, :size) || 0
    if cache_size > @correlation_cache_max_entries do
      entries_to_evict = cache_size - @correlation_cache_max_entries
      :ets.tab2list(@correlation_cache_table)
      |> Enum.sort_by(fn {_key, entry} -> entry[:cached_at] || 0 end)
      |> Enum.take(entries_to_evict)
      |> Enum.each(fn {key, _entry} -> :ets.delete(@correlation_cache_table, key) end)
    end

    # Safety valve for per-agent process tree graphs: these accumulate a vertex
    # per process seen and are never pruned on process exit. Drop any agent tree
    # that has grown past the bound so a long-lived agent cannot leak unbounded.
    :ets.tab2list(@process_tree_table)
    |> Enum.each(fn {agent_id, graph} ->
      if Graph.num_vertices(graph) > @process_tree_max_vertices do
        :ets.delete(@process_tree_table, agent_id)
        Logger.warning("Evicted oversized process tree for agent #{agent_id} (>#{@process_tree_max_vertices} vertices)")
      end
    end)

    Logger.debug("Correlation engine cleanup completed")
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, Config.cleanup_interval())
  end

  # ---------------------------------------------------------------------------
  # Temporal pattern detection (delegates to TemporalScorer)
  # ---------------------------------------------------------------------------

  # Rate-limit temporal anomaly detection to once per 60s per agent
  @temporal_rate_limit_ms 60_000

  defp detect_temporal_patterns(agent_id, event) do
    try do
      # 1. Score the event for temporal proximity (side effect: records it)
      temporal_score = TemporalScorer.score_event(event, agent_id)

      # 2. Check for burst behavior on this event type
      event_type = EventTypes.normalize(event[:event_type] || event["event_type"])
      burst_score = TemporalScorer.get_burst_score(agent_id, event_type)

      # 3. Rate-limited temporal anomaly detection
      now_ms = System.system_time(:millisecond)
      rate_key = {:temporal_last_check, agent_id}
      last_check = Process.get(rate_key, 0)

      anomalies = if now_ms - last_check >= @temporal_rate_limit_ms do
        Process.put(rate_key, now_ms)
        TemporalScorer.detect_temporal_anomalies(agent_id,
          window_ms: :timer.minutes(5))
      else
        []
      end

      # Convert anomalies to correlation detections
      anomaly_detections =
        Enum.map(anomalies, fn anomaly ->
          %{
            type: anomaly.type,
            description: anomaly.description,
            mitre_tactics: anomaly[:mitre_tactics] || [],
            mitre_techniques: anomaly[:mitre_techniques] || [],
            temporal_score: temporal_score,
            burst_score: burst_score
          }
        end)

      # 4. If burst score is extreme (>= 0.9) and not already captured by
      #    an anomaly, add a standalone burst detection
      burst_detection =
        if burst_score >= 0.9 and
           not Enum.any?(anomaly_detections, &(&1.type == :rapid_succession)) do
          [%{
            type: :temporal_burst,
            description: "Extreme event burst detected for #{event_type} (burst score #{Float.round(burst_score, 2)})",
            mitre_tactics: ["execution"],
            mitre_techniques: [],
            temporal_score: temporal_score,
            burst_score: burst_score
          }]
        else
          []
        end

      anomaly_detections ++ burst_detection
    rescue
      e ->
        Logger.warning("Temporal pattern detection failed: #{inspect(e)}")
        []
    catch
      :exit, _ -> []
    end
  end

  # Extract a millisecond timestamp from an event, falling back to 0.
  defp event_ts_ms(nil), do: 0

  defp event_ts_ms(event) do
    raw = event[:timestamp] || event["timestamp"]

    case raw do
      ms when is_integer(ms) and ms > 1_000_000_000_000 -> ms
      s when is_integer(s) -> s * 1_000
      %DateTime{} = dt -> DateTime.to_unix(dt, :millisecond)
      _ -> 0
    end
  end

  defp update_stats(state, keys) when is_list(keys) do
    Enum.reduce(keys, state, fn key, acc ->
      update_stats(acc, key)
    end)
  end

  defp update_stats(state, key) do
    %{state | stats: Map.update(state.stats, key, 1, &(&1 + 1))}
  end

  # ============================================================================
  # Public API Wrapper Functions
  # ============================================================================

  @doc """
  Correlate events across multiple endpoints.
  Detects lateral movement, shared IOCs, and coordinated attacks.

  Options:
    - :time_window_ms - Time window for correlation (default: 10 minutes)
    - :min_endpoints - Minimum endpoints to consider a cross-endpoint pattern (default: 2)
  """
  @spec correlate_cross_endpoint(keyword()) :: {:ok, map()} | {:error, term()}
  def correlate_cross_endpoint(opts \\ []) do
    GenServer.call(__MODULE__, {:correlate_cross_endpoint, opts}, 30_000)
  end

  @doc """
  Find endpoints that share indicators of compromise (hashes, IPs, domains).
  """
  @spec find_shared_iocs(keyword()) :: {:ok, [map()]}
  def find_shared_iocs(opts \\ []) do
    GenServer.call(__MODULE__, {:find_shared_iocs, opts}, 30_000)
  end

  @doc """
  Detect potential lateral movement patterns across agents.
  """
  @spec detect_lateral_movement(keyword()) :: {:ok, [map()]}
  def detect_lateral_movement(opts \\ []) do
    GenServer.call(__MODULE__, {:detect_lateral_movement, opts}, 30_000)
  end

  @doc """
  Correlate events from different agents to find cross-endpoint attack patterns.

  Given a list of events from multiple agents, identifies:
  - Same IOC (hash, IP, domain) appearing on multiple endpoints
  - Same user account active on multiple endpoints within a short timeframe
  - Sequential attack patterns (e.g., recon on host A, lateral movement to host B)

  Groups correlated events by a generated correlation_id and calculates
  confidence based on temporal proximity and IOC overlap.

  ## Parameters
  - `events` - List of event maps from different agents
  - `opts` - Options:
    - `:time_window_ms` - Maximum time gap for temporal correlation (default: 10 minutes)
    - `:min_confidence` - Minimum confidence to include a correlation group (default: 0.3)

  ## Returns
  A list of correlation group maps, each containing:
  - `:correlation_id` - Unique identifier for this group
  - `:correlation_type` - The type of correlation found
  - `:events` - The correlated events
  - `:agents` - List of distinct agent IDs involved
  - `:confidence` - Calculated confidence score (0.0 - 1.0)
  - `:description` - Human-readable description
  """
  @spec correlate_across_agents([map()], keyword()) :: [map()]
  def correlate_across_agents(events, opts \\ []) do
    time_window_ms = Keyword.get(opts, :time_window_ms, :timer.minutes(10))
    min_confidence = Keyword.get(opts, :min_confidence, 0.3)

    correlations =
      do_ioc_cross_correlation(events, time_window_ms) ++
      do_user_cross_correlation(events, time_window_ms) ++
      do_sequential_attack_correlation(events, time_window_ms)

    correlations
    |> Enum.filter(fn group -> group.confidence >= min_confidence end)
    |> Enum.sort_by(& &1.confidence, :desc)
  end

  # Find same IOC (hash, IP, domain) appearing on multiple endpoints.
  defp do_ioc_cross_correlation(events, time_window_ms) do
    ioc_types = [
      {:sha256, "hash"},
      {:remote_ip, "ip"},
      {:domain, "domain"}
    ]

    Enum.flat_map(ioc_types, fn {field, ioc_label} ->
      events
      |> Enum.map(fn e ->
        payload = e[:payload] || e["payload"] || %{}
        value = payload[field] || payload[to_string(field)]
        agent_id = e[:agent_id] || e["agent_id"]
        ts = e[:timestamp] || e["timestamp"] || 0
        if value && agent_id, do: {value, agent_id, ts, e}, else: nil
      end)
      |> Enum.reject(&is_nil/1)
      |> Enum.group_by(&elem(&1, 0))
      |> Enum.filter(fn {_value, entries} ->
        entries |> Enum.map(&elem(&1, 1)) |> Enum.uniq() |> length() >= 2
      end)
      |> Enum.map(fn {ioc_value, entries} ->
        agents = entries |> Enum.map(&elem(&1, 1)) |> Enum.uniq()
        timestamps = entries |> Enum.map(&elem(&1, 2)) |> Enum.sort()
        matched_events = entries |> Enum.map(&elem(&1, 3))

        time_span = List.last(timestamps) - List.first(timestamps)
        temporal_factor = if time_span <= time_window_ms, do: 1.0, else: max(0.3, 1.0 - time_span / (time_window_ms * 5))
        agent_factor = min(1.0, length(agents) * 0.2 + 0.4)
        confidence = Float.round(min(1.0, temporal_factor * agent_factor), 3)

        %{
          correlation_id: "ioc_#{ioc_label}_#{:erlang.phash2(ioc_value)}",
          correlation_type: :"shared_#{ioc_label}",
          ioc_type: ioc_label,
          ioc_value: ioc_value,
          events: matched_events,
          agents: agents,
          agent_count: length(agents),
          time_span_ms: time_span,
          first_seen: List.first(timestamps),
          last_seen: List.last(timestamps),
          confidence: confidence,
          description: "Same #{ioc_label} (#{ioc_value}) seen on #{length(agents)} endpoints within #{div(time_span, 1000)}s"
        }
      end)
    end)
  end

  # Find same user account active on multiple endpoints in a short timeframe.
  defp do_user_cross_correlation(events, time_window_ms) do
    events
    |> Enum.map(fn e ->
      payload = e[:payload] || e["payload"] || %{}
      user = payload[:user] || payload["user"]
      agent_id = e[:agent_id] || e["agent_id"]
      ts = e[:timestamp] || e["timestamp"] || 0
      if user && agent_id, do: {user, agent_id, ts, e}, else: nil
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.group_by(&elem(&1, 0))
    |> Enum.filter(fn {_user, entries} ->
      entries |> Enum.map(&elem(&1, 1)) |> Enum.uniq() |> length() >= 2
    end)
    |> Enum.map(fn {user, entries} ->
      agents = entries |> Enum.map(&elem(&1, 1)) |> Enum.uniq()
      timestamps = entries |> Enum.map(&elem(&1, 2)) |> Enum.sort()
      matched_events = entries |> Enum.map(&elem(&1, 3))

      time_span = List.last(timestamps) - List.first(timestamps)

      # Tighter time windows yield higher confidence -- rapid user pivoting is suspicious
      temporal_factor =
        cond do
          time_span <= :timer.minutes(1) -> 1.0
          time_span <= :timer.minutes(5) -> 0.85
          time_span <= time_window_ms -> 0.7
          true -> 0.4
        end

      agent_factor = min(1.0, length(agents) * 0.25 + 0.3)
      confidence = Float.round(min(1.0, temporal_factor * agent_factor), 3)

      %{
        correlation_id: "user_spread_#{:erlang.phash2(user)}",
        correlation_type: :user_cross_endpoint,
        user: user,
        events: matched_events,
        agents: agents,
        agent_count: length(agents),
        time_span_ms: time_span,
        first_seen: List.first(timestamps),
        last_seen: List.last(timestamps),
        confidence: confidence,
        description: "User '#{user}' active on #{length(agents)} endpoints within #{div(time_span, 1000)}s (possible lateral movement)"
      }
    end)
  end

  # Detect sequential attack patterns: recon on host A followed by lateral movement to host B.
  defp do_sequential_attack_correlation(events, time_window_ms) do
    # Classify events by attack phase
    classified =
      events
      |> Enum.map(fn e ->
        payload = e[:payload] || e["payload"] || %{}
        cmdline = payload[:cmdline] || payload["cmdline"] || ""
        event_type = EventTypes.normalize(e[:event_type] || e["event_type"])
        agent_id = e[:agent_id] || e["agent_id"]
        ts = e[:timestamp] || e["timestamp"] || 0
        phase = classify_attack_phase(event_type, cmdline)
        if phase && agent_id, do: {phase, agent_id, ts, e}, else: nil
      end)
      |> Enum.reject(&is_nil/1)

    # Group by agent and look for recon -> lateral movement across different agents
    recon_events =
      classified
      |> Enum.filter(fn {phase, _, _, _} -> phase == :reconnaissance end)

    lateral_events =
      classified
      |> Enum.filter(fn {phase, _, _, _} -> phase == :lateral_movement end)

    # For each recon event, check if a lateral movement event on a DIFFERENT agent
    # follows within the time window
    recon_events
    |> Enum.flat_map(fn {_phase, recon_agent, recon_ts, recon_event} ->
      lateral_events
      |> Enum.filter(fn {_phase, lat_agent, lat_ts, _lat_event} ->
        lat_agent != recon_agent &&
          lat_ts > recon_ts &&
          lat_ts - recon_ts <= time_window_ms
      end)
      |> Enum.map(fn {_phase, lat_agent, lat_ts, lat_event} ->
        time_delta = lat_ts - recon_ts

        # Closer temporal proximity => higher confidence
        temporal_factor =
          cond do
            time_delta <= :timer.minutes(1) -> 1.0
            time_delta <= :timer.minutes(5) -> 0.85
            time_delta <= time_window_ms -> 0.65
            true -> 0.4
          end

        confidence = Float.round(temporal_factor * 0.85, 3)

        %{
          correlation_id: "seq_attack_#{:erlang.phash2({recon_agent, lat_agent, recon_ts})}",
          correlation_type: :sequential_attack,
          events: [recon_event, lat_event],
          agents: [recon_agent, lat_agent],
          agent_count: 2,
          source_agent: recon_agent,
          target_agent: lat_agent,
          time_span_ms: time_delta,
          first_seen: recon_ts,
          last_seen: lat_ts,
          confidence: confidence,
          description: "Reconnaissance on #{recon_agent} followed by lateral movement to #{lat_agent} (#{div(time_delta, 1000)}s gap)"
        }
      end)
    end)
    |> Enum.uniq_by(fn g -> {g.source_agent, g.target_agent} end)
  end

  # Classify an event into an attack phase based on event type and command line content.
  defp classify_attack_phase(event_type, cmdline) do
    cond do
      # Reconnaissance phase: discovery commands
      Regex.match?(~r/(?:net\s+user|net\s+group|nltest|dsquery|whoami|systeminfo|ipconfig|net\s+share|net\s+view|arp\s+-a|nbtstat)/i, cmdline) ->
        :reconnaissance

      # Lateral movement phase: remote execution tools
      Regex.match?(~r/(?:psexec|wmic\s+.*process\s+.*call|winrm|invoke-command|enter-pssession|new-pssession|copy.*\\\\|net\s+use\s+\\\\)/i, cmdline) ->
        :lateral_movement

      # Lateral movement via network events to internal IPs
      event_type == :network_connect and
        Regex.match?(~r/(?:445|135|5985|5986|3389|22)\b/, cmdline) ->
        :lateral_movement

      true ->
        nil
    end
  end

  @doc """
  Correlate events by specified criteria.
  """
  def correlate_by_criteria(events, criteria \\ %{}) do
    GenServer.call(__MODULE__, {:correlate_by_criteria, events, criteria})
  end

  @doc """
  Get a correlation timeline by ID.
  """
  def get_timeline(timeline_id) do
    GenServer.call(__MODULE__, {:get_timeline, timeline_id})
  end

  @doc """
  List all correlation timelines with optional filters.
  """
  def list_timelines(opts \\ %{}) do
    GenServer.call(__MODULE__, {:list_timelines, opts})
  end

  # ============================================================================
  # Related Events Correlation
  # ============================================================================

  @doc """
  Get events related to a source event by actual correlation, not just time.

  Correlation criteria (with scoring):
  1. Same process (PID match = 100 points)
  2. Parent/child relationship (80 points)
  3. Sibling process (same PPID = 60 points)
  4. Same file hash (70 points)
  5. Same network destination (50 points)
  6. Same user (30 points)
  7. Temporal proximity (5-20 points based on closeness)

  Returns a list of events with :correlation_score and :correlation_reason fields.
  """
  @spec get_related_events(String.t(), String.t() | nil, integer()) :: [map()]
  def get_related_events(agent_id, source_event_id, time_window_minutes \\ 30) do
    # Get the source event from database
    source_event = case source_event_id do
      nil -> nil
      id -> TamanduaServer.Telemetry.get_event(id)
    end

    if source_event do
      get_correlated_events(agent_id, source_event, time_window_minutes)
    else
      # Fallback to recent events for this agent
      get_recent_events_for_agent(agent_id, time_window_minutes)
    end
  end

  defp get_correlated_events(agent_id, source_event, time_window_minutes) do
    # Extract criteria from source event
    payload = source_event.payload || %{}
    timestamp = source_event.timestamp

    # Get criteria for correlation - handle both atom and string keys
    pid = payload[:pid] || payload["pid"]
    ppid = payload[:ppid] || payload["ppid"]
    sha256 = payload[:sha256] || payload["sha256"]
    remote_ip = payload[:remote_ip] || payload["remote_ip"]
    user = payload[:user] || payload["user"]

    criteria = %{
      source_event_id: source_event.id,
      pid: pid,
      ppid: ppid,
      sha256: sha256,
      remote_ip: remote_ip,
      user: user,
      timestamp: timestamp,
      time_window_minutes: time_window_minutes
    }

    # Get events from ETS (fast in-memory storage)
    window_ms = time_window_minutes * 60 * 1000
    ets_events = get_ets_events_for_agent(agent_id, timestamp, window_ms)

    # Also get events from database for completeness
    db_events = get_db_events_for_agent(agent_id, timestamp, time_window_minutes)

    # Combine and deduplicate (prefer ETS events as they have richer data)
    all_events = (ets_events ++ db_events)
    |> Enum.uniq_by(fn e ->
      # Deduplicate by event_id if present, else by type+timestamp+pid
      # Use bracket access for safety with both maps and structs
      e[:event_id] || e[:id] || {e[:event_type], e[:timestamp], get_in(e, [:payload, :pid])}
    end)
    |> Enum.reject(fn e ->
      # Exclude the source event itself
      (e[:event_id] || e[:id]) == source_event.id
    end)

    # Calculate correlation scores and reasons
    all_events
    |> Enum.map(fn event ->
      {score, reasons} = calculate_event_correlation_score(event, criteria)
      event
      |> Map.put(:correlation_score, score)
      |> Map.put(:correlation_reason, Enum.join(reasons, ", "))
    end)
    |> Enum.filter(fn e -> e[:correlation_score] > 0 end)
    |> Enum.filter(&strong_related_event?/1)
    |> Enum.sort_by(fn e -> e[:correlation_score] end, :desc)
    |> Enum.take(50)
  end

  defp get_ets_events_for_agent(agent_id, reference_time, window_ms) do
    # Get all events for this agent from ETS
    :ets.tab2list(@table_name)
    |> Enum.filter(fn {{a_id, _pid}, _event} -> a_id == agent_id end)
    |> Enum.map(fn {_key, event} -> event end)
    |> Enum.filter(fn event ->
      case {event[:timestamp], reference_time} do
        {nil, _} -> false
        {_, nil} -> true
        {event_ts, ref_ts} -> calculate_time_diff_ms(event_ts, ref_ts) <= window_ms
      end
    end)
  end

  defp strong_related_event?(event) do
    score = event[:correlation_score] || 0
    reason = event[:correlation_reason] || ""

    score >= 50 and
      Enum.any?(
        [
          "Same process",
          "Child of source process",
          "Parent of source process",
          "Sibling process",
          "Same file hash",
          "Same network destination"
        ],
        &String.contains?(reason, &1)
      )
  end

  defp get_db_events_for_agent(agent_id, reference_time, time_window_minutes) do
    # Get events from database within the time window
    TamanduaServer.Telemetry.list_events_for_agent(agent_id, 100)
    |> Enum.filter(fn event ->
      case {event.timestamp, reference_time} do
        {nil, _} -> false
        {_, nil} -> true
        {event_ts, ref_ts} ->
          diff_ms = calculate_time_diff_ms(event_ts, ref_ts)
          diff_ms <= time_window_minutes * 60 * 1000
      end
    end)
    |> Enum.map(fn event ->
      # Convert Ecto struct to map format compatible with ETS events
      %{
        event_id: event.id,
        id: event.id,
        event_type: event.event_type,
        timestamp: event.timestamp,
        payload: event.payload || %{},
        severity: event.severity
      }
    end)
  end

  defp calculate_event_correlation_score(event, criteria) do
    # Handle both ETS events (maps with atom/string keys) and DB events
    # Use only bracket access for safety with both maps and structs
    payload = event[:payload] || %{}
    event_ts = event[:timestamp]

    event_pid = payload[:pid] || payload["pid"]
    event_ppid = payload[:ppid] || payload["ppid"]
    event_sha256 = payload[:sha256] || payload["sha256"]
    event_remote_ip = payload[:remote_ip] || payload["remote_ip"]
    event_user = payload[:user] || payload["user"]

    # Build list of scores and reasons
    scores_and_reasons = [
      # Same process (highest weight)
      if(event_pid && event_pid == criteria.pid,
        do: {100, "Same process (PID #{event_pid})"},
        else: nil),

      # Parent/child relationship
      if(event_pid && event_pid == criteria.ppid,
        do: {80, "Child of source process"},
        else: nil),
      if(event_ppid && event_ppid == criteria.pid,
        do: {80, "Parent of source process"},
        else: nil),

      # Same parent (sibling process)
      if(event_ppid && criteria.ppid && event_ppid == criteria.ppid && event_pid != criteria.pid,
        do: {60, "Sibling process (same parent PID #{event_ppid})"},
        else: nil),

      # Same file hash
      if(event_sha256 && criteria.sha256 && event_sha256 == criteria.sha256,
        do: {70, "Same file hash"},
        else: nil),

      # Same network destination
      if(event_remote_ip && criteria.remote_ip && event_remote_ip == criteria.remote_ip,
        do: {50, "Same network destination (#{event_remote_ip})"},
        else: nil),

      # Same user
      if(event_user && criteria.user && event_user == criteria.user,
        do: {30, "Same user (#{event_user})"},
        else: nil),

      # Temporal proximity
      calculate_temporal_proximity_score(event_ts, criteria.timestamp, criteria.time_window_minutes)
    ]
    |> Enum.reject(&is_nil/1)

    # Sum scores and collect reasons
    total_score = scores_and_reasons |> Enum.map(&elem(&1, 0)) |> Enum.sum()
    reasons = scores_and_reasons |> Enum.map(&elem(&1, 1))

    {total_score, reasons}
  end

  defp calculate_temporal_proximity_score(event_ts, source_ts, _time_window_minutes) do
    case {event_ts, source_ts} do
      {nil, _} -> nil
      {_, nil} -> nil
      {event_dt, source_dt} ->
        # Handle both DateTime and NaiveDateTime/integer
        diff_ms = calculate_time_diff_ms(event_dt, source_dt)

        cond do
          diff_ms < 5_000 -> {20, "Within 5 seconds"}
          diff_ms < 30_000 -> {15, "Within 30 seconds"}
          diff_ms < 60_000 -> {10, "Within 1 minute"}
          diff_ms < 300_000 -> {5, "Within 5 minutes"}
          true -> nil
        end
    end
  end

  defp calculate_time_diff_ms(dt1, dt2) when is_integer(dt1) and is_integer(dt2) do
    abs(dt1 - dt2)
  end

  defp calculate_time_diff_ms(%DateTime{} = dt1, %DateTime{} = dt2) do
    abs(DateTime.diff(dt1, dt2, :millisecond))
  end

  defp calculate_time_diff_ms(dt1, dt2) do
    # Try to convert to DateTime if possible
    try do
      dt1_converted = ensure_datetime(dt1)
      dt2_converted = ensure_datetime(dt2)
      abs(DateTime.diff(dt1_converted, dt2_converted, :millisecond))
    rescue
      _ -> 999_999_999  # Return large diff if conversion fails
    end
  end

  defp ensure_datetime(%DateTime{} = dt), do: dt
  defp ensure_datetime(%NaiveDateTime{} = ndt) do
    DateTime.from_naive!(ndt, "Etc/UTC")
  end
  defp ensure_datetime(ts) when is_integer(ts) do
    DateTime.from_unix!(ts, :millisecond)
  end
  defp ensure_datetime(_), do: raise("Cannot convert to DateTime")

  defp get_recent_events_for_agent(agent_id, _time_window_minutes) do
    # Fallback: get recent events from database without correlation scoring
    TamanduaServer.Telemetry.list_events_for_agent(agent_id, 50)
    |> Enum.map(fn event ->
      %{
        event_id: event.id,
        id: event.id,
        event_type: event.event_type,
        timestamp: event.timestamp,
        payload: event.payload || %{},
        severity: event.severity,
        correlation_score: 0,
        correlation_reason: "Fallback: recent event from same agent"
      }
    end)
  end
end
