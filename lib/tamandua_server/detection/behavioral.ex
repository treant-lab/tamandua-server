defmodule TamanduaServer.Detection.Behavioral do
  @moduledoc """
  Behavioral Analytics Engine

  Detects anomalies in user and system behavior using statistical models
  and baseline profiling. This goes beyond simple rule-based detection.

  Features:
  - User behavior profiling (login times, accessed resources, typical operations)
  - Process behavior baselines (normal parent-child relationships, typical args)
  - Network pattern analysis (connection frequency, data volumes, destinations)
  - Entity context scoring (combines multiple signals into risk score)
  - Anomaly detection using statistical methods (z-score against persisted baselines)
  - Rule-based process/command-line detection via compiled regexes
  - Periodic baseline persistence to database
  - Z-score anomaly detection with online mean/variance (Welford's algorithm)
  - Peer group analysis comparing entities against similar peers
  - Temporal pattern detection (time-of-day, day-of-week baselines)
  - Adaptive threshold learning via Bayesian updating from analyst feedback
  - Risk score trending with exponentially weighted moving average (EWMA)
  - PubSub integration for real-time telemetry ingestion and dashboard stats

  ## ETS Tables (public reads, GenServer mutations)

  - `:behavioral_profiles`       - Entity profiles (user/process/host baselines)
  - `:behavioral_stats`          - Online statistics (mean/variance per feature)
  - `:behavioral_peer_groups`    - Peer group membership and aggregated norms
  - `:behavioral_temporal`       - Temporal pattern matrices (hour x day_of_week)
  - `:behavioral_thresholds`     - Adaptive thresholds per entity type/feature
  - `:behavioral_risk_trends`    - EWMA risk score trends per entity

  Detection rules are defined as structured maps with compiled regex patterns,
  severity levels, and MITRE ATT&CK technique references.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.Config
  alias TamanduaServer.Detection.EventTypes
  alias TamanduaServer.Detection.Evidence
  alias TamanduaServer.Alerts

  # ============================================================================
  # ETS Table Names (public for reads, GenServer serializes writes)
  # ============================================================================

  @profiles_table :behavioral_profiles
  @stats_table :behavioral_stats
  @peer_groups_table :behavioral_peer_groups
  @temporal_table :behavioral_temporal
  @thresholds_table :behavioral_thresholds
  @risk_trends_table :behavioral_risk_trends
  # Recent significant anomalies per {entity_type, entity_id}, read by
  # TamanduaServerWeb.API.V1.BehavioralController. Bounded to
  # @anomaly_history_per_entity most-recent entries to cap memory.
  @anomaly_table :behavioral_anomalies
  @anomaly_history_per_entity 100

  # GeoIP ETS cache table
  @geoip_cache_table :geoip_cache
  # Earth radius in km (for Haversine formula)
  @earth_radius_km 6371.0
  # GeoIP API base URL (ip-api.com, free for non-commercial use)
  @geoip_api_url "http://ip-api.com/json/"

  # EWMA smoothing factor (alpha). Higher = more weight on recent observations.
  @ewma_alpha 0.15
  # Minimum observations before z-score alerts are emitted
  @min_observations_for_zscore 30
  # Sustained risk trend window (number of EWMA ticks above threshold to alert)
  @sustained_risk_ticks 5
  # Periodic schedule intervals
  @trend_tick_interval :timer.minutes(1)
  @cleanup_interval :timer.minutes(10)
  @pubsub_stats_interval :timer.seconds(30)
  # Peer group recalculation interval
  @peer_group_recalc_interval :timer.minutes(15)
  # Adaptive threshold Bayesian prior strength (pseudo-observations)
  @threshold_prior_strength 10

  # ============================================================================
  # Rule Definitions (regex-based, loaded once at compile time as defaults)
  # ============================================================================

  @default_process_rules [
    # === Original rules ===
    %{
      id: "mimikatz_execution",
      pattern: %{process_name: ~r/mimikatz/i},
      severity: :critical,
      risk_score: 95,
      mitre: ["T1003.001"],
      description: "Mimikatz credential dumping tool detected"
    },
    %{
      id: "psexec_execution",
      pattern: %{process_name: ~r/psexec/i},
      severity: :high,
      risk_score: 85,
      mitre: ["T1570", "T1021.002"],
      description: "PsExec remote execution tool detected"
    },
    %{
      id: "cobalt_strike_beacon",
      pattern: %{process_name: ~r/(?:cobalt|beacon)/i},
      severity: :critical,
      risk_score: 95,
      mitre: ["T1071.001"],
      description: "Cobalt Strike beacon detected"
    },
    %{
      id: "typosquatted_system_process",
      pattern: %{process_name: ~r/(?:svch0st|lsas[^s]|csrs[^s])/i},
      severity: :high,
      risk_score: 85,
      mitre: ["T1036.005"],
      description: "Typosquatted system process name detected"
    },
    %{
      id: "random_name_executable",
      pattern: %{process_name: ~r/^[a-z0-9]{16,}\.exe$/i},
      severity: :medium,
      risk_score: 60,
      mitre: ["T1036"],
      description: "Executable with random-looking name detected"
    },

    # === NEW: Credential Dumping Tools ===
    %{
      id: "lazagne_execution",
      pattern: %{process_name: ~r/lazagne/i},
      severity: :critical,
      risk_score: 95,
      mitre: ["T1003", "T1555"],
      description: "LaZagne credential harvesting tool detected"
    },
    %{
      id: "procdump_lsass",
      pattern: %{process_name: ~r/procdump/i},
      severity: :high,
      risk_score: 85,
      mitre: ["T1003.001"],
      description: "ProcDump detected (potential LSASS dump)"
    },
    %{
      id: "comsvcs_minidump",
      pattern: %{process_name: ~r/rundll32/i},
      severity: :high,
      risk_score: 80,
      mitre: ["T1003.001"],
      description: "Rundll32 detected (check for comsvcs.dll MiniDump)"
    },
    %{
      id: "secretsdump_execution",
      pattern: %{process_name: ~r/secretsdump/i},
      severity: :critical,
      risk_score: 95,
      mitre: ["T1003.002", "T1003.003"],
      description: "Impacket secretsdump detected"
    },

    # === NEW: Lateral Movement Tools ===
    %{
      id: "wmiexec_execution",
      pattern: %{process_name: ~r/wmiexec/i},
      severity: :high,
      risk_score: 85,
      mitre: ["T1047", "T1021.006"],
      description: "WMI execution tool detected"
    },
    %{
      id: "smbexec_execution",
      pattern: %{process_name: ~r/smbexec/i},
      severity: :high,
      risk_score: 85,
      mitre: ["T1021.002"],
      description: "SMB execution tool detected"
    },
    %{
      id: "dcomexec_execution",
      pattern: %{process_name: ~r/dcomexec/i},
      severity: :high,
      risk_score: 85,
      mitre: ["T1021.003"],
      description: "DCOM execution tool detected"
    },
    %{
      id: "atexec_execution",
      pattern: %{process_name: ~r/atexec/i},
      severity: :high,
      risk_score: 80,
      mitre: ["T1053.002"],
      description: "AT execution tool detected"
    },

    # === NEW: C2 Frameworks ===
    %{
      id: "sliver_implant",
      pattern: %{process_name: ~r/sliver/i},
      severity: :critical,
      risk_score: 95,
      mitre: ["T1071.001", "T1095"],
      description: "Sliver C2 implant detected"
    },
    %{
      id: "metasploit_payload",
      pattern: %{process_name: ~r/(?:meterpreter|msfvenom|msf)/i},
      severity: :critical,
      risk_score: 95,
      mitre: ["T1071.001"],
      description: "Metasploit payload detected"
    },
    %{
      id: "bruteratel_implant",
      pattern: %{process_name: ~r/(?:brute\s*ratel|badger)/i},
      severity: :critical,
      risk_score: 95,
      mitre: ["T1071.001"],
      description: "Brute Ratel C4 implant detected"
    },
    %{
      id: "empire_agent",
      pattern: %{process_name: ~r/(?:empire|starkiller)/i},
      severity: :critical,
      risk_score: 90,
      mitre: ["T1059.001", "T1071.001"],
      description: "Empire/Starkiller C2 agent detected"
    },

    # === NEW: Reconnaissance Tools ===
    %{
      id: "bloodhound_collector",
      pattern: %{process_name: ~r/(?:bloodhound|sharphound|azurehound)/i},
      severity: :high,
      risk_score: 85,
      mitre: ["T1087.002", "T1069.002"],
      description: "BloodHound AD enumeration tool detected"
    },
    %{
      id: "adrecon_tool",
      pattern: %{process_name: ~r/adrecon/i},
      severity: :high,
      risk_score: 80,
      mitre: ["T1087.002"],
      description: "ADRecon Active Directory enumeration detected"
    },

    # === NEW: Evasion Tools ===
    %{
      id: "rubeus_kerberos",
      pattern: %{process_name: ~r/rubeus/i},
      severity: :critical,
      risk_score: 95,
      mitre: ["T1558.003", "T1550.003"],
      description: "Rubeus Kerberos attack tool detected"
    },
    %{
      id: "kekeo_tool",
      pattern: %{process_name: ~r/kekeo/i},
      severity: :critical,
      risk_score: 95,
      mitre: ["T1558"],
      description: "Kekeo Kerberos exploitation tool detected"
    },

    # === NEW: Process Injection Indicators ===
    %{
      id: "process_hollowing_tool",
      pattern: %{process_name: ~r/(?:hollow|donut|shellcode)/i},
      severity: :critical,
      risk_score: 90,
      mitre: ["T1055.012"],
      description: "Process hollowing/shellcode tool detected"
    }
  ]

  # ============================================================================
  # Legitimate Parent Process Patterns (for reducing false positives)
  # ============================================================================
  # These patterns match processes that legitimately perform administrative
  # operations. When a rule match has a legitimate parent, severity is reduced.

  @legitimate_system_parents [
    ~r/services\.exe$/i,           # Windows Service Control Manager
    ~r/svchost\.exe$/i,            # Windows Service Host
    ~r/mmc\.exe$/i,                # Microsoft Management Console
    ~r/gpscript\.exe$/i,           # Group Policy Script
    ~r/ccmexec\.exe$/i,            # SCCM/MECM client agent
    ~r/wuauclt\.exe$/i,            # Windows Update Agent
    ~r/trustedinstaller\.exe$/i    # Windows Trusted Installer
  ]

  @legitimate_admin_parents [
    ~r/explorer\.exe$/i,           # Windows Explorer (user-initiated)
    ~r/cmd\.exe$/i,                # Command prompt
    ~r/powershell(?:_ise)?\.exe$/i # PowerShell
  ]

  @legitimate_deployment_parents [
    ~r/sccm/i,                     # SCCM/MECM management
    ~r/mecm/i,                     # Microsoft Endpoint Configuration Manager
    ~r/intune/i,                   # Microsoft Intune management
    ~r/wsus/i,                     # WSUS server
    ~r/chef/i,                     # Chef deployment
    ~r/puppet/i,                   # Puppet deployment
    ~r/ansible/i,                  # Ansible deployment
    ~r/salt[-_]?minion/i,          # SaltStack
    ~r/dsc/i,                      # PowerShell DSC
    ~r/terraform/i,                # Terraform provisioning
    ~r/chocolatey/i,               # Chocolatey package manager
    ~r/choco\.exe$/i,              # Chocolatey CLI
    ~r/winget\.exe$/i,             # Windows Package Manager
    ~r/pdqdeploy/i,                # PDQ Deploy
    ~r/landesk/i,                  # Ivanti/LANDesk
    ~r/bigfix/i                    # HCL BigFix
  ]

  @legitimate_av_parents [
    ~r/mpcmdrun\.exe$/i,           # Windows Defender CLI
    ~r/msmpeng\.exe$/i,            # Windows Defender engine
    ~r/nissrv\.exe$/i,             # Windows Defender NIS
    ~r/securityhealthservice/i,    # Windows Security Health
    ~r/senseir\.exe$/i,            # Microsoft Defender for Endpoint
    ~r/sensecncproxy/i,            # Defender EDR proxy
    ~r/cyserver/i,                 # CylancePROTECT
    ~r/csc\.exe$/i,                # CrowdStrike Sensor
    ~r/falcon/i,                   # CrowdStrike Falcon
    ~r/sentinel/i,                 # SentinelOne
    ~r/carbon\s*black/i,           # VMware Carbon Black
    ~r/sophos/i,                   # Sophos
    ~r/symantec/i,                 # Broadcom/Symantec
    ~r/mcafee/i,                   # Trellix/McAfee
    ~r/trend\s*micro/i             # Trend Micro
  ]

  @legitimate_backup_parents [
    ~r/backup/i,                   # Generic backup software
    ~r/veeam/i,                    # Veeam backup
    ~r/acronis/i,                  # Acronis backup
    ~r/shadow\s*protect/i,         # StorageCraft
    ~r/storage\s*craft/i,
    ~r/commvault/i,                # Commvault
    ~r/arcserve/i,                 # Arcserve
    ~r/veritas/i,                  # Veritas NetBackup
    ~r/datto/i,                    # Datto backup
    ~r/carbonite/i                 # Carbonite
  ]

  # ============================================================================
  # Known-safe parent-child relationships (suppress behavioral FP)
  # ============================================================================
  # Maps lowercased parent → set of lowercased children that are always legitimate.
  # These are well-documented Windows process relationships that must never trigger
  # unusual-parent alerts regardless of frequency in the baseline.

  @known_safe_parent_child %{
    "system" => MapSet.new(["smss.exe", "registry", "memory compression",
                            "system interrupts", "secure system"]),
    "smss.exe" => MapSet.new(["csrss.exe", "wininit.exe", "winlogon.exe", "smss.exe"]),
    "wininit.exe" => MapSet.new(["services.exe", "lsass.exe", "lsaiso.exe",
                                  "fontdrvhost.exe"]),
    "winlogon.exe" => MapSet.new(["dwm.exe", "fontdrvhost.exe", "userinit.exe",
                                   "logonui.exe", "mpnotify.exe"]),
    "services.exe" => MapSet.new([
      "svchost.exe", "spoolsv.exe", "searchindexer.exe", "lsass.exe",
      "vds.exe", "msdtc.exe", "dllhost.exe", "wlanext.exe", "vmtoolsd.exe",
      "vgauthservice.exe", "mqsvc.exe", "inetinfo.exe", "msiexec.exe",
      "mscorsvw.exe", "wmiprvse.exe", "alg.exe", "diagtrack.exe",
      "sensecncproxy.exe", "securityhealthservice.exe", "nvsvc64.exe",
      "dashost.exe", "pla.exe", "wmpnetwk.exe", "appidsvc.exe",
      "ui0detect.exe", "snmp.exe", "snmptrap.exe", "uhssvc.exe",
      "trustedinstaller.exe", "tiworker.exe", "wuauserv.exe",
      "bits.exe", "dosvc.exe", "usosvc.exe", "audiodg.exe"
    ]),
    "svchost.exe" => MapSet.new([
      "wuauclt.exe", "taskhostw.exe", "runtimebroker.exe", "sihost.exe",
      "ctfmon.exe", "smartscreen.exe", "backgroundtaskhost.exe",
      "mousocoreworker.exe", "dllhost.exe", "wmiprvse.exe",
      "searchprotocolhost.exe", "searchfilterhost.exe", "werfault.exe",
      "consent.exe", "securehealthagent.exe", "clipup.exe",
      "devicecensus.exe", "compattelrunner.exe", "musnotification.exe",
      "wuapihost.exe", "settingsynchost.exe", "rundll32.exe",
      "fontdrvhost.exe", "mpcmdrun.exe"
    ]),
    "userinit.exe" => MapSet.new(["explorer.exe"]),
    "explorer.exe" => MapSet.new([
      "cmd.exe", "powershell.exe", "pwsh.exe", "taskmgr.exe", "mmc.exe",
      "control.exe", "rundll32.exe", "dllhost.exe", "msiexec.exe",
      "notepad.exe", "calc.exe", "regedit.exe", "msedge.exe", "chrome.exe",
      "firefox.exe", "iexplore.exe", "outlook.exe", "winword.exe",
      "excel.exe", "powerpnt.exe", "onenote.exe", "teams.exe",
      "code.exe", "devenv.exe", "msinfo32.exe"
    ]),
    "csrss.exe" => MapSet.new(["conhost.exe", "winlogon.exe"]),
    "taskeng.exe" => MapSet.new(["conhost.exe"]),
    "taskhostw.exe" => MapSet.new(["conhost.exe"]),
    "msiexec.exe" => MapSet.new(["msiexec.exe", "rundll32.exe"]),
    "cmd.exe" => MapSet.new(["conhost.exe"]),
    "powershell.exe" => MapSet.new(["conhost.exe"]),
    "pwsh.exe" => MapSet.new(["conhost.exe"]),
    "wmiprvse.exe" => MapSet.new(["conhost.exe", "mofcomp.exe"]),
    # Systemd / Linux init
    "systemd" => MapSet.new(["systemd-journald", "systemd-logind",
                              "systemd-resolved", "systemd-networkd",
                              "systemd-udevd", "dbus-daemon"]),
    "init" => MapSet.new(["getty", "login", "cron", "atd", "sshd"])
  }

  # Common ports that should never trigger unusual-port alerts
  @common_safe_ports MapSet.new([
    80, 443, 53, 8080, 8443, 3389, 22, 135, 139, 445, 389, 636,
    5985, 5986, 88, 464, 3268, 3269, 993, 995, 587, 25, 110, 143
  ])

  @legitimate_installer_parents [
    ~r/msiexec\.exe$/i,            # Windows Installer
    ~r/setup\.exe$/i,              # Setup programs
    ~r/installer/i,                # Generic installer
    ~r/wusa\.exe$/i                # Windows Update Standalone
  ]

  @default_command_line_rules [
    # Rule 1: Encoded PowerShell - high FP when run by legitimate automation
    %{
      id: "encoded_powershell",
      pattern: ~r/-(?:enc|encodedcommand)\s/i,
      severity: :high,
      risk_score: 65,
      mitre: ["T1059.001", "T1027"],
      description: "Encoded PowerShell execution",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_deployment_parents,
      parent_reduces_severity: true
    },
    # Rule 2: Base64 decode - common in legitimate automation
    %{
      id: "base64_decode",
      pattern: ~r/frombase64/i,
      severity: :high,
      risk_score: 80,
      mitre: ["T1027", "T1140"],
      description: "Base64 decode operation in command line",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_deployment_parents,
      parent_reduces_severity: true
    },
    # Rule 3: Download cradle (.NET) - common in package managers and update tools
    %{
      id: "download_cradle_dotnet",
      pattern: ~r/(?:downloadstring|downloadfile|invoke-webrequest|start-bitstransfer)\b/i,
      severity: :high,
      risk_score: 80,
      mitre: ["T1105", "T1059.001"],
      description: "Download cradle pattern detected (.NET/PowerShell)",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_deployment_parents ++ [
        ~r/nuget\.exe$/i,
        ~r/dotnet\.exe$/i,
        ~r/windows\s*update/i
      ],
      parent_reduces_severity: true
    },
    # Rule 4: Download cradle (native) - very common for legitimate updates
    %{
      id: "download_cradle_native",
      pattern: ~r/(?:wget|curl)\s+(?:https?:\/\/|-O\s)/i,
      severity: :medium,
      risk_score: 45,
      mitre: ["T1105"],
      description: "Download cradle pattern detected (native tool)",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_deployment_parents,
      parent_reduces_severity: true
    },
    # Rule 5: Execution policy bypass - often used legitimately by IT scripts
    %{
      id: "execution_policy_bypass",
      pattern: ~r/-(?:ep|executionpolicy)\s+bypass/i,
      severity: :high,
      risk_score: 75,
      mitre: ["T1059.001"],
      description: "PowerShell execution policy bypass",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_deployment_parents ++ [
        ~r/schtasks\.exe$/i,
        ~r/taskeng\.exe$/i,
        ~r/taskhostw\.exe$/i
      ],
      parent_reduces_severity: true
    },
    # Rule 6: Hidden window - common in scheduled tasks and services
    %{
      id: "hidden_window",
      pattern: ~r/-(?:w(?:indowstyle)?)\s+hidden/i,
      severity: :medium,
      risk_score: 70,
      mitre: ["T1564.003"],
      description: "Hidden window execution",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_deployment_parents ++ [
        ~r/schtasks\.exe$/i,
        ~r/taskeng\.exe$/i,
        ~r/taskhostw\.exe$/i
      ],
      parent_reduces_severity: true
    },
    # Rule 7: Disable Defender - critical but may be done by IT management
    %{
      id: "disable_defender",
      pattern: ~r/(?:set-mppreference\s+-disablerealtimemonitoring|sc\s+(?:stop|config)\s+windefend)/i,
      severity: :critical,
      risk_score: 90,
      mitre: ["T1562.001"],
      description: "Attempt to disable Windows Defender",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_av_parents ++
        @legitimate_deployment_parents ++ [
        ~r/gpo/i,
        ~r/group\s*policy/i
      ],
      parent_reduces_severity: true
    },
    # Rule 8: Credential access - almost never legitimate from unexpected parents
    %{
      id: "credential_access_cmdline",
      pattern: ~r/(?:sekurlsa|lsadump|kerberos::list|privilege::debug)/i,
      severity: :critical,
      risk_score: 95,
      mitre: ["T1003"],
      description: "Credential access tool arguments detected",
      # Very narrow legitimate context - only security testing tools
      legitimate_parents: [
        ~r/pentest/i,
        ~r/security[-_]?assessment/i,
        ~r/red[-_]?team/i,
        ~r/atomic[-_]?red/i
      ],
      parent_reduces_severity: false  # Log context but don't reduce severity
    },
    # Rule 9: Shadow copy deletion - ransomware indicator but backup software may do this
    %{
      id: "shadow_copy_deletion",
      pattern: ~r/(?:vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete)/i,
      severity: :critical,
      risk_score: 95,
      mitre: ["T1490"],
      description: "Volume shadow copy deletion (ransomware indicator)",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_backup_parents ++ [
        ~r/disk\s*cleanup/i,
        ~r/cleanmgr\.exe$/i
      ],
      parent_reduces_severity: true
    },
    # Rule 10: Certutil download - LOLBin but occasionally used legitimately
    %{
      id: "lolbin_certutil_download",
      pattern: ~r/certutil(?:\.exe)?\s+.*-urlcache/i,
      severity: :high,
      risk_score: 80,
      mitre: ["T1105", "T1218"],
      description: "Certutil LOLBin download",
      legitimate_parents: @legitimate_system_parents ++ [
        ~r/pki/i,
        ~r/certsvc/i,
        ~r/ad\s*cs/i,
        ~r/certificate/i
      ],
      parent_reduces_severity: true
    },
    # Rule 11: MSHTA - rarely legitimate
    %{
      id: "lolbin_mshta",
      pattern: ~r/mshta(?:\.exe)?\s+(?:https?:|javascript:)/i,
      severity: :high,
      risk_score: 85,
      mitre: ["T1218.005"],
      description: "MSHTA script execution",
      legitimate_parents: @legitimate_system_parents,
      parent_reduces_severity: true
    },
    # Rule 12: Scheduled task creation with encoded command
    %{
      id: "schtask_encoded",
      pattern: ~r/schtasks\s+\/create.*(?:-enc|-encodedcommand)/i,
      severity: :high,
      risk_score: 80,
      mitre: ["T1053.005", "T1059.001"],
      description: "Scheduled task with encoded PowerShell",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_deployment_parents,
      parent_reduces_severity: true
    },
    # Rule 13: Registry Run key modification for persistence
    %{
      id: "registry_run_key",
      pattern: ~r/reg\s+add\s+[^\s]*(?:run|runonce)/i,
      severity: :high,
      risk_score: 75,
      mitre: ["T1547.001"],
      description: "Registry Run key modification for persistence",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_deployment_parents ++
        @legitimate_installer_parents,
      parent_reduces_severity: true
    },
    # Rule 14: Windows service creation
    %{
      id: "service_creation",
      pattern: ~r/(?:sc\s+create|new-service)/i,
      severity: :medium,
      risk_score: 60,
      mitre: ["T1543.003"],
      description: "Windows service creation",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_deployment_parents ++
        @legitimate_installer_parents,
      parent_reduces_severity: true
    },

    # ============================================================================
    # NEW: Living-off-the-Land Binaries (LOLBins)
    # ============================================================================

    # Rule 15: Regsvr32 proxy execution
    %{
      id: "lolbin_regsvr32_scrobj",
      pattern: ~r/regsvr32(?:\.exe)?\s+.*(?:\/s|\/n|\/u:.*scrobj)/i,
      severity: :high,
      risk_score: 85,
      mitre: ["T1218.010"],
      description: "Regsvr32 LOLBin execution (Squiblydoo technique)",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_installer_parents,
      parent_reduces_severity: true
    },

    # Rule 16: WMIC process call
    %{
      id: "lolbin_wmic_process",
      pattern: ~r/wmic(?:\.exe)?\s+.*(?:process\s+call\s+create|\/node:)/i,
      severity: :high,
      risk_score: 80,
      mitre: ["T1047"],
      description: "WMIC process creation or remote execution",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_deployment_parents,
      parent_reduces_severity: true
    },

    # Rule 17: RunDLL32 with JavaScript
    %{
      id: "lolbin_rundll32_js",
      pattern: ~r/rundll32(?:\.exe)?\s+.*javascript:/i,
      severity: :critical,
      risk_score: 90,
      mitre: ["T1218.011"],
      description: "RunDLL32 JavaScript execution",
      legitimate_parents: [],
      parent_reduces_severity: false
    },

    # Rule 18: MSBuild inline task
    %{
      id: "lolbin_msbuild_inline",
      pattern: ~r/msbuild(?:\.exe)?\s+.*(?:\/t:|\/target:)/i,
      severity: :high,
      risk_score: 80,
      mitre: ["T1127.001"],
      description: "MSBuild trusted developer utility abuse",
      legitimate_parents: @legitimate_system_parents ++ [
        ~r/visual\s*studio/i,
        ~r/devenv/i,
        ~r/msbuild/i
      ],
      parent_reduces_severity: true
    },

    # Rule 19: InstallUtil bypass
    %{
      id: "lolbin_installutil",
      pattern: ~r/installutil(?:\.exe)?\s+.*(?:\/logfile|\/logtoconsole)/i,
      severity: :high,
      risk_score: 80,
      mitre: ["T1218.004"],
      description: "InstallUtil .NET execution bypass",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_installer_parents,
      parent_reduces_severity: true
    },

    # Rule 20: Cscript/Wscript with network
    %{
      id: "lolbin_wscript_network",
      pattern: ~r/(?:cscript|wscript)(?:\.exe)?\s+.*(?:\/\/e:|\/\/b|https?:)/i,
      severity: :high,
      risk_score: 75,
      mitre: ["T1059.005"],
      description: "WScript/CScript remote script execution",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_deployment_parents,
      parent_reduces_severity: true
    },

    # Rule 21: BITSAdmin file transfer
    %{
      id: "lolbin_bitsadmin_transfer",
      pattern: ~r/bitsadmin(?:\.exe)?\s+.*(?:\/transfer|\/create.*\/addfile)/i,
      severity: :high,
      risk_score: 75,
      mitre: ["T1197"],
      description: "BITSAdmin file download",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_deployment_parents,
      parent_reduces_severity: true
    },

    # Rule 22: CMSTP bypass
    %{
      id: "lolbin_cmstp",
      pattern: ~r/cmstp(?:\.exe)?\s+.*(?:\/s|\/ni|\/au)/i,
      severity: :high,
      risk_score: 85,
      mitre: ["T1218.003"],
      description: "CMSTP execution bypass",
      legitimate_parents: @legitimate_system_parents,
      parent_reduces_severity: true
    },

    # Rule 23: Odbcconf DLL loading
    %{
      id: "lolbin_odbcconf",
      pattern: ~r/odbcconf(?:\.exe)?\s+.*(?:\/a|regsvr)/i,
      severity: :high,
      risk_score: 80,
      mitre: ["T1218.008"],
      description: "Odbcconf DLL registration abuse",
      legitimate_parents: @legitimate_system_parents,
      parent_reduces_severity: true
    },

    # Rule 24: PresentationHost/XPS abuse
    %{
      id: "lolbin_presentationhost",
      pattern: ~r/presentationhost(?:\.exe)?/i,
      severity: :medium,
      risk_score: 70,
      mitre: ["T1218"],
      description: "PresentationHost XAML execution",
      legitimate_parents: @legitimate_system_parents,
      parent_reduces_severity: true
    },

    # ============================================================================
    # NEW: Fileless Attack Patterns
    # ============================================================================

    # Rule 25: AMSI bypass attempt
    %{
      id: "fileless_amsi_bypass",
      pattern: ~r/(?:amsicontext|amsiinitfailed|amsiutils)/i,
      severity: :critical,
      risk_score: 95,
      mitre: ["T1562.001"],
      description: "AMSI bypass attempt detected",
      legitimate_parents: [],
      parent_reduces_severity: false
    },

    # Rule 26: Reflective DLL loading
    %{
      id: "fileless_reflective_load",
      pattern: ~r/(?:\[reflection\.assembly\]::load|loadlibrary.*memorymappedfile)/i,
      severity: :critical,
      risk_score: 90,
      mitre: ["T1620"],
      description: "Reflective DLL/assembly loading detected",
      legitimate_parents: [],
      parent_reduces_severity: false
    },

    # Rule 27: PowerShell memory-only execution
    %{
      id: "fileless_ps_iex",
      pattern: ~r/(?:iex|invoke-expression)\s*\(\s*\$[^)]+\)/i,
      severity: :high,
      risk_score: 80,
      mitre: ["T1059.001"],
      description: "PowerShell Invoke-Expression execution",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_deployment_parents,
      parent_reduces_severity: true
    },

    # Rule 28: .NET in-memory compilation
    %{
      id: "fileless_csharp_compile",
      pattern: ~r/(?:add-type\s+-typedefinition|csharpcodeprovider)/i,
      severity: :high,
      risk_score: 80,
      mitre: ["T1027.004"],
      description: ".NET in-memory compilation detected",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_deployment_parents,
      parent_reduces_severity: true
    },

    # Rule 29: WMI event subscription persistence
    %{
      id: "fileless_wmi_persistence",
      pattern: ~r/(?:__eventconsumer|commandlineeventconsumer|activescripteventconsumer)/i,
      severity: :critical,
      risk_score: 90,
      mitre: ["T1546.003"],
      description: "WMI event subscription persistence",
      legitimate_parents: @legitimate_system_parents,
      parent_reduces_severity: true
    },

    # ============================================================================
    # NEW: Process Injection Patterns
    # ============================================================================

    # Rule 30: CreateRemoteThread indication
    %{
      id: "injection_createremotethread",
      pattern: ~r/(?:createremotethread|ntcreatethreadex|rtlcreateuserthread)/i,
      severity: :critical,
      risk_score: 90,
      mitre: ["T1055.002"],
      description: "Remote thread creation detected",
      legitimate_parents: [],
      parent_reduces_severity: false
    },

    # Rule 31: Process hollowing indicators
    %{
      id: "injection_hollow",
      pattern: ~r/(?:zwunmapviewofsection|ntunmapviewofsection|setthreadcontext)/i,
      severity: :critical,
      risk_score: 95,
      mitre: ["T1055.012"],
      description: "Process hollowing API usage detected",
      legitimate_parents: [],
      parent_reduces_severity: false
    },

    # Rule 32: APC injection
    %{
      id: "injection_apc",
      pattern: ~r/(?:queueuserapc|ntqueueapcthread)/i,
      severity: :critical,
      risk_score: 90,
      mitre: ["T1055.004"],
      description: "APC injection detected",
      legitimate_parents: [],
      parent_reduces_severity: false
    },

    # Rule 33: DLL injection via LoadLibrary
    %{
      id: "injection_dll_loadlibrary",
      pattern: ~r/(?:loadlibrarya|loadlibraryw|ldrloaddll).*(?:writevirtualmemory|writeprocessmemory)/i,
      severity: :critical,
      risk_score: 90,
      mitre: ["T1055.001"],
      description: "DLL injection via memory write detected",
      legitimate_parents: [],
      parent_reduces_severity: false
    },

    # ============================================================================
    # NEW: Credential Dumping Patterns
    # ============================================================================

    # Rule 34: SAM hive export
    %{
      id: "cred_sam_export",
      pattern: ~r/reg(?:\.exe)?\s+save\s+(?:hklm\\)?(?:sam|security|system)/i,
      severity: :critical,
      risk_score: 95,
      mitre: ["T1003.002"],
      description: "Registry hive export (SAM/SECURITY/SYSTEM)",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_backup_parents,
      parent_reduces_severity: true
    },

    # Rule 35: Ntdsutil AD database
    %{
      id: "cred_ntdsutil",
      pattern: ~r/ntdsutil(?:\.exe)?\s+.*(?:ac\s+i|ifm|snapshot)/i,
      severity: :critical,
      risk_score: 95,
      mitre: ["T1003.003"],
      description: "Ntdsutil AD database extraction",
      legitimate_parents: @legitimate_system_parents,
      parent_reduces_severity: true
    },

    # Rule 36: DCSync attack indicators
    %{
      id: "cred_dcsync",
      pattern: ~r/(?:dcsync|drs_getncchanges|drsuapi)/i,
      severity: :critical,
      risk_score: 95,
      mitre: ["T1003.006"],
      description: "DCSync replication attack detected",
      legitimate_parents: [],
      parent_reduces_severity: false
    },

    # Rule 37: Kerberoasting
    %{
      id: "cred_kerberoast",
      pattern: ~r/(?:invoke-kerberoast|request-spnticket|getuserspn)/i,
      severity: :critical,
      risk_score: 90,
      mitre: ["T1558.003"],
      description: "Kerberoasting attack detected",
      legitimate_parents: [],
      parent_reduces_severity: false
    },

    # Rule 38: AS-REP roasting
    %{
      id: "cred_asreproast",
      pattern: ~r/(?:asreproast|get-asrephas|dontuserequirepreauth)/i,
      severity: :high,
      risk_score: 85,
      mitre: ["T1558.004"],
      description: "AS-REP roasting attack detected",
      legitimate_parents: [],
      parent_reduces_severity: false
    },

    # ============================================================================
    # NEW: Defense Evasion Patterns
    # ============================================================================

    # Rule 39: Event log clearing
    %{
      id: "evasion_clear_logs",
      pattern: ~r/(?:wevtutil\s+cl|clear-eventlog|for.*do.*wevtutil)/i,
      severity: :critical,
      risk_score: 90,
      mitre: ["T1070.001"],
      description: "Windows event log clearing",
      legitimate_parents: @legitimate_system_parents,
      parent_reduces_severity: true
    },

    # Rule 40: Timestomping
    %{
      id: "evasion_timestomp",
      pattern: ~r/(?:timestomp|setfiletime|touch.*-d)/i,
      severity: :high,
      risk_score: 80,
      mitre: ["T1070.006"],
      description: "File timestamp modification detected",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_deployment_parents,
      parent_reduces_severity: true
    },

    # Rule 41: Firewall manipulation
    %{
      id: "evasion_firewall",
      pattern: ~r/(?:netsh\s+.*firewall.*(?:delete|disable)|set-netfirewallprofile.*-enabled\s+false)/i,
      severity: :high,
      risk_score: 85,
      mitre: ["T1562.004"],
      description: "Windows Firewall manipulation",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_deployment_parents,
      parent_reduces_severity: true
    },

    # Rule 42: UAC bypass
    %{
      id: "evasion_uac_bypass",
      pattern: ~r/(?:fodhelper|computerdefaults|eventvwr|sdclt).*(?:ms-settings|shell:::{)/i,
      severity: :critical,
      risk_score: 90,
      mitre: ["T1548.002"],
      description: "UAC bypass technique detected",
      legitimate_parents: [],
      parent_reduces_severity: false
    },

    # Rule 43: NTFS alternate data streams
    %{
      id: "evasion_ads",
      pattern: ~r/(?:type\s+.*:|\$data|zone\.identifier)/i,
      severity: :medium,
      risk_score: 65,
      mitre: ["T1564.004"],
      description: "NTFS alternate data stream usage",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_deployment_parents,
      parent_reduces_severity: true
    },

    # ============================================================================
    # NEW: Discovery/Reconnaissance Patterns
    # ============================================================================

    # Rule 44: Network share enumeration
    %{
      id: "recon_net_share",
      pattern: ~r/(?:net\s+(?:share|view|use)|get-smbshare|invoke-sharefinder)/i,
      severity: :medium,
      risk_score: 60,
      mitre: ["T1135"],
      description: "Network share enumeration",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_admin_parents,
      parent_reduces_severity: true
    },

    # Rule 45: Domain trust enumeration
    %{
      id: "recon_domain_trust",
      pattern: ~r/(?:nltest.*\/domain_trusts|get-adtrust|get-netforest)/i,
      severity: :medium,
      risk_score: 65,
      mitre: ["T1482"],
      description: "Domain trust enumeration",
      legitimate_parents: @legitimate_system_parents ++ @legitimate_admin_parents,
      parent_reduces_severity: true
    },

    # Rule 46: Service enumeration for privilege escalation
    %{
      id: "recon_service_enum",
      pattern: ~r/(?:accesschk.*-uwcqv|get-service.*unquoted|modifiableservice)/i,
      severity: :high,
      risk_score: 75,
      mitre: ["T1574.011"],
      description: "Service privilege escalation reconnaissance",
      legitimate_parents: @legitimate_system_parents,
      parent_reduces_severity: true
    }
  ]

  @default_sensitive_path_rules [
    %{id: "sam_database", pattern: ~r/\\sam$/i, mitre: ["T1003.002"], description: "SAM database access"},
    %{id: "security_hive", pattern: ~r/\\security$/i, mitre: ["T1003.002"], description: "SECURITY hive access"},
    %{id: "system32_config", pattern: ~r/\\system32\\config\\/i, mitre: ["T1003.002"], description: "System32 config access"},
    %{id: "ntds_dit", pattern: ~r/\\ntds\.dit$/i, mitre: ["T1003.003"], description: "NTDS.dit access (AD database)"},
    %{id: "lsass_memory", pattern: ~r/\\lsass/i, mitre: ["T1003.001"], description: "LSASS process memory access"},
    %{id: "ssh_keys", pattern: ~r/[\/\\]\.ssh[\/\\]/i, mitre: ["T1552.004"], description: "SSH key access"},
    %{id: "credential_files", pattern: ~r/[\/\\](?:credentials|passwords)/i, mitre: ["T1552.001"], description: "Credential file access"},
    %{id: "aws_credentials", pattern: ~r/[\/\\]\.aws[\/\\]credentials/i, mitre: ["T1552.001"], description: "AWS credential file access"}
  ]

  @ransomware_extensions ~w(.encrypted .locked .crypt .locky .wannacry .lockbit .conti .ryuk .cerber .zepto .zzzzz)

  # ============================================================================
  # Ancestor Chain Analysis - Multi-hop Process Chain Detection
  # ============================================================================
  #
  # These patterns detect multi-stage attack chains by walking up the process
  # tree from the current process through its ancestors. Research from KAIROS
  # (IEEE S&P 2024) and CAPTAIN (NDSS 2025) demonstrates that provenance graph
  # analysis with multi-hop ancestor chains significantly improves detection
  # of advanced persistent threats.
  #
  # Each chain pattern is a tuple of:
  #   {ancestor_name_patterns, severity, mitre_technique, description}
  #
  # Patterns are matched in order from the deepest ancestor (closest to root)
  # to the shallowest (closest to the current process). The `_any` atom matches
  # any process name. Patterns are matched case-insensitively against process
  # names extracted from the correlator's process tree.

  # Maximum depth for ancestor chain walking (prevents infinite loops)
  @ancestor_chain_max_depth 5

  # ETS table name used by the Correlator for process trees
  @process_tree_table :process_trees

  # Suspicious multi-hop ancestor chain patterns
  # Format: {[ancestor_pattern, ...], severity, mitre_technique, description}
  # Patterns match from deepest ancestor -> current process (left to right)
  @suspicious_ancestor_chains [
    # ---- Office document -> shell -> payload chains ----
    {[~r/winword\.exe$/i, ~r/cmd\.exe$/i, :_any],
     :high, "T1204.002", "Office document spawned shell chain"},
    {[~r/winword\.exe$/i, ~r/powershell\.exe$/i, :_any],
     :high, "T1204.002", "Office document spawned PowerShell chain"},
    {[~r/excel\.exe$/i, ~r/cmd\.exe$/i, :_any],
     :high, "T1204.002", "Excel spawned shell chain"},
    {[~r/excel\.exe$/i, ~r/powershell\.exe$/i, :_any],
     :high, "T1204.002", "Excel spawned PowerShell chain"},
    {[~r/powerpnt\.exe$/i, ~r/cmd\.exe$/i, :_any],
     :high, "T1204.002", "PowerPoint spawned shell chain"},
    {[~r/outlook\.exe$/i, :_any, ~r/powershell\.exe$/i],
     :high, "T1566.001", "Email client spawned PowerShell indirectly"},
    {[~r/outlook\.exe$/i, :_any, ~r/cmd\.exe$/i],
     :high, "T1566.001", "Email client spawned command shell indirectly"},

    # ---- Browser -> download -> execution chains ----
    {[~r/chrome\.exe$/i, :_any, ~r/cmd\.exe$/i],
     :medium, "T1189", "Browser-spawned command chain"},
    {[~r/msedge\.exe$/i, :_any, ~r/powershell\.exe$/i],
     :medium, "T1189", "Browser-spawned PowerShell chain"},
    {[~r/firefox\.exe$/i, :_any, ~r/cmd\.exe$/i],
     :medium, "T1189", "Firefox-spawned command chain"},
    {[~r/iexplore\.exe$/i, :_any, ~r/powershell\.exe$/i],
     :medium, "T1189", "IE-spawned PowerShell chain"},

    # ---- Living-off-the-land chains ----
    {[:_any, ~r/mshta\.exe$/i, :_any],
     :high, "T1218.005", "MSHTA in process chain"},
    {[:_any, ~r/wscript\.exe$/i, ~r/cmd\.exe$/i],
     :medium, "T1059.005", "Script host spawned command shell"},
    {[:_any, ~r/cscript\.exe$/i, ~r/cmd\.exe$/i],
     :medium, "T1059.005", "Script host spawned command shell"},
    {[:_any, ~r/rundll32\.exe$/i, :_any, ~r/cmd\.exe$/i],
     :high, "T1218.011", "Rundll32 chain to command shell"},
    {[:_any, ~r/regsvr32\.exe$/i, :_any, ~r/cmd\.exe$/i],
     :high, "T1218.010", "Regsvr32 chain to command shell"},

    # ---- Lateral movement indicators ----
    {[~r/services\.exe$/i, :_any, ~r/cmd\.exe$/i],
     :medium, "T1021.002", "Service spawned command chain"},
    {[~r/services\.exe$/i, :_any, ~r/powershell\.exe$/i],
     :medium, "T1021.002", "Service spawned PowerShell chain"},
    {[~r/wmiprvse\.exe$/i, :_any, :_any],
     :medium, "T1047", "WMI provider deep chain"},

    # ---- Persistence / privilege escalation chains ----
    {[~r/svchost\.exe$/i, :_any, ~r/powershell\.exe$/i],
     :medium, "T1053", "Service host deep PowerShell chain"},
    {[:_any, ~r/taskeng\.exe$/i, :_any, ~r/cmd\.exe$/i],
     :medium, "T1053.005", "Scheduled task deep chain"},
    {[:_any, ~r/taskhostw?\.exe$/i, :_any, ~r/cmd\.exe$/i],
     :medium, "T1053.005", "Scheduled task host deep chain"},

    # ---- Full phishing chains (4+ hops) ----
    {[~r/outlook\.exe$/i, ~r/(?:winword|excel|powerpnt)\.exe$/i, ~r/cmd\.exe$/i, :_any],
     :critical, "T1566.001", "Full phishing chain: email -> document -> shell -> payload"},
    {[~r/outlook\.exe$/i, ~r/(?:winword|excel|powerpnt)\.exe$/i, ~r/powershell\.exe$/i, :_any],
     :critical, "T1566.001", "Full phishing chain: email -> document -> PowerShell -> payload"}
  ]

  # Sensitive processes that are suspicious when deep in ancestor chains
  @deep_chain_sensitive_processes [
    ~r/powershell\.exe$/i,
    ~r/pwsh\.exe$/i,
    ~r/cmd\.exe$/i,
    ~r/certutil\.exe$/i,
    ~r/mshta\.exe$/i,
    ~r/wscript\.exe$/i,
    ~r/cscript\.exe$/i,
    ~r/rundll32\.exe$/i,
    ~r/regsvr32\.exe$/i,
    ~r/bitsadmin\.exe$/i,
    ~r/msbuild\.exe$/i,
    ~r/installutil\.exe$/i
  ]

  # Known Living-off-the-Land Binaries (LOLBins)
  @lolbin_processes MapSet.new([
    "certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "bitsadmin.exe", "msbuild.exe", "installutil.exe", "cmstp.exe",
    "odbcconf.exe", "wmic.exe", "presentationhost.exe", "xwizard.exe",
    "forfiles.exe", "pcalua.exe", "csc.exe", "vbc.exe",
    "desktopimgdownldr.exe", "esentutl.exe", "expand.exe", "extrac32.exe",
    "findstr.exe", "hh.exe", "ieexec.exe", "makecab.exe",
    "replace.exe", "rpcping.exe", "sfc.exe", "xslt.exe"
  ])

  # Known Microsoft signed system processes
  @microsoft_signed_processes MapSet.new([
    "svchost.exe", "services.exe", "lsass.exe", "csrss.exe",
    "smss.exe", "wininit.exe", "winlogon.exe", "explorer.exe",
    "taskhost.exe", "taskhostw.exe", "taskeng.exe", "conhost.exe",
    "dllhost.exe", "sihost.exe", "runtimebroker.exe", "searchindexer.exe",
    "spoolsv.exe", "mmc.exe", "consent.exe", "dwm.exe",
    "wmiprvse.exe", "wuauclt.exe", "trustedinstaller.exe"
  ])

  # ============================================================================
  # Structs
  # ============================================================================

  defmodule UserProfile do
    @moduledoc "User behavioral profile"
    defstruct [
      :user_id,
      :typical_login_hours,     # %{hour_of_day => frequency}
      :typical_source_ips,      # %{ip => frequency}
      :typical_processes,       # %{process_name => frequency}
      :typical_file_paths,      # %{path_pattern => frequency}
      :typical_network_dests,   # %{ip_port => frequency}
      :command_patterns,        # %{pattern => frequency}
      :peer_group,              # String peer group label (e.g. "role:engineering")
      :department,              # String department for peer grouping
      last_updated: nil,
      total_events: 0
    ]
  end

  defmodule ProcessProfile do
    @moduledoc "Process behavioral profile"
    defstruct [
      :process_name,
      :typical_parents,         # %{parent_name => frequency}
      :typical_args,            # %{arg_pattern => frequency}
      :typical_children,        # %{child_name => frequency}
      :typical_network_ports,   # %{port => frequency}
      :typical_file_operations, # %{path_pattern => frequency}
      :process_type,            # :system, :user_app, :service, :browser, :shell, :unknown
      avg_memory_usage: 0,
      avg_cpu_usage: 0,
      memory_stddev: 0,
      cpu_stddev: 0,
      last_updated: nil,
      total_events: 0
    ]
  end

  defmodule BehavioralAnomaly do
    @moduledoc "Detected behavioral anomaly"
    defstruct [
      :anomaly_type,
      :entity_type,      # :user, :process, :host
      :entity_id,
      :agent_id,
      :organization_id,
      :description,
      :risk_score,       # 0-100
      :deviation_score,  # Z-score or similar
      :baseline_value,
      :observed_value,
      :mitre_techniques,
      :rule_id,          # ID of matching rule (if rule-based)
      :timestamp
    ]
  end

  # Online statistics tracker using Welford's algorithm.
  # Stored in ETS keyed by `{org_id, entity_type, entity_id, feature_name}` (Phase 2).
  # Supports incremental mean/variance without storing all observations.
  defmodule OnlineStats do
    @moduledoc "Welford's online mean/variance tracker"
    defstruct [
      count: 0,         # Number of observations
      mean: 0.0,        # Running mean
      m2: 0.0,          # Sum of squares of differences from the mean
      min_val: nil,      # Minimum observed value
      max_val: nil,      # Maximum observed value
      last_updated: nil  # Monotonic-time (:second) of last update, for future TTL cleanup
    ]

    @doc "Add a new observation and return updated stats."
    def update(%__MODULE__{count: 0} = _stats, value) when is_number(value) do
      %__MODULE__{count: 1, mean: value * 1.0, m2: 0.0, min_val: value, max_val: value, last_updated: System.monotonic_time(:second)}
    end

    def update(%__MODULE__{} = stats, value) when is_number(value) do
      n = stats.count + 1
      delta = value - stats.mean
      new_mean = stats.mean + delta / n
      delta2 = value - new_mean
      new_m2 = stats.m2 + delta * delta2

      %__MODULE__{
        count: n,
        mean: new_mean,
        m2: new_m2,
        min_val: if(is_nil(stats.min_val), do: value, else: min(stats.min_val, value)),
        max_val: if(is_nil(stats.max_val), do: value, else: max(stats.max_val, value)),
        last_updated: System.monotonic_time(:second)
      }
    end

    def update(stats, _value), do: stats

    @doc "Calculate population variance."
    def variance(%__MODULE__{count: n}) when n < 2, do: 0.0
    def variance(%__MODULE__{count: n, m2: m2}), do: m2 / n

    @doc "Calculate population standard deviation."
    def stddev(%__MODULE__{} = stats), do: :math.sqrt(variance(stats))

    @doc "Calculate z-score for a given value."
    def z_score(%__MODULE__{count: n}, _value) when n < 2, do: 0.0
    def z_score(%__MODULE__{} = stats, value) do
      sd = stddev(stats)
      if sd < 1.0e-10, do: 0.0, else: (value - stats.mean) / sd
    end
  end

  # Temporal pattern matrix: 24 hours x 7 days_of_week.
  # Stored in ETS keyed by `{org_id, entity_type, entity_id}` (Phase 2).
  defmodule TemporalPattern do
    @moduledoc "Time-of-day and day-of-week activity pattern"
    defstruct [
      # 24x7 matrix stored as %{{hour, day_of_week} => count}
      matrix: %{},
      total: 0,
      last_updated: nil  # Monotonic-time (:second) of last update, for future TTL cleanup
    ]

    @doc "Record an observation at the given hour (0-23) and day_of_week (1=Mon..7=Sun)."
    def record(%__MODULE__{} = tp, hour, day_of_week)
        when is_integer(hour) and hour >= 0 and hour <= 23
        and is_integer(day_of_week) and day_of_week >= 1 and day_of_week <= 7 do
      key = {hour, day_of_week}
      %__MODULE__{
        matrix: Map.update(tp.matrix, key, 1, &(&1 + 1)),
        total: tp.total + 1,
        last_updated: System.monotonic_time(:second)
      }
    end

    def record(tp, _hour, _dow), do: tp

    @doc """
    Calculate how anomalous a given (hour, day_of_week) is.
    Returns a value 0.0 (normal) to 1.0 (very anomalous).
    Uses the proportion of activity at this time slot vs. expected uniform.
    """
    def anomaly_score(%__MODULE__{total: t}, _hour, _dow) when t < 50, do: 0.0
    def anomaly_score(%__MODULE__{} = tp, hour, day_of_week) do
      key = {hour, day_of_week}
      observed = Map.get(tp.matrix, key, 0)
      # Expected under uniform distribution across 168 slots (24 * 7)
      expected = tp.total / 168.0

      if expected < 0.1 do
        0.0
      else
        # Use a modified chi-squared-like ratio
        ratio = observed / expected
        cond do
          ratio >= 0.2 -> 0.0        # Activity at or above 20% of expected - normal
          ratio >= 0.05 -> 0.5       # Rare but not unheard of
          true -> 1.0                # Never or almost never seen at this time
        end
      end
    end

    @doc "Check if current time is within working hours (Mon-Fri 07:00-19:00 UTC)."
    def working_hours?(hour, day_of_week) do
      day_of_week >= 1 and day_of_week <= 5 and hour >= 7 and hour <= 18
    end
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    # Create ETS tables (public for reads, GenServer serializes writes)
    init_ets_tables()

    # Schedule periodic baseline updates and persistence
    Process.send_after(self(), :update_baselines, Config.baseline_update_interval())
    Process.send_after(self(), :persist_baselines, Config.baseline_persist_interval())
    # Schedule new periodic tasks
    Process.send_after(self(), :trend_tick, @trend_tick_interval)
    Process.send_after(self(), :cleanup_stale, @cleanup_interval)
    Process.send_after(self(), :publish_stats, @pubsub_stats_interval)
    Process.send_after(self(), :recalc_peer_groups, @peer_group_recalc_interval)

    # Create GeoIP cache ETS table
    ensure_geoip_cache_table()

    # Subscribe to PubSub for telemetry events
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "telemetry:events")
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "alerts:verdict_feedback")

    # Load rules (compile-time defaults + any DB overrides)
    rules = load_rules()

    # Load persisted baselines from database (Phase 2: org-nested)
    # Returns %{org_id => %{user_id => UserProfile}}, %{org_id => %{proc_name => ProcessProfile}}
    {user_profiles, process_profiles} = load_persisted_baselines()

    # Seed ETS tables from loaded profiles
    seed_ets_from_profiles(user_profiles, process_profiles)

    state = %{
      # Phase 2: nested-by-org. Shape: %{org_id => %{user_id => UserProfile.t()}}
      user_profiles: user_profiles,
      # Phase 2: nested-by-org. Shape: %{org_id => %{process_name => ProcessProfile.t()}}
      process_profiles: process_profiles,
      # Phase 2: nested-by-org. Shape: %{org_id => %{...}}
      host_profiles: %{},
      # Phase 2: keyed by {org_id, user_id}
      last_login_locations: %{},
      rules: rules,
      # Phase 2: nested-by-org. Shape: %{org_id => stats}
      # Historical stats for z-score calculation (loaded from DB)
      historical_stats: load_historical_stats(),
      # KEEP singleton: server-wide totals, not per-tenant
      global_stats: %{
        avg_events_per_hour: 0,
        avg_network_connections: 0,
        avg_file_operations: 0
      },
      # Learning period: suppress low-confidence behavioral alerts during baseline warmup
      started_at: System.monotonic_time(:second),
      learning_period_secs: 600,
      # Counters for dashboard stats (singleton, server-wide)
      events_processed: 0,
      anomalies_detected: 0,
      alerts_created: 0
    }

    user_count = state.user_profiles |> Enum.map(fn {_org, m} -> map_size(m) end) |> Enum.sum()
    proc_count = state.process_profiles |> Enum.map(fn {_org, m} -> map_size(m) end) |> Enum.sum()

    Logger.info("Behavioral Analytics Engine started " <>
      "(#{user_count} user profiles across #{map_size(state.user_profiles)} orgs, " <>
      "#{proc_count} process profiles across #{map_size(state.process_profiles)} orgs, " <>
      "7 ETS tables initialized)")
    {:ok, state}
  end

  # Initialize all ETS tables. Public read access allows other modules
  # (dashboard controllers, API endpoints) to read without going through
  # the GenServer, while writes are serialized through handle_cast/handle_info.
  defp init_ets_tables do
    tables = [
      {@profiles_table, [:set, :public, :named_table, read_concurrency: true]},
      {@stats_table, [:set, :public, :named_table, read_concurrency: true]},
      {@peer_groups_table, [:set, :public, :named_table, read_concurrency: true]},
      {@temporal_table, [:set, :public, :named_table, read_concurrency: true]},
      {@thresholds_table, [:set, :public, :named_table, read_concurrency: true]},
      {@risk_trends_table, [:set, :public, :named_table, read_concurrency: true]},
      {@anomaly_table, [:set, :public, :named_table, read_concurrency: true]}
    ]

    Enum.each(tables, fn {name, opts} ->
      case :ets.whereis(name) do
        :undefined -> :ets.new(name, opts)
        _tid -> :ok
      end
    end)

    # Phase 2: thresholds are now per-org. Seeding deferred to first read per org
    # (see ensure_default_thresholds/1). No eager seed at boot — orgs do not yet
    # exist at GenServer init time.
    :ok
  end

  # Phase 2: per-org lazy seed of default adaptive thresholds.
  # Called from the threshold-read path on cache-miss for a given org.
  # Idempotent and safe to call multiple times (each row is gated by lookup).
  defp ensure_default_thresholds(nil), do: :ok
  defp ensure_default_thresholds(org_id) do
    defaults = [
      # {entity_type, feature} => {threshold_z, fp_count, tp_count}
      {{:user, :login_hour}, {3.0, 0, 0}},
      {{:user, :source_ip}, {3.0, 0, 0}},
      {{:user, :process_count}, {3.0, 0, 0}},
      {{:process, :parent_child}, {3.0, 0, 0}},
      {{:process, :network_port}, {3.0, 0, 0}},
      {{:process, :data_volume}, {3.0, 0, 0}},
      {{:host, :connection_count}, {3.0, 0, 0}},
      {{:host, :process_count}, {3.0, 0, 0}}
    ]

    Enum.each(defaults, fn {{entity_type, feature}, value} ->
      key = {org_id, entity_type, feature}
      # Only seed if not already present (preserves learned thresholds across restarts)
      case :ets.lookup(@thresholds_table, key) do
        [] -> :ets.insert(@thresholds_table, {key, value})
        _ -> :ok
      end
    end)
  rescue
    _ -> :ok
  end

  # Phase 2: user_profiles/process_profiles are now org-nested maps
  # (%{org_id => %{id => profile}}). ETS keys gain org_id prefix.
  defp seed_ets_from_profiles(user_profiles, process_profiles) do
    # Seed profiles table — user profiles per-org
    Enum.each(user_profiles, fn {org_id, users} ->
      Enum.each(users, fn {user_id, profile} ->
        :ets.insert(@profiles_table, {{org_id, :user, user_id}, profile})
      end)
    end)

    # Seed profiles table — process profiles per-org
    Enum.each(process_profiles, fn {org_id, processes} ->
      Enum.each(processes, fn {proc_name, profile} ->
        :ets.insert(@profiles_table, {{org_id, :process, proc_name}, profile})
      end)
    end)

    # Initialize empty temporal patterns for known entities
    Enum.each(user_profiles, fn {org_id, users} ->
      Enum.each(users, fn {user_id, _profile} ->
        key = {org_id, :user, user_id}
        case :ets.lookup(@temporal_table, key) do
          [] -> :ets.insert(@temporal_table, {key, %TemporalPattern{}})
          _ -> :ok
        end
      end)
    end)
  end

  @impl true
  def handle_call({:analyze_event, event}, _from, state) do
    {anomalies, new_state} = analyze_event(event, state)
    {:reply, {:ok, anomalies}, new_state}
  end

  @impl true
  def handle_call({:get_user_profile, org_id, user_id}, _from, state) do
    profile = state.user_profiles |> Map.get(org_id, %{}) |> Map.get(user_id)
    {:reply, {:ok, profile}, state}
  end

  @impl true
  def handle_call({:get_risk_score, org_id, entity_type, entity_id}, _from, state) do
    score = calculate_entity_risk_score(org_id, entity_type, entity_id, state)
    {:reply, {:ok, score}, state}
  end

  @impl true
  def handle_call({:get_all_profiles, org_id}, _from, state) do
    users = Map.get(state.user_profiles, org_id, %{})
    processes = Map.get(state.process_profiles, org_id, %{})
    hosts = Map.get(state.host_profiles, org_id, %{})
    {:reply, {:ok, users, processes, hosts}, state}
  end

  @impl true
  def handle_call({:get_process_profile, org_id, process_name}, _from, state) do
    profile =
      state.process_profiles
      |> Map.get(org_id, %{})
      |> Map.get(String.downcase(process_name))

    {:reply, {:ok, profile}, state}
  end

  @impl true
  def handle_call(:reload_rules, _from, state) do
    rules = load_rules()
    Logger.info("Behavioral rules reloaded: #{length(rules.process)} process, " <>
      "#{length(rules.command_line)} command-line, " <>
      "#{length(rules.sensitive_path)} path rules")
    {:reply, :ok, %{state | rules: rules}}
  end

  @impl true
  def handle_info(:update_baselines, state) do
    Logger.info("Updating behavioral baselines")
    new_state = update_all_baselines(state)
    Process.send_after(self(), :update_baselines, Config.baseline_update_interval())
    {:noreply, new_state}
  end

  @impl true
  def handle_info(:persist_baselines, state) do
    persist_baselines_to_db(state)
    persist_ets_stats_to_db()
    Process.send_after(self(), :persist_baselines, Config.baseline_persist_interval())
    {:noreply, state}
  end

  # ── PubSub: Ingest telemetry events in real-time ─────────────────────────
  @impl true
  def handle_info({:telemetry_event, event}, state) do
    {anomalies, new_state} = analyze_event(event, state)
    new_state = %{new_state |
      events_processed: new_state.events_processed + 1,
      anomalies_detected: new_state.anomalies_detected + length(anomalies)
    }
    {:noreply, new_state}
  end

  # ── PubSub: Analyst verdict feedback for adaptive threshold learning ─────
  # Phase 2: payload may carry :organization_id (preferred) or :alert_id (we resolve
  # the org via Alerts.get_alert! fallback). If neither yields an org, we skip the
  # update — global thresholds no longer exist after the per-org refactor.
  @impl true
  def handle_info({:verdict_feedback, %{alert_id: alert_id, verdict: verdict, rule_id: rule_id, entity_type: entity_type, feature: feature} = payload}, state) do
    org_id =
      Map.get(payload, :organization_id) ||
        resolve_org_from_alert(alert_id)

    if org_id do
      update_adaptive_threshold(org_id, entity_type, feature, verdict)
      Logger.debug("[Behavioral] Adaptive threshold updated for org=#{inspect(org_id)} #{entity_type}:#{feature} (verdict: #{verdict}, rule: #{rule_id})")
    else
      Logger.debug("[Behavioral] Verdict feedback received without org_id (alert=#{inspect(alert_id)}); skipping threshold update")
    end

    {:noreply, state}
  end

  # Resolve org_id from an alert id; safe to call when Alerts/Repo is unavailable.
  defp resolve_org_from_alert(nil), do: nil
  defp resolve_org_from_alert(alert_id) do
    try do
      case Alerts.get_alert!(alert_id) do
        %{organization_id: org_id} -> org_id
        _ -> nil
      end
    rescue
      _ -> nil
    end
  end

  # ── Risk Score Trend Tick (EWMA) ─────────────────────────────────────────
  @impl true
  def handle_info(:trend_tick, state) do
    check_sustained_risk_trends(state)
    Process.send_after(self(), :trend_tick, @trend_tick_interval)
    {:noreply, state}
  end

  # ── Cleanup stale ETS entries ────────────────────────────────────────────
  @impl true
  def handle_info(:cleanup_stale, state) do
    cleanup_stale_ets_entries()
    Process.send_after(self(), :cleanup_stale, @cleanup_interval)
    {:noreply, state}
  end

  # ── Publish dashboard stats via PubSub ───────────────────────────────────
  @impl true
  def handle_info(:publish_stats, state) do
    publish_dashboard_stats(state)
    Process.send_after(self(), :publish_stats, @pubsub_stats_interval)
    {:noreply, state}
  end

  # ── Peer group recalculation ─────────────────────────────────────────────
  @impl true
  def handle_info(:recalc_peer_groups, state) do
    recalculate_peer_groups(state)
    Process.send_after(self(), :recalc_peer_groups, @peer_group_recalc_interval)
    {:noreply, state}
  end

  # Catch-all for unknown messages (prevents GenServer crash)
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Analyze an event for behavioral anomalies.

  Phase 2: signature unchanged. Org-id is resolved inside `analyze_event/2`
  from the event's :organization_id (with `safe_org_lookup/1` fallback via
  agent_id).
  """
  def analyze(event) do
    GenServer.call(__MODULE__, {:analyze_event, event})
  end

  @doc "Get the behavioral profile for a user within an organization."
  def get_user_profile(org_id, user_id) do
    GenServer.call(__MODULE__, {:get_user_profile, org_id, user_id})
  end

  @doc "Calculate risk score for an entity (user, process, or host) within an organization."
  def get_risk_score(org_id, entity_type, entity_id) do
    GenServer.call(__MODULE__, {:get_risk_score, org_id, entity_type, entity_id})
  end

  @doc "Get all profiles (user, process, host) for an organization."
  def get_all_profiles(org_id) do
    GenServer.call(__MODULE__, {:get_all_profiles, org_id})
  end

  @doc "Get the behavioral profile for a process within an organization."
  def get_process_profile(org_id, process_name) do
    GenServer.call(__MODULE__, {:get_process_profile, org_id, process_name})
  end

  @doc "Reload detection rules from defaults and database."
  def reload_rules do
    GenServer.call(__MODULE__, :reload_rules)
  end

  # ── ETS-backed public reads (no GenServer bottleneck) ────────────────────
  # Phase 2: all ETS reads scope to org_id to prevent cross-tenant data leak.

  @doc "Read online statistics for a feature directly from ETS (no GenServer call)."
  @spec get_feature_stats(any(), atom(), String.t(), atom()) :: OnlineStats.t() | nil
  def get_feature_stats(org_id, entity_type, entity_id, feature) do
    case ets_lookup(@stats_table, {org_id, entity_type, entity_id, feature}) do
      nil -> nil
      stats -> stats
    end
  end

  @doc "Read a temporal pattern directly from ETS."
  @spec get_temporal_pattern(any(), atom(), String.t()) :: TemporalPattern.t() | nil
  def get_temporal_pattern(org_id, entity_type, entity_id) do
    ets_lookup(@temporal_table, {org_id, entity_type, entity_id})
  end

  @doc """
  Read the adaptive threshold for an entity type and feature from ETS,
  scoped to an organization. Lazily seeds default thresholds for the org
  on first access.
  """
  @spec get_adaptive_threshold(any(), atom(), atom()) :: {float(), integer(), integer()} | nil
  def get_adaptive_threshold(org_id, entity_type, feature) do
    case ets_lookup(@thresholds_table, {org_id, entity_type, feature}) do
      nil ->
        # Cache-miss: seed defaults for this org and retry.
        ensure_default_thresholds(org_id)
        ets_lookup(@thresholds_table, {org_id, entity_type, feature})

      value ->
        value
    end
  end

  @doc "Read the EWMA risk trend for an entity directly from ETS."
  @spec get_risk_trend(any(), atom(), String.t()) :: map() | nil
  def get_risk_trend(org_id, entity_type, entity_id) do
    ets_lookup(@risk_trends_table, {org_id, entity_type, entity_id})
  end

  @doc "Read peer group norms from ETS for a given organization."
  @spec get_peer_group_norms(any(), String.t()) :: map() | nil
  def get_peer_group_norms(org_id, group_label) do
    ets_lookup(@peer_groups_table, {org_id, group_label})
  end

  @doc "Get a summary of the behavioral engine state for dashboard display."
  @spec dashboard_summary() :: map()
  def dashboard_summary do
    %{
      profiles_count: safe_ets_size(@profiles_table),
      stats_features: safe_ets_size(@stats_table),
      peer_groups: safe_ets_size(@peer_groups_table),
      temporal_patterns: safe_ets_size(@temporal_table),
      adaptive_thresholds: safe_ets_size(@thresholds_table),
      risk_trends: safe_ets_size(@risk_trends_table)
    }
  end

  @doc """
  Submit analyst verdict feedback for adaptive threshold learning.

  Phase 2: signature preserved. Org-id is resolved from the alert via
  `resolve_org_from_alert/1`; if the alert lookup fails, the update is dropped
  (no global thresholds exist post-Phase-2). The message is sent to the
  registered `Detection.Behavioral` process — fixes a bug where `send(self(),
  ...)` would target the *caller's* mailbox, not the GenServer.
  """
  @spec submit_feedback(String.t(), String.t(), atom(), atom(), String.t() | nil) :: :ok
  def submit_feedback(alert_id, verdict, entity_type, feature, rule_id \\ nil) do
    org_id = resolve_org_from_alert(alert_id)

    payload = %{
      alert_id: alert_id,
      organization_id: org_id,
      verdict: verdict,
      entity_type: entity_type,
      feature: feature,
      rule_id: rule_id
    }

    case Process.whereis(__MODULE__) do
      nil ->
        # GenServer not running — apply directly when we have an org context.
        if org_id, do: update_adaptive_threshold(org_id, entity_type, feature, verdict)
        :ok

      pid ->
        send(pid, {:verdict_feedback, payload})
        :ok
    end
  rescue
    _ ->
      # Best-effort fallback: if anything explodes, still try a direct update
      # when we have an org context.
      org_id = resolve_org_from_alert(alert_id)
      if org_id, do: update_adaptive_threshold(org_id, entity_type, feature, verdict)
      :ok
  end

  # Safe ETS helper that returns nil if table or key doesn't exist
  defp ets_lookup(table, key) do
    case :ets.lookup(table, key) do
      [{^key, value}] -> value
      _ -> nil
    end
  rescue
    ArgumentError -> nil
  end

  defp safe_ets_size(table) do
    :ets.info(table, :size) || 0
  rescue
    _ -> 0
  end

  # ============================================================================
  # Event Analysis
  # ============================================================================

  defp analyze_event(event, state) do
    # Normalize event
    normalized = normalize_event(event)
    event_type = normalized.event_type

    # Run rule-based and behavioral analysis based on event category
    agent_id = normalized.agent_id
    category = EventTypes.category(event_type)

    # Phase 2: resolve org_id up-front so we can thread it through every
    # analysis/write path. The fallback to `safe_org_lookup/1` covers events
    # whose `organization_id` wasn't stamped at ingress.
    org_id = normalized.organization_id || safe_org_lookup(agent_id)
    normalized = Map.put(normalized, :organization_id, org_id)

    anomalies =
      case category do
        :process ->
          analyze_process_event(normalized.payload, agent_id, org_id, state) ++
          analyze_command_line_rules(normalized.payload, state)

        :auth ->
          analyze_auth_event(normalized.payload, org_id, state)

        :network ->
          analyze_network_event(normalized.payload, org_id, state)

        :file ->
          analyze_file_event(normalized.payload, state)

        _ ->
          []
      end

    # ── Z-Score Anomaly Detection via Online Stats ──────────────────────
    # Phase 2: entity_key is now a 3-tuple {org_id, entity_type, entity_id}
    entity_key = extract_entity_key(normalized)
    zscore_anomalies = run_zscore_analysis(entity_key, normalized, category, state)

    # ── Temporal Pattern Detection ──────────────────────────────────────
    temporal_anomalies = run_temporal_analysis(entity_key, normalized)

    # ── Peer Group Analysis ─────────────────────────────────────────────
    peer_anomalies = run_peer_group_analysis(entity_key, normalized, state)

    anomalies = anomalies ++ zscore_anomalies ++ temporal_anomalies ++ peer_anomalies

    # ── Update ETS: Online Stats, Temporal Patterns, Risk Trends ────────
    update_ets_stats(entity_key, normalized, category)
    update_ets_temporal(entity_key)
    update_ets_risk_trend(entity_key, anomalies)

    # Update GenServer-local profiles (Phase 2: org-scoped writes)
    new_state = update_profiles_from_event(normalized, state)

    # Stamp agent/org context onto every anomaly
    anomalies = Enum.map(anomalies, fn a ->
      %{a | agent_id: agent_id, organization_id: org_id}
    end)

    # Filter to significant anomalies using adaptive thresholds
    significant_anomalies = filter_significant_anomalies(anomalies, state)

    # Create alerts for significant anomalies
    Enum.each(significant_anomalies, &create_anomaly_alert/1)

    # Persist recent anomalies in ETS so BehavioralController/{statistics,
    # anomalies, risk_trends, heatmap, categories, entity_history} have data.
    # Phase 2: keyed by {org_id, entity_type, entity_id}.
    record_anomalies_in_ets(significant_anomalies)

    {significant_anomalies, new_state}
  end

  # Append significant anomalies into @anomaly_table, grouped by entity, keeping
  # at most @anomaly_history_per_entity most-recent entries per entity. Safe to
  # call with [] (no-op). Tolerant of missing table so test/standalone usage
  # without init/1 does not crash callers (rescued to :ok).
  defp record_anomalies_in_ets([]), do: :ok
  defp record_anomalies_in_ets(anomalies) when is_list(anomalies) do
    anomalies
    |> Enum.group_by(&{&1.organization_id, &1.entity_type, &1.entity_id})
    |> Enum.each(fn {key, fresh} ->
      existing =
        case :ets.lookup(@anomaly_table, key) do
          [{^key, list}] when is_list(list) -> list
          _ -> []
        end

      merged = Enum.take(fresh ++ existing, @anomaly_history_per_entity)
      :ets.insert(@anomaly_table, {key, merged})
    end)
  rescue
    error ->
      Logger.warning("record_anomalies_in_ets failed: #{inspect(error)}")
      :ok
  end

  # Phase 2: Extract a stable, org-scoped entity key from the normalized event
  # for ETS operations. Returns {org_id, entity_type, entity_id}.
  defp extract_entity_key(normalized) do
    org_id = normalized[:organization_id] ||
               Map.get(normalized, :organization_id) ||
               safe_org_lookup(normalized.agent_id)
    payload = normalized.payload
    user = get_field(payload, "user") || get_field(payload, "username")
    process_name = get_field(payload, "name") || get_field(payload, "process_name")
    hostname = get_field(payload, "hostname") || normalized.agent_id

    cond do
      user && user != "" -> {org_id, :user, user}
      process_name && process_name != "" -> {org_id, :process, String.downcase(process_name)}
      hostname -> {org_id, :host, hostname}
      true -> {org_id, :unknown, "unknown"}
    end
  end

  # Filter anomalies using adaptive thresholds (Bayesian-tuned z-score thresholds)
  # Phase 2: thresholds are org-scoped; we read each anomaly's :organization_id.
  defp filter_significant_anomalies(anomalies, _state) do
    risk_threshold = Config.risk_score_alert_threshold()

    Enum.filter(anomalies, fn a ->
      # Rule-based matches always pass if risk is above threshold
      if a.risk_score >= risk_threshold do
        true
      else
        # For z-score based anomalies, use adaptive threshold
        if is_number(a.deviation_score) and abs(a.deviation_score) > 0 do
          adaptive_z = get_adaptive_z_threshold(a.organization_id, a.entity_type, feature_from_anomaly(a))
          abs(a.deviation_score) >= adaptive_z
        else
          false
        end
      end
    end)
  end

  # Look up the adaptive z-score threshold for this org/entity_type/feature.
  # Phase 2: thresholds are org-scoped; we read the org-keyed row and fall back
  # to the configured default if absent.
  defp get_adaptive_z_threshold(org_id, entity_type, feature) do
    case ets_lookup(@thresholds_table, {org_id, entity_type, feature}) do
      {threshold_z, _fp, _tp} -> threshold_z
      _ -> Config.z_score_threshold()
    end
  end

  defp feature_from_anomaly(%BehavioralAnomaly{anomaly_type: type}) do
    case type do
      :unusual_login_time -> :login_hour
      :new_source_ip -> :source_ip
      :unusual_parent_process -> :parent_child
      :unusual_network_port -> :network_port
      :large_data_transfer -> :data_volume
      :unusual_process_for_user -> :process_count
      :temporal_anomaly -> :temporal
      :peer_group_outlier -> :peer_deviation
      _ -> :general
    end
  end

  # ============================================================================
  # Event Normalization
  # ============================================================================

  defp normalize_event(event) do
    raw_type = event["event_type"] || event[:event_type]

    %{
      event_type: EventTypes.normalize(raw_type),
      payload: event["payload"] || event[:payload] || %{},
      timestamp: event["timestamp"] || event[:timestamp] || DateTime.utc_now(),
      agent_id: event["agent_id"] || event[:agent_id],
      organization_id: event["organization_id"] || event[:organization_id]
    }
  end

  # ============================================================================
  # Process Analysis (rule-based + behavioral)
  # ============================================================================

  # Phase 2: profiles maps are org-nested. Lookups must scope by org_id.
  defp analyze_process_event(payload, agent_id, org_id, state) do
    process_name = get_field(payload, "name") || ""
    parent_name = get_field(payload, "parent_name")
    user = get_field(payload, "user")
    pid = get_field(payload, "pid")

    anomalies = []

    # 1. Match against process rules (regex-based)
    anomalies = anomalies ++ match_process_rules(process_name, state.rules.process)

    # 2. Behavioral: unusual parent-child relationship
    org_processes = Map.get(state.process_profiles, org_id, %{})
    process_profile = Map.get(org_processes, String.downcase(process_name))

    anomalies = anomalies ++
      if not is_nil(process_profile) and not is_nil(parent_name) do
        check_unusual_parent(process_name, parent_name, process_profile, state)
      else
        []
      end

    # 3. Behavioral: unusual process for user
    anomalies = anomalies ++
      if not is_nil(user) do
        check_unusual_process_for_user(process_name, user, org_id, state)
      else
        []
      end

    # 4. Multi-hop ancestor chain analysis
    # Walk up the process tree to detect multi-stage attack chains
    anomalies = anomalies ++ check_ancestor_chain(payload, agent_id, pid)

    anomalies
  end

  defp match_process_rules(process_name, rules) do
    Enum.flat_map(rules, fn rule ->
      matches = case rule.pattern do
        %{process_name: regex} ->
          Regex.match?(regex, process_name)
        %{command_line: _regex} ->
          # Command-line rules handled separately
          false
        _ ->
          false
      end

      if matches do
        [%BehavioralAnomaly{
          anomaly_type: :rule_match,
          entity_type: :process,
          entity_id: process_name,
          description: rule.description,
          risk_score: rule.risk_score,
          deviation_score: 0,
          baseline_value: nil,
          observed_value: process_name,
          mitre_techniques: rule.mitre,
          rule_id: rule.id,
          timestamp: DateTime.utc_now()
        }]
      else
        []
      end
    end)
  end

  defp check_unusual_parent(process_name, parent_name, process_profile, state) do
    parent_lower = String.downcase(parent_name)
    child_lower = String.downcase(process_name)

    # 1. Skip known-safe Windows parent-child relationships
    safe_children = Map.get(@known_safe_parent_child, parent_lower)
    if safe_children && MapSet.member?(safe_children, child_lower) do
      []
    else
      # 2. Skip during learning period (first 10 minutes)
      uptime = System.monotonic_time(:second) - state.started_at
      if uptime < state.learning_period_secs do
        []
      else
        typical_parents = process_profile.typical_parents || %{}
        parent_freq = Map.get(typical_parents, parent_lower, 0)
        total = safe_sum(Map.values(typical_parents))

        # 3. Require substantial baseline (500+ observations) and very low frequency (< 0.1%)
        if total > 500 and parent_freq < total * 0.001 do
          z_score = calculate_z_score_from_history(
            :parent_child,
            {process_name, parent_name},
            parent_freq,
            state.historical_stats
          )

          # Base risk 40 (below alert threshold), z-score can boost it
          base_risk = 40
          z_boost = if is_number(z_score) and abs(z_score) > 3.0, do: 30, else: 0
          risk = min(base_risk + z_boost, 95)

          [%BehavioralAnomaly{
            anomaly_type: :unusual_parent_process,
            entity_type: :process,
            entity_id: process_name,
            description: "Unusual parent process: #{parent_name} spawned #{process_name}",
            risk_score: risk,
            deviation_score: z_score,
            baseline_value: "typical parents (#{total} total observations)",
            observed_value: parent_name,
            mitre_techniques: ["T1055", "T1106"],
            timestamp: DateTime.utc_now()
          }]
        else
          []
        end
      end
    end
  end

  # Phase 2: user_profiles is org-nested; scope lookup by org_id.
  defp check_unusual_process_for_user(process_name, user, org_id, state) do
    # Skip during learning period
    uptime = System.monotonic_time(:second) - state.started_at
    if uptime < state.learning_period_secs do
      []
    else
      org_users = Map.get(state.user_profiles, org_id, %{})
      user_profile = Map.get(org_users, user)

      if not is_nil(user_profile) do
        typical_procs = user_profile.typical_processes || %{}
        proc_freq = Map.get(typical_procs, String.downcase(process_name), 0)
        total = safe_sum(Map.values(typical_procs))

        # Require 200+ observations and process never seen before
        if total > 200 and proc_freq == 0 do
          z_score = calculate_z_score_from_history(
            :user_process,
            {user, process_name},
            0,
            state.historical_stats
          )

          [%BehavioralAnomaly{
            anomaly_type: :unusual_process_for_user,
            entity_type: :user,
            entity_id: user,
            description: "User #{user} executed unusual process: #{process_name}",
            risk_score: 50,
            deviation_score: z_score,
            baseline_value: "user's typical processes (#{total} total observations)",
            observed_value: process_name,
            mitre_techniques: ["T1078"],
            timestamp: DateTime.utc_now()
          }]
        else
          []
        end
      else
        []
      end
    end
  end

  # ============================================================================
  # Multi-Hop Ancestor Chain Analysis
  # ============================================================================
  #
  # Walks up the process tree using the Correlator's ETS-backed process tree
  # to build a full ancestor chain, then applies multiple detection strategies:
  #
  # 1. Suspicious chain pattern matching (known multi-stage attack signatures)
  # 2. Chain depth anomaly scoring (sensitive processes deep in chains)
  # 3. Trust boundary crossing detection (signed -> unsigned transitions)
  # 4. Elevation change detection (unexpected privilege changes)
  # 5. LOLBin chain detection (living-off-the-land binary sequences)

  defp check_ancestor_chain(_payload, nil, _pid), do: []
  defp check_ancestor_chain(_payload, _agent_id, nil), do: []
  defp check_ancestor_chain(payload, agent_id, pid) do
    chain = build_ancestor_chain(agent_id, pid, payload)

    # Skip analysis for very short chains (1-2 processes are normal)
    if length(chain) < 3 do
      []
    else
      anomalies =
        []
        |> append_anomalies(check_suspicious_chain_patterns(chain))
        |> append_anomalies(check_chain_depth_anomaly(chain))
        |> append_anomalies(check_trust_boundary_crossing(chain))
        |> append_anomalies(check_elevation_changes(chain))
        |> append_anomalies(check_lolbin_chain(chain))

      case anomalies do
        [] ->
          []

        anomalies ->
          # Return the highest-scoring anomaly as a BehavioralAnomaly
          best = Enum.max_by(anomalies, & &1.score)
          chain_names = Enum.map(chain, & &1.process_name)

          [%BehavioralAnomaly{
            anomaly_type: :ancestor_chain_anomaly,
            entity_type: :process,
            entity_id: List.last(chain_names) || "unknown",
            description: "#{best.description} | Chain: #{Enum.join(chain_names, " -> ")}",
            risk_score: best.score,
            deviation_score: 0,
            baseline_value: "chain depth: #{length(chain)}, max normal: 2-3 hops",
            observed_value: Enum.join(chain_names, " -> "),
            mitre_techniques: [best.technique],
            rule_id: "ancestor_chain:#{best.check_type}",
            timestamp: DateTime.utc_now()
          }]
      end
    end
  end

  # Build the ancestor chain by walking up the correlator's process tree.
  # Returns a list of process info maps from root ancestor to current process.
  # Falls back to constructing a minimal chain from the event payload if the
  # process tree is not available.
  defp build_ancestor_chain(agent_id, pid, payload) do
    chain_from_tree = try do
      case :ets.lookup(@process_tree_table, agent_id) do
        [{^agent_id, graph}] ->
          # Walk up from pid to ancestors, with depth limit
          ancestors = walk_ancestors(graph, pid, @ancestor_chain_max_depth)

          # Convert PIDs to process info maps
          Enum.map(ancestors, fn ancestor_pid ->
            labels = Graph.vertex_labels(graph, ancestor_pid) |> List.first() || %{}
            %{
              pid: ancestor_pid,
              process_name: extract_process_name(labels[:name] || labels[:path] || "PID_#{ancestor_pid}"),
              path: labels[:path] || "",
              is_signed: labels[:is_signed] || false,
              signer: labels[:signer],
              is_elevated: labels[:is_elevated] || false,
              user: labels[:user]
            }
          end)

        [] ->
          []
      end
    rescue
      # ETS table may not exist yet (Correlator not started)
      _ -> []
    end

    if length(chain_from_tree) >= 2 do
      chain_from_tree
    else
      # Fallback: build minimal chain from event payload (parent + current)
      build_fallback_chain(payload)
    end
  end

  # Walk up the process tree from a given PID, collecting ancestors.
  # Returns PIDs in order from root ancestor to the given PID.
  # Includes cycle detection and depth limiting.
  defp walk_ancestors(graph, pid, max_depth) do
    do_walk_ancestors(graph, pid, max_depth, MapSet.new(), [pid])
  end

  defp do_walk_ancestors(_graph, _pid, 0, _visited, acc), do: acc
  defp do_walk_ancestors(graph, pid, remaining_depth, visited, acc) do
    if MapSet.member?(visited, pid) do
      # Cycle detected, stop walking
      acc
    else
      visited = MapSet.put(visited, pid)

      case Graph.in_neighbors(graph, pid) do
        [parent_pid | _] ->
          # Continue walking up
          do_walk_ancestors(
            graph, parent_pid, remaining_depth - 1, visited,
            [parent_pid | acc]
          )

        [] ->
          # Reached root of the tree
          acc
      end
    end
  end

  # Build a minimal 2-element chain from event payload when the process tree
  # is not available. This provides degraded but functional ancestor analysis.
  defp build_fallback_chain(payload) do
    parent_name = get_field(payload, "parent_name")
    parent_path = get_field(payload, "parent_path")
    process_name = get_field(payload, "name")
    process_path = get_field(payload, "path")
    ppid = get_field(payload, "ppid")
    pid = get_field(payload, "pid")

    parent_entry = if parent_name || parent_path do
      %{
        pid: ppid,
        process_name: extract_process_name(parent_path || parent_name || "unknown"),
        path: parent_path || "",
        is_signed: false,
        signer: nil,
        is_elevated: false,
        user: nil
      }
    end

    current_entry = if process_name || process_path do
      %{
        pid: pid,
        process_name: extract_process_name(process_path || process_name || "unknown"),
        path: process_path || "",
        is_signed: get_field(payload, "is_signed") || false,
        signer: get_field(payload, "signer"),
        is_elevated: get_field(payload, "is_elevated") || false,
        user: get_field(payload, "user")
      }
    end

    [parent_entry, current_entry] |> Enum.reject(&is_nil/1)
  end

  # --------------------------------------------------------------------------
  # Check 1: Suspicious chain patterns
  # --------------------------------------------------------------------------
  # Matches the ancestor chain against known multi-stage attack signatures.
  # Uses a sliding window to find pattern subsequences within the chain.

  defp check_suspicious_chain_patterns(chain) do
    chain_names = Enum.map(chain, & &1.process_name)

    @suspicious_ancestor_chains
    |> Enum.flat_map(fn {patterns, severity, technique, description} ->
      pattern_len = length(patterns)

      if length(chain_names) >= pattern_len do
        # Slide a window of pattern_len across the chain names
        chain_names
        |> Enum.chunk_every(pattern_len, 1, :discard)
        |> Enum.flat_map(fn window ->
          if chain_window_matches?(window, patterns) do
            score = severity_to_base_score(severity) + chain_depth_bonus(length(chain))
            [%{
              check_type: :suspicious_pattern,
              severity: severity,
              score: min(100, score),
              technique: technique,
              description: description
            }]
          else
            []
          end
        end)
      else
        []
      end
    end)
    # Deduplicate: keep highest-scoring match per technique
    |> Enum.group_by(& &1.technique)
    |> Enum.map(fn {_technique, matches} ->
      Enum.max_by(matches, & &1.score)
    end)
  end

  # Match a window of process names against a pattern list.
  # :_any matches any process name; Regex patterns are matched case-insensitively.
  defp chain_window_matches?(window, patterns) do
    Enum.zip(window, patterns)
    |> Enum.all?(fn {name, pattern} ->
      case pattern do
        :_any -> true
        %Regex{} = regex -> Regex.match?(regex, name)
        _ -> false
      end
    end)
  end

  # --------------------------------------------------------------------------
  # Check 2: Chain depth anomaly
  # --------------------------------------------------------------------------
  # Flags sensitive processes (shells, LOLBins) that appear 3+ hops deep.
  # Normal processes rarely go past 2-3 hops in the ancestor chain.

  defp check_chain_depth_anomaly(chain) do
    chain
    |> Enum.with_index()
    |> Enum.flat_map(fn {entry, index} ->
      # Only flag processes at depth 3+ (0-indexed, so index >= 3 means 4th+ process)
      # The depth in the chain represents how many parent hops from root
      depth = index
      name = entry.process_name

      is_sensitive = Enum.any?(@deep_chain_sensitive_processes, fn regex ->
        Regex.match?(regex, name)
      end)

      if is_sensitive and depth >= 3 do
        # Score increases with depth
        base_score = 55
        depth_bonus = min(30, (depth - 2) * 10)
        score = base_score + depth_bonus

        [%{
          check_type: :chain_depth,
          severity: if(depth >= 4, do: :high, else: :medium),
          score: score,
          technique: "T1106",
          description: "Sensitive process #{name} at unusual chain depth #{depth}"
        }]
      else
        []
      end
    end)
    # Keep only the deepest/highest-scoring entry per process name
    |> Enum.group_by(& &1.description)
    |> Enum.map(fn {_desc, matches} ->
      Enum.max_by(matches, & &1.score)
    end)
  end

  # --------------------------------------------------------------------------
  # Check 3: Trust boundary crossing
  # --------------------------------------------------------------------------
  # Detects chains where unsigned processes appear after a sequence of signed
  # Microsoft processes. This pattern is characteristic of malware that
  # leverages legitimate signed processes to eventually execute unsigned payloads.

  defp check_trust_boundary_crossing(chain) do
    # Walk the chain and look for transitions from signed -> unsigned
    chain
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.with_index()
    |> Enum.flat_map(fn {[parent, child], index} ->
      parent_is_trusted = parent.is_signed == true and
                          is_known_microsoft_process(parent.process_name)
      child_is_unsigned = child.is_signed != true

      # Only flag if the parent is a known signed Microsoft process and the
      # child is unsigned, and we are past the first hop (depth > 0)
      if parent_is_trusted and child_is_unsigned and index >= 1 do
        # Check if there is a run of signed processes before this transition
        signed_run_length = count_signed_ancestors_before(chain, index + 1)

        if signed_run_length >= 2 do
          score = 70 + min(20, signed_run_length * 5)

          [%{
            check_type: :trust_boundary,
            severity: :high,
            score: score,
            technique: "T1218",
            description: "Unsigned process #{child.process_name} spawned after #{signed_run_length} signed Microsoft ancestors"
          }]
        else
          []
        end
      else
        []
      end
    end)
  end

  # Count consecutive signed ancestors before a given index in the chain
  defp count_signed_ancestors_before(chain, index) do
    chain
    |> Enum.take(index)
    |> Enum.reverse()
    |> Enum.take_while(fn entry ->
      entry.is_signed == true and is_known_microsoft_process(entry.process_name)
    end)
    |> length()
  end

  # Check if a process name is a known Microsoft signed system process
  defp is_known_microsoft_process(process_name) when is_binary(process_name) do
    MapSet.member?(@microsoft_signed_processes, String.downcase(process_name))
  end
  defp is_known_microsoft_process(_), do: false

  # --------------------------------------------------------------------------
  # Check 4: Elevation changes
  # --------------------------------------------------------------------------
  # Detects unexpected elevation changes in the ancestor chain. If a
  # non-elevated process spawns an elevated process deep in the chain,
  # this may indicate privilege escalation.

  defp check_elevation_changes(chain) do
    chain
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.with_index()
    |> Enum.flat_map(fn {[parent, child], index} ->
      parent_elevated = parent.is_elevated == true
      child_elevated = child.is_elevated == true

      # Flag non-elevated -> elevated transitions at depth 2+
      if not parent_elevated and child_elevated and index >= 2 do
        [%{
          check_type: :elevation_change,
          severity: :high,
          score: 75,
          technique: "T1548",
          description: "Unexpected privilege escalation: #{parent.process_name} (non-elevated) -> #{child.process_name} (elevated) at chain depth #{index + 1}"
        }]
      else
        []
      end
    end)
  end

  # --------------------------------------------------------------------------
  # Check 5: LOLBin chain detection
  # --------------------------------------------------------------------------
  # Detects chains containing multiple LOLBins. A single LOLBin in a chain
  # may be normal, but multiple LOLBins chained together is highly suspicious
  # and indicates an adversary is chaining trusted binaries to evade detection.

  defp check_lolbin_chain(chain) do
    lolbin_entries = Enum.filter(chain, fn entry ->
      MapSet.member?(@lolbin_processes, String.downcase(entry.process_name))
    end)

    lolbin_count = length(lolbin_entries)

    if lolbin_count >= 2 do
      lolbin_names = Enum.map(lolbin_entries, & &1.process_name) |> Enum.join(", ")
      score = 70 + min(25, lolbin_count * 10)

      [%{
        check_type: :lolbin_chain,
        severity: if(lolbin_count >= 3, do: :critical, else: :high),
        score: score,
        technique: "T1218",
        description: "Multiple LOLBins in ancestor chain (#{lolbin_count}): #{lolbin_names}"
      }]
    else
      []
    end
  end

  # --------------------------------------------------------------------------
  # Ancestor chain helper functions
  # --------------------------------------------------------------------------

  # Convert severity atom to a base numeric score
  defp severity_to_base_score(:critical), do: 90
  defp severity_to_base_score(:high), do: 75
  defp severity_to_base_score(:medium), do: 55
  defp severity_to_base_score(:low), do: 35
  defp severity_to_base_score(_), do: 50

  # Bonus score for deeper chains (longer chains are more suspicious)
  defp chain_depth_bonus(depth) when depth >= 5, do: 10
  defp chain_depth_bonus(depth) when depth >= 4, do: 5
  defp chain_depth_bonus(_), do: 0

  # Append non-empty anomaly lists
  defp append_anomalies(acc, []), do: acc
  defp append_anomalies(acc, new_anomalies), do: acc ++ new_anomalies

  # ============================================================================
  # Command Line Analysis (regex rule-based with parent context checking)
  # ============================================================================

  defp analyze_command_line_rules(payload, state) do
    command_line = get_field(payload, "command_line") || ""
    process_name = get_field(payload, "name") || ""
    parent_path = get_field(payload, "parent_path") || get_field(payload, "parent_name") || ""

    if command_line == "" do
      []
    else
      Enum.flat_map(state.rules.command_line, fn rule ->
        if Regex.match?(rule.pattern, command_line) do
          # Check parent context to potentially reduce severity
          {adjusted_rule, parent_context} = check_rule_with_parent_context(rule, parent_path)

          # Build description with parent context info
          description = build_rule_description(rule, process_name, parent_path, parent_context)

          [%BehavioralAnomaly{
            anomaly_type: :command_line_rule_match,
            entity_type: :process,
            entity_id: process_name,
            description: description,
            risk_score: adjusted_rule.risk_score,
            deviation_score: 0,
            baseline_value: parent_context_baseline(parent_context, parent_path),
            observed_value: String.slice(command_line, 0, 200),
            mitre_techniques: rule.mitre,
            rule_id: rule.id,
            timestamp: DateTime.utc_now()
          }]
        else
          []
        end
      end)
    end
  end

  @doc """
  Check if the parent process matches a legitimate parent pattern for this rule.
  Returns {adjusted_rule, parent_context} where:
  - adjusted_rule has potentially reduced severity/risk_score
  - parent_context is :legitimate, :suspicious, or :unknown
  """
  defp check_rule_with_parent_context(rule, parent_path) do
    legitimate_parents = Map.get(rule, :legitimate_parents, [])
    parent_reduces_severity = Map.get(rule, :parent_reduces_severity, false)

    cond do
      # No parent context checking configured for this rule
      legitimate_parents == [] ->
        {rule, :unknown}

      # Check if parent matches any legitimate pattern
      is_legitimate_parent?(parent_path, legitimate_parents) ->
        if parent_reduces_severity do
          # Reduce severity and risk score for legitimate parent context
          adjusted_rule = %{rule |
            severity: reduce_severity(rule.severity),
            risk_score: round(rule.risk_score * 0.3)
          }
          {adjusted_rule, :legitimate}
        else
          # Log the context but don't reduce severity (e.g., credential access)
          {rule, :legitimate}
        end

      # Parent provided but doesn't match legitimate patterns
      parent_path != "" ->
        {rule, :suspicious}

      # No parent information available
      true ->
        {rule, :unknown}
    end
  end

  @doc """
  Check if the parent path matches any of the legitimate parent patterns.
  """
  defp is_legitimate_parent?("", _patterns), do: false
  defp is_legitimate_parent?(parent_path, patterns) do
    Enum.any?(patterns, fn pattern ->
      Regex.match?(pattern, parent_path)
    end)
  end

  @doc """
  Reduce severity by one level for legitimate parent context.
  """
  defp reduce_severity(:critical), do: :high
  defp reduce_severity(:high), do: :medium
  defp reduce_severity(:medium), do: :low
  defp reduce_severity(:low), do: :info
  defp reduce_severity(other), do: other

  @doc """
  Build a descriptive message that includes parent context information.
  """
  defp build_rule_description(rule, process_name, parent_path, parent_context) do
    base_desc = "#{rule.description} in #{process_name}"

    case parent_context do
      :legitimate ->
        "#{base_desc} (legitimate parent: #{extract_process_name(parent_path)}, severity reduced)"

      :suspicious ->
        "#{base_desc} (suspicious parent: #{extract_process_name(parent_path)})"

      :unknown when parent_path != "" ->
        "#{base_desc} (parent: #{extract_process_name(parent_path)})"

      _ ->
        base_desc
    end
  end

  @doc """
  Build baseline value string based on parent context.
  """
  defp parent_context_baseline(:legitimate, parent_path) do
    "Legitimate parent detected: #{extract_process_name(parent_path)}"
  end
  defp parent_context_baseline(:suspicious, parent_path) do
    "Parent not in allowlist: #{extract_process_name(parent_path)}"
  end
  defp parent_context_baseline(_, _), do: nil

  @doc """
  Extract just the process name from a full path.
  """
  defp extract_process_name(path) when is_binary(path) do
    path
    |> String.split(~r/[\/\\]/)
    |> List.last()
    |> case do
      nil -> path
      name -> name
    end
  end
  defp extract_process_name(_), do: "unknown"

  # ============================================================================
  # Auth Analysis
  # ============================================================================

  # Phase 2: user_profiles is org-nested; last_login_locations is keyed by
  # {org_id, user}. All lookups now require org_id.
  defp analyze_auth_event(payload, org_id, state) do
    user = get_field(payload, "user") || get_field(payload, "username") || ""
    source_ip = get_field(payload, "source_ip")

    org_users = Map.get(state.user_profiles, org_id, %{})
    user_profile = Map.get(org_users, user)

    anomalies = []

    # Check unusual login time
    anomalies = anomalies ++ check_unusual_login_time(user, user_profile, state)

    # Check unusual source IP
    anomalies = anomalies ++ check_unusual_source_ip(user, source_ip, user_profile, state)

    # Check impossible travel (org-scoped login-location lookup)
    anomalies = anomalies ++ check_impossible_travel(user, source_ip, org_id, state)

    anomalies
  end

  defp check_unusual_login_time(user, nil, _state), do: []
  defp check_unusual_login_time(user, user_profile, state) do
    typical_hours = user_profile.typical_login_hours || %{}
    current_hour = DateTime.utc_now().hour
    hour_freq = Map.get(typical_hours, current_hour, 0)
    total_logins = safe_sum(Map.values(typical_hours))

    if total_logins > 20 and hour_freq < total_logins * 0.02 do
      z_score = calculate_z_score_from_history(
        :login_hour,
        {user, current_hour},
        hour_freq,
        state.historical_stats
      )

      [%BehavioralAnomaly{
        anomaly_type: :unusual_login_time,
        entity_type: :user,
        entity_id: user,
        description: "Login at unusual time (#{current_hour}:00) for user #{user}",
        risk_score: 50,
        deviation_score: z_score,
        baseline_value: "typical login hours (#{total_logins} total logins)",
        observed_value: current_hour,
        mitre_techniques: ["T1078"],
        timestamp: DateTime.utc_now()
      }]
    else
      []
    end
  end

  defp check_unusual_source_ip(_user, nil, _profile, _state), do: []
  defp check_unusual_source_ip(_user, _ip, nil, _state), do: []
  defp check_unusual_source_ip(user, source_ip, user_profile, state) do
    typical_ips = user_profile.typical_source_ips || %{}
    ip_freq = Map.get(typical_ips, source_ip, 0)
    total = safe_sum(Map.values(typical_ips))

    if total > 10 and ip_freq == 0 do
      z_score = calculate_z_score_from_history(
        :source_ip,
        {user, source_ip},
        0,
        state.historical_stats
      )

      [%BehavioralAnomaly{
        anomaly_type: :new_source_ip,
        entity_type: :user,
        entity_id: user,
        description: "Login from new IP address #{source_ip} for user #{user}",
        risk_score: 65,
        deviation_score: z_score,
        baseline_value: "#{map_size(typical_ips)} known IPs",
        observed_value: source_ip,
        mitre_techniques: ["T1078", "T1021"],
        timestamp: DateTime.utc_now()
      }]
    else
      []
    end
  end

  # ============================================================================
  # Network Analysis
  # ============================================================================

  # Phase 2: process_profiles is org-nested; thread org_id through.
  defp analyze_network_event(payload, org_id, state) do
    process_name = get_field(payload, "process_name") || ""
    remote_ip = get_field(payload, "remote_ip")
    remote_port = payload["remote_port"] || payload[:remote_port]
    bytes_sent = payload["bytes_sent"] || payload[:bytes_sent] || 0

    anomalies = []

    # Check unusual port for process (behavioral)
    anomalies = anomalies ++ check_unusual_port(process_name, remote_port, org_id, state)

    # Check large data transfer (configurable threshold)
    large_threshold = Config.large_transfer_bytes()
    anomalies = anomalies ++
      if is_number(bytes_sent) and bytes_sent > large_threshold do
        [%BehavioralAnomaly{
          anomaly_type: :large_data_transfer,
          entity_type: :host,
          entity_id: remote_ip || "unknown",
          description: "Large data transfer (#{format_bytes(bytes_sent)}) to #{remote_ip}",
          risk_score: 70,
          deviation_score: 0,
          baseline_value: "threshold: #{format_bytes(large_threshold)}",
          observed_value: bytes_sent,
          mitre_techniques: ["T1041"],
          timestamp: DateTime.utc_now()
        }]
      else
        []
      end

    # Check suspicious ports (configurable list)
    suspicious_ports = Config.suspicious_ports()
    anomalies = anomalies ++
      if remote_port in suspicious_ports do
        [%BehavioralAnomaly{
          anomaly_type: :suspicious_port,
          entity_type: :process,
          entity_id: process_name,
          description: "Connection to potentially malicious port #{remote_port}",
          risk_score: 75,
          deviation_score: 0,
          baseline_value: "suspicious port list",
          observed_value: remote_port,
          mitre_techniques: ["T1571"],
          timestamp: DateTime.utc_now()
        }]
      else
        []
      end

    anomalies
  end

  defp check_unusual_port(_process_name, nil, _org_id, _state), do: []
  defp check_unusual_port(process_name, remote_port, org_id, state) do
    # Skip common infrastructure ports
    port_int = parse_port(remote_port)

    if port_int && MapSet.member?(@common_safe_ports, port_int) do
      []
    else
      # Skip during learning period
      uptime = System.monotonic_time(:second) - state.started_at
      if uptime < state.learning_period_secs do
        []
      else
        org_processes = Map.get(state.process_profiles, org_id, %{})
        process_profile = Map.get(org_processes, String.downcase(process_name))

        if not is_nil(process_profile) do
          typical_ports = process_profile.typical_network_ports || %{}
          port_freq = Map.get(typical_ports, remote_port, 0)
          total = safe_sum(Map.values(typical_ports))

          # Require 200+ observations and port never seen (frequency 0)
          if total > 200 and port_freq == 0 do
            [%BehavioralAnomaly{
              anomaly_type: :unusual_network_port,
              entity_type: :process,
              entity_id: process_name,
              description: "Process #{process_name} connected to unusual port #{remote_port}",
              risk_score: 50,
              deviation_score: calculate_rarity_score(0, total),
              baseline_value: "typical ports (#{total} observations)",
              observed_value: remote_port,
              mitre_techniques: ["T1071"],
              timestamp: DateTime.utc_now()
            }]
          else
            []
          end
        else
          []
        end
      end
    end
  end

  # ============================================================================
  # File Analysis (regex rule-based)
  # ============================================================================

  defp analyze_file_event(payload, state) do
    path = get_field(payload, "path") || ""
    process_name = get_field(payload, "process_name") || ""

    anomalies = []

    # Check sensitive path rules (regex-based)
    anomalies = anomalies ++
      Enum.flat_map(state.rules.sensitive_path, fn rule ->
        if Regex.match?(rule.pattern, path) do
          [%BehavioralAnomaly{
            anomaly_type: :sensitive_file_access,
            entity_type: :process,
            entity_id: process_name,
            description: "#{rule.description}: #{path}",
            risk_score: 85,
            deviation_score: 0,
            baseline_value: nil,
            observed_value: path,
            mitre_techniques: rule.mitre,
            rule_id: rule.id,
            timestamp: DateTime.utc_now()
          }]
        else
          []
        end
      end)

    # Check ransomware extensions
    anomalies = anomalies ++
      if Enum.any?(@ransomware_extensions, &String.ends_with?(path, &1)) do
        [%BehavioralAnomaly{
          anomaly_type: :ransomware_extension,
          entity_type: :process,
          entity_id: process_name,
          description: "File created with ransomware-like extension: #{path}",
          risk_score: 95,
          deviation_score: 0,
          baseline_value: nil,
          observed_value: path,
          mitre_techniques: ["T1486"],
          timestamp: DateTime.utc_now()
        }]
      else
        []
      end

    anomalies
  end

  # ============================================================================
  # Profile Updates
  # ============================================================================

  # Phase 2: state.user_profiles / state.process_profiles are org-nested. All
  # writes scope by the normalized event's :organization_id (already resolved
  # in analyze_event/2).
  defp update_profiles_from_event(normalized, state) do
    event_type = normalized.event_type
    payload = normalized.payload
    org_id = normalized[:organization_id] || Map.get(normalized, :organization_id)

    case EventTypes.category(event_type) do
      :process ->
        process_name = get_field(payload, "name")
        if process_name do
          update_process_profile(state, org_id, process_name, payload)
        else
          state
        end

      :auth ->
        user = get_field(payload, "user") || get_field(payload, "username")
        source_ip = get_field(payload, "source_ip")

        state = if user do
          update_user_profile(state, org_id, user, payload)
        else
          state
        end

        if user && source_ip do
          update_last_login_location(state, org_id, user, source_ip)
        else
          state
        end

      _ ->
        state
    end
  end

  defp update_process_profile(state, org_id, process_name, payload) do
    key = String.downcase(process_name)
    org_processes = Map.get(state.process_profiles, org_id, %{})
    current = Map.get(org_processes, key, %ProcessProfile{process_name: key})

    parent_name = get_field(payload, "parent_name")
    port = payload["remote_port"] || payload[:remote_port]

    updated = %{current |
      typical_parents: update_frequency_map(current.typical_parents, parent_name),
      typical_network_ports: update_frequency_map(current.typical_network_ports, port),
      total_events: current.total_events + 1,
      last_updated: DateTime.utc_now()
    }

    new_org_processes = Map.put(org_processes, key, updated)
    %{state | process_profiles: Map.put(state.process_profiles, org_id, new_org_processes)}
  end

  defp update_user_profile(state, org_id, user, payload) do
    org_users = Map.get(state.user_profiles, org_id, %{})
    current = Map.get(org_users, user, %UserProfile{user_id: user})

    current_hour = DateTime.utc_now().hour
    source_ip = get_field(payload, "source_ip")
    process_name = get_field(payload, "process_name")

    updated = %{current |
      typical_login_hours: update_frequency_map(current.typical_login_hours, current_hour),
      typical_source_ips: update_frequency_map(current.typical_source_ips, source_ip),
      typical_processes: update_frequency_map(current.typical_processes, process_name),
      total_events: current.total_events + 1,
      last_updated: DateTime.utc_now()
    }

    new_org_users = Map.put(org_users, user, updated)
    %{state | user_profiles: Map.put(state.user_profiles, org_id, new_org_users)}
  end

  defp update_frequency_map(nil, _value), do: %{}
  defp update_frequency_map(map, nil), do: map
  defp update_frequency_map(map, value) do
    key = if is_binary(value), do: String.downcase(value), else: value
    Map.update(map, key, 1, &(&1 + 1))
  end

  defp update_all_baselines(state) do
    # Phase 2: profiles are nested by org_id. Sum across orgs for the log line.
    user_count = state.user_profiles |> Enum.map(fn {_org, m} -> map_size(m) end) |> Enum.sum()
    proc_count = state.process_profiles |> Enum.map(fn {_org, m} -> map_size(m) end) |> Enum.sum()
    # In production, this queries historical data and rebuilds profiles
    Logger.info("Baseline update completed - " <>
      "#{user_count} user profiles across #{map_size(state.user_profiles)} orgs, " <>
      "#{proc_count} process profiles across #{map_size(state.process_profiles)} orgs")
    state
  end

  # ============================================================================
  # Database Persistence (baselines)
  # ============================================================================

  # Phase 2: profile maps are nested by org_id. We encode the org_id INTO the
  # persisted entity_id (e.g. "ORG_UUID::alice") so the existing
  # behavioral_baselines schema (entity_type, entity_id, data) keeps working
  # without a DB migration. Phase 5 will add a dedicated org_id column. The
  # load path parses the same prefix back into org buckets.
  @org_id_separator "::"

  defp persist_baselines_to_db(state) do
    user_count = state.user_profiles |> Enum.map(fn {_org, m} -> map_size(m) end) |> Enum.sum()
    process_count = state.process_profiles |> Enum.map(fn {_org, m} -> map_size(m) end) |> Enum.sum()

    try do
      # Persist user profiles per-org
      Enum.each(state.user_profiles, fn {org_id, users} ->
        Enum.each(users, fn {user_id, profile} ->
          upsert_baseline(:user, scoped_entity_id(org_id, user_id), %{
            organization_id: org_id,
            typical_login_hours: profile.typical_login_hours || %{},
            typical_source_ips: profile.typical_source_ips || %{},
            typical_processes: profile.typical_processes || %{},
            total_events: profile.total_events,
            last_updated: profile.last_updated
          })
        end)
      end)

      # Persist process profiles per-org
      Enum.each(state.process_profiles, fn {org_id, processes} ->
        Enum.each(processes, fn {proc_name, profile} ->
          upsert_baseline(:process, scoped_entity_id(org_id, proc_name), %{
            organization_id: org_id,
            typical_parents: profile.typical_parents || %{},
            typical_network_ports: profile.typical_network_ports || %{},
            total_events: profile.total_events,
            last_updated: profile.last_updated
          })
        end)
      end)

      # Persist historical stats for z-score calculation
      persist_historical_stats(state.historical_stats)

      Logger.debug("Persisted baselines to DB: #{user_count} user, #{process_count} process profiles")
    rescue
      e ->
        Logger.error("Failed to persist baselines: #{inspect(e)}")
    end
  end

  # Encode {org_id, entity_id} into the persisted entity_id column.
  defp scoped_entity_id(nil, entity_id), do: "__noorg__#{@org_id_separator}#{entity_id}"
  defp scoped_entity_id(org_id, entity_id), do: "#{org_id}#{@org_id_separator}#{entity_id}"

  # Decode "ORG_UUID::entity" back into {org_id, entity_id}; legacy unprefixed
  # rows (pre-Phase-2) are returned as {nil, raw_id}.
  defp parse_scoped_entity_id(raw) when is_binary(raw) do
    case String.split(raw, @org_id_separator, parts: 2) do
      ["__noorg__", rest] -> {nil, rest}
      [org_id, rest] -> {org_id, rest}
      [_only] -> {nil, raw}
    end
  end

  defp upsert_baseline(entity_type, entity_id, data) do
    # Uses Repo to upsert a behavioral_baselines record
    # Table: behavioral_baselines (entity_type, entity_id, data jsonb, updated_at)
    now = DateTime.utc_now()

    try do
      TamanduaServer.Repo.insert_all(
        "behavioral_baselines",
        [%{
          entity_type: to_string(entity_type),
          entity_id: to_string(entity_id),
          data: Jason.encode!(data),
          updated_at: now
        }],
        on_conflict: {:replace, [:data, :updated_at]},
        conflict_target: [:entity_type, :entity_id]
      )
    rescue
      # Table may not exist yet in development
      _ -> :ok
    end
  end

  # Phase 2: returns {%{org_id => %{user_id => UserProfile}},
  #                   %{org_id => %{proc_name => ProcessProfile}}}
  defp load_persisted_baselines do
    try do
      rows = TamanduaServer.Repo.query!(
        "SELECT entity_type, entity_id, data FROM behavioral_baselines"
      ).rows

      {user_profiles, process_profiles} =
        Enum.reduce(rows, {%{}, %{}}, fn [entity_type, raw_entity_id, data_json], {users, procs} ->
          case Jason.decode(data_json) do
            {:ok, data} ->
              {parsed_org, parsed_id} = parse_scoped_entity_id(raw_entity_id)
              # Prefer the org_id embedded in the JSON payload; fall back to
              # the prefix parsed out of the entity_id column. Either may be nil
              # for legacy/unscoped rows.
              org_id = data["organization_id"] || parsed_org

              case entity_type do
                "user" ->
                  profile = %UserProfile{
                    user_id: parsed_id,
                    typical_login_hours: atomize_int_keys(data["typical_login_hours"]),
                    typical_source_ips: data["typical_source_ips"] || %{},
                    typical_processes: data["typical_processes"] || %{},
                    total_events: data["total_events"] || 0,
                    last_updated: parse_datetime(data["last_updated"])
                  }
                  org_bucket = Map.get(users, org_id, %{})
                  new_org_bucket = Map.put(org_bucket, parsed_id, profile)
                  {Map.put(users, org_id, new_org_bucket), procs}

                "process" ->
                  profile = %ProcessProfile{
                    process_name: parsed_id,
                    typical_parents: data["typical_parents"] || %{},
                    typical_network_ports: atomize_int_keys(data["typical_network_ports"]),
                    total_events: data["total_events"] || 0,
                    last_updated: parse_datetime(data["last_updated"])
                  }
                  org_bucket = Map.get(procs, org_id, %{})
                  new_org_bucket = Map.put(org_bucket, parsed_id, profile)
                  {users, Map.put(procs, org_id, new_org_bucket)}

                _ ->
                  {users, procs}
              end

            _ ->
              {users, procs}
          end
        end)

      {user_profiles, process_profiles}
    rescue
      _ ->
        Logger.debug("No persisted baselines found (table may not exist yet)")
        {%{}, %{}}
    end
  end

  defp load_historical_stats do
    try do
      case TamanduaServer.Repo.query(
        "SELECT data FROM behavioral_baselines WHERE entity_type = 'historical_stats' AND entity_id = 'global' LIMIT 1"
      ) do
        {:ok, %{rows: [[data_json]]}} ->
          case Jason.decode(data_json) do
            {:ok, stats} -> stats
            _ -> %{}
          end
        _ -> %{}
      end
    rescue
      _ -> %{}
    end
  end

  defp persist_historical_stats(stats) do
    upsert_baseline(:historical_stats, "global", stats)
  end

  # ============================================================================
  # Z-Score Calculation
  # ============================================================================

  defp calculate_z_score_from_history(metric_type, key, observed_value, historical_stats) do
    # Look up persisted mean and stddev for this metric type
    metric_key = "#{metric_type}:#{inspect(key)}"

    case Map.get(historical_stats, metric_key) do
      %{"mean" => mean, "stddev" => stddev} when is_number(mean) and is_number(stddev) and stddev > 0 ->
        (observed_value - mean) / stddev

      _ ->
        # No historical data available; fall back to rarity-based score
        calculate_rarity_score(observed_value, 100)
    end
  end

  # ============================================================================
  # Risk Scoring
  # ============================================================================

  # Phase 2: org-scoped lookup into nested profile maps.
  defp calculate_entity_risk_score(org_id, entity_type, entity_id, state) do
    base_score = 0

    case entity_type do
      :user ->
        org_users = Map.get(state.user_profiles, org_id, %{})
        profile = Map.get(org_users, entity_id)
        if profile do
          if profile.total_events > 100, do: base_score, else: base_score + 10
        else
          base_score + 20
        end

      :process ->
        org_processes = Map.get(state.process_profiles, org_id, %{})
        profile = Map.get(org_processes, String.downcase(to_string(entity_id)))
        if profile do
          if profile.total_events > 50, do: base_score, else: base_score + 15
        else
          base_score + 25
        end

      _ -> base_score
    end
  end

  defp calculate_rarity_score(observed_freq, total_freq) do
    if total_freq == 0 do
      0.0
    else
      expected = total_freq / 100
      if expected == 0, do: 0.0, else: (expected - observed_freq) / :math.sqrt(expected)
    end
  end

  # ============================================================================
  # Rule Loading
  # ============================================================================

  defp load_rules do
    # Start with compile-time defaults, then overlay any DB-stored custom rules
    db_rules = load_rules_from_db()

    %{
      process: merge_rules(@default_process_rules, db_rules[:process] || []),
      command_line: merge_rules(@default_command_line_rules, db_rules[:command_line] || []),
      sensitive_path: merge_rules(@default_sensitive_path_rules, db_rules[:sensitive_path] || [])
    }
  end

  defp load_rules_from_db do
    # Load custom detection rules from database
    # Expected table: detection_rules (id, category, definition jsonb, enabled boolean)
    try do
      case TamanduaServer.Repo.query(
        "SELECT category, definition FROM detection_rules WHERE enabled = true"
      ) do
        {:ok, %{rows: rows}} ->
          Enum.reduce(rows, %{}, fn [category, definition_json], acc ->
            case Jason.decode(definition_json) do
              {:ok, definition} ->
                rule = parse_db_rule(category, definition)
                if rule do
                  cat_key = String.to_existing_atom(category)
                  Map.update(acc, cat_key, [rule], &[rule | &1])
                else
                  acc
                end
              _ -> acc
            end
          end)

        _ -> %{}
      end
    rescue
      _ ->
        Logger.debug("No custom detection rules table found")
        %{}
    end
  end

  defp parse_db_rule(category, definition) do
    try do
      case category do
        "process" ->
          %{
            id: definition["id"],
            pattern: %{process_name: Regex.compile!(definition["pattern"], "i")},
            severity: String.to_existing_atom(definition["severity"] || "medium"),
            risk_score: definition["risk_score"] || 70,
            mitre: definition["mitre"] || [],
            description: definition["description"] || ""
          }

        "command_line" ->
          %{
            id: definition["id"],
            pattern: Regex.compile!(definition["pattern"], "i"),
            severity: String.to_existing_atom(definition["severity"] || "medium"),
            risk_score: definition["risk_score"] || 70,
            mitre: definition["mitre"] || [],
            description: definition["description"] || ""
          }

        "sensitive_path" ->
          %{
            id: definition["id"],
            pattern: Regex.compile!(definition["pattern"], "i"),
            mitre: definition["mitre"] || [],
            description: definition["description"] || ""
          }

        _ -> nil
      end
    rescue
      e ->
        Logger.warning("Failed to parse DB rule: #{inspect(e)}")
        nil
    end
  end

  defp merge_rules(defaults, custom) do
    # Custom rules with the same ID override defaults
    custom_ids = MapSet.new(Enum.map(custom, & &1.id))
    filtered_defaults = Enum.reject(defaults, fn r -> MapSet.member?(custom_ids, r.id) end)
    filtered_defaults ++ custom
  end

  # ============================================================================
  # Z-Score Anomaly Detection (Welford's Online Algorithm)
  # ============================================================================

  # Run z-score analysis on numeric features extracted from the event.
  # Compares each feature's current value against the running mean/stddev
  # stored in the :behavioral_stats ETS table.
  # Phase 2: entity_key is org-scoped {org_id, entity_type, entity_id} and the
  # stats_key includes org_id so two tenants cannot pollute each other's baseline.
  defp run_zscore_analysis({org_id, entity_type, entity_id}, normalized, category, _state) do
    payload = normalized.payload

    features = extract_numeric_features(payload, category)

    features
    |> Enum.flat_map(fn {feature_name, value} ->
      stats_key = {org_id, entity_type, entity_id, feature_name}

      case ets_lookup(@stats_table, stats_key) do
        %OnlineStats{count: n} = stats when n >= @min_observations_for_zscore ->
          z = OnlineStats.z_score(stats, value)
          adaptive_z = get_adaptive_z_threshold(org_id, entity_type, feature_name)

          if abs(z) >= adaptive_z do
            [%BehavioralAnomaly{
              anomaly_type: :zscore_anomaly,
              entity_type: entity_type,
              entity_id: entity_id,
              description: "Statistical anomaly: #{feature_name} z-score=#{Float.round(z, 2)} " <>
                "(mean=#{Float.round(stats.mean, 2)}, stddev=#{Float.round(OnlineStats.stddev(stats), 2)}, " <>
                "observed=#{value}, n=#{n})",
              risk_score: z_score_to_risk(z),
              deviation_score: z,
              baseline_value: "mean=#{Float.round(stats.mean, 2)} stddev=#{Float.round(OnlineStats.stddev(stats), 2)}",
              observed_value: value,
              mitre_techniques: zscore_mitre_techniques(entity_type, feature_name),
              rule_id: "zscore:#{entity_type}:#{feature_name}",
              timestamp: DateTime.utc_now()
            }]
          else
            []
          end

        _ ->
          # Not enough data yet, skip
          []
      end
    end)
  end

  # Extract numeric features from payload depending on event category
  defp extract_numeric_features(payload, :process) do
    features = []
    features = if v = get_field(payload, "memory_usage"), do: [{:memory_usage, to_number(v)} | features], else: features
    features = if v = get_field(payload, "cpu_usage"), do: [{:cpu_usage, to_number(v)} | features], else: features
    features = if v = get_field(payload, "thread_count"), do: [{:thread_count, to_number(v)} | features], else: features
    features = if v = get_field(payload, "handle_count"), do: [{:handle_count, to_number(v)} | features], else: features
    features
  end

  defp extract_numeric_features(payload, :network) do
    features = []
    features = if v = get_field(payload, "bytes_sent"), do: [{:bytes_sent, to_number(v)} | features], else: features
    features = if v = get_field(payload, "bytes_received"), do: [{:bytes_received, to_number(v)} | features], else: features
    features = if v = get_field(payload, "connection_count"), do: [{:connection_count, to_number(v)} | features], else: features
    features
  end

  defp extract_numeric_features(payload, :file) do
    features = []
    features = if v = get_field(payload, "file_size"), do: [{:file_size, to_number(v)} | features], else: features
    features = if v = get_field(payload, "entropy"), do: [{:file_entropy, to_number(v)} | features], else: features
    features
  end

  defp extract_numeric_features(_payload, _category), do: []

  defp to_number(v) when is_integer(v), do: v * 1.0
  defp to_number(v) when is_float(v), do: v
  defp to_number(v) when is_binary(v) do
    case Float.parse(v) do
      {f, _} -> f
      :error -> 0.0
    end
  end
  defp to_number(_), do: 0.0

  # Map z-score magnitude to risk score (0-100)
  defp z_score_to_risk(z) do
    abs_z = abs(z)
    cond do
      abs_z >= 5.0 -> 95
      abs_z >= 4.0 -> 85
      abs_z >= 3.5 -> 75
      abs_z >= 3.0 -> 65
      abs_z >= 2.5 -> 55
      true -> 45
    end
  end

  # Map z-score anomalies to MITRE techniques based on entity type and feature
  defp zscore_mitre_techniques(:user, :login_hour), do: ["T1078"]
  defp zscore_mitre_techniques(:user, :source_ip), do: ["T1078", "T1133"]
  defp zscore_mitre_techniques(:process, :memory_usage), do: ["T1055"]
  defp zscore_mitre_techniques(:process, :cpu_usage), do: ["T1496"]
  defp zscore_mitre_techniques(:host, :connection_count), do: ["T1071"]
  defp zscore_mitre_techniques(:host, :process_count), do: ["T1059"]
  defp zscore_mitre_techniques(_, :bytes_sent), do: ["T1041"]
  defp zscore_mitre_techniques(_, :bytes_received), do: ["T1105"]
  defp zscore_mitre_techniques(_, _), do: ["T1078"]

  # Update ETS online stats for all numeric features in this event.
  # Phase 2: stats_key is org-scoped {org_id, entity_type, entity_id, feature}.
  defp update_ets_stats({org_id, entity_type, entity_id}, normalized, category) do
    payload = normalized.payload
    features = extract_numeric_features(payload, category)

    Enum.each(features, fn {feature_name, value} ->
      stats_key = {org_id, entity_type, entity_id, feature_name}

      current = case :ets.lookup(@stats_table, stats_key) do
        [{^stats_key, stats}] -> stats
        _ -> %OnlineStats{}
      end

      updated = OnlineStats.update(current, value)
      :ets.insert(@stats_table, {stats_key, updated})
    end)
  rescue
    _ -> :ok
  end

  # ============================================================================
  # Temporal Pattern Detection
  # ============================================================================

  # Detect activity at unusual times by comparing against the entity's
  # historical time-of-day x day-of-week matrix.
  # Phase 2: temporal key is org-scoped {org_id, entity_type, entity_id}.
  defp run_temporal_analysis({org_id, entity_type, entity_id}, _normalized) do
    now = DateTime.utc_now()
    hour = now.hour
    day_of_week = Date.day_of_week(DateTime.to_date(now))

    case ets_lookup(@temporal_table, {org_id, entity_type, entity_id}) do
      %TemporalPattern{total: t} = tp when t >= 50 ->
        score = TemporalPattern.anomaly_score(tp, hour, day_of_week)
        is_after_hours = not TemporalPattern.working_hours?(hour, day_of_week)

        cond do
          # High anomaly score and after working hours
          score >= 0.8 and is_after_hours ->
            [%BehavioralAnomaly{
              anomaly_type: :temporal_anomaly,
              entity_type: entity_type,
              entity_id: entity_id,
              description: "After-hours activity at #{format_time(hour, day_of_week)} " <>
                "(anomaly score: #{Float.round(score, 2)}, baseline: #{t} observations)",
              risk_score: 70,
              deviation_score: score * 3.0,
              baseline_value: "temporal pattern (#{t} observations)",
              observed_value: "#{format_time(hour, day_of_week)}",
              mitre_techniques: ["T1078", "T1133"],
              rule_id: "temporal:after_hours",
              timestamp: now
            }]

          # High anomaly score during working hours (still unusual for this entity)
          score >= 0.8 ->
            [%BehavioralAnomaly{
              anomaly_type: :temporal_anomaly,
              entity_type: entity_type,
              entity_id: entity_id,
              description: "Unusual activity time at #{format_time(hour, day_of_week)} " <>
                "(anomaly score: #{Float.round(score, 2)})",
              risk_score: 45,
              deviation_score: score * 2.0,
              baseline_value: "temporal pattern (#{t} observations)",
              observed_value: "#{format_time(hour, day_of_week)}",
              mitre_techniques: ["T1078"],
              rule_id: "temporal:unusual_time",
              timestamp: now
            }]

          true ->
            []
        end

      _ ->
        []
    end
  end

  defp format_time(hour, day_of_week) do
    day_name = case day_of_week do
      1 -> "Mon"; 2 -> "Tue"; 3 -> "Wed"; 4 -> "Thu"
      5 -> "Fri"; 6 -> "Sat"; 7 -> "Sun"; _ -> "?"
    end
    "#{day_name} #{String.pad_leading(to_string(hour), 2, "0")}:00 UTC"
  end

  # Update the temporal pattern matrix in ETS.
  # Phase 2: tp_key is org-scoped {org_id, entity_type, entity_id}.
  defp update_ets_temporal({org_id, entity_type, entity_id}) do
    now = DateTime.utc_now()
    hour = now.hour
    day_of_week = Date.day_of_week(DateTime.to_date(now))
    tp_key = {org_id, entity_type, entity_id}

    current = case :ets.lookup(@temporal_table, tp_key) do
      [{^tp_key, tp}] -> tp
      _ -> %TemporalPattern{}
    end

    updated = TemporalPattern.record(current, hour, day_of_week)
    :ets.insert(@temporal_table, {tp_key, updated})
  rescue
    _ -> :ok
  end

  # ============================================================================
  # Peer Group Analysis
  # ============================================================================

  # Compare an entity's current behavior against its peer group norms.
  # Users are grouped by department/role, processes by type.
  # Phase 2: entity_key carries org_id; peer-group ETS key is {org_id, group_label}
  # so peers in tenant A never compare against peers in tenant B.
  defp run_peer_group_analysis({org_id, entity_type, entity_id}, _normalized, state) do
    group_label = determine_peer_group(org_id, entity_type, entity_id, state)

    if group_label do
      case ets_lookup(@peer_groups_table, {org_id, group_label}) do
        %{mean_events: peer_mean, stddev_events: peer_stddev, member_count: n} when n >= 3 and peer_stddev > 0 ->
          entity_events = get_entity_event_count(org_id, entity_type, entity_id, state)

          if entity_events > 0 do
            z = (entity_events - peer_mean) / peer_stddev

            if abs(z) >= 3.0 do
              direction = if z > 0, do: "above", else: "below"
              [%BehavioralAnomaly{
                anomaly_type: :peer_group_outlier,
                entity_type: entity_type,
                entity_id: entity_id,
                description: "Entity #{entity_id} is #{Float.round(abs(z), 1)} stddev #{direction} " <>
                  "peer group '#{group_label}' norm (entity: #{entity_events}, " <>
                  "peer mean: #{Float.round(peer_mean, 1)}, n=#{n})",
                risk_score: min(90, 50 + round(abs(z) * 10)),
                deviation_score: z,
                baseline_value: "peer group '#{group_label}' mean=#{Float.round(peer_mean, 1)}",
                observed_value: entity_events,
                mitre_techniques: ["T1078"],
                rule_id: "peer_group:#{group_label}",
                timestamp: DateTime.utc_now()
              }]
            else
              []
            end
          else
            []
          end

        _ ->
          []
      end
    else
      []
    end
  end

  # Determine peer group label for an entity.
  # Phase 2: org_id scopes the profile lookup so a user in tenant A's
  # "engineering" department is not grouped with tenant B's "engineering".
  defp determine_peer_group(org_id, :user, user_id, state) do
    org_users = Map.get(state.user_profiles, org_id, %{})
    case Map.get(org_users, user_id) do
      %UserProfile{peer_group: group} when is_binary(group) and group != "" -> group
      %UserProfile{department: dept} when is_binary(dept) and dept != "" -> "dept:#{dept}"
      _ -> "user:default"
    end
  end

  defp determine_peer_group(_org_id, :process, proc_name, _state) do
    type = classify_process_type(proc_name)
    "process_type:#{type}"
  end

  defp determine_peer_group(_org_id, :host, _host_id, _state), do: "host:default"
  defp determine_peer_group(_org_id, _, _, _), do: nil

  defp get_entity_event_count(org_id, :user, user_id, state) do
    org_users = Map.get(state.user_profiles, org_id, %{})
    case Map.get(org_users, user_id) do
      %UserProfile{total_events: n} -> n
      _ -> 0
    end
  end

  defp get_entity_event_count(org_id, :process, proc_name, state) do
    org_processes = Map.get(state.process_profiles, org_id, %{})
    case Map.get(org_processes, String.downcase(proc_name)) do
      %ProcessProfile{total_events: n} -> n
      _ -> 0
    end
  end

  defp get_entity_event_count(_org_id, _, _, _), do: 0

  # Classify a process name into a type category for peer grouping
  defp classify_process_type(name) when is_binary(name) do
    lower = String.downcase(name)
    cond do
      MapSet.member?(@microsoft_signed_processes, lower) -> :system
      lower =~ ~r/^(svc|service|daemon)/ -> :service
      lower =~ ~r/(chrome|firefox|edge|safari|opera|brave)/ -> :browser
      lower =~ ~r/(cmd|powershell|pwsh|bash|sh|zsh)/ -> :shell
      lower =~ ~r/(code|devenv|idea|eclipse|vim|emacs)/ -> :dev_tool
      true -> :user_app
    end
  end

  defp classify_process_type(_), do: :unknown

  # Periodically recalculate peer group norms from current profiles.
  # Phase 2: iterates per-org so a peer group in tenant A is computed only
  # from tenant-A profiles. ETS rows are keyed {org_id, group_label}.
  defp recalculate_peer_groups(state) do
    orgs = enumerate_known_orgs(state)
    total_user_groups = Enum.reduce(orgs, 0, fn org_id, acc ->
      acc + recalculate_user_peer_groups(org_id, state)
    end)

    total_process_groups = Enum.reduce(orgs, 0, fn org_id, acc ->
      acc + recalculate_process_peer_groups(org_id, state)
    end)

    Logger.debug(
      "[Behavioral] Recalculated #{total_user_groups + total_process_groups} peer groups across #{length(orgs)} org(s)"
    )
  rescue
    e -> Logger.warning("[Behavioral] Peer group recalculation failed: #{inspect(e)}")
  end

  # Phase 2 helper: union of org_ids seen across user/process/host profile maps.
  # Returns a list (possibly including `nil` for unscoped legacy data).
  defp enumerate_known_orgs(state) do
    user_orgs = Map.keys(state.user_profiles || %{})
    process_orgs = Map.keys(state.process_profiles || %{})
    host_orgs = Map.keys(state.host_profiles || %{})

    (user_orgs ++ process_orgs ++ host_orgs)
    |> Enum.uniq()
  end

  defp recalculate_user_peer_groups(org_id, state) do
    org_users = Map.get(state.user_profiles, org_id, %{})

    groups =
      org_users
      |> Enum.group_by(fn {user_id, _profile} ->
        determine_peer_group(org_id, :user, user_id, state)
      end)
      |> Enum.reject(fn {group, _} -> is_nil(group) end)

    Enum.each(groups, fn {group_label, members} ->
      event_counts = Enum.map(members, fn {_id, profile} -> profile.total_events * 1.0 end)
      n = length(event_counts)

      if n >= 2 do
        mean_val = Enum.sum(event_counts) / n
        variance = Enum.reduce(event_counts, 0.0, fn x, acc -> acc + (x - mean_val) * (x - mean_val) end) / n
        stddev_val = :math.sqrt(variance)

        :ets.insert(@peer_groups_table, {{org_id, group_label}, %{
          mean_events: mean_val,
          stddev_events: max(stddev_val, 1.0),
          member_count: n,
          updated_at: System.monotonic_time(:second)
        }})
      end
    end)

    length(groups)
  end

  defp recalculate_process_peer_groups(org_id, state) do
    org_processes = Map.get(state.process_profiles, org_id, %{})

    groups =
      org_processes
      |> Enum.group_by(fn {proc_name, _profile} ->
        determine_peer_group(org_id, :process, proc_name, state)
      end)
      |> Enum.reject(fn {group, _} -> is_nil(group) end)

    Enum.each(groups, fn {group_label, members} ->
      event_counts = Enum.map(members, fn {_name, profile} -> profile.total_events * 1.0 end)
      n = length(event_counts)

      if n >= 2 do
        mean_val = Enum.sum(event_counts) / n
        variance = Enum.reduce(event_counts, 0.0, fn x, acc -> acc + (x - mean_val) * (x - mean_val) end) / n
        stddev_val = :math.sqrt(variance)

        :ets.insert(@peer_groups_table, {{org_id, group_label}, %{
          mean_events: mean_val,
          stddev_events: max(stddev_val, 1.0),
          member_count: n,
          updated_at: System.monotonic_time(:second)
        }})
      end
    end)

    length(groups)
  end

  # ============================================================================
  # Adaptive Threshold Learning (Bayesian Updating)
  # ============================================================================

  # Update threshold for a feature based on analyst verdict.
  # Uses Bayesian updating: treat current threshold as prior, update with evidence.
  # - "false_positive" verdict -> raise threshold (fewer alerts)
  # - "true_positive" verdict -> lower threshold (more sensitive)
  # - "benign" -> same as false_positive
  # Phase 2: thresholds are org-scoped; the key carries org_id so one tenant's
  # verdict feedback cannot retune another tenant's sensitivity.
  defp update_adaptive_threshold(org_id, entity_type, feature, verdict) do
    key = {org_id, entity_type, feature}

    {current_z, fp_count, tp_count} = case :ets.lookup(@thresholds_table, key) do
      [{^key, val}] -> val
      _ -> {Config.z_score_threshold(), 0, 0}
    end

    {new_z, new_fp, new_tp} = case to_string(verdict) do
      v when v in ["false_positive", "benign", "fp"] ->
        new_fp = fp_count + 1
        # Bayesian posterior: push threshold up (less sensitive)
        # New threshold = prior * (prior_strength + fp) / (prior_strength + fp + tp)
        posterior = current_z * (@threshold_prior_strength + new_fp) / (@threshold_prior_strength + new_fp + tp_count)
        # Clamp between 2.0 and 5.0
        clamped = max(2.0, min(5.0, posterior))
        {clamped, new_fp, tp_count}

      v when v in ["true_positive", "confirmed", "tp"] ->
        new_tp = tp_count + 1
        # Push threshold down (more sensitive)
        posterior = current_z * (@threshold_prior_strength + fp_count) / (@threshold_prior_strength + fp_count + new_tp)
        clamped = max(2.0, min(5.0, posterior))
        {clamped, fp_count, new_tp}

      _ ->
        {current_z, fp_count, tp_count}
    end

    :ets.insert(@thresholds_table, {key, {new_z, new_fp, new_tp}})
  rescue
    _ -> :ok
  end

  # ============================================================================
  # Risk Score Trending (EWMA)
  # ============================================================================

  # Update the EWMA risk trend for an entity after processing anomalies.
  # Phase 2: trend_key is org-scoped {org_id, entity_type, entity_id}.
  defp update_ets_risk_trend({org_id, entity_type, entity_id}, anomalies) do
    # Current risk score is the max risk from any anomaly, or 0 if no anomalies
    current_risk = case anomalies do
      [] -> 0.0
      list -> Enum.max_by(list, & &1.risk_score).risk_score * 1.0
    end

    trend_key = {org_id, entity_type, entity_id}

    current_trend = case :ets.lookup(@risk_trends_table, trend_key) do
      [{^trend_key, trend}] -> trend
      _ -> %{ewma: 0.0, ticks_above: 0, last_updated: System.monotonic_time(:second)}
    end

    # EWMA: new_ewma = alpha * observation + (1 - alpha) * old_ewma
    new_ewma = @ewma_alpha * current_risk + (1.0 - @ewma_alpha) * current_trend.ewma

    # Track how many consecutive ticks the EWMA has been above the alert threshold
    risk_threshold = Config.risk_score_alert_threshold() * 1.0
    new_ticks = if new_ewma >= risk_threshold do
      current_trend.ticks_above + 1
    else
      0
    end

    updated_trend = %{
      ewma: new_ewma,
      ticks_above: new_ticks,
      last_risk: current_risk,
      last_updated: System.monotonic_time(:second)
    }

    :ets.insert(@risk_trends_table, {trend_key, updated_trend})
  rescue
    _ -> :ok
  end

  # Check all entities with sustained elevated risk trends and create alerts.
  # Phase 2: risk_trends key is {org_id, entity_type, entity_id}. We carry the
  # org_id straight through to the generated alert so cross-tenant attribution
  # is preserved; the `safe_org_lookup/1` fallback only fires for legacy rows
  # that were written without an org context.
  defp check_sustained_risk_trends(_state) do
    try do
      :ets.foldl(fn {key, trend}, acc ->
        {trend_org_id, entity_type, entity_id} = key

        if trend.ticks_above >= @sustained_risk_ticks do
          # Reset ticks to prevent repeated alerts
          :ets.insert(@risk_trends_table, {key, %{trend | ticks_above: 0}})

          # Create a sustained risk alert
          org_id =
            cond do
              not is_nil(trend_org_id) -> trend_org_id
              entity_type == :user -> nil
              true -> safe_org_lookup(entity_id)
            end

          anomaly = %BehavioralAnomaly{
            anomaly_type: :sustained_risk_trend,
            entity_type: entity_type,
            entity_id: entity_id,
            agent_id: if(entity_type == :host, do: entity_id, else: nil),
            organization_id: org_id,
            description: "Sustained elevated risk for #{entity_type}:#{entity_id} " <>
              "(EWMA: #{Float.round(trend.ewma, 1)}, " <>
              "above threshold for #{trend.ticks_above} minutes)",
            risk_score: min(95, round(trend.ewma)),
            deviation_score: trend.ewma / max(Config.risk_score_alert_threshold(), 1),
            baseline_value: "risk threshold: #{Config.risk_score_alert_threshold()}",
            observed_value: "EWMA: #{Float.round(trend.ewma, 1)}",
            mitre_techniques: ["T1078"],
            rule_id: "risk_trend:sustained",
            timestamp: DateTime.utc_now()
          }

          create_anomaly_alert(anomaly)
          acc + 1
        else
          acc
        end
      end, 0, @risk_trends_table)
    rescue
      _ -> :ok
    end
  end

  # ============================================================================
  # ETS Persistence & Cleanup
  # ============================================================================

  # Persist OnlineStats from ETS to database for recovery after restart.
  # Phase 2: stats_key is {org_id, entity_type, entity_id, feature} and
  # thresholds_key is {org_id, entity_type, feature}. We encode the org_id
  # via `scoped_entity_id/2` so the row roundtrips through the existing
  # `behavioral_baselines` schema without a migration (Phase 5 will add a
  # dedicated organization_id column).
  defp persist_ets_stats_to_db do
    try do
      count = :ets.foldl(fn
        {{org_id, entity_type, entity_id, feature}, stats}, acc ->
          scoped = scoped_entity_id(org_id, entity_id)
          key = "#{entity_type}:#{scoped}:#{feature}"
          data = %{
            "organization_id" => org_id,
            "count" => stats.count,
            "mean" => stats.mean,
            "m2" => stats.m2,
            "min_val" => stats.min_val,
            "max_val" => stats.max_val
          }

          upsert_baseline(:online_stats, key, data)
          acc + 1

        _, acc ->
          # Defensive: skip legacy untupled rows if any exist mid-rollout.
          acc
      end, 0, @stats_table)

      # Also persist adaptive thresholds (org-scoped key)
      :ets.foldl(fn
        {{org_id, entity_type, feature}, {threshold_z, fp, tp}}, _acc ->
          scoped = scoped_entity_id(org_id, to_string(feature))
          key = "threshold:#{entity_type}:#{scoped}"
          upsert_baseline(:adaptive_threshold, key, %{
            "organization_id" => org_id,
            "threshold_z" => threshold_z,
            "fp_count" => fp,
            "tp_count" => tp
          })

        _, acc ->
          acc
      end, :ok, @thresholds_table)

      Logger.debug("[Behavioral] Persisted #{count} online stats and thresholds to DB")
    rescue
      e -> Logger.warning("[Behavioral] ETS stats persistence failed: #{inspect(e)}")
    end
  end

  # Clean up stale entries from ETS tables (entities not updated recently)
  defp cleanup_stale_ets_entries do
    cutoff = System.monotonic_time(:second) - 86_400  # 24 hours

    # Clean risk trends older than 24h
    try do
      stale_keys = :ets.foldl(fn {key, trend}, acc ->
        if trend.last_updated < cutoff, do: [key | acc], else: acc
      end, [], @risk_trends_table)

      Enum.each(stale_keys, &:ets.delete(@risk_trends_table, &1))

      if length(stale_keys) > 0 do
        Logger.debug("[Behavioral] Cleaned #{length(stale_keys)} stale risk trend entries")
      end
    rescue
      _ -> :ok
    end

    # Clean online stats / temporal patterns with a separate, generous 7-day TTL
    # so recently-active entities are never evicted. Legacy entries with a nil
    # last_updated (pre-field) are kept until they next update.
    stale_cutoff = System.monotonic_time(:second) - 7 * 86_400  # 7 days

    # Clean online stats older than 7 days
    try do
      stale_keys = :ets.foldl(fn {key, stats}, acc ->
        if stats.last_updated != nil and stats.last_updated < stale_cutoff, do: [key | acc], else: acc
      end, [], @stats_table)

      Enum.each(stale_keys, &:ets.delete(@stats_table, &1))

      if length(stale_keys) > 0 do
        Logger.debug("[Behavioral] Cleaned #{length(stale_keys)} stale online stats entries")
      end
    rescue
      _ -> :ok
    end

    # Clean temporal patterns older than 7 days
    try do
      stale_keys = :ets.foldl(fn {key, pattern}, acc ->
        if pattern.last_updated != nil and pattern.last_updated < stale_cutoff, do: [key | acc], else: acc
      end, [], @temporal_table)

      Enum.each(stale_keys, &:ets.delete(@temporal_table, &1))

      if length(stale_keys) > 0 do
        Logger.debug("[Behavioral] Cleaned #{length(stale_keys)} stale temporal pattern entries")
      end
    rescue
      _ -> :ok
    end
  end

  # ============================================================================
  # Dashboard Stats Publishing
  # ============================================================================

  # Phase 2: profile maps are org-nested %{org_id => %{entity_id => profile}},
  # so we sum the inner map sizes across orgs to keep the dashboard counts
  # consistent with the pre-Phase-2 semantics ("how many distinct entities are
  # being tracked across the deployment").
  defp publish_dashboard_stats(state) do
    stats = %{
      events_processed: state.events_processed,
      anomalies_detected: state.anomalies_detected,
      alerts_created: state.alerts_created,
      user_profiles: sum_nested_profile_count(state.user_profiles),
      process_profiles: sum_nested_profile_count(state.process_profiles),
      host_profiles: sum_nested_profile_count(state.host_profiles),
      tracked_orgs: state.user_profiles |> Map.keys() |> length(),
      ets_stats: dashboard_summary(),
      uptime_seconds: System.monotonic_time(:second) - state.started_at
    }

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "behavioral:stats",
      {:behavioral_stats, stats}
    )
  rescue
    _ -> :ok
  end

  defp sum_nested_profile_count(nested) when is_map(nested) do
    Enum.reduce(nested, 0, fn
      {_org_id, inner}, acc when is_map(inner) -> acc + map_size(inner)
      {_org_id, _}, acc -> acc
    end)
  end
  defp sum_nested_profile_count(_), do: 0

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp get_field(map, key) when is_binary(key) do
    case Map.get(map, key) do
      nil ->
        try do
          Map.get(map, String.to_existing_atom(key))
        rescue
          _ -> nil
        end
      val -> val
    end
  end

  defp safe_sum([]), do: 0
  defp safe_sum(values), do: Enum.sum(values)

  defp parse_port(port) when is_integer(port), do: port
  defp parse_port(port) when is_binary(port) do
    case Integer.parse(port) do
      {p, _} -> p
      :error -> nil
    end
  end
  defp parse_port(port), do: parse_port("#{port}")

  defp safe_org_lookup(nil), do: nil
  defp safe_org_lookup(agent_id) do
    try do
      TamanduaServer.Agents.OrgLookup.get_org_id(agent_id)
    rescue
      _ -> nil
    end
  end

  defp atomize_int_keys(nil), do: %{}
  defp atomize_int_keys(map) when is_map(map) do
    Map.new(map, fn {k, v} ->
      case Integer.parse(to_string(k)) do
        {int, ""} -> {int, v}
        _ -> {k, v}
      end
    end)
  end

  defp parse_datetime(nil), do: nil
  defp parse_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end
  defp parse_datetime(%DateTime{} = dt), do: dt
  defp parse_datetime(_), do: nil

  defp format_bytes(bytes) when is_number(bytes) and bytes >= 1_000_000_000,
    do: "#{Float.round(bytes / 1_000_000_000, 2)} GB"
  defp format_bytes(bytes) when is_number(bytes) and bytes >= 1_000_000,
    do: "#{Float.round(bytes / 1_000_000, 2)} MB"
  defp format_bytes(bytes) when is_number(bytes) and bytes >= 1_000,
    do: "#{Float.round(bytes / 1_000, 2)} KB"
  defp format_bytes(bytes), do: "#{bytes} B"

  # ============================================================================
  # Impossible Travel Detection (GeoIP)
  # ============================================================================

  defp ensure_geoip_cache_table do
    case :ets.whereis(@geoip_cache_table) do
      :undefined ->
        :ets.new(@geoip_cache_table, [:set, :public, :named_table])
      _ ->
        :ok
    end
  end

  defp geoip_lookup(ip) when is_binary(ip) do
    if private_ip?(ip) do
      {:error, :private_ip}
    else
      ensure_geoip_cache_table()

      case :ets.lookup(@geoip_cache_table, ip) do
        [{^ip, result}] ->
          result

        [] ->
          result = fetch_geoip(ip)
          :ets.insert(@geoip_cache_table, {ip, result})
          result
      end
    end
  end

  defp geoip_lookup(_), do: {:error, :invalid_ip}

  defp fetch_geoip(ip) do
    url = @geoip_api_url <> ip

    try do
      case Finch.build(:get, url, []) |> Finch.request(TamanduaServer.Finch, receive_timeout: 5_000) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          case Jason.decode(body) do
            {:ok, %{"status" => "success", "lat" => lat, "lon" => lon, "city" => city, "country" => country}} ->
              {:ok, %{lat: lat, lon: lon, city: city, country: country}}

            {:ok, %{"status" => "fail"}} ->
              {:error, :geoip_lookup_failed}

            _ ->
              {:error, :geoip_parse_error}
          end

        {:ok, %Finch.Response{status: 429}} ->
          Logger.warning("GeoIP rate limit hit for IP: #{ip}")
          {:error, :rate_limited}

        {:error, %Mint.TransportError{reason: reason}} ->
          Logger.warning("GeoIP lookup failed for #{ip}: #{inspect(reason)}")
          {:error, :request_failed}

        {:error, reason} ->
          Logger.warning("GeoIP lookup failed for #{ip}: #{inspect(reason)}")
          {:error, :request_failed}
      end
    rescue
      e ->
        Logger.warning("GeoIP lookup exception for #{ip}: #{inspect(e)}")
        {:error, :exception}
    end
  end

  defp private_ip?(ip) do
    case String.split(ip, ".") do
      ["10" | _] -> true
      ["172", second | _] ->
        case Integer.parse(second) do
          {n, ""} when n >= 16 and n <= 31 -> true
          _ -> false
        end
      ["192", "168" | _] -> true
      ["127" | _] -> true
      ["0" | _] -> true
      _ -> false
    end
  end

  defp haversine_distance(lat1, lon1, lat2, lon2) do
    lat1_rad = lat1 * :math.pi() / 180.0
    lat2_rad = lat2 * :math.pi() / 180.0
    dlat = (lat2 - lat1) * :math.pi() / 180.0
    dlon = (lon2 - lon1) * :math.pi() / 180.0

    a = :math.sin(dlat / 2) * :math.sin(dlat / 2) +
        :math.cos(lat1_rad) * :math.cos(lat2_rad) *
        :math.sin(dlon / 2) * :math.sin(dlon / 2)

    c = 2 * :math.atan2(:math.sqrt(a), :math.sqrt(1 - a))

    @earth_radius_km * c
  end

  # Phase 2: last_login_locations is keyed {org_id, user} so a user that exists
  # in two tenants is tracked independently per tenant.
  defp check_impossible_travel(user, source_ip, org_id, state) when is_binary(user) and is_binary(source_ip) do
    speed_threshold = Config.impossible_travel_speed_kmh()

    case Map.get(state.last_login_locations, {org_id, user}) do
      nil ->
        []

      %{ip: prev_ip} when prev_ip == source_ip ->
        []

      %{ip: prev_ip, lat: prev_lat, lon: prev_lon, timestamp: prev_time} ->
        case geoip_lookup(source_ip) do
          {:ok, %{lat: curr_lat, lon: curr_lon, city: curr_city, country: curr_country}} ->
            distance_km = haversine_distance(prev_lat, prev_lon, curr_lat, curr_lon)
            time_delta_seconds = DateTime.diff(DateTime.utc_now(), prev_time, :second)

            if time_delta_seconds > 60 and distance_km > 50 do
              time_delta_hours = time_delta_seconds / 3600.0
              speed_kmh = distance_km / time_delta_hours

              if speed_kmh > speed_threshold do
                prev_location = case geoip_lookup(prev_ip) do
                  {:ok, %{city: c, country: co}} -> "#{c}, #{co}"
                  _ -> prev_ip
                end

                curr_location = "#{curr_city}, #{curr_country}"

                [%BehavioralAnomaly{
                  anomaly_type: :impossible_travel,
                  entity_type: :user,
                  entity_id: user,
                  description: "Impossible travel detected for user #{user}: " <>
                    "login from #{prev_location} to #{curr_location} " <>
                    "(#{Float.round(distance_km, 1)} km in #{Float.round(time_delta_hours, 2)} hours, " <>
                    "#{Float.round(speed_kmh, 0)} km/h)",
                  risk_score: 90,
                  deviation_score: speed_kmh / speed_threshold,
                  baseline_value: "max #{speed_threshold} km/h",
                  observed_value: "#{Float.round(speed_kmh, 0)} km/h",
                  mitre_techniques: ["T1078"],
                  timestamp: DateTime.utc_now()
                }]
              else
                []
              end
            else
              []
            end

          _ ->
            []
        end
    end
  end

  defp check_impossible_travel(_, _, _, _), do: []

  # Phase 2: last_login_locations is keyed {org_id, user}.
  defp update_last_login_location(state, org_id, user, source_ip) do
    case geoip_lookup(source_ip) do
      {:ok, %{lat: lat, lon: lon}} ->
        location = %{ip: source_ip, lat: lat, lon: lon, timestamp: DateTime.utc_now()}
        %{state | last_login_locations: Map.put(state.last_login_locations, {org_id, user}, location)}

      _ ->
        state
    end
  end

  # ============================================================================
  # Alert Creation
  # ============================================================================

  defp create_anomaly_alert(%BehavioralAnomaly{} = anomaly) do
    alias TamanduaServer.Detection.Correlator

    severity = Config.severity_from_risk(anomaly.risk_score)

    Logger.warning("Behavioral anomaly detected: #{anomaly.description} " <>
      "(risk: #{anomaly.risk_score}, rule: #{anomaly.rule_id || "behavioral"})")

    # Build a synthetic event from the anomaly so Evidence.extract can work
    synthetic_event = %{
      payload: %{
        name: if(anomaly.entity_type == :process, do: anomaly.entity_id, else: nil),
        user: if(anomaly.entity_type == :user, do: anomaly.entity_id, else: nil)
      },
      event_type: anomaly.entity_type,
      agent_id: anomaly.agent_id
    }

    # Build a detection entry for Evidence.extract
    behavioral_detection = %{
      type: :behavioral,
      rule_name: anomaly.rule_id || "Behavioral: #{anomaly.anomaly_type}",
      description: anomaly.description,
      confidence: anomaly.risk_score / 100,
      mitre_techniques: anomaly.mitre_techniques || [],
      mitre_tactics: [],
      matched_pattern: anomaly.observed_value,
      severity: severity
    }

    # Use Evidence.extract for structured evidence
    evidence = Evidence.extract(synthetic_event, [behavioral_detection])

    # Merge anomaly-specific context into the evidence
    evidence = Map.merge(evidence, %{
      anomaly_context: %{
        anomaly_type: anomaly.anomaly_type,
        entity_type: anomaly.entity_type,
        entity_id: anomaly.entity_id,
        observed_value: anomaly.observed_value,
        baseline_value: anomaly.baseline_value,
        risk_score: anomaly.risk_score
      }
    })

    # Build process chain if we have agent_id and a PID in the evidence/entity
    # For process-type anomalies, try to extract PID from the entity_id if it's numeric
    process_chain = build_process_chain_for_anomaly(anomaly)

    # Generate contextual title using Evidence module
    title = Evidence.build_contextual_title(
      synthetic_event,
      [behavioral_detection],
      anomaly.mitre_techniques
    )

    # Append entity context if title is too generic
    title = if anomaly.entity_type == :process && anomaly.entity_id do
      if not String.contains?(title, to_string(anomaly.entity_id)) do
        "#{title} (#{anomaly.entity_id})"
      else
        title
      end
    else
      title
    end

    # Build detection_metadata for investigator context
    detection_metadata = %{
      "rule_name" => anomaly.rule_id || "Behavioral: #{anomaly.anomaly_type}",
      "rule_type" => "behavioral",
      "confidence" => anomaly.risk_score / 100,
      "anomaly_type" => to_string(anomaly.anomaly_type),
      "entity_type" => to_string(anomaly.entity_type),
      "entity_id" => anomaly.entity_id,
      "observed_value" => anomaly.observed_value,
      "event_type" => to_string(anomaly.entity_type)
    }

    # Capture raw anomaly context as raw_event for forensic review
    raw_event = %{
      "anomaly_type" => to_string(anomaly.anomaly_type),
      "entity_type" => to_string(anomaly.entity_type),
      "entity_id" => anomaly.entity_id,
      "observed_value" => anomaly.observed_value,
      "baseline_value" => anomaly.baseline_value,
      "risk_score" => anomaly.risk_score,
      "agent_id" => anomaly.agent_id
    }

    case Alerts.create_alert(%{
      agent_id: anomaly.agent_id,
      organization_id: anomaly.organization_id,
      title: title,
      description: anomaly.description,
      severity: severity,
      source_event_id: anomaly[:source_event_id],
      event_ids: List.wrap(anomaly[:source_event_id]),
      evidence: evidence,
      process_chain: process_chain,
      raw_event: raw_event,
      detection_metadata: detection_metadata,
      mitre_tactics: [],
      mitre_techniques: anomaly.mitre_techniques || [],
      threat_score: anomaly.risk_score / 100
    }) do
      {:ok, _alert} -> :ok
      {:error, reason} ->
        Logger.warning("Failed to create behavioral anomaly alert (#{anomaly.anomaly_type}): #{inspect(reason)}")
    end
  end

  # Build process chain for behavioral anomaly alerts
  # Attempts to extract PID from anomaly context and build storyline
  defp build_process_chain_for_anomaly(%BehavioralAnomaly{agent_id: nil}), do: []
  defp build_process_chain_for_anomaly(%BehavioralAnomaly{} = anomaly) do
    alias TamanduaServer.Detection.Correlator

    # Try to extract PID from the anomaly's observed_value or entity_id
    pid = extract_pid_from_anomaly(anomaly)

    if anomaly.agent_id && pid do
      case Correlator.build_storyline(anomaly.agent_id, pid) do
        {:ok, storyline} -> storyline.process_chain
        _ -> []
      end
    else
      []
    end
  end

  # Extract PID from various anomaly fields
  defp extract_pid_from_anomaly(%BehavioralAnomaly{} = anomaly) do
    cond do
      # If observed_value is a map with :pid
      is_map(anomaly.observed_value) and is_integer(anomaly.observed_value[:pid]) ->
        anomaly.observed_value[:pid]

      # If observed_value is a map with "pid" string key
      is_map(anomaly.observed_value) and is_integer(anomaly.observed_value["pid"]) ->
        anomaly.observed_value["pid"]

      # If entity_id is a numeric PID (for process entities)
      anomaly.entity_type == :process and is_integer(anomaly.entity_id) ->
        anomaly.entity_id

      # Try to parse entity_id as integer if it's a string that looks like a PID
      anomaly.entity_type == :process and is_binary(anomaly.entity_id) ->
        case Integer.parse(anomaly.entity_id) do
          {pid, ""} when pid > 0 -> pid
          _ -> nil
        end

      true ->
        nil
    end
  end

  # Map MITRE techniques to human-readable categories
  defp mitre_technique_to_category(nil), do: "Behavioral Anomaly"
  defp mitre_technique_to_category(technique) do
    case technique do
      "T1003" <> _ -> "Credential Access"
      "T1047" <> _ -> "WMI Execution"
      "T1053" <> _ -> "Scheduled Task Abuse"
      "T1055" <> _ -> "Process Injection"
      "T1059" <> _ -> "Command Execution"
      "T1021" <> _ -> "Lateral Movement"
      "T1078" <> _ -> "Valid Accounts"
      "T1106" <> _ -> "Native API Abuse"
      "T1189" <> _ -> "Drive-by Compromise"
      "T1204" <> _ -> "User Execution"
      "T1218" <> _ -> "Signed Binary Proxy Execution"
      "T1486" <> _ -> "Ransomware"
      "T1041" <> _ -> "Data Exfiltration"
      "T1071" <> _ -> "Command and Control"
      "T1027" <> _ -> "Obfuscation"
      "T1036" <> _ -> "Masquerading"
      "T1105" <> _ -> "File Download"
      "T1140" <> _ -> "Deobfuscation"
      "T1490" <> _ -> "Recovery Inhibition"
      "T1548" <> _ -> "Privilege Escalation"
      "T1562" <> _ -> "Security Tool Tampering"
      "T1564" <> _ -> "Hidden Execution"
      "T1566" <> _ -> "Phishing"
      "T1571" <> _ -> "Non-Standard Port"
      _ -> "Behavioral Anomaly"
    end
  end
end
