defmodule TamanduaServer.Detection.Mitre do
  @moduledoc """
  MITRE ATT&CK Framework mapping and enrichment.

  Provides:
  - Comprehensive technique-to-tactic mapping
  - Technique lookup and search
  - Alert enrichment with MITRE context
  - Coverage calculation based on detections
  - Sub-technique support

  Based on MITRE ATT&CK Enterprise Matrix v14
  """

  alias TamanduaServer.Alerts
  alias TamanduaServer.Repo
  import Ecto.Query

  @tactics [
    %{
      id: "TA0043",
      name: "Reconnaissance",
      shortname: "reconnaissance",
      description: "Gathering information to plan future operations"
    },
    %{
      id: "TA0042",
      name: "Resource Development",
      shortname: "resource-development",
      description: "Establishing resources for operations"
    },
    %{
      id: "TA0001",
      name: "Initial Access",
      shortname: "initial-access",
      description: "Techniques to gain initial foothold"
    },
    %{
      id: "TA0002",
      name: "Execution",
      shortname: "execution",
      description: "Techniques to run malicious code"
    },
    %{
      id: "TA0003",
      name: "Persistence",
      shortname: "persistence",
      description: "Techniques to maintain presence"
    },
    %{
      id: "TA0004",
      name: "Privilege Escalation",
      shortname: "privilege-escalation",
      description: "Techniques to gain higher permissions"
    },
    %{
      id: "TA0005",
      name: "Defense Evasion",
      shortname: "defense-evasion",
      description: "Techniques to avoid detection"
    },
    %{
      id: "TA0006",
      name: "Credential Access",
      shortname: "credential-access",
      description: "Techniques to steal credentials"
    },
    %{
      id: "TA0007",
      name: "Discovery",
      shortname: "discovery",
      description: "Techniques to explore the environment"
    },
    %{
      id: "TA0008",
      name: "Lateral Movement",
      shortname: "lateral-movement",
      description: "Techniques to move through the network"
    },
    %{
      id: "TA0009",
      name: "Collection",
      shortname: "collection",
      description: "Techniques to gather target data"
    },
    %{
      id: "TA0011",
      name: "Command and Control",
      shortname: "command-and-control",
      description: "Techniques for C2 communication"
    },
    %{
      id: "TA0010",
      name: "Exfiltration",
      shortname: "exfiltration",
      description: "Techniques to steal data"
    },
    %{
      id: "TA0040",
      name: "Impact",
      shortname: "impact",
      description: "Techniques to disrupt availability or integrity"
    }
  ]

  @tactic_shortnames Enum.map(@tactics, & &1.shortname)
  @tactic_by_id Map.new(@tactics, fn t -> {String.downcase(t.id), t.shortname} end)
  @tactic_by_name Map.new(@tactics, fn t -> {String.downcase(t.name), t.shortname} end)

  @doc """
  Normalizes a single MITRE tactic value into the canonical hyphenated
  shortname.

  Accepts the many forms seen in the wild — `"attack.defense_evasion"`,
  `"Defense Evasion"`, `"defense_evasion"`, `"TA0005"` — and returns
  `"defense-evasion"`. Values that are not recognized ATT&CK tactics
  (e.g. `"stealth"`, `"defense-impairment"`, software IDs like `"s0404"`)
  return `nil` so callers can drop them.
  """
  def normalize_tactic(value) when is_atom(value) and not is_nil(value),
    do: value |> Atom.to_string() |> normalize_tactic()

  def normalize_tactic(value) when is_binary(value) do
    cleaned =
      value
      |> String.trim()
      |> String.downcase()
      |> String.replace_prefix("attack.", "")

    hyphen = String.replace(cleaned, ["_", " "], "-")

    cond do
      cleaned == "" -> nil
      Map.has_key?(@tactic_by_id, cleaned) -> @tactic_by_id[cleaned]
      hyphen in @tactic_shortnames -> hyphen
      Map.has_key?(@tactic_by_name, cleaned) -> @tactic_by_name[cleaned]
      true -> nil
    end
  end

  def normalize_tactic(_), do: nil

  @doc """
  Normalizes and de-duplicates a list of MITRE tactic values, dropping any
  value that is not a recognized ATT&CK tactic.
  """
  def normalize_tactics(values) when is_list(values) do
    values
    |> Enum.map(&normalize_tactic/1)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  def normalize_tactics(_), do: []

  @doc """
  Normalizes a single MITRE technique id into canonical `Txxxx` / `Txxxx.yyy`
  form.

  Accepts the forms seen in the wild — `"attack.t1059.001"`, `"t1059"`,
  `"T1059"` — and returns the upper-cased `"T1059.001"` / `"T1059"`. Values
  that are not technique ids (e.g. `"multiple"`, software ids) return `nil`
  so callers can drop them.
  """
  def normalize_technique(value) when is_atom(value) and not is_nil(value),
    do: value |> Atom.to_string() |> normalize_technique()

  def normalize_technique(value) when is_binary(value) do
    cleaned =
      value
      |> String.trim()
      |> String.upcase()
      |> String.replace_prefix("ATTACK.", "")

    if Regex.match?(~r/^T\d{4}(\.\d{3})?$/, cleaned), do: cleaned, else: nil
  end

  def normalize_technique(_), do: nil

  @doc """
  Normalizes and de-duplicates a list of MITRE technique ids, dropping any
  value that is not a recognized technique id format.
  """
  def normalize_techniques(values) when is_list(values) do
    values
    |> Enum.map(&normalize_technique/1)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  def normalize_techniques(_), do: []

  # Comprehensive technique database with tactics mapping
  # Format: {technique_id, name, [tactics], [platforms], description}
  @techniques [
    # Initial Access
    {"T1189", "Drive-by Compromise", ["initial-access"], ["windows", "linux", "macos"],
     "Adversaries may gain access through a user visiting a compromised website"},
    {"T1190", "Exploit Public-Facing Application", ["initial-access"], ["windows", "linux", "macos"],
     "Adversaries exploit vulnerabilities in internet-facing systems"},
    {"T1133", "External Remote Services", ["persistence", "initial-access"], ["windows", "linux", "macos"],
     "Adversaries use remote services such as VPNs, Citrix, and RDP"},
    {"T1200", "Hardware Additions", ["initial-access"], ["windows", "linux", "macos"],
     "Adversaries introduce malicious hardware devices"},
    {"T1566", "Phishing", ["initial-access"], ["windows", "linux", "macos"],
     "Adversaries send phishing messages to gain access"},
    {"T1566.001", "Spearphishing Attachment", ["initial-access"], ["windows", "linux", "macos"],
     "Phishing with malicious attachments"},
    {"T1566.002", "Spearphishing Link", ["initial-access"], ["windows", "linux", "macos"],
     "Phishing with malicious links"},
    {"T1566.003", "Spearphishing via Service", ["initial-access"], ["windows", "linux", "macos"],
     "Phishing through third-party services"},
    {"T1091", "Replication Through Removable Media", ["lateral-movement", "initial-access"], ["windows"],
     "Adversaries spread via removable media"},
    {"T1195", "Supply Chain Compromise", ["initial-access"], ["windows", "linux", "macos"],
     "Adversaries compromise the supply chain"},
    {"T1199", "Trusted Relationship", ["initial-access"], ["windows", "linux", "macos"],
     "Adversaries exploit trusted third parties"},
    {"T1078", "Valid Accounts", ["defense-evasion", "persistence", "privilege-escalation", "initial-access"],
     ["windows", "linux", "macos"], "Adversaries use legitimate credentials"},

    # Execution
    {"T1059", "Command and Scripting Interpreter", ["execution"], ["windows", "linux", "macos"],
     "Adversaries execute commands via interpreters"},
    {"T1059.001", "PowerShell", ["execution"], ["windows"],
     "Adversaries use PowerShell for execution"},
    {"T1059.003", "Windows Command Shell", ["execution"], ["windows"],
     "Adversaries use cmd.exe for execution"},
    {"T1059.004", "Unix Shell", ["execution"], ["linux", "macos"],
     "Adversaries use Unix shells for execution"},
    {"T1059.005", "Visual Basic", ["execution"], ["windows"],
     "Adversaries use VBScript for execution"},
    {"T1059.006", "Python", ["execution"], ["windows", "linux", "macos"],
     "Adversaries use Python for execution"},
    {"T1059.007", "JavaScript", ["execution"], ["windows", "linux", "macos"],
     "Adversaries use JavaScript for execution"},
    {"T1203", "Exploitation for Client Execution", ["execution"], ["windows", "linux", "macos"],
     "Adversaries exploit client applications"},
    {"T1559", "Inter-Process Communication", ["execution"], ["windows", "linux", "macos"],
     "Adversaries use IPC for execution"},
    {"T1106", "Native API", ["execution"], ["windows", "linux", "macos"],
     "Adversaries use OS native APIs"},
    {"T1053", "Scheduled Task/Job", ["execution", "persistence", "privilege-escalation"], ["windows", "linux", "macos"],
     "Adversaries use task scheduling"},
    {"T1053.005", "Scheduled Task", ["execution", "persistence", "privilege-escalation"], ["windows"],
     "Windows scheduled tasks"},
    {"T1053.003", "Cron", ["execution", "persistence", "privilege-escalation"], ["linux", "macos"],
     "Unix cron jobs"},
    {"T1129", "Shared Modules", ["execution"], ["windows"],
     "Adversaries execute payloads via shared modules"},
    {"T1072", "Software Deployment Tools", ["execution", "lateral-movement"], ["windows", "linux", "macos"],
     "Adversaries use deployment tools like SCCM"},
    {"T1569", "System Services", ["execution"], ["windows", "linux", "macos"],
     "Adversaries abuse system services"},
    {"T1569.002", "Service Execution", ["execution"], ["windows"],
     "Windows service execution"},
    {"T1204", "User Execution", ["execution"], ["windows", "linux", "macos"],
     "Adversaries rely on user interaction"},
    {"T1047", "Windows Management Instrumentation", ["execution"], ["windows"],
     "Adversaries use WMI for execution"},

    # Persistence
    {"T1098", "Account Manipulation", ["persistence", "privilege-escalation"], ["windows", "linux", "macos"],
     "Adversaries modify accounts"},
    {"T1197", "BITS Jobs", ["defense-evasion", "persistence"], ["windows"],
     "Adversaries use BITS for persistence"},
    {"T1547", "Boot or Logon Autostart Execution", ["persistence", "privilege-escalation"], ["windows", "linux", "macos"],
     "Adversaries configure autostart execution"},
    {"T1547.001", "Registry Run Keys / Startup Folder", ["persistence", "privilege-escalation"], ["windows"],
     "Windows registry/startup folder persistence"},
    {"T1547.004", "Winlogon Helper DLL", ["persistence", "privilege-escalation"], ["windows"],
     "Winlogon DLL persistence"},
    {"T1547.009", "Shortcut Modification", ["persistence", "privilege-escalation"], ["windows"],
     "Shortcut modification for persistence"},
    {"T1037", "Boot or Logon Initialization Scripts", ["persistence", "privilege-escalation"], ["windows", "linux", "macos"],
     "Adversaries use logon scripts"},
    {"T1543", "Create or Modify System Process", ["persistence", "privilege-escalation"], ["windows", "linux", "macos"],
     "Adversaries create/modify system processes"},
    {"T1543.003", "Windows Service", ["persistence", "privilege-escalation"], ["windows"],
     "Windows service manipulation"},
    {"T1543.002", "Systemd Service", ["persistence", "privilege-escalation"], ["linux"],
     "Systemd service manipulation"},
    {"T1136", "Create Account", ["persistence"], ["windows", "linux", "macos"],
     "Adversaries create accounts"},
    {"T1546", "Event Triggered Execution", ["persistence", "privilege-escalation"], ["windows", "linux", "macos"],
     "Adversaries use event triggers"},

    # Privilege Escalation
    {"T1548", "Abuse Elevation Control Mechanism", ["privilege-escalation", "defense-evasion"], ["windows", "linux", "macos"],
     "Adversaries bypass elevation controls"},
    {"T1548.002", "Bypass User Account Control", ["privilege-escalation", "defense-evasion"], ["windows"],
     "UAC bypass techniques"},
    {"T1548.001", "Setuid and Setgid", ["privilege-escalation", "defense-evasion"], ["linux", "macos"],
     "Setuid/setgid abuse"},
    {"T1548.003", "Sudo and Sudo Caching", ["privilege-escalation", "defense-evasion"], ["linux", "macos"],
     "Sudo abuse"},
    {"T1134", "Access Token Manipulation", ["defense-evasion", "privilege-escalation"], ["windows"],
     "Adversaries manipulate access tokens"},
    {"T1134.001", "Token Impersonation/Theft", ["defense-evasion", "privilege-escalation"], ["windows"],
     "Token impersonation"},
    {"T1134.002", "Create Process with Token", ["defense-evasion", "privilege-escalation"], ["windows"],
     "Process creation with stolen token"},
    {"T1068", "Exploitation for Privilege Escalation", ["privilege-escalation"], ["windows", "linux", "macos"],
     "Adversaries exploit vulnerabilities to escalate"},
    {"T1055", "Process Injection", ["defense-evasion", "privilege-escalation"], ["windows", "linux", "macos"],
     "Adversaries inject code into processes"},
    {"T1055.001", "Dynamic-link Library Injection", ["defense-evasion", "privilege-escalation"], ["windows"],
     "DLL injection"},
    {"T1055.002", "Portable Executable Injection", ["defense-evasion", "privilege-escalation"], ["windows"],
     "PE injection"},
    {"T1055.003", "Thread Execution Hijacking", ["defense-evasion", "privilege-escalation"], ["windows"],
     "Thread hijacking"},
    {"T1055.004", "Asynchronous Procedure Call", ["defense-evasion", "privilege-escalation"], ["windows"],
     "APC injection"},
    {"T1055.008", "Ptrace System Calls", ["defense-evasion", "privilege-escalation"], ["linux"],
     "Ptrace injection"},
    {"T1055.012", "Process Hollowing", ["defense-evasion", "privilege-escalation"], ["windows"],
     "Process hollowing technique"},

    # Defense Evasion
    {"T1140", "Deobfuscate/Decode Files or Information", ["defense-evasion"], ["windows", "linux", "macos"],
     "Adversaries decode obfuscated content"},
    {"T1480", "Execution Guardrails", ["defense-evasion"], ["windows", "linux", "macos"],
     "Adversaries use guardrails to limit execution"},
    {"T1211", "Exploitation for Defense Evasion", ["defense-evasion"], ["windows", "linux", "macos"],
     "Adversaries exploit vulnerabilities to evade"},
    {"T1222", "File and Directory Permissions Modification", ["defense-evasion"], ["windows", "linux", "macos"],
     "Adversaries modify file permissions"},
    {"T1564", "Hide Artifacts", ["defense-evasion"], ["windows", "linux", "macos"],
     "Adversaries hide various artifacts"},
    {"T1564.001", "Hidden Files and Directories", ["defense-evasion"], ["windows", "linux", "macos"],
     "Hidden files/directories"},
    {"T1574", "Hijack Execution Flow", ["persistence", "privilege-escalation", "defense-evasion"], ["windows", "linux", "macos"],
     "Adversaries hijack execution flow"},
    {"T1574.001", "DLL Search Order Hijacking", ["persistence", "privilege-escalation", "defense-evasion"], ["windows"],
     "DLL search order hijacking"},
    {"T1574.002", "DLL Side-Loading", ["persistence", "privilege-escalation", "defense-evasion"], ["windows"],
     "DLL side-loading"},
    {"T1574.006", "Dynamic Linker Hijacking", ["persistence", "privilege-escalation", "defense-evasion"], ["linux", "macos"],
     "LD_PRELOAD hijacking"},
    {"T1070", "Indicator Removal", ["defense-evasion"], ["windows", "linux", "macos"],
     "Adversaries remove indicators"},
    {"T1070.001", "Clear Windows Event Logs", ["defense-evasion"], ["windows"],
     "Windows event log clearing"},
    {"T1070.004", "File Deletion", ["defense-evasion"], ["windows", "linux", "macos"],
     "Malicious file deletion"},
    {"T1202", "Indirect Command Execution", ["defense-evasion"], ["windows"],
     "Adversaries use indirect execution"},
    {"T1036", "Masquerading", ["defense-evasion"], ["windows", "linux", "macos"],
     "Adversaries disguise malicious artifacts"},
    {"T1036.003", "Rename System Utilities", ["defense-evasion"], ["windows", "linux", "macos"],
     "Renaming system utilities"},
    {"T1036.005", "Match Legitimate Name or Location", ["defense-evasion"], ["windows", "linux", "macos"],
     "Matching legitimate names"},
    {"T1112", "Modify Registry", ["defense-evasion"], ["windows"],
     "Adversaries modify the registry"},
    {"T1027", "Obfuscated Files or Information", ["defense-evasion"], ["windows", "linux", "macos"],
     "Adversaries obfuscate content"},
    {"T1027.002", "Software Packing", ["defense-evasion"], ["windows", "linux", "macos"],
     "Using packers"},
    {"T1218", "System Binary Proxy Execution", ["defense-evasion"], ["windows", "linux", "macos"],
     "Adversaries use system binaries as proxies"},
    {"T1218.001", "Compiled HTML File", ["defense-evasion"], ["windows"],
     "CHM file abuse"},
    {"T1218.003", "CMSTP", ["defense-evasion"], ["windows"],
     "CMSTP abuse"},
    {"T1218.005", "Mshta", ["defense-evasion"], ["windows"],
     "Mshta abuse"},
    {"T1218.010", "Regsvr32", ["defense-evasion"], ["windows"],
     "Regsvr32 abuse"},
    {"T1218.011", "Rundll32", ["defense-evasion"], ["windows"],
     "Rundll32 abuse"},

    # Credential Access
    {"T1110", "Brute Force", ["credential-access"], ["windows", "linux", "macos"],
     "Adversaries use brute force attacks"},
    {"T1555", "Credentials from Password Stores", ["credential-access"], ["windows", "linux", "macos"],
     "Adversaries access password stores"},
    {"T1555.003", "Credentials from Web Browsers", ["credential-access"], ["windows", "linux", "macos"],
     "Browser credential theft"},
    {"T1212", "Exploitation for Credential Access", ["credential-access"], ["windows", "linux", "macos"],
     "Adversaries exploit for credentials"},
    {"T1187", "Forced Authentication", ["credential-access"], ["windows"],
     "Adversaries force authentication"},
    {"T1003", "OS Credential Dumping", ["credential-access"], ["windows", "linux", "macos"],
     "Adversaries dump credentials"},
    {"T1003.001", "LSASS Memory", ["credential-access"], ["windows"],
     "LSASS memory dumping"},
    {"T1003.002", "Security Account Manager", ["credential-access"], ["windows"],
     "SAM database dumping"},
    {"T1003.003", "NTDS", ["credential-access"], ["windows"],
     "AD database dumping"},
    {"T1003.004", "LSA Secrets", ["credential-access"], ["windows"],
     "LSA secrets extraction"},
    {"T1003.005", "Cached Domain Credentials", ["credential-access"], ["windows"],
     "DCC2 hash extraction"},
    {"T1003.007", "Proc Filesystem", ["credential-access"], ["linux"],
     "/proc credential access"},
    {"T1003.008", "/etc/passwd and /etc/shadow", ["credential-access"], ["linux"],
     "Unix password file access"},
    {"T1552", "Unsecured Credentials", ["credential-access"], ["windows", "linux", "macos"],
     "Adversaries search for unsecured credentials"},
    {"T1558", "Steal or Forge Kerberos Tickets", ["credential-access"], ["windows"],
     "Kerberos ticket manipulation"},
    {"T1558.003", "Kerberoasting", ["credential-access"], ["windows"],
     "Service ticket cracking"},

    # Discovery
    {"T1087", "Account Discovery", ["discovery"], ["windows", "linux", "macos"],
     "Adversaries discover accounts"},
    {"T1087.001", "Local Account", ["discovery"], ["windows", "linux", "macos"],
     "Local account enumeration"},
    {"T1087.002", "Domain Account", ["discovery"], ["windows"],
     "Domain account enumeration"},
    {"T1010", "Application Window Discovery", ["discovery"], ["windows", "linux", "macos"],
     "Adversaries discover open windows"},
    {"T1217", "Browser Information Discovery", ["discovery"], ["windows", "linux", "macos"],
     "Adversaries gather browser data"},
    {"T1083", "File and Directory Discovery", ["discovery"], ["windows", "linux", "macos"],
     "Adversaries enumerate files"},
    {"T1135", "Network Share Discovery", ["discovery"], ["windows", "linux", "macos"],
     "Adversaries discover network shares"},
    {"T1040", "Network Sniffing", ["credential-access", "discovery"], ["windows", "linux", "macos"],
     "Adversaries capture network traffic"},
    {"T1201", "Password Policy Discovery", ["discovery"], ["windows", "linux", "macos"],
     "Adversaries discover password policies"},
    {"T1120", "Peripheral Device Discovery", ["discovery"], ["windows", "linux", "macos"],
     "Adversaries discover peripherals"},
    {"T1069", "Permission Groups Discovery", ["discovery"], ["windows", "linux", "macos"],
     "Adversaries discover group permissions"},
    {"T1057", "Process Discovery", ["discovery"], ["windows", "linux", "macos"],
     "Adversaries enumerate processes"},
    {"T1012", "Query Registry", ["discovery"], ["windows"],
     "Adversaries query the registry"},
    {"T1018", "Remote System Discovery", ["discovery"], ["windows", "linux", "macos"],
     "Adversaries discover remote systems"},
    {"T1518", "Software Discovery", ["discovery"], ["windows", "linux", "macos"],
     "Adversaries discover installed software"},
    {"T1082", "System Information Discovery", ["discovery"], ["windows", "linux", "macos"],
     "Adversaries gather system info"},
    {"T1016", "System Network Configuration Discovery", ["discovery"], ["windows", "linux", "macos"],
     "Adversaries discover network config"},
    {"T1049", "System Network Connections Discovery", ["discovery"], ["windows", "linux", "macos"],
     "Adversaries discover connections"},
    {"T1033", "System Owner/User Discovery", ["discovery"], ["windows", "linux", "macos"],
     "Adversaries discover users"},
    {"T1007", "System Service Discovery", ["discovery"], ["windows", "linux", "macos"],
     "Adversaries discover services"},
    {"T1124", "System Time Discovery", ["discovery"], ["windows", "linux", "macos"],
     "Adversaries discover system time"},
    {"T1046", "Network Service Discovery", ["discovery"], ["windows", "linux", "macos"],
     "Adversaries scan for services"},

    # Lateral Movement
    {"T1210", "Exploitation of Remote Services", ["lateral-movement"], ["windows", "linux", "macos"],
     "Adversaries exploit remote services"},
    {"T1534", "Internal Spearphishing", ["lateral-movement"], ["windows", "linux", "macos"],
     "Adversaries phish internally"},
    {"T1570", "Lateral Tool Transfer", ["lateral-movement"], ["windows", "linux", "macos"],
     "Adversaries transfer tools laterally"},
    {"T1021", "Remote Services", ["lateral-movement"], ["windows", "linux", "macos"],
     "Adversaries use remote services"},
    {"T1021.001", "Remote Desktop Protocol", ["lateral-movement"], ["windows"],
     "RDP lateral movement"},
    {"T1021.002", "SMB/Windows Admin Shares", ["lateral-movement"], ["windows"],
     "SMB lateral movement"},
    {"T1021.003", "Distributed Component Object Model", ["lateral-movement"], ["windows"],
     "DCOM lateral movement"},
    {"T1021.004", "SSH", ["lateral-movement"], ["linux", "macos"],
     "SSH lateral movement"},
    {"T1021.006", "Windows Remote Management", ["lateral-movement"], ["windows"],
     "WinRM lateral movement"},
    {"T1080", "Taint Shared Content", ["lateral-movement"], ["windows", "linux", "macos"],
     "Adversaries modify shared content"},

    # Collection
    {"T1560", "Archive Collected Data", ["collection"], ["windows", "linux", "macos"],
     "Adversaries archive data"},
    {"T1123", "Audio Capture", ["collection"], ["windows", "linux", "macos"],
     "Adversaries capture audio"},
    {"T1119", "Automated Collection", ["collection"], ["windows", "linux", "macos"],
     "Adversaries automate collection"},
    {"T1115", "Clipboard Data", ["collection"], ["windows", "linux", "macos"],
     "Adversaries capture clipboard"},
    {"T1530", "Data from Cloud Storage", ["collection"], ["windows", "linux", "macos"],
     "Adversaries access cloud storage"},
    {"T1602", "Data from Configuration Repository", ["collection"], ["windows", "linux", "macos"],
     "Adversaries access configs"},
    {"T1213", "Data from Information Repositories", ["collection"], ["windows", "linux", "macos"],
     "Adversaries access info repos"},
    {"T1005", "Data from Local System", ["collection"], ["windows", "linux", "macos"],
     "Adversaries collect local data"},
    {"T1039", "Data from Network Shared Drive", ["collection"], ["windows", "linux", "macos"],
     "Adversaries collect from shares"},
    {"T1025", "Data from Removable Media", ["collection"], ["windows", "linux", "macos"],
     "Adversaries collect from media"},
    {"T1074", "Data Staged", ["collection"], ["windows", "linux", "macos"],
     "Adversaries stage data"},
    {"T1114", "Email Collection", ["collection"], ["windows", "linux", "macos"],
     "Adversaries collect email"},
    {"T1056", "Input Capture", ["collection", "credential-access"], ["windows", "linux", "macos"],
     "Adversaries capture input"},
    {"T1056.001", "Keylogging", ["collection", "credential-access"], ["windows", "linux", "macos"],
     "Keystroke logging"},
    {"T1113", "Screen Capture", ["collection"], ["windows", "linux", "macos"],
     "Adversaries capture screens"},
    {"T1125", "Video Capture", ["collection"], ["windows", "linux", "macos"],
     "Adversaries capture video"},

    # Command and Control
    {"T1071", "Application Layer Protocol", ["command-and-control"], ["windows", "linux", "macos"],
     "Adversaries use application protocols"},
    {"T1071.001", "Web Protocols", ["command-and-control"], ["windows", "linux", "macos"],
     "HTTP/HTTPS C2"},
    {"T1071.004", "DNS", ["command-and-control"], ["windows", "linux", "macos"],
     "DNS C2"},
    {"T1132", "Data Encoding", ["command-and-control"], ["windows", "linux", "macos"],
     "Adversaries encode C2 data"},
    {"T1001", "Data Obfuscation", ["command-and-control"], ["windows", "linux", "macos"],
     "Adversaries obfuscate C2 data"},
    {"T1568", "Dynamic Resolution", ["command-and-control"], ["windows", "linux", "macos"],
     "Adversaries use dynamic resolution"},
    {"T1573", "Encrypted Channel", ["command-and-control"], ["windows", "linux", "macos"],
     "Adversaries encrypt C2 traffic"},
    {"T1008", "Fallback Channels", ["command-and-control"], ["windows", "linux", "macos"],
     "Adversaries use fallback channels"},
    {"T1105", "Ingress Tool Transfer", ["command-and-control"], ["windows", "linux", "macos"],
     "Adversaries transfer tools in"},
    {"T1104", "Multi-Stage Channels", ["command-and-control"], ["windows", "linux", "macos"],
     "Adversaries use staged C2"},
    {"T1095", "Non-Application Layer Protocol", ["command-and-control"], ["windows", "linux", "macos"],
     "Adversaries use low-level protocols"},
    {"T1571", "Non-Standard Port", ["command-and-control"], ["windows", "linux", "macos"],
     "Adversaries use non-standard ports"},
    {"T1572", "Protocol Tunneling", ["command-and-control"], ["windows", "linux", "macos"],
     "Adversaries tunnel protocols"},
    {"T1090", "Proxy", ["command-and-control"], ["windows", "linux", "macos"],
     "Adversaries use proxies"},
    {"T1219", "Remote Access Software", ["command-and-control"], ["windows", "linux", "macos"],
     "Adversaries use remote access tools"},
    {"T1102", "Web Service", ["command-and-control"], ["windows", "linux", "macos"],
     "Adversaries use web services for C2"},

    # Exfiltration
    {"T1020", "Automated Exfiltration", ["exfiltration"], ["windows", "linux", "macos"],
     "Adversaries automate exfiltration"},
    {"T1030", "Data Transfer Size Limits", ["exfiltration"], ["windows", "linux", "macos"],
     "Adversaries limit transfer sizes"},
    {"T1048", "Exfiltration Over Alternative Protocol", ["exfiltration"], ["windows", "linux", "macos"],
     "Adversaries exfiltrate via alt protocols"},
    {"T1041", "Exfiltration Over C2 Channel", ["exfiltration"], ["windows", "linux", "macos"],
     "Adversaries exfiltrate via C2"},
    {"T1011", "Exfiltration Over Other Network Medium", ["exfiltration"], ["windows", "linux", "macos"],
     "Adversaries exfiltrate via other means"},
    {"T1052", "Exfiltration Over Physical Medium", ["exfiltration"], ["windows", "linux", "macos"],
     "Adversaries exfiltrate via physical media"},
    {"T1567", "Exfiltration Over Web Service", ["exfiltration"], ["windows", "linux", "macos"],
     "Adversaries exfiltrate via web services"},
    {"T1029", "Scheduled Transfer", ["exfiltration"], ["windows", "linux", "macos"],
     "Adversaries schedule transfers"},

    # Impact
    {"T1531", "Account Access Removal", ["impact"], ["windows", "linux", "macos"],
     "Adversaries remove account access"},
    {"T1485", "Data Destruction", ["impact"], ["windows", "linux", "macos"],
     "Adversaries destroy data"},
    {"T1486", "Data Encrypted for Impact", ["impact"], ["windows", "linux", "macos"],
     "Adversaries encrypt data (ransomware)"},
    {"T1565", "Data Manipulation", ["impact"], ["windows", "linux", "macos"],
     "Adversaries manipulate data"},
    {"T1491", "Defacement", ["impact"], ["windows", "linux", "macos"],
     "Adversaries deface systems"},
    {"T1561", "Disk Wipe", ["impact"], ["windows", "linux", "macos"],
     "Adversaries wipe disks"},
    {"T1499", "Endpoint Denial of Service", ["impact"], ["windows", "linux", "macos"],
     "Adversaries cause endpoint DoS"},
    {"T1495", "Firmware Corruption", ["impact"], ["windows", "linux", "macos"],
     "Adversaries corrupt firmware"},
    {"T1490", "Inhibit System Recovery", ["impact"], ["windows", "linux", "macos"],
     "Adversaries inhibit recovery"},
    {"T1498", "Network Denial of Service", ["impact"], ["windows", "linux", "macos"],
     "Adversaries cause network DoS"},
    {"T1496", "Resource Hijacking", ["impact"], ["windows", "linux", "macos"],
     "Adversaries hijack resources (cryptomining)"},
    {"T1489", "Service Stop", ["impact"], ["windows", "linux", "macos"],
     "Adversaries stop services"},
    {"T1529", "System Shutdown/Reboot", ["impact"], ["windows", "linux", "macos"],
     "Adversaries shutdown/reboot systems"}
  ]

  @doc """
  Get all tactics.
  """
  def list_tactics do
    @tactics
  end

  @doc """
  Get all techniques. Tries to load from a JSON config file first,
  falling back to the hardcoded list compiled into the module.
  """
  def list_techniques do
    case load_techniques_from_file() do
      {:ok, techniques} -> techniques
      :error -> @techniques |> Enum.map(&technique_to_map/1)
    end
  end

  @doc """
  Load techniques from a JSON file if it exists.

  The file should be at `priv/mitre_techniques.json` and contain an array
  of objects with keys: id, name, tactics, platforms, description.

  Returns `{:ok, techniques}` on success or `:error` if the file doesn't
  exist or can't be parsed.
  """
  @spec load_techniques_from_file() :: {:ok, [map()]} | :error
  def load_techniques_from_file do
    path = Application.app_dir(:tamandua_server, "priv/mitre_techniques.json")
    load_techniques_from_path(path)
  end

  @doc """
  Load techniques from a specific JSON file path.
  """
  @spec load_techniques_from_path(String.t()) :: {:ok, [map()]} | :error
  def load_techniques_from_path(path) do
    with true <- File.exists?(path),
         {:ok, content} <- File.read(path),
         {:ok, data} <- Jason.decode(content) do
      techniques =
        data
        |> Enum.map(fn entry ->
          %{
            id: entry["id"],
            name: entry["name"],
            tactics: entry["tactics"] || [],
            platforms: entry["platforms"] || [],
            description: entry["description"] || "",
            is_subtechnique: String.contains?(entry["id"] || "", ".")
          }
        end)
        |> Enum.filter(fn t -> t.id != nil and t.name != nil end)

      {:ok, techniques}
    else
      _ -> :error
    end
  end

  @doc """
  Export the hardcoded techniques to JSON format (useful for generating
  the config file that can then be edited externally).
  """
  @spec export_techniques_json() :: String.t()
  def export_techniques_json do
    @techniques
    |> Enum.map(fn {id, name, tactics, platforms, description} ->
      %{id: id, name: name, tactics: tactics, platforms: platforms, description: description}
    end)
    |> Jason.encode!(pretty: true)
  end

  @doc """
  Get the raw hardcoded techniques (always returns the compiled-in list).
  """
  def list_builtin_techniques do
    @techniques |> Enum.map(&technique_to_map/1)
  end

  @doc """
  Get techniques for a specific tactic.
  """
  def get_techniques_for_tactic(tactic_shortname) do
    @techniques
    |> Enum.filter(fn {_, _, tactics, _, _} ->
      tactic_shortname in tactics
    end)
    |> Enum.map(&technique_to_map/1)
  end

  @doc """
  Get technique by ID.
  """
  def get_technique(technique_id) do
    @techniques
    |> Enum.find(fn {id, _, _, _, _} -> id == technique_id end)
    |> case do
      nil -> nil
      technique -> technique_to_map(technique)
    end
  end

  @doc """
  Search techniques by name or ID.
  """
  def search_techniques(query) do
    query_lower = String.downcase(query)

    @techniques
    |> Enum.filter(fn {id, name, _, _, desc} ->
      String.contains?(String.downcase(id), query_lower) ||
        String.contains?(String.downcase(name), query_lower) ||
        String.contains?(String.downcase(desc), query_lower)
    end)
    |> Enum.map(&technique_to_map/1)
  end

  @doc """
  Calculate MITRE ATT&CK coverage based on alerts.

  Returns a map of technique_id => %{count: N, severity: :high/:medium/:low}
  """
  def calculate_coverage(opts \\ []) do
    days = Keyword.get(opts, :days, 30)
    since = DateTime.utc_now() |> DateTime.add(-days * 24 * 60 * 60, :second)

    alerts = Repo.all(
      from a in Alerts.Alert,
        where: a.inserted_at >= ^since,
        select: %{
          mitre_techniques: a.mitre_techniques,
          severity: a.severity
        }
    )

    # Build coverage map
    alerts
    |> Enum.flat_map(fn alert ->
      techniques = alert.mitre_techniques || []
      Enum.map(techniques, fn tech -> {tech, alert.severity} end)
    end)
    |> Enum.group_by(fn {tech, _} -> tech end, fn {_, severity} -> severity end)
    |> Enum.map(fn {technique_id, severities} ->
      max_severity = get_max_severity(severities)
      {technique_id, %{count: length(severities), severity: max_severity}}
    end)
    |> Map.new()
  end

  @doc """
  Enrich an alert with MITRE ATT&CK context.
  """
  def enrich_alert(alert) do
    techniques = alert.mitre_techniques || []

    enriched_techniques =
      Enum.map(techniques, fn tech_id ->
        case get_technique(tech_id) do
          nil -> %{id: tech_id, name: "Unknown", tactics: [], description: "Unknown technique"}
          tech -> tech
        end
      end)

    tactics =
      enriched_techniques
      |> Enum.flat_map(& &1.tactics)
      |> Enum.uniq()
      |> Enum.map(fn tactic_shortname ->
        Enum.find(@tactics, fn t -> t.shortname == tactic_shortname end)
      end)
      |> Enum.reject(&is_nil/1)

    %{
      alert: alert,
      techniques: enriched_techniques,
      tactics: tactics
    }
  end

  @doc """
  Get MITRE ATT&CK matrix coverage summary.
  """
  def get_matrix_coverage(opts \\ []) do
    coverage = calculate_coverage(opts)

    @tactics
    |> Enum.map(fn tactic ->
      techniques = get_techniques_for_tactic(tactic.shortname)
      covered_count = Enum.count(techniques, fn t -> Map.has_key?(coverage, t.id) end)

      %{
        tactic: tactic,
        techniques: techniques,
        covered_count: covered_count,
        total_count: length(techniques),
        coverage_percent: if(length(techniques) > 0, do: Float.round(covered_count / length(techniques) * 100, 1), else: 0.0),
        technique_coverage: Enum.map(techniques, fn t ->
          Map.merge(t, %{detected: Map.get(coverage, t.id)})
        end)
      }
    end)
  end

  @doc """
  Get coverage stats for the MITRE page.
  """
  def get_coverage(opts \\ []) do
    coverage = calculate_coverage(opts)
    total_techniques = length(@techniques)
    covered_count = map_size(coverage)

    %{
      total_techniques: total_techniques,
      covered_count: covered_count,
      coverage_percent: if(total_techniques > 0, do: Float.round(covered_count / total_techniques * 100, 1), else: 0.0),
      by_tactic: get_matrix_coverage(opts)
    }
  end

  @doc """
  Get tactic coverage - counts of alerts per tactic.
  """
  def get_tactic_coverage(opts \\ []) do
    days = Keyword.get(opts, :days, 30)
    since = DateTime.utc_now() |> DateTime.add(-days * 24 * 60 * 60, :second)

    alerts = Repo.all(
      from a in Alerts.Alert,
        where: a.inserted_at >= ^since,
        select: a.mitre_tactics
    )

    alerts
    |> Enum.flat_map(fn tactics -> tactics || [] end)
    |> Enum.frequencies()
    |> Enum.sort_by(fn {_, count} -> -count end)
  end

  @doc """
  Get technique IDs from event detections.
  """
  def extract_techniques_from_event(event) do
    detections = event[:detections] || []

    detections
    |> Enum.flat_map(fn detection ->
      detection[:mitre_techniques] || []
    end)
    |> Enum.uniq()
  end

  @doc """
  Get tactic IDs from event detections.
  """
  def extract_tactics_from_event(event) do
    detections = event[:detections] || []

    detections
    |> Enum.flat_map(fn detection ->
      detection[:mitre_tactics] || []
    end)
    |> Enum.uniq()
  end

  @doc """
  Get navigator layer JSON for visualization tools.
  """
  def export_navigator_layer(opts \\ []) do
    coverage = calculate_coverage(opts)

    techniques =
      coverage
      |> Enum.map(fn {technique_id, data} ->
        score = case data.severity do
          :critical -> 100
          :high -> 75
          :medium -> 50
          :low -> 25
          _ -> 10
        end

        %{
          "techniqueID" => technique_id,
          "score" => score,
          "comment" => "#{data.count} detections"
        }
      end)

    %{
      "name" => "Tamandua EDR Coverage",
      "version" => "4.5",
      "domain" => "enterprise-attack",
      "description" => "MITRE ATT&CK coverage from Tamandua EDR",
      "techniques" => techniques,
      "gradient" => %{
        "colors" => ["#ffffff", "#66b1ff", "#ff6666"],
        "minValue" => 0,
        "maxValue" => 100
      }
    }
  end

  # Private functions

  defp technique_to_map({id, name, tactics, platforms, description}) do
    %{
      id: id,
      name: name,
      tactics: tactics,
      platforms: platforms,
      description: description,
      is_subtechnique: String.contains?(id, ".")
    }
  end

  defp get_max_severity(severities) do
    cond do
      :critical in severities -> :critical
      :high in severities -> :high
      :medium in severities -> :medium
      :low in severities -> :low
      true -> :info
    end
  end
end
