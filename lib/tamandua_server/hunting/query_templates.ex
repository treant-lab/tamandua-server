defmodule TamanduaServer.Hunting.QueryTemplates do
  @moduledoc """
  Pre-built threat hunting query templates mapped to MITRE ATT&CK framework.
  Provides 30+ ready-to-use queries for common threat scenarios.
  """

  @doc """
  Returns all MITRE-mapped query templates.
  Each template includes:
  - name: Query name
  - description: What it detects
  - query: The actual query
  - category: MITRE tactic
  - mitre_tactics: List of tactics (TA####)
  - mitre_techniques: List of techniques (T####)
  - tags: Searchable tags
  - query_type: hunt/sql
  - is_template: true
  - is_public: true
  """
  def all_templates do
    initial_access_templates() ++
      execution_templates() ++
      persistence_templates() ++
      privilege_escalation_templates() ++
      defense_evasion_templates() ++
      credential_access_templates() ++
      discovery_templates() ++
      lateral_movement_templates() ++
      collection_templates() ++
      command_and_control_templates() ++
      exfiltration_templates() ++
      impact_templates()
  end

  # ============================================================================
  # Initial Access (TA0001)
  # ============================================================================

  def initial_access_templates do
    [
      %{
        name: "Phishing Attachments - Suspicious Downloads",
        query: "event_type:file_create AND file.path:*Downloads* AND (file.extension:exe OR file.extension:dll OR file.extension:js OR file.extension:vbs)",
        category: "Initial Access",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0001"],
        mitre_techniques: ["T1566.001", "T1566.002"],
        tags: ["phishing", "downloads", "initial-access", "email"],
        description: "Detects suspicious executable files downloaded to user directories, often indicating phishing payloads"
      },
      %{
        name: "Drive-by Downloads - Browser Spawning Executables",
        query: "event_type:process_create AND process.parent_name:(chrome.exe OR firefox.exe OR msedge.exe OR iexplore.exe) AND process.name:*.exe AND process.name:!(browser* OR update*)",
        category: "Initial Access",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0001"],
        mitre_techniques: ["T1189"],
        tags: ["drive-by", "browser", "initial-access", "web"],
        description: "Browser spawning executables - potential drive-by compromise or malicious download"
      },
      %{
        name: "Office Macro Execution",
        query: "event_type:process_create AND process.parent_name:(winword.exe OR excel.exe OR powerpnt.exe OR outlook.exe) AND process.name:(powershell.exe OR cmd.exe OR wscript.exe OR cscript.exe OR mshta.exe)",
        category: "Initial Access",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0001"],
        mitre_techniques: ["T1566.001"],
        tags: ["office", "macro", "initial-access", "phishing"],
        description: "Office applications spawning script interpreters - common macro malware indicator"
      },
      %{
        name: "Exploit Public-Facing Application",
        query: "event_type:network_connect AND (process.name:iis* OR process.name:apache* OR process.name:nginx* OR process.name:tomcat*) AND network.remote_port:(4444 OR 8080 OR 1337)",
        category: "Initial Access",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0001"],
        mitre_techniques: ["T1190"],
        tags: ["exploit", "web-server", "initial-access"],
        description: "Web servers making outbound connections to suspicious ports"
      }
    ]
  end

  # ============================================================================
  # Execution (TA0002)
  # ============================================================================

  def execution_templates do
    [
      %{
        name: "PowerShell Encoded Command Execution",
        query: "event_type:process_create AND process.name:powershell.exe AND (process.cmdline:*-enc* OR process.cmdline:*-encodedcommand* OR process.cmdline:*-e *)",
        category: "Execution",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0002"],
        mitre_techniques: ["T1059.001"],
        tags: ["powershell", "encoded", "execution", "obfuscation"],
        description: "Base64 encoded PowerShell commands - common evasion technique"
      },
      %{
        name: "PowerShell Download and Execute",
        query: "event_type:process_create AND process.name:powershell.exe AND (process.cmdline:*downloadstring* OR process.cmdline:*downloadfile* OR process.cmdline:*invoke-webrequest* OR process.cmdline:*iwr *)",
        category: "Execution",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0002"],
        mitre_techniques: ["T1059.001", "T1105"],
        tags: ["powershell", "download", "execution", "c2"],
        description: "PowerShell downloading files from internet - potential malware dropper"
      },
      %{
        name: "Windows Script Host Execution",
        query: "event_type:process_create AND (process.name:wscript.exe OR process.name:cscript.exe) AND process.cmdline:*.js*",
        category: "Execution",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0002"],
        mitre_techniques: ["T1059.007"],
        tags: ["wsh", "javascript", "execution", "script"],
        description: "Windows Script Host executing JavaScript files"
      },
      %{
        name: "MSHTA Execution - LOLBin Abuse",
        query: "event_type:process_create AND process.name:mshta.exe",
        category: "Execution",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0002", "TA0005"],
        mitre_techniques: ["T1218.005"],
        tags: ["mshta", "lolbin", "execution", "defense-evasion"],
        description: "MSHTA.exe execution - often used to execute malicious HTA files"
      },
      %{
        name: "WMI Command Execution",
        query: "event_type:process_create AND process.name:wmic.exe AND process.cmdline:*process*call*create*",
        category: "Execution",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0002"],
        mitre_techniques: ["T1047"],
        tags: ["wmi", "execution", "remote"],
        description: "WMI being used to spawn processes remotely"
      },
      %{
        name: "Regsvr32 Execution - Squiblydoo",
        query: "event_type:process_create AND process.name:regsvr32.exe AND (process.cmdline:*/i:http* OR process.cmdline:*/u *)",
        category: "Execution",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0002", "TA0005"],
        mitre_techniques: ["T1218.010"],
        tags: ["regsvr32", "lolbin", "execution", "squiblydoo"],
        description: "Regsvr32 downloading and executing remote scripts - Squiblydoo technique"
      },
      %{
        name: "Rundll32 Suspicious Execution",
        query: "event_type:process_create AND process.name:rundll32.exe AND process.cmdline:!(printui.dll OR shell32.dll OR setupapi.dll)",
        category: "Execution",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0002", "TA0005"],
        mitre_techniques: ["T1218.011"],
        tags: ["rundll32", "lolbin", "execution"],
        description: "Rundll32 executing unusual DLLs - potential proxy execution"
      },
      %{
        name: "MSBuild Proxy Execution",
        query: "event_type:process_create AND process.name:msbuild.exe AND process.parent_name:!devenv.exe",
        category: "Execution",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0002", "TA0005"],
        mitre_techniques: ["T1127.001"],
        tags: ["msbuild", "lolbin", "execution", "code-execution"],
        description: "MSBuild running outside Visual Studio - potential code execution"
      },
      %{
        name: "Command Shell with Suspicious Arguments",
        query: "event_type:process_create AND process.name:cmd.exe AND (process.cmdline:*/c * OR process.cmdline:*/k *) AND (process.cmdline:*&& * OR process.cmdline:*| *)",
        category: "Execution",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0002"],
        mitre_techniques: ["T1059.003"],
        tags: ["cmd", "shell", "execution", "command"],
        description: "Command prompt with chained commands - potential malicious script"
      }
    ]
  end

  # ============================================================================
  # Persistence (TA0003)
  # ============================================================================

  def persistence_templates do
    [
      %{
        name: "Registry Run Keys Modification",
        query: "event_type:registry_set AND (registry.path:*\\\\CurrentVersion\\\\Run* OR registry.path:*\\\\CurrentVersion\\\\RunOnce*)",
        category: "Persistence",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0003"],
        mitre_techniques: ["T1547.001"],
        tags: ["registry", "persistence", "autorun"],
        description: "Modifications to autorun registry keys for persistence"
      },
      %{
        name: "Scheduled Task Creation",
        query: "event_type:process_create AND process.name:schtasks.exe AND process.cmdline:*/create*",
        category: "Persistence",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0003", "TA0004"],
        mitre_techniques: ["T1053.005"],
        tags: ["scheduled-task", "persistence", "task-scheduler"],
        description: "New scheduled task creation - common persistence mechanism"
      },
      %{
        name: "Service Installation",
        query: "event_type:process_create AND process.name:sc.exe AND process.cmdline:*create*",
        category: "Persistence",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0003", "TA0004"],
        mitre_techniques: ["T1543.003"],
        tags: ["service", "persistence", "windows"],
        description: "Windows service installation via sc.exe"
      },
      %{
        name: "WMI Event Subscription Persistence",
        query: "event_type:process_create AND (process.cmdline:*__EventFilter* OR process.cmdline:*__EventConsumer* OR process.cmdline:*CommandLineEventConsumer*)",
        category: "Persistence",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0003"],
        mitre_techniques: ["T1546.003"],
        tags: ["wmi", "persistence", "event-subscription"],
        description: "WMI event subscriptions used for stealthy persistence"
      },
      %{
        name: "Startup Folder File Drops",
        query: "event_type:file_create AND file.path:*\\\\Start Menu\\\\Programs\\\\Startup\\\\*",
        category: "Persistence",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0003"],
        mitre_techniques: ["T1547.001"],
        tags: ["startup", "persistence", "file"],
        description: "Files dropped into startup folder for automatic execution"
      }
    ]
  end

  # ============================================================================
  # Privilege Escalation (TA0004)
  # ============================================================================

  def privilege_escalation_templates do
    [
      %{
        name: "UAC Bypass Attempts",
        query: "event_type:process_create AND (process.cmdline:*fodhelper* OR process.cmdline:*eventvwr* OR process.cmdline:*sdclt* OR registry.path:*\\\\mscfile\\\\shell\\\\open\\\\command*)",
        category: "Privilege Escalation",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0004", "TA0005"],
        mitre_techniques: ["T1548.002"],
        tags: ["uac-bypass", "privilege-escalation", "fodhelper", "eventvwr"],
        description: "Common UAC bypass techniques (fodhelper, eventvwr, sdclt)"
      },
      %{
        name: "Token Manipulation",
        query: "event_type:process_create AND (process.name:runas.exe OR process.cmdline:*SeDebugPrivilege* OR process.cmdline:*SeImpersonatePrivilege*)",
        category: "Privilege Escalation",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0004"],
        mitre_techniques: ["T1134"],
        tags: ["token", "privilege-escalation", "impersonation"],
        description: "Process token manipulation for privilege escalation"
      },
      %{
        name: "Named Pipe Impersonation",
        query: "event_type:process_create AND process.cmdline:*\\\\\\\\.\\\\pipe\\\\*",
        category: "Privilege Escalation",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0004"],
        mitre_techniques: ["T1134.001"],
        tags: ["named-pipe", "privilege-escalation", "impersonation"],
        description: "Named pipe access for privilege escalation via impersonation"
      }
    ]
  end

  # ============================================================================
  # Defense Evasion (TA0005)
  # ============================================================================

  def defense_evasion_templates do
    [
      %{
        name: "Process Hollowing Detection",
        query: "event_type:process_create AND process.name:svchost.exe AND process.parent_name:!services.exe",
        category: "Defense Evasion",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0005"],
        mitre_techniques: ["T1055.012"],
        tags: ["process-hollowing", "defense-evasion", "injection"],
        description: "Suspicious svchost parent - potential process hollowing"
      },
      %{
        name: "File Timestomping",
        query: "event_type:file_modify AND file.path:*\\\\Windows\\\\System32\\\\* AND file.operation:setinfo",
        category: "Defense Evasion",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0005"],
        mitre_techniques: ["T1070.006"],
        tags: ["timestomping", "defense-evasion", "anti-forensics"],
        description: "File timestamp modifications in system directories"
      },
      %{
        name: "AMSI Bypass Attempts",
        query: "event_type:process_create AND (process.cmdline:*AmsiScanBuffer* OR process.cmdline:*amsi.dll* OR process.cmdline:*AmsiInitFailed*)",
        category: "Defense Evasion",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0005"],
        mitre_techniques: ["T1562.001"],
        tags: ["amsi-bypass", "defense-evasion", "powershell"],
        description: "AMSI (Antimalware Scan Interface) bypass attempts"
      },
      %{
        name: "Disabling Windows Defender",
        query: "event_type:process_create AND (process.cmdline:*Set-MpPreference* OR process.cmdline:*DisableRealtimeMonitoring*) AND process.cmdline:*$true*",
        category: "Defense Evasion",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0005"],
        mitre_techniques: ["T1562.001"],
        tags: ["defender", "defense-evasion", "disable-av"],
        description: "Attempts to disable Windows Defender real-time protection"
      },
      %{
        name: "Event Log Clearing",
        query: "event_type:process_create AND (process.name:wevtutil.exe AND process.cmdline:*cl * OR process.cmdline:*Clear-EventLog*)",
        category: "Defense Evasion",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0005"],
        mitre_techniques: ["T1070.001"],
        tags: ["log-clearing", "defense-evasion", "anti-forensics"],
        description: "Windows event log clearing to hide tracks"
      },
      %{
        name: "Masquerading - System Binary in Wrong Location",
        query: "event_type:process_create AND process.name:(svchost.exe OR lsass.exe OR winlogon.exe OR csrss.exe) AND process.path:!*\\\\Windows\\\\System32\\\\*",
        category: "Defense Evasion",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0005"],
        mitre_techniques: ["T1036.003"],
        tags: ["masquerading", "defense-evasion", "impersonation"],
        description: "System binaries running from non-standard locations"
      }
    ]
  end

  # ============================================================================
  # Credential Access (TA0006)
  # ============================================================================

  def credential_access_templates do
    [
      %{
        name: "LSASS Memory Access",
        query: "event_type:process_access AND target.process.name:lsass.exe",
        category: "Credential Access",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0006"],
        mitre_techniques: ["T1003.001"],
        tags: ["lsass", "credential-dumping", "memory"],
        description: "LSASS memory access for credential dumping (Mimikatz, etc.)"
      },
      %{
        name: "Mimikatz Keywords Detection",
        query: "event_type:process_create AND (process.name:*mimikatz* OR process.cmdline:*sekurlsa* OR process.cmdline:*privilege::debug*)",
        category: "Credential Access",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0006"],
        mitre_techniques: ["T1003.001"],
        tags: ["mimikatz", "credential-dumping", "passwords"],
        description: "Mimikatz credential dumping tool activity patterns"
      },
      %{
        name: "SAM Database Access",
        query: "event_type:file_access AND (file.path:*\\\\SAM OR registry.path:*\\\\SAM\\\\SAM\\\\Domains\\\\Account*)",
        category: "Credential Access",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0006"],
        mitre_techniques: ["T1003.002"],
        tags: ["sam", "credential-dumping", "registry"],
        description: "SAM hive access for local password hash extraction"
      },
      %{
        name: "NTDS.dit Extraction",
        query: "event_type:file_access AND file.path:*\\\\ntds.dit* OR (process.name:ntdsutil.exe AND process.cmdline:*ifm*)",
        category: "Credential Access",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0006"],
        mitre_techniques: ["T1003.003"],
        tags: ["ntds", "credential-dumping", "active-directory"],
        description: "Active Directory database extraction for credential access"
      },
      %{
        name: "Credential Manager Access",
        query: "event_type:file_access AND (file.path:*\\\\Microsoft\\\\Credentials\\\\* OR process.cmdline:*vaultcmd* OR process.cmdline:*Get-Credential*)",
        category: "Credential Access",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0006"],
        mitre_techniques: ["T1555.004"],
        tags: ["credentials", "credential-manager", "vault"],
        description: "Windows Credential Manager vault access"
      },
      %{
        name: "Keylogger Activity",
        query: "event_type:process_create AND (process.cmdline:*Get-Keystrokes* OR process.cmdline:*keylogger*)",
        category: "Credential Access",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0006"],
        mitre_techniques: ["T1056.001"],
        tags: ["keylogger", "credential-access", "input-capture"],
        description: "Keylogging activity for credential capture"
      }
    ]
  end

  # ============================================================================
  # Discovery (TA0007)
  # ============================================================================

  def discovery_templates do
    [
      %{
        name: "System Information Discovery",
        query: "event_type:process_create AND (process.name:systeminfo.exe OR process.name:hostname.exe OR process.name:whoami.exe)",
        category: "Discovery",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0007"],
        mitre_techniques: ["T1082"],
        tags: ["discovery", "enumeration", "system-info"],
        description: "System information gathering commands"
      },
      %{
        name: "Network Configuration Discovery",
        query: "event_type:process_create AND (process.name:ipconfig.exe OR process.name:arp.exe OR process.name:route.exe OR process.name:nslookup.exe)",
        category: "Discovery",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0007"],
        mitre_techniques: ["T1016"],
        tags: ["discovery", "network", "enumeration"],
        description: "Network configuration enumeration"
      },
      %{
        name: "Active Directory Enumeration",
        query: "event_type:process_create AND (process.cmdline:*dsquery* OR process.cmdline:*ldapsearch* OR process.cmdline:*Get-ADUser* OR process.cmdline:*Get-ADComputer*)",
        category: "Discovery",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0007"],
        mitre_techniques: ["T1087.002"],
        tags: ["discovery", "active-directory", "ldap"],
        description: "Active Directory user and computer enumeration"
      },
      %{
        name: "Process and Service Discovery",
        query: "event_type:process_create AND (process.name:tasklist.exe OR process.cmdline:*Get-Process* OR process.name:net.exe AND process.cmdline:*start*)",
        category: "Discovery",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0007"],
        mitre_techniques: ["T1057", "T1007"],
        tags: ["discovery", "process", "service"],
        description: "Process and service enumeration for reconnaissance"
      },
      %{
        name: "Security Software Discovery",
        query: "event_type:process_create AND (process.cmdline:*antivirus* OR process.cmdline:*defender* OR process.cmdline:*firewall* OR process.cmdline:*Get-MpPreference*)",
        category: "Discovery",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0007"],
        mitre_techniques: ["T1518.001"],
        tags: ["discovery", "security-software", "av"],
        description: "Security tool discovery and enumeration"
      }
    ]
  end

  # ============================================================================
  # Lateral Movement (TA0008)
  # ============================================================================

  def lateral_movement_templates do
    [
      %{
        name: "PsExec Lateral Movement",
        query: "event_type:process_create AND (process.name:*psexec* OR process.cmdline:*psexec* OR file.name:psexesvc.exe)",
        category: "Lateral Movement",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0008"],
        mitre_techniques: ["T1021.002"],
        tags: ["psexec", "lateral-movement", "remote-execution"],
        description: "PsExec remote execution for lateral movement"
      },
      %{
        name: "WMI Remote Command Execution",
        query: "event_type:process_create AND process.name:wmic.exe AND process.cmdline:*/node:*",
        category: "Lateral Movement",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0008"],
        mitre_techniques: ["T1047"],
        tags: ["wmi", "lateral-movement", "remote"],
        description: "WMI being used for remote command execution"
      },
      %{
        name: "RDP Connection Activity",
        query: "event_type:network_connect AND (network.remote_port:3389 OR process.name:mstsc.exe)",
        category: "Lateral Movement",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0008"],
        mitre_techniques: ["T1021.001"],
        tags: ["rdp", "lateral-movement", "remote-desktop"],
        description: "Remote Desktop Protocol connection activity"
      },
      %{
        name: "SMB Admin Share Access",
        query: "event_type:network_connect AND network.remote_port:445 AND file.path:*\\\\$\\\\*",
        category: "Lateral Movement",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0008"],
        mitre_techniques: ["T1021.002"],
        tags: ["smb", "lateral-movement", "admin-share"],
        description: "Administrative share access over SMB"
      },
      %{
        name: "WinRM Remote Execution",
        query: "event_type:network_connect AND (network.remote_port:5985 OR network.remote_port:5986) OR process.cmdline:*Enter-PSSession* OR process.cmdline:*Invoke-Command*",
        category: "Lateral Movement",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0008"],
        mitre_techniques: ["T1021.006"],
        tags: ["winrm", "lateral-movement", "powershell-remoting"],
        description: "Windows Remote Management activity"
      }
    ]
  end

  # ============================================================================
  # Collection (TA0009)
  # ============================================================================

  def collection_templates do
    [
      %{
        name: "Archive Tools - Data Staging",
        query: "event_type:process_create AND (process.name:7z.exe OR process.name:rar.exe OR process.name:winrar.exe OR process.cmdline:*Compress-Archive*)",
        category: "Collection",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0009"],
        mitre_techniques: ["T1560.001"],
        tags: ["archive", "collection", "compression"],
        description: "Archive tools used for staging data before exfiltration"
      },
      %{
        name: "Screenshot Capture",
        query: "event_type:process_create AND (process.cmdline:*screenshot* OR process.cmdline:*Get-Screenshot* OR process.cmdline:*[Drawing.Graphics]::FromImage*)",
        category: "Collection",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0009"],
        mitre_techniques: ["T1113"],
        tags: ["screenshot", "collection", "screen-capture"],
        description: "Screen capture activity for data collection"
      },
      %{
        name: "Email Collection",
        query: "event_type:file_access AND (file.path:*.pst OR file.path:*.ost) OR (process.cmdline:*outlook* AND process.cmdline:*export*)",
        category: "Collection",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0009"],
        mitre_techniques: ["T1114.001"],
        tags: ["email", "collection", "outlook"],
        description: "Email file access and potential email harvesting"
      }
    ]
  end

  # ============================================================================
  # Command and Control (TA0011)
  # ============================================================================

  def command_and_control_templates do
    [
      %{
        name: "Suspicious Port Communication",
        query: "event_type:network_connect AND (network.remote_port:4444 OR network.remote_port:8080 OR network.remote_port:1337 OR network.remote_port:31337)",
        category: "Command and Control",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0011"],
        mitre_techniques: ["T1071"],
        tags: ["c2", "network", "suspicious-port"],
        description: "Communication on commonly used C2 ports"
      },
      %{
        name: "DNS Tunneling Detection",
        query: "event_type:dns_query AND dns.query_type:TXT AND dns.query_length:>100",
        category: "Command and Control",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0011"],
        mitre_techniques: ["T1071.004"],
        tags: ["dns-tunneling", "c2", "exfiltration"],
        description: "Unusually long DNS TXT queries - potential DNS tunneling"
      },
      %{
        name: "Long DNS Subdomain Queries",
        query: "event_type:dns_query AND dns.query:*.*.*.*.*.*.*",
        category: "Command and Control",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0011"],
        mitre_techniques: ["T1071.004"],
        tags: ["dns", "c2", "subdomain"],
        description: "Excessively long subdomain queries - C2 or exfiltration"
      },
      %{
        name: "Non-Standard HTTP Ports",
        query: "event_type:network_connect AND (network.remote_port:8443 OR network.remote_port:8888 OR network.remote_port:9000)",
        category: "Command and Control",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0011"],
        mitre_techniques: ["T1071.001"],
        tags: ["http", "c2", "non-standard-port"],
        description: "HTTP traffic on non-standard ports"
      }
    ]
  end

  # ============================================================================
  # Exfiltration (TA0010)
  # ============================================================================

  def exfiltration_templates do
    [
      %{
        name: "Large Data Uploads",
        query: "event_type:network_connect AND network.bytes_sent:>10000000",
        category: "Exfiltration",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0010"],
        mitre_techniques: ["T1041"],
        tags: ["exfiltration", "network", "data-upload"],
        description: "Large outbound data transfers (>10MB)"
      },
      %{
        name: "Cloud Storage Service Access",
        query: "event_type:dns_query AND (dns.query:*dropbox* OR dns.query:*drive.google* OR dns.query:*onedrive* OR dns.query:*box.com* OR dns.query:*mega.nz*)",
        category: "Exfiltration",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0010"],
        mitre_techniques: ["T1567.002"],
        tags: ["exfiltration", "cloud-storage", "saas"],
        description: "Cloud storage service access - potential data exfiltration"
      },
      %{
        name: "FTP Exfiltration",
        query: "event_type:network_connect AND (network.remote_port:21 OR process.name:ftp.exe)",
        category: "Exfiltration",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0010"],
        mitre_techniques: ["T1048.003"],
        tags: ["ftp", "exfiltration", "file-transfer"],
        description: "FTP-based data exfiltration"
      },
      %{
        name: "Removable Media Data Copy",
        query: "event_type:file_create AND (file.path:*removable* OR file.path:E:\\\\* OR file.path:F:\\\\*)",
        category: "Exfiltration",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0010"],
        mitre_techniques: ["T1052.001"],
        tags: ["usb", "exfiltration", "removable-media"],
        description: "Files copied to removable media"
      }
    ]
  end

  # ============================================================================
  # Impact (TA0040)
  # ============================================================================

  def impact_templates do
    [
      %{
        name: "Ransomware File Extensions",
        query: "event_type:file_rename AND (file.new_name:*.encrypted OR file.new_name:*.locked OR file.new_name:*.crypto OR file.new_name:*.crypt OR file.new_name:*.locky)",
        category: "Impact",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0040"],
        mitre_techniques: ["T1486"],
        tags: ["ransomware", "impact", "encryption"],
        description: "Common ransomware file extensions detected"
      },
      %{
        name: "Volume Shadow Copy Deletion",
        query: "event_type:process_create AND (process.cmdline:*vssadmin* AND process.cmdline:*delete* AND process.cmdline:*shadows* OR process.cmdline:*wmic* AND process.cmdline:*shadowcopy* AND process.cmdline:*delete*)",
        category: "Impact",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0040"],
        mitre_techniques: ["T1490"],
        tags: ["ransomware", "impact", "vss", "shadow-copy"],
        description: "Volume Shadow Copy deletion - common ransomware indicator"
      },
      %{
        name: "Service Stop - Impact Phase",
        query: "event_type:process_create AND (process.name:net.exe OR process.name:sc.exe) AND (process.cmdline:*stop* OR process.cmdline:*disable*) AND (process.cmdline:*sql* OR process.cmdline:*backup* OR process.cmdline:*vss*)",
        category: "Impact",
        query_type: "hunt",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0040"],
        mitre_techniques: ["T1489"],
        tags: ["service", "impact", "ransomware"],
        description: "Critical service stopping - potential ransomware preparation"
      },
      %{
        name: "Mass File Modifications",
        query: "SELECT process.name, COUNT(*) as file_count FROM events WHERE event_type = 'file_modify' AND timestamp > NOW() - INTERVAL '5 minutes' GROUP BY process.name HAVING COUNT(*) > 100 ORDER BY file_count DESC",
        category: "Impact",
        query_type: "sql",
        is_template: true,
        visibility: "public",
        mitre_tactics: ["TA0040"],
        mitre_techniques: ["T1486"],
        tags: ["ransomware", "impact", "file-modification"],
        description: "Rapid mass file modifications - ransomware encryption activity"
      }
    ]
  end

  @doc """
  Gets templates by MITRE tactic.
  """
  def get_by_tactic(tactic_id) do
    Enum.filter(all_templates(), fn template ->
      tactic_id in (template[:mitre_tactics] || [])
    end)
  end

  @doc """
  Gets templates by MITRE technique.
  """
  def get_by_technique(technique_id) do
    Enum.filter(all_templates(), fn template ->
      technique_id in (template[:mitre_techniques] || [])
    end)
  end

  @doc """
  Gets templates by category name.
  """
  def get_by_category(category_name) do
    Enum.filter(all_templates(), fn template ->
      template[:category] == category_name
    end)
  end
end
