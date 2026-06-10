# MITRE ATT&CK Coverage Configuration
# Run with: mix run priv/repo/seeds/mitre_coverage.exs
#
# Defines the detection capabilities mapped to MITRE ATT&CK framework.
# This data is used for the MITRE coverage visualization dashboard.

IO.puts("Seeding MITRE ATT&CK coverage data...")

# Detection capability mapping to MITRE ATT&CK techniques
# This represents what Tamandua EDR can detect

mitre_coverage = %{
  # ============================================================================
  # RECONNAISSANCE (TA0043)
  # ============================================================================
  "TA0043" => %{
    name: "Reconnaissance",
    coverage_percent: 25,
    notes: "Limited visibility into pre-compromise reconnaissance",
    techniques: [
      %{id: "T1595", name: "Active Scanning", coverage: :partial, detection_method: "Network IDS integration"},
      %{id: "T1592", name: "Gather Victim Host Information", coverage: :none, detection_method: nil}
    ]
  },

  # ============================================================================
  # RESOURCE DEVELOPMENT (TA0042)
  # ============================================================================
  "TA0042" => %{
    name: "Resource Development",
    coverage_percent: 15,
    notes: "Requires threat intelligence integration",
    techniques: [
      %{id: "T1583", name: "Acquire Infrastructure", coverage: :partial, detection_method: "Threat intel IOC matching"},
      %{id: "T1587", name: "Develop Capabilities", coverage: :none, detection_method: nil}
    ]
  },

  # ============================================================================
  # INITIAL ACCESS (TA0001)
  # ============================================================================
  "TA0001" => %{
    name: "Initial Access",
    coverage_percent: 75,
    notes: "Strong detection through endpoint and email telemetry",
    techniques: [
      %{
        id: "T1189",
        name: "Drive-by Compromise",
        coverage: :full,
        detection_method: "Browser process anomalies, exploit detection",
        sigma_rules: ["web_exploit_detection", "browser_cve_exploit"],
        data_sources: ["process_creation", "network_connection", "file_creation"]
      },
      %{
        id: "T1190",
        name: "Exploit Public-Facing Application",
        coverage: :partial,
        detection_method: "Web shell detection, exploit signatures",
        sigma_rules: ["webshell_detection", "iis_exploit"],
        data_sources: ["file_creation", "process_creation"]
      },
      %{
        id: "T1133",
        name: "External Remote Services",
        coverage: :full,
        detection_method: "Anomalous VPN/RDP access patterns",
        sigma_rules: ["suspicious_rdp_login", "vpn_anomaly"],
        data_sources: ["authentication_log", "network_connection"]
      },
      %{
        id: "T1566",
        name: "Phishing",
        coverage: :full,
        detection_method: "Email attachment analysis, URL reputation",
        sigma_rules: ["malicious_attachment", "phishing_url"],
        data_sources: ["email", "file_creation", "process_creation"]
      },
      %{
        id: "T1566.001",
        name: "Spearphishing Attachment",
        coverage: :full,
        detection_method: "Macro detection, document exploit detection",
        sigma_rules: ["office_macro_execution", "ole_object_execution"],
        data_sources: ["file_creation", "process_creation"]
      },
      %{
        id: "T1566.002",
        name: "Spearphishing Link",
        coverage: :full,
        detection_method: "URL analysis, browser download monitoring",
        sigma_rules: ["suspicious_url_click", "browser_download"],
        data_sources: ["network_connection", "file_creation"]
      },
      %{
        id: "T1078",
        name: "Valid Accounts",
        coverage: :partial,
        detection_method: "Behavioral analytics, impossible travel",
        sigma_rules: ["anomalous_login", "impossible_travel"],
        data_sources: ["authentication_log"]
      },
      %{
        id: "T1195",
        name: "Supply Chain Compromise",
        coverage: :partial,
        detection_method: "Software integrity verification, behavioral analysis",
        sigma_rules: ["unsigned_software_execution", "supply_chain_indicator"],
        data_sources: ["file_creation", "process_creation"]
      }
    ]
  },

  # ============================================================================
  # EXECUTION (TA0002)
  # ============================================================================
  "TA0002" => %{
    name: "Execution",
    coverage_percent: 90,
    notes: "Excellent coverage through process monitoring",
    techniques: [
      %{
        id: "T1059",
        name: "Command and Scripting Interpreter",
        coverage: :full,
        detection_method: "Command line analysis, script block logging",
        sigma_rules: ["powershell_suspicious", "cmd_suspicious", "script_execution"],
        data_sources: ["process_creation", "script_execution"]
      },
      %{
        id: "T1059.001",
        name: "PowerShell",
        coverage: :full,
        detection_method: "PowerShell logging, AMSI, obfuscation detection",
        sigma_rules: ["powershell_download_cradle", "powershell_encoded", "powershell_bypass"],
        data_sources: ["process_creation", "script_execution", "module_load"]
      },
      %{
        id: "T1059.003",
        name: "Windows Command Shell",
        coverage: :full,
        detection_method: "Command line monitoring, process tree analysis",
        sigma_rules: ["cmd_suspicious_execution"],
        data_sources: ["process_creation"]
      },
      %{
        id: "T1059.004",
        name: "Unix Shell",
        coverage: :full,
        detection_method: "Shell command monitoring, auditd integration",
        sigma_rules: ["linux_suspicious_shell", "reverse_shell_indicator"],
        data_sources: ["process_creation", "command_execution"]
      },
      %{
        id: "T1059.005",
        name: "Visual Basic",
        coverage: :full,
        detection_method: "VBS execution monitoring, wscript/cscript tracking",
        sigma_rules: ["vbs_execution", "wscript_suspicious"],
        data_sources: ["process_creation", "script_execution"]
      },
      %{
        id: "T1059.006",
        name: "Python",
        coverage: :full,
        detection_method: "Python process monitoring",
        sigma_rules: ["python_suspicious_execution"],
        data_sources: ["process_creation"]
      },
      %{
        id: "T1059.007",
        name: "JavaScript",
        coverage: :full,
        detection_method: "JS execution via wscript/node monitoring",
        sigma_rules: ["javascript_execution"],
        data_sources: ["process_creation"]
      },
      %{
        id: "T1203",
        name: "Exploitation for Client Execution",
        coverage: :full,
        detection_method: "Exploit behavior detection, abnormal process spawning",
        sigma_rules: ["office_child_process", "browser_exploit"],
        data_sources: ["process_creation", "file_creation"]
      },
      %{
        id: "T1204",
        name: "User Execution",
        coverage: :full,
        detection_method: "User-initiated suspicious process chains",
        sigma_rules: ["user_execution_suspicious"],
        data_sources: ["process_creation"]
      },
      %{
        id: "T1047",
        name: "Windows Management Instrumentation",
        coverage: :full,
        detection_method: "WMI process creation, subscription monitoring",
        sigma_rules: ["wmi_execution", "wmi_persistence"],
        data_sources: ["process_creation", "wmi_event"]
      },
      %{
        id: "T1053",
        name: "Scheduled Task/Job",
        coverage: :full,
        detection_method: "Scheduled task creation and execution monitoring",
        sigma_rules: ["scheduled_task_creation", "suspicious_schtasks"],
        data_sources: ["process_creation", "scheduled_task"]
      },
      %{
        id: "T1053.005",
        name: "Scheduled Task",
        coverage: :full,
        detection_method: "schtasks.exe monitoring, Task Scheduler events",
        sigma_rules: ["schtasks_persistence"],
        data_sources: ["process_creation", "scheduled_task"]
      },
      %{
        id: "T1106",
        name: "Native API",
        coverage: :partial,
        detection_method: "API hooking, behavioral analysis",
        sigma_rules: ["suspicious_api_call"],
        data_sources: ["api_monitoring"]
      },
      %{
        id: "T1569.002",
        name: "Service Execution",
        coverage: :full,
        detection_method: "Service creation and start monitoring",
        sigma_rules: ["service_creation", "suspicious_service"],
        data_sources: ["service_creation"]
      }
    ]
  },

  # ============================================================================
  # PERSISTENCE (TA0003)
  # ============================================================================
  "TA0003" => %{
    name: "Persistence",
    coverage_percent: 85,
    notes: "Comprehensive registry and startup monitoring",
    techniques: [
      %{
        id: "T1547",
        name: "Boot or Logon Autostart Execution",
        coverage: :full,
        detection_method: "Registry monitoring, startup folder tracking",
        sigma_rules: ["registry_run_keys", "startup_folder_modification"],
        data_sources: ["registry_modification", "file_creation"]
      },
      %{
        id: "T1547.001",
        name: "Registry Run Keys / Startup Folder",
        coverage: :full,
        detection_method: "Registry Run key monitoring",
        sigma_rules: ["registry_run_key_modification"],
        data_sources: ["registry_modification"]
      },
      %{
        id: "T1543",
        name: "Create or Modify System Process",
        coverage: :full,
        detection_method: "Service creation monitoring",
        sigma_rules: ["new_service_installation", "service_modification"],
        data_sources: ["service_creation"]
      },
      %{
        id: "T1543.003",
        name: "Windows Service",
        coverage: :full,
        detection_method: "Service creation from suspicious paths",
        sigma_rules: ["suspicious_service_path"],
        data_sources: ["service_creation"]
      },
      %{
        id: "T1136",
        name: "Create Account",
        coverage: :full,
        detection_method: "Account creation event monitoring",
        sigma_rules: ["account_creation", "admin_account_creation"],
        data_sources: ["user_account_creation"]
      },
      %{
        id: "T1053.005",
        name: "Scheduled Task",
        coverage: :full,
        detection_method: "Task Scheduler persistence detection",
        sigma_rules: ["scheduled_task_persistence"],
        data_sources: ["scheduled_task"]
      },
      %{
        id: "T1546",
        name: "Event Triggered Execution",
        coverage: :full,
        detection_method: "WMI subscription, registry monitoring",
        sigma_rules: ["wmi_subscription", "event_log_persistence"],
        data_sources: ["wmi_event", "registry_modification"]
      },
      %{
        id: "T1574",
        name: "Hijack Execution Flow",
        coverage: :partial,
        detection_method: "DLL monitoring, PATH analysis",
        sigma_rules: ["dll_search_order_hijacking", "dll_sideloading"],
        data_sources: ["module_load", "file_creation"]
      },
      %{
        id: "T1574.001",
        name: "DLL Search Order Hijacking",
        coverage: :partial,
        detection_method: "Suspicious DLL loading patterns",
        sigma_rules: ["dll_hijacking"],
        data_sources: ["module_load"]
      },
      %{
        id: "T1574.002",
        name: "DLL Side-Loading",
        coverage: :partial,
        detection_method: "Unsigned DLL in trusted app directories",
        sigma_rules: ["dll_sideloading"],
        data_sources: ["module_load", "file_creation"]
      }
    ]
  },

  # ============================================================================
  # PRIVILEGE ESCALATION (TA0004)
  # ============================================================================
  "TA0004" => %{
    name: "Privilege Escalation",
    coverage_percent: 80,
    notes: "Strong coverage for common escalation techniques",
    techniques: [
      %{
        id: "T1548",
        name: "Abuse Elevation Control Mechanism",
        coverage: :full,
        detection_method: "UAC bypass detection, sudo abuse",
        sigma_rules: ["uac_bypass", "sudo_abuse"],
        data_sources: ["process_creation"]
      },
      %{
        id: "T1548.002",
        name: "Bypass User Account Control",
        coverage: :full,
        detection_method: "Known UAC bypass technique detection",
        sigma_rules: ["uac_bypass_fodhelper", "uac_bypass_eventvwr"],
        data_sources: ["process_creation", "registry_modification"]
      },
      %{
        id: "T1134",
        name: "Access Token Manipulation",
        coverage: :partial,
        detection_method: "Token theft indicators",
        sigma_rules: ["token_manipulation"],
        data_sources: ["process_access"]
      },
      %{
        id: "T1055",
        name: "Process Injection",
        coverage: :full,
        detection_method: "CreateRemoteThread, process hollowing detection",
        sigma_rules: ["process_injection", "create_remote_thread"],
        data_sources: ["process_access", "process_creation"]
      },
      %{
        id: "T1055.001",
        name: "Dynamic-link Library Injection",
        coverage: :full,
        detection_method: "DLL injection monitoring",
        sigma_rules: ["dll_injection"],
        data_sources: ["process_access", "module_load"]
      },
      %{
        id: "T1055.012",
        name: "Process Hollowing",
        coverage: :full,
        detection_method: "Memory region anomaly detection",
        sigma_rules: ["process_hollowing"],
        data_sources: ["process_creation"]
      },
      %{
        id: "T1068",
        name: "Exploitation for Privilege Escalation",
        coverage: :partial,
        detection_method: "Exploit behavior patterns",
        sigma_rules: ["privilege_escalation_exploit"],
        data_sources: ["process_creation"]
      }
    ]
  },

  # ============================================================================
  # DEFENSE EVASION (TA0005)
  # ============================================================================
  "TA0005" => %{
    name: "Defense Evasion",
    coverage_percent: 75,
    notes: "Good coverage but some advanced techniques require behavioral analysis",
    techniques: [
      %{
        id: "T1140",
        name: "Deobfuscate/Decode Files or Information",
        coverage: :full,
        detection_method: "Certutil, base64 decode monitoring",
        sigma_rules: ["certutil_decode", "base64_decode"],
        data_sources: ["process_creation"]
      },
      %{
        id: "T1070",
        name: "Indicator Removal",
        coverage: :full,
        detection_method: "Log clearing detection, file deletion tracking",
        sigma_rules: ["event_log_clearing", "file_deletion"],
        data_sources: ["process_creation", "file_deletion"]
      },
      %{
        id: "T1070.001",
        name: "Clear Windows Event Logs",
        coverage: :full,
        detection_method: "wevtutil clear, EventLog service stopping",
        sigma_rules: ["event_log_clearing"],
        data_sources: ["process_creation"]
      },
      %{
        id: "T1036",
        name: "Masquerading",
        coverage: :full,
        detection_method: "Process name/path anomalies",
        sigma_rules: ["masquerading_detection", "rename_system_utility"],
        data_sources: ["process_creation", "file_creation"]
      },
      %{
        id: "T1027",
        name: "Obfuscated Files or Information",
        coverage: :partial,
        detection_method: "Packed binary detection, obfuscation indicators",
        sigma_rules: ["obfuscated_command", "packed_binary"],
        data_sources: ["process_creation", "file_creation"]
      },
      %{
        id: "T1218",
        name: "Signed Binary Proxy Execution",
        coverage: :full,
        detection_method: "LOLBAS technique detection",
        sigma_rules: ["lolbas_execution"],
        data_sources: ["process_creation"]
      },
      %{
        id: "T1218.005",
        name: "Mshta",
        coverage: :full,
        detection_method: "Mshta with suspicious parameters",
        sigma_rules: ["mshta_execution"],
        data_sources: ["process_creation"]
      },
      %{
        id: "T1218.010",
        name: "Regsvr32",
        coverage: :full,
        detection_method: "Regsvr32 scriptlet execution (Squiblydoo)",
        sigma_rules: ["regsvr32_scriptlet"],
        data_sources: ["process_creation"]
      },
      %{
        id: "T1218.011",
        name: "Rundll32",
        coverage: :full,
        detection_method: "Suspicious rundll32 patterns",
        sigma_rules: ["rundll32_suspicious"],
        data_sources: ["process_creation"]
      },
      %{
        id: "T1112",
        name: "Modify Registry",
        coverage: :full,
        detection_method: "Registry modification monitoring",
        sigma_rules: ["registry_modification"],
        data_sources: ["registry_modification"]
      },
      %{
        id: "T1562",
        name: "Impair Defenses",
        coverage: :full,
        detection_method: "Security tool disabling detection",
        sigma_rules: ["disable_defender", "tamper_protection"],
        data_sources: ["process_creation", "registry_modification"]
      }
    ]
  },

  # ============================================================================
  # CREDENTIAL ACCESS (TA0006)
  # ============================================================================
  "TA0006" => %{
    name: "Credential Access",
    coverage_percent: 90,
    notes: "Excellent coverage for credential theft techniques",
    techniques: [
      %{
        id: "T1003",
        name: "OS Credential Dumping",
        coverage: :full,
        detection_method: "LSASS access, credential tool detection",
        sigma_rules: ["credential_dumping", "mimikatz_detection"],
        data_sources: ["process_access", "process_creation"]
      },
      %{
        id: "T1003.001",
        name: "LSASS Memory",
        coverage: :full,
        detection_method: "LSASS memory access monitoring",
        sigma_rules: ["lsass_memory_access", "mimikatz"],
        data_sources: ["process_access"]
      },
      %{
        id: "T1003.002",
        name: "Security Account Manager",
        coverage: :full,
        detection_method: "SAM file access monitoring",
        sigma_rules: ["sam_database_access"],
        data_sources: ["file_access"]
      },
      %{
        id: "T1003.003",
        name: "NTDS",
        coverage: :full,
        detection_method: "NTDS.dit access, DCSync detection",
        sigma_rules: ["dcsync", "ntds_extraction"],
        data_sources: ["process_creation", "file_access"]
      },
      %{
        id: "T1110",
        name: "Brute Force",
        coverage: :full,
        detection_method: "Failed authentication monitoring",
        sigma_rules: ["brute_force_detection"],
        data_sources: ["authentication_log"]
      },
      %{
        id: "T1555",
        name: "Credentials from Password Stores",
        coverage: :full,
        detection_method: "Browser credential access, vault access",
        sigma_rules: ["browser_credential_access", "vault_access"],
        data_sources: ["file_access", "process_creation"]
      },
      %{
        id: "T1555.003",
        name: "Credentials from Web Browsers",
        coverage: :full,
        detection_method: "Browser credential file access",
        sigma_rules: ["browser_credential_theft"],
        data_sources: ["file_access"]
      },
      %{
        id: "T1558",
        name: "Steal or Forge Kerberos Tickets",
        coverage: :full,
        detection_method: "Kerberoasting, golden ticket detection",
        sigma_rules: ["kerberoasting", "golden_ticket"],
        data_sources: ["authentication_log"]
      },
      %{
        id: "T1558.003",
        name: "Kerberoasting",
        coverage: :full,
        detection_method: "Service ticket request anomalies",
        sigma_rules: ["kerberoasting_detection"],
        data_sources: ["authentication_log"]
      }
    ]
  },

  # ============================================================================
  # DISCOVERY (TA0007)
  # ============================================================================
  "TA0007" => %{
    name: "Discovery",
    coverage_percent: 70,
    notes: "Detection through command monitoring, may have false positives",
    techniques: [
      %{
        id: "T1087",
        name: "Account Discovery",
        coverage: :full,
        detection_method: "net user, dsquery monitoring",
        sigma_rules: ["account_discovery"],
        data_sources: ["process_creation"]
      },
      %{
        id: "T1083",
        name: "File and Directory Discovery",
        coverage: :partial,
        detection_method: "Bulk file enumeration patterns",
        sigma_rules: ["file_discovery"],
        data_sources: ["process_creation"]
      },
      %{
        id: "T1082",
        name: "System Information Discovery",
        coverage: :full,
        detection_method: "systeminfo, hostname monitoring",
        sigma_rules: ["system_discovery"],
        data_sources: ["process_creation"]
      },
      %{
        id: "T1057",
        name: "Process Discovery",
        coverage: :partial,
        detection_method: "tasklist, ps enumeration",
        sigma_rules: ["process_discovery"],
        data_sources: ["process_creation"]
      },
      %{
        id: "T1018",
        name: "Remote System Discovery",
        coverage: :full,
        detection_method: "Network scanning, ping sweeps",
        sigma_rules: ["network_discovery"],
        data_sources: ["process_creation", "network_connection"]
      },
      %{
        id: "T1046",
        name: "Network Service Discovery",
        coverage: :full,
        detection_method: "Port scanning detection",
        sigma_rules: ["port_scan"],
        data_sources: ["network_connection"]
      }
    ]
  },

  # ============================================================================
  # LATERAL MOVEMENT (TA0008)
  # ============================================================================
  "TA0008" => %{
    name: "Lateral Movement",
    coverage_percent: 85,
    notes: "Strong coverage through network and authentication monitoring",
    techniques: [
      %{
        id: "T1021",
        name: "Remote Services",
        coverage: :full,
        detection_method: "RDP, SSH, WinRM monitoring",
        sigma_rules: ["remote_service_usage"],
        data_sources: ["authentication_log", "network_connection"]
      },
      %{
        id: "T1021.001",
        name: "Remote Desktop Protocol",
        coverage: :full,
        detection_method: "RDP session monitoring",
        sigma_rules: ["rdp_lateral_movement"],
        data_sources: ["authentication_log"]
      },
      %{
        id: "T1021.002",
        name: "SMB/Windows Admin Shares",
        coverage: :full,
        detection_method: "Admin share access, PsExec detection",
        sigma_rules: ["admin_share_access", "psexec_detection"],
        data_sources: ["authentication_log", "network_share"]
      },
      %{
        id: "T1021.004",
        name: "SSH",
        coverage: :full,
        detection_method: "SSH connection monitoring",
        sigma_rules: ["ssh_lateral_movement"],
        data_sources: ["authentication_log"]
      },
      %{
        id: "T1021.006",
        name: "Windows Remote Management",
        coverage: :full,
        detection_method: "WinRM session detection",
        sigma_rules: ["winrm_lateral_movement"],
        data_sources: ["process_creation", "network_connection"]
      },
      %{
        id: "T1570",
        name: "Lateral Tool Transfer",
        coverage: :full,
        detection_method: "File copy to admin shares",
        sigma_rules: ["lateral_tool_transfer"],
        data_sources: ["file_creation", "network_share"]
      },
      %{
        id: "T1210",
        name: "Exploitation of Remote Services",
        coverage: :partial,
        detection_method: "Exploit behavior patterns",
        sigma_rules: ["remote_exploit"],
        data_sources: ["network_connection", "process_creation"]
      }
    ]
  },

  # ============================================================================
  # COLLECTION (TA0009)
  # ============================================================================
  "TA0009" => %{
    name: "Collection",
    coverage_percent: 60,
    notes: "Partial coverage - some techniques require DLP integration",
    techniques: [
      %{
        id: "T1560",
        name: "Archive Collected Data",
        coverage: :full,
        detection_method: "Archive tool execution monitoring",
        sigma_rules: ["archive_creation"],
        data_sources: ["process_creation", "file_creation"]
      },
      %{
        id: "T1005",
        name: "Data from Local System",
        coverage: :partial,
        detection_method: "Bulk file access patterns",
        sigma_rules: ["bulk_file_access"],
        data_sources: ["file_access"]
      },
      %{
        id: "T1074",
        name: "Data Staged",
        coverage: :partial,
        detection_method: "Staging directory patterns",
        sigma_rules: ["data_staging"],
        data_sources: ["file_creation"]
      },
      %{
        id: "T1113",
        name: "Screen Capture",
        coverage: :partial,
        detection_method: "Screenshot tool usage",
        sigma_rules: ["screenshot_capture"],
        data_sources: ["process_creation"]
      },
      %{
        id: "T1056.001",
        name: "Keylogging",
        coverage: :partial,
        detection_method: "Keylogger behavior patterns",
        sigma_rules: ["keylogger_detection"],
        data_sources: ["process_creation", "api_monitoring"]
      }
    ]
  },

  # ============================================================================
  # COMMAND AND CONTROL (TA0011)
  # ============================================================================
  "TA0011" => %{
    name: "Command and Control",
    coverage_percent: 70,
    notes: "Good coverage through network monitoring and DNS analysis",
    techniques: [
      %{
        id: "T1071",
        name: "Application Layer Protocol",
        coverage: :full,
        detection_method: "HTTP/HTTPS anomaly detection",
        sigma_rules: ["suspicious_http_traffic"],
        data_sources: ["network_connection"]
      },
      %{
        id: "T1071.001",
        name: "Web Protocols",
        coverage: :full,
        detection_method: "Beaconing detection, suspicious URLs",
        sigma_rules: ["c2_beaconing", "suspicious_url"],
        data_sources: ["network_connection"]
      },
      %{
        id: "T1071.004",
        name: "DNS",
        coverage: :full,
        detection_method: "DNS tunneling detection, DGA detection",
        sigma_rules: ["dns_tunneling", "dga_detection"],
        data_sources: ["dns_query"]
      },
      %{
        id: "T1105",
        name: "Ingress Tool Transfer",
        coverage: :full,
        detection_method: "Download cradle detection",
        sigma_rules: ["tool_download"],
        data_sources: ["process_creation", "network_connection"]
      },
      %{
        id: "T1571",
        name: "Non-Standard Port",
        coverage: :full,
        detection_method: "Unusual port usage detection",
        sigma_rules: ["unusual_port_connection"],
        data_sources: ["network_connection"]
      },
      %{
        id: "T1572",
        name: "Protocol Tunneling",
        coverage: :partial,
        detection_method: "Tunneling pattern detection",
        sigma_rules: ["protocol_tunneling"],
        data_sources: ["network_connection"]
      },
      %{
        id: "T1219",
        name: "Remote Access Software",
        coverage: :full,
        detection_method: "RAT tool detection",
        sigma_rules: ["rat_detection", "teamviewer_suspicious"],
        data_sources: ["process_creation", "network_connection"]
      }
    ]
  },

  # ============================================================================
  # EXFILTRATION (TA0010)
  # ============================================================================
  "TA0010" => %{
    name: "Exfiltration",
    coverage_percent: 65,
    notes: "Requires DLP and network monitoring integration",
    techniques: [
      %{
        id: "T1041",
        name: "Exfiltration Over C2 Channel",
        coverage: :partial,
        detection_method: "Large data transfers over C2",
        sigma_rules: ["large_c2_transfer"],
        data_sources: ["network_connection"]
      },
      %{
        id: "T1048",
        name: "Exfiltration Over Alternative Protocol",
        coverage: :full,
        detection_method: "DNS exfiltration, ICMP tunneling",
        sigma_rules: ["dns_exfiltration", "icmp_tunneling"],
        data_sources: ["network_connection", "dns_query"]
      },
      %{
        id: "T1567",
        name: "Exfiltration Over Web Service",
        coverage: :partial,
        detection_method: "Cloud storage upload detection",
        sigma_rules: ["cloud_exfiltration"],
        data_sources: ["network_connection"]
      },
      %{
        id: "T1020",
        name: "Automated Exfiltration",
        coverage: :partial,
        detection_method: "Scheduled data transfer patterns",
        sigma_rules: ["automated_exfiltration"],
        data_sources: ["scheduled_task", "network_connection"]
      }
    ]
  },

  # ============================================================================
  # IMPACT (TA0040)
  # ============================================================================
  "TA0040" => %{
    name: "Impact",
    coverage_percent: 85,
    notes: "Strong detection for ransomware and destructive attacks",
    techniques: [
      %{
        id: "T1486",
        name: "Data Encrypted for Impact",
        coverage: :full,
        detection_method: "Mass file encryption detection, ransomware signatures",
        sigma_rules: ["ransomware_file_extension", "mass_encryption"],
        data_sources: ["file_modification", "process_creation"]
      },
      %{
        id: "T1485",
        name: "Data Destruction",
        coverage: :full,
        detection_method: "Mass file deletion, wiper detection",
        sigma_rules: ["mass_file_deletion", "wiper_detection"],
        data_sources: ["file_deletion", "process_creation"]
      },
      %{
        id: "T1490",
        name: "Inhibit System Recovery",
        coverage: :full,
        detection_method: "Volume shadow copy deletion",
        sigma_rules: ["vss_deletion", "bcdedit_recovery"],
        data_sources: ["process_creation"]
      },
      %{
        id: "T1489",
        name: "Service Stop",
        coverage: :full,
        detection_method: "Critical service stopping",
        sigma_rules: ["security_service_stop"],
        data_sources: ["service_modification"]
      },
      %{
        id: "T1496",
        name: "Resource Hijacking",
        coverage: :full,
        detection_method: "Cryptominer detection",
        sigma_rules: ["cryptominer_detection"],
        data_sources: ["process_creation", "network_connection"]
      },
      %{
        id: "T1561",
        name: "Disk Wipe",
        coverage: :full,
        detection_method: "MBR modification, disk wiping tools",
        sigma_rules: ["disk_wipe_detection"],
        data_sources: ["process_creation", "disk_modification"]
      }
    ]
  }
}

# Calculate overall statistics
total_techniques = mitre_coverage
|> Map.values()
|> Enum.flat_map(fn tactic -> Map.get(tactic, :techniques, []) end)
|> length()

full_coverage = mitre_coverage
|> Map.values()
|> Enum.flat_map(fn tactic -> Map.get(tactic, :techniques, []) end)
|> Enum.count(fn t -> t.coverage == :full end)

partial_coverage = mitre_coverage
|> Map.values()
|> Enum.flat_map(fn tactic -> Map.get(tactic, :techniques, []) end)
|> Enum.count(fn t -> t.coverage == :partial end)

# Output summary
IO.puts("\n" <> String.duplicate("=", 71))
IO.puts("MITRE ATT&CK Coverage Summary")
IO.puts("=" <> String.duplicate("=", 70))

IO.puts("\nCoverage by Tactic:")
for {tactic_id, tactic_data} <- Enum.sort(mitre_coverage) do
  technique_count = length(Map.get(tactic_data, :techniques, []))
  IO.puts("  #{tactic_id} #{tactic_data.name}: #{tactic_data.coverage_percent}% (#{technique_count} techniques)")
end

IO.puts("\nOverall Statistics:")
IO.puts("  Total Techniques Mapped: #{total_techniques}")
IO.puts("  Full Coverage: #{full_coverage} (#{Float.round(full_coverage / total_techniques * 100, 1)}%)")
IO.puts("  Partial Coverage: #{partial_coverage} (#{Float.round(partial_coverage / total_techniques * 100, 1)}%)")
IO.puts("  No Coverage: #{total_techniques - full_coverage - partial_coverage}")

# Store in application environment for runtime access
Application.put_env(:tamandua_server, :mitre_coverage, mitre_coverage)

IO.puts("\nMITRE ATT&CK coverage data stored in application environment.")
IO.puts("Access via: Application.get_env(:tamandua_server, :mitre_coverage)")
IO.puts("\nMITRE coverage seeding complete!")
