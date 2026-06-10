defmodule TamanduaServer.Hunting.WorkflowLibrary do
  @moduledoc """
  Built-in workflow library with pre-defined threat hunting workflows.

  Provides 10+ pre-built workflows for common threat hunting scenarios:
  1. Lateral Movement Detection
  2. Credential Theft Investigation
  3. Ransomware Indicators
  4. C2 Communication Hunt
  5. Persistence Mechanism Discovery
  6. Data Exfiltration Hunt
  7. Privilege Escalation Hunt
  8. Suspicious PowerShell Hunt
  9. Living-off-the-Land Binaries (LOLBAS)
  10. Shadow IT Detection
  11. Insider Threat Detection
  12. Supply Chain Compromise Hunt
  """

  @doc """
  Get all built-in workflow definitions.
  """
  def all_workflows do
    [
      lateral_movement_workflow(),
      credential_theft_workflow(),
      ransomware_workflow(),
      c2_communication_workflow(),
      persistence_workflow(),
      data_exfiltration_workflow(),
      privilege_escalation_workflow(),
      powershell_abuse_workflow(),
      lolbas_workflow(),
      shadow_it_workflow(),
      insider_threat_workflow(),
      supply_chain_workflow()
    ]
  end

  @doc """
  Get a workflow by category.
  """
  def get_by_category(category) do
    all_workflows()
    |> Enum.find(&(&1.category == category))
  end

  # ============================================================================
  # Workflow Definitions
  # ============================================================================

  defp lateral_movement_workflow do
    %{
      name: "Lateral Movement Detection",
      description: "Hunt for lateral movement attempts using remote administration tools, credential reuse, and network pivoting.",
      category: "lateral_movement",
      metadata: %{
        mitre_techniques: ["T1021", "T1021.001", "T1021.002", "T1021.006"],
        mitre_tactics: ["lateral-movement"],
        difficulty: "medium",
        expected_duration_minutes: 30
      },
      steps: [
        %{
          type: "query",
          name: "Initial Remote Execution Scan",
          description: "Search for remote execution tools like PsExec, WMI, WinRM, and remote PowerShell.",
          query_template: """
          event_type:process_create AND (
            name:(psexec.exe OR wmic.exe OR winrs.exe OR wsmprovhost.exe) OR
            cmdline:(*Invoke-Command* OR *Enter-PSSession*)
          )
          """,
          expected_results: "Remote execution attempts",
          next_actions: %{
            "found" => 1,  # Go to step 1 (next step)
            "not_found" => 5  # Skip to SMB analysis
          }
        },
        %{
          type: "decision",
          name: "Evaluate Remote Execution Legitimacy",
          description: "Determine if remote execution is legitimate admin activity or suspicious.",
          decision_criteria: [
            "Check if source host is a known admin workstation",
            "Verify if user has legitimate remote admin privileges",
            "Check execution timing (business hours vs off-hours)",
            "Review command line for suspicious patterns"
          ],
          next_actions: %{
            "legitimate" => 5,
            "suspicious" => 2
          }
        },
        %{
          type: "collect_evidence",
          name: "Gather Lateral Movement Evidence",
          description: "Collect related events: authentication logs, network connections, process chains.",
          evidence_queries: [
            "parent_process_chain",
            "network_connections_same_timeframe",
            "authentication_events"
          ]
        },
        %{
          type: "query",
          name: "Check for Credential Theft Tools",
          description: "Look for credential dumping tools that may have been used for lateral movement.",
          query_template: """
          event_type:process_create AND (
            name:(mimikatz.exe OR procdump.exe OR pwdump*.exe) OR
            cmdline:(*sekurlsa* OR *lsadump* OR *logonpasswords*)
          ) AND timestamp:[evidence.earliest - 1h TO evidence.latest + 1h]
          """
        },
        %{
          type: "manual_review",
          name: "Analyst Review",
          description: "Review all findings and determine hypothesis status.",
          review_checklist: [
            "Are the remote execution attempts part of a pattern?",
            "Is there evidence of credential theft before lateral movement?",
            "Are multiple hosts affected?",
            "Is this consistent with known threat actor TTPs?"
          ]
        },
        %{
          type: "query",
          name: "SMB Share Access Analysis",
          description: "Analyze admin share access (C$, ADMIN$, IPC$) for lateral movement.",
          query_template: """
          event_type:network_connect AND remote_port:445 AND
          (path:*\\C$* OR path:*\\ADMIN$* OR path:*\\IPC$*)
          """
        },
        %{
          type: "decision",
          name: "Determine Scope",
          description: "Determine if this is isolated incident or widespread lateral movement.",
          decision_criteria: [
            "Number of affected hosts",
            "Timeline spread",
            "Attack pattern consistency"
          ],
          next_actions: %{
            "isolated" => 7,
            "widespread" => 7
          }
        },
        %{
          type: "collect_evidence",
          name: "Final Evidence Collection",
          description: "Collect all IOCs and evidence for reporting.",
          evidence_queries: [
            "all_involved_hosts",
            "all_involved_users",
            "all_tools_used",
            "timeline_of_events"
          ]
        },
        %{
          type: "export_iocs",
          name: "Export IOCs",
          description: "Export discovered IOCs to threat intelligence platform.",
          export_types: ["ip_addresses", "file_hashes", "usernames", "hostnames"]
        }
      ]
    }
  end

  defp credential_theft_workflow do
    %{
      name: "Credential Theft Investigation",
      description: "Investigate credential dumping, hash extraction, and password theft activities.",
      category: "credential_theft",
      metadata: %{
        mitre_techniques: ["T1003", "T1003.001", "T1003.002", "T1003.003"],
        mitre_tactics: ["credential-access"],
        difficulty: "medium",
        expected_duration_minutes: 25
      },
      steps: [
        %{
          type: "query",
          name: "LSASS Access Detection",
          description: "Search for processes accessing LSASS memory.",
          query_template: """
          event_type:process_access AND target_process:lsass.exe
          """,
          expected_results: "Processes accessing LSASS",
          next_actions: %{"found" => 1, "not_found" => 3}
        },
        %{
          type: "collect_evidence",
          name: "Analyze LSASS Access",
          description: "Collect details about the accessing process.",
          evidence_queries: [
            "source_process_details",
            "process_signature_status",
            "process_parent_chain"
          ]
        },
        %{
          type: "decision",
          name: "Legitimate vs Suspicious Access",
          description: "Determine if LSASS access is legitimate (e.g., security software).",
          decision_criteria: [
            "Is process signed by Microsoft or known security vendor?",
            "Is process running from System32?",
            "Does process match known security tools?"
          ],
          next_actions: %{"legitimate" => 9, "suspicious" => 3}
        },
        %{
          type: "query",
          name: "Credential Dumping Tools",
          description: "Search for known credential theft tools.",
          query_template: """
          event_type:process_create AND (
            name:(mimikatz.exe OR procdump*.exe OR pwdump*.exe OR gsecdump.exe OR wce.exe) OR
            cmdline:(*sekurlsa* OR *lsadump* OR *logonpasswords* OR *sam* OR *lsa*)
          )
          """
        },
        %{
          type: "query",
          name: "Registry SAM Access",
          description: "Check for SAM registry hive access.",
          query_template: """
          event_type:(registry_read OR registry_export) AND
          key_path:(*SAM* OR *SECURITY* OR *SYSTEM*)
          """
        },
        %{
          type: "query",
          name: "NTDS.dit Access",
          description: "Look for Active Directory database access attempts.",
          query_template: """
          event_type:file_access AND path:*ntds.dit*
          """
        },
        %{
          type: "collect_evidence",
          name: "Comprehensive Evidence Gathering",
          description: "Gather all credential theft indicators.",
          evidence_queries: [
            "all_credential_tools",
            "privileged_accounts_accessed",
            "files_created_by_attacker"
          ]
        },
        %{
          type: "manual_review",
          name: "Impact Assessment",
          description: "Assess the scope and impact of credential theft.",
          review_checklist: [
            "Which accounts were potentially compromised?",
            "Is Domain Admin credential theft suspected?",
            "Is there evidence of credential reuse?",
            "Should forced password reset be initiated?"
          ]
        },
        %{
          type: "create_alert",
          name: "Generate Alert",
          description: "Create high-severity alert for confirmed credential theft.",
          alert_config: %{
            severity: "critical",
            title: "Credential Theft Detected",
            recommended_actions: [
              "Force password reset for affected accounts",
              "Enable MFA if not already active",
              "Review privileged access logs",
              "Isolate affected hosts"
            ]
          }
        }
      ]
    }
  end

  defp ransomware_workflow do
    %{
      name: "Ransomware Indicators Hunt",
      description: "Hunt for ransomware indicators including encryption activity, shadow copy deletion, and ransom notes.",
      category: "ransomware",
      metadata: %{
        mitre_techniques: ["T1486", "T1490", "T1489"],
        mitre_tactics: ["impact"],
        difficulty: "easy",
        expected_duration_minutes: 20
      },
      steps: [
        %{
          type: "query",
          name: "Shadow Copy Deletion",
          description: "Search for shadow copy deletion attempts.",
          query_template: """
          event_type:process_create AND
          cmdline:(*vssadmin*delete*shadows* OR *wmic*shadowcopy*delete* OR *bcdedit*recoveryenabled*no*)
          """
        },
        %{
          type: "query",
          name: "Mass File Modification",
          description: "Detect mass file encryption activity.",
          query_template: """
          event_type:file_modify AND
          (extension:(.encrypted OR .locked OR .crypt OR .enc OR .crypted OR .kraken) OR
           entropy:>7.5)
          GROUP BY agent_id HAVING COUNT(*) > 50 WITHIN 5m
          """
        },
        %{
          type: "query",
          name: "Ransom Note Detection",
          description: "Look for ransom note files.",
          query_template: """
          event_type:file_create AND
          name:(READ_ME.txt OR DECRYPT.txt OR HOW_TO_DECRYPT.txt OR RECOVERY*.txt OR *RANSOM*.txt)
          """
        },
        %{
          type: "collect_evidence",
          name: "Collect Ransomware Evidence",
          description: "Gather comprehensive ransomware indicators.",
          evidence_queries: [
            "all_encrypted_files",
            "ransom_note_contents",
            "ransomware_process_chain",
            "initial_access_vector"
          ]
        },
        %{
          type: "query",
          name: "Service Termination",
          description: "Check for database/backup service termination.",
          query_template: """
          event_type:service_stop AND
          service_name:(SQL* OR *backup* OR vss OR VSS)
          """
        },
        %{
          type: "decision",
          name: "Ransomware Confirmation",
          description: "Confirm ransomware activity based on indicators.",
          decision_criteria: [
            "Are multiple ransomware indicators present?",
            "Is there evidence of mass encryption?",
            "Has a ransom note been found?"
          ],
          next_actions: %{"confirmed" => 6, "unconfirmed" => 8}
        },
        %{
          type: "notify",
          name: "Critical Alert",
          description: "Send immediate critical alert to SOC and management.",
          notification_config: %{
            priority: "critical",
            channels: ["email", "sms", "slack"],
            recipients: ["soc_team", "management", "incident_response"]
          }
        },
        %{
          type: "collect_evidence",
          name: "Forensic Evidence Collection",
          description: "Preserve forensic evidence before remediation.",
          evidence_queries: [
            "memory_dump",
            "ransomware_binary",
            "ransom_note_sample",
            "encryption_timeline"
          ]
        },
        %{
          type: "create_alert",
          name: "Ransomware Alert",
          description: "Create ransomware incident alert.",
          alert_config: %{
            severity: "critical",
            title: "Active Ransomware Incident",
            recommended_actions: [
              "Isolate all affected hosts immediately",
              "Disable backups to prevent encryption",
              "Identify ransomware variant",
              "Contact law enforcement if required",
              "Assess backup recovery options"
            ]
          }
        }
      ]
    }
  end

  defp c2_communication_workflow do
    %{
      name: "C2 Communication Hunt",
      description: "Hunt for command and control communication patterns including beaconing, suspicious domains, and encrypted channels.",
      category: "c2_communication",
      metadata: %{
        mitre_techniques: ["T1071", "T1071.001", "T1071.004", "T1573"],
        mitre_tactics: ["command-and-control"],
        difficulty: "hard",
        expected_duration_minutes: 40
      },
      steps: [
        %{
          type: "query",
          name: "Beaconing Detection",
          description: "Identify periodic network connections suggesting C2 beaconing.",
          query_template: """
          event_type:network_connect
          GROUP BY remote_ip, agent_id
          HAVING COUNT(*) > 10 AND STD_DEV(time_delta) < 5s WITHIN 1h
          """
        },
        %{
          type: "query",
          name: "Suspicious Domains",
          description: "Search for connections to suspicious or newly registered domains.",
          query_template: """
          event_type:dns_query AND (
            domain_age:<30d OR
            domain:(*-*.* OR *[0-9][0-9][0-9][0-9]*.* OR *.tk OR *.ml OR *.ga)
          )
          """
        },
        %{
          type: "query",
          name: "Non-Standard Ports",
          description: "Check for common protocols on non-standard ports.",
          query_template: """
          event_type:network_connect AND
          (protocol:http AND remote_port:!=80,443 OR
           protocol:dns AND remote_port:!=53)
          """
        },
        %{
          type: "collect_evidence",
          name: "Network Behavior Analysis",
          description: "Analyze network patterns for C2 characteristics.",
          evidence_queries: [
            "connection_frequency",
            "data_transfer_patterns",
            "jitter_analysis",
            "connection_duration"
          ]
        },
        %{
          type: "query",
          name: "Encoded Payloads",
          description: "Look for base64 or other encoding in network traffic.",
          query_template: """
          event_type:(network_connect OR dns_query) AND
          payload:(*==* OR contains_base64:true OR entropy:>6.0)
          """
        },
        %{
          type: "decision",
          name: "C2 Classification",
          description: "Classify the type of C2 communication detected.",
          decision_criteria: [
            "Beaconing pattern present?",
            "Domain reputation score",
            "Encryption/encoding detected?",
            "Known C2 framework signatures?"
          ],
          next_actions: %{
            "http_c2" => 6,
            "dns_c2" => 6,
            "encrypted_c2" => 6,
            "false_positive" => 9
          }
        },
        %{
          type: "query",
          name: "Process Analysis",
          description: "Identify the process making C2 connections.",
          query_template: """
          event_type:network_connect AND remote_ip:[c2_ips]
          JOIN event_type:process_create ON pid
          """
        },
        %{
          type: "collect_evidence",
          name: "Malware Extraction",
          description: "Extract and analyze the malware binary.",
          evidence_queries: [
            "binary_hash",
            "binary_path",
            "process_memory_dump",
            "network_pcap"
          ]
        },
        %{
          type: "export_iocs",
          name: "Export C2 IOCs",
          description: "Export C2 indicators to threat intel platform.",
          export_types: ["ip_addresses", "domains", "urls", "file_hashes"]
        },
        %{
          type: "create_alert",
          name: "C2 Communication Alert",
          description: "Create alert for C2 detection.",
          alert_config: %{
            severity: "high",
            title: "C2 Communication Detected"
          }
        }
      ]
    }
  end

  defp persistence_workflow do
    %{
      name: "Persistence Mechanism Discovery",
      description: "Hunt for persistence mechanisms including registry run keys, scheduled tasks, services, and startup items.",
      category: "persistence",
      metadata: %{
        mitre_techniques: ["T1547", "T1053", "T1543"],
        mitre_tactics: ["persistence"],
        difficulty: "medium",
        expected_duration_minutes: 30
      },
      steps: [
        %{
          type: "query",
          name: "Registry Run Keys",
          description: "Search for registry run key modifications.",
          query_template: """
          event_type:(registry_create OR registry_modify) AND
          key_path:(*\\Run* OR *\\RunOnce* OR *\\RunServices* OR *Winlogon*)
          """
        },
        %{
          type: "query",
          name: "Scheduled Tasks",
          description: "Detect suspicious scheduled task creation.",
          query_template: """
          event_type:process_create AND
          (name:schtasks.exe OR cmdline:*Register-ScheduledTask*) AND
          cmdline:(/Create OR -Create)
          """
        },
        %{
          type: "query",
          name: "Service Creation",
          description: "Look for new service installations.",
          query_template: """
          event_type:(service_create OR service_modify) OR
          (event_type:process_create AND name:sc.exe AND cmdline:*create*)
          """
        },
        %{
          type: "query",
          name: "Startup Folder",
          description: "Check for files added to startup folders.",
          query_template: """
          event_type:file_create AND
          path:(*\\Start Menu\\Programs\\Startup* OR *\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu*)
          """
        },
        %{
          type: "query",
          name: "WMI Event Subscriptions",
          description: "Detect WMI persistence mechanisms.",
          query_template: """
          event_type:wmi_event AND
          (operation:(__EventFilter OR __EventConsumer OR __FilterToConsumerBinding))
          """
        },
        %{
          type: "collect_evidence",
          name: "Persistence Analysis",
          description: "Analyze discovered persistence mechanisms.",
          evidence_queries: [
            "persistence_value_data",
            "file_hashes",
            "creation_timestamps",
            "responsible_process"
          ]
        },
        %{
          type: "manual_review",
          name: "Legitimacy Review",
          description: "Review persistence mechanisms for legitimacy.",
          review_checklist: [
            "Is the persistence mechanism from a known software?",
            "Is the binary signed?",
            "Is the creation time suspicious?",
            "Is the mechanism commonly abused by malware?"
          ]
        },
        %{
          type: "decision",
          name: "Persistence Classification",
          description: "Classify persistence as legitimate or malicious.",
          decision_criteria: [
            "Binary signature status",
            "Known good software",
            "Threat intelligence match"
          ],
          next_actions: %{"malicious" => 8, "legitimate" => 9}
        },
        %{
          type: "create_alert",
          name: "Suspicious Persistence Alert",
          description: "Create alert for malicious persistence.",
          alert_config: %{
            severity: "high",
            title: "Malicious Persistence Mechanism Detected",
            recommended_actions: [
              "Remove persistence mechanism",
              "Analyze dropped binaries",
              "Check for additional compromise indicators"
            ]
          }
        }
      ]
    }
  end

  defp data_exfiltration_workflow do
    %{
      name: "Data Exfiltration Hunt",
      description: "Hunt for data exfiltration via network transfers, cloud uploads, removable media, and DNS tunneling.",
      category: "data_exfiltration",
      metadata: %{
        mitre_techniques: ["T1041", "T1048", "T1567"],
        mitre_tactics: ["exfiltration"],
        difficulty: "hard",
        expected_duration_minutes: 35
      },
      steps: [
        %{
          type: "query",
          name: "Large Data Transfers",
          description: "Identify large outbound network transfers.",
          query_template: """
          event_type:network_connect AND
          bytes_sent:>100MB AND
          direction:outbound
          GROUP BY remote_ip, agent_id
          """
        },
        %{
          type: "query",
          name: "Cloud Storage Access",
          description: "Detect uploads to cloud storage services.",
          query_template: """
          event_type:(network_connect OR dns_query) AND
          (domain:(*dropbox.com OR *drive.google.com OR *onedrive.com OR *box.com OR *mega.nz) OR
           url:(*upload* OR *share*))
          """
        },
        %{
          type: "query",
          name: "File Archival",
          description: "Look for file compression/archival before exfiltration.",
          query_template: """
          event_type:process_create AND
          (name:(7z.exe OR WinRAR.exe OR zip.exe) OR
           cmdline:(*-r* OR *-p* OR *archive*)) AND
          cmdline:(*.rar OR *.zip OR *.7z)
          """
        },
        %{
          type: "query",
          name: "DNS Tunneling",
          description: "Detect DNS tunneling exfiltration.",
          query_template: """
          event_type:dns_query AND
          (query_length:>50 OR
           subdomain_count:>5 OR
           query_entropy:>4.0)
          GROUP BY domain HAVING COUNT(*) > 100 WITHIN 10m
          """
        },
        %{
          type: "query",
          name: "Removable Media",
          description: "Check for data copying to USB drives.",
          query_template: """
          event_type:file_copy AND
          destination_path:(D:\\* OR E:\\* OR F:\\* OR G:\\*) AND
          file_size:>10MB
          """
        },
        %{
          type: "collect_evidence",
          name: "Exfiltration Pattern Analysis",
          description: "Analyze exfiltration patterns and scope.",
          evidence_queries: [
            "total_data_transferred",
            "destination_analysis",
            "file_types_exfiltrated",
            "user_account_involved"
          ]
        },
        %{
          type: "decision",
          name: "Data Sensitivity Assessment",
          description: "Assess the sensitivity of potentially exfiltrated data.",
          decision_criteria: [
            "Source directory contains sensitive data?",
            "File types indicate PII/IP?",
            "User has access to sensitive data?",
            "Transfer to unauthorized destination?"
          ],
          next_actions: %{"high_sensitivity" => 7, "low_sensitivity" => 9}
        },
        %{
          type: "notify",
          name: "Data Breach Alert",
          description: "Send urgent notification for potential data breach.",
          notification_config: %{
            priority: "critical",
            channels: ["email", "sms"],
            recipients: ["ciso", "legal", "incident_response"]
          }
        },
        %{
          type: "collect_evidence",
          name: "Forensic Preservation",
          description: "Preserve evidence for potential data breach investigation.",
          evidence_queries: [
            "network_logs",
            "file_access_logs",
            "user_activity_timeline",
            "destination_info"
          ]
        },
        %{
          type: "create_alert",
          name: "Data Exfiltration Alert",
          description: "Create data exfiltration alert.",
          alert_config: %{
            severity: "critical",
            title: "Potential Data Exfiltration Detected"
          }
        }
      ]
    }
  end

  defp privilege_escalation_workflow do
    %{
      name: "Privilege Escalation Hunt",
      description: "Hunt for privilege escalation attempts including exploit usage, token manipulation, and bypass techniques.",
      category: "privilege_escalation",
      metadata: %{
        mitre_techniques: ["T1068", "T1134", "T1548"],
        mitre_tactics: ["privilege-escalation"],
        difficulty: "hard",
        expected_duration_minutes: 35
      },
      steps: [
        %{
          type: "query",
          name: "UAC Bypass Detection",
          description: "Search for UAC bypass techniques.",
          query_template: """
          event_type:process_create AND
          (cmdline:*eventvwr.exe* OR cmdline:*fodhelper.exe* OR cmdline:*ComputerDefaults.exe*) AND
          parent_name:!=explorer.exe
          """
        },
        %{
          type: "query",
          name: "Exploit Tools",
          description: "Look for known privilege escalation exploit tools.",
          query_template: """
          event_type:process_create AND
          name:(juicy*.exe OR *potato*.exe OR printspoofer.exe)
          """
        },
        %{
          type: "query",
          name: "Token Manipulation",
          description: "Detect token manipulation activities.",
          query_template: """
          event_type:process_create AND
          cmdline:(*SeDebugPrivilege* OR *SeImpersonatePrivilege* OR *runas* OR *incognito*)
          """
        },
        %{
          type: "query",
          name: "Suspicious Privilege Escalation",
          description: "Identify processes running with unexpected privileges.",
          query_template: """
          event_type:process_create AND
          is_elevated:true AND
          parent_is_elevated:false
          """
        },
        %{
          type: "collect_evidence",
          name: "Privilege Change Analysis",
          description: "Analyze the privilege escalation event.",
          evidence_queries: [
            "process_privileges",
            "parent_process_chain",
            "exploit_indicators",
            "vulnerability_info"
          ]
        },
        %{
          type: "decision",
          name: "Exploit Classification",
          description: "Classify the privilege escalation method.",
          decision_criteria: [
            "Known vulnerability exploited?",
            "Legitimate admin tool misused?",
            "Token manipulation detected?",
            "UAC bypass technique used?"
          ],
          next_actions: %{"confirmed_exploit" => 6, "uncertain" => 7}
        },
        %{
          type: "notify",
          name: "Urgent Alert",
          description: "Send alert for confirmed privilege escalation.",
          notification_config: %{
            priority: "high",
            channels: ["email", "slack"]
          }
        },
        %{
          type: "manual_review",
          name: "Vulnerability Assessment",
          description: "Assess if systems are vulnerable.",
          review_checklist: [
            "Is this a known CVE being exploited?",
            "Are other systems vulnerable?",
            "Has the vulnerability been patched?",
            "Should emergency patching be initiated?"
          ]
        },
        %{
          type: "create_alert",
          name: "Privilege Escalation Alert",
          description: "Create privilege escalation alert.",
          alert_config: %{
            severity: "high",
            title: "Privilege Escalation Detected"
          }
        }
      ]
    }
  end

  defp powershell_abuse_workflow do
    %{
      name: "Suspicious PowerShell Hunt",
      description: "Hunt for malicious PowerShell usage including encoded commands, obfuscation, and fileless malware.",
      category: "powershell_abuse",
      metadata: %{
        mitre_techniques: ["T1059.001", "T1027", "T1140"],
        mitre_tactics: ["execution", "defense-evasion"],
        difficulty: "medium",
        expected_duration_minutes: 25
      },
      steps: [
        %{
          type: "query",
          name: "Encoded PowerShell",
          description: "Search for encoded/obfuscated PowerShell commands.",
          query_template: """
          event_type:process_create AND
          name:(powershell.exe OR pwsh.exe) AND
          cmdline:(*-enc* OR *-encodedcommand* OR *-e* OR *frombase64*)
          """
        },
        %{
          type: "query",
          name: "Download Cradles",
          description: "Detect PowerShell download cradles.",
          query_template: """
          event_type:process_create AND
          cmdline:(*downloadstring* OR *downloadfile* OR *invoke-webrequest* OR *wget* OR *curl* OR *iwr*)
          """
        },
        %{
          type: "query",
          name: "Execution Policy Bypass",
          description: "Look for execution policy bypass attempts.",
          query_template: """
          event_type:process_create AND
          cmdline:(*-executionpolicy*bypass* OR *-ep*bypass* OR *-noprofile*)
          """
        },
        %{
          type: "query",
          name: "Reflection Injection",
          description: "Detect reflective code injection.",
          query_template: """
          event_type:process_create AND
          cmdline:(*[Reflection.Assembly]* OR *Load(* OR *invoke-expression* OR *iex*)
          """
        },
        %{
          type: "collect_evidence",
          name: "Decode PowerShell Commands",
          description: "Decode and analyze PowerShell commands.",
          evidence_queries: [
            "decode_base64",
            "deobfuscate_script",
            "extract_urls",
            "extract_ips"
          ]
        },
        %{
          type: "decision",
          name: "Malicious Intent Assessment",
          description: "Assess if PowerShell usage is malicious.",
          decision_criteria: [
            "Does decoded command download malware?",
            "Is obfuscation present?",
            "Are known malicious patterns present?",
            "Is the user/process context suspicious?"
          ],
          next_actions: %{"malicious" => 6, "benign" => 8}
        },
        %{
          type: "query",
          name: "Related Network Activity",
          description: "Check for network connections from PowerShell.",
          query_template: """
          event_type:network_connect AND
          process_name:(powershell.exe OR pwsh.exe) AND
          timestamp:[evidence.earliest - 1m TO evidence.latest + 5m]
          """
        },
        %{
          type: "collect_evidence",
          name: "Full Attack Chain",
          description: "Reconstruct the full attack chain.",
          evidence_queries: [
            "parent_process",
            "child_processes",
            "files_created",
            "registry_modifications"
          ]
        },
        %{
          type: "create_alert",
          name: "Malicious PowerShell Alert",
          description: "Create alert for malicious PowerShell activity.",
          alert_config: %{
            severity: "high",
            title: "Malicious PowerShell Activity Detected"
          }
        }
      ]
    }
  end

  defp lolbas_workflow do
    %{
      name: "Living-off-the-Land Binaries (LOLBAS) Hunt",
      description: "Hunt for abuse of legitimate Windows binaries for malicious purposes.",
      category: "lolbas",
      metadata: %{
        mitre_techniques: ["T1218", "T1216", "T1127"],
        mitre_tactics: ["defense-evasion", "execution"],
        difficulty: "hard",
        expected_duration_minutes: 30
      },
      steps: [
        %{
          type: "query",
          name: "Suspicious regsvr32",
          description: "Detect regsvr32 abuse (Squiblydoo).",
          query_template: """
          event_type:process_create AND
          name:regsvr32.exe AND
          (cmdline:(*scrobj.dll* OR */i:http* OR */i:*.sct*) OR network_connection:true)
          """
        },
        %{
          type: "query",
          name: "Suspicious mshta",
          description: "Look for mshta executing remote scripts.",
          query_template: """
          event_type:process_create AND
          name:mshta.exe AND
          (cmdline:(*http* OR *javascript:* OR *vbscript:*))
          """
        },
        %{
          type: "query",
          name: "Suspicious certutil",
          description: "Detect certutil download/decode abuse.",
          query_template: """
          event_type:process_create AND
          name:certutil.exe AND
          cmdline:(*-decode* OR *-urlcache* OR *-verifyctl* OR *-ping* OR http*)
          """
        },
        %{
          type: "query",
          name: "Suspicious rundll32",
          description: "Look for rundll32 with unusual DLLs or functions.",
          query_template: """
          event_type:process_create AND
          name:rundll32.exe AND
          (cmdline:(*javascript:* OR *http* OR *.dat,* OR *.tmp,*) OR
           parent_name:!=explorer.exe)
          """
        },
        %{
          type: "query",
          name: "MSBuild/Compiler Abuse",
          description: "Detect abuse of build tools for execution.",
          query_template: """
          event_type:process_create AND
          name:(msbuild.exe OR csc.exe OR jsc.exe OR vbc.exe) AND
          cmdline:!=*Visual Studio*
          """
        },
        %{
          type: "query",
          name: "BITSAdmin Abuse",
          description: "Look for BITS admin download abuse.",
          query_template: """
          event_type:process_create AND
          name:bitsadmin.exe AND
          cmdline:(*transfer* OR *addfile* OR *setnotifycmdline*)
          """
        },
        %{
          type: "collect_evidence",
          name: "LOLBAS Context Analysis",
          description: "Analyze the context of LOLBAS usage.",
          evidence_queries: [
            "parent_process_analysis",
            "spawned_children",
            "network_connections",
            "files_touched"
          ]
        },
        %{
          type: "decision",
          name: "Legitimate vs Malicious",
          description: "Determine if LOLBAS usage is legitimate.",
          decision_criteria: [
            "Is parent process expected?",
            "Are command line arguments suspicious?",
            "Is user context appropriate?",
            "Is timing suspicious?"
          ],
          next_actions: %{"malicious" => 8, "legitimate" => 9}
        },
        %{
          type: "create_alert",
          name: "LOLBAS Abuse Alert",
          description: "Create alert for LOLBAS abuse.",
          alert_config: %{
            severity: "medium",
            title: "Living-off-the-Land Binary Abuse Detected"
          }
        }
      ]
    }
  end

  defp shadow_it_workflow do
    %{
      name: "Shadow IT Detection",
      description: "Hunt for unauthorized cloud services, applications, and remote access tools.",
      category: "shadow_it",
      metadata: %{
        mitre_techniques: ["T1567"],
        mitre_tactics: ["exfiltration"],
        difficulty: "medium",
        expected_duration_minutes: 30
      },
      steps: [
        %{
          type: "query",
          name: "Unauthorized Cloud Services",
          description: "Detect connections to unapproved cloud services.",
          query_template: """
          event_type:(network_connect OR dns_query) AND
          domain:(*wetransfer.com OR *sendspace.com OR *filemail.com OR *mediafire.com) AND
          domain:!=[approved_cloud_services]
          """
        },
        %{
          type: "query",
          name: "Remote Access Tools",
          description: "Look for unauthorized remote access software.",
          query_template: """
          event_type:process_create AND
          name:(teamviewer.exe OR anydesk.exe OR ammyy.exe OR tightvnc.exe OR logmein.exe)
          """
        },
        %{
          type: "query",
          name: "Personal File Sync",
          description: "Detect personal cloud sync clients.",
          query_template: """
          event_type:process_create AND
          (name:(*sync*.exe OR dropbox.exe) OR
           path:*AppData\\Local\\* OR path:*AppData\\Roaming\\*) AND
          name:!=[approved_sync_tools]
          """
        },
        %{
          type: "query",
          name: "Instant Messaging",
          description: "Find unapproved messaging applications.",
          query_template: """
          event_type:(process_create OR network_connect) AND
          (name:(telegram.exe OR signal.exe OR whatsapp.exe) OR
           domain:(*telegram.org OR *signal.org OR *web.whatsapp.com*))
          """
        },
        %{
          type: "collect_evidence",
          name: "Usage Pattern Analysis",
          description: "Analyze shadow IT usage patterns.",
          evidence_queries: [
            "user_accounts",
            "data_transfer_volume",
            "usage_frequency",
            "departments_affected"
          ]
        },
        %{
          type: "decision",
          name: "Risk Assessment",
          description: "Assess the risk level of shadow IT usage.",
          decision_criteria: [
            "Is sensitive data being uploaded?",
            "Is the service from a trusted vendor?",
            "Is there a business justification?",
            "Are there security/compliance implications?"
          ],
          next_actions: %{"high_risk" => 6, "low_risk" => 8}
        },
        %{
          type: "notify",
          name: "Policy Violation Alert",
          description: "Notify security and management of policy violation.",
          notification_config: %{
            priority: "medium",
            channels: ["email"],
            recipients: ["security_team", "user_manager"]
          }
        },
        %{
          type: "manual_review",
          name: "Business Justification Review",
          description: "Review if there's legitimate business need.",
          review_checklist: [
            "Has user requested approval?",
            "Is there a business case?",
            "Are approved alternatives available?",
            "Should policy be updated?"
          ]
        },
        %{
          type: "create_alert",
          name: "Shadow IT Alert",
          description: "Create alert for shadow IT usage.",
          alert_config: %{
            severity: "low",
            title: "Unauthorized Software/Service Detected"
          }
        }
      ]
    }
  end

  defp insider_threat_workflow do
    %{
      name: "Insider Threat Detection",
      description: "Hunt for insider threat indicators including data hoarding, after-hours access, and policy violations.",
      category: "insider_threat",
      metadata: %{
        mitre_techniques: ["T1530", "T1074"],
        mitre_tactics: ["collection"],
        difficulty: "hard",
        expected_duration_minutes: 45
      },
      steps: [
        %{
          type: "query",
          name: "After-Hours Access",
          description: "Detect unusual after-hours system access.",
          query_template: """
          event_type:authentication AND
          success:true AND
          hour:(0-5 OR 22-23) AND
          day_of_week:(6 OR 7)
          """
        },
        %{
          type: "query",
          name: "Data Hoarding",
          description: "Look for mass file copying or archiving.",
          query_template: """
          event_type:(file_copy OR file_read) AND
          path:(*Confidential* OR *Finance* OR *HR* OR *Legal*) AND
          COUNT(*) > 100 WITHIN 1h BY user
          """
        },
        %{
          type: "query",
          name: "USB Usage",
          description: "Monitor removable media usage.",
          query_template: """
          event_type:device_connect AND
          device_type:usb_storage
          """
        },
        %{
          type: "query",
          name: "Unauthorized Access",
          description: "Detect access to unauthorized resources.",
          query_template: """
          event_type:(file_access OR share_access) AND
          authorized:false AND
          access_denied:false
          """
        },
        %{
          type: "collect_evidence",
          name: "User Behavior Analysis",
          description: "Analyze user behavior patterns.",
          evidence_queries: [
            "access_patterns",
            "data_access_history",
            "employment_status",
            "recent_hr_actions"
          ]
        },
        %{
          type: "decision",
          name: "Insider Threat Level",
          description: "Assess the insider threat level.",
          decision_criteria: [
            "Is employee terminated or resigning?",
            "Has behavior changed recently?",
            "Is access to sensitive data excessive?",
            "Are there policy violations?"
          ],
          next_actions: %{"high_threat" => 6, "medium_threat" => 7, "low_threat" => 8}
        },
        %{
          type: "notify",
          name: "Urgent HR/Security Alert",
          description: "Alert HR and security immediately.",
          notification_config: %{
            priority: "high",
            channels: ["email", "phone"],
            recipients: ["hr", "security_manager", "legal"]
          }
        },
        %{
          type: "collect_evidence",
          name: "Comprehensive Evidence Collection",
          description: "Gather all evidence for investigation.",
          evidence_queries: [
            "all_file_access",
            "email_activity",
            "chat_logs",
            "badge_access_logs"
          ]
        },
        %{
          type: "manual_review",
          name: "Investigation Review",
          description: "Review all evidence with HR/Legal.",
          review_checklist: [
            "Is there sufficient evidence of malicious intent?",
            "Should employee access be restricted?",
            "Should law enforcement be contacted?",
            "What is the potential damage?"
          ]
        },
        %{
          type: "create_alert",
          name: "Insider Threat Alert",
          description: "Create insider threat alert.",
          alert_config: %{
            severity: "high",
            title: "Potential Insider Threat Activity"
          }
        }
      ]
    }
  end

  defp supply_chain_workflow do
    %{
      name: "Supply Chain Compromise Hunt",
      description: "Hunt for supply chain attack indicators including compromised software updates, malicious dependencies, and build process tampering.",
      category: "supply_chain",
      metadata: %{
        mitre_techniques: ["T1195", "T1195.001", "T1195.002"],
        mitre_tactics: ["initial-access"],
        difficulty: "hard",
        expected_duration_minutes: 40
      },
      steps: [
        %{
          type: "query",
          name: "Suspicious Software Updates",
          description: "Detect anomalous software update behavior.",
          query_template: """
          event_type:process_create AND
          (name:(*update*.exe OR *installer*.exe) OR
           cmdline:(*auto-update* OR *software-update*)) AND
          (is_signed:false OR signer:!=[trusted_vendors])
          """
        },
        %{
          type: "query",
          name: "Package Manager Activity",
          description: "Monitor package manager installations.",
          query_template: """
          event_type:process_create AND
          name:(npm.exe OR pip.exe OR gem.exe OR nuget.exe) AND
          cmdline:(install OR add OR update)
          """
        },
        %{
          type: "query",
          name: "Build Tool Execution",
          description: "Detect build tool execution outside CI/CD.",
          query_template: """
          event_type:process_create AND
          name:(msbuild.exe OR gradle.exe OR maven.exe OR make.exe) AND
          parent_name:!=(jenkins.exe OR teamcity* OR bamboo*)
          """
        },
        %{
          type: "query",
          name: "Dependency Downloads",
          description: "Monitor dependency downloads from repositories.",
          query_template: """
          event_type:network_connect AND
          domain:(*npmjs.org OR *pypi.org OR *rubygems.org OR *maven.org OR *nuget.org) AND
          http_status:200
          """
        },
        %{
          type: "collect_evidence",
          name: "Integrity Verification",
          description: "Verify integrity of downloaded components.",
          evidence_queries: [
            "file_hashes",
            "signature_verification",
            "repository_source",
            "version_comparison"
          ]
        },
        %{
          type: "decision",
          name: "Compromise Assessment",
          description: "Assess if supply chain compromise is suspected.",
          decision_criteria: [
            "Hash mismatch with known good version?",
            "Signature invalid or untrusted?",
            "Download from unofficial source?",
            "Known vulnerable dependency?"
          ],
          next_actions: %{"compromised" => 6, "uncertain" => 7, "clean" => 9}
        },
        %{
          type: "notify",
          name: "Critical Supply Chain Alert",
          description: "Send critical alert for supply chain compromise.",
          notification_config: %{
            priority: "critical",
            channels: ["email", "sms", "slack"],
            recipients: ["ciso", "development_team", "security_team"]
          }
        },
        %{
          type: "query",
          name: "Lateral Impact Analysis",
          description: "Identify other systems with the compromised component.",
          query_template: """
          event_type:file_create AND
          (hash:[compromised_hashes] OR name:[compromised_files])
          GROUP BY agent_id
          """
        },
        %{
          type: "collect_evidence",
          name: "Full Compromise Scope",
          description: "Determine full scope of supply chain compromise.",
          evidence_queries: [
            "affected_systems",
            "installation_timeline",
            "post_install_activity",
            "data_access"
          ]
        },
        %{
          type: "create_alert",
          name: "Supply Chain Compromise Alert",
          description: "Create supply chain compromise alert.",
          alert_config: %{
            severity: "critical",
            title: "Supply Chain Compromise Detected",
            recommended_actions: [
              "Isolate affected systems",
              "Roll back to known good versions",
              "Verify integrity of all dependencies",
              "Report to vendor/maintainer",
              "Initiate incident response"
            ]
          }
        }
      ]
    }
  end
end
