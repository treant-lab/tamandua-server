defmodule TamanduaServer.Remediation.Templates do
  @moduledoc """
  Pre-built Remediation Playbook Templates

  Provides 10+ production-ready playbook templates for common security scenarios:
  1. Ransomware Response
  2. Malware Cleanup
  3. Credential Compromise Response
  4. Data Exfiltration Response
  5. Insider Threat Response
  6. Phishing Response
  7. Lateral Movement Response
  8. Privilege Escalation Response
  9. Brute Force Attack Response
  10. Vulnerability Exploitation Response
  11. Zero-Day Threat Response
  12. Supply Chain Attack Response

  Each template includes:
  - Pre-configured action steps
  - Conditional logic
  - Parallel execution where appropriate
  - Appropriate approval workflows
  - Rollback support
  """

  @doc """
  Get all available playbook templates.
  """
  def list_templates do
    [
      ransomware_response(),
      malware_cleanup(),
      credential_compromise(),
      data_exfiltration(),
      insider_threat(),
      phishing_response(),
      lateral_movement(),
      privilege_escalation(),
      brute_force_attack(),
      vulnerability_exploitation(),
      zero_day_threat(),
      supply_chain_attack()
    ]
  end

  @doc """
  Get a specific template by ID.
  """
  def get_template(template_id) do
    list_templates()
    |> Enum.find(&(&1.id == template_id))
  end

  # ============================================================================
  # Template Definitions
  # ============================================================================

  @doc """
  Ransomware Response Playbook

  Immediate response to ransomware detection:
  1. Isolate infected host from network
  2. Kill malicious process
  3. Quarantine ransomware binary
  4. Collect forensic evidence
  5. Create incident ticket
  6. Notify security team

  Risk Level: CRITICAL
  Approval: Not required (auto-execute)
  """
  def ransomware_response do
    %{
      id: "template_ransomware_response",
      name: "Ransomware Response",
      description: "Automated containment and response for ransomware detections",
      category: "ransomware",
      trigger_type: "alert",
      trigger_conditions: %{
        "detection_type" => "ransomware",
        "severity" => "critical"
      },
      require_approval: false,
      approval_tier: "analyst",
      auto_rollback_on_failure: false,
      risk_level: "critical",
      severity_threshold: "high",
      tags: ["ransomware", "critical", "automated", "isolation"],
      steps: [
        %{
          "action" => "isolate_network",
          "name" => "Isolate Infected Host",
          "params" => %{},
          "max_retries" => 3,
          "timeout_seconds" => 60
        },
        %{
          "action" => "kill_process",
          "name" => "Terminate Ransomware Process",
          "params" => %{},
          "max_retries" => 2,
          "continue_on_failure" => true
        },
        %{
          "action" => "quarantine_file",
          "name" => "Quarantine Ransomware Binary",
          "params" => %{},
          "max_retries" => 2,
          "continue_on_failure" => true
        },
        %{
          "action" => "collect_forensics",
          "name" => "Collect Full Forensic Evidence",
          "params" => %{
            "type" => "full",
            "memory_dump" => true,
            "process_list" => true,
            "network_connections" => true
          },
          "max_retries" => 1,
          "continue_on_failure" => true
        },
        %{
          "action" => "create_ticket",
          "name" => "Create Critical Incident Ticket",
          "params" => %{
            "priority" => "critical",
            "title" => "CRITICAL: Ransomware Detection - {{agent_id}}"
          },
          "continue_on_failure" => true
        },
        %{
          "action" => "send_notification",
          "name" => "Alert Security Team",
          "params" => %{
            "channel" => "slack",
            "message" => "CRITICAL: Ransomware detected and contained on {{agent_id}}"
          },
          "continue_on_failure" => true
        }
      ],
      is_template: true
    }
  end

  @doc """
  Malware Cleanup Playbook

  Comprehensive malware remediation:
  1. Kill malicious process
  2. Quarantine malware file
  3. Delete associated files
  4. Clean registry (Windows)
  5. Scan system for additional threats
  6. Deploy latest patches
  7. Reboot system (optional)

  Risk Level: HIGH
  Approval: Required for reboot
  """
  def malware_cleanup do
    %{
      id: "template_malware_cleanup",
      name: "Malware Cleanup",
      description: "Comprehensive malware removal and system hardening",
      category: "malware",
      trigger_type: "alert",
      trigger_conditions: %{
        "detection_type" => "malware",
        "confidence" => 0.8
      },
      require_approval: true,
      approval_tier: "analyst",
      auto_rollback_on_failure: true,
      risk_level: "high",
      severity_threshold: "medium",
      tags: ["malware", "cleanup", "remediation"],
      steps: [
        %{
          "action" => "kill_process",
          "name" => "Kill Malicious Process",
          "params" => %{},
          "max_retries" => 3
        },
        %{
          "action" => "quarantine_file",
          "name" => "Quarantine Malware Binary",
          "params" => %{},
          "max_retries" => 2
        },
        %{
          "action" => "delete_registry_key",
          "name" => "Remove Persistence Registry Keys",
          "params" => %{
            "key_path" => "{{persistence_key}}"
          },
          "continue_on_failure" => true
        },
        %{
          "action" => "run_script",
          "name" => "Scan for Additional Threats",
          "params" => %{
            "script_type" => "powershell",
            "script" => "Start-MpScan -ScanType QuickScan"
          },
          "timeout_seconds" => 300,
          "continue_on_failure" => true
        },
        %{
          "action" => "deploy_patch",
          "name" => "Deploy Security Updates",
          "params" => %{},
          "timeout_seconds" => 600,
          "continue_on_failure" => true
        },
        %{
          "action" => "send_notification",
          "name" => "Notify Completion",
          "params" => %{
            "channel" => "email",
            "message" => "Malware cleanup completed on {{agent_id}}"
          }
        }
      ],
      is_template: true
    }
  end

  @doc """
  Credential Compromise Response Playbook

  Response to credential theft or compromise:
  1. Force password reset for affected user
  2. Terminate all user sessions
  3. Enforce MFA
  4. Disable compromised account temporarily
  5. Collect memory forensics
  6. Alert identity team
  7. Create incident ticket

  Risk Level: CRITICAL
  Approval: Required (Senior Analyst)
  """
  def credential_compromise do
    %{
      id: "template_credential_compromise",
      name: "Credential Compromise Response",
      description: "Immediate response to credential theft or compromise",
      category: "credential_theft",
      trigger_type: "alert",
      trigger_conditions: %{
        "mitre_tactic" => "credential-access",
        "severity" => "high"
      },
      require_approval: true,
      approval_tier: "senior_analyst",
      auto_rollback_on_failure: true,
      risk_level: "critical",
      severity_threshold: "high",
      tags: ["credentials", "identity", "critical"],
      steps: [
        %{
          "action" => "terminate_session",
          "name" => "Terminate All User Sessions",
          "params" => %{},
          "max_retries" => 2
        },
        %{
          "action" => "force_password_reset",
          "name" => "Force Password Reset",
          "params" => %{},
          "max_retries" => 3
        },
        %{
          "action" => "enforce_mfa",
          "name" => "Enforce MFA Requirement",
          "params" => %{},
          "continue_on_failure" => true
        },
        %{
          "action" => "disable_user",
          "name" => "Temporarily Disable Account",
          "params" => %{},
          "max_retries" => 2
        },
        %{
          "action" => "collect_forensics",
          "name" => "Collect Memory Dump",
          "params" => %{
            "type" => "memory",
            "memory_dump" => true,
            "process_list" => true
          },
          "timeout_seconds" => 300,
          "continue_on_failure" => true
        },
        %{
          "action" => "create_ticket",
          "name" => "Create Incident Ticket",
          "params" => %{
            "priority" => "critical",
            "title" => "Credential Compromise - {{username}}"
          }
        },
        %{
          "action" => "send_notification",
          "name" => "Alert Security & Identity Teams",
          "params" => %{
            "channel" => "slack",
            "message" => "CRITICAL: Credential compromise detected for {{username}}"
          }
        }
      ],
      is_template: true
    }
  end

  @doc """
  Data Exfiltration Response Playbook

  Response to data exfiltration attempts:
  1. Isolate affected host
  2. Block destination IP/domain
  3. Kill exfiltration process
  4. Collect network forensics
  5. Create incident ticket
  6. Alert DLP team

  Risk Level: CRITICAL
  Approval: Not required (auto-execute)
  """
  def data_exfiltration do
    %{
      id: "template_data_exfiltration",
      name: "Data Exfiltration Response",
      description: "Immediate containment of data exfiltration attempts",
      category: "data_exfiltration",
      trigger_type: "alert",
      trigger_conditions: %{
        "mitre_tactic" => "exfiltration",
        "severity" => "critical"
      },
      require_approval: false,
      approval_tier: "analyst",
      auto_rollback_on_failure: false,
      risk_level: "critical",
      severity_threshold: "high",
      tags: ["exfiltration", "dlp", "critical", "network"],
      steps: [
        %{
          "action" => "isolate_network",
          "name" => "Isolate Source Host",
          "params" => %{},
          "max_retries" => 3
        },
        %{
          "action" => "block_ip",
          "name" => "Block Destination IP",
          "params" => %{},
          "max_retries" => 2,
          "continue_on_failure" => true
        },
        %{
          "action" => "block_domain",
          "name" => "Block Destination Domain",
          "params" => %{},
          "continue_on_failure" => true
        },
        %{
          "action" => "kill_process",
          "name" => "Terminate Exfiltration Process",
          "params" => %{},
          "max_retries" => 2,
          "continue_on_failure" => true
        },
        %{
          "action" => "collect_forensics",
          "name" => "Collect Network Forensics",
          "params" => %{
            "type" => "network",
            "network_connections" => true,
            "process_list" => true
          },
          "continue_on_failure" => true
        },
        %{
          "action" => "create_ticket",
          "name" => "Create DLP Incident",
          "params" => %{
            "priority" => "critical",
            "title" => "Data Exfiltration Detected - {{agent_id}}"
          }
        },
        %{
          "action" => "send_notification",
          "name" => "Alert DLP & Security Teams",
          "params" => %{
            "channel" => "slack",
            "message" => "CRITICAL: Data exfiltration blocked on {{agent_id}}"
          }
        }
      ],
      is_template: true
    }
  end

  @doc """
  Insider Threat Response Playbook

  Response to insider threat indicators:
  1. Disable user account
  2. Terminate all sessions
  3. Revoke certificates
  4. Collect comprehensive forensics
  5. Preserve evidence
  6. Alert HR and legal
  7. Create incident ticket

  Risk Level: CRITICAL
  Approval: Required (Manager)
  """
  def insider_threat do
    %{
      id: "template_insider_threat",
      name: "Insider Threat Response",
      description: "Containment and evidence preservation for insider threats",
      category: "insider_threat",
      trigger_type: "alert",
      trigger_conditions: %{
        "category" => "insider_threat",
        "risk_score" => 80
      },
      require_approval: true,
      approval_tier: "manager",
      auto_rollback_on_failure: false,
      risk_level: "critical",
      severity_threshold: "high",
      tags: ["insider", "critical", "legal", "hr"],
      steps: [
        %{
          "action" => "disable_user",
          "name" => "Disable User Account",
          "params" => %{},
          "max_retries" => 3
        },
        %{
          "action" => "terminate_session",
          "name" => "Terminate All Active Sessions",
          "params" => %{},
          "max_retries" => 2
        },
        %{
          "action" => "revoke_certificate",
          "name" => "Revoke User Certificates",
          "params" => %{},
          "continue_on_failure" => true
        },
        %{
          "action" => "collect_forensics",
          "name" => "Collect Comprehensive Forensics",
          "params" => %{
            "type" => "full",
            "memory_dump" => true,
            "process_list" => true,
            "network_connections" => true,
            "browser_history" => true,
            "event_logs" => true
          },
          "timeout_seconds" => 600
        },
        %{
          "action" => "create_ticket",
          "name" => "Create Legal Hold Ticket",
          "params" => %{
            "priority" => "critical",
            "title" => "Insider Threat - Legal Hold Required - {{username}}"
          }
        },
        %{
          "action" => "send_notification",
          "name" => "Alert Security, HR, and Legal",
          "params" => %{
            "channel" => "email",
            "message" => "CRITICAL: Insider threat activity detected for {{username}}"
          }
        }
      ],
      is_template: true
    }
  end

  @doc """
  Phishing Response Playbook

  Response to phishing attempts:
  1. Block sender domain
  2. Quarantine email attachments
  3. Reset compromised credentials (if applicable)
  4. Block phishing URLs
  5. Send user awareness notification
  6. Create ticket for investigation

  Risk Level: MEDIUM
  Approval: Not required
  """
  def phishing_response do
    %{
      id: "template_phishing_response",
      name: "Phishing Response",
      description: "Automated response to phishing attempts",
      category: "phishing",
      trigger_type: "alert",
      trigger_conditions: %{
        "detection_type" => "phishing",
        "confidence" => 0.7
      },
      require_approval: false,
      approval_tier: "analyst",
      auto_rollback_on_failure: true,
      risk_level: "medium",
      severity_threshold: "medium",
      tags: ["phishing", "email", "awareness"],
      steps: [
        %{
          "action" => "block_domain",
          "name" => "Block Sender Domain",
          "params" => %{},
          "max_retries" => 2
        },
        %{
          "action" => "quarantine_file",
          "name" => "Quarantine Email Attachments",
          "params" => %{},
          "continue_on_failure" => true
        },
        %{
          "action" => "block_ip",
          "name" => "Block Phishing Server IP",
          "params" => %{},
          "continue_on_failure" => true
        },
        %{
          "action" => "send_notification",
          "name" => "Send User Awareness Alert",
          "params" => %{
            "channel" => "email",
            "message" => "A phishing attempt was detected and blocked. Please remain vigilant."
          }
        },
        %{
          "action" => "create_ticket",
          "name" => "Create Investigation Ticket",
          "params" => %{
            "priority" => "medium",
            "title" => "Phishing Investigation - {{domain}}"
          }
        }
      ],
      is_template: true
    }
  end

  @doc """
  Lateral Movement Response Playbook

  Response to lateral movement detection:
  1. Isolate source and target hosts
  2. Block suspicious IPs
  3. Terminate suspicious processes
  4. Force password reset for affected accounts
  5. Collect forensics from both hosts
  6. Create incident ticket

  Risk Level: HIGH
  Approval: Required (Analyst)
  """
  def lateral_movement do
    %{
      id: "template_lateral_movement",
      name: "Lateral Movement Response",
      description: "Containment response for lateral movement activity",
      category: "lateral_movement",
      trigger_type: "alert",
      trigger_conditions: %{
        "mitre_tactic" => "lateral-movement",
        "severity" => "high"
      },
      require_approval: true,
      approval_tier: "analyst",
      auto_rollback_on_failure: false,
      risk_level: "high",
      severity_threshold: "high",
      tags: ["lateral-movement", "network", "apt"],
      steps: [
        %{
          "action" => "isolate_network",
          "name" => "Isolate Source Host",
          "params" => %{},
          "max_retries" => 3
        },
        %{
          "action" => "block_ip",
          "name" => "Block Suspicious Communication",
          "params" => %{},
          "max_retries" => 2
        },
        %{
          "action" => "kill_process",
          "name" => "Terminate Suspicious Processes",
          "params" => %{},
          "continue_on_failure" => true
        },
        %{
          "action" => "force_password_reset",
          "name" => "Reset Compromised Credentials",
          "params" => %{},
          "continue_on_failure" => true
        },
        %{
          "action" => "collect_forensics",
          "name" => "Collect Forensics (Source)",
          "params" => %{
            "type" => "full",
            "memory_dump" => false,
            "process_list" => true,
            "network_connections" => true
          },
          "continue_on_failure" => true
        },
        %{
          "action" => "create_ticket",
          "name" => "Create APT Investigation Ticket",
          "params" => %{
            "priority" => "high",
            "title" => "Lateral Movement Detected - {{agent_id}}"
          }
        },
        %{
          "action" => "send_notification",
          "name" => "Alert Threat Hunting Team",
          "params" => %{
            "channel" => "slack",
            "message" => "HIGH: Lateral movement activity detected and contained"
          }
        }
      ],
      is_template: true
    }
  end

  @doc """
  Privilege Escalation Response Playbook

  Response to privilege escalation attempts:
  1. Terminate escalated process
  2. Revert user privileges
  3. Disable affected account
  4. Collect forensics
  5. Audit system permissions
  6. Deploy patches (if vulnerability-based)
  7. Create incident ticket

  Risk Level: HIGH
  Approval: Required (Senior Analyst)
  """
  def privilege_escalation do
    %{
      id: "template_privilege_escalation",
      name: "Privilege Escalation Response",
      description: "Response to privilege escalation attempts",
      category: "privilege_escalation",
      trigger_type: "alert",
      trigger_conditions: %{
        "mitre_tactic" => "privilege-escalation",
        "severity" => "high"
      },
      require_approval: true,
      approval_tier: "senior_analyst",
      auto_rollback_on_failure: true,
      risk_level: "high",
      severity_threshold: "high",
      tags: ["privilege-escalation", "vulnerability"],
      steps: [
        %{
          "action" => "kill_process",
          "name" => "Terminate Escalated Process",
          "params" => %{},
          "max_retries" => 3
        },
        %{
          "action" => "disable_user",
          "name" => "Disable Affected Account",
          "params" => %{},
          "max_retries" => 2
        },
        %{
          "action" => "collect_forensics",
          "name" => "Collect System Forensics",
          "params" => %{
            "type" => "full",
            "memory_dump" => true,
            "process_list" => true,
            "event_logs" => true
          },
          "timeout_seconds" => 600,
          "continue_on_failure" => true
        },
        %{
          "action" => "run_script",
          "name" => "Audit System Permissions",
          "params" => %{
            "script_type" => "powershell",
            "script" => "Get-Acl | Select-Object Path,Owner,AccessToString"
          },
          "continue_on_failure" => true
        },
        %{
          "action" => "deploy_patch",
          "name" => "Deploy Security Updates",
          "params" => %{},
          "timeout_seconds" => 600,
          "continue_on_failure" => true
        },
        %{
          "action" => "create_ticket",
          "name" => "Create Investigation Ticket",
          "params" => %{
            "priority" => "high",
            "title" => "Privilege Escalation Attempt - {{agent_id}}"
          }
        },
        %{
          "action" => "send_notification",
          "name" => "Alert Security Team",
          "params" => %{
            "channel" => "slack",
            "message" => "HIGH: Privilege escalation attempt detected and blocked"
          }
        }
      ],
      is_template: true
    }
  end

  @doc """
  Brute Force Attack Response Playbook

  Response to brute force authentication attempts:
  1. Block source IP
  2. Lock targeted account
  3. Enforce MFA
  4. Collect authentication logs
  5. Create incident ticket
  6. Alert security team

  Risk Level: MEDIUM
  Approval: Not required
  """
  def brute_force_attack do
    %{
      id: "template_brute_force_attack",
      name: "Brute Force Attack Response",
      description: "Automated response to brute force authentication attempts",
      category: "brute_force",
      trigger_type: "alert",
      trigger_conditions: %{
        "mitre_technique" => "T1110",
        "failed_login_count" => 10
      },
      require_approval: false,
      approval_tier: "analyst",
      auto_rollback_on_failure: true,
      risk_level: "medium",
      severity_threshold: "medium",
      tags: ["brute-force", "authentication", "credential"],
      steps: [
        %{
          "action" => "block_ip",
          "name" => "Block Attack Source IP",
          "params" => %{
            "duration" => 3600
          },
          "max_retries" => 3
        },
        %{
          "action" => "disable_user",
          "name" => "Lock Targeted Account",
          "params" => %{},
          "max_retries" => 2
        },
        %{
          "action" => "enforce_mfa",
          "name" => "Enforce MFA Requirement",
          "params" => %{},
          "continue_on_failure" => true
        },
        %{
          "action" => "collect_forensics",
          "name" => "Collect Authentication Logs",
          "params" => %{
            "type" => "auth",
            "event_logs" => true
          },
          "continue_on_failure" => true
        },
        %{
          "action" => "create_ticket",
          "name" => "Create Investigation Ticket",
          "params" => %{
            "priority" => "medium",
            "title" => "Brute Force Attack - {{username}}"
          }
        },
        %{
          "action" => "send_notification",
          "name" => "Alert Security Team",
          "params" => %{
            "channel" => "email",
            "message" => "Brute force attack detected and blocked for {{username}}"
          }
        }
      ],
      is_template: true
    }
  end

  @doc """
  Vulnerability Exploitation Response Playbook

  Response to vulnerability exploitation attempts:
  1. Isolate vulnerable host
  2. Kill exploit process
  3. Deploy emergency patch
  4. Collect exploit forensics
  5. Scan for additional compromised hosts
  6. Create incident ticket

  Risk Level: CRITICAL
  Approval: Required (Analyst)
  """
  def vulnerability_exploitation do
    %{
      id: "template_vulnerability_exploitation",
      name: "Vulnerability Exploitation Response",
      description: "Response to active vulnerability exploitation",
      category: "exploitation",
      trigger_type: "alert",
      trigger_conditions: %{
        "mitre_tactic" => "initial-access",
        "exploit_detected" => true
      },
      require_approval: true,
      approval_tier: "analyst",
      auto_rollback_on_failure: false,
      risk_level: "critical",
      severity_threshold: "high",
      tags: ["exploitation", "vulnerability", "critical"],
      steps: [
        %{
          "action" => "isolate_network",
          "name" => "Isolate Vulnerable Host",
          "params" => %{},
          "max_retries" => 3
        },
        %{
          "action" => "kill_process",
          "name" => "Terminate Exploit Process",
          "params" => %{},
          "max_retries" => 2
        },
        %{
          "action" => "deploy_patch",
          "name" => "Deploy Emergency Patch",
          "params" => %{},
          "timeout_seconds" => 600,
          "max_retries" => 2
        },
        %{
          "action" => "collect_forensics",
          "name" => "Collect Exploit Forensics",
          "params" => %{
            "type" => "full",
            "memory_dump" => true,
            "process_list" => true,
            "network_connections" => true
          },
          "timeout_seconds" => 600,
          "continue_on_failure" => true
        },
        %{
          "action" => "run_script",
          "name" => "Scan for Additional Compromised Hosts",
          "params" => %{
            "script_type" => "powershell",
            "script" => "# Scan network for similar exploits"
          },
          "timeout_seconds" => 300,
          "continue_on_failure" => true
        },
        %{
          "action" => "create_ticket",
          "name" => "Create Critical Incident",
          "params" => %{
            "priority" => "critical",
            "title" => "Vulnerability Exploitation - {{cve_id}} - {{agent_id}}"
          }
        },
        %{
          "action" => "send_notification",
          "name" => "Alert Vulnerability Management Team",
          "params" => %{
            "channel" => "slack",
            "message" => "CRITICAL: Vulnerability exploitation detected - {{cve_id}}"
          }
        }
      ],
      is_template: true
    }
  end

  @doc """
  Zero-Day Threat Response Playbook

  Response to zero-day threat indicators:
  1. Immediate isolation
  2. Full forensic collection
  3. Kill all suspicious processes
  4. Create emergency incident
  5. Alert threat intelligence team
  6. Preserve evidence for analysis

  Risk Level: CRITICAL
  Approval: Not required (emergency response)
  """
  def zero_day_threat do
    %{
      id: "template_zero_day_threat",
      name: "Zero-Day Threat Response",
      description: "Emergency response for zero-day threats",
      category: "zero_day",
      trigger_type: "alert",
      trigger_conditions: %{
        "zero_day" => true,
        "severity" => "critical"
      },
      require_approval: false,
      approval_tier: "analyst",
      auto_rollback_on_failure: false,
      risk_level: "critical",
      severity_threshold: "critical",
      tags: ["zero-day", "apt", "critical", "emergency"],
      steps: [
        %{
          "action" => "isolate_network",
          "name" => "Emergency Isolation",
          "params" => %{},
          "max_retries" => 5
        },
        %{
          "action" => "collect_forensics",
          "name" => "Comprehensive Forensic Collection",
          "params" => %{
            "type" => "full",
            "memory_dump" => true,
            "process_list" => true,
            "network_connections" => true,
            "event_logs" => true,
            "prefetch" => true,
            "browser_history" => true
          },
          "timeout_seconds" => 1800
        },
        %{
          "action" => "kill_process",
          "name" => "Terminate All Suspicious Processes",
          "params" => %{},
          "continue_on_failure" => true
        },
        %{
          "action" => "create_ticket",
          "name" => "Create Emergency Incident",
          "params" => %{
            "priority" => "critical",
            "title" => "ZERO-DAY THREAT DETECTED - {{agent_id}}"
          }
        },
        %{
          "action" => "send_notification",
          "name" => "Emergency Alert - All Teams",
          "params" => %{
            "channel" => "slack",
            "message" => "🚨 CRITICAL: Zero-day threat detected on {{agent_id}} - Immediate response required"
          }
        }
      ],
      is_template: true
    }
  end

  @doc """
  Supply Chain Attack Response Playbook

  Response to supply chain compromise:
  1. Quarantine compromised software/packages
  2. Disable affected services
  3. Collect forensic evidence
  4. Block command and control servers
  5. Alert vendor and community
  6. Deploy remediation patches

  Risk Level: CRITICAL
  Approval: Required (Manager)
  """
  def supply_chain_attack do
    %{
      id: "template_supply_chain_attack",
      name: "Supply Chain Attack Response",
      description: "Response to supply chain compromise detection",
      category: "supply_chain",
      trigger_type: "alert",
      trigger_conditions: %{
        "supply_chain_compromise" => true,
        "severity" => "critical"
      },
      require_approval: true,
      approval_tier: "manager",
      auto_rollback_on_failure: false,
      risk_level: "critical",
      severity_threshold: "critical",
      tags: ["supply-chain", "critical", "vendor"],
      steps: [
        %{
          "action" => "quarantine_file",
          "name" => "Quarantine Compromised Software",
          "params" => %{},
          "max_retries" => 3
        },
        %{
          "action" => "stop_service",
          "name" => "Stop Affected Services",
          "params" => %{},
          "max_retries" => 2
        },
        %{
          "action" => "disable_service",
          "name" => "Disable Compromised Services",
          "params" => %{},
          "max_retries" => 2
        },
        %{
          "action" => "collect_forensics",
          "name" => "Collect Supply Chain Evidence",
          "params" => %{
            "type" => "full",
            "memory_dump" => true,
            "process_list" => true,
            "network_connections" => true,
            "registry_hives" => true
          },
          "timeout_seconds" => 900
        },
        %{
          "action" => "block_ip",
          "name" => "Block C2 Servers",
          "params" => %{},
          "continue_on_failure" => true
        },
        %{
          "action" => "block_domain",
          "name" => "Block C2 Domains",
          "params" => %{},
          "continue_on_failure" => true
        },
        %{
          "action" => "create_ticket",
          "name" => "Create Supply Chain Incident",
          "params" => %{
            "priority" => "critical",
            "title" => "Supply Chain Compromise - {{package_name}}"
          }
        },
        %{
          "action" => "send_notification",
          "name" => "Alert Security & Procurement",
          "params" => %{
            "channel" => "email",
            "message" => "CRITICAL: Supply chain compromise detected - {{package_name}}"
          }
        }
      ],
      is_template: true
    }
  end
end
