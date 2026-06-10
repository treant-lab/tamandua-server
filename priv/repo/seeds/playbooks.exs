# Professional Incident Response Playbooks
# Run with: mix run priv/repo/seeds/playbooks.exs
#
# These playbooks are designed to match enterprise-grade EDR platforms
# like CrowdStrike Falcon, SentinelOne, and Microsoft Defender for Endpoint.

alias TamanduaServer.Repo
alias TamanduaServer.Response.Playbook.Schema, as: PlaybookSchema

IO.puts("Seeding professional incident response playbooks...")

playbooks = [
  # ============================================================================
  # 1. RANSOMWARE RESPONSE PLAYBOOK
  # ============================================================================
  %{
    name: "Ransomware Response",
    description: """
    Comprehensive ransomware incident response playbook. Automatically isolates
    infected hosts, terminates malicious processes, collects forensic evidence,
    and initiates recovery procedures. Follows NIST and CISA ransomware guidance.
    """,
    trigger_type: "detection",
    trigger_conditions: %{
      "detection_type" => "ransomware",
      "severity" => "high",
      "mitre_technique" => "T1486"
    },
    enabled: true,
    require_approval: false,
    approval_timeout_minutes: 5,
    severity_threshold: "high",
    tags: ["ransomware", "critical", "automated", "containment", "NIST-IR"],
    steps: [
      %{
        "action" => "isolate_host",
        "params" => %{},
        "description" => "Immediately isolate the infected host from the network",
        "timeout_seconds" => 30,
        "on_failure" => "continue"
      },
      %{
        "action" => "kill_process",
        "params" => %{},
        "description" => "Terminate the ransomware process and child processes",
        "timeout_seconds" => 15
      },
      %{
        "action" => "quarantine_file",
        "params" => %{},
        "description" => "Quarantine the ransomware binary",
        "timeout_seconds" => 30
      },
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "full",
          "include_memory" => true,
          "include_disk_artifacts" => true,
          "include_network_connections" => true,
          "include_registry" => true
        },
        "description" => "Collect comprehensive forensic evidence",
        "timeout_seconds" => 300
      },
      %{
        "action" => "block_ip",
        "params" => %{"scope" => "organization"},
        "description" => "Block C2 IP across all endpoints"
      },
      %{
        "action" => "block_domain",
        "params" => %{"scope" => "organization"},
        "description" => "Block C2 domains at DNS level"
      },
      %{
        "action" => "enrich_ioc",
        "params" => %{"sources" => ["virustotal", "hybrid-analysis", "any.run"]},
        "description" => "Enrich IOCs with threat intelligence"
      },
      %{
        "action" => "trigger_scan",
        "params" => %{
          "scope" => "organization",
          "scan_type" => "ransomware_indicators"
        },
        "description" => "Scan all endpoints for ransomware indicators"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "critical",
          "category" => "ransomware",
          "template" => "ransomware_incident",
          "assign_to" => "security_team_lead"
        },
        "description" => "Create critical incident ticket"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["slack", "pagerduty", "email"],
          "severity" => "critical",
          "message" => "CRITICAL: Ransomware detected and contained. Immediate response required.",
          "notify_executives" => true
        },
        "description" => "Alert security team and executives"
      }
    ]
  },

  # ============================================================================
  # 2. PHISHING INCIDENT RESPONSE
  # ============================================================================
  %{
    name: "Phishing Incident Response",
    description: """
    Automated response to phishing attacks including credential harvesting attempts,
    malicious attachments, and business email compromise. Integrates with email
    security gateways and identity providers for comprehensive response.
    """,
    trigger_type: "alert",
    trigger_conditions: %{
      "detection_type" => "phishing",
      "mitre_tactic" => "initial-access"
    },
    enabled: true,
    require_approval: false,
    approval_timeout_minutes: 15,
    severity_threshold: "medium",
    tags: ["phishing", "email", "credential-theft", "BEC", "initial-access"],
    steps: [
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "email",
          "include_headers" => true,
          "include_attachments" => true,
          "include_urls" => true
        },
        "description" => "Extract email artifacts and attachments"
      },
      %{
        "action" => "quarantine_file",
        "params" => %{"type" => "email_attachment"},
        "description" => "Quarantine malicious attachments"
      },
      %{
        "action" => "block_domain",
        "params" => %{
          "scope" => "email_gateway",
          "block_similar" => true
        },
        "description" => "Block sender domain and similar domains"
      },
      %{
        "action" => "enrich_ioc",
        "params" => %{
          "sources" => ["urlscan.io", "phishtank", "virustotal"],
          "check_url_reputation" => true
        },
        "description" => "Check URL and domain reputation"
      },
      %{
        "action" => "conditional",
        "params" => %{
          "condition" => %{
            "field" => "user_clicked_link",
            "operator" => "equals",
            "value" => true
          },
          "true_step" => 5,
          "false_step" => 8
        },
        "description" => "Check if user interacted with phishing content"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "check_credential_exposure",
          "target" => "identity_provider"
        },
        "description" => "Check for credential compromise"
      },
      %{
        "action" => "conditional",
        "params" => %{
          "condition" => %{
            "field" => "credentials_exposed",
            "operator" => "equals",
            "value" => true
          },
          "true_step" => 7,
          "false_step" => 8
        }
      },
      %{
        "action" => "disable_user",
        "params" => %{
          "force_password_reset" => true,
          "revoke_sessions" => true,
          "notify_user" => true
        },
        "description" => "Force password reset and revoke active sessions"
      },
      %{
        "action" => "trigger_scan",
        "params" => %{
          "scope" => "mailbox",
          "look_for_similar" => true
        },
        "description" => "Scan organization mailboxes for similar phishing emails"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "high",
          "category" => "phishing",
          "include_email_analysis" => true
        },
        "description" => "Create incident ticket with analysis"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["slack", "email"],
          "include_iocs" => true,
          "send_user_awareness" => true
        },
        "description" => "Notify security team and affected users"
      }
    ]
  },

  # ============================================================================
  # 3. DATA EXFILTRATION INVESTIGATION
  # ============================================================================
  %{
    name: "Data Exfiltration Investigation",
    description: """
    Investigates potential data exfiltration attempts including large file transfers,
    unusual cloud uploads, encrypted traffic to unknown destinations, and staging
    activity. Integrates with DLP solutions and network monitoring.
    """,
    trigger_type: "alert",
    trigger_conditions: %{
      "mitre_tactic" => "exfiltration",
      "severity" => "high"
    },
    enabled: true,
    require_approval: true,
    approval_timeout_minutes: 30,
    severity_threshold: "medium",
    tags: ["data-exfiltration", "DLP", "insider-threat", "exfiltration"],
    steps: [
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "network",
          "include_pcap" => true,
          "include_dns_queries" => true,
          "include_netflow" => true,
          "timeframe_hours" => 24
        },
        "description" => "Collect network forensics for traffic analysis"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "analyze_data_transfers",
          "check_cloud_uploads" => true,
          "check_usb_activity" => true,
          "check_email_attachments" => true
        },
        "description" => "Analyze all data transfer channels"
      },
      %{
        "action" => "enrich_ioc",
        "params" => %{
          "check_destination_reputation" => true,
          "check_geolocation" => true,
          "identify_data_classification" => true
        },
        "description" => "Enrich destination and data context"
      },
      %{
        "action" => "conditional",
        "params" => %{
          "condition" => %{
            "field" => "data_sensitivity",
            "operator" => "in",
            "value" => ["confidential", "secret", "pii", "phi"]
          },
          "true_step" => 5,
          "false_step" => 7
        },
        "description" => "Check data sensitivity level"
      },
      %{
        "action" => "isolate_host",
        "params" => %{"allow_investigation_access" => true},
        "description" => "Isolate host while allowing investigation"
      },
      %{
        "action" => "block_ip",
        "params" => %{"scope" => "organization"},
        "description" => "Block exfiltration destination"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "identify_affected_data",
          "generate_data_inventory" => true
        },
        "description" => "Identify all potentially exfiltrated data"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "critical",
          "category" => "data_breach",
          "include_compliance_team" => true,
          "include_legal_team" => true
        },
        "description" => "Create data breach incident ticket"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["slack", "pagerduty", "email"],
          "notify_dpo" => true,
          "notify_legal" => true
        },
        "description" => "Notify security, legal, and privacy teams"
      }
    ]
  },

  # ============================================================================
  # 4. INSIDER THREAT RESPONSE
  # ============================================================================
  %{
    name: "Insider Threat Response",
    description: """
    Responds to insider threat indicators including unauthorized access attempts,
    unusual working hours activity, bulk data access, and policy violations.
    Coordinates with HR and legal for proper handling.
    """,
    trigger_type: "alert",
    trigger_conditions: %{
      "detection_type" => "insider_threat",
      "severity" => "medium"
    },
    enabled: true,
    require_approval: true,
    approval_timeout_minutes: 60,
    severity_threshold: "medium",
    tags: ["insider-threat", "UEBA", "policy-violation", "HR-coordination"],
    steps: [
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "user_activity",
          "include_file_access" => true,
          "include_login_history" => true,
          "include_email_activity" => true,
          "include_cloud_access" => true,
          "timeframe_days" => 30
        },
        "description" => "Collect comprehensive user activity history"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "ueba_analysis",
          "compare_to_baseline" => true,
          "identify_anomalies" => true
        },
        "description" => "Perform UEBA analysis and baseline comparison"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "access_review",
          "check_privilege_escalation" => true,
          "check_unauthorized_access" => true
        },
        "description" => "Review access patterns and privilege usage"
      },
      %{
        "action" => "conditional",
        "params" => %{
          "condition" => %{
            "field" => "risk_score",
            "operator" => "greater_than",
            "value" => 75
          },
          "true_step" => 5,
          "false_step" => 7
        },
        "description" => "Evaluate risk score threshold"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "restrict_user_access",
          "require_mfa_everywhere" => true,
          "enable_enhanced_monitoring" => true
        },
        "description" => "Implement access restrictions"
      },
      %{
        "action" => "human_approval",
        "params" => %{
          "approvers" => ["security_manager", "hr_manager"],
          "timeout_minutes" => 30
        },
        "description" => "Require human approval for further action"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "high",
          "category" => "insider_threat",
          "visibility" => "restricted",
          "include_hr" => true,
          "include_legal" => true
        },
        "description" => "Create confidential incident ticket"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["secure_email"],
          "recipients" => ["security_manager", "hr_director", "legal_counsel"],
          "confidential" => true
        },
        "description" => "Send confidential notification to stakeholders"
      }
    ]
  },

  # ============================================================================
  # 5. APT/NATION-STATE ATTACK RESPONSE
  # ============================================================================
  %{
    name: "APT/Nation-State Attack Response",
    description: """
    Advanced playbook for sophisticated nation-state or APT attacks. Implements
    careful containment to avoid alerting the attacker, preserves evidence for
    attribution, and coordinates with threat intelligence teams.
    """,
    trigger_type: "alert",
    trigger_conditions: %{
      "detection_type" => "apt",
      "severity" => "critical"
    },
    enabled: true,
    require_approval: true,
    approval_timeout_minutes: 15,
    severity_threshold: "high",
    tags: ["APT", "nation-state", "advanced-threat", "attribution", "CISA"],
    steps: [
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "stealth_monitoring",
          "enable_enhanced_logging" => true,
          "capture_all_activity" => true,
          "do_not_alert_attacker" => true
        },
        "description" => "Enable stealth monitoring without alerting attacker"
      },
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "comprehensive",
          "include_memory" => true,
          "include_disk" => true,
          "include_network" => true,
          "include_timeline" => true,
          "preserve_chain_of_custody" => true
        },
        "description" => "Collect comprehensive forensic evidence"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "lateral_movement_detection",
          "scan_all_systems" => true,
          "identify_persistence" => true,
          "map_attacker_infrastructure" => true
        },
        "description" => "Map attacker presence across environment"
      },
      %{
        "action" => "enrich_ioc",
        "params" => %{
          "sources" => ["mandiant", "crowdstrike", "recorded_future"],
          "check_attribution" => true,
          "correlate_with_known_campaigns" => true
        },
        "description" => "Correlate with known APT campaigns"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "identify_all_compromised_systems",
          "build_attack_timeline" => true
        },
        "description" => "Build comprehensive attack timeline"
      },
      %{
        "action" => "human_approval",
        "params" => %{
          "approvers" => ["ciso", "incident_commander"],
          "message" => "APT detected. Review findings before coordinated containment.",
          "timeout_minutes" => 60
        },
        "description" => "Executive approval for containment"
      },
      %{
        "action" => "parallel",
        "params" => %{
          "steps" => [
            %{"action" => "isolate_host", "params" => %{"all_compromised" => true}},
            %{"action" => "block_ip", "params" => %{"all_c2" => true}},
            %{"action" => "block_domain", "params" => %{"all_c2" => true}},
            %{"action" => "disable_user", "params" => %{"all_compromised_accounts" => true}}
          ]
        },
        "description" => "Coordinated simultaneous containment"
      },
      %{
        "action" => "trigger_scan",
        "params" => %{
          "scope" => "organization",
          "scan_type" => "apt_indicators",
          "include_all_iocs" => true
        },
        "description" => "Organization-wide scan for APT indicators"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "critical",
          "category" => "apt_attack",
          "classification" => "confidential",
          "include_threat_intel_team" => true,
          "include_external_ir" => true
        },
        "description" => "Create critical APT incident ticket"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["secure_channel", "phone"],
          "recipients" => ["ciso", "ceo", "board_security_committee"],
          "include_attribution_assessment" => true,
          "consider_government_notification" => true
        },
        "description" => "Executive and potential government notification"
      }
    ]
  },

  # ============================================================================
  # 6. MALWARE OUTBREAK CONTAINMENT
  # ============================================================================
  %{
    name: "Malware Outbreak Containment",
    description: """
    Rapid response to malware spreading across the organization. Implements
    network segmentation, blocks propagation vectors, and coordinates
    organization-wide remediation efforts.
    """,
    trigger_type: "alert",
    trigger_conditions: %{
      "detection_type" => "malware",
      "affected_hosts_count" => 5,
      "severity" => "high"
    },
    enabled: true,
    require_approval: false,
    approval_timeout_minutes: 10,
    severity_threshold: "high",
    tags: ["malware", "outbreak", "containment", "propagation", "worm"],
    steps: [
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "emergency_network_segmentation",
          "isolate_affected_vlans" => true,
          "block_smb_laterally" => true,
          "block_wmi_laterally" => true
        },
        "description" => "Emergency network segmentation"
      },
      %{
        "action" => "parallel",
        "params" => %{
          "steps" => [
            %{"action" => "isolate_host", "params" => %{"all_infected" => true}},
            %{"action" => "kill_process", "params" => %{"all_infected_hosts" => true}},
            %{"action" => "quarantine_file", "params" => %{"all_instances" => true}}
          ]
        },
        "description" => "Simultaneous containment on all infected hosts"
      },
      %{
        "action" => "block_ip",
        "params" => %{
          "scope" => "organization",
          "block_at_perimeter" => true
        },
        "description" => "Block malware C2 at perimeter"
      },
      %{
        "action" => "enrich_ioc",
        "params" => %{
          "generate_yara_rule" => true,
          "generate_sigma_rule" => true,
          "submit_to_sandbox" => true
        },
        "description" => "Generate detection rules from malware sample"
      },
      %{
        "action" => "trigger_scan",
        "params" => %{
          "scope" => "organization",
          "scan_type" => "full",
          "use_generated_rules" => true,
          "priority" => "critical"
        },
        "description" => "Organization-wide emergency scan"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "identify_patient_zero",
          "correlate_timeline" => true
        },
        "description" => "Identify initial infection vector"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "critical",
          "category" => "malware_outbreak",
          "create_war_room" => true
        },
        "description" => "Create outbreak incident ticket and war room"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["all_hands", "slack", "pagerduty"],
          "message" => "CRITICAL: Malware outbreak in progress. Containment measures active.",
          "include_infection_count" => true
        },
        "description" => "Organization-wide security alert"
      }
    ]
  },

  # ============================================================================
  # 7. CREDENTIAL COMPROMISE RESPONSE
  # ============================================================================
  %{
    name: "Credential Compromise Response",
    description: """
    Responds to credential theft including LSASS dumping, Mimikatz activity,
    pass-the-hash attacks, and Kerberoasting. Integrates with identity
    providers to force password resets and revoke sessions.
    """,
    trigger_type: "alert",
    trigger_conditions: %{
      "mitre_tactic" => "credential-access",
      "severity" => "high"
    },
    enabled: true,
    require_approval: false,
    approval_timeout_minutes: 15,
    severity_threshold: "high",
    tags: ["credential-theft", "mimikatz", "LSASS", "kerberoasting", "pass-the-hash"],
    steps: [
      %{
        "action" => "kill_process",
        "params" => %{},
        "description" => "Terminate credential dumping tool"
      },
      %{
        "action" => "quarantine_file",
        "params" => %{},
        "description" => "Quarantine credential theft tool"
      },
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "memory",
          "capture_lsass" => true,
          "include_security_logs" => true,
          "include_kerberos_tickets" => true
        },
        "description" => "Collect memory and authentication forensics"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "identify_exposed_credentials",
          "check_logged_on_users" => true,
          "check_cached_credentials" => true,
          "check_service_accounts" => true
        },
        "description" => "Identify all potentially exposed credentials"
      },
      %{
        "action" => "parallel",
        "params" => %{
          "steps" => [
            %{
              "action" => "disable_user",
              "params" => %{
                "scope" => "all_exposed",
                "force_password_reset" => true,
                "revoke_sessions" => true,
                "revoke_tokens" => true
              }
            },
            %{
              "action" => "run_script",
              "params" => %{
                "script" => "invalidate_kerberos_tickets",
                "reset_krbtgt_twice" => false
              }
            }
          ]
        },
        "description" => "Reset credentials and revoke sessions"
      },
      %{
        "action" => "trigger_scan",
        "params" => %{
          "scope" => "domain_controllers",
          "scan_type" => "golden_ticket_detection"
        },
        "description" => "Check for golden ticket persistence"
      },
      %{
        "action" => "enrich_ioc",
        "params" => %{
          "correlate_tool_signatures" => true,
          "check_known_attacker_tools" => true
        },
        "description" => "Correlate with known credential theft tools"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "critical",
          "category" => "credential_compromise",
          "include_identity_team" => true
        },
        "description" => "Create credential compromise incident"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["slack", "pagerduty"],
          "include_affected_accounts" => true
        },
        "description" => "Alert security and identity teams"
      }
    ]
  },

  # ============================================================================
  # 8. SUPPLY CHAIN ATTACK INVESTIGATION
  # ============================================================================
  %{
    name: "Supply Chain Attack Investigation",
    description: """
    Investigates potential supply chain compromises including compromised
    software updates, malicious dependencies, and trusted vendor breaches.
    Coordinates with vendor security teams and procurement.
    """,
    trigger_type: "alert",
    trigger_conditions: %{
      "mitre_technique" => "T1195",
      "detection_type" => "supply_chain"
    },
    enabled: true,
    require_approval: true,
    approval_timeout_minutes: 30,
    severity_threshold: "high",
    tags: ["supply-chain", "vendor-risk", "SolarWinds-type", "software-integrity"],
    steps: [
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "freeze_software_deployments",
          "pause_updates" => true,
          "pause_ci_cd" => true
        },
        "description" => "Freeze all software deployments"
      },
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "software_inventory",
          "verify_signatures" => true,
          "verify_hashes" => true,
          "check_certificates" => true
        },
        "description" => "Verify software integrity across environment"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "identify_affected_software",
          "check_all_versions" => true,
          "check_dependencies" => true,
          "check_build_pipeline" => true
        },
        "description" => "Identify all affected software and dependencies"
      },
      %{
        "action" => "enrich_ioc",
        "params" => %{
          "check_sbom" => true,
          "correlate_with_known_attacks" => true,
          "check_vendor_advisories" => true
        },
        "description" => "Check software bill of materials and advisories"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "map_software_deployment",
          "identify_all_installations" => true
        },
        "description" => "Map deployment of compromised software"
      },
      %{
        "action" => "human_approval",
        "params" => %{
          "approvers" => ["ciso", "it_director"],
          "message" => "Supply chain compromise suspected. Review before remediation."
        },
        "description" => "Executive approval for remediation"
      },
      %{
        "action" => "parallel",
        "params" => %{
          "steps" => [
            %{"action" => "quarantine_file", "params" => %{"all_compromised_versions" => true}},
            %{"action" => "run_script", "params" => %{"script" => "rollback_to_known_good"}}
          ]
        },
        "description" => "Remediate compromised software"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "critical",
          "category" => "supply_chain_attack",
          "include_vendor_management" => true,
          "include_procurement" => true,
          "include_legal" => true
        },
        "description" => "Create supply chain incident ticket"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["secure_email", "phone"],
          "notify_vendor" => true,
          "notify_cisa" => true,
          "notify_isac" => true
        },
        "description" => "Coordinate with vendors and authorities"
      }
    ]
  },

  # ============================================================================
  # 9. CLOUD SECURITY INCIDENT RESPONSE
  # ============================================================================
  %{
    name: "Cloud Security Incident Response",
    description: """
    Responds to cloud security incidents including misconfigured resources,
    compromised IAM credentials, cryptojacking, and data exposure in
    AWS, Azure, and GCP environments.
    """,
    trigger_type: "alert",
    trigger_conditions: %{
      "detection_type" => "cloud_security",
      "severity" => "high"
    },
    enabled: true,
    require_approval: true,
    approval_timeout_minutes: 20,
    severity_threshold: "medium",
    tags: ["cloud", "AWS", "Azure", "GCP", "IAM", "misconfiguration"],
    steps: [
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "cloud_logs",
          "include_cloudtrail" => true,
          "include_azure_activity" => true,
          "include_gcp_audit" => true,
          "timeframe_hours" => 72
        },
        "description" => "Collect cloud provider audit logs"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "cloud_iam_analysis",
          "check_api_key_usage" => true,
          "check_role_assumptions" => true,
          "check_permission_changes" => true
        },
        "description" => "Analyze IAM activity and permissions"
      },
      %{
        "action" => "conditional",
        "params" => %{
          "condition" => %{
            "field" => "iam_compromise_detected",
            "operator" => "equals",
            "value" => true
          },
          "true_step" => 4,
          "false_step" => 6
        },
        "description" => "Check for IAM compromise"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "rotate_cloud_credentials",
          "rotate_access_keys" => true,
          "rotate_service_principals" => true,
          "revoke_temporary_credentials" => true
        },
        "description" => "Rotate compromised cloud credentials"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "remove_unauthorized_resources",
          "terminate_rogue_instances" => true,
          "remove_unauthorized_users" => true
        },
        "description" => "Remove attacker-created resources"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "cloud_configuration_audit",
          "check_public_exposure" => true,
          "check_encryption_status" => true,
          "check_network_acls" => true
        },
        "description" => "Audit cloud configuration"
      },
      %{
        "action" => "enrich_ioc",
        "params" => %{
          "check_source_ip_reputation" => true,
          "correlate_with_known_attacks" => true
        },
        "description" => "Enrich threat intelligence"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "high",
          "category" => "cloud_security",
          "include_cloud_team" => true,
          "include_devsecops" => true
        },
        "description" => "Create cloud security incident ticket"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["slack", "pagerduty"],
          "include_affected_resources" => true,
          "include_remediation_steps" => true
        },
        "description" => "Alert cloud and security teams"
      }
    ]
  },

  # ============================================================================
  # 10. DDOS MITIGATION
  # ============================================================================
  %{
    name: "DDoS Mitigation",
    description: """
    Automated response to DDoS attacks including volumetric, protocol, and
    application-layer attacks. Integrates with CDN providers, cloud DDoS
    protection services, and network infrastructure.
    """,
    trigger_type: "alert",
    trigger_conditions: %{
      "detection_type" => "ddos",
      "mitre_technique" => "T1498"
    },
    enabled: true,
    require_approval: false,
    approval_timeout_minutes: 5,
    severity_threshold: "high",
    tags: ["DDoS", "availability", "network", "CDN", "WAF"],
    steps: [
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "enable_ddos_protection",
          "activate_scrubbing" => true,
          "enable_rate_limiting" => true,
          "enable_geo_blocking" => true
        },
        "description" => "Activate DDoS protection services"
      },
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "network_traffic",
          "capture_attack_patterns" => true,
          "identify_attack_vectors" => true
        },
        "description" => "Capture attack traffic patterns"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "analyze_attack_characteristics",
          "identify_source_ips" => true,
          "identify_attack_type" => true,
          "calculate_bandwidth" => true
        },
        "description" => "Analyze attack characteristics"
      },
      %{
        "action" => "parallel",
        "params" => %{
          "steps" => [
            %{
              "action" => "run_script",
              "params" => %{
                "script" => "update_waf_rules",
                "block_attack_patterns" => true
              }
            },
            %{
              "action" => "block_ip",
              "params" => %{
                "scope" => "perimeter",
                "source_ips" => true
              }
            }
          ]
        },
        "description" => "Apply blocking rules"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "scale_infrastructure",
          "enable_auto_scaling" => true,
          "increase_capacity" => true
        },
        "description" => "Scale infrastructure to absorb attack"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "enable_cdn_protection",
          "activate_ddos_mode" => true,
          "enable_challenge_page" => true
        },
        "description" => "Activate CDN DDoS protection"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "critical",
          "category" => "ddos_attack",
          "include_network_team" => true,
          "include_isp" => true
        },
        "description" => "Create DDoS incident ticket"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["pagerduty", "slack"],
          "include_attack_metrics" => true,
          "notify_isp" => true,
          "notify_cdn_provider" => true
        },
        "description" => "Alert all stakeholders"
      }
    ]
  },

  # ============================================================================
  # 11. ZERO-DAY EXPLOIT RESPONSE
  # ============================================================================
  %{
    name: "Zero-Day Exploit Response",
    description: """
    Responds to zero-day exploits with unknown signatures. Implements
    behavioral containment, virtual patching, and coordinates with
    vendor and security research communities.
    """,
    trigger_type: "alert",
    trigger_conditions: %{
      "detection_type" => "zero_day",
      "severity" => "critical"
    },
    enabled: true,
    require_approval: true,
    approval_timeout_minutes: 15,
    severity_threshold: "high",
    tags: ["zero-day", "0day", "exploit", "vulnerability", "CVE"],
    steps: [
      %{
        "action" => "isolate_host",
        "params" => %{"preserve_for_analysis" => true},
        "description" => "Isolate affected system for analysis"
      },
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "comprehensive",
          "include_exploit_artifacts" => true,
          "include_crash_dumps" => true,
          "include_memory" => true,
          "preserve_for_research" => true
        },
        "description" => "Collect exploit artifacts for analysis"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "identify_vulnerable_systems",
          "check_software_versions" => true,
          "check_configurations" => true
        },
        "description" => "Identify all vulnerable systems"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "implement_virtual_patch",
          "block_exploit_patterns" => true,
          "update_waf_rules" => true,
          "update_ids_rules" => true
        },
        "description" => "Implement virtual patching"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "behavioral_monitoring",
          "enable_enhanced_detection" => true,
          "monitor_exploit_indicators" => true
        },
        "description" => "Enable enhanced behavioral monitoring"
      },
      %{
        "action" => "enrich_ioc",
        "params" => %{
          "submit_to_sandbox" => true,
          "correlate_with_threat_intel" => true,
          "check_for_similar_exploits" => true
        },
        "description" => "Analyze exploit and correlate intelligence"
      },
      %{
        "action" => "trigger_scan",
        "params" => %{
          "scope" => "organization",
          "scan_type" => "vulnerability",
          "check_exploitation_indicators" => true
        },
        "description" => "Scan for exploitation indicators"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "critical",
          "category" => "zero_day",
          "include_vulnerability_team" => true,
          "include_vendor_liaison" => true
        },
        "description" => "Create zero-day incident ticket"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["secure_email", "pagerduty"],
          "notify_vendor" => true,
          "notify_cert" => true,
          "share_with_isac" => true
        },
        "description" => "Coordinate disclosure and response"
      }
    ]
  },

  # ============================================================================
  # 12. LATERAL MOVEMENT DETECTION
  # ============================================================================
  %{
    name: "Lateral Movement Detection",
    description: """
    Responds to lateral movement indicators including pass-the-hash,
    pass-the-ticket, remote execution, and network scanning within
    the environment.
    """,
    trigger_type: "alert",
    trigger_conditions: %{
      "mitre_tactic" => "lateral-movement",
      "severity" => "high"
    },
    enabled: true,
    require_approval: true,
    approval_timeout_minutes: 20,
    severity_threshold: "medium",
    tags: ["lateral-movement", "network", "propagation", "PtH", "PtT"],
    steps: [
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "network",
          "include_smb_traffic" => true,
          "include_wmi_activity" => true,
          "include_rdp_sessions" => true,
          "include_psexec_activity" => true
        },
        "description" => "Collect lateral movement forensics"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "map_lateral_movement",
          "identify_source_host" => true,
          "identify_all_targets" => true,
          "build_movement_graph" => true
        },
        "description" => "Map lateral movement path"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "identify_credentials_used",
          "check_authentication_logs" => true,
          "identify_compromised_accounts" => true
        },
        "description" => "Identify credentials used for movement"
      },
      %{
        "action" => "conditional",
        "params" => %{
          "condition" => %{
            "field" => "critical_systems_accessed",
            "operator" => "equals",
            "value" => true
          },
          "true_step" => 5,
          "false_step" => 6
        },
        "description" => "Check if critical systems were accessed"
      },
      %{
        "action" => "parallel",
        "params" => %{
          "steps" => [
            %{"action" => "isolate_host", "params" => %{"all_affected" => true}},
            %{"action" => "disable_user", "params" => %{"compromised_accounts" => true}}
          ]
        },
        "description" => "Contain compromised systems and accounts"
      },
      %{
        "action" => "block_ip",
        "params" => %{
          "scope" => "internal_network",
          "block_source_host" => true
        },
        "description" => "Block source host network access"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "segment_network",
          "isolate_affected_vlan" => true
        },
        "description" => "Implement network segmentation"
      },
      %{
        "action" => "enrich_ioc",
        "params" => %{
          "identify_attack_tools" => true,
          "check_known_techniques" => true
        },
        "description" => "Identify tools and techniques used"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "high",
          "category" => "lateral_movement",
          "include_network_team" => true
        },
        "description" => "Create lateral movement incident"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["slack", "pagerduty"],
          "include_movement_graph" => true
        },
        "description" => "Alert with movement visualization"
      }
    ]
  },

  # ============================================================================
  # 13. BUSINESS EMAIL COMPROMISE
  # ============================================================================
  %{
    name: "Business Email Compromise",
    description: """
    Responds to BEC attacks including CEO fraud, invoice scams, and
    account takeover. Coordinates with finance, legal, and banks
    to prevent financial losses.
    """,
    trigger_type: "alert",
    trigger_conditions: %{
      "detection_type" => "bec",
      "severity" => "high"
    },
    enabled: true,
    require_approval: false,
    approval_timeout_minutes: 10,
    severity_threshold: "high",
    tags: ["BEC", "CEO-fraud", "invoice-fraud", "email-compromise", "financial"],
    steps: [
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "email",
          "include_full_thread" => true,
          "include_headers" => true,
          "include_similar_emails" => true,
          "timeframe_days" => 30
        },
        "description" => "Collect email forensics"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "analyze_email_compromise",
          "check_forwarding_rules" => true,
          "check_inbox_rules" => true,
          "check_delegate_access" => true
        },
        "description" => "Analyze mailbox for compromise indicators"
      },
      %{
        "action" => "conditional",
        "params" => %{
          "condition" => %{
            "field" => "financial_transaction_requested",
            "operator" => "equals",
            "value" => true
          },
          "true_step" => 4,
          "false_step" => 6
        },
        "description" => "Check for financial fraud attempt"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["phone", "secure_email"],
          "recipients" => ["cfo", "finance_controller"],
          "message" => "URGENT: BEC attack detected. Halt all pending wire transfers.",
          "priority" => "critical"
        },
        "description" => "Emergency alert to finance"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "contact_bank",
          "request_transfer_hold" => true
        },
        "description" => "Contact bank to hold suspicious transfers"
      },
      %{
        "action" => "disable_user",
        "params" => %{
          "revoke_sessions" => true,
          "force_password_reset" => true,
          "enable_mfa" => true
        },
        "description" => "Secure compromised account"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "remove_malicious_rules",
          "remove_forwarding" => true,
          "remove_inbox_rules" => true,
          "remove_delegates" => true
        },
        "description" => "Remove attacker persistence"
      },
      %{
        "action" => "trigger_scan",
        "params" => %{
          "scope" => "organization",
          "scan_type" => "bec_indicators",
          "check_similar_rules" => true
        },
        "description" => "Scan organization for similar compromises"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "critical",
          "category" => "bec",
          "include_finance" => true,
          "include_legal" => true
        },
        "description" => "Create BEC incident ticket"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["slack", "email"],
          "notify_cfo" => true,
          "notify_legal" => true,
          "report_to_fbi_ic3" => true
        },
        "description" => "Notify stakeholders and report to authorities"
      }
    ]
  },

  # ============================================================================
  # 14. CRYPTOMINING DETECTION
  # ============================================================================
  %{
    name: "Cryptomining Detection",
    description: """
    Detects and responds to cryptomining activity including unauthorized
    miners, compromised containers, and cloud resource abuse for
    cryptocurrency mining.
    """,
    trigger_type: "detection",
    trigger_conditions: %{
      "detection_type" => "cryptomining",
      "mitre_technique" => "T1496"
    },
    enabled: true,
    require_approval: false,
    approval_timeout_minutes: 15,
    severity_threshold: "medium",
    tags: ["cryptomining", "cryptojacking", "resource-hijacking", "monero"],
    steps: [
      %{
        "action" => "kill_process",
        "params" => %{},
        "description" => "Terminate mining process"
      },
      %{
        "action" => "quarantine_file",
        "params" => %{},
        "description" => "Quarantine miner binary"
      },
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "process",
          "include_command_line" => true,
          "include_parent_process" => true,
          "include_network_connections" => true
        },
        "description" => "Collect miner forensics"
      },
      %{
        "action" => "block_ip",
        "params" => %{
          "scope" => "organization",
          "block_mining_pools" => true
        },
        "description" => "Block mining pool connections"
      },
      %{
        "action" => "block_domain",
        "params" => %{
          "scope" => "dns",
          "block_known_pools" => true
        },
        "description" => "Block mining pool domains"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "identify_infection_vector",
          "check_docker_images" => true,
          "check_kubernetes_pods" => true,
          "check_scheduled_tasks" => true
        },
        "description" => "Identify how miner was deployed"
      },
      %{
        "action" => "trigger_scan",
        "params" => %{
          "scope" => "organization",
          "scan_type" => "cryptominer_detection",
          "check_containers" => true,
          "check_cloud_resources" => true
        },
        "description" => "Scan for additional miners"
      },
      %{
        "action" => "enrich_ioc",
        "params" => %{
          "identify_miner_family" => true,
          "identify_wallet_addresses" => true
        },
        "description" => "Identify miner variant and wallet"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "medium",
          "category" => "cryptomining",
          "include_cloud_team" => true
        },
        "description" => "Create cryptomining incident"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["slack"],
          "include_resource_impact" => true
        },
        "description" => "Alert security and cloud teams"
      }
    ]
  },

  # ============================================================================
  # 15. NETWORK INTRUSION RESPONSE
  # ============================================================================
  %{
    name: "Network Intrusion Response",
    description: """
    Responds to network intrusion attempts including exploitation of
    perimeter devices, unauthorized network access, and network-based
    attacks against internal systems.
    """,
    trigger_type: "alert",
    trigger_conditions: %{
      "mitre_tactic" => "initial-access",
      "detection_type" => "network_intrusion"
    },
    enabled: true,
    require_approval: true,
    approval_timeout_minutes: 15,
    severity_threshold: "high",
    tags: ["network-intrusion", "perimeter", "firewall", "IDS", "exploit"],
    steps: [
      %{
        "action" => "block_ip",
        "params" => %{
          "scope" => "perimeter",
          "duration" => "permanent"
        },
        "description" => "Block attacker IP at perimeter"
      },
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "network",
          "include_firewall_logs" => true,
          "include_ids_alerts" => true,
          "include_pcap" => true,
          "timeframe_hours" => 24
        },
        "description" => "Collect network forensics"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "analyze_intrusion_attempt",
          "identify_exploit_used" => true,
          "identify_target_vulnerability" => true
        },
        "description" => "Analyze intrusion attempt"
      },
      %{
        "action" => "conditional",
        "params" => %{
          "condition" => %{
            "field" => "intrusion_successful",
            "operator" => "equals",
            "value" => true
          },
          "true_step" => 5,
          "false_step" => 8
        },
        "description" => "Check if intrusion succeeded"
      },
      %{
        "action" => "isolate_host",
        "params" => %{"compromised_system" => true},
        "description" => "Isolate compromised system"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "check_lateral_movement",
          "scan_internal_network" => true
        },
        "description" => "Check for post-exploitation activity"
      },
      %{
        "action" => "trigger_scan",
        "params" => %{
          "scope" => "dmz",
          "scan_type" => "vulnerability",
          "check_similar_vulns" => true
        },
        "description" => "Scan DMZ for similar vulnerabilities"
      },
      %{
        "action" => "enrich_ioc",
        "params" => %{
          "check_attacker_reputation" => true,
          "correlate_with_campaigns" => true,
          "geo_locate_source" => true
        },
        "description" => "Enrich attacker intelligence"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "update_firewall_rules",
          "implement_compensating_controls" => true
        },
        "description" => "Implement additional protections"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "high",
          "category" => "network_intrusion",
          "include_network_team" => true,
          "include_vulnerability_team" => true
        },
        "description" => "Create intrusion incident ticket"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["pagerduty", "slack"],
          "include_attack_details" => true,
          "include_blocked_ips" => true
        },
        "description" => "Alert security and network teams"
      }
    ]
  },

  # ============================================================================
  # 16. PRIVILEGE ESCALATION RESPONSE
  # ============================================================================
  %{
    name: "Privilege Escalation Response",
    description: """
    Responds to privilege escalation attempts including UAC bypass,
    local privilege escalation exploits, and unauthorized admin access.
    """,
    trigger_type: "alert",
    trigger_conditions: %{
      "mitre_tactic" => "privilege-escalation",
      "severity" => "high"
    },
    enabled: true,
    require_approval: false,
    approval_timeout_minutes: 15,
    severity_threshold: "high",
    tags: ["privilege-escalation", "UAC-bypass", "local-exploit", "admin-access"],
    steps: [
      %{
        "action" => "kill_process",
        "params" => %{},
        "description" => "Terminate escalation process"
      },
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "process",
          "include_security_logs" => true,
          "include_privilege_changes" => true
        },
        "description" => "Collect privilege escalation artifacts"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "audit_privilege_changes",
          "check_new_admin_accounts" => true,
          "check_group_membership_changes" => true,
          "check_scheduled_tasks" => true
        },
        "description" => "Audit all privilege changes"
      },
      %{
        "action" => "conditional",
        "params" => %{
          "condition" => %{
            "field" => "persistent_admin_access",
            "operator" => "equals",
            "value" => true
          },
          "true_step" => 5,
          "false_step" => 7
        },
        "description" => "Check for persistent admin access"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "remove_unauthorized_access",
          "remove_admin_accounts" => true,
          "revert_group_changes" => true
        },
        "description" => "Remove unauthorized admin access"
      },
      %{
        "action" => "isolate_host",
        "params" => %{},
        "description" => "Isolate compromised host"
      },
      %{
        "action" => "enrich_ioc",
        "params" => %{
          "identify_exploit_cve" => true,
          "check_patch_status" => true
        },
        "description" => "Identify vulnerability exploited"
      },
      %{
        "action" => "trigger_scan",
        "params" => %{
          "scope" => "organization",
          "scan_type" => "privilege_audit"
        },
        "description" => "Audit privileges organization-wide"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "high",
          "category" => "privilege_escalation"
        },
        "description" => "Create privilege escalation ticket"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["slack", "pagerduty"]
        },
        "description" => "Alert security team"
      }
    ]
  },

  # ============================================================================
  # 17. PERSISTENCE MECHANISM REMOVAL
  # ============================================================================
  %{
    name: "Persistence Mechanism Removal",
    description: """
    Detects and removes persistence mechanisms including registry keys,
    scheduled tasks, services, startup items, and other autostart
    persistence techniques.
    """,
    trigger_type: "detection",
    trigger_conditions: %{
      "mitre_tactic" => "persistence",
      "severity" => "medium"
    },
    enabled: true,
    require_approval: true,
    approval_timeout_minutes: 20,
    severity_threshold: "medium",
    tags: ["persistence", "registry", "scheduled-task", "service", "autorun"],
    steps: [
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "autoruns",
          "include_registry" => true,
          "include_scheduled_tasks" => true,
          "include_services" => true,
          "include_startup_folders" => true,
          "include_wmi_subscriptions" => true
        },
        "description" => "Collect all persistence mechanisms"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "analyze_persistence",
          "compare_to_baseline" => true,
          "identify_anomalies" => true
        },
        "description" => "Analyze persistence against baseline"
      },
      %{
        "action" => "enrich_ioc",
        "params" => %{
          "check_file_reputation" => true,
          "check_signer" => true
        },
        "description" => "Check persistence binary reputation"
      },
      %{
        "action" => "human_approval",
        "params" => %{
          "approvers" => ["security_analyst"],
          "message" => "Review persistence mechanisms before removal",
          "include_analysis" => true
        },
        "description" => "Analyst approval for removal"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "remove_persistence",
          "remove_registry_keys" => true,
          "remove_scheduled_tasks" => true,
          "stop_and_remove_services" => true,
          "clean_startup_items" => true
        },
        "description" => "Remove identified persistence"
      },
      %{
        "action" => "quarantine_file",
        "params" => %{"all_persistence_binaries" => true},
        "description" => "Quarantine persistence binaries"
      },
      %{
        "action" => "trigger_scan",
        "params" => %{
          "scope" => "host",
          "scan_type" => "full",
          "verify_removal" => true
        },
        "description" => "Verify persistence removal"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "medium",
          "category" => "persistence"
        },
        "description" => "Create persistence removal ticket"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["slack"],
          "include_removed_items" => true
        },
        "description" => "Notify of persistence removal"
      }
    ]
  },

  # ============================================================================
  # 18. C2 COMMUNICATION BLOCK
  # ============================================================================
  %{
    name: "C2 Communication Block",
    description: """
    Rapidly blocks command and control communications. Identifies C2
    infrastructure, blocks at network layer, and hunts for other infected
    hosts using the same C2.
    """,
    trigger_type: "detection",
    trigger_conditions: %{
      "detection_type" => "c2_communication",
      "severity" => "high"
    },
    enabled: true,
    require_approval: false,
    approval_timeout_minutes: 5,
    severity_threshold: "high",
    tags: ["c2", "command-and-control", "network", "beacon", "callback"],
    steps: [
      %{
        "action" => "parallel",
        "params" => %{
          "steps" => [
            %{"action" => "block_ip", "params" => %{"scope" => "organization"}},
            %{"action" => "block_domain", "params" => %{"scope" => "dns_sinkhole"}},
            %{"action" => "kill_process", "params" => %{}}
          ]
        },
        "description" => "Immediately block C2 and terminate beacon"
      },
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "network",
          "include_pcap" => true,
          "include_dns_queries" => true,
          "timeframe_hours" => 72
        },
        "description" => "Capture C2 communication artifacts"
      },
      %{
        "action" => "enrich_ioc",
        "params" => %{
          "identify_c2_framework" => true,
          "check_known_c2_infrastructure" => true,
          "extract_beacon_config" => true
        },
        "description" => "Identify C2 framework and extract config"
      },
      %{
        "action" => "trigger_scan",
        "params" => %{
          "scope" => "organization",
          "scan_type" => "c2_detection",
          "use_extracted_iocs" => true
        },
        "description" => "Hunt for other infected hosts"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "extract_c2_domains",
          "check_dga" => true,
          "predict_future_domains" => true
        },
        "description" => "Extract and predict DGA domains"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "critical",
          "category" => "c2_compromise"
        },
        "description" => "Create C2 incident ticket"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["slack", "pagerduty"],
          "include_c2_details" => true,
          "include_affected_hosts" => true
        },
        "description" => "Alert with C2 details"
      }
    ]
  },

  # ============================================================================
  # 19. BROWSER EXTENSION THREAT
  # ============================================================================
  %{
    name: "Browser Extension Threat Response",
    description: """
    Responds to malicious browser extension activity including credential
    theft, session hijacking, and cryptocurrency theft extensions.
    """,
    trigger_type: "detection",
    trigger_conditions: %{
      "detection_type" => "browser_extension",
      "severity" => "high"
    },
    enabled: true,
    require_approval: false,
    approval_timeout_minutes: 10,
    severity_threshold: "medium",
    tags: ["browser", "extension", "chrome", "firefox", "credential-theft"],
    steps: [
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "remove_browser_extension",
          "browsers" => ["chrome", "firefox", "edge", "brave"],
          "force_close_browsers" => true
        },
        "description" => "Remove malicious extension from all browsers"
      },
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "browser",
          "include_extension_source" => true,
          "include_local_storage" => true,
          "include_cookies" => true
        },
        "description" => "Collect browser forensic artifacts"
      },
      %{
        "action" => "enrich_ioc",
        "params" => %{
          "analyze_extension" => true,
          "check_webstore_status" => true
        },
        "description" => "Analyze extension behavior"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "check_credential_exposure",
          "clear_stored_passwords" => false,
          "check_session_tokens" => true
        },
        "description" => "Check for credential/session exposure"
      },
      %{
        "action" => "trigger_scan",
        "params" => %{
          "scope" => "organization",
          "scan_type" => "browser_extension_audit"
        },
        "description" => "Scan organization for similar extensions"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "high",
          "category" => "browser_threat"
        },
        "description" => "Create browser threat ticket"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["slack"],
          "notify_affected_user" => true
        },
        "description" => "Notify security and affected user"
      }
    ]
  },

  # ============================================================================
  # 20. WEBSHELL DETECTION RESPONSE
  # ============================================================================
  %{
    name: "Webshell Detection Response",
    description: """
    Responds to webshell detection on web servers. Isolates the server,
    preserves evidence, and coordinates with web application security team.
    """,
    trigger_type: "detection",
    trigger_conditions: %{
      "detection_type" => "webshell",
      "mitre_technique" => "T1505.003"
    },
    enabled: true,
    require_approval: true,
    approval_timeout_minutes: 15,
    severity_threshold: "high",
    tags: ["webshell", "web-server", "persistence", "backdoor", "T1505"],
    steps: [
      %{
        "action" => "quarantine_file",
        "params" => %{},
        "description" => "Quarantine the webshell file"
      },
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "web_server",
          "include_access_logs" => true,
          "include_error_logs" => true,
          "include_uploaded_files" => true,
          "timeframe_days" => 30
        },
        "description" => "Collect web server forensics"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "identify_webshell_access",
          "parse_access_logs" => true,
          "identify_source_ips" => true
        },
        "description" => "Identify who accessed the webshell"
      },
      %{
        "action" => "block_ip",
        "params" => %{
          "scope" => "waf",
          "source_ips" => true
        },
        "description" => "Block attacker IPs at WAF"
      },
      %{
        "action" => "trigger_scan",
        "params" => %{
          "scope" => "webroot",
          "scan_type" => "webshell_detection",
          "check_modified_files" => true
        },
        "description" => "Scan webroot for additional webshells"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "identify_vulnerability",
          "check_cms_version" => true,
          "check_plugin_vulnerabilities" => true
        },
        "description" => "Identify how webshell was uploaded"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "critical",
          "category" => "webshell",
          "include_webapp_team" => true
        },
        "description" => "Create webshell incident ticket"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["slack", "pagerduty"],
          "include_webapp_team" => true
        },
        "description" => "Alert security and web application teams"
      }
    ]
  },

  # ============================================================================
  # 21. LIVING OFF THE LAND RESPONSE
  # ============================================================================
  %{
    name: "Living Off The Land Response",
    description: """
    Responds to LOLBin/LOLBas abuse where attackers use legitimate system
    tools for malicious purposes. Carefully balances containment with
    business continuity.
    """,
    trigger_type: "detection",
    trigger_conditions: %{
      "detection_type" => "lolbin",
      "severity" => "medium"
    },
    enabled: true,
    require_approval: true,
    approval_timeout_minutes: 15,
    severity_threshold: "medium",
    tags: ["lolbin", "lolbas", "powershell", "wmic", "certutil", "living-off-the-land"],
    steps: [
      %{
        "action" => "kill_process",
        "params" => %{},
        "description" => "Terminate abused LOLBin process"
      },
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "process",
          "include_command_line" => true,
          "include_parent_chain" => true,
          "include_loaded_modules" => true,
          "include_script_block_logs" => true
        },
        "description" => "Collect process and script forensics"
      },
      %{
        "action" => "enrich_ioc",
        "params" => %{
          "decode_obfuscation" => true,
          "extract_urls" => true,
          "identify_payload" => true
        },
        "description" => "Decode and analyze command"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "analyze_lolbin_abuse",
          "identify_technique" => true,
          "check_for_persistence" => true
        },
        "description" => "Analyze LOLBin technique used"
      },
      %{
        "action" => "trigger_scan",
        "params" => %{
          "scope" => "host",
          "scan_type" => "behavioral",
          "focus_on_lolbins" => true
        },
        "description" => "Scan for related LOLBin abuse"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "high",
          "category" => "lolbin_abuse"
        },
        "description" => "Create LOLBin abuse ticket"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["slack"],
          "include_technique_analysis" => true
        },
        "description" => "Notify with technique details"
      }
    ]
  },

  # ============================================================================
  # 22. USB THREAT RESPONSE
  # ============================================================================
  %{
    name: "USB Threat Response",
    description: """
    Responds to USB-based threats including autorun malware, BadUSB attacks,
    and data exfiltration via removable media.
    """,
    trigger_type: "detection",
    trigger_conditions: %{
      "detection_type" => "usb_threat",
      "severity" => "high"
    },
    enabled: true,
    require_approval: false,
    approval_timeout_minutes: 5,
    severity_threshold: "high",
    tags: ["usb", "removable-media", "badusb", "autorun", "data-theft"],
    steps: [
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "disable_usb_device",
          "block_autorun" => true
        },
        "description" => "Disable USB device and autorun"
      },
      %{
        "action" => "kill_process",
        "params" => %{},
        "description" => "Kill any malicious processes from USB"
      },
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "usb",
          "include_device_info" => true,
          "include_autorun_contents" => true,
          "include_file_listing" => true
        },
        "description" => "Collect USB device forensics"
      },
      %{
        "action" => "trigger_scan",
        "params" => %{
          "scope" => "usb_device",
          "scan_type" => "full",
          "include_hidden_files" => true
        },
        "description" => "Scan USB device contents"
      },
      %{
        "action" => "enrich_ioc",
        "params" => %{
          "check_device_reputation" => true,
          "identify_device_type" => true
        },
        "description" => "Identify USB device type and reputation"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "high",
          "category" => "usb_threat"
        },
        "description" => "Create USB threat ticket"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["slack"],
          "include_device_details" => true
        },
        "description" => "Notify with USB device details"
      }
    ]
  },

  # ============================================================================
  # 23. FILELESS MALWARE RESPONSE
  # ============================================================================
  %{
    name: "Fileless Malware Response",
    description: """
    Responds to fileless malware operating entirely in memory. Captures
    memory artifacts and terminates malicious processes while preserving
    forensic evidence.
    """,
    trigger_type: "detection",
    trigger_conditions: %{
      "detection_type" => "fileless_malware",
      "severity" => "critical"
    },
    enabled: true,
    require_approval: false,
    approval_timeout_minutes: 5,
    severity_threshold: "high",
    tags: ["fileless", "memory", "reflective-loading", "process-injection"],
    steps: [
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "memory",
          "full_memory_dump" => true,
          "include_process_memory" => true,
          "priority" => "immediate"
        },
        "description" => "Capture memory before termination (critical)"
      },
      %{
        "action" => "kill_process",
        "params" => %{
          "force" => true
        },
        "description" => "Terminate fileless malware process"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "analyze_injection",
          "check_process_hollowing" => true,
          "check_dll_injection" => true,
          "check_apc_injection" => true
        },
        "description" => "Analyze injection technique"
      },
      %{
        "action" => "trigger_scan",
        "params" => %{
          "scope" => "host",
          "scan_type" => "memory",
          "check_all_processes" => true
        },
        "description" => "Memory scan all processes"
      },
      %{
        "action" => "enrich_ioc",
        "params" => %{
          "extract_shellcode" => true,
          "identify_payload" => true,
          "check_known_frameworks" => true
        },
        "description" => "Analyze extracted memory artifacts"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "critical",
          "category" => "fileless_malware",
          "include_memory_analysis_team" => true
        },
        "description" => "Create fileless malware incident"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["pagerduty", "slack"],
          "severity" => "critical"
        },
        "description" => "Critical alert to security team"
      }
    ]
  },

  # ============================================================================
  # 24. DNS TUNNELING RESPONSE
  # ============================================================================
  %{
    name: "DNS Tunneling Response",
    description: """
    Responds to DNS tunneling for data exfiltration or C2 communication.
    Blocks malicious DNS traffic and identifies all affected systems.
    """,
    trigger_type: "detection",
    trigger_conditions: %{
      "detection_type" => "dns_tunneling",
      "mitre_technique" => "T1071.004"
    },
    enabled: true,
    require_approval: false,
    approval_timeout_minutes: 10,
    severity_threshold: "high",
    tags: ["dns", "tunneling", "exfiltration", "c2", "covert-channel"],
    steps: [
      %{
        "action" => "block_domain",
        "params" => %{
          "scope" => "dns_server",
          "include_subdomains" => true
        },
        "description" => "Block tunneling domain at DNS"
      },
      %{
        "action" => "kill_process",
        "params" => %{},
        "description" => "Terminate tunneling client"
      },
      %{
        "action" => "collect_forensics",
        "params" => %{
          "type" => "dns",
          "include_query_logs" => true,
          "include_pcap" => true,
          "timeframe_hours" => 48
        },
        "description" => "Collect DNS query forensics"
      },
      %{
        "action" => "run_script",
        "params" => %{
          "script" => "decode_dns_tunnel",
          "extract_exfiltrated_data" => true,
          "identify_tunnel_protocol" => true
        },
        "description" => "Decode and analyze tunnel contents"
      },
      %{
        "action" => "trigger_scan",
        "params" => %{
          "scope" => "organization",
          "scan_type" => "dns_anomaly",
          "check_entropy" => true
        },
        "description" => "Hunt for other DNS tunneling"
      },
      %{
        "action" => "create_ticket",
        "params" => %{
          "priority" => "high",
          "category" => "dns_tunneling"
        },
        "description" => "Create DNS tunneling incident"
      },
      %{
        "action" => "send_notification",
        "params" => %{
          "channels" => ["slack", "pagerduty"],
          "include_decoded_content" => true
        },
        "description" => "Alert with tunnel analysis"
      }
    ]
  }
]

for playbook_attrs <- playbooks do
  case Repo.get_by(PlaybookSchema, name: playbook_attrs.name) do
    nil ->
      %PlaybookSchema{}
      |> PlaybookSchema.changeset(playbook_attrs)
      |> Repo.insert!()
      IO.puts("  Created playbook: #{playbook_attrs.name}")

    existing ->
      existing
      |> PlaybookSchema.changeset(playbook_attrs)
      |> Repo.update!()
      IO.puts("  Updated playbook: #{playbook_attrs.name}")
  end
end

IO.puts("\nPlaybooks seeding complete! Created/updated #{length(playbooks)} playbooks.")
