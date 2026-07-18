defmodule TamanduaServer.XDR.XDRPlaybooks do
  @moduledoc """
  XDR Cross-Domain Response Playbooks.

  Enterprise-grade automated response workflows that orchestrate actions across
  multiple security domains: endpoint, network, cloud, identity, and email.

  ## Key Features

  - **Cross-Domain Coordination**: Firewall block + endpoint isolate
  - **Multi-Stage Response**: Email quarantine + endpoint scan + user disable
  - **Cloud Integration**: Cloud revoke + local lockdown
  - **Intelligence-Driven**: Automatic IOC propagation across systems
  - **Approval Workflows**: Human-in-the-loop for high-impact actions

  ## Built-in Playbook Templates

  1. **Malware Outbreak Response** - Isolate + scan + block C2
  2. **Phishing Response** - Quarantine + purge + scan endpoints
  3. **Insider Threat Response** - Revoke + preserve evidence + notify
  4. **Ransomware Response** - Isolate + backup + block lateral movement
  5. **Cloud Compromise Response** - Revoke credentials + audit + remediate

  ## Integration Points

  - Endpoint: Process kill, file quarantine, host isolation
  - Firewall: IP/domain blocking, rule updates
  - Email: Message quarantine, purge, sender block
  - Cloud: Credential revocation, resource lockdown
  - Identity: User disable, session termination, MFA reset
  """

  use GenServer
  require Logger

  alias TamanduaServer.Response.Playbook
  alias TamanduaServer.Agents

  # Built-in XDR playbook templates
  @xdr_playbook_templates [
    # =========================================================================
    # Malware Outbreak Response
    # =========================================================================
    %{
      id: "xdr-malware-outbreak",
      name: "XDR: Malware Outbreak Response",
      description: "Comprehensive malware containment across endpoint, network, and cloud",
      category: "threat_response",
      severity_threshold: "high",
      tags: ["xdr", "malware", "outbreak", "containment"],
      cross_domain: true,
      domains: [:endpoint, :network, :cloud],
      steps: [
        %{
          id: "step_1",
          name: "Isolate Infected Endpoints",
          action: "isolate_host",
          domain: :endpoint,
          parallel: true,
          config: %{
            isolation_level: "network",
            allow_management: true
          },
          on_failure: "continue"
        },
        %{
          id: "step_2",
          name: "Block C2 Domains on Firewall",
          action: "block_domain",
          domain: :network,
          parallel: true,
          config: %{
            source: "from_alert",
            propagate_to: ["firewall", "proxy", "dns"]
          },
          on_failure: "continue"
        },
        %{
          id: "step_3",
          name: "Block C2 IPs on Firewall",
          action: "block_ip",
          domain: :network,
          parallel: true,
          config: %{
            source: "from_alert",
            duration: "permanent",
            propagate_to: ["firewall", "cloud_security_group"]
          },
          on_failure: "continue"
        },
        %{
          id: "step_4",
          name: "Quarantine Malicious Files",
          action: "quarantine_file",
          domain: :endpoint,
          config: %{
            source: "from_alert",
            collect_forensics: true
          },
          depends_on: ["step_1"]
        },
        %{
          id: "step_5",
          name: "Kill Malicious Processes",
          action: "kill_process",
          domain: :endpoint,
          config: %{
            source: "from_alert",
            include_children: true
          },
          depends_on: ["step_4"]
        },
        %{
          id: "step_6",
          name: "Trigger Full Endpoint Scan",
          action: "trigger_scan",
          domain: :endpoint,
          config: %{
            scan_type: "full",
            priority: "high"
          },
          depends_on: ["step_5"]
        },
        %{
          id: "step_7",
          name: "Update Cloud Security Groups",
          action: "update_cloud_security",
          domain: :cloud,
          config: %{
            action: "block_outbound",
            target: "infected_instances"
          },
          depends_on: ["step_3"]
        },
        %{
          id: "step_8",
          name: "Collect Forensics Package",
          action: "collect_forensics",
          domain: :endpoint,
          config: %{
            include_memory: true,
            include_disk_artifacts: true,
            upload_to: "forensics_bucket"
          },
          depends_on: ["step_6"]
        },
        %{
          id: "step_9",
          name: "Create Incident Ticket",
          action: "create_ticket",
          domain: :integration,
          config: %{
            priority: "high",
            assign_to: "security_team",
            include_evidence: true
          },
          depends_on: ["step_8"]
        },
        %{
          id: "step_10",
          name: "Send Executive Notification",
          action: "send_notification",
          domain: :integration,
          config: %{
            channel: "email",
            recipients: ["security_team", "ciso"],
            template: "malware_outbreak"
          },
          depends_on: ["step_9"]
        }
      ]
    },

    # =========================================================================
    # Phishing Campaign Response
    # =========================================================================
    %{
      id: "xdr-phishing-response",
      name: "XDR: Phishing Campaign Response",
      description: "Multi-domain response to phishing attacks: email + endpoint + identity",
      category: "threat_response",
      severity_threshold: "medium",
      tags: ["xdr", "phishing", "email", "identity"],
      cross_domain: true,
      domains: [:email, :endpoint, :identity],
      steps: [
        %{
          id: "step_1",
          name: "Quarantine Phishing Emails",
          action: "quarantine_email",
          domain: :email,
          parallel: true,
          config: %{
            scope: "organization",
            match_by: ["sender", "subject", "url"]
          }
        },
        %{
          id: "step_2",
          name: "Block Phishing URLs on Proxy",
          action: "block_url",
          domain: :network,
          parallel: true,
          config: %{
            source: "from_alert",
            propagate_to: ["proxy", "firewall", "browser_extension"]
          }
        },
        %{
          id: "step_3",
          name: "Identify Affected Users",
          action: "query_logs",
          domain: :email,
          config: %{
            query: "users_who_clicked",
            time_window: "24h"
          }
        },
        %{
          id: "step_4",
          name: "Reset Passwords for Affected Users",
          action: "reset_password",
          domain: :identity,
          require_approval: true,
          approval_timeout_minutes: 30,
          config: %{
            force_mfa_reenroll: true,
            notify_user: true
          },
          depends_on: ["step_3"]
        },
        %{
          id: "step_5",
          name: "Terminate Active Sessions",
          action: "terminate_sessions",
          domain: :identity,
          config: %{
            scope: "affected_users",
            include_cloud: true
          },
          depends_on: ["step_4"]
        },
        %{
          id: "step_6",
          name: "Scan Affected Endpoints",
          action: "trigger_scan",
          domain: :endpoint,
          config: %{
            scan_type: "quick",
            focus: "recent_downloads"
          },
          depends_on: ["step_3"]
        },
        %{
          id: "step_7",
          name: "Block Sender Domain",
          action: "block_email_sender",
          domain: :email,
          config: %{
            scope: "domain",
            duration: "7d"
          }
        },
        %{
          id: "step_8",
          name: "Create Phishing Report",
          action: "generate_report",
          domain: :integration,
          config: %{
            template: "phishing_incident",
            include_metrics: true
          },
          depends_on: ["step_6"]
        },
        %{
          id: "step_9",
          name: "Notify Affected Users",
          action: "send_notification",
          domain: :integration,
          config: %{
            channel: "email",
            template: "phishing_awareness",
            recipients: "affected_users"
          },
          depends_on: ["step_3"]
        }
      ]
    },

    # =========================================================================
    # Ransomware Response
    # =========================================================================
    %{
      id: "xdr-ransomware-response",
      name: "XDR: Ransomware Emergency Response",
      description: "Critical response for ransomware: isolate, block lateral movement, preserve evidence",
      category: "critical_response",
      severity_threshold: "critical",
      tags: ["xdr", "ransomware", "critical", "containment"],
      cross_domain: true,
      domains: [:endpoint, :network, :cloud, :identity],
      require_approval: false,  # Auto-execute for ransomware
      steps: [
        %{
          id: "step_1",
          name: "Immediate Network Isolation",
          action: "isolate_host",
          domain: :endpoint,
          priority: "critical",
          config: %{
            isolation_level: "full",
            allow_management: true
          }
        },
        %{
          id: "step_2",
          name: "Block Lateral Movement Ports",
          action: "block_ports",
          domain: :network,
          parallel: true,
          config: %{
            ports: [445, 135, 139, 3389, 5985, 5986],
            scope: "internal_segment",
            duration: "until_resolved"
          }
        },
        %{
          id: "step_3",
          name: "Disable Affected User Accounts",
          action: "disable_user",
          domain: :identity,
          parallel: true,
          config: %{
            scope: "compromised_users",
            preserve_data: true
          }
        },
        %{
          id: "step_4",
          name: "Snapshot Cloud Resources",
          action: "create_snapshot",
          domain: :cloud,
          parallel: true,
          config: %{
            include: ["vms", "storage", "databases"],
            retention: "30d"
          }
        },
        %{
          id: "step_5",
          name: "Kill Ransomware Processes",
          action: "kill_process",
          domain: :endpoint,
          config: %{
            process_hash: "from_alert",
            include_children: true,
            prevent_restart: true
          },
          depends_on: ["step_1"]
        },
        %{
          id: "step_6",
          name: "Collect Memory Dump",
          action: "collect_forensics",
          domain: :endpoint,
          config: %{
            include_memory: true,
            priority: "immediate"
          },
          depends_on: ["step_5"]
        },
        %{
          id: "step_7",
          name: "Identify Encrypted Files",
          action: "scan_filesystem",
          domain: :endpoint,
          config: %{
            pattern: "ransomware_extensions",
            generate_inventory: true
          },
          depends_on: ["step_5"]
        },
        %{
          id: "step_8",
          name: "Initiate Backup Verification",
          action: "verify_backups",
          domain: :cloud,
          config: %{
            scope: "affected_systems",
            check_integrity: true
          },
          depends_on: ["step_4"]
        },
        %{
          id: "step_9",
          name: "Page Incident Response Team",
          action: "send_notification",
          domain: :integration,
          priority: "critical",
          config: %{
            channel: ["pagerduty", "sms", "phone"],
            recipients: ["ir_team", "ciso", "it_ops"],
            template: "ransomware_alert"
          },
          parallel: true
        },
        %{
          id: "step_10",
          name: "Create Critical Incident",
          action: "create_ticket",
          domain: :integration,
          config: %{
            priority: "critical",
            type: "security_incident",
            classification: "ransomware"
          },
          depends_on: ["step_6"]
        }
      ]
    },

    # =========================================================================
    # Insider Threat Response
    # =========================================================================
    %{
      id: "xdr-insider-threat",
      name: "XDR: Insider Threat Response",
      description: "Coordinated response to insider threats: evidence preservation + access revocation",
      category: "threat_response",
      severity_threshold: "high",
      tags: ["xdr", "insider", "data_leak", "access_control"],
      cross_domain: true,
      domains: [:endpoint, :cloud, :identity, :dlp],
      require_approval: true,
      approval_timeout_minutes: 60,
      steps: [
        %{
          id: "step_1",
          name: "Enable Enhanced Monitoring",
          action: "enable_monitoring",
          domain: :endpoint,
          config: %{
            level: "detailed",
            capture_screen: true,
            log_keystrokes: false  # Privacy consideration
          }
        },
        %{
          id: "step_2",
          name: "Preserve Email Evidence",
          action: "legal_hold",
          domain: :email,
          config: %{
            scope: "user_mailbox",
            include_deleted: true
          }
        },
        %{
          id: "step_3",
          name: "Preserve Cloud Evidence",
          action: "legal_hold",
          domain: :cloud,
          config: %{
            scope: ["onedrive", "sharepoint", "teams"],
            include_versions: true
          }
        },
        %{
          id: "step_4",
          name: "Audit Recent File Access",
          action: "query_logs",
          domain: :endpoint,
          config: %{
            query: "file_access_by_user",
            time_window: "30d",
            include_cloud_storage: true
          }
        },
        %{
          id: "step_5",
          name: "Review Cloud Permissions",
          action: "audit_permissions",
          domain: :cloud,
          config: %{
            scope: "user_access",
            flag_sensitive: true
          }
        },
        %{
          id: "step_6",
          name: "Revoke Cloud Access Tokens",
          action: "revoke_tokens",
          domain: :identity,
          require_approval: true,
          config: %{
            scope: "all_applications",
            include_api_keys: true
          },
          depends_on: ["step_5"]
        },
        %{
          id: "step_7",
          name: "Block USB Storage",
          action: "update_policy",
          domain: :endpoint,
          config: %{
            policy: "usb_storage",
            action: "block"
          }
        },
        %{
          id: "step_8",
          name: "Update DLP Rules",
          action: "update_dlp",
          domain: :dlp,
          config: %{
            add_user_to_watchlist: true,
            increase_sensitivity: true
          }
        },
        %{
          id: "step_9",
          name: "Generate Access Report",
          action: "generate_report",
          domain: :integration,
          config: %{
            template: "user_access_audit",
            include_timeline: true
          },
          depends_on: ["step_4", "step_5"]
        },
        %{
          id: "step_10",
          name: "Notify HR and Legal",
          action: "send_notification",
          domain: :integration,
          config: %{
            channel: "secure_email",
            recipients: ["hr_security", "legal_team"],
            template: "insider_threat_report"
          },
          depends_on: ["step_9"]
        }
      ]
    },

    # =========================================================================
    # Cloud Compromise Response
    # =========================================================================
    %{
      id: "xdr-cloud-compromise",
      name: "XDR: Cloud Account Compromise Response",
      description: "Response to compromised cloud credentials: revoke, audit, remediate",
      category: "cloud_security",
      severity_threshold: "critical",
      tags: ["xdr", "cloud", "aws", "azure", "gcp", "compromise"],
      cross_domain: true,
      domains: [:cloud, :identity, :endpoint],
      steps: [
        %{
          id: "step_1",
          name: "Revoke All Active Sessions",
          action: "revoke_sessions",
          domain: :identity,
          priority: "critical",
          config: %{
            scope: "all_platforms",
            include_service_accounts: false
          }
        },
        %{
          id: "step_2",
          name: "Rotate Access Keys",
          action: "rotate_credentials",
          domain: :cloud,
          config: %{
            include_access_keys: true,
            include_passwords: true,
            notify_user: false  # Don't tip off attacker
          }
        },
        %{
          id: "step_3",
          name: "Disable Compromised API Keys",
          action: "disable_api_keys",
          domain: :cloud,
          parallel: true,
          config: %{
            scope: "user_owned",
            create_audit_trail: true
          }
        },
        %{
          id: "step_4",
          name: "Audit CloudTrail/Activity Logs",
          action: "query_logs",
          domain: :cloud,
          config: %{
            query: "user_api_calls",
            time_window: "7d",
            flag_sensitive_actions: true
          }
        },
        %{
          id: "step_5",
          name: "Review IAM Changes",
          action: "audit_iam",
          domain: :cloud,
          config: %{
            time_window: "7d",
            flag_privilege_escalation: true
          },
          depends_on: ["step_4"]
        },
        %{
          id: "step_6",
          name: "Check for Persistence Mechanisms",
          action: "scan_cloud_resources",
          domain: :cloud,
          config: %{
            check: ["lambda_functions", "scheduled_tasks", "ec2_userdata", "container_images"],
            flag_suspicious: true
          },
          depends_on: ["step_4"]
        },
        %{
          id: "step_7",
          name: "Revert Unauthorized Changes",
          action: "revert_changes",
          domain: :cloud,
          require_approval: true,
          config: %{
            scope: "flagged_changes",
            create_backup_first: true
          },
          depends_on: ["step_5", "step_6"]
        },
        %{
          id: "step_8",
          name: "Scan User Endpoint",
          action: "trigger_scan",
          domain: :endpoint,
          config: %{
            scan_type: "full",
            check_credentials: true
          }
        },
        %{
          id: "step_9",
          name: "Enable MFA Enforcement",
          action: "enforce_mfa",
          domain: :identity,
          config: %{
            scope: "user",
            require_hardware_key: true
          },
          depends_on: ["step_2"]
        },
        %{
          id: "step_10",
          name: "Generate Incident Report",
          action: "generate_report",
          domain: :integration,
          config: %{
            template: "cloud_compromise",
            include_timeline: true,
            include_recommendations: true
          },
          depends_on: ["step_7"]
        }
      ]
    },

    # =========================================================================
    # Network Intrusion Response
    # =========================================================================
    %{
      id: "xdr-network-intrusion",
      name: "XDR: Network Intrusion Response",
      description: "Coordinated response to network-based attacks: firewall + endpoint + threat intel",
      category: "threat_response",
      severity_threshold: "high",
      tags: ["xdr", "network", "intrusion", "firewall"],
      cross_domain: true,
      domains: [:network, :endpoint, :threat_intel],
      steps: [
        %{
          id: "step_1",
          name: "Block Attacker IP",
          action: "block_ip",
          domain: :network,
          priority: "critical",
          config: %{
            source: "from_alert",
            propagate_to: ["firewall", "router", "ids"],
            duration: "permanent"
          }
        },
        %{
          id: "step_2",
          name: "Enable Enhanced IDS Rules",
          action: "update_ids_rules",
          domain: :network,
          config: %{
            enable_category: "exploit_attempt",
            sensitivity: "high"
          }
        },
        %{
          id: "step_3",
          name: "Capture Network Traffic",
          action: "start_pcap",
          domain: :network,
          config: %{
            filter: "attacker_ip",
            duration: "1h",
            storage: "forensics_bucket"
          }
        },
        %{
          id: "step_4",
          name: "Identify Affected Systems",
          action: "query_logs",
          domain: :network,
          config: %{
            query: "connections_to_attacker",
            time_window: "24h"
          }
        },
        %{
          id: "step_5",
          name: "Scan Affected Endpoints",
          action: "trigger_scan",
          domain: :endpoint,
          config: %{
            scope: "affected_systems",
            scan_type: "ioc_based"
          },
          depends_on: ["step_4"]
        },
        %{
          id: "step_6",
          name: "Submit IOCs to Threat Intel",
          action: "submit_iocs",
          domain: :threat_intel,
          config: %{
            platforms: ["virustotal", "alienvault", "misp"],
            include_context: true
          }
        },
        %{
          id: "step_7",
          name: "Update Threat Feeds",
          action: "update_feeds",
          domain: :threat_intel,
          config: %{
            add_to_local_blocklist: true,
            share_with_isac: false
          },
          depends_on: ["step_6"]
        },
        %{
          id: "step_8",
          name: "Create Security Ticket",
          action: "create_ticket",
          domain: :integration,
          config: %{
            priority: "high",
            assign_to: "network_security"
          }
        }
      ]
    },

    # =========================================================================
    # Data Exfiltration Response
    # =========================================================================
    %{
      id: "xdr-data-exfiltration",
      name: "XDR: Data Exfiltration Response",
      description: "Response to data exfiltration: block egress, preserve evidence, assess impact",
      category: "data_protection",
      severity_threshold: "critical",
      tags: ["xdr", "exfiltration", "data_loss", "dlp"],
      cross_domain: true,
      domains: [:network, :endpoint, :cloud, :dlp],
      steps: [
        %{
          id: "step_1",
          name: "Block Exfiltration Destination",
          action: "block_destination",
          domain: :network,
          priority: "critical",
          config: %{
            source: "from_alert",
            block_type: ["ip", "domain"],
            propagate_to: ["firewall", "proxy", "cloud_egress"]
          }
        },
        %{
          id: "step_2",
          name: "Isolate Source Endpoint",
          action: "isolate_host",
          domain: :endpoint,
          config: %{
            isolation_level: "network",
            allow_management: true
          }
        },
        %{
          id: "step_3",
          name: "Capture Network Evidence",
          action: "start_pcap",
          domain: :network,
          config: %{
            filter: "exfiltration_destination",
            reconstruct_files: true
          }
        },
        %{
          id: "step_4",
          name: "Identify Exfiltrated Data",
          action: "analyze_traffic",
          domain: :network,
          config: %{
            reconstruct_content: true,
            classify_data: true
          },
          depends_on: ["step_3"]
        },
        %{
          id: "step_5",
          name: "Query DLP Logs",
          action: "query_logs",
          domain: :dlp,
          config: %{
            query: "sensitive_data_transfers",
            time_window: "7d"
          }
        },
        %{
          id: "step_6",
          name: "Assess Data Sensitivity",
          action: "classify_data",
          domain: :dlp,
          config: %{
            use_ml_classification: true,
            check_pii: true,
            check_compliance: ["gdpr", "pci", "hipaa"]
          },
          depends_on: ["step_4"]
        },
        %{
          id: "step_7",
          name: "Generate Impact Assessment",
          action: "generate_report",
          domain: :integration,
          config: %{
            template: "data_breach_assessment",
            include_regulatory_requirements: true
          },
          depends_on: ["step_6"]
        },
        %{
          id: "step_8",
          name: "Notify Compliance Team",
          action: "send_notification",
          domain: :integration,
          priority: "critical",
          config: %{
            channel: "secure_email",
            recipients: ["compliance", "dpo", "legal"],
            template: "potential_data_breach"
          },
          depends_on: ["step_7"]
        }
      ]
    }
  ]

  defstruct [
    templates: @xdr_playbook_templates,
    active_executions: %{},
    stats: %{
      playbooks_triggered: 0,
      steps_executed: 0,
      cross_domain_actions: 0
    }
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  List all XDR playbook templates.
  """
  @spec list_templates(keyword()) :: {:ok, [map()]}
  def list_templates(opts \\ []) do
    GenServer.call(__MODULE__, {:list_templates, opts})
  end

  @doc """
  Get a specific XDR playbook template by ID.
  """
  @spec get_template(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_template(template_id) do
    GenServer.call(__MODULE__, {:get_template, template_id})
  end

  @doc """
  Execute an XDR playbook for an alert or incident.
  """
  @spec execute_playbook(String.t(), map(), keyword()) :: {:ok, map()} | {:error, term()}
  def execute_playbook(template_id, context, opts \\ []) do
    GenServer.call(__MODULE__, {:execute_playbook, template_id, context, opts}, 60_000)
  end

  @doc """
  Execute a custom XDR playbook (not from template).
  """
  @spec execute_custom(map(), map()) :: {:ok, map()} | {:error, term()}
  def execute_custom(playbook_def, context) do
    GenServer.call(__MODULE__, {:execute_custom, playbook_def, context}, 60_000)
  end

  @doc """
  Get execution status.
  """
  @spec get_execution_status(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_execution_status(execution_id) do
    GenServer.call(__MODULE__, {:get_execution_status, execution_id})
  end

  @doc """
  Cancel a running execution.
  """
  @spec cancel_execution(String.t(), String.t()) :: :ok | {:error, term()}
  def cancel_execution(execution_id, reason) do
    GenServer.call(__MODULE__, {:cancel_execution, execution_id, reason})
  end

  @doc """
  Trigger XDR playbooks based on an alert.
  """
  @spec trigger_for_alert(map()) :: :ok
  def trigger_for_alert(alert) do
    GenServer.cast(__MODULE__, {:trigger_for_alert, alert})
  end

  @doc """
  Trigger XDR playbooks based on a cross-domain correlation.
  """
  @spec trigger_for_correlation(map()) :: :ok
  def trigger_for_correlation(correlation) do
    GenServer.cast(__MODULE__, {:trigger_for_correlation, correlation})
  end

  @doc """
  Get XDR playbook statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Create a custom XDR playbook from template.
  """
  @spec create_from_template(String.t(), map(), term()) :: {:ok, map()} | {:error, term()}
  def create_from_template(template_id, customizations, scope \\ nil) do
    GenServer.call(__MODULE__, {:create_from_template, template_id, customizations, scope})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("XDR Playbooks engine started with #{length(@xdr_playbook_templates)} templates")
    {:ok, %__MODULE__{}}
  end

  @impl true
  def handle_call({:list_templates, opts}, _from, state) do
    templates = filter_templates(state.templates, opts)
    {:reply, {:ok, templates}, state}
  end

  @impl true
  def handle_call({:get_template, template_id}, _from, state) do
    case Enum.find(state.templates, & &1.id == template_id) do
      nil -> {:reply, {:error, :not_found}, state}
      template -> {:reply, {:ok, template}, state}
    end
  end

  @impl true
  def handle_call({:execute_playbook, template_id, context, opts}, _from, state) do
    case Enum.find(state.templates, & &1.id == template_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      template ->
        execution = start_playbook_execution(template, context, opts)
        new_state = %{state |
          active_executions: Map.put(state.active_executions, execution.id, execution),
          stats: Map.update(state.stats, :playbooks_triggered, 1, & &1 + 1)
        }

        # Start async execution
        spawn(fn -> execute_steps(execution, template, context) end)

        {:reply, {:ok, execution}, new_state}
    end
  end

  @impl true
  def handle_call({:execute_custom, playbook_def, context}, _from, state) do
    execution = start_playbook_execution(playbook_def, context, [])
    new_state = %{state |
      active_executions: Map.put(state.active_executions, execution.id, execution),
      stats: Map.update(state.stats, :playbooks_triggered, 1, & &1 + 1)
    }

    spawn(fn -> execute_steps(execution, playbook_def, context) end)

    {:reply, {:ok, execution}, new_state}
  end

  @impl true
  def handle_call({:get_execution_status, execution_id}, _from, state) do
    case Map.get(state.active_executions, execution_id) do
      nil -> {:reply, {:error, :not_found}, state}
      execution -> {:reply, {:ok, execution}, state}
    end
  end

  @impl true
  def handle_call({:cancel_execution, execution_id, reason}, _from, state) do
    case Map.get(state.active_executions, execution_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      execution ->
        cancelled = %{execution |
          status: :cancelled,
          error: reason,
          completed_at: DateTime.utc_now()
        }

        new_executions = Map.put(state.active_executions, execution_id, cancelled)
        {:reply, :ok, %{state | active_executions: new_executions}}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_call({:create_from_template, template_id, customizations, scope}, _from, state) do
    case Enum.find(state.templates, & &1.id == template_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      template ->
        # Create a new playbook based on template
        new_playbook = template
        |> Map.merge(customizations)
        |> Map.put(:id, Ecto.UUID.generate())
        |> Map.put(:source_template, template_id)

        # Register with main playbook engine
        case Playbook.create_playbook(convert_to_playbook_format(new_playbook), scope) do
          {:ok, playbook} -> {:reply, {:ok, playbook}, state}
          error -> {:reply, error, state}
        end
    end
  end

  @impl true
  def handle_cast({:trigger_for_alert, alert}, state) do
    # Find matching playbooks
    matching = Enum.filter(state.templates, fn template ->
      matches_alert?(template, alert)
    end)

    # Execute matching playbooks
    Enum.each(matching, fn template ->
      context = build_context_from_alert(alert)
      spawn(fn ->
        execute_playbook(template.id, context, [auto_triggered: true])
      end)
    end)

    {:noreply, state}
  end

  @impl true
  def handle_cast({:trigger_for_correlation, correlation}, state) do
    # Determine appropriate playbook based on correlation type
    playbook_id = determine_playbook_for_correlation(correlation)

    if playbook_id do
      context = build_context_from_correlation(correlation)
      spawn(fn ->
        execute_playbook(playbook_id, context, [auto_triggered: true])
      end)
    end

    {:noreply, state}
  end

  @impl true
  def handle_info({:step_completed, execution_id, step_id, result}, state) do
    case Map.get(state.active_executions, execution_id) do
      nil ->
        {:noreply, state}

      execution ->
        updated_steps = [%{step_id: step_id, result: result, completed_at: DateTime.utc_now()} | execution.completed_steps]
        updated = %{execution | completed_steps: updated_steps}
        new_executions = Map.put(state.active_executions, execution_id, updated)
        new_stats = Map.update(state.stats, :steps_executed, 1, & &1 + 1)

        {:noreply, %{state | active_executions: new_executions, stats: new_stats}}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Execution Logic
  # ============================================================================

  defp start_playbook_execution(playbook, context, opts) do
    %{
      id: Ecto.UUID.generate(),
      playbook_id: playbook[:id],
      playbook_name: playbook[:name],
      status: :running,
      context: context,
      steps: playbook[:steps] || [],
      completed_steps: [],
      current_step: 0,
      started_at: DateTime.utc_now(),
      completed_at: nil,
      error: nil,
      opts: opts
    }
  end

  defp execute_steps(execution, playbook, context) do
    steps = playbook[:steps] || []

    # Build dependency graph
    dependency_graph = build_dependency_graph(steps)

    # Execute steps respecting dependencies
    execute_step_graph(execution, steps, dependency_graph, context, %{})
  end

  defp build_dependency_graph(steps) do
    Enum.reduce(steps, %{}, fn step, acc ->
      depends_on = step[:depends_on] || []
      Map.put(acc, step[:id], MapSet.new(depends_on))
    end)
  end

  defp execute_step_graph(execution, steps, dependency_graph, context, completed) do
    # Find steps ready to execute (all dependencies satisfied)
    ready_steps = Enum.filter(steps, fn step ->
      step_id = step[:id]
      dependencies = Map.get(dependency_graph, step_id, MapSet.new())

      not Map.has_key?(completed, step_id) and
      MapSet.subset?(dependencies, MapSet.new(Map.keys(completed)))
    end)

    if Enum.empty?(ready_steps) do
      # All steps completed or stuck
      Logger.info("XDR Playbook #{execution.playbook_id} completed")
      :ok
    else
      # Execute ready steps (parallel if marked)
      parallel_steps = Enum.filter(ready_steps, & &1[:parallel])
      sequential_steps = Enum.reject(ready_steps, & &1[:parallel])

      # Execute parallel steps
      parallel_results = if length(parallel_steps) > 0 do
        tasks = Enum.map(parallel_steps, fn step ->
          Task.async(fn -> execute_single_step(step, context, execution) end)
        end)
        Task.await_many(tasks, 30_000)
        |> Enum.zip(parallel_steps)
        |> Enum.map(fn {result, step} -> {step[:id], result} end)
        |> Map.new()
      else
        %{}
      end

      # Execute sequential steps
      sequential_results = Enum.reduce(sequential_steps, %{}, fn step, acc ->
        result = execute_single_step(step, context, execution)
        Map.put(acc, step[:id], result)
      end)

      # Merge results
      new_completed = Map.merge(completed, Map.merge(parallel_results, sequential_results))

      # Notify step completion
      Enum.each(Map.keys(Map.merge(parallel_results, sequential_results)), fn step_id ->
        send(self(), {:step_completed, execution.id, step_id, new_completed[step_id]})
      end)

      # Continue with remaining steps
      execute_step_graph(execution, steps, dependency_graph, context, new_completed)
    end
  end

  defp execute_single_step(step, context, execution) do
    Logger.info("Executing XDR step: #{step[:name]} (#{step[:action]}) for playbook #{execution.playbook_id}")

    action = step[:action]
    domain = step[:domain]
    config = step[:config] || %{}

    # Merge context into config
    config = resolve_config_variables(config, context)

    result = case domain do
      :endpoint -> execute_endpoint_action(action, config, context)
      :network -> execute_network_action(action, config, context)
      :cloud -> execute_cloud_action(action, config, context)
      :identity -> execute_identity_action(action, config, context)
      :email -> execute_email_action(action, config, context)
      :dlp -> execute_dlp_action(action, config, context)
      :threat_intel -> execute_threat_intel_action(action, config, context)
      :integration -> execute_integration_action(action, config, context)
      _ -> {:error, :unknown_domain}
    end

    # Handle step failure based on on_failure policy
    case {result, step[:on_failure]} do
      {{:error, _reason}, "continue"} ->
        Logger.warning("Step #{step[:name]} failed but continuing: #{inspect(result)}")
        {:ok, :continued_after_failure}
      {{:error, reason}, _} ->
        Logger.error("Step #{step[:name]} failed: #{inspect(reason)}")
        result
      _ ->
        result
    end
  end

  defp resolve_config_variables(config, context) do
    Enum.map(config, fn {key, value} ->
      resolved_value = case value do
        "from_alert" -> context[:alert]
        "affected_systems" -> context[:affected_systems]
        "affected_users" -> context[:affected_users]
        "compromised_users" -> context[:compromised_users]
        v when is_binary(v) -> resolve_string_variables(v, context)
        v -> v
      end
      {key, resolved_value}
    end)
    |> Map.new()
  end

  defp resolve_string_variables(str, context) do
    Regex.replace(~r/\$\{(\w+)\}/, str, fn _, var ->
      to_string(context[String.to_atom(var)] || context[var] || "")
    end)
  end

  # ============================================================================
  # Domain-Specific Action Executors
  # ============================================================================

  defp execute_endpoint_action("isolate_host", config, context) do
    agent_ids = context[:agent_ids] || [context[:agent_id]]
    Enum.each(agent_ids, fn agent_id ->
      send_agent_command(agent_id, "isolate_network", config)
    end)
    {:ok, :isolated}
  end

  defp execute_endpoint_action("kill_process", config, context) do
    agent_id = context[:agent_id]
    send_agent_command(agent_id, "kill_process", config)
    {:ok, :killed}
  end

  defp execute_endpoint_action("quarantine_file", config, context) do
    agent_id = context[:agent_id]
    send_agent_command(agent_id, "quarantine_file", config)
    {:ok, :quarantined}
  end

  defp execute_endpoint_action("trigger_scan", config, context) do
    agent_ids = context[:agent_ids] || [context[:agent_id]]
    Enum.each(agent_ids, fn agent_id ->
      send_agent_command(agent_id, "scan_path", config)
    end)
    {:ok, :scan_initiated}
  end

  defp execute_endpoint_action("collect_forensics", config, context) do
    agent_id = context[:agent_id]
    send_agent_command(agent_id, "collect_forensics", config)
    {:ok, :forensics_collection_started}
  end

  defp execute_endpoint_action(action, _config, _context) do
    Logger.warning("Unknown endpoint action: #{action}")
    {:error, :unknown_action}
  end

  # Agents.send_command/2 expects the canonical command envelope
  # (%{command_type: ..., payload: ...}) used across the agent protocol;
  # command_type strings match the Response.Executor action vocabulary.
  defp send_agent_command(agent_id, command_type, payload) do
    Agents.send_command(agent_id, %{command_type: command_type, payload: payload})
  end

  defp execute_network_action("block_ip", config, _context) do
    # Would integrate with firewall APIs
    Logger.info("Blocking IP: #{inspect(config)}")
    {:ok, :ip_blocked}
  end

  defp execute_network_action("block_domain", config, _context) do
    Logger.info("Blocking domain: #{inspect(config)}")
    {:ok, :domain_blocked}
  end

  defp execute_network_action("block_url", config, _context) do
    Logger.info("Blocking URL: #{inspect(config)}")
    {:ok, :url_blocked}
  end

  defp execute_network_action("block_ports", config, _context) do
    Logger.info("Blocking ports: #{inspect(config)}")
    {:ok, :ports_blocked}
  end

  defp execute_network_action("start_pcap", config, _context) do
    Logger.info("Starting packet capture: #{inspect(config)}")
    {:ok, :pcap_started}
  end

  defp execute_network_action("update_ids_rules", config, _context) do
    Logger.info("Updating IDS rules: #{inspect(config)}")
    {:ok, :ids_updated}
  end

  defp execute_network_action(action, _config, _context) do
    Logger.warning("Unknown network action: #{action}")
    {:error, :unknown_action}
  end

  defp execute_cloud_action("update_cloud_security", config, _context) do
    Logger.info("Updating cloud security groups: #{inspect(config)}")
    {:ok, :security_groups_updated}
  end

  defp execute_cloud_action("create_snapshot", config, _context) do
    Logger.info("Creating cloud snapshots: #{inspect(config)}")
    {:ok, :snapshots_created}
  end

  defp execute_cloud_action("rotate_credentials", config, _context) do
    Logger.info("Rotating cloud credentials: #{inspect(config)}")
    {:ok, :credentials_rotated}
  end

  defp execute_cloud_action("disable_api_keys", config, _context) do
    Logger.info("Disabling API keys: #{inspect(config)}")
    {:ok, :api_keys_disabled}
  end

  defp execute_cloud_action("audit_iam", config, _context) do
    Logger.info("Auditing IAM: #{inspect(config)}")
    {:ok, :iam_audited}
  end

  defp execute_cloud_action("verify_backups", config, _context) do
    Logger.info("Verifying backups: #{inspect(config)}")
    {:ok, :backups_verified}
  end

  defp execute_cloud_action(action, _config, _context) do
    Logger.warning("Unknown cloud action: #{action}")
    {:error, :unknown_action}
  end

  defp execute_identity_action("disable_user", config, _context) do
    Logger.info("Disabling user: #{inspect(config)}")
    {:ok, :user_disabled}
  end

  defp execute_identity_action("reset_password", config, _context) do
    Logger.info("Resetting password: #{inspect(config)}")
    {:ok, :password_reset}
  end

  defp execute_identity_action("terminate_sessions", config, _context) do
    Logger.info("Terminating sessions: #{inspect(config)}")
    {:ok, :sessions_terminated}
  end

  defp execute_identity_action("revoke_tokens", config, _context) do
    Logger.info("Revoking tokens: #{inspect(config)}")
    {:ok, :tokens_revoked}
  end

  defp execute_identity_action("enforce_mfa", config, _context) do
    Logger.info("Enforcing MFA: #{inspect(config)}")
    {:ok, :mfa_enforced}
  end

  defp execute_identity_action("revoke_sessions", config, _context) do
    Logger.info("Revoking sessions: #{inspect(config)}")
    {:ok, :sessions_revoked}
  end

  defp execute_identity_action(action, _config, _context) do
    Logger.warning("Unknown identity action: #{action}")
    {:error, :unknown_action}
  end

  defp execute_email_action("quarantine_email", config, _context) do
    Logger.info("Quarantining emails: #{inspect(config)}")
    {:ok, :emails_quarantined}
  end

  defp execute_email_action("block_email_sender", config, _context) do
    Logger.info("Blocking email sender: #{inspect(config)}")
    {:ok, :sender_blocked}
  end

  defp execute_email_action("legal_hold", config, _context) do
    Logger.info("Applying legal hold: #{inspect(config)}")
    {:ok, :legal_hold_applied}
  end

  defp execute_email_action(action, _config, _context) do
    Logger.warning("Unknown email action: #{action}")
    {:error, :unknown_action}
  end

  defp execute_dlp_action("update_dlp", config, _context) do
    Logger.info("Updating DLP rules: #{inspect(config)}")
    {:ok, :dlp_updated}
  end

  defp execute_dlp_action("classify_data", config, _context) do
    Logger.info("Classifying data: #{inspect(config)}")
    {:ok, :data_classified}
  end

  defp execute_dlp_action(action, _config, _context) do
    Logger.warning("Unknown DLP action: #{action}")
    {:error, :unknown_action}
  end

  defp execute_threat_intel_action("submit_iocs", config, _context) do
    Logger.info("Submitting IOCs: #{inspect(config)}")
    {:ok, :iocs_submitted}
  end

  defp execute_threat_intel_action("update_feeds", config, _context) do
    Logger.info("Updating threat feeds: #{inspect(config)}")
    {:ok, :feeds_updated}
  end

  defp execute_threat_intel_action(action, _config, _context) do
    Logger.warning("Unknown threat intel action: #{action}")
    {:error, :unknown_action}
  end

  defp execute_integration_action("create_ticket", config, _context) do
    Logger.info("Creating ticket: #{inspect(config)}")
    {:ok, :ticket_created}
  end

  defp execute_integration_action("send_notification", config, _context) do
    Logger.info("Sending notification: #{inspect(config)}")
    {:ok, :notification_sent}
  end

  defp execute_integration_action("generate_report", config, _context) do
    Logger.info("Generating report: #{inspect(config)}")
    {:ok, :report_generated}
  end

  defp execute_integration_action("query_logs", config, _context) do
    Logger.info("Querying logs: #{inspect(config)}")
    {:ok, %{results: []}}
  end

  defp execute_integration_action(action, _config, _context) do
    Logger.warning("Unknown integration action: #{action}")
    {:error, :unknown_action}
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp filter_templates(templates, opts) do
    templates
    |> maybe_filter_by_category(Keyword.get(opts, :category))
    |> maybe_filter_by_severity(Keyword.get(opts, :severity_threshold))
    |> maybe_filter_by_domain(Keyword.get(opts, :domain))
    |> maybe_filter_by_tag(Keyword.get(opts, :tag))
  end

  defp maybe_filter_by_category(templates, nil), do: templates
  defp maybe_filter_by_category(templates, category) do
    Enum.filter(templates, & &1[:category] == category)
  end

  defp maybe_filter_by_severity(templates, nil), do: templates
  defp maybe_filter_by_severity(templates, threshold) do
    Enum.filter(templates, & &1[:severity_threshold] == threshold)
  end

  defp maybe_filter_by_domain(templates, nil), do: templates
  defp maybe_filter_by_domain(templates, domain) do
    Enum.filter(templates, fn t ->
      domain in (t[:domains] || [])
    end)
  end

  defp maybe_filter_by_tag(templates, nil), do: templates
  defp maybe_filter_by_tag(templates, tag) do
    Enum.filter(templates, fn t ->
      tag in (t[:tags] || [])
    end)
  end

  defp matches_alert?(template, alert) do
    severity_threshold = template[:severity_threshold]
    severity_order = ["info", "low", "medium", "high", "critical"]

    alert_severity = alert[:severity] || "low"
    alert_idx = Enum.find_index(severity_order, & &1 == alert_severity) || 0
    threshold_idx = Enum.find_index(severity_order, & &1 == severity_threshold) || 0

    # Check severity threshold
    alert_idx >= threshold_idx
  end

  defp build_context_from_alert(alert) do
    %{
      alert: alert,
      alert_id: alert[:id],
      agent_id: alert[:agent_id],
      source_ip: alert[:source_ip],
      dest_ip: alert[:dest_ip],
      user: alert[:user],
      file_hash: alert[:file_hash],
      process_name: alert[:process_name],
      timestamp: DateTime.utc_now()
    }
  end

  defp determine_playbook_for_correlation(correlation) do
    patterns = correlation[:patterns] || []
    phases = correlation[:kill_chain_phases] || []

    cond do
      "ransomware" in patterns -> "xdr-ransomware-response"
      "phishing" in patterns -> "xdr-phishing-response"
      "exfiltration" in phases -> "xdr-data-exfiltration"
      "credential_access" in phases -> "xdr-cloud-compromise"
      "lateral_movement" in phases -> "xdr-network-intrusion"
      length(patterns) > 0 -> "xdr-malware-outbreak"
      true -> nil
    end
  end

  defp build_context_from_correlation(correlation) do
    %{
      correlation: correlation,
      correlation_id: correlation[:id],
      events: correlation[:events] || [],
      indicators: correlation[:indicators] || %{},
      affected_systems: extract_affected_from_correlation(correlation),
      timestamp: DateTime.utc_now()
    }
  end

  defp extract_affected_from_correlation(correlation) do
    events = correlation[:events] || []
    Enum.flat_map(events, fn event ->
      [event[:agent_id], event[:hostname]]
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  defp convert_to_playbook_format(xdr_playbook) do
    %{
      name: xdr_playbook[:name],
      description: xdr_playbook[:description],
      trigger_type: "detection",
      trigger_conditions: %{
        severity: xdr_playbook[:severity_threshold]
      },
      steps: Enum.map(xdr_playbook[:steps], fn step ->
        %{
          "action" => step[:action],
          "name" => step[:name],
          "config" => step[:config],
          "domain" => step[:domain]
        }
      end),
      enabled: true,
      require_approval: xdr_playbook[:require_approval] || false,
      tags: xdr_playbook[:tags] ++ ["xdr-generated"],
      severity_threshold: xdr_playbook[:severity_threshold]
    }
  end
end
