defmodule TamanduaServer.Cloud.DetectionRules do
  @moduledoc """
  Cloud-specific detection rules for identifying threats across AWS, Azure, and GCP.

  Implements 40+ cloud-specific detection rules covering:
  - Cryptojacking detection
  - Data exfiltration to cloud storage
  - Suspicious API calls
  - Privilege escalation
  - Lateral movement
  - Persistence mechanisms
  - Defense evasion
  - Initial access vectors

  Each rule maps to MITRE ATT&CK Cloud Matrix techniques.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts

  @ets_table :cloud_detection_rules
  @rule_matches_table :cloud_rule_matches

  # ============================================================================
  # CRYPTOJACKING DETECTION RULES (8 rules)
  # ============================================================================

  @cryptojacking_rules [
    %{
      id: "CLOUD-CRYPTO-001",
      name: "EC2 Instance Mining Pool Connection",
      description: "Detects EC2 instance connecting to known cryptocurrency mining pools",
      severity: :critical,
      mitre: "T1496",
      provider: :aws,
      rule_type: :network,
      indicators: [
        "stratum+tcp://",
        "stratum2+tcp://",
        "mining.pool.",
        "pool.minexmr.com",
        "xmrpool.eu",
        "f2pool.com",
        "ethermine.org",
        "nanopool.org",
        "nicehash.com"
      ]
    },
    %{
      id: "CLOUD-CRYPTO-002",
      name: "High GPU Utilization Without Approved Workload",
      description: "Detects sustained high GPU usage on instances not tagged for ML/rendering",
      severity: :high,
      mitre: "T1496",
      provider: :all,
      rule_type: :metric,
      condition: %{
        metric: "gpu_utilization",
        threshold: 90,
        duration_minutes: 30,
        exclude_tags: ["ml-workload", "rendering", "approved-compute"]
      }
    },
    %{
      id: "CLOUD-CRYPTO-003",
      name: "Cryptominer Process Detection",
      description: "Detects known cryptominer processes running on cloud workloads",
      severity: :critical,
      mitre: "T1496",
      provider: :all,
      rule_type: :process,
      indicators: [
        "xmrig", "cpuminer", "bfgminer", "cgminer", "ethminer",
        "minerd", "minergate", "nicehash", "phoenixminer", "t-rex",
        "nbminer", "gminer", "lolminer", "teamredminer", "ccminer"
      ]
    },
    %{
      id: "CLOUD-CRYPTO-004",
      name: "Lambda Cryptojacking via High Duration",
      description: "Detects Lambda functions with unusually high execution duration (potential mining)",
      severity: :high,
      mitre: "T1496",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_name: "Invoke",
        event_source: "lambda.amazonaws.com",
        duration_threshold_ms: 840000,  # 14 minutes (near max)
        frequency_per_hour: 50
      }
    },
    %{
      id: "CLOUD-CRYPTO-005",
      name: "Azure Container Instance Cryptomining",
      description: "Detects ACI containers spawned with mining-related images",
      severity: :critical,
      mitre: "T1496",
      provider: :azure,
      rule_type: :activity_log,
      condition: %{
        operation: "Microsoft.ContainerInstance/containerGroups/write",
        image_patterns: ["*miner*", "*xmr*", "*monero*", "*crypto*"]
      }
    },
    %{
      id: "CLOUD-CRYPTO-006",
      name: "GCP Compute Engine Mining Detection",
      description: "Detects GCE instances with cryptomining characteristics",
      severity: :critical,
      mitre: "T1496",
      provider: :gcp,
      rule_type: :audit_log,
      condition: %{
        method: "compute.instances.insert",
        indicators: %{
          high_cpu_count: 32,
          preemptible: true,
          no_external_ip: false,
          startup_script_patterns: ["*pool*", "*stratum*", "*miner*"]
        }
      }
    },
    %{
      id: "CLOUD-CRYPTO-007",
      name: "Kubernetes Cryptominer Pod",
      description: "Detects pods running with known cryptominer images or arguments",
      severity: :critical,
      mitre: "T1496",
      provider: :all,
      rule_type: :kubernetes,
      condition: %{
        resource: "pods",
        patterns: [
          %{field: "spec.containers[*].image", values: ["*xmrig*", "*minerd*", "*cpuminer*"]},
          %{field: "spec.containers[*].args", values: ["*--donate-level*", "*--coin*", "*stratum*"]}
        ]
      }
    },
    %{
      id: "CLOUD-CRYPTO-008",
      name: "Spot Instance Mining Farm",
      description: "Detects pattern of launching many spot instances simultaneously (mining farm)",
      severity: :high,
      mitre: "T1496",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_name: "RequestSpotInstances",
        count_threshold: 20,
        time_window_minutes: 5
      }
    }
  ]

  # ============================================================================
  # DATA EXFILTRATION RULES (10 rules)
  # ============================================================================

  @exfiltration_rules [
    %{
      id: "CLOUD-EXFIL-001",
      name: "S3 Bucket Made Public",
      description: "Detects S3 bucket ACL changed to allow public access",
      severity: :critical,
      mitre: "T1537",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_names: ["PutBucketAcl", "PutBucketPolicy"],
        indicators: ["AllUsers", "AuthenticatedUsers", "\"Principal\":\"*\""]
      }
    },
    %{
      id: "CLOUD-EXFIL-002",
      name: "Unusual S3 Data Transfer Volume",
      description: "Detects anomalous large data transfer from S3 buckets",
      severity: :high,
      mitre: "T1537",
      provider: :aws,
      rule_type: :metric,
      condition: %{
        metric: "s3:BytesDownloaded",
        anomaly_threshold: 3.0,  # 3 standard deviations
        baseline_days: 30
      }
    },
    %{
      id: "CLOUD-EXFIL-003",
      name: "S3 Replication to External Account",
      description: "Detects S3 cross-region replication to accounts outside organization",
      severity: :critical,
      mitre: "T1537",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_name: "PutBucketReplication",
        external_account: true
      }
    },
    %{
      id: "CLOUD-EXFIL-004",
      name: "Azure Blob Container Public Access",
      description: "Detects Azure Blob container made publicly accessible",
      severity: :critical,
      mitre: "T1537",
      provider: :azure,
      rule_type: :activity_log,
      condition: %{
        operation: "Microsoft.Storage/storageAccounts/blobServices/containers/write",
        public_access: ["blob", "container"]
      }
    },
    %{
      id: "CLOUD-EXFIL-005",
      name: "GCS Bucket Made Public",
      description: "Detects GCS bucket IAM policy allowing allUsers access",
      severity: :critical,
      mitre: "T1537",
      provider: :gcp,
      rule_type: :audit_log,
      condition: %{
        method: "storage.setIamPermissions",
        members: ["allUsers", "allAuthenticatedUsers"]
      }
    },
    %{
      id: "CLOUD-EXFIL-006",
      name: "Database Snapshot Shared Externally",
      description: "Detects RDS/Azure SQL/Cloud SQL snapshots shared with external accounts",
      severity: :critical,
      mitre: "T1537",
      provider: :all,
      rule_type: :cloudtrail,
      condition: %{
        event_names: [
          "ModifyDBSnapshotAttribute",  # AWS
          "Microsoft.Sql/servers/databases/export/action",  # Azure
          "cloudsql.instances.export"  # GCP
        ],
        external_share: true
      }
    },
    %{
      id: "CLOUD-EXFIL-007",
      name: "EC2 Instance Data Exfil via DNS",
      description: "Detects large volume DNS queries potentially encoding exfiltrated data",
      severity: :high,
      mitre: "T1048.003",
      provider: :aws,
      rule_type: :vpc_flow,
      condition: %{
        port: 53,
        packet_threshold: 10000,
        time_window_minutes: 60,
        unusual_query_length: 50
      }
    },
    %{
      id: "CLOUD-EXFIL-008",
      name: "Mass Download from Cloud Storage",
      description: "Detects rapid download of many objects from cloud storage",
      severity: :high,
      mitre: "T1530",
      provider: :all,
      rule_type: :cloudtrail,
      condition: %{
        event_names: ["GetObject", "Microsoft.Storage/blob/read", "storage.objects.get"],
        count_threshold: 500,
        time_window_minutes: 10
      }
    },
    %{
      id: "CLOUD-EXFIL-009",
      name: "Secrets Manager Bulk Access",
      description: "Detects bulk retrieval of secrets from secrets management services",
      severity: :critical,
      mitre: "T1552.005",
      provider: :all,
      rule_type: :cloudtrail,
      condition: %{
        event_names: [
          "GetSecretValue",  # AWS
          "Microsoft.KeyVault/vaults/secrets/read",  # Azure
          "secretmanager.secrets.get"  # GCP
        ],
        count_threshold: 20,
        time_window_minutes: 5
      }
    },
    %{
      id: "CLOUD-EXFIL-010",
      name: "Lambda Data Exfiltration",
      description: "Detects Lambda functions sending data to unknown external endpoints",
      severity: :high,
      mitre: "T1567",
      provider: :aws,
      rule_type: :vpc_flow,
      condition: %{
        source: "lambda",
        external_destination: true,
        exclude_allowed_endpoints: true,
        bytes_threshold: 10_000_000
      }
    }
  ]

  # ============================================================================
  # SUSPICIOUS API CALLS RULES (12 rules)
  # ============================================================================

  @suspicious_api_rules [
    %{
      id: "CLOUD-API-001",
      name: "Console Login Without MFA",
      description: "Detects AWS Console login without multi-factor authentication",
      severity: :high,
      mitre: "T1078.004",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_name: "ConsoleLogin",
        mfa_authenticated: "No",
        exclude_service_accounts: true
      }
    },
    %{
      id: "CLOUD-API-002",
      name: "Root Account Usage",
      description: "Detects usage of the root account for any action",
      severity: :critical,
      mitre: "T1078.004",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        user_identity_type: "Root",
        exclude_events: ["ConsoleLogin"]  # Separate rule for login
      }
    },
    %{
      id: "CLOUD-API-003",
      name: "CloudTrail Logging Disabled",
      description: "Detects CloudTrail logging being stopped or deleted",
      severity: :critical,
      mitre: "T1562.008",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_names: ["StopLogging", "DeleteTrail", "UpdateTrail"],
        exclude_authorized: true
      }
    },
    %{
      id: "CLOUD-API-004",
      name: "GuardDuty Disabled",
      description: "Detects AWS GuardDuty being disabled or detector deleted",
      severity: :critical,
      mitre: "T1562.001",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_names: ["DeleteDetector", "UpdateDetector", "DisassociateFromMasterAccount"]
      }
    },
    %{
      id: "CLOUD-API-005",
      name: "Security Group Wide Open",
      description: "Detects security group allowing 0.0.0.0/0 on sensitive ports",
      severity: :critical,
      mitre: "T1190",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_names: ["AuthorizeSecurityGroupIngress", "CreateSecurityGroup"],
        cidr: "0.0.0.0/0",
        sensitive_ports: [22, 3389, 445, 1433, 3306, 5432, 6379, 27017]
      }
    },
    %{
      id: "CLOUD-API-006",
      name: "KMS Key Deletion Scheduled",
      description: "Detects KMS customer master key scheduled for deletion",
      severity: :critical,
      mitre: "T1485",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_name: "ScheduleKeyDeletion"
      }
    },
    %{
      id: "CLOUD-API-007",
      name: "Azure Activity Log Disabled",
      description: "Detects Azure diagnostic settings being deleted",
      severity: :critical,
      mitre: "T1562.008",
      provider: :azure,
      rule_type: :activity_log,
      condition: %{
        operation: "Microsoft.Insights/diagnosticSettings/delete"
      }
    },
    %{
      id: "CLOUD-API-008",
      name: "Azure NSG Allow All Inbound",
      description: "Detects NSG rule allowing all inbound traffic",
      severity: :critical,
      mitre: "T1190",
      provider: :azure,
      rule_type: :activity_log,
      condition: %{
        operation: "Microsoft.Network/networkSecurityGroups/securityRules/write",
        source_address_prefix: "*",
        access: "Allow",
        direction: "Inbound"
      }
    },
    %{
      id: "CLOUD-API-009",
      name: "GCP Audit Logging Disabled",
      description: "Detects GCP audit logging being disabled for a project",
      severity: :critical,
      mitre: "T1562.008",
      provider: :gcp,
      rule_type: :audit_log,
      condition: %{
        method: "SetIamPolicy",
        audit_config_change: true,
        logging_disabled: true
      }
    },
    %{
      id: "CLOUD-API-010",
      name: "GCP Firewall Rule Wide Open",
      description: "Detects GCP firewall rule allowing 0.0.0.0/0",
      severity: :critical,
      mitre: "T1190",
      provider: :gcp,
      rule_type: :audit_log,
      condition: %{
        method: "compute.firewalls.insert",
        source_ranges: "0.0.0.0/0",
        sensitive_ports: [22, 3389, 445, 1433, 3306, 5432]
      }
    },
    %{
      id: "CLOUD-API-011",
      name: "API Call from Tor Exit Node",
      description: "Detects API calls originating from known Tor exit nodes",
      severity: :high,
      mitre: "T1090.003",
      provider: :all,
      rule_type: :cloudtrail,
      condition: %{
        source_ip_type: :tor_exit_node,
        exclude_authorized_vpn: true
      }
    },
    %{
      id: "CLOUD-API-012",
      name: "API Call from Unusual Country",
      description: "Detects API calls from countries not in baseline",
      severity: :medium,
      mitre: "T1078.004",
      provider: :all,
      rule_type: :cloudtrail,
      condition: %{
        source_country_not_in_baseline: true,
        baseline_days: 90
      }
    }
  ]

  # ============================================================================
  # PRIVILEGE ESCALATION RULES (10 rules)
  # ============================================================================

  @privilege_escalation_rules [
    %{
      id: "CLOUD-PRIVESC-001",
      name: "IAM User Created with Admin Privileges",
      description: "Detects new IAM user created with AdministratorAccess",
      severity: :critical,
      mitre: "T1136.003",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_sequence: [
          %{event_name: "CreateUser"},
          %{event_name: "AttachUserPolicy", policy_arn: "*AdministratorAccess*"}
        ],
        time_window_minutes: 5
      }
    },
    %{
      id: "CLOUD-PRIVESC-002",
      name: "IAM Role Trust Policy Modified",
      description: "Detects IAM role trust relationship changed to allow external principals",
      severity: :critical,
      mitre: "T1098.003",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_name: "UpdateAssumeRolePolicy",
        external_principal: true
      }
    },
    %{
      id: "CLOUD-PRIVESC-003",
      name: "IAM Policy Version Revert",
      description: "Detects setting a previous IAM policy version as default (bypass detection)",
      severity: :high,
      mitre: "T1098.001",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_name: "SetDefaultPolicyVersion",
        not_latest_version: true
      }
    },
    %{
      id: "CLOUD-PRIVESC-004",
      name: "Lambda Function Code Update",
      description: "Detects Lambda function code being updated (potential privilege escalation)",
      severity: :medium,
      mitre: "T1078.004",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_name: "UpdateFunctionCode20150331v2",
        exclude_ci_cd: true
      }
    },
    %{
      id: "CLOUD-PRIVESC-005",
      name: "EC2 Instance Profile Attached",
      description: "Detects instance profile with high privileges attached to EC2",
      severity: :high,
      mitre: "T1098.001",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_name: "AssociateIamInstanceProfile",
        role_has_admin: true
      }
    },
    %{
      id: "CLOUD-PRIVESC-006",
      name: "Azure AD Role Assignment",
      description: "Detects assignment of Global Administrator or high-privilege role",
      severity: :critical,
      mitre: "T1098.003",
      provider: :azure,
      rule_type: :activity_log,
      condition: %{
        operation: "Microsoft.Authorization/roleAssignments/write",
        role_definitions: [
          "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
          "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
          "e8611ab8-c189-46e8-94e1-60213ab1f814"   # Privileged Role Administrator
        ]
      }
    },
    %{
      id: "CLOUD-PRIVESC-007",
      name: "Azure Service Principal Secret Added",
      description: "Detects new credential added to service principal",
      severity: :high,
      mitre: "T1098.001",
      provider: :azure,
      rule_type: :audit_log,
      condition: %{
        activity: "Add service principal credentials",
        actor_not_owner: true
      }
    },
    %{
      id: "CLOUD-PRIVESC-008",
      name: "GCP IAM Binding for Owner Role",
      description: "Detects granting of roles/owner to a member",
      severity: :critical,
      mitre: "T1098.003",
      provider: :gcp,
      rule_type: :audit_log,
      condition: %{
        method: "SetIamPolicy",
        role: "roles/owner"
      }
    },
    %{
      id: "CLOUD-PRIVESC-009",
      name: "GCP Service Account Key Created",
      description: "Detects creation of service account key (persistence mechanism)",
      severity: :high,
      mitre: "T1098.001",
      provider: :gcp,
      rule_type: :audit_log,
      condition: %{
        method: "google.iam.admin.v1.CreateServiceAccountKey"
      }
    },
    %{
      id: "CLOUD-PRIVESC-010",
      name: "Cross-Account AssumeRole",
      description: "Detects AssumeRole to external AWS account",
      severity: :high,
      mitre: "T1550.001",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_name: "AssumeRole",
        cross_account: true,
        external_account: true
      }
    }
  ]

  # ============================================================================
  # PERSISTENCE RULES (5 rules)
  # ============================================================================

  @persistence_rules [
    %{
      id: "CLOUD-PERSIST-001",
      name: "Lambda Backdoor Function Created",
      description: "Detects Lambda function with suspicious configuration (persistence)",
      severity: :high,
      mitre: "T1525",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_name: "CreateFunction20150331",
        indicators: [
          %{field: "runtime", values: ["python*", "nodejs*"]},
          %{field: "timeout", min: 300},
          %{field: "trigger", values: ["schedule", "api-gateway"]}
        ]
      }
    },
    %{
      id: "CLOUD-PERSIST-002",
      name: "SSM Document Backdoor",
      description: "Detects creation of SSM document for command execution",
      severity: :high,
      mitre: "T1059.006",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_name: "CreateDocument",
        document_type: "Command"
      }
    },
    %{
      id: "CLOUD-PERSIST-003",
      name: "Azure Automation Runbook Created",
      description: "Detects creation of Azure Automation runbook (persistence)",
      severity: :medium,
      mitre: "T1525",
      provider: :azure,
      rule_type: :activity_log,
      condition: %{
        operation: "Microsoft.Automation/automationAccounts/runbooks/write"
      }
    },
    %{
      id: "CLOUD-PERSIST-004",
      name: "GCP Cloud Function Backdoor",
      description: "Detects Cloud Function with suspicious triggers",
      severity: :high,
      mitre: "T1525",
      provider: :gcp,
      rule_type: :audit_log,
      condition: %{
        method: "cloudfunctions.functions.create",
        http_trigger: true,
        allow_unauthenticated: true
      }
    },
    %{
      id: "CLOUD-PERSIST-005",
      name: "EC2 UserData Script Persistence",
      description: "Detects modification of EC2 instance UserData",
      severity: :high,
      mitre: "T1525",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_name: "ModifyInstanceAttribute",
        attribute: "userData"
      }
    }
  ]

  # ============================================================================
  # LATERAL MOVEMENT RULES (5 rules)
  # ============================================================================

  @lateral_movement_rules [
    %{
      id: "CLOUD-LATERAL-001",
      name: "SSM Session Started to Multiple Hosts",
      description: "Detects SSM sessions started to multiple EC2 instances rapidly",
      severity: :high,
      mitre: "T1021.007",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_name: "StartSession",
        unique_targets: 5,
        time_window_minutes: 10
      }
    },
    %{
      id: "CLOUD-LATERAL-002",
      name: "EC2 Instance Connect Multiple Targets",
      description: "Detects EC2 Instance Connect to multiple instances",
      severity: :high,
      mitre: "T1021.004",
      provider: :aws,
      rule_type: :cloudtrail,
      condition: %{
        event_name: "SendSSHPublicKey",
        unique_targets: 5,
        time_window_minutes: 15
      }
    },
    %{
      id: "CLOUD-LATERAL-003",
      name: "Azure Bastion Multiple Target Connections",
      description: "Detects Azure Bastion connections to multiple VMs",
      severity: :high,
      mitre: "T1021",
      provider: :azure,
      rule_type: :activity_log,
      condition: %{
        resource_type: "Microsoft.Network/bastionHosts",
        unique_targets: 5,
        time_window_minutes: 15
      }
    },
    %{
      id: "CLOUD-LATERAL-004",
      name: "GCP IAP Tunnel to Multiple Instances",
      description: "Detects IAP tunnel creation to multiple GCE instances",
      severity: :high,
      mitre: "T1021",
      provider: :gcp,
      rule_type: :audit_log,
      condition: %{
        method: "iap.startTunnel",
        unique_targets: 5,
        time_window_minutes: 15
      }
    },
    %{
      id: "CLOUD-LATERAL-005",
      name: "Container Escape to Host",
      description: "Detects container breakout attempting host access",
      severity: :critical,
      mitre: "T1611",
      provider: :all,
      rule_type: :runtime,
      condition: %{
        indicators: [
          "/var/run/docker.sock",
          "nsenter --target 1",
          "chroot /host",
          "/proc/*/root",
          "CAP_SYS_ADMIN"
        ]
      }
    }
  ]

  # Combine all rules
  def all_rules do
    @cryptojacking_rules ++
    @exfiltration_rules ++
    @suspicious_api_rules ++
    @privilege_escalation_rules ++
    @persistence_rules ++
    @lateral_movement_rules
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    :ets.new(@ets_table, [:set, :public, :named_table, read_concurrency: true])
    :ets.new(@rule_matches_table, [:set, :public, :named_table, write_concurrency: true])

    # Load all rules into ETS
    load_rules()

    Logger.info("Cloud Detection Rules initialized with #{length(all_rules())} rules")

    {:ok, %{
      rules_loaded: length(all_rules()),
      last_updated: DateTime.utc_now()
    }}
  end

  defp load_rules do
    Enum.each(all_rules(), fn rule ->
      :ets.insert(@ets_table, {rule.id, rule})
    end)
  end

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Evaluate an event against all cloud detection rules.
  Returns list of matching rules.
  """
  def evaluate_event(event) do
    GenServer.call(__MODULE__, {:evaluate_event, event})
  end

  @doc """
  Get all rules for a specific provider.
  """
  def get_rules_by_provider(provider) when provider in [:aws, :azure, :gcp, :all] do
    all_rules()
    |> Enum.filter(fn rule ->
      rule.provider == provider or rule.provider == :all
    end)
  end

  @doc """
  Get all rules by MITRE technique.
  """
  def get_rules_by_mitre(technique_id) do
    all_rules()
    |> Enum.filter(fn rule -> rule.mitre == technique_id end)
  end

  @doc """
  Get rule by ID.
  """
  def get_rule(rule_id) do
    case :ets.lookup(@ets_table, rule_id) do
      [{^rule_id, rule}] -> {:ok, rule}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Get all rules grouped by category.
  """
  def get_rules_by_category do
    %{
      cryptojacking: @cryptojacking_rules,
      data_exfiltration: @exfiltration_rules,
      suspicious_api: @suspicious_api_rules,
      privilege_escalation: @privilege_escalation_rules,
      persistence: @persistence_rules,
      lateral_movement: @lateral_movement_rules
    }
  end

  @doc """
  Get detection coverage statistics.
  """
  def get_coverage_stats do
    rules = all_rules()

    %{
      total_rules: length(rules),
      by_provider: %{
        aws: count_by_provider(rules, :aws),
        azure: count_by_provider(rules, :azure),
        gcp: count_by_provider(rules, :gcp),
        all: count_by_provider(rules, :all)
      },
      by_severity: %{
        critical: count_by_severity(rules, :critical),
        high: count_by_severity(rules, :high),
        medium: count_by_severity(rules, :medium),
        low: count_by_severity(rules, :low)
      },
      by_category: %{
        cryptojacking: length(@cryptojacking_rules),
        data_exfiltration: length(@exfiltration_rules),
        suspicious_api: length(@suspicious_api_rules),
        privilege_escalation: length(@privilege_escalation_rules),
        persistence: length(@persistence_rules),
        lateral_movement: length(@lateral_movement_rules)
      },
      mitre_techniques: rules |> Enum.map(& &1.mitre) |> Enum.uniq() |> length()
    }
  end

  defp count_by_provider(rules, provider) do
    Enum.count(rules, fn r -> r.provider == provider end)
  end

  defp count_by_severity(rules, severity) do
    Enum.count(rules, fn r -> r.severity == severity end)
  end

  @doc """
  Evaluate CloudTrail event against AWS rules.
  """
  def evaluate_cloudtrail(event) do
    aws_rules = get_rules_by_provider(:aws)
    |> Enum.filter(fn r -> r.rule_type == :cloudtrail end)

    matches = Enum.filter(aws_rules, fn rule ->
      match_cloudtrail_rule?(event, rule)
    end)

    # Create alerts for matches
    Enum.each(matches, fn rule ->
      create_alert(rule, event)
    end)

    matches
  end

  @doc """
  Evaluate Azure Activity Log event against Azure rules.
  """
  def evaluate_activity_log(event) do
    azure_rules = get_rules_by_provider(:azure)
    |> Enum.filter(fn r -> r.rule_type in [:activity_log, :audit_log] end)

    matches = Enum.filter(azure_rules, fn rule ->
      match_azure_rule?(event, rule)
    end)

    Enum.each(matches, fn rule ->
      create_alert(rule, event)
    end)

    matches
  end

  @doc """
  Evaluate GCP Audit Log event against GCP rules.
  """
  def evaluate_audit_log(event) do
    gcp_rules = get_rules_by_provider(:gcp)
    |> Enum.filter(fn r -> r.rule_type == :audit_log end)

    matches = Enum.filter(gcp_rules, fn rule ->
      match_gcp_rule?(event, rule)
    end)

    Enum.each(matches, fn rule ->
      create_alert(rule, event)
    end)

    matches
  end

  @doc """
  Evaluate runtime event against runtime rules.
  """
  def evaluate_runtime(event) do
    runtime_rules = all_rules()
    |> Enum.filter(fn r -> r.rule_type in [:runtime, :process, :network] end)

    matches = Enum.filter(runtime_rules, fn rule ->
      match_runtime_rule?(event, rule)
    end)

    Enum.each(matches, fn rule ->
      create_alert(rule, event)
    end)

    matches
  end

  @doc """
  Evaluate Kubernetes event against K8s rules.
  """
  def evaluate_kubernetes(event) do
    k8s_rules = all_rules()
    |> Enum.filter(fn r -> r.rule_type == :kubernetes end)

    matches = Enum.filter(k8s_rules, fn rule ->
      match_kubernetes_rule?(event, rule)
    end)

    Enum.each(matches, fn rule ->
      create_alert(rule, event)
    end)

    matches
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def handle_call({:evaluate_event, event}, _from, state) do
    matches = case determine_event_type(event) do
      :cloudtrail -> evaluate_cloudtrail(event)
      :activity_log -> evaluate_activity_log(event)
      :audit_log -> evaluate_audit_log(event)
      :runtime -> evaluate_runtime(event)
      :kubernetes -> evaluate_kubernetes(event)
      _ -> []
    end

    {:reply, {:ok, matches}, state}
  end

  # ============================================================================
  # Private Functions - Rule Matching
  # ============================================================================

  defp determine_event_type(event) do
    cond do
      Map.has_key?(event, :eventSource) and String.contains?(event.eventSource || "", "amazonaws.com") ->
        :cloudtrail
      Map.has_key?(event, :operationName) and Map.has_key?(event, :resourceId) ->
        :activity_log
      Map.has_key?(event, :protoPayload) and Map.has_key?(event, :resource) ->
        :audit_log
      Map.has_key?(event, :kind) and event.kind in ["Pod", "Deployment", "DaemonSet"] ->
        :kubernetes
      Map.has_key?(event, :process) or Map.has_key?(event, :command_line) ->
        :runtime
      true ->
        :unknown
    end
  end

  defp match_cloudtrail_rule?(event, rule) do
    condition = rule.condition

    event_name_match = case condition[:event_name] do
      nil ->
        case condition[:event_names] do
          nil -> true
          names -> Map.get(event, :eventName) in names
        end
      name ->
        Map.get(event, :eventName) == name
    end

    # Check additional conditions
    event_name_match and match_additional_conditions?(event, condition)
  end

  defp match_azure_rule?(event, rule) do
    condition = rule.condition

    operation_match = case condition[:operation] do
      nil -> true
      op -> Map.get(event, :operationName) == op
    end

    operation_match and match_additional_conditions?(event, condition)
  end

  defp match_gcp_rule?(event, rule) do
    condition = rule.condition

    method_match = case condition[:method] do
      nil -> true
      method ->
        proto = Map.get(event, :protoPayload, %{})
        Map.get(proto, :methodName) == method
    end

    method_match and match_additional_conditions?(event, condition)
  end

  defp match_runtime_rule?(event, rule) do
    condition = rule.condition

    case rule.rule_type do
      :process ->
        process_name = Map.get(event, :process, "") |> String.downcase()
        indicators = condition[:indicators] || rule.indicators || []
        Enum.any?(indicators, fn ind ->
          String.contains?(process_name, String.downcase(ind))
        end)

      :network ->
        indicators = rule.indicators || []
        destination = Map.get(event, :destination, "") |> String.downcase()
        Enum.any?(indicators, fn ind ->
          String.contains?(destination, String.downcase(ind))
        end)

      :runtime ->
        indicators = condition[:indicators] || []
        command = Map.get(event, :command_line, "") |> String.downcase()
        Enum.any?(indicators, fn ind ->
          String.contains?(command, String.downcase(ind))
        end)

      _ ->
        false
    end
  end

  defp match_kubernetes_rule?(event, rule) do
    condition = rule.condition

    resource_match = case condition[:resource] do
      nil -> true
      res -> String.downcase(Map.get(event, :kind, "")) == res
    end

    resource_match and match_k8s_patterns?(event, condition[:patterns] || [])
  end

  defp match_k8s_patterns?(_event, []), do: true
  defp match_k8s_patterns?(event, patterns) do
    Enum.any?(patterns, fn pattern ->
      field_value = get_nested_field(event, pattern.field)
      Enum.any?(pattern.values, fn val_pattern ->
        String.match?(to_string(field_value), glob_to_regex(val_pattern))
      end)
    end)
  end

  defp get_nested_field(data, field_path) do
    # Simplified - in production would handle array notation properly
    field_path
    |> String.split(".")
    |> Enum.reject(&String.contains?(&1, "["))
    |> Enum.reduce(data, fn key, acc ->
      case acc do
        %{} = map -> Map.get(map, key) || Map.get(map, String.to_atom(key))
        _ -> nil
      end
    end)
  end

  defp glob_to_regex(pattern) do
    pattern
    |> Regex.escape()
    |> String.replace("\\*", ".*")
    |> then(&Regex.compile!("^#{&1}$", "i"))
  end

  defp match_additional_conditions?(_event, condition) when map_size(condition) == 0, do: true
  defp match_additional_conditions?(event, condition) do
    # Check for indicators in request parameters
    case condition[:indicators] do
      nil -> true
      indicators ->
        event_json = Jason.encode!(event) |> String.downcase()
        Enum.any?(indicators, fn ind ->
          String.contains?(event_json, String.downcase(ind))
        end)
    end
  end

  defp create_alert(rule, event) do
    alert_params = %{
      title: rule.name,
      description: "#{rule.description}\n\nRule ID: #{rule.id}\nMITRE: #{rule.mitre}",
      severity: severity_to_string(rule.severity),
      source: "cloud_detection_rules",
      mitre_technique: rule.mitre,
      raw_event: event,
      metadata: %{
        rule_id: rule.id,
        provider: rule.provider,
        rule_type: rule.rule_type
      }
    }

    case Alerts.create_alert(alert_params) do
      {:ok, alert} ->
        Logger.info("Cloud detection rule #{rule.id} triggered alert #{alert.id}")

        # Record match
        key = {rule.id, DateTime.utc_now() |> DateTime.to_unix()}
        :ets.insert(@rule_matches_table, {key, event})

        {:ok, alert}

      {:error, reason} ->
        Logger.error("Failed to create alert for rule #{rule.id}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp severity_to_string(:critical), do: "critical"
  defp severity_to_string(:high), do: "high"
  defp severity_to_string(:medium), do: "medium"
  defp severity_to_string(:low), do: "low"
end
