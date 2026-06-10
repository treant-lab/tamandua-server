# Sample Endpoint Agents
# Run with: mix run priv/repo/seeds/sample_agents.exs
#
# Creates realistic endpoint agent entries representing a diverse
# enterprise environment with Windows, Linux, and macOS systems.

alias TamanduaServer.Repo
alias TamanduaServer.Agents.Agent
alias TamanduaServer.Accounts.Organization

IO.puts("Seeding sample endpoint agents...")

# Get or create demo organization
org = case Repo.get_by(Organization, slug: "tamandua-demo") do
  nil ->
    %Organization{}
    |> Organization.changeset(%{name: "Tamandua Demo Organization", slug: "tamandua-demo"})
    |> Repo.insert!()
  existing -> existing
end

IO.puts("Using organization: #{org.name}")

# Helper to generate last seen timestamps
generate_last_seen = fn status ->
  case status do
    "online" ->
      # Online agents seen within last 5 minutes
      NaiveDateTime.utc_now()
      |> NaiveDateTime.add(-Enum.random(0..300), :second)
      |> NaiveDateTime.truncate(:second)

    "offline" ->
      # Offline agents not seen for hours to days
      NaiveDateTime.utc_now()
      |> NaiveDateTime.add(-Enum.random(3600..604800), :second)
      |> NaiveDateTime.truncate(:second)

    "isolated" ->
      # Isolated agents - last seen when isolated
      NaiveDateTime.utc_now()
      |> NaiveDateTime.add(-Enum.random(1800..7200), :second)
      |> NaiveDateTime.truncate(:second)
  end
end

sample_agents = [
  # ============================================================================
  # WINDOWS WORKSTATIONS
  # ============================================================================

  # Executive workstations
  %{
    hostname: "EXEC-CEO-01",
    os_type: "windows",
    os_version: "Windows 11 Enterprise 23H2",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "executive", "vip", "high-value"],
    config: %{
      "scan_interval_seconds" => 300,
      "telemetry_level" => "full",
      "real_time_protection" => true,
      "isolation_enabled" => true,
      "forensics_enabled" => true
    },
    organization_id: org.id
  },
  %{
    hostname: "EXEC-CFO-01",
    os_type: "windows",
    os_version: "Windows 11 Enterprise 23H2",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "executive", "finance", "vip", "high-value"],
    config: %{
      "scan_interval_seconds" => 300,
      "telemetry_level" => "full",
      "real_time_protection" => true
    },
    organization_id: org.id
  },

  # Finance department
  %{
    hostname: "FIN-WKS-01",
    os_type: "windows",
    os_version: "Windows 11 Pro 23H2",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "finance", "pci-scope"],
    config: %{
      "scan_interval_seconds" => 600,
      "telemetry_level" => "full",
      "real_time_protection" => true
    },
    organization_id: org.id
  },
  %{
    hostname: "FIN-WKS-02",
    os_type: "windows",
    os_version: "Windows 11 Pro 23H2",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "finance", "pci-scope"],
    config: %{
      "scan_interval_seconds" => 600,
      "telemetry_level" => "full"
    },
    organization_id: org.id
  },
  %{
    hostname: "FIN-WKS-03",
    os_type: "windows",
    os_version: "Windows 10 Enterprise 22H2",
    agent_version: "1.1.5",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "offline",
    tags: ["workstation", "finance", "pci-scope"],
    config: %{},
    organization_id: org.id
  },

  # IT department
  %{
    hostname: "IT-ADMIN-01",
    os_type: "windows",
    os_version: "Windows 11 Pro 23H2",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "it-admin", "privileged"],
    config: %{
      "scan_interval_seconds" => 300,
      "telemetry_level" => "full",
      "real_time_protection" => true,
      "forensics_enabled" => true
    },
    organization_id: org.id
  },
  %{
    hostname: "IT-ADMIN-02",
    os_type: "windows",
    os_version: "Windows 11 Pro 23H2",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "it-admin", "privileged"],
    config: %{
      "scan_interval_seconds" => 300,
      "telemetry_level" => "full"
    },
    organization_id: org.id
  },
  %{
    hostname: "IT-HELPDESK-01",
    os_type: "windows",
    os_version: "Windows 11 Pro 23H2",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "helpdesk", "it"],
    config: %{},
    organization_id: org.id
  },

  # Engineering/Development
  %{
    hostname: "DEV-WKS-01",
    os_type: "windows",
    os_version: "Windows 11 Pro 23H2",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "development", "engineering"],
    config: %{
      "exclusions" => ["C:\\Projects", "C:\\dev"],
      "scan_interval_seconds" => 900
    },
    organization_id: org.id
  },
  %{
    hostname: "DEV-WKS-02",
    os_type: "windows",
    os_version: "Windows 11 Pro 23H2",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "development", "engineering"],
    config: %{
      "exclusions" => ["C:\\Projects"],
      "scan_interval_seconds" => 900
    },
    organization_id: org.id
  },
  %{
    hostname: "DEV-WKS-03",
    os_type: "windows",
    os_version: "Windows 10 Pro 22H2",
    agent_version: "1.1.5",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "offline",
    tags: ["workstation", "development"],
    config: %{},
    organization_id: org.id
  },

  # HR Department
  %{
    hostname: "HR-WKS-01",
    os_type: "windows",
    os_version: "Windows 11 Pro 23H2",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "hr", "pii-access"],
    config: %{
      "dlp_enabled" => true,
      "telemetry_level" => "full"
    },
    organization_id: org.id
  },
  %{
    hostname: "HR-WKS-02",
    os_type: "windows",
    os_version: "Windows 11 Pro 23H2",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "hr", "pii-access"],
    config: %{
      "dlp_enabled" => true
    },
    organization_id: org.id
  },

  # Sales/Marketing
  %{
    hostname: "SALES-WKS-01",
    os_type: "windows",
    os_version: "Windows 11 Pro 23H2",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "sales", "remote-worker"],
    config: %{
      "vpn_required" => true
    },
    organization_id: org.id
  },
  %{
    hostname: "SALES-WKS-02",
    os_type: "windows",
    os_version: "Windows 11 Pro 23H2",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "sales"],
    config: %{},
    organization_id: org.id
  },
  %{
    hostname: "MKT-WKS-01",
    os_type: "windows",
    os_version: "Windows 11 Pro 23H2",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "marketing"],
    config: %{},
    organization_id: org.id
  },

  # Isolated/Quarantined workstation
  %{
    hostname: "SEC-QUARANTINE-01",
    os_type: "windows",
    os_version: "Windows 11 Pro 23H2",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "isolated",
    tags: ["workstation", "quarantined", "incident-response"],
    config: %{
      "isolation_mode" => true,
      "forensics_enabled" => true,
      "allow_investigation_access" => true
    },
    organization_id: org.id
  },

  # ============================================================================
  # WINDOWS SERVERS
  # ============================================================================

  # Domain Controllers
  %{
    hostname: "DC01",
    os_type: "windows",
    os_version: "Windows Server 2022 Datacenter",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "domain-controller", "tier-0", "critical"],
    config: %{
      "scan_interval_seconds" => 300,
      "telemetry_level" => "full",
      "real_time_protection" => true,
      "lsass_protection" => true,
      "credential_guard" => true
    },
    organization_id: org.id
  },
  %{
    hostname: "DC02",
    os_type: "windows",
    os_version: "Windows Server 2022 Datacenter",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "domain-controller", "tier-0", "critical"],
    config: %{
      "scan_interval_seconds" => 300,
      "telemetry_level" => "full",
      "real_time_protection" => true,
      "lsass_protection" => true
    },
    organization_id: org.id
  },

  # File Servers
  %{
    hostname: "FILE01",
    os_type: "windows",
    os_version: "Windows Server 2022 Standard",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "file-server", "data-storage"],
    config: %{
      "ransomware_protection" => true,
      "honeypot_files" => true,
      "telemetry_level" => "full"
    },
    organization_id: org.id
  },
  %{
    hostname: "FILE02",
    os_type: "windows",
    os_version: "Windows Server 2019 Standard",
    agent_version: "1.1.5",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "file-server"],
    config: %{
      "ransomware_protection" => true
    },
    organization_id: org.id
  },

  # SQL Servers
  %{
    hostname: "SQL01",
    os_type: "windows",
    os_version: "Windows Server 2022 Standard",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "database", "sql-server", "pci-scope"],
    config: %{
      "exclusions" => ["D:\\MSSQL\\DATA"],
      "telemetry_level" => "full"
    },
    organization_id: org.id
  },
  %{
    hostname: "SQL02",
    os_type: "windows",
    os_version: "Windows Server 2022 Standard",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "database", "sql-server"],
    config: %{
      "exclusions" => ["D:\\MSSQL\\DATA"]
    },
    organization_id: org.id
  },

  # Exchange Server
  %{
    hostname: "EXCH01",
    os_type: "windows",
    os_version: "Windows Server 2019 Standard",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "exchange", "email", "critical"],
    config: %{
      "exclusions" => ["D:\\Exchange"],
      "web_shell_detection" => true,
      "telemetry_level" => "full"
    },
    organization_id: org.id
  },

  # Terminal/RDP Server
  %{
    hostname: "TERM01",
    os_type: "windows",
    os_version: "Windows Server 2022 Standard",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "terminal-server", "rds", "internet-facing"],
    config: %{
      "brute_force_protection" => true,
      "session_monitoring" => true,
      "telemetry_level" => "full"
    },
    organization_id: org.id
  },

  # ============================================================================
  # LINUX SERVERS
  # ============================================================================

  # Web Servers
  %{
    hostname: "web-prod-01",
    os_type: "linux",
    os_version: "Ubuntu 22.04.3 LTS",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "web", "production", "nginx", "internet-facing"],
    config: %{
      "web_shell_detection" => true,
      "file_integrity_monitoring" => true,
      "monitored_paths" => ["/var/www", "/etc/nginx"]
    },
    organization_id: org.id
  },
  %{
    hostname: "web-prod-02",
    os_type: "linux",
    os_version: "Ubuntu 22.04.3 LTS",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "web", "production", "nginx", "internet-facing"],
    config: %{
      "web_shell_detection" => true,
      "file_integrity_monitoring" => true
    },
    organization_id: org.id
  },
  %{
    hostname: "web-staging-01",
    os_type: "linux",
    os_version: "Ubuntu 22.04.3 LTS",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "web", "staging", "nginx"],
    config: %{},
    organization_id: org.id
  },

  # Application Servers
  %{
    hostname: "app-prod-01",
    os_type: "linux",
    os_version: "Red Hat Enterprise Linux 9.2",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "application", "production", "java"],
    config: %{
      "telemetry_level" => "full"
    },
    organization_id: org.id
  },
  %{
    hostname: "app-prod-02",
    os_type: "linux",
    os_version: "Red Hat Enterprise Linux 9.2",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "application", "production", "java"],
    config: %{},
    organization_id: org.id
  },

  # Database Servers (Linux)
  %{
    hostname: "db-prod-01",
    os_type: "linux",
    os_version: "Ubuntu 22.04.3 LTS",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "database", "postgresql", "production", "pci-scope"],
    config: %{
      "exclusions" => ["/var/lib/postgresql"],
      "telemetry_level" => "full"
    },
    organization_id: org.id
  },
  %{
    hostname: "db-prod-02",
    os_type: "linux",
    os_version: "Ubuntu 22.04.3 LTS",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "database", "postgresql", "production"],
    config: %{
      "exclusions" => ["/var/lib/postgresql"]
    },
    organization_id: org.id
  },
  %{
    hostname: "redis-01",
    os_type: "linux",
    os_version: "Debian 12",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "cache", "redis", "production"],
    config: %{},
    organization_id: org.id
  },

  # Kubernetes/Container Infrastructure
  %{
    hostname: "k8s-master-01",
    os_type: "linux",
    os_version: "Ubuntu 22.04.3 LTS",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "kubernetes", "control-plane", "critical"],
    config: %{
      "container_monitoring" => true,
      "telemetry_level" => "full"
    },
    organization_id: org.id
  },
  %{
    hostname: "k8s-worker-01",
    os_type: "linux",
    os_version: "Ubuntu 22.04.3 LTS",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "kubernetes", "worker"],
    config: %{
      "container_monitoring" => true
    },
    organization_id: org.id
  },
  %{
    hostname: "k8s-worker-02",
    os_type: "linux",
    os_version: "Ubuntu 22.04.3 LTS",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "kubernetes", "worker"],
    config: %{
      "container_monitoring" => true
    },
    organization_id: org.id
  },

  # CI/CD Infrastructure
  %{
    hostname: "jenkins-01",
    os_type: "linux",
    os_version: "Ubuntu 22.04.3 LTS",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "ci-cd", "jenkins", "development"],
    config: %{
      "supply_chain_monitoring" => true
    },
    organization_id: org.id
  },
  %{
    hostname: "gitlab-01",
    os_type: "linux",
    os_version: "Ubuntu 22.04.3 LTS",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "source-control", "gitlab", "development", "critical"],
    config: %{
      "supply_chain_monitoring" => true,
      "file_integrity_monitoring" => true
    },
    organization_id: org.id
  },

  # Monitoring/Logging
  %{
    hostname: "elk-01",
    os_type: "linux",
    os_version: "CentOS Stream 9",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "logging", "elasticsearch", "monitoring"],
    config: %{},
    organization_id: org.id
  },
  %{
    hostname: "prometheus-01",
    os_type: "linux",
    os_version: "Ubuntu 22.04.3 LTS",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "monitoring", "prometheus", "grafana"],
    config: %{},
    organization_id: org.id
  },

  # Offline Linux server
  %{
    hostname: "backup-srv-01",
    os_type: "linux",
    os_version: "Rocky Linux 9.2",
    agent_version: "1.1.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "offline",
    tags: ["server", "backup", "offline-backup"],
    config: %{},
    organization_id: org.id
  },

  # ============================================================================
  # MACOS ENDPOINTS
  # ============================================================================

  # Executive MacBooks
  %{
    hostname: "MBP-EXEC-01",
    os_type: "macos",
    os_version: "macOS 14.2.1 Sonoma",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "macos", "executive", "vip"],
    config: %{
      "telemetry_level" => "full"
    },
    organization_id: org.id
  },

  # Development MacBooks
  %{
    hostname: "MBP-DEV-01",
    os_type: "macos",
    os_version: "macOS 14.2.1 Sonoma",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "macos", "development", "engineering"],
    config: %{
      "exclusions" => ["/Users/developer/Projects"]
    },
    organization_id: org.id
  },
  %{
    hostname: "MBP-DEV-02",
    os_type: "macos",
    os_version: "macOS 14.2.1 Sonoma",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "macos", "development", "engineering"],
    config: %{},
    organization_id: org.id
  },
  %{
    hostname: "MBP-DEV-03",
    os_type: "macos",
    os_version: "macOS 13.6 Ventura",
    agent_version: "1.1.5",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "macos", "development"],
    config: %{},
    organization_id: org.id
  },

  # Design team MacBooks
  %{
    hostname: "MBP-DESIGN-01",
    os_type: "macos",
    os_version: "macOS 14.2.1 Sonoma",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "macos", "design", "creative"],
    config: %{},
    organization_id: org.id
  },
  %{
    hostname: "MBP-DESIGN-02",
    os_type: "macos",
    os_version: "macOS 14.2.1 Sonoma",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["workstation", "macos", "design", "creative"],
    config: %{},
    organization_id: org.id
  },

  # Mac Mini build servers
  %{
    hostname: "MACMINI-BUILD-01",
    os_type: "macos",
    os_version: "macOS 14.2.1 Sonoma",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["server", "macos", "build-server", "ci-cd"],
    config: %{
      "supply_chain_monitoring" => true
    },
    organization_id: org.id
  },

  # Offline MacBook
  %{
    hostname: "MBP-SALES-01",
    os_type: "macos",
    os_version: "macOS 13.6 Ventura",
    agent_version: "1.1.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "offline",
    tags: ["workstation", "macos", "sales", "remote-worker"],
    config: %{},
    organization_id: org.id
  },

  # ============================================================================
  # CLOUD INSTANCES (AWS/Azure/GCP)
  # ============================================================================

  # AWS Instances
  %{
    hostname: "aws-web-us-east-1a-01",
    os_type: "linux",
    os_version: "Amazon Linux 2023",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["cloud", "aws", "web", "production", "us-east-1"],
    config: %{
      "cloud_provider" => "aws",
      "instance_id" => "i-0abc123def456",
      "region" => "us-east-1"
    },
    organization_id: org.id
  },
  %{
    hostname: "aws-api-us-east-1a-01",
    os_type: "linux",
    os_version: "Amazon Linux 2023",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["cloud", "aws", "api", "production", "us-east-1"],
    config: %{
      "cloud_provider" => "aws",
      "instance_id" => "i-0def456abc789",
      "region" => "us-east-1"
    },
    organization_id: org.id
  },

  # Azure VMs
  %{
    hostname: "az-app-eastus-01",
    os_type: "linux",
    os_version: "Ubuntu 22.04 LTS",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["cloud", "azure", "application", "production", "eastus"],
    config: %{
      "cloud_provider" => "azure",
      "resource_group" => "rg-production",
      "region" => "eastus"
    },
    organization_id: org.id
  },
  %{
    hostname: "az-db-eastus-01",
    os_type: "linux",
    os_version: "Ubuntu 22.04 LTS",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["cloud", "azure", "database", "production", "eastus"],
    config: %{
      "cloud_provider" => "azure",
      "resource_group" => "rg-production"
    },
    organization_id: org.id
  },

  # GCP Instances
  %{
    hostname: "gcp-ml-us-central1-01",
    os_type: "linux",
    os_version: "Debian 12",
    agent_version: "1.2.0",
    machine_id: :crypto.strong_rand_bytes(16),
    status: "online",
    tags: ["cloud", "gcp", "ml", "gpu", "us-central1"],
    config: %{
      "cloud_provider" => "gcp",
      "project" => "tamandua-ml",
      "zone" => "us-central1-a"
    },
    organization_id: org.id
  }
]

# Insert agents
for agent_attrs <- sample_agents do
  # Check if agent with same hostname exists
  case Repo.get_by(Agent, hostname: agent_attrs.hostname, organization_id: org.id) do
    nil ->
      agent_with_timestamp = Map.put(agent_attrs, :last_seen_at, generate_last_seen.(agent_attrs.status))

      %Agent{}
      |> Agent.changeset(agent_with_timestamp)
      |> Repo.insert!()
      IO.puts("  Created agent: #{agent_attrs.hostname} (#{agent_attrs.os_type}) [#{agent_attrs.status}]")

    existing ->
      # Update existing agent
      agent_with_timestamp = Map.put(agent_attrs, :last_seen_at, generate_last_seen.(agent_attrs.status))

      existing
      |> Agent.changeset(agent_with_timestamp)
      |> Repo.update!()
      IO.puts("  Updated agent: #{agent_attrs.hostname} (#{agent_attrs.os_type}) [#{agent_attrs.status}]")
  end
end

# Summary
IO.puts("\n" <> String.duplicate("=", 71))
IO.puts("Sample Agents Summary")
IO.puts("=" <> String.duplicate("=", 70))

by_os = Enum.group_by(sample_agents, & &1.os_type)
IO.puts("\nBy Operating System:")
for {os, agents} <- by_os do
  IO.puts("  #{os}: #{length(agents)} agents")
end

by_status = Enum.group_by(sample_agents, & &1.status)
IO.puts("\nBy Status:")
for {status, agents} <- by_status do
  IO.puts("  #{status}: #{length(agents)} agents")
end

workstations = Enum.count(sample_agents, fn a -> "workstation" in a.tags end)
servers = Enum.count(sample_agents, fn a -> "server" in a.tags end)
cloud = Enum.count(sample_agents, fn a -> "cloud" in a.tags end)

IO.puts("\nBy Type:")
IO.puts("  Workstations: #{workstations}")
IO.puts("  Servers: #{servers}")
IO.puts("  Cloud Instances: #{cloud}")

IO.puts("\nTotal agents seeded: #{length(sample_agents)}")
IO.puts("Sample agents seeding complete!")
