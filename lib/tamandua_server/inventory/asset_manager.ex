defmodule TamanduaServer.Inventory.AssetManager do
  @moduledoc """
  Asset Inventory & Risk Scoring Engine

  UNIQUE FEATURE: Comprehensive asset management that:
  - Tracks all endpoints with detailed inventory
  - Calculates dynamic risk scores (0-100)
  - Identifies vulnerabilities and misconfigurations
  - Monitors software inventory and versions
  - Detects shadow IT and unauthorized software
  - Prioritizes remediation based on risk

  This provides attack surface visibility similar to
  Qualys, Tenable, or CrowdStrike Falcon Spotlight.
  """

  use GenServer
  require Logger
  import Ecto.Query

  alias TamanduaServer.{Repo, Agents}
  alias TamanduaServer.Inventory.LicenseAnalyzer

  # Asset schema
  defmodule Asset do
    use Ecto.Schema
    import Ecto.Changeset

    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id
    schema "assets" do
      field :agent_id, :binary_id
      field :hostname, :string
      field :fqdn, :string
      field :os_type, :string
      field :os_version, :string
      field :os_build, :string
      field :architecture, :string
      field :ip_addresses, {:array, :string}, default: []
      field :mac_addresses, {:array, :string}, default: []
      field :domain, :string
      field :last_seen, :utc_datetime
      field :first_seen, :utc_datetime

      # Hardware info
      field :cpu_model, :string
      field :cpu_cores, :integer
      field :memory_gb, :float
      field :disk_gb, :float
      field :is_virtual, :boolean
      field :hypervisor, :string

      # Risk & security
      field :risk_score, :integer, default: 0
      field :criticality, :string, default: "medium"  # low, medium, high, critical
      field :security_posture, :map, default: %{}
      field :compliance_status, :map, default: %{}

      # Software inventory
      field :installed_software, {:array, :map}, default: []
      field :running_services, {:array, :map}, default: []
      field :open_ports, {:array, :map}, default: []

      # Vulnerabilities
      field :vulnerabilities, {:array, :map}, default: []
      field :vulnerability_count, :integer, default: 0
      field :critical_vuln_count, :integer, default: 0

      # Tags and classification
      field :tags, {:array, :string}, default: []
      field :business_unit, :string
      field :owner, :string
      field :environment, :string  # production, staging, development, test
      field :asset_type, :string  # workstation, server, laptop, virtual_machine

      # Cloud metadata
      field :cloud_provider, :string
      field :cloud_region, :string
      field :cloud_instance_type, :string
      field :cloud_tags, :map, default: %{}

      timestamps()
    end

    def changeset(asset, attrs) do
      asset
      |> cast(attrs, [
        :agent_id, :hostname, :fqdn, :os_type, :os_version, :os_build,
        :architecture, :ip_addresses, :mac_addresses, :domain, :last_seen,
        :first_seen, :cpu_model, :cpu_cores, :memory_gb, :disk_gb, :is_virtual,
        :hypervisor, :risk_score, :criticality, :security_posture, :compliance_status,
        :installed_software, :running_services, :open_ports, :vulnerabilities,
        :vulnerability_count, :critical_vuln_count, :tags, :business_unit,
        :owner, :environment, :asset_type, :cloud_provider, :cloud_region,
        :cloud_instance_type, :cloud_tags
      ])
      |> validate_required([:hostname])
      |> validate_inclusion(:criticality, ["low", "medium", "high", "critical"])
      |> validate_inclusion(:environment, [nil, "production", "staging", "development", "test"])
    end
  end

  # Software inventory item
  defmodule SoftwareItem do
    @enforce_keys [:name, :version]
    defstruct [
      :name,
      :version,
      :vendor,
      :install_date,
      :install_path,
      :is_authorized,
      :category,
      :cve_list
    ]
  end

  # Vulnerability record
  defmodule Vulnerability do
    @enforce_keys [:cve_id, :severity]
    defstruct [
      :cve_id,
      :severity,           # critical, high, medium, low
      :cvss_score,
      :description,
      :affected_software,
      :remediation,
      :exploit_available,
      :exploit_in_wild,
      :patch_available,
      :discovered_at
    ]
  end

  # Risk factors for scoring
  @risk_factors %{
    # Vulnerability-based
    critical_vulns: 25,
    high_vulns: 15,
    medium_vulns: 5,
    exploit_available: 20,
    exploit_in_wild: 30,

    # Configuration-based
    no_antivirus: 15,
    outdated_os: 20,
    no_encryption: 15,
    admin_account_enabled: 10,
    rdp_exposed: 20,
    ssh_exposed: 10,

    # Behavior-based
    recent_alert: 10,
    multiple_alerts: 15,
    anomalous_behavior: 10,

    # Asset value
    critical_asset: 20,
    production_environment: 10,
    holds_sensitive_data: 15
  }

  # Authorized software list (baseline)
  @authorized_software [
    # Operating systems and components
    ~r/^Microsoft Windows/i,
    ~r/^Microsoft Visual C\+\+/i,
    ~r/^Microsoft .NET/i,

    # Browsers
    ~r/^Google Chrome$/i,
    ~r/^Mozilla Firefox$/i,
    ~r/^Microsoft Edge$/i,

    # Office
    ~r/^Microsoft Office/i,
    ~r/^Microsoft 365/i,

    # Development tools
    ~r/^Visual Studio/i,
    ~r/^Git for Windows$/i,
    ~r/^Node\.js$/i,
    ~r/^Python/i,

    # Security tools
    ~r/^Tamandua Agent$/i,
    ~r/^Windows Defender/i
  ]

  # GenServer state
  defstruct [
    :assets,
    :vulnerability_db,
    :risk_calculation_interval,
    :software_baseline,
    :last_scan
  ]

  ## Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Register or update an asset from agent telemetry
  """
  def register_asset(agent_id, asset_info) do
    GenServer.call(__MODULE__, {:register_asset, agent_id, asset_info})
  end

  @doc """
  Get all assets
  """
  def list_assets(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_assets, filters})
  end

  @doc """
  Get a specific asset
  """
  def get_asset(id) do
    GenServer.call(__MODULE__, {:get_asset, id})
  end

  @doc """
  Update asset metadata
  """
  def update_asset(id, attrs) do
    GenServer.call(__MODULE__, {:update_asset, id, attrs})
  end

  @doc """
  Update software inventory for an asset
  """
  def update_software_inventory(agent_id, software_list) do
    GenServer.call(__MODULE__, {:update_software, agent_id, software_list})
  end

  @doc """
  Analyze license metadata for a persisted asset.
  """
  def analyze_license_metadata(asset_id) when is_binary(asset_id) do
    case get_asset(asset_id) do
      {:ok, asset} -> {:ok, LicenseAnalyzer.analyze_asset(asset)}
      {:error, reason} -> {:error, reason}
    end
  end

  def analyze_license_metadata(%Asset{} = asset), do: {:ok, LicenseAnalyzer.analyze_asset(asset)}
  def analyze_license_metadata(asset) when is_map(asset), do: {:ok, LicenseAnalyzer.analyze_asset(asset)}

  @doc """
  Calculate risk score for an asset
  """
  def calculate_risk_score(asset_id) do
    GenServer.call(__MODULE__, {:calculate_risk, asset_id})
  end

  @doc """
  Get assets by risk level
  """
  def get_high_risk_assets(threshold \\ 70) do
    GenServer.call(__MODULE__, {:high_risk_assets, threshold})
  end

  @doc """
  Scan for vulnerabilities
  """
  def scan_vulnerabilities(asset_id) do
    GenServer.call(__MODULE__, {:scan_vulns, asset_id})
  end

  @doc """
  Get vulnerability summary
  """
  def get_vulnerability_summary do
    GenServer.call(__MODULE__, :vuln_summary)
  end

  @doc """
  Detect unauthorized software
  """
  def detect_unauthorized_software(asset_id) do
    GenServer.call(__MODULE__, {:detect_unauthorized, asset_id})
  end

  @doc """
  Get asset risk report
  """
  def get_risk_report(asset_id) do
    GenServer.call(__MODULE__, {:risk_report, asset_id})
  end

  ## Server Callbacks

  @impl true
  def init(_opts) do
    Logger.info("Starting Asset Inventory Manager")

    state = %__MODULE__{
      assets: load_assets(),
      vulnerability_db: init_vulnerability_database(),
      risk_calculation_interval: 3600_000,  # 1 hour
      software_baseline: @authorized_software,
      last_scan: nil
    }

    # Schedule periodic risk recalculation
    schedule_risk_calculation()

    {:ok, state}
  end

  @impl true
  def handle_call({:register_asset, agent_id, info}, _from, state) do
    asset = find_or_create_asset(state.assets, agent_id, info)
    updated_asset = update_asset_info(asset, info)

    # Calculate initial risk score
    risk_score = calculate_asset_risk(updated_asset, state)
    final_asset = %{updated_asset | risk_score: risk_score}

    # Save to database
    save_asset(final_asset)

    new_assets = Map.put(state.assets, final_asset.id, final_asset)
    {:reply, {:ok, final_asset}, %{state | assets: new_assets}}
  end

  @impl true
  def handle_call({:list_assets, filters}, _from, state) do
    assets = state.assets
      |> Map.values()
      |> filter_assets(filters)
      |> Enum.sort_by(& &1.risk_score, :desc)

    {:reply, {:ok, assets}, state}
  end

  @impl true
  def handle_call({:get_asset, id}, _from, state) do
    case Map.get(state.assets, id) do
      nil -> {:reply, {:error, :not_found}, state}
      asset -> {:reply, {:ok, asset}, state}
    end
  end

  @impl true
  def handle_call({:update_asset, id, attrs}, _from, state) do
    case Map.get(state.assets, id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      asset ->
        updated = struct(asset, attrs)
        save_asset(updated)
        new_assets = Map.put(state.assets, id, updated)
        {:reply, {:ok, updated}, %{state | assets: new_assets}}
    end
  end

  @impl true
  def handle_call({:update_software, agent_id, software_list}, _from, state) do
    case find_asset_by_agent(state.assets, agent_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      asset ->
        # Process software list
        processed = process_software_list(software_list, state.software_baseline)

        # Check for vulnerabilities
        vulns = check_software_vulnerabilities(processed, state.vulnerability_db)

        updated = %{asset |
          installed_software: processed,
          vulnerabilities: vulns,
          vulnerability_count: length(vulns),
          critical_vuln_count: Enum.count(vulns, & &1.severity == "critical")
        }

        # Recalculate risk
        risk_score = calculate_asset_risk(updated, state)
        final = %{updated | risk_score: risk_score}

        save_asset(final)
        new_assets = Map.put(state.assets, asset.id, final)

        {:reply, {:ok, final}, %{state | assets: new_assets}}
    end
  end

  @impl true
  def handle_call({:calculate_risk, asset_id}, _from, state) do
    case Map.get(state.assets, asset_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      asset ->
        risk_score = calculate_asset_risk(asset, state)
        updated = %{asset | risk_score: risk_score}
        save_asset(updated)
        new_assets = Map.put(state.assets, asset_id, updated)
        {:reply, {:ok, risk_score}, %{state | assets: new_assets}}
    end
  end

  @impl true
  def handle_call({:high_risk_assets, threshold}, _from, state) do
    high_risk = state.assets
      |> Map.values()
      |> Enum.filter(& &1.risk_score >= threshold)
      |> Enum.sort_by(& &1.risk_score, :desc)

    {:reply, {:ok, high_risk}, state}
  end

  @impl true
  def handle_call({:scan_vulns, asset_id}, _from, state) do
    case Map.get(state.assets, asset_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      asset ->
        vulns = check_software_vulnerabilities(
          asset.installed_software,
          state.vulnerability_db
        )

        # Add OS-level vulnerabilities
        os_vulns = check_os_vulnerabilities(asset, state.vulnerability_db)
        all_vulns = vulns ++ os_vulns

        updated = %{asset |
          vulnerabilities: all_vulns,
          vulnerability_count: length(all_vulns),
          critical_vuln_count: Enum.count(all_vulns, & &1.severity == "critical")
        }

        risk_score = calculate_asset_risk(updated, state)
        final = %{updated | risk_score: risk_score}

        save_asset(final)
        new_assets = Map.put(state.assets, asset_id, final)

        {:reply, {:ok, all_vulns}, %{state | assets: new_assets}}
    end
  end

  @impl true
  def handle_call(:vuln_summary, _from, state) do
    summary = state.assets
      |> Map.values()
      |> Enum.reduce(%{total: 0, critical: 0, high: 0, medium: 0, low: 0}, fn asset, acc ->
        %{
          total: acc.total + asset.vulnerability_count,
          critical: acc.critical + asset.critical_vuln_count,
          high: acc.high + count_vulns_by_severity(asset.vulnerabilities, "high"),
          medium: acc.medium + count_vulns_by_severity(asset.vulnerabilities, "medium"),
          low: acc.low + count_vulns_by_severity(asset.vulnerabilities, "low")
        }
      end)

    total_assets = map_size(state.assets)
    affected_assets = Enum.count(state.assets, fn {_, a} -> a.vulnerability_count > 0 end)

    result = %{
      vulnerabilities: summary,
      assets: %{
        total: total_assets,
        affected: affected_assets,
        percentage: if(total_assets > 0, do: affected_assets / total_assets * 100, else: 0)
      },
      average_risk_score: calculate_average_risk(state.assets)
    }

    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:detect_unauthorized, asset_id}, _from, state) do
    case Map.get(state.assets, asset_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      asset ->
        unauthorized = asset.installed_software
          |> Enum.reject(fn sw -> sw[:is_authorized] == true end)
          |> Enum.map(fn sw ->
            %{
              name: sw[:name],
              version: sw[:version],
              category: categorize_software(sw[:name]),
              risk_level: assess_software_risk(sw)
            }
          end)

        {:reply, {:ok, unauthorized}, state}
    end
  end

  @impl true
  def handle_call({:risk_report, asset_id}, _from, state) do
    case Map.get(state.assets, asset_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      asset ->
        report = generate_risk_report(asset, state)
        {:reply, {:ok, report}, state}
    end
  end

  @impl true
  def handle_info(:recalculate_all_risks, state) do
    Logger.debug("Recalculating risk scores for all assets")

    new_assets = state.assets
      |> Map.new(fn {id, asset} ->
        risk_score = calculate_asset_risk(asset, state)
        updated = %{asset | risk_score: risk_score}
        save_asset(updated)
        {id, updated}
      end)

    schedule_risk_calculation()
    {:noreply, %{state | assets: new_assets, last_scan: DateTime.utc_now()}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  ## Private Functions

  defp load_assets do
    try do
      Repo.all(Asset)
      |> Enum.map(fn asset -> {asset.id, asset} end)
      |> Map.new()
    rescue
      _ -> %{}
    end
  end

  defp init_vulnerability_database do
    # In production, this would load from a CVE database or vulnerability feed
    %{
      # Example known vulnerable software patterns
      "vulnerable_software" => [
        %{
          pattern: ~r/Log4j.*2\.(0|1[0-6])/i,
          cve: "CVE-2021-44228",
          severity: "critical",
          cvss: 10.0,
          description: "Log4Shell - Remote Code Execution"
        },
        %{
          pattern: ~r/OpenSSL.*(1\.0\.[0-1]|0\.9)/i,
          cve: "CVE-2014-0160",
          severity: "critical",
          cvss: 9.8,
          description: "Heartbleed vulnerability"
        },
        %{
          pattern: ~r/Apache.*2\.4\.(49|50)/i,
          cve: "CVE-2021-41773",
          severity: "critical",
          cvss: 9.8,
          description: "Apache Path Traversal"
        },
        %{
          pattern: ~r/Microsoft Exchange.*(2013|2016|2019)/i,
          cve: "CVE-2021-26855",
          severity: "critical",
          cvss: 9.8,
          description: "ProxyLogon SSRF"
        }
      ],
      # OS-level vulnerabilities
      "vulnerable_os" => [
        %{
          pattern: ~r/Windows 7/i,
          cve: "multiple",
          severity: "high",
          description: "End-of-life OS - No security updates"
        },
        %{
          pattern: ~r/Windows Server 2008/i,
          cve: "multiple",
          severity: "critical",
          description: "End-of-life OS - Critical risk"
        },
        %{
          pattern: ~r/Windows XP/i,
          cve: "multiple",
          severity: "critical",
          description: "End-of-life OS - Extreme risk"
        }
      ]
    }
  end

  defp find_or_create_asset(assets, agent_id, info) do
    case find_asset_by_agent(assets, agent_id) do
      nil ->
        %Asset{
          id: Ecto.UUID.generate(),
          agent_id: agent_id,
          first_seen: DateTime.utc_now()
        }
      existing ->
        existing
    end
  end

  defp find_asset_by_agent(assets, agent_id) do
    assets
    |> Map.values()
    |> Enum.find(& &1.agent_id == agent_id)
  end

  defp update_asset_info(asset, info) do
    %{asset |
      hostname: info[:hostname] || asset.hostname,
      fqdn: info[:fqdn] || asset.fqdn,
      os_type: info[:os_type] || asset.os_type,
      os_version: info[:os_version] || asset.os_version,
      os_build: info[:os_build] || asset.os_build,
      architecture: info[:architecture] || asset.architecture,
      ip_addresses: info[:ip_addresses] || asset.ip_addresses,
      mac_addresses: info[:mac_addresses] || asset.mac_addresses,
      domain: info[:domain] || asset.domain,
      last_seen: DateTime.utc_now(),
      cpu_model: info[:cpu_model] || asset.cpu_model,
      cpu_cores: info[:cpu_cores] || asset.cpu_cores,
      memory_gb: info[:memory_gb] || asset.memory_gb,
      disk_gb: info[:disk_gb] || asset.disk_gb,
      is_virtual: info[:is_virtual] || asset.is_virtual,
      hypervisor: info[:hypervisor] || asset.hypervisor,
      cloud_provider: info[:cloud_provider] || asset.cloud_provider,
      cloud_region: info[:cloud_region] || asset.cloud_region,
      cloud_instance_type: info[:cloud_instance_type] || asset.cloud_instance_type,
      security_posture: info[:security_posture] || asset.security_posture
    }
  end

  defp save_asset(asset) do
    try do
      %Asset{}
      |> Asset.changeset(Map.from_struct(asset))
      |> Repo.insert(on_conflict: :replace_all, conflict_target: :id)
    rescue
      e ->
        Logger.error("Failed to save asset: #{inspect(e)}")
        {:error, e}
    end
  end

  defp calculate_asset_risk(asset, state) do
    base_score = 0

    # Vulnerability risk
    vuln_score = calculate_vulnerability_risk(asset)

    # Configuration risk
    config_score = calculate_config_risk(asset)

    # Behavioral risk
    behavior_score = calculate_behavior_risk(asset)

    # Asset value multiplier
    value_multiplier = get_asset_value_multiplier(asset)

    # Calculate final score (0-100)
    raw_score = (base_score + vuln_score + config_score + behavior_score) * value_multiplier

    min(round(raw_score), 100)
  end

  defp calculate_vulnerability_risk(asset) do
    vulns = asset.vulnerabilities || []

    critical = Enum.count(vulns, & &1[:severity] == "critical")
    high = Enum.count(vulns, & &1[:severity] == "high")
    medium = Enum.count(vulns, & &1[:severity] == "medium")

    exploitable = Enum.count(vulns, & &1[:exploit_available] == true)
    in_wild = Enum.count(vulns, & &1[:exploit_in_wild] == true)

    critical * @risk_factors.critical_vulns +
    high * @risk_factors.high_vulns +
    medium * @risk_factors.medium_vulns +
    exploitable * @risk_factors.exploit_available +
    in_wild * @risk_factors.exploit_in_wild
  end

  defp calculate_config_risk(asset) do
    posture = asset.security_posture || %{}
    score = 0

    score = if !posture["antivirus_enabled"], do: score + @risk_factors.no_antivirus, else: score
    score = if !posture["disk_encrypted"], do: score + @risk_factors.no_encryption, else: score
    score = if posture["admin_account_enabled"], do: score + @risk_factors.admin_account_enabled, else: score
    score = if posture["rdp_exposed"], do: score + @risk_factors.rdp_exposed, else: score
    score = if posture["ssh_exposed"], do: score + @risk_factors.ssh_exposed, else: score

    # Check for outdated OS
    score = if is_os_outdated?(asset.os_type, asset.os_version), do: score + @risk_factors.outdated_os, else: score

    score
  end

  defp calculate_behavior_risk(asset) do
    # This would integrate with the alerts system
    # For now, return 0
    0
  end

  defp get_asset_value_multiplier(asset) do
    base = 1.0

    base = if asset.criticality == "critical", do: base * 1.5, else: base
    base = if asset.criticality == "high", do: base * 1.25, else: base
    base = if asset.environment == "production", do: base * 1.25, else: base

    base
  end

  defp is_os_outdated?(nil, _), do: false
  defp is_os_outdated?(os_type, os_version) do
    outdated_os = [
      {~r/Windows 7/i, true},
      {~r/Windows 8/i, true},
      {~r/Windows XP/i, true},
      {~r/Windows Server 2008/i, true},
      {~r/Windows Server 2003/i, true},
      {~r/Ubuntu 16/i, true},
      {~r/Ubuntu 14/i, true},
      {~r/CentOS 6/i, true},
      {~r/CentOS 7/i, false}  # Still in maintenance
    ]

    full_os = "#{os_type} #{os_version}"

    Enum.any?(outdated_os, fn {pattern, outdated} ->
      Regex.match?(pattern, full_os) && outdated
    end)
  end

  defp filter_assets(assets, filters) do
    Enum.filter(assets, fn asset ->
      Enum.all?(filters, fn
        {:criticality, value} -> asset.criticality == value
        {:environment, value} -> asset.environment == value
        {:os_type, value} -> String.contains?(String.downcase(asset.os_type || ""), String.downcase(value))
        {:min_risk, value} -> asset.risk_score >= value
        {:max_risk, value} -> asset.risk_score <= value
        {:tag, value} -> value in (asset.tags || [])
        {:has_vulns, true} -> asset.vulnerability_count > 0
        {:has_vulns, false} -> asset.vulnerability_count == 0
        _ -> true
      end)
    end)
  end

  defp process_software_list(software_list, baseline) do
    Enum.map(software_list, fn sw ->
      name = software_value(sw, "name")

      is_authorized = Enum.any?(baseline, fn pattern ->
        Regex.match?(pattern, name || "")
      end)

      %{
        name: name,
        version: software_value(sw, "version"),
        vendor: software_value(sw, "vendor"),
        license: software_value(sw, "license"),
        install_date: software_value(sw, "install_date"),
        install_path: software_value(sw, "install_path"),
        metadata: software_metadata(sw),
        is_authorized: is_authorized,
        category: categorize_software(name)
      }
    end)
  end

  defp software_value(sw, key) when is_map(sw) do
    Map.get(sw, key) || Map.get(sw, software_atom_key(key))
  end

  defp software_value(_sw, _key), do: nil

  defp software_atom_key("license"), do: :license
  defp software_atom_key("metadata"), do: :metadata
  defp software_atom_key("licenses"), do: :licenses
  defp software_atom_key("name"), do: :name
  defp software_atom_key("version"), do: :version
  defp software_atom_key("vendor"), do: :vendor
  defp software_atom_key("install_date"), do: :install_date
  defp software_atom_key("install_path"), do: :install_path
  defp software_atom_key(_key), do: nil

  defp software_metadata(sw) when is_map(sw) do
    case software_value(sw, "metadata") do
      metadata when is_map(metadata) -> metadata
      _ -> %{}
    end
  end

  defp software_metadata(_sw), do: %{}

  defp categorize_software(nil), do: "unknown"
  defp categorize_software(name) do
    cond do
      Regex.match?(~r/(antivirus|defender|security|protection)/i, name) -> "security"
      Regex.match?(~r/(chrome|firefox|edge|safari|browser)/i, name) -> "browser"
      Regex.match?(~r/(office|word|excel|powerpoint|outlook)/i, name) -> "productivity"
      Regex.match?(~r/(visual studio|vscode|intellij|eclipse)/i, name) -> "development"
      Regex.match?(~r/(7-zip|winrar|winzip)/i, name) -> "utility"
      Regex.match?(~r/(teamviewer|anydesk|vnc|remote)/i, name) -> "remote_access"
      Regex.match?(~r/(torrent|utorrent|bittorrent)/i, name) -> "p2p"
      true -> "other"
    end
  end

  defp assess_software_risk(software) do
    category = software[:category] || categorize_software(software[:name])

    case category do
      "p2p" -> "high"
      "remote_access" ->
        if software[:is_authorized], do: "low", else: "high"
      "security" -> "low"
      "browser" -> "low"
      "productivity" -> "low"
      "development" -> "medium"
      _ -> "medium"
    end
  end

  defp check_software_vulnerabilities(software_list, vuln_db) do
    patterns = vuln_db["vulnerable_software"] || []

    software_list
    |> Enum.flat_map(fn sw ->
      full_name = "#{sw[:name]} #{sw[:version]}"

      patterns
      |> Enum.filter(fn vuln -> Regex.match?(vuln.pattern, full_name) end)
      |> Enum.map(fn vuln ->
        %{
          cve_id: vuln.cve,
          severity: vuln.severity,
          cvss_score: vuln.cvss,
          description: vuln.description,
          affected_software: sw[:name],
          affected_version: sw[:version],
          exploit_available: true,
          patch_available: true,
          discovered_at: DateTime.utc_now()
        }
      end)
    end)
  end

  defp check_os_vulnerabilities(asset, vuln_db) do
    patterns = vuln_db["vulnerable_os"] || []
    full_os = "#{asset.os_type} #{asset.os_version}"

    patterns
    |> Enum.filter(fn vuln -> Regex.match?(vuln.pattern, full_os) end)
    |> Enum.map(fn vuln ->
      %{
        cve_id: vuln.cve,
        severity: vuln.severity,
        description: vuln.description,
        affected_software: "Operating System",
        affected_version: asset.os_version,
        discovered_at: DateTime.utc_now()
      }
    end)
  end

  defp count_vulns_by_severity(vulns, severity) do
    Enum.count(vulns || [], & &1[:severity] == severity)
  end

  defp calculate_average_risk(assets) do
    if map_size(assets) == 0 do
      0
    else
      total = assets
        |> Map.values()
        |> Enum.map(& &1.risk_score)
        |> Enum.sum()

      round(total / map_size(assets))
    end
  end

  defp generate_risk_report(asset, state) do
    %{
      asset_id: asset.id,
      hostname: asset.hostname,
      risk_score: asset.risk_score,
      risk_level: get_risk_level(asset.risk_score),
      generated_at: DateTime.utc_now(),

      risk_breakdown: %{
        vulnerability_risk: calculate_vulnerability_risk(asset),
        configuration_risk: calculate_config_risk(asset),
        behavioral_risk: calculate_behavior_risk(asset)
      },

      vulnerabilities: %{
        total: asset.vulnerability_count,
        critical: asset.critical_vuln_count,
        high: count_vulns_by_severity(asset.vulnerabilities, "high"),
        medium: count_vulns_by_severity(asset.vulnerabilities, "medium"),
        low: count_vulns_by_severity(asset.vulnerabilities, "low"),
        list: asset.vulnerabilities || []
      },

      security_posture: asset.security_posture,

      unauthorized_software: asset.installed_software
        |> Enum.reject(& &1[:is_authorized])
        |> Enum.map(& %{name: &1[:name], category: &1[:category]}),

      recommendations: generate_recommendations(asset),

      metadata: %{
        os: "#{asset.os_type} #{asset.os_version}",
        environment: asset.environment,
        criticality: asset.criticality,
        last_seen: asset.last_seen
      }
    }
  end

  defp get_risk_level(score) do
    cond do
      score >= 80 -> "critical"
      score >= 60 -> "high"
      score >= 40 -> "medium"
      score >= 20 -> "low"
      true -> "minimal"
    end
  end

  defp generate_recommendations(asset) do
    recommendations = []

    # Vulnerability recommendations
    recommendations = if asset.critical_vuln_count > 0 do
      recommendations ++ ["URGENT: Patch #{asset.critical_vuln_count} critical vulnerabilities"]
    else
      recommendations
    end

    # OS recommendations
    recommendations = if is_os_outdated?(asset.os_type, asset.os_version) do
      recommendations ++ ["Upgrade operating system to a supported version"]
    else
      recommendations
    end

    # Security posture recommendations
    posture = asset.security_posture || %{}

    recommendations = if !posture["antivirus_enabled"] do
      recommendations ++ ["Enable antivirus protection"]
    else
      recommendations
    end

    recommendations = if !posture["disk_encrypted"] do
      recommendations ++ ["Enable disk encryption"]
    else
      recommendations
    end

    recommendations = if posture["rdp_exposed"] do
      recommendations ++ ["Restrict RDP access to VPN or specific IPs"]
    else
      recommendations
    end

    # Unauthorized software
    unauthorized = asset.installed_software
      |> Enum.reject(& &1[:is_authorized])
      |> Enum.filter(& &1[:category] in ["p2p", "remote_access"])

    recommendations = if length(unauthorized) > 0 do
      recommendations ++ ["Review and remove #{length(unauthorized)} potentially risky applications"]
    else
      recommendations
    end

    recommendations
  end

  defp schedule_risk_calculation do
    # Recalculate every hour
    Process.send_after(self(), :recalculate_all_risks, 3600_000)
  end

  # ============================================================================
  # Public API Wrapper Functions
  # ============================================================================

  @doc """
  Create a new asset from params.
  """
  def create_asset(params) when is_map(params) do
    changeset = Asset.changeset(%Asset{}, params)
    Repo.insert(changeset)
  end

  @doc """
  Delete an asset by ID.
  """
  def delete_asset(asset_id) do
    case get_asset(asset_id) do
      {:ok, asset} -> Repo.delete(asset)
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  List vulnerabilities for an asset or all assets.
  """
  def list_vulnerabilities(asset_id \\ nil, opts \\ %{}) do
    query = if asset_id do
      from a in Asset,
        where: a.id == ^asset_id,
        select: a.vulnerabilities
    else
      from a in Asset,
        where: a.vulnerability_count > 0,
        select: %{asset_id: a.id, hostname: a.hostname, vulnerabilities: a.vulnerabilities}
    end

    results = Repo.all(query)

    filtered = case opts do
      %{severity: severity} ->
        Enum.filter(results, fn
          vulns when is_list(vulns) ->
            Enum.any?(vulns, &(&1["severity"] == severity))
          %{vulnerabilities: vulns} ->
            Enum.any?(vulns || [], &(&1["severity"] == severity))
        end)
      _ -> results
    end

    {:ok, filtered}
  end

  @doc """
  Trigger a vulnerability scan on an asset.
  """
  def trigger_vulnerability_scan(asset_id, scan_type \\ "full", opts \\ %{}) do
    case get_asset(asset_id) do
      {:ok, asset} ->
        scan_job = %{
          id: UUID.uuid4(),
          asset_id: asset_id,
          hostname: asset.hostname,
          scan_type: scan_type,
          status: "pending",
          started_at: DateTime.utc_now(),
          options: opts
        }

        # In production, would queue the scan job
        Logger.info("Triggered vulnerability scan for asset #{asset_id}: #{scan_type}")
        {:ok, scan_job}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
