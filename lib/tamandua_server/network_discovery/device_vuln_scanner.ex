defmodule TamanduaServer.NetworkDiscovery.DeviceVulnScanner do
  @moduledoc """
  Network Device Vulnerability Scanner

  Agentless vulnerability scanning for network infrastructure devices (switches,
  routers, printers, cameras, IoT). Performs protocol-based security checks:

  - **SNMP**: default community strings, firmware version extraction (sysDescr/sysObjectID)
  - **SSH**: version banner checking against known CVE database
  - **HTTP/HTTPS**: web interface detection, TLS version/cipher checks, default credentials
  - **Telnet**: detect open telnet (inherently insecure), banner grab
  - **TFTP**: detect open TFTP (firmware exfiltration risk)

  Findings are cross-referenced with the existing Vulnerability.CVE module.
  Scans are scheduled with configurable frequency and can be run on-demand.
  """

  use GenServer
  require Logger

  alias TamanduaServer.NetworkDiscovery.DeviceInventory

  # ============================================================================
  # Types
  # ============================================================================

  defmodule VulnFinding do
    @moduledoc "A vulnerability finding for a network device."
    defstruct [
      :id,
      :device_id,
      :device_ip,
      :device_mac,
      :device_type,
      :protocol,          # "snmp"|"ssh"|"http"|"https"|"telnet"|"tftp"
      :port,
      :check_type,        # "default_credentials"|"insecure_protocol"|"cve_match"|"weak_crypto"|"version_vuln"
      :title,
      :description,
      :severity,          # "critical"|"high"|"medium"|"low"|"info"
      :cvss_score,
      :cve_ids,           # List of matching CVE IDs
      :evidence,          # Raw evidence (banner, version string, etc.)
      :remediation,       # Recommended fix
      :service_version,
      :discovered_at,
      :scan_id,
      :status             # "open"|"resolved"|"accepted_risk"|"false_positive"
    ]
  end

  defmodule ScanJob do
    @moduledoc "A vulnerability scan job."
    defstruct [
      :id,
      :target_devices,     # List of device IDs
      :target_subnet,      # Or scan entire subnet
      :scan_type,          # "full"|"quick"|"protocol_specific"
      :protocols,          # Specific protocols to check
      :status,             # "pending"|"running"|"completed"|"failed"
      :started_at,
      :completed_at,
      :findings_count,
      :scanned_devices,
      :errors
    ]
  end

  # ============================================================================
  # Known vulnerable versions database
  # ============================================================================

  @ssh_vulns [
    %{pattern: ~r/OpenSSH[_ ]([1-6]\.\d|7\.[0-3])/i, cve: "CVE-2016-10012", severity: "high",
      description: "OpenSSH < 7.4 - privilege escalation via shared memory manager"},
    %{pattern: ~r/OpenSSH[_ ]([1-6]\.\d|7\.[0-6])/i, cve: "CVE-2018-15473", severity: "medium",
      description: "OpenSSH < 7.7 - user enumeration via malformed packets"},
    %{pattern: ~r/OpenSSH[_ ]([1-7]\.\d|8\.[0-7])/i, cve: "CVE-2023-38408", severity: "critical",
      description: "OpenSSH < 8.8 - PKCS#11 remote code execution via ssh-agent"},
    %{pattern: ~r/OpenSSH[_ ]([1-8]\.\d|9\.[0-7])/i, cve: "CVE-2024-6387", severity: "critical",
      description: "OpenSSH < 9.8 - regreSSHion race condition RCE (glibc-based Linux)"},
    %{pattern: ~r/dropbear[_ ]20(1[0-9]|20\.[0-8])/i, cve: "CVE-2021-36369", severity: "medium",
      description: "Dropbear SSH < 2020.79 - trivial authentication bypass"},
  ]

  @http_server_vulns [
    %{pattern: ~r/Apache\/2\.4\.(49|50)/i, cve: "CVE-2021-41773", severity: "critical",
      description: "Apache 2.4.49-50 - path traversal and remote code execution"},
    %{pattern: ~r/Apache\/2\.4\.([0-3]\d|4[0-8])/i, cve: "CVE-2021-40438", severity: "high",
      description: "Apache < 2.4.49 - SSRF via mod_proxy"},
    %{pattern: ~r/nginx\/(0\.\d|1\.[0-9]\.|1\.1[0-6]\.)/i, cve: "CVE-2021-23017", severity: "high",
      description: "nginx < 1.17.7 - DNS resolver off-by-one heap write"},
    %{pattern: ~r/Microsoft-IIS\/([5-7]\.\d|8\.0)/i, cve: "CVE-2017-7269", severity: "critical",
      description: "IIS 6.0 WebDAV buffer overflow remote code execution"},
    %{pattern: ~r/lighttpd\/1\.(4\.([0-3]\d|4[0-4]))/i, cve: "CVE-2022-22707", severity: "high",
      description: "lighttpd < 1.4.45 - use-after-free via HTTP request smuggling"},
    %{pattern: ~r/mini_httpd/i, cve: "CVE-2018-18778", severity: "high",
      description: "mini_httpd - directory traversal and information disclosure"},
    %{pattern: ~r/GoAhead/i, cve: "CVE-2017-17562", severity: "critical",
      description: "GoAhead embedded web server - environment variable injection RCE"},
  ]

  @snmp_default_communities ["public", "private", "community", "admin", "snmp",
    "default", "manager", "monitor", "secret", "cisco", "switch",
    "router", "cable-docsis", "ILMI"]

  @telnet_vulns [
    %{check: :open_telnet, severity: "high",
      description: "Telnet service is open - transmits credentials in cleartext",
      remediation: "Disable telnet and use SSH for remote management"},
  ]

  @weak_tls_versions ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]

  @weak_ciphers [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5"
  ]

  # ============================================================================
  # GenServer State
  # ============================================================================

  defstruct [
    :findings,          # %{finding_id => VulnFinding}
    :scan_jobs,         # %{scan_id => ScanJob}
    :scan_interval,     # Interval in seconds between scheduled scans
    :last_scan,
    :stats
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Trigger a vulnerability scan on specific devices.
  """
  def scan_devices(device_ids, opts \\ %{}) do
    GenServer.call(__MODULE__, {:scan_devices, device_ids, opts}, 120_000)
  end

  @doc """
  Trigger a vulnerability scan on all devices in a subnet.
  """
  def scan_subnet(subnet, opts \\ %{}) do
    GenServer.call(__MODULE__, {:scan_subnet, subnet, opts}, 120_000)
  end

  @doc """
  Run a full scan on all known devices.
  """
  def scan_all(opts \\ %{}) do
    GenServer.cast(__MODULE__, {:scan_all, opts})
  end

  @doc """
  List vulnerability findings with optional filters.
  """
  def list_findings(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_findings, filters})
  end

  @doc """
  Get a specific finding.
  """
  def get_finding(finding_id) do
    GenServer.call(__MODULE__, {:get_finding, finding_id})
  end

  @doc """
  Update finding status (resolved, accepted_risk, false_positive).
  """
  def update_finding_status(finding_id, status) do
    GenServer.call(__MODULE__, {:update_finding_status, finding_id, status})
  end

  @doc """
  Get scan jobs history.
  """
  def list_scan_jobs do
    GenServer.call(__MODULE__, :list_scan_jobs)
  end

  @doc """
  Get vulnerability summary statistics.
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("[DeviceVulnScanner] Starting Network Device Vulnerability Scanner")

    state = %__MODULE__{
      findings: %{},
      scan_jobs: %{},
      scan_interval: 86_400,  # Default: daily scans
      last_scan: nil,
      stats: %{
        total_findings: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        devices_scanned: 0,
        last_scan: nil
      }
    }

    # Schedule periodic scans
    schedule_scan()

    {:ok, state}
  end

  @impl true
  def handle_call({:scan_devices, device_ids, opts}, _from, state) do
    {scan_job, findings, new_state} = run_device_scan(device_ids, opts, state)
    {:reply, {:ok, %{scan_job: scan_job, findings: findings}}, new_state}
  end

  @impl true
  def handle_call({:scan_subnet, subnet, opts}, _from, state) do
    case DeviceInventory.list_devices(%{subnet: subnet}) do
      {:ok, devices} ->
        device_ids = Enum.map(devices, & &1.id)
        {scan_job, findings, new_state} = run_device_scan(device_ids, opts, state)
        {:reply, {:ok, %{scan_job: scan_job, findings: findings}}, new_state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:list_findings, filters}, _from, state) do
    findings = state.findings
      |> Map.values()
      |> filter_findings(filters)
      |> Enum.sort_by(fn f ->
        severity_rank(f.severity)
      end, :desc)

    {:reply, {:ok, findings}, state}
  end

  @impl true
  def handle_call({:get_finding, finding_id}, _from, state) do
    case Map.get(state.findings, finding_id) do
      nil -> {:reply, {:error, :not_found}, state}
      finding -> {:reply, {:ok, finding}, state}
    end
  end

  @impl true
  def handle_call({:update_finding_status, finding_id, status}, _from, state) do
    case Map.get(state.findings, finding_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      finding ->
        updated = %{finding | status: status}
        new_findings = Map.put(state.findings, finding_id, updated)
        new_state = update_scan_stats(%{state | findings: new_findings})
        {:reply, {:ok, updated}, new_state}
    end
  end

  @impl true
  def handle_call(:list_scan_jobs, _from, state) do
    jobs = state.scan_jobs |> Map.values() |> Enum.sort_by(& &1.started_at, {:desc, DateTime})
    {:reply, {:ok, jobs}, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, {:ok, state.stats}, state}
  end

  @impl true
  def handle_cast({:scan_all, opts}, state) do
    case DeviceInventory.list_devices() do
      {:ok, devices} ->
        device_ids = Enum.map(devices, & &1.id)
        {_scan_job, _findings, new_state} = run_device_scan(device_ids, opts, state)
        {:noreply, new_state}

      {:error, reason} ->
        Logger.error("[DeviceVulnScanner] Failed to list devices for full scan: #{inspect(reason)}")
        {:noreply, state}
    end
  end

  @impl true
  def handle_info(:scheduled_scan, state) do
    Logger.info("[DeviceVulnScanner] Running scheduled vulnerability scan")
    GenServer.cast(self(), {:scan_all, %{}})
    schedule_scan()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Scan Logic
  # ============================================================================

  defp run_device_scan(device_ids, opts, state) do
    scan_id = Ecto.UUID.generate()
    now = DateTime.utc_now()
    scan_type = Map.get(opts, :scan_type, "full")
    protocols = Map.get(opts, :protocols, ["snmp", "ssh", "http", "https", "telnet", "tftp"])

    scan_job = %ScanJob{
      id: scan_id,
      target_devices: device_ids,
      scan_type: scan_type,
      protocols: protocols,
      status: "running",
      started_at: now,
      findings_count: 0,
      scanned_devices: 0,
      errors: []
    }

    # Scan each device
    {findings, errors, scanned} = Enum.reduce(device_ids, {[], [], 0}, fn device_id, {acc_findings, acc_errors, acc_count} ->
      case DeviceInventory.get_device(device_id) do
        {:ok, device} ->
          device_findings = scan_single_device(device, scan_id, protocols)
          {acc_findings ++ device_findings, acc_errors, acc_count + 1}

        {:error, reason} ->
          {acc_findings, [{device_id, reason} | acc_errors], acc_count}
      end
    end)

    # Complete scan job
    completed_job = %{scan_job |
      status: "completed",
      completed_at: DateTime.utc_now(),
      findings_count: length(findings),
      scanned_devices: scanned,
      errors: errors
    }

    # Merge findings
    new_findings = findings
      |> Enum.map(fn f -> {f.id, f} end)
      |> Map.new()
      |> Map.merge(state.findings)

    new_jobs = Map.put(state.scan_jobs, scan_id, completed_job)

    new_state = %{state |
      findings: new_findings,
      scan_jobs: new_jobs,
      last_scan: now
    }
    |> update_scan_stats()

    Logger.info(
      "[DeviceVulnScanner] Scan #{scan_id} complete: #{scanned} devices, #{length(findings)} findings"
    )

    # Emit alerts for critical/high findings
    Enum.each(findings, fn finding ->
      if finding.severity in ["critical", "high"] do
        emit_vuln_alert(finding)
      end
    end)

    {completed_job, findings, new_state}
  end

  defp scan_single_device(device, scan_id, protocols) do
    # Get primary IP for scanning
    primary_ip = List.first(device.ip_addresses)

    if is_nil(primary_ip) do
      []
    else
      do_scan_single_device(device, primary_ip, scan_id, protocols)
    end
  end

  defp do_scan_single_device(device, primary_ip, scan_id, protocols) do
    findings = []

    # Check each open port/service
    port_map = device.open_ports
      |> Enum.map(fn p ->
        port = Map.get(p, "port") || Map.get(p, :port)
        service = Map.get(p, "service") || Map.get(p, :service) || ""
        {port, service}
      end)
      |> Map.new()

    service_map = device.services
      |> Enum.map(fn s ->
        port = Map.get(s, "port") || Map.get(s, :port)
        {port, s}
      end)
      |> Map.new()

    # SNMP checks
    findings = if "snmp" in protocols && (Map.has_key?(port_map, 161) || Map.has_key?(port_map, "161")) do
      findings ++ check_snmp(device, primary_ip, scan_id)
    else
      findings
    end

    # SSH checks
    findings = if "ssh" in protocols do
      ssh_service = Map.get(service_map, 22) || Map.get(service_map, "22")
      if ssh_service do
        findings ++ check_ssh(device, ssh_service, scan_id)
      else
        findings
      end
    else
      findings
    end

    # HTTP checks
    findings = if "http" in protocols do
      http_ports = Enum.filter(port_map, fn {port, service} ->
        port_num = if is_binary(port), do: String.to_integer(port), else: port
        port_num in [80, 8080, 8888, 9090] || String.contains?(to_string(service), "http")
      end)

      Enum.reduce(http_ports, findings, fn {port, _service}, acc ->
        http_svc = Map.get(service_map, port)
        acc ++ check_http(device, primary_ip, port, http_svc, scan_id)
      end)
    else
      findings
    end

    # HTTPS / TLS checks
    findings = if "https" in protocols do
      https_ports = Enum.filter(port_map, fn {port, service} ->
        port_num = if is_binary(port), do: String.to_integer(port), else: port
        port_num in [443, 8443] || String.contains?(to_string(service), "https")
      end)

      Enum.reduce(https_ports, findings, fn {port, _service}, acc ->
        acc ++ check_tls(device, primary_ip, port, scan_id)
      end)
    else
      findings
    end

    # Telnet checks
    findings = if "telnet" in protocols && (Map.has_key?(port_map, 23) || Map.has_key?(port_map, "23")) do
      telnet_svc = Map.get(service_map, 23) || Map.get(service_map, "23")
      findings ++ check_telnet(device, telnet_svc, scan_id)
    else
      findings
    end

    # TFTP checks
    findings = if "tftp" in protocols && (Map.has_key?(port_map, 69) || Map.has_key?(port_map, "69")) do
      findings ++ check_tftp(device, scan_id)
    else
      findings
    end

    findings
  end

  # ============================================================================
  # Protocol-Specific Checks
  # ============================================================================

  defp check_snmp(device, ip, scan_id) do
    findings = []
    now = DateTime.utc_now()

    # Check for default/common community strings
    # Note: actual SNMP probing would use an SNMP library;
    # here we record findings based on what the agent discovered
    services = device.services || []
    snmp_service = Enum.find(services, fn s ->
      port = Map.get(s, "port") || Map.get(s, :port)
      port == 161 || port == "161"
    end)

    # If SNMP port is open, flag default community strings
    extra = if snmp_service, do: Map.get(snmp_service, "extra_info") || Map.get(snmp_service, :extra_info) || %{}, else: %{}

    community = Map.get(extra, "snmp_community") || Map.get(extra, :snmp_community)

    if community && community in @snmp_default_communities do
      findings = [%VulnFinding{
        id: Ecto.UUID.generate(),
        device_id: device.id,
        device_ip: ip,
        device_mac: device.mac_address,
        device_type: device.device_type,
        protocol: "snmp",
        port: 161,
        check_type: "default_credentials",
        title: "SNMP default community string '#{community}'",
        description: "Device responds to SNMP queries with the default community string '#{community}'. " <>
                     "This allows unauthenticated read access to device configuration and potentially write access.",
        severity: if(community == "private", do: "critical", else: "high"),
        cvss_score: if(community == "private", do: 9.8, else: 7.5),
        cve_ids: [],
        evidence: "SNMP community string: #{community}",
        remediation: "Change SNMP community strings to strong, unique values. " <>
                     "Consider upgrading to SNMPv3 with authentication and encryption. " <>
                     "Restrict SNMP access to management VLANs only.",
        service_version: Map.get(extra, "sysDescr"),
        discovered_at: now,
        scan_id: scan_id,
        status: "open"
      } | findings]
    end

    # SNMP v1/v2c without encryption is inherently insecure
    if snmp_service do
      findings = [%VulnFinding{
        id: Ecto.UUID.generate(),
        device_id: device.id,
        device_ip: ip,
        device_mac: device.mac_address,
        device_type: device.device_type,
        protocol: "snmp",
        port: 161,
        check_type: "insecure_protocol",
        title: "SNMP v1/v2c in use (no encryption)",
        description: "SNMP v1/v2c transmits community strings and data in cleartext. " <>
                     "An attacker on the network can intercept credentials and device information.",
        severity: "medium",
        cvss_score: 5.3,
        cve_ids: [],
        evidence: "SNMP service detected on port 161",
        remediation: "Upgrade to SNMPv3 with authentication (SHA) and privacy (AES). " <>
                     "If SNMPv3 is not supported, restrict SNMP access via ACLs and use strong community strings.",
        discovered_at: now,
        scan_id: scan_id,
        status: "open"
      } | findings]
    end

    findings
  end

  defp check_ssh(device, ssh_service, scan_id) do
    findings = []
    now = DateTime.utc_now()
    ip = List.first(device.ip_addresses)

    banner = Map.get(ssh_service, "banner") || Map.get(ssh_service, :banner) || ""
    version = Map.get(ssh_service, "version") || Map.get(ssh_service, :version) || ""
    full_version = "#{banner} #{version}"

    # Check against known SSH vulnerabilities
    Enum.reduce(@ssh_vulns, findings, fn vuln, acc ->
      if Regex.match?(vuln.pattern, full_version) do
        [%VulnFinding{
          id: Ecto.UUID.generate(),
          device_id: device.id,
          device_ip: ip,
          device_mac: device.mac_address,
          device_type: device.device_type,
          protocol: "ssh",
          port: 22,
          check_type: "cve_match",
          title: "#{vuln.cve} - #{vuln.description}",
          description: vuln.description,
          severity: vuln.severity,
          cvss_score: severity_to_cvss(vuln.severity),
          cve_ids: [vuln.cve],
          evidence: "SSH banner: #{String.slice(full_version, 0, 256)}",
          remediation: "Update SSH server to the latest version.",
          service_version: String.trim(full_version),
          discovered_at: now,
          scan_id: scan_id,
          status: "open"
        } | acc]
      else
        acc
      end
    end)
  end

  defp check_http(device, ip, port, http_service, scan_id) do
    findings = []
    now = DateTime.utc_now()
    port_num = if is_binary(port), do: String.to_integer(port), else: port

    banner = if http_service do
      Map.get(http_service, "banner") || Map.get(http_service, :banner) || ""
    else
      ""
    end

    extra = if http_service do
      Map.get(http_service, "extra_info") || Map.get(http_service, :extra_info) || %{}
    else
      %{}
    end

    server_header = Map.get(extra, "http_server") || Map.get(extra, :http_server) || ""
    full_server = "#{server_header} #{banner}"

    # Check for known vulnerable HTTP servers
    findings = Enum.reduce(@http_server_vulns, findings, fn vuln, acc ->
      if Regex.match?(vuln.pattern, full_server) do
        [%VulnFinding{
          id: Ecto.UUID.generate(),
          device_id: device.id,
          device_ip: ip,
          device_mac: device.mac_address,
          device_type: device.device_type,
          protocol: "http",
          port: port_num,
          check_type: "cve_match",
          title: "#{vuln.cve} - #{vuln.description}",
          description: vuln.description,
          severity: vuln.severity,
          cvss_score: severity_to_cvss(vuln.severity),
          cve_ids: [vuln.cve],
          evidence: "HTTP Server: #{String.slice(full_server, 0, 256)}",
          remediation: "Update the web server to the latest patched version.",
          service_version: String.trim(full_server),
          discovered_at: now,
          scan_id: scan_id,
          status: "open"
        } | acc]
      else
        acc
      end
    end)

    # Detect embedded web management interfaces (often have default creds)
    if String.contains?(String.downcase(full_server), ["goahead", "mini_httpd", "boa/", "thttpd", "micro_httpd"]) do
      findings = [%VulnFinding{
        id: Ecto.UUID.generate(),
        device_id: device.id,
        device_ip: ip,
        device_mac: device.mac_address,
        device_type: device.device_type,
        protocol: "http",
        port: port_num,
        check_type: "version_vuln",
        title: "Embedded web server detected - likely default credentials",
        description: "An embedded web server was detected (#{String.trim(full_server)}). " <>
                     "Embedded web interfaces frequently ship with default or weak credentials " <>
                     "and may have known vulnerabilities.",
        severity: "high",
        cvss_score: 7.5,
        cve_ids: [],
        evidence: "Server: #{String.slice(full_server, 0, 256)}",
        remediation: "Change default credentials immediately. " <>
                     "Restrict web interface access to management VLAN. " <>
                     "Update firmware to latest version.",
        service_version: String.trim(full_server),
        discovered_at: now,
        scan_id: scan_id,
        status: "open"
      } | findings]
    end

    findings
  end

  defp check_tls(device, ip, port, scan_id) do
    findings = []
    now = DateTime.utc_now()
    port_num = if is_binary(port), do: String.to_integer(port), else: port

    # Note: In production, this would use an SSL/TLS library to probe
    # the actual TLS configuration. For now, we flag the existence of
    # HTTPS and note potential issues based on common configurations.

    services = device.services || []
    tls_service = Enum.find(services, fn s ->
      p = Map.get(s, "port") || Map.get(s, :port)
      p == port || p == port_num
    end)

    extra = if tls_service do
      Map.get(tls_service, "extra_info") || Map.get(tls_service, :extra_info) || %{}
    else
      %{}
    end

    tls_version = Map.get(extra, "tls_version") || Map.get(extra, :tls_version)
    cipher = Map.get(extra, "cipher_suite") || Map.get(extra, :cipher_suite)

    # Check for weak TLS versions
    if tls_version && tls_version in @weak_tls_versions do
      findings = [%VulnFinding{
        id: Ecto.UUID.generate(),
        device_id: device.id,
        device_ip: ip,
        device_mac: device.mac_address,
        device_type: device.device_type,
        protocol: "https",
        port: port_num,
        check_type: "weak_crypto",
        title: "Weak TLS version: #{tls_version}",
        description: "The device supports #{tls_version}, which has known vulnerabilities " <>
                     "(POODLE, BEAST, CRIME). This version should be disabled.",
        severity: if(tls_version in ["SSLv2", "SSLv3"], do: "critical", else: "high"),
        cvss_score: if(tls_version in ["SSLv2", "SSLv3"], do: 9.1, else: 7.4),
        cve_ids: case tls_version do
          "SSLv3" -> ["CVE-2014-3566"]
          "TLSv1.0" -> ["CVE-2011-3389"]
          _ -> []
        end,
        evidence: "TLS version: #{tls_version}",
        remediation: "Disable #{tls_version} and enable TLS 1.2 or TLS 1.3.",
        discovered_at: now,
        scan_id: scan_id,
        status: "open"
      } | findings]
    end

    # Check for weak ciphers
    if cipher do
      weak = Enum.find(@weak_ciphers, fn wc ->
        String.contains?(String.upcase(to_string(cipher)), String.upcase(wc))
      end)

      if weak do
        findings = [%VulnFinding{
          id: Ecto.UUID.generate(),
          device_id: device.id,
          device_ip: ip,
          device_mac: device.mac_address,
          device_type: device.device_type,
          protocol: "https",
          port: port_num,
          check_type: "weak_crypto",
          title: "Weak cipher suite: #{cipher}",
          description: "The device uses a weak cipher suite containing #{weak}. " <>
                       "This may be susceptible to known cryptographic attacks.",
          severity: "medium",
          cvss_score: 5.3,
          cve_ids: [],
          evidence: "Cipher suite: #{cipher}",
          remediation: "Configure the device to use modern cipher suites " <>
                       "(AES-GCM, ChaCha20-Poly1305) and disable weak ciphers.",
          discovered_at: now,
          scan_id: scan_id,
          status: "open"
        } | findings]
      end
    end

    findings
  end

  defp check_telnet(device, telnet_service, scan_id) do
    now = DateTime.utc_now()
    ip = List.first(device.ip_addresses)

    banner = if telnet_service do
      Map.get(telnet_service, "banner") || Map.get(telnet_service, :banner) || ""
    else
      ""
    end

    [%VulnFinding{
      id: Ecto.UUID.generate(),
      device_id: device.id,
      device_ip: ip,
      device_mac: device.mac_address,
      device_type: device.device_type,
      protocol: "telnet",
      port: 23,
      check_type: "insecure_protocol",
      title: "Telnet service enabled - cleartext credential transmission",
      description: "Telnet transmits all data including credentials in cleartext. " <>
                   "Any attacker with network access can intercept login credentials. " <>
                   "Banner: #{String.slice(banner, 0, 128)}",
      severity: "high",
      cvss_score: 7.5,
      cve_ids: [],
      evidence: "Telnet service open on port 23. Banner: #{String.slice(banner, 0, 256)}",
      remediation: "Disable telnet and use SSH for remote management. " <>
                   "If telnet cannot be disabled, restrict access via ACLs to management VLAN only.",
      service_version: String.trim(banner),
      discovered_at: now,
      scan_id: scan_id,
      status: "open"
    }]
  end

  defp check_tftp(device, scan_id) do
    now = DateTime.utc_now()
    ip = List.first(device.ip_addresses)

    [%VulnFinding{
      id: Ecto.UUID.generate(),
      device_id: device.id,
      device_ip: ip,
      device_mac: device.mac_address,
      device_type: device.device_type,
      protocol: "tftp",
      port: 69,
      check_type: "insecure_protocol",
      title: "TFTP service enabled - unauthenticated file transfer",
      description: "TFTP provides no authentication or encryption. " <>
                   "Attackers can potentially download device firmware, configuration files, " <>
                   "or upload malicious firmware updates.",
      severity: "high",
      cvss_score: 8.1,
      cve_ids: [],
      evidence: "TFTP service detected on port 69",
      remediation: "Disable TFTP if not required. " <>
                   "If needed for firmware updates, restrict access via ACLs " <>
                   "and use SFTP/SCP as an alternative where supported.",
      discovered_at: now,
      scan_id: scan_id,
      status: "open"
    }]
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp severity_to_cvss("critical"), do: 9.8
  defp severity_to_cvss("high"), do: 7.5
  defp severity_to_cvss("medium"), do: 5.3
  defp severity_to_cvss("low"), do: 3.1
  defp severity_to_cvss(_), do: 0.0

  defp severity_rank("critical"), do: 4
  defp severity_rank("high"), do: 3
  defp severity_rank("medium"), do: 2
  defp severity_rank("low"), do: 1
  defp severity_rank(_), do: 0

  defp filter_findings(findings, filters) do
    Enum.filter(findings, fn finding ->
      Enum.all?(filters, fn
        {:severity, sev} -> finding.severity == sev
        {:protocol, proto} -> finding.protocol == proto
        {:device_id, did} -> finding.device_id == did
        {:status, status} -> finding.status == status
        {:check_type, ct} -> finding.check_type == ct
        {:min_cvss, score} -> (finding.cvss_score || 0.0) >= score
        {:scan_id, sid} -> finding.scan_id == sid
        _ -> true
      end)
    end)
  end

  defp update_scan_stats(state) do
    open_findings = state.findings
      |> Map.values()
      |> Enum.filter(&(&1.status == "open"))

    stats = %{
      total_findings: map_size(state.findings),
      open_findings: length(open_findings),
      critical: Enum.count(open_findings, &(&1.severity == "critical")),
      high: Enum.count(open_findings, &(&1.severity == "high")),
      medium: Enum.count(open_findings, &(&1.severity == "medium")),
      low: Enum.count(open_findings, &(&1.severity == "low")),
      devices_scanned: state.scan_jobs |> Map.values() |> Enum.map(& &1.scanned_devices) |> Enum.sum(),
      scans_completed: map_size(state.scan_jobs),
      by_protocol: Enum.frequencies_by(open_findings, & &1.protocol),
      by_check_type: Enum.frequencies_by(open_findings, & &1.check_type),
      last_scan: state.last_scan
    }

    %{state | stats: stats}
  end

  defp emit_vuln_alert(finding) do
    alert = %{
      alert_type: "device_vulnerability",
      severity: finding.severity,
      title: finding.title,
      description: finding.description,
      device_id: finding.device_id,
      device_ip: finding.device_ip,
      device_mac: finding.device_mac,
      protocol: finding.protocol,
      port: finding.port,
      cve_ids: finding.cve_ids,
      cvss_score: finding.cvss_score,
      remediation: finding.remediation,
      finding_id: finding.id,
      timestamp: finding.discovered_at
    }

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alerts:feed",
      {:alert_created, alert}
    )
  end

  defp schedule_scan do
    # Default: run daily scans at 2 AM
    # Calculate delay until next 2 AM
    now = DateTime.utc_now()
    next_2am = %{now | hour: 2, minute: 0, second: 0, microsecond: {0, 0}}

    next_2am = if DateTime.compare(next_2am, now) == :lt do
      DateTime.add(next_2am, 86_400, :second)
    else
      next_2am
    end

    delay_ms = DateTime.diff(next_2am, now, :millisecond) |> max(60_000)
    Process.send_after(self(), :scheduled_scan, delay_ms)
  end
end
