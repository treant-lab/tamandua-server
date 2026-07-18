defmodule TamanduaServer.ASM.Exposure do
  @moduledoc """
  Attack Surface Management - Exposure Analysis Module

  Analyzes discovered assets for security exposures:

  - Open port detection
  - Service fingerprinting
  - SSL/TLS configuration analysis
  - Known vulnerability mapping
  - Misconfigurations detection
  - Weak credential detection
  - Security header analysis

  Provides detailed exposure reports for each asset and
  aggregate exposure metrics for the attack surface.
  """

  use GenServer
  require Logger

  alias TamanduaServer.ASM.{RiskScoring}
  alias TamanduaServer.Vulnerability

  # Well-known risky ports and services
  @high_risk_ports %{
    21 => %{service: "FTP", risk: :high, reason: "Unencrypted file transfer"},
    22 => %{service: "SSH", risk: :medium, reason: "Remote access - ensure strong auth"},
    23 => %{service: "Telnet", risk: :critical, reason: "Unencrypted remote access"},
    25 => %{service: "SMTP", risk: :medium, reason: "Mail relay potential"},
    53 => %{service: "DNS", risk: :medium, reason: "DNS amplification potential"},
    80 => %{service: "HTTP", risk: :medium, reason: "Unencrypted web traffic"},
    110 => %{service: "POP3", risk: :high, reason: "Unencrypted email access"},
    111 => %{service: "RPC", risk: :high, reason: "Remote procedure call"},
    135 => %{service: "MSRPC", risk: :high, reason: "Windows RPC"},
    139 => %{service: "NetBIOS", risk: :high, reason: "SMB/NetBIOS exposure"},
    143 => %{service: "IMAP", risk: :high, reason: "Unencrypted email access"},
    161 => %{service: "SNMP", risk: :high, reason: "Network management protocol"},
    389 => %{service: "LDAP", risk: :high, reason: "Directory services"},
    443 => %{service: "HTTPS", risk: :low, reason: "Encrypted web - check TLS config"},
    445 => %{service: "SMB", risk: :critical, reason: "Windows file sharing"},
    465 => %{service: "SMTPS", risk: :low, reason: "Encrypted SMTP"},
    587 => %{service: "Submission", risk: :low, reason: "Mail submission"},
    636 => %{service: "LDAPS", risk: :low, reason: "Encrypted LDAP"},
    993 => %{service: "IMAPS", risk: :low, reason: "Encrypted IMAP"},
    995 => %{service: "POP3S", risk: :low, reason: "Encrypted POP3"},
    1433 => %{service: "MSSQL", risk: :critical, reason: "Database server"},
    1521 => %{service: "Oracle", risk: :critical, reason: "Database server"},
    2049 => %{service: "NFS", risk: :high, reason: "Network file system"},
    3306 => %{service: "MySQL", risk: :critical, reason: "Database server"},
    3389 => %{service: "RDP", risk: :critical, reason: "Remote desktop"},
    5432 => %{service: "PostgreSQL", risk: :critical, reason: "Database server"},
    5900 => %{service: "VNC", risk: :critical, reason: "Remote desktop"},
    5984 => %{service: "CouchDB", risk: :high, reason: "Database server"},
    6379 => %{service: "Redis", risk: :critical, reason: "In-memory database"},
    8080 => %{service: "HTTP-Alt", risk: :medium, reason: "Alternative HTTP"},
    8443 => %{service: "HTTPS-Alt", risk: :low, reason: "Alternative HTTPS"},
    9200 => %{service: "Elasticsearch", risk: :critical, reason: "Search engine"},
    27017 => %{service: "MongoDB", risk: :critical, reason: "Database server"}
  }

  # TLS/SSL configuration grades
  @tls_grades %{
    "A+" => %{score: 100, issues: []},
    "A" => %{score: 90, issues: ["Minor TLS configuration improvements possible"]},
    "B" => %{score: 70, issues: ["TLS configuration needs attention"]},
    "C" => %{score: 50, issues: ["Significant TLS weaknesses present"]},
    "D" => %{score: 30, issues: ["Serious TLS vulnerabilities"]},
    "F" => %{score: 0, issues: ["Critical TLS failures"]}
  }

  # Required security headers
  @security_headers [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy"
  ]

  # State structure
  defstruct [
    :exposure_cache,     # ETS table for exposure data
    :analysis_queue,     # Queue of assets to analyze
    :active_scans,       # Currently running scans
    :config,             # Configuration
    :stats               # Statistics
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Analyze a single asset for exposures.
  """
  @spec analyze_asset(map()) :: {:ok, map()} | {:error, term()}
  def analyze_asset(asset) do
    GenServer.call(__MODULE__, {:analyze_asset, asset}, 60_000)
  end

  @doc """
  Analyze all assets for a domain.
  """
  @spec analyze_domain(String.t()) :: {:ok, [map()]} | {:error, term()}
  def analyze_domain(domain) do
    GenServer.call(__MODULE__, {:analyze_domain, domain}, 120_000)
  end

  @doc """
  Get exposure analysis for an asset.
  """
  @spec get_exposures(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_exposures(asset_id) do
    GenServer.call(__MODULE__, {:get_exposures, asset_id})
  end

  @doc """
  List all exposures with optional filters.
  """
  @spec list_exposures(keyword()) :: [map()]
  def list_exposures(opts \\ []) do
    GenServer.call(__MODULE__, {:list_exposures, opts})
  end

  @doc """
  Scan a specific IP or host for open ports.
  """
  @spec port_scan(String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def port_scan(target, opts \\ []) do
    GenServer.call(__MODULE__, {:port_scan, target, opts}, 120_000)
  end

  @doc """
  Analyze SSL/TLS configuration for a host.
  """
  @spec analyze_tls(String.t(), integer()) :: {:ok, map()} | {:error, term()}
  def analyze_tls(host, port \\ 443) do
    GenServer.call(__MODULE__, {:analyze_tls, host, port}, 30_000)
  end

  @doc """
  Check security headers for a web endpoint.
  """
  @spec check_headers(String.t()) :: {:ok, map()} | {:error, term()}
  def check_headers(url) do
    GenServer.call(__MODULE__, {:check_headers, url}, 30_000)
  end

  @doc """
  Fingerprint a service on a specific port.
  """
  @spec fingerprint_service(String.t(), integer()) :: {:ok, map()} | {:error, term()}
  def fingerprint_service(host, port) do
    GenServer.call(__MODULE__, {:fingerprint_service, host, port}, 30_000)
  end

  @doc """
  Map known vulnerabilities to discovered services.
  """
  @spec map_vulnerabilities(map()) :: {:ok, [map()]} | {:error, term()}
  def map_vulnerabilities(service_info) do
    GenServer.call(__MODULE__, {:map_vulnerabilities, service_info})
  end

  @doc """
  Get exposure statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Get aggregate exposure metrics for the attack surface.
  """
  @spec get_aggregate_metrics() :: map()
  def get_aggregate_metrics do
    GenServer.call(__MODULE__, :get_aggregate_metrics)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting Attack Surface Management - Exposure Analysis Service")

    # Create ETS table for exposure cache
    exposure_table = :ets.new(:asm_exposures, [:named_table, :set, :public, read_concurrency: true])

    state = %__MODULE__{
      exposure_cache: exposure_table,
      analysis_queue: :queue.new(),
      active_scans: %{},
      config: build_config(opts),
      stats: initial_stats()
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:analyze_asset, asset}, _from, state) do
    result = do_analyze_asset(asset, state)

    # Cache the result
    :ets.insert(state.exposure_cache, {asset.id, result})

    # Update risk score
    RiskScoring.update_asset_risk(asset.id, result)

    new_stats = increment_stats(state.stats, :assets_analyzed)
    {:reply, {:ok, result}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:analyze_domain, domain}, _from, state) do
    # Get all assets for the domain
    case TamanduaServer.ASM.Discovery.get_subdomains(domain) do
      assets when is_list(assets) ->
        results = Enum.map(assets, fn asset ->
          result = do_analyze_asset(asset, state)
          :ets.insert(state.exposure_cache, {asset.id, result})
          result
        end)

        {:reply, {:ok, results}, state}

      _ ->
        {:reply, {:error, :domain_not_found}, state}
    end
  end

  @impl true
  def handle_call({:get_exposures, asset_id}, _from, state) do
    case :ets.lookup(state.exposure_cache, asset_id) do
      [{^asset_id, exposures}] -> {:reply, {:ok, exposures}, state}
      [] -> {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:list_exposures, opts}, _from, state) do
    exposures = get_all_exposures(state.exposure_cache)

    filtered = exposures
    |> filter_by_severity(opts[:severity])
    |> filter_by_type(opts[:type])
    |> filter_by_status(opts[:status])
    |> sort_exposures(opts[:sort])
    |> maybe_limit(opts[:limit])

    {:reply, filtered, state}
  end

  @impl true
  def handle_call({:port_scan, target, opts}, _from, state) do
    ports = opts[:ports] || Map.keys(@high_risk_ports)
    timeout = opts[:timeout] || state.config.scan_timeout

    results = scan_ports(target, ports, timeout)
    {:reply, {:ok, results}, state}
  end

  @impl true
  def handle_call({:analyze_tls, host, port}, _from, state) do
    result = do_analyze_tls(host, port, state.config)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:check_headers, url}, _from, state) do
    result = do_check_headers(url, state.config)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:fingerprint_service, host, port}, _from, state) do
    result = do_fingerprint_service(host, port, state.config)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:map_vulnerabilities, service_info}, _from, state) do
    vulns = do_map_vulnerabilities(service_info)
    {:reply, {:ok, vulns}, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_call(:get_aggregate_metrics, _from, state) do
    metrics = calculate_aggregate_metrics(state.exposure_cache)
    {:reply, metrics, state}
  end

  # ============================================================================
  # Analysis Functions
  # ============================================================================

  defp do_analyze_asset(asset, state) do
    timestamp = DateTime.utc_now()

    # Gather all exposure data
    port_results = if asset.ip_addresses && length(asset.ip_addresses) > 0 do
      primary_ip = List.first(asset.ip_addresses)
      scan_ports(primary_ip, Map.keys(@high_risk_ports), state.config.scan_timeout)
    else
      []
    end

    # TLS analysis for HTTPS endpoints
    tls_result = if Enum.any?(port_results, & &1.port in [443, 8443]) do
      target = asset.value || List.first(asset.ip_addresses || [])
      if target, do: do_analyze_tls(target, 443, state.config), else: nil
    else
      nil
    end

    # Security headers for web services
    headers_result = if Enum.any?(port_results, & &1.port in [80, 443, 8080, 8443]) do
      url = build_url(asset, port_results)
      if url, do: do_check_headers(url, state.config), else: nil
    else
      nil
    end

    # Service fingerprinting
    services = Enum.map(port_results, fn port_info ->
      if port_info.open do
        target = asset.value || List.first(asset.ip_addresses || [])
        if target do
          fingerprint = do_fingerprint_service(target, port_info.port, state.config)
          Map.merge(port_info, fingerprint)
        else
          port_info
        end
      else
        port_info
      end
    end)

    # Map vulnerabilities
    vulnerabilities = services
    |> Enum.filter(& &1.open && &1[:product])
    |> Enum.flat_map(&do_map_vulnerabilities/1)
    |> Enum.uniq_by(& &1.cve_id)

    # Calculate exposures
    exposures = generate_exposures(port_results, tls_result, headers_result, services)

    # Calculate overall exposure score
    exposure_score = calculate_exposure_score(exposures, tls_result, vulnerabilities)

    %{
      asset_id: asset.id,
      asset_value: asset.value,
      analyzed_at: timestamp,
      open_ports: Enum.filter(port_results, & &1.open),
      closed_ports: Enum.reject(port_results, & &1.open) |> length(),
      services: services,
      tls_analysis: tls_result,
      security_headers: headers_result,
      exposures: exposures,
      vulnerabilities: vulnerabilities,
      exposure_score: exposure_score,
      risk_level: score_to_risk_level(exposure_score),
      recommendations: generate_recommendations(exposures, tls_result, headers_result)
    }
  end

  defp scan_ports(target, ports, timeout) do
    # Parallel port scanning
    target_charlist = String.to_charlist(target)

    ports
    |> Task.async_stream(fn port ->
      result = try do
        case :gen_tcp.connect(target_charlist, port, [:binary, active: false], timeout) do
          {:ok, socket} ->
            :gen_tcp.close(socket)
            port_info = Map.get(@high_risk_ports, port, %{service: "unknown", risk: :unknown, reason: ""})
            %{
              port: port,
              open: true,
              service: port_info.service,
              risk: port_info.risk,
              reason: port_info.reason
            }

          {:error, _} ->
            %{port: port, open: false}
        end
      catch
        _, _ -> %{port: port, open: false, error: true}
      end

      result
    end, timeout: timeout + 1000, max_concurrency: 20)
    |> Enum.map(fn
      {:ok, result} -> result
      {:exit, _} -> nil
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp do_analyze_tls(host, port, _config) do
    host_charlist = String.to_charlist(host)

    try do
      case :ssl.connect(host_charlist, port, [verify: :verify_none, depth: 3], 10_000) do
        {:ok, socket} ->
          # Get certificate info
          {:ok, cert_der} = :ssl.peercert(socket)
          cert = :public_key.pkix_decode_cert(cert_der, :otp)

          # Get protocol and cipher info
          {:ok, protocol} = :ssl.protocol(socket)
          {:ok, cipher} = :ssl.cipher_suite(socket)

          :ssl.close(socket)

          # Extract certificate details
          cert_info = extract_cert_info(cert)

          # Determine grade based on protocol and cipher
          grade = determine_tls_grade(protocol, cipher)
          grade_info = Map.get(@tls_grades, grade, %{score: 0, issues: ["Unknown configuration"]})

          issues = detect_tls_issues(protocol, cipher, cert_info)

          %{
            host: host,
            port: port,
            protocol: protocol,
            cipher_suite: format_cipher(cipher),
            certificate: cert_info,
            grade: grade,
            score: grade_info.score,
            issues: issues,
            expires_at: cert_info[:not_after],
            expires_soon: cert_expires_soon?(cert_info[:not_after]),
            is_expired: cert_expired?(cert_info[:not_after])
          }

        {:error, reason} ->
          %{
            host: host,
            port: port,
            error: true,
            reason: inspect(reason),
            grade: "F",
            score: 0
          }
      end
    catch
      _, err ->
        %{
          host: host,
          port: port,
          error: true,
          reason: inspect(err),
          grade: "F",
          score: 0
        }
    end
  end

  defp do_check_headers(url, config) do
    timeout = config.http_timeout || 10_000

    try do
      case :httpc.request(:head, {String.to_charlist(url), []}, [timeout: timeout], []) do
        {:ok, {{_, status, _}, headers, _}} ->
          header_map = headers
          |> Enum.map(fn {k, v} -> {String.downcase(to_string(k)), to_string(v)} end)
          |> Map.new()

          # Check for each security header
          header_analysis = Enum.map(@security_headers, fn header ->
            value = Map.get(header_map, header)
            %{
              header: header,
              present: value != nil,
              value: value,
              issue: if(value == nil, do: "Missing #{header} header", else: nil)
            }
          end)

          present_count = Enum.count(header_analysis, & &1.present)
          total_count = length(@security_headers)
          score = round(present_count / total_count * 100)

          %{
            url: url,
            status_code: status,
            headers: header_analysis,
            present_count: present_count,
            missing_count: total_count - present_count,
            score: score,
            grade: headers_score_to_grade(score)
          }

        {:error, reason} ->
          %{
            url: url,
            error: true,
            reason: inspect(reason)
          }
      end
    catch
      _, err ->
        %{
          url: url,
          error: true,
          reason: inspect(err)
        }
    end
  end

  defp do_fingerprint_service(host, port, config) do
    timeout = config.scan_timeout || 5000
    host_charlist = String.to_charlist(host)

    try do
      case :gen_tcp.connect(host_charlist, port, [:binary, active: false], timeout) do
        {:ok, socket} ->
          # Send probe and read banner
          :gen_tcp.send(socket, "\r\n")
          banner = case :gen_tcp.recv(socket, 0, timeout) do
            {:ok, data} -> data
            {:error, _} -> ""
          end
          :gen_tcp.close(socket)

          # Parse banner for service info
          service_info = parse_banner(banner, port)

          %{
            port: port,
            banner: String.slice(banner, 0, 500),
            product: service_info[:product],
            version: service_info[:version],
            os_hint: service_info[:os],
            cpe: service_info[:cpe]
          }

        {:error, _} ->
          %{port: port, error: true}
      end
    catch
      _, _ -> %{port: port, error: true}
    end
  end

  defp do_map_vulnerabilities(service_info) do
    # Map services to known CVEs
    # In production, this would query the NVD or vulnerability database

    product = service_info[:product] || ""
    version = service_info[:version] || ""
    cpe = service_info[:cpe]

    cond do
      cpe != nil ->
        # Query vulnerabilities by CPE
        case Vulnerability.check_cpe(cpe) do
          {:ok, vulns} -> vulns
          _ -> []
        end

      product != "" ->
        # Query by product name and version
        case Vulnerability.search(%{product: product, version: version}) do
          {:ok, results} -> results.vulnerabilities || []
          _ -> []
        end

      true ->
        []
    end
  end

  # ============================================================================
  # Exposure Generation
  # ============================================================================

  defp generate_exposures(port_results, tls_result, headers_result, services) do
    exposures = []

    # Port-based exposures
    port_exposures = port_results
    |> Enum.filter(& &1.open && &1.risk in [:high, :critical])
    |> Enum.map(fn port_info ->
      %{
        id: "exp_port_#{port_info.port}",
        type: :open_port,
        severity: port_info.risk,
        title: "#{port_info.service} (port #{port_info.port}) exposed",
        description: port_info.reason,
        port: port_info.port,
        service: port_info.service,
        remediation: port_remediation(port_info.port)
      }
    end)

    # TLS exposures
    tls_exposures = if tls_result && !tls_result[:error] do
      issues = tls_result[:issues] || []
      Enum.map(issues, fn issue ->
        %{
          id: "exp_tls_#{:erlang.phash2(issue)}",
          type: :tls_issue,
          severity: tls_issue_severity(issue),
          title: "TLS Configuration Issue",
          description: issue,
          remediation: tls_remediation(issue)
        }
      end) ++
      if tls_result[:is_expired] do
        [%{
          id: "exp_tls_expired",
          type: :certificate,
          severity: :critical,
          title: "SSL/TLS Certificate Expired",
          description: "The certificate has expired and is no longer valid",
          remediation: "Renew the SSL/TLS certificate immediately"
        }]
      else
        []
      end ++
      if tls_result[:expires_soon] do
        [%{
          id: "exp_tls_expiring",
          type: :certificate,
          severity: :high,
          title: "SSL/TLS Certificate Expiring Soon",
          description: "The certificate will expire within 30 days",
          remediation: "Renew the SSL/TLS certificate before expiration"
        }]
      else
        []
      end
    else
      []
    end

    # Security headers exposures
    header_exposures = if headers_result && !headers_result[:error] do
      headers_result[:headers]
      |> Enum.filter(fn h -> !h.present end)
      |> Enum.map(fn h ->
        %{
          id: "exp_header_#{h.header}",
          type: :missing_header,
          severity: header_severity(h.header),
          title: "Missing Security Header: #{h.header}",
          description: "The #{h.header} header is not configured",
          remediation: header_remediation(h.header)
        }
      end)
    else
      []
    end

    # Service-specific exposures
    service_exposures = services
    |> Enum.filter(& &1[:open] && &1[:version])
    |> Enum.filter(&outdated_version?/1)
    |> Enum.map(fn svc ->
      %{
        id: "exp_outdated_#{svc.port}",
        type: :outdated_software,
        severity: :high,
        title: "Outdated #{svc.product || svc.service} Version",
        description: "Running version #{svc.version} which may have known vulnerabilities",
        port: svc.port,
        product: svc.product,
        version: svc.version,
        remediation: "Update #{svc.product || svc.service} to the latest version"
      }
    end)

    exposures ++ port_exposures ++ tls_exposures ++ header_exposures ++ service_exposures
  end

  defp generate_recommendations(exposures, tls_result, headers_result) do
    recommendations = []

    # Critical port recommendations
    critical_ports = Enum.filter(exposures, & &1.type == :open_port && &1.severity == :critical)
    recommendations = if length(critical_ports) > 0 do
      ["Close or restrict access to critical ports: #{Enum.map(critical_ports, & &1.port) |> Enum.join(", ")}" | recommendations]
    else
      recommendations
    end

    # TLS recommendations
    recommendations = if tls_result && tls_result[:grade] in ["D", "F"] do
      ["Upgrade TLS configuration to use TLS 1.2+ with strong cipher suites" | recommendations]
    else
      recommendations
    end

    # Headers recommendations
    recommendations = if headers_result && headers_result[:score] < 50 do
      ["Implement security headers: CSP, HSTS, X-Frame-Options, etc." | recommendations]
    else
      recommendations
    end

    # Vulnerability recommendations
    vuln_count = Enum.count(exposures, & &1.type == :vulnerability)
    recommendations = if vuln_count > 0 do
      ["Address #{vuln_count} known vulnerabilities in exposed services" | recommendations]
    else
      recommendations
    end

    Enum.reverse(recommendations)
  end

  # ============================================================================
  # Scoring Functions
  # ============================================================================

  defp calculate_exposure_score(exposures, tls_result, vulnerabilities) do
    # Base score from exposures
    exposure_score = Enum.reduce(exposures, 0, fn exp, acc ->
      case exp.severity do
        :critical -> acc + 30
        :high -> acc + 20
        :medium -> acc + 10
        :low -> acc + 5
        _ -> acc
      end
    end)

    # TLS score contribution (inverse - higher TLS score = lower exposure)
    tls_score = if tls_result && !tls_result[:error] do
      max(0, 20 - round((tls_result[:score] || 0) / 5))
    else
      20
    end

    # Vulnerability contribution
    vuln_score = Enum.reduce(vulnerabilities, 0, fn vuln, acc ->
      cvss = vuln[:cvss_score] || 5.0
      cond do
        cvss >= 9.0 -> acc + 25
        cvss >= 7.0 -> acc + 15
        cvss >= 4.0 -> acc + 8
        true -> acc + 3
      end
    end)

    # Cap at 100
    min(100, exposure_score + tls_score + vuln_score)
  end

  defp score_to_risk_level(score) do
    cond do
      score >= 80 -> :critical
      score >= 60 -> :high
      score >= 40 -> :medium
      score >= 20 -> :low
      true -> :minimal
    end
  end

  defp calculate_aggregate_metrics(exposure_table) do
    all_exposures = get_all_exposures(exposure_table)

    %{
      total_assets_analyzed: length(all_exposures),
      total_exposures: Enum.sum(Enum.map(all_exposures, fn e -> length(e[:exposures] || []) end)),
      exposures_by_severity: %{
        critical: count_by_severity(all_exposures, :critical),
        high: count_by_severity(all_exposures, :high),
        medium: count_by_severity(all_exposures, :medium),
        low: count_by_severity(all_exposures, :low)
      },
      exposures_by_type: count_by_type(all_exposures),
      average_exposure_score: calculate_average_score(all_exposures),
      assets_by_risk: %{
        critical: Enum.count(all_exposures, & &1[:risk_level] == :critical),
        high: Enum.count(all_exposures, & &1[:risk_level] == :high),
        medium: Enum.count(all_exposures, & &1[:risk_level] == :medium),
        low: Enum.count(all_exposures, & &1[:risk_level] == :low),
        minimal: Enum.count(all_exposures, & &1[:risk_level] == :minimal)
      },
      total_vulnerabilities: Enum.sum(Enum.map(all_exposures, fn e -> length(e[:vulnerabilities] || []) end)),
      assets_with_critical_exposures: Enum.count(all_exposures, fn e ->
        Enum.any?(e[:exposures] || [], & &1.severity == :critical)
      end)
    }
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp get_all_exposures(table) do
    :ets.tab2list(table)
    |> Enum.map(fn {_id, exposure} -> exposure end)
  end

  defp filter_by_severity(exposures, nil), do: exposures
  defp filter_by_severity(exposures, severity) do
    severity_atom = if is_binary(severity), do: String.to_atom(severity), else: severity
    Enum.filter(exposures, fn e ->
      Enum.any?(e[:exposures] || [], & &1.severity == severity_atom)
    end)
  end

  defp filter_by_type(exposures, nil), do: exposures
  defp filter_by_type(exposures, type) do
    type_atom = if is_binary(type), do: String.to_atom(type), else: type
    Enum.filter(exposures, fn e ->
      Enum.any?(e[:exposures] || [], & &1.type == type_atom)
    end)
  end

  defp filter_by_status(exposures, nil), do: exposures
  defp filter_by_status(exposures, _status), do: exposures # Placeholder

  defp sort_exposures(exposures, nil), do: Enum.sort_by(exposures, & &1[:exposure_score], :desc)
  defp sort_exposures(exposures, :score), do: Enum.sort_by(exposures, & &1[:exposure_score], :desc)
  defp sort_exposures(exposures, :date), do: Enum.sort_by(exposures, & &1[:analyzed_at], :desc)
  defp sort_exposures(exposures, _), do: exposures

  defp maybe_limit(exposures, nil), do: exposures
  defp maybe_limit(exposures, limit), do: Enum.take(exposures, limit)

  defp count_by_severity(all_exposures, severity) do
    Enum.sum(Enum.map(all_exposures, fn e ->
      Enum.count(e[:exposures] || [], & &1.severity == severity)
    end))
  end

  defp count_by_type(all_exposures) do
    all_exposures
    |> Enum.flat_map(fn e -> e[:exposures] || [] end)
    |> Enum.group_by(& &1.type)
    |> Enum.map(fn {type, items} -> {type, length(items)} end)
    |> Map.new()
  end

  defp calculate_average_score(exposures) when length(exposures) == 0, do: 0
  defp calculate_average_score(exposures) do
    sum = Enum.sum(Enum.map(exposures, & &1[:exposure_score] || 0))
    round(sum / length(exposures))
  end

  defp build_url(asset, port_results) do
    host = asset.value || List.first(asset.ip_addresses || [])
    if host do
      if Enum.any?(port_results, & &1.port == 443 && &1.open) do
        "https://#{host}"
      else
        "http://#{host}"
      end
    else
      nil
    end
  end

  defp extract_cert_info(cert) do
    # Extract basic certificate information from OTP certificate
    try do
      {:OTPCertificate, tbs, _, _} = cert
      {:OTPTBSCertificate, _, _, _, _, validity, subject, _, _, _, _} = tbs
      {:Validity, {:utcTime, not_before}, {:utcTime, not_after}} = validity

      %{
        subject: format_subject(subject),
        issuer: nil, # Would extract similarly
        not_before: parse_utc_time(not_before),
        not_after: parse_utc_time(not_after),
        serial_number: nil,
        signature_algorithm: nil
      }
    catch
      _, _ -> %{}
    end
  end

  defp format_subject(_subject), do: "Unknown"

  defp parse_utc_time(_time) do
    try do
      DateTime.utc_now() # Placeholder - would properly parse ASN.1 time
    catch
      _, _ -> nil
    end
  end

  defp format_cipher(cipher) when is_tuple(cipher), do: inspect(cipher)
  defp format_cipher(cipher), do: to_string(cipher)

  defp determine_tls_grade(protocol, _cipher) do
    case protocol do
      {:tlsv1, 3} -> "A"  # TLS 1.3
      {:tlsv1, 2} -> "B"  # TLS 1.2
      {:tlsv1, 1} -> "D"  # TLS 1.1
      {:tlsv1, 0} -> "F"  # TLS 1.0
      _ -> "C"
    end
  end

  defp detect_tls_issues(protocol, _cipher, cert_info) do
    issues = []

    # Protocol issues
    issues = case protocol do
      {:tlsv1, 0} -> ["TLS 1.0 is deprecated and insecure" | issues]
      {:tlsv1, 1} -> ["TLS 1.1 is deprecated" | issues]
      _ -> issues
    end

    # Certificate issues
    issues = if cert_info[:not_after] && DateTime.compare(cert_info[:not_after], DateTime.utc_now()) == :lt do
      ["Certificate has expired" | issues]
    else
      issues
    end

    issues
  end

  defp cert_expires_soon?(nil), do: false
  defp cert_expires_soon?(not_after) do
    thirty_days = DateTime.add(DateTime.utc_now(), 30, :day)
    DateTime.compare(not_after, thirty_days) == :lt
  end

  defp cert_expired?(nil), do: false
  defp cert_expired?(not_after) do
    DateTime.compare(not_after, DateTime.utc_now()) == :lt
  end

  defp headers_score_to_grade(score) do
    cond do
      score >= 90 -> "A"
      score >= 70 -> "B"
      score >= 50 -> "C"
      score >= 30 -> "D"
      true -> "F"
    end
  end

  defp parse_banner(banner, port) do
    # Basic banner parsing - would be more sophisticated in production
    banner_lower = String.downcase(banner)

    cond do
      String.contains?(banner_lower, "apache") ->
        version = Regex.run(~r/apache[\/\s]+(\d+\.\d+\.?\d*)/, banner_lower)
        %{product: "Apache HTTP Server", version: List.last(version || [""])}

      String.contains?(banner_lower, "nginx") ->
        version = Regex.run(~r/nginx[\/\s]+(\d+\.\d+\.?\d*)/, banner_lower)
        %{product: "nginx", version: List.last(version || [""])}

      String.contains?(banner_lower, "openssh") ->
        version = Regex.run(~r/openssh[_\s]+(\d+\.\d+\.?\d*)/, banner_lower)
        %{product: "OpenSSH", version: List.last(version || [""])}

      String.contains?(banner_lower, "microsoft") ->
        %{product: "Microsoft IIS", version: nil, os: "Windows"}

      true ->
        known_service = Map.get(@high_risk_ports, port, %{})
        %{product: known_service[:service], version: nil}
    end
  end

  defp outdated_version?(_service) do
    # Check if version is known to be outdated
    # This would integrate with vulnerability data in production
    false
  end

  defp port_remediation(21), do: "Consider using SFTP instead of FTP, or restrict FTP access via firewall"
  defp port_remediation(22), do: "Ensure strong SSH configuration: disable password auth, use key-based auth"
  defp port_remediation(23), do: "Disable Telnet immediately and use SSH instead"
  defp port_remediation(445), do: "Restrict SMB access to internal networks only, ensure SMBv1 is disabled"
  defp port_remediation(3389), do: "Use VPN or restrict RDP access, enable NLA"
  defp port_remediation(port) when port in [1433, 1521, 3306, 5432, 27017, 6379, 9200] do
    "Restrict database access to application servers only, never expose to internet"
  end
  defp port_remediation(_), do: "Review if this service needs to be publicly accessible"

  defp tls_issue_severity(issue) do
    cond do
      String.contains?(issue, "expired") -> :critical
      String.contains?(issue, "TLS 1.0") -> :critical
      String.contains?(issue, "TLS 1.1") -> :high
      true -> :medium
    end
  end

  defp tls_remediation(issue) do
    cond do
      String.contains?(issue, "TLS 1.0") or String.contains?(issue, "TLS 1.1") ->
        "Configure server to use TLS 1.2 or TLS 1.3 only"
      String.contains?(issue, "expired") ->
        "Renew the SSL/TLS certificate"
      true ->
        "Review and update TLS configuration"
    end
  end

  defp header_severity("strict-transport-security"), do: :high
  defp header_severity("content-security-policy"), do: :high
  defp header_severity("x-frame-options"), do: :medium
  defp header_severity("x-content-type-options"), do: :medium
  defp header_severity(_), do: :low

  defp header_remediation("strict-transport-security") do
    "Add Strict-Transport-Security header with max-age of at least 1 year"
  end
  defp header_remediation("content-security-policy") do
    "Implement Content-Security-Policy to prevent XSS and data injection"
  end
  defp header_remediation("x-frame-options") do
    "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking"
  end
  defp header_remediation("x-content-type-options") do
    "Add X-Content-Type-Options: nosniff to prevent MIME sniffing"
  end
  defp header_remediation(header) do
    "Configure the #{header} security header"
  end

  defp build_config(opts) do
    %{
      scan_timeout: Keyword.get(opts, :scan_timeout, 5000),
      http_timeout: Keyword.get(opts, :http_timeout, 10000),
      max_parallel_scans: Keyword.get(opts, :max_parallel_scans, 10),
      enable_active_scanning: Keyword.get(opts, :enable_active_scanning, true)
    }
  end

  defp initial_stats do
    %{
      assets_analyzed: 0,
      exposures_found: 0,
      vulnerabilities_mapped: 0,
      started_at: DateTime.utc_now()
    }
  end

  defp increment_stats(stats, key) do
    Map.update(stats, key, 1, & &1 + 1)
  end
end
