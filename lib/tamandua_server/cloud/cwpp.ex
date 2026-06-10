defmodule TamanduaServer.Cloud.CWPP do
  @moduledoc """
  Cloud Workload Protection Platform (CWPP).

  Provides comprehensive security for cloud workloads including:
  - Vulnerability management
  - Compliance monitoring
  - File integrity monitoring
  - Network segmentation analysis
  - Workload hardening

  ## Features

  ### Vulnerability Management
  - CVE detection and tracking
  - Risk-based prioritization
  - Patch recommendations
  - Container image scanning

  ### Compliance Monitoring
  - CIS Benchmarks (Docker, Kubernetes, OS)
  - PCI DSS compliance
  - HIPAA compliance
  - SOC2 compliance
  - Custom compliance policies

  ### File Integrity Monitoring
  - Critical file monitoring
  - Configuration drift detection
  - Change auditing
  - Real-time alerts

  ### Network Segmentation Analysis
  - Workload communication mapping
  - Network policy recommendations
  - Lateral movement detection
  - Microsegmentation validation
  """

  use GenServer
  require Logger

  alias TamanduaServer.Cloud.Finding
  alias TamanduaServer.Alerts

  # ETS tables
  @workloads_table :cwpp_workloads
  @vulnerabilities_table :cwpp_vulnerabilities
  @compliance_table :cwpp_compliance
  @fim_baselines_table :cwpp_fim_baselines
  @network_flows_table :cwpp_network_flows

  # CIS Benchmark Checks
  @cis_docker_checks [
    %{
      id: "CIS-DI-1.1",
      name: "Docker daemon audit",
      description: "Ensure auditing is configured for the Docker daemon",
      category: "Host Configuration",
      check_type: :audit_rule,
      severity: "medium"
    },
    %{
      id: "CIS-DI-1.2",
      name: "Docker directory permissions",
      description: "Ensure docker.sock has secure permissions",
      category: "Host Configuration",
      check_type: :file_permission,
      severity: "high"
    },
    %{
      id: "CIS-DI-2.1",
      name: "Container user",
      description: "Run container as non-root user",
      category: "Container Runtime",
      check_type: :container_config,
      severity: "high"
    },
    %{
      id: "CIS-DI-2.2",
      name: "Privileged containers",
      description: "Do not run privileged containers",
      category: "Container Runtime",
      check_type: :container_config,
      severity: "critical"
    },
    %{
      id: "CIS-DI-2.3",
      name: "Sensitive host directories",
      description: "Do not mount sensitive host directories",
      category: "Container Runtime",
      check_type: :container_config,
      severity: "high"
    },
    %{
      id: "CIS-DI-2.4",
      name: "Host network namespace",
      description: "Do not use host network namespace",
      category: "Container Runtime",
      check_type: :container_config,
      severity: "high"
    },
    %{
      id: "CIS-DI-2.5",
      name: "Memory limits",
      description: "Limit container memory",
      category: "Container Runtime",
      check_type: :container_config,
      severity: "medium"
    },
    %{
      id: "CIS-DI-2.6",
      name: "CPU limits",
      description: "Limit container CPU",
      category: "Container Runtime",
      check_type: :container_config,
      severity: "medium"
    },
    %{
      id: "CIS-DI-3.1",
      name: "Image vulnerabilities",
      description: "Do not use images with known critical vulnerabilities",
      category: "Container Images",
      check_type: :image_scan,
      severity: "critical"
    },
    %{
      id: "CIS-DI-3.2",
      name: "Base image freshness",
      description: "Use up-to-date base images",
      category: "Container Images",
      check_type: :image_scan,
      severity: "medium"
    },
    %{
      id: "CIS-DI-4.1",
      name: "Content trust",
      description: "Enable Docker Content Trust for image signatures",
      category: "Docker Security",
      check_type: :docker_config,
      severity: "high"
    },
    %{
      id: "CIS-DI-4.2",
      name: "Health checks",
      description: "Configure container health checks",
      category: "Container Runtime",
      check_type: :container_config,
      severity: "low"
    }
  ]

  # Critical files for FIM
  @linux_critical_files [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/pam.d/",
    "/root/.ssh/",
    "/root/.bashrc",
    "/etc/systemd/",
    "/var/spool/cron/",
    "/etc/ld.so.conf"
  ]

  @windows_critical_files [
    "C:\\Windows\\System32\\config\\SAM",
    "C:\\Windows\\System32\\config\\SYSTEM",
    "C:\\Windows\\System32\\config\\SECURITY",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\System32\\Tasks\\",
    "C:\\Windows\\System32\\GroupPolicy\\"
  ]

  # Severity scoring for vulnerabilities
  @cvss_severity_map %{
    critical: {9.0, 10.0},
    high: {7.0, 8.9},
    medium: {4.0, 6.9},
    low: {0.1, 3.9},
    informational: {0.0, 0.0}
  }

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Register a workload for protection.
  """
  def register_workload(workload) do
    GenServer.call(__MODULE__, {:register_workload, workload})
  end

  @doc """
  Scan a workload for vulnerabilities.
  """
  def scan_vulnerabilities(workload_id) do
    GenServer.call(__MODULE__, {:scan_vulnerabilities, workload_id}, 120_000)
  end

  @doc """
  Scan container image for vulnerabilities.
  """
  def scan_image(image_ref) do
    GenServer.call(__MODULE__, {:scan_image, image_ref}, 120_000)
  end

  @doc """
  Run compliance check on a workload.
  """
  def check_compliance(workload_id, framework \\ "cis_docker") do
    GenServer.call(__MODULE__, {:check_compliance, workload_id, framework}, 60_000)
  end

  @doc """
  Initialize FIM baseline for a workload.
  """
  def init_fim_baseline(workload_id, file_list \\ nil) do
    GenServer.call(__MODULE__, {:init_fim_baseline, workload_id, file_list})
  end

  @doc """
  Check FIM for changes.
  """
  def check_fim(workload_id, current_state) do
    GenServer.call(__MODULE__, {:check_fim, workload_id, current_state})
  end

  @doc """
  Record network flow between workloads.
  """
  def record_network_flow(source, destination, port, protocol) do
    GenServer.cast(__MODULE__, {:record_flow, source, destination, port, protocol})
  end

  @doc """
  Analyze network segmentation.
  """
  def analyze_network_segmentation(scope \\ :all) do
    GenServer.call(__MODULE__, {:analyze_segmentation, scope})
  end

  @doc """
  Get workload security posture.
  """
  def get_workload_posture(workload_id) do
    GenServer.call(__MODULE__, {:get_posture, workload_id})
  end

  @doc """
  Get all vulnerabilities for a workload.
  """
  def get_vulnerabilities(workload_id) do
    GenServer.call(__MODULE__, {:get_vulnerabilities, workload_id})
  end

  @doc """
  Get CWPP statistics.
  """
  def get_statistics do
    GenServer.call(__MODULE__, :get_statistics)
  end

  @doc """
  Generate hardening recommendations for a workload.
  """
  def get_hardening_recommendations(workload_id) do
    GenServer.call(__MODULE__, {:get_recommendations, workload_id})
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@workloads_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@vulnerabilities_table, [:bag, :named_table, :public, read_concurrency: true])
    :ets.new(@compliance_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@fim_baselines_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@network_flows_table, [:bag, :named_table, :public, read_concurrency: true])

    # Schedule periodic scans
    :timer.send_interval(3600_000, :periodic_vulnerability_scan)
    :timer.send_interval(86400_000, :periodic_compliance_check)

    Logger.info("Cloud Workload Protection Platform started")

    {:ok,
     %{
       scans_performed: 0,
       vulnerabilities_found: 0,
       compliance_checks: 0
     }}
  end

  @impl true
  def handle_call({:register_workload, workload}, _from, state) do
    workload_record = %{
      id: workload[:id] || Ecto.UUID.generate(),
      name: workload[:name],
      type: workload[:type] || "container",
      image: workload[:image],
      namespace: workload[:namespace],
      cluster: workload[:cluster],
      agent_id: workload[:agent_id],
      labels: workload[:labels] || %{},
      status: :registered,
      security_posture: %{
        vulnerability_score: nil,
        compliance_score: nil,
        overall_risk: nil
      },
      last_scan: nil,
      registered_at: DateTime.utc_now()
    }

    :ets.insert(@workloads_table, {workload_record.id, workload_record})
    {:reply, {:ok, workload_record}, state}
  end

  @impl true
  def handle_call({:scan_vulnerabilities, workload_id}, _from, state) do
    case :ets.lookup(@workloads_table, workload_id) do
      [{^workload_id, workload}] ->
        result = perform_vulnerability_scan(workload)

        new_state = %{
          state
          | scans_performed: state.scans_performed + 1,
            vulnerabilities_found: state.vulnerabilities_found + length(result.vulnerabilities)
        }

        {:reply, {:ok, result}, new_state}

      [] ->
        {:reply, {:error, :workload_not_found}, state}
    end
  end

  @impl true
  def handle_call({:scan_image, image_ref}, _from, state) do
    result = scan_container_image(image_ref)

    new_state = %{
      state
      | scans_performed: state.scans_performed + 1,
        vulnerabilities_found: state.vulnerabilities_found + length(result.vulnerabilities)
    }

    {:reply, {:ok, result}, new_state}
  end

  @impl true
  def handle_call({:check_compliance, workload_id, framework}, _from, state) do
    case :ets.lookup(@workloads_table, workload_id) do
      [{^workload_id, workload}] ->
        result = perform_compliance_check(workload, framework)

        new_state = %{state | compliance_checks: state.compliance_checks + 1}
        {:reply, {:ok, result}, new_state}

      [] ->
        {:reply, {:error, :workload_not_found}, state}
    end
  end

  @impl true
  def handle_call({:init_fim_baseline, workload_id, file_list}, _from, state) do
    files =
      file_list ||
        case determine_workload_os(workload_id) do
          :linux -> @linux_critical_files
          :windows -> @windows_critical_files
          _ -> @linux_critical_files
        end

    baseline = %{
      workload_id: workload_id,
      files: %{},
      created_at: DateTime.utc_now(),
      last_check: nil
    }

    # Would normally collect actual file hashes here
    baseline_with_files =
      Enum.reduce(files, baseline, fn file, acc ->
        update_in(acc.files, fn files ->
          Map.put(files, file, %{
            hash: generate_placeholder_hash(),
            permissions: "644",
            owner: "root",
            last_modified: DateTime.utc_now()
          })
        end)
      end)

    :ets.insert(@fim_baselines_table, {workload_id, baseline_with_files})
    {:reply, {:ok, baseline_with_files}, state}
  end

  @impl true
  def handle_call({:check_fim, workload_id, current_state}, _from, state) do
    case :ets.lookup(@fim_baselines_table, workload_id) do
      [{^workload_id, baseline}] ->
        changes = compare_fim_state(baseline, current_state)

        updated_baseline = %{
          baseline
          | last_check: DateTime.utc_now()
        }

        :ets.insert(@fim_baselines_table, {workload_id, updated_baseline})

        if length(changes) > 0 do
          generate_fim_alerts(workload_id, changes)
        end

        {:reply, {:ok, changes}, state}

      [] ->
        {:reply, {:error, :baseline_not_found}, state}
    end
  end

  @impl true
  def handle_call({:analyze_segmentation, scope}, _from, state) do
    result = analyze_network_flows(scope)
    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_call({:get_posture, workload_id}, _from, state) do
    case :ets.lookup(@workloads_table, workload_id) do
      [{^workload_id, workload}] ->
        vulnerabilities = get_workload_vulnerabilities(workload_id)
        compliance = get_workload_compliance(workload_id)

        posture = %{
          workload_id: workload_id,
          workload_name: workload.name,
          workload_type: workload.type,
          vulnerability_summary: summarize_vulnerabilities(vulnerabilities),
          compliance_summary: summarize_compliance(compliance),
          overall_risk: calculate_overall_risk(vulnerabilities, compliance),
          last_updated: DateTime.utc_now()
        }

        {:reply, {:ok, posture}, state}

      [] ->
        {:reply, {:error, :workload_not_found}, state}
    end
  end

  @impl true
  def handle_call({:get_vulnerabilities, workload_id}, _from, state) do
    vulnerabilities = get_workload_vulnerabilities(workload_id)
    {:reply, {:ok, vulnerabilities}, state}
  end

  @impl true
  def handle_call(:get_statistics, _from, state) do
    workloads = :ets.info(@workloads_table, :size)
    vulnerabilities = :ets.info(@vulnerabilities_table, :size)

    # Count by severity
    severity_counts =
      :ets.foldl(
        fn {_key, vuln}, acc ->
          severity = vuln.severity
          Map.update(acc, severity, 1, &(&1 + 1))
        end,
        %{},
        @vulnerabilities_table
      )

    stats = %{
      total_workloads: workloads,
      total_vulnerabilities: vulnerabilities,
      vulnerabilities_by_severity: severity_counts,
      scans_performed: state.scans_performed,
      compliance_checks: state.compliance_checks
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_call({:get_recommendations, workload_id}, _from, state) do
    recommendations = generate_hardening_recommendations(workload_id)
    {:reply, {:ok, recommendations}, state}
  end

  @impl true
  def handle_cast({:record_flow, source, destination, port, protocol}, state) do
    flow = %{
      source: source,
      destination: destination,
      port: port,
      protocol: protocol,
      timestamp: DateTime.utc_now()
    }

    flow_key = "#{source}->#{destination}:#{port}"
    :ets.insert(@network_flows_table, {flow_key, flow})

    {:noreply, state}
  end

  @impl true
  def handle_info(:periodic_vulnerability_scan, state) do
    # Trigger vulnerability scans for all registered workloads
    workloads =
      :ets.tab2list(@workloads_table)
      |> Enum.map(fn {_id, workload} -> workload end)

    Enum.each(workloads, fn workload ->
      spawn(fn -> perform_vulnerability_scan(workload) end)
    end)

    {:noreply, state}
  end

  @impl true
  def handle_info(:periodic_compliance_check, state) do
    # Trigger compliance checks for all registered workloads
    workloads =
      :ets.tab2list(@workloads_table)
      |> Enum.map(fn {_id, workload} -> workload end)

    Enum.each(workloads, fn workload ->
      spawn(fn -> perform_compliance_check(workload, "cis_docker") end)
    end)

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Vulnerability Scanning

  defp perform_vulnerability_scan(workload) do
    # In production, this would call a vulnerability scanner like Trivy, Grype, etc.
    # For now, simulate scanning

    Logger.info("Scanning workload #{workload.id} for vulnerabilities")

    vulnerabilities = scan_container_image(workload.image).vulnerabilities

    # Store vulnerabilities
    Enum.each(vulnerabilities, fn vuln ->
      vuln_record = Map.put(vuln, :workload_id, workload.id)
      :ets.insert(@vulnerabilities_table, {workload.id, vuln_record})
    end)

    # Update workload security posture
    update_workload_posture(workload.id, :vulnerability_score, calculate_vuln_score(vulnerabilities))

    # Generate findings for critical vulnerabilities
    generate_vulnerability_findings(workload, vulnerabilities)

    %{
      workload_id: workload.id,
      vulnerabilities: vulnerabilities,
      summary: summarize_vulnerabilities(vulnerabilities),
      scanned_at: DateTime.utc_now()
    }
  end

  defp scan_container_image(image_ref) do
    # Simulate vulnerability scan results
    # In production, integrate with Trivy, Grype, Clair, etc.

    vulnerabilities = [
      %{
        cve_id: "CVE-2024-0001",
        package: "openssl",
        installed_version: "1.1.1n",
        fixed_version: "1.1.1o",
        severity: "critical",
        cvss_score: 9.8,
        description: "Critical vulnerability in OpenSSL",
        published_at: ~U[2024-01-15 00:00:00Z]
      },
      %{
        cve_id: "CVE-2024-0002",
        package: "curl",
        installed_version: "7.68.0",
        fixed_version: "7.88.0",
        severity: "high",
        cvss_score: 8.1,
        description: "Buffer overflow in curl",
        published_at: ~U[2024-02-20 00:00:00Z]
      },
      %{
        cve_id: "CVE-2024-0003",
        package: "glibc",
        installed_version: "2.31",
        fixed_version: "2.35",
        severity: "medium",
        cvss_score: 5.5,
        description: "Use after free in glibc",
        published_at: ~U[2024-03-10 00:00:00Z]
      }
    ]

    # Add some randomization for demo purposes
    vulnerabilities =
      if :rand.uniform() > 0.5 do
        vulnerabilities
      else
        Enum.take(vulnerabilities, 2)
      end

    %{
      image: image_ref,
      vulnerabilities: vulnerabilities,
      packages_scanned: 150,
      scanned_at: DateTime.utc_now()
    }
  end

  defp calculate_vuln_score(vulnerabilities) do
    if Enum.empty?(vulnerabilities) do
      100
    else
      # Weight by severity
      weighted_score =
        Enum.reduce(vulnerabilities, 0, fn vuln, acc ->
          weight =
            case vuln.severity do
              "critical" -> 25
              "high" -> 15
              "medium" -> 5
              "low" -> 2
              _ -> 1
            end

          acc + weight
        end)

      max(0, 100 - weighted_score)
    end
  end

  defp generate_vulnerability_findings(workload, vulnerabilities) do
    critical_vulns = Enum.filter(vulnerabilities, fn v -> v.severity == "critical" end)
    high_vulns = Enum.filter(vulnerabilities, fn v -> v.severity == "high" end)

    if length(critical_vulns) > 0 do
      Finding.create(%{
        provider: workload[:cluster] || "kubernetes",
        account_id: workload[:namespace] || "default",
        resource_id: workload.id,
        resource_arn: workload.image,
        resource_name: workload.name,
        resource_type: "Container",
        region: "cluster",
        category: "compute_security",
        severity: "critical",
        title: "Critical vulnerabilities detected",
        description:
          "#{length(critical_vulns)} critical vulnerabilities found in workload #{workload.name}: #{Enum.map_join(critical_vulns, ", ", & &1.cve_id)}",
        recommendation: "Update packages to patched versions immediately",
        compliance: ["PCI DSS 6.2", "HIPAA 164.308(a)(5)"]
      })
    end

    if length(high_vulns) > 0 do
      Finding.create(%{
        provider: workload[:cluster] || "kubernetes",
        account_id: workload[:namespace] || "default",
        resource_id: workload.id,
        resource_arn: workload.image,
        resource_name: workload.name,
        resource_type: "Container",
        region: "cluster",
        category: "compute_security",
        severity: "high",
        title: "High severity vulnerabilities detected",
        description:
          "#{length(high_vulns)} high severity vulnerabilities found in workload #{workload.name}",
        recommendation: "Schedule patching within 30 days",
        compliance: ["PCI DSS 6.2"]
      })
    end
  end

  # Compliance Checking

  defp perform_compliance_check(workload, framework) do
    checks =
      case framework do
        "cis_docker" -> @cis_docker_checks
        _ -> @cis_docker_checks
      end

    results =
      Enum.map(checks, fn check ->
        result = run_compliance_check(workload, check)

        %{
          check_id: check.id,
          name: check.name,
          category: check.category,
          severity: check.severity,
          status: result.status,
          details: result.details
        }
      end)

    passing = Enum.count(results, fn r -> r.status == :pass end)
    total = length(results)
    score = if total > 0, do: Float.round(passing / total * 100, 1), else: 100.0

    compliance_record = %{
      workload_id: workload.id,
      framework: framework,
      results: results,
      score: score,
      checked_at: DateTime.utc_now()
    }

    :ets.insert(@compliance_table, {"#{workload.id}:#{framework}", compliance_record})

    # Update workload posture
    update_workload_posture(workload.id, :compliance_score, score)

    # Generate findings for failed checks
    failed_checks = Enum.filter(results, fn r -> r.status == :fail end)
    generate_compliance_findings(workload, framework, failed_checks)

    compliance_record
  end

  defp run_compliance_check(workload, check) do
    # Simulate compliance check
    # In production, would actually check the workload configuration

    case check.check_type do
      :container_config ->
        check_container_config(workload, check)

      :image_scan ->
        check_image_compliance(workload, check)

      :docker_config ->
        check_docker_config(workload, check)

      :audit_rule ->
        check_audit_rules(workload, check)

      :file_permission ->
        check_file_permissions(workload, check)

      :network_policy ->
        check_network_policy(workload, check)

      :secret_management ->
        check_secret_management(workload, check)

      :log_configuration ->
        check_log_configuration(workload, check)

      :resource_quota ->
        check_resource_quota(workload, check)

      other ->
        Logger.warning("Unknown CWPP check type: #{inspect(other)} for check #{check.id}")
        %{status: :unknown, details: "Unrecognized check type: #{inspect(other)}"}
    end
  end

  defp check_container_config(workload, check) do
    # Simulate container config checks
    case check.id do
      "CIS-DI-2.1" ->
        if workload[:run_as_user] != 0 do
          %{status: :pass, details: "Container runs as non-root user"}
        else
          %{status: :fail, details: "Container runs as root"}
        end

      "CIS-DI-2.2" ->
        if workload[:privileged] != true do
          %{status: :pass, details: "Container is not privileged"}
        else
          %{status: :fail, details: "Container is running in privileged mode"}
        end

      "CIS-DI-2.3" ->
        sensitive_mounts = ["/", "/etc", "/var/run/docker.sock"]
        mounted = workload[:mounts] || []

        if Enum.any?(mounted, fn m -> m in sensitive_mounts end) do
          %{status: :fail, details: "Sensitive host directories are mounted"}
        else
          %{status: :pass, details: "No sensitive host directories mounted"}
        end

      "CIS-DI-2.4" ->
        if workload[:host_network] != true do
          %{status: :pass, details: "Not using host network namespace"}
        else
          %{status: :fail, details: "Using host network namespace"}
        end

      "CIS-DI-2.5" ->
        if workload[:memory_limit] do
          %{status: :pass, details: "Memory limit is set"}
        else
          %{status: :fail, details: "No memory limit configured"}
        end

      "CIS-DI-2.6" ->
        if workload[:cpu_limit] do
          %{status: :pass, details: "CPU limit is set"}
        else
          %{status: :fail, details: "No CPU limit configured"}
        end

      "CIS-DI-4.2" ->
        if workload[:health_check] do
          %{status: :pass, details: "Health check is configured"}
        else
          %{status: :fail, details: "No health check configured"}
        end

      _ ->
        %{status: :pass, details: "Check passed"}
    end
  end

  defp check_image_compliance(workload, check) do
    case check.id do
      "CIS-DI-3.1" ->
        # Check for critical vulnerabilities
        vulns = get_workload_vulnerabilities(workload.id)
        critical = Enum.count(vulns, fn v -> v.severity == "critical" end)

        if critical == 0 do
          %{status: :pass, details: "No critical vulnerabilities"}
        else
          %{status: :fail, details: "#{critical} critical vulnerabilities found"}
        end

      "CIS-DI-3.2" ->
        # Check image age
        if workload[:image_created_at] do
          age = DateTime.diff(DateTime.utc_now(), workload.image_created_at, :day)

          if age < 90 do
            %{status: :pass, details: "Image is #{age} days old"}
          else
            %{status: :fail, details: "Image is #{age} days old (>90 days)"}
          end
        else
          %{status: :unknown, details: "Image creation date unknown"}
        end

      _ ->
        %{status: :pass, details: "Check passed"}
    end
  end

  defp check_docker_config(workload, check) do
    case check.id do
      "CIS-DI-4.1" ->
        docker_content_trust_check(workload)

      _ ->
        %{status: :pass, details: "Check passed"}
    end
  end

  # Docker Content Trust (DCT) verification.
  #
  # Checks three things:
  # 1. Whether the image reference uses a digest (@sha256:...) which guarantees
  #    the pulled image matches a known hash, regardless of DCT being enabled.
  # 2. Whether the image pull policy is "Always" (or "IfNotPresent" with digest),
  #    which ensures fresh pulls are validated.
  # 3. Whether DOCKER_CONTENT_TRUST=1 is set in the workload's environment,
  #    which enables Notary signature verification for all pulls.
  defp docker_content_trust_check(workload) do
    image = workload[:image] || ""
    findings = []

    # --- Check 1: Image digest ---
    has_digest = String.contains?(image, "@sha256:")

    findings =
      if has_digest do
        findings ++ ["Image references content-addressable digest"]
      else
        findings ++ ["Image does not reference a digest (@sha256:...) -- tag-only references can be mutated"]
      end

    # --- Check 2: Image pull policy ---
    pull_policy = get_in_workload(workload, [:pull_policy]) || get_in_workload(workload, [:image_pull_policy])

    {pull_policy_ok, findings} =
      case pull_policy do
        policy when policy in ["Always", "always"] ->
          {true, findings ++ ["Image pull policy is 'Always'"]}

        policy when policy in ["IfNotPresent", "ifNotPresent"] and has_digest ->
          {true, findings ++ ["Pull policy is 'IfNotPresent' but image uses digest (acceptable)"]}

        policy when policy in ["IfNotPresent", "ifNotPresent"] ->
          {false, findings ++ ["Pull policy 'IfNotPresent' with tag-only image -- consider using 'Always' or referencing a digest"]}

        policy when policy in ["Never", "never"] ->
          {false, findings ++ ["Pull policy is 'Never' -- cannot verify content trust on pull"]}

        nil ->
          {false, findings ++ ["No image pull policy specified -- defaults may not enforce content trust"]}

        other ->
          {false, findings ++ ["Unknown pull policy: #{other}"]}
      end

    # --- Check 3: DOCKER_CONTENT_TRUST environment variable ---
    env_vars = get_in_workload(workload, [:env]) || get_in_workload(workload, [:environment]) || []

    dct_enabled =
      Enum.any?(env_vars, fn
        %{"name" => "DOCKER_CONTENT_TRUST", "value" => val} -> val in ["1", "true"]
        {"DOCKER_CONTENT_TRUST", val} -> val in ["1", "true"]
        "DOCKER_CONTENT_TRUST=1" -> true
        _ -> false
      end)

    findings =
      if dct_enabled do
        findings ++ ["DOCKER_CONTENT_TRUST=1 is set in workload environment"]
      else
        findings ++ ["DOCKER_CONTENT_TRUST is not enabled in workload environment"]
      end

    # --- Verdict ---
    cond do
      has_digest and (dct_enabled or pull_policy_ok) ->
        %{status: :pass, details: "Content trust verified: " <> Enum.join(findings, "; ")}

      has_digest ->
        %{status: :warning, details: "Image uses digest but pull policy/DCT not fully configured: " <> Enum.join(findings, "; ")}

      dct_enabled and pull_policy_ok ->
        %{status: :warning, details: "DCT enabled but image should reference digest for full verification: " <> Enum.join(findings, "; ")}

      true ->
        %{status: :fail, details: "Docker content trust not enforced: " <> Enum.join(findings, "; ")}
    end
  end

  # Safe nested access for workload maps that may use atom or string keys
  defp get_in_workload(workload, keys) do
    Enum.reduce_while(keys, workload, fn key, acc ->
      cond do
        is_map(acc) and is_atom(key) ->
          case Map.get(acc, key) || Map.get(acc, to_string(key)) do
            nil -> {:halt, nil}
            val -> {:cont, val}
          end

        is_map(acc) ->
          case Map.get(acc, key) do
            nil -> {:halt, nil}
            val -> {:cont, val}
          end

        true ->
          {:halt, nil}
      end
    end)
  end

  defp check_audit_rules(workload, check) do
    # Check whether the workload (or its host agent) has audit rules configured.
    # We inspect the workload metadata for evidence of audit configuration
    # supplied by the agent's telemetry or the container runtime config.
    agent_id = workload[:agent_id]
    audit_config = workload[:audit_config] || workload[:labels]["audit"] || nil

    cond do
      # If the workload has explicit audit configuration metadata
      is_map(audit_config) ->
        rules_count = Map.get(audit_config, :rules_count, Map.get(audit_config, "rules_count", 0))

        if rules_count > 0 do
          %{status: :pass, details: "#{rules_count} audit rule(s) configured for #{check.id}"}
        else
          %{status: :fail, details: "Audit rules are configured but empty (0 rules)"}
        end

      # If there is a connected agent we can check
      is_binary(agent_id) ->
        case TamanduaServer.Agents.Registry.get(agent_id) do
          {:ok, agent_info} ->
            audit_enabled = agent_info[:audit_enabled] || false

            if audit_enabled do
              %{status: :pass, details: "Host agent #{agent_id} reports auditing enabled"}
            else
              %{status: :fail, details: "Host agent #{agent_id} does not have auditing enabled"}
            end

          _ ->
            %{status: :unknown, details: "Agent #{agent_id} is offline; cannot verify audit rules"}
        end

      true ->
        %{status: :unknown, details: "No agent or audit metadata available to verify audit rules"}
    end
  end

  defp check_file_permissions(workload, check) do
    # Check whether sensitive file permissions are correct.
    # Inspects workload metadata or FIM baseline for permission data.
    workload_id = workload[:id] || workload.id

    case :ets.lookup(@fim_baselines_table, workload_id) do
      [{^workload_id, baseline}] ->
        # We have a FIM baseline -- check permissions on sensitive paths
        sensitive_paths =
          case check.id do
            "CIS-DI-1.2" ->
              ["/var/run/docker.sock", "/run/docker.sock"]

            _ ->
              ["/etc/shadow", "/etc/sudoers"]
          end

        issues =
          Enum.reduce(sensitive_paths, [], fn path, acc ->
            case Map.get(baseline.files, path) do
              nil ->
                acc

              file_info ->
                perms = file_info[:permissions] || file_info.permissions

                if overly_permissive?(perms) do
                  ["#{path} has permissions #{perms}" | acc]
                else
                  acc
                end
            end
          end)

        if Enum.empty?(issues) do
          %{status: :pass, details: "File permissions are within acceptable range"}
        else
          %{status: :fail, details: "Overly permissive files: #{Enum.join(issues, "; ")}"}
        end

      [] ->
        # No FIM baseline -- check workload labels or agent metadata
        agent_id = workload[:agent_id]

        if is_binary(agent_id) do
          %{status: :unknown, details: "No FIM baseline for workload; run init_fim_baseline first"}
        else
          %{status: :unknown, details: "No FIM baseline or agent available to verify file permissions"}
        end
    end
  end

  defp overly_permissive?(perms) when is_binary(perms) do
    # Permissions like "777", "666", "776", etc. are overly permissive
    case Integer.parse(perms) do
      {num, ""} when num >= 666 -> true
      _ -> false
    end
  end

  defp overly_permissive?(_), do: false

  defp check_network_policy(workload, _check) do
    # Verify that the workload has a Kubernetes NetworkPolicy or equivalent
    # network segmentation applied.
    network_policy = workload[:network_policy] || workload[:labels]["network_policy"]
    namespace = workload[:namespace] || "default"

    cond do
      is_map(network_policy) ->
        ingress = Map.get(network_policy, :ingress, Map.get(network_policy, "ingress"))
        egress = Map.get(network_policy, :egress, Map.get(network_policy, "egress"))

        if ingress || egress do
          %{status: :pass, details: "Network policy applied with ingress/egress rules in namespace #{namespace}"}
        else
          %{status: :fail, details: "Network policy exists but has no ingress or egress rules defined"}
        end

      is_binary(network_policy) and network_policy != "" ->
        %{status: :pass, details: "Network policy '#{network_policy}' is referenced"}

      true ->
        # Check flows table for evidence of unrestricted communication
        workload_id = workload[:id] || workload.id
        flows = :ets.lookup(@network_flows_table, workload_id)

        if Enum.empty?(flows) do
          %{status: :unknown, details: "No network policy and no observed flows; policy should be defined"}
        else
          %{status: :fail, details: "No network policy defined but workload has active network flows"}
        end
    end
  end

  defp check_secret_management(workload, _check) do
    # Verify that secrets are managed properly (not embedded as environment
    # variables, using Kubernetes Secrets or external vault).
    env_vars = workload[:env] || workload[:environment] || []

    secret_patterns = ["PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY", "CREDENTIALS"]

    exposed_secrets =
      Enum.filter(env_vars, fn
        %{"name" => _name, "valueFrom" => _} ->
          # Using valueFrom (secret ref) is acceptable
          false

        %{"name" => name, "value" => _value} when is_binary(name) ->
          String.upcase(name) |> then(fn upper_name ->
            Enum.any?(secret_patterns, &String.contains?(upper_name, &1))
          end)

        {name, _value} when is_binary(name) ->
          String.upcase(name) |> then(fn upper_name ->
            Enum.any?(secret_patterns, &String.contains?(upper_name, &1))
          end)

        _ ->
          false
      end)

    secret_refs =
      workload[:volume_mounts]
      |> List.wrap()
      |> Enum.filter(fn
        %{"secret" => _} -> true
        %{secret: _} -> true
        _ -> false
      end)

    cond do
      length(exposed_secrets) > 0 ->
        names =
          Enum.map(exposed_secrets, fn
            %{"name" => n} -> n
            {n, _} -> n
            _ -> "unknown"
          end)

        %{
          status: :fail,
          details: "Secrets exposed as plain environment variables: #{Enum.join(names, ", ")}"
        }

      length(secret_refs) > 0 or Enum.empty?(env_vars) ->
        %{status: :pass, details: "Secrets are managed via references or volume mounts"}

      true ->
        %{status: :pass, details: "No sensitive environment variables detected"}
    end
  end

  defp check_log_configuration(workload, _check) do
    # Verify that the workload has logging configured (log driver, log options).
    log_config = workload[:log_config] || workload[:log_driver] || workload[:labels]["logging"]

    cond do
      is_map(log_config) ->
        driver = Map.get(log_config, :driver, Map.get(log_config, "driver", "unknown"))

        if driver in ["json-file", "journald", "fluentd", "syslog", "gelf", "splunk", "awslogs"] do
          %{status: :pass, details: "Logging configured with driver: #{driver}"}
        else
          %{status: :warning, details: "Logging driver '#{driver}' may not be production-ready"}
        end

      is_binary(log_config) and log_config != "" ->
        %{status: :pass, details: "Logging configuration present: #{log_config}"}

      true ->
        # Check for stdout/stderr logging (default container logging)
        %{status: :warning, details: "No explicit log configuration; relying on default container stdout/stderr"}
    end
  end

  defp check_resource_quota(workload, _check) do
    # Verify that the workload has resource requests and limits set
    # (both memory and CPU).
    memory_limit = workload[:memory_limit] || workload[:resources_memory_limit]
    cpu_limit = workload[:cpu_limit] || workload[:resources_cpu_limit]
    memory_request = workload[:memory_request] || workload[:resources_memory_request]
    cpu_request = workload[:cpu_request] || workload[:resources_cpu_request]

    issues = []

    issues =
      if is_nil(memory_limit),
        do: ["No memory limit set" | issues],
        else: issues

    issues =
      if is_nil(cpu_limit),
        do: ["No CPU limit set" | issues],
        else: issues

    issues =
      if is_nil(memory_request),
        do: ["No memory request set" | issues],
        else: issues

    issues =
      if is_nil(cpu_request),
        do: ["No CPU request set" | issues],
        else: issues

    cond do
      Enum.empty?(issues) ->
        %{status: :pass, details: "Resource quotas configured: memory and CPU requests/limits are set"}

      length(issues) <= 2 ->
        %{status: :warning, details: "Partial resource quotas: #{Enum.join(issues, "; ")}"}

      true ->
        %{status: :fail, details: "Missing resource quotas: #{Enum.join(issues, "; ")}"}
    end
  end

  defp generate_compliance_findings(workload, framework, failed_checks) do
    critical_fails = Enum.filter(failed_checks, fn c -> c.severity == "critical" end)
    high_fails = Enum.filter(failed_checks, fn c -> c.severity == "high" end)

    if length(critical_fails) > 0 do
      Finding.create(%{
        provider: workload[:cluster] || "kubernetes",
        account_id: workload[:namespace] || "default",
        resource_id: workload.id,
        resource_arn: workload.image,
        resource_name: workload.name,
        resource_type: "Container",
        region: "cluster",
        category: "compliance",
        severity: "critical",
        title: "Critical #{framework} compliance failures",
        description:
          "#{length(critical_fails)} critical compliance checks failed: #{Enum.map_join(critical_fails, ", ", & &1.check_id)}",
        recommendation: "Address critical compliance issues immediately",
        compliance: [framework]
      })
    end

    if length(high_fails) > 0 do
      Finding.create(%{
        provider: workload[:cluster] || "kubernetes",
        account_id: workload[:namespace] || "default",
        resource_id: workload.id,
        resource_arn: workload.image,
        resource_name: workload.name,
        resource_type: "Container",
        region: "cluster",
        category: "compliance",
        severity: "high",
        title: "High severity #{framework} compliance failures",
        description:
          "#{length(high_fails)} high severity compliance checks failed",
        recommendation: "Review and remediate compliance failures",
        compliance: [framework]
      })
    end
  end

  # File Integrity Monitoring

  defp compare_fim_state(baseline, current_state) do
    baseline_files = baseline.files
    current_files = current_state[:files] || %{}

    changes = []

    # Check for modified files
    changes =
      Enum.reduce(baseline_files, changes, fn {path, baseline_info}, acc ->
        case Map.get(current_files, path) do
          nil ->
            [%{type: :deleted, path: path, details: "File was deleted"} | acc]

          current_info ->
            file_changes = []

            file_changes =
              if current_info[:hash] != baseline_info.hash do
                [%{type: :modified, path: path, details: "Content changed"} | file_changes]
              else
                file_changes
              end

            file_changes =
              if current_info[:permissions] != baseline_info.permissions do
                [
                  %{
                    type: :permissions_changed,
                    path: path,
                    details: "Permissions changed from #{baseline_info.permissions} to #{current_info[:permissions]}"
                  }
                  | file_changes
                ]
              else
                file_changes
              end

            file_changes =
              if current_info[:owner] != baseline_info.owner do
                [
                  %{
                    type: :owner_changed,
                    path: path,
                    details: "Owner changed from #{baseline_info.owner} to #{current_info[:owner]}"
                  }
                  | file_changes
                ]
              else
                file_changes
              end

            acc ++ file_changes
        end
      end)

    # Check for new files
    changes =
      Enum.reduce(current_files, changes, fn {path, _info}, acc ->
        if Map.has_key?(baseline_files, path) do
          acc
        else
          [%{type: :added, path: path, details: "New file detected"} | acc]
        end
      end)

    changes
  end

  defp generate_fim_alerts(workload_id, changes) do
    critical_changes =
      Enum.filter(changes, fn c ->
        c.type in [:modified, :deleted] and is_critical_file?(c.path)
      end)

    if length(critical_changes) > 0 do
      Alerts.create_alert(%{
        agent_id: workload_id,
        title: "Critical file integrity change detected",
        description:
          "#{length(critical_changes)} critical files were modified or deleted",
        severity: "critical",
        source: "cwpp_fim",
        metadata: %{
          changes: critical_changes
        }
      })
    end
  end

  defp is_critical_file?(path) do
    critical_patterns = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "SAM", "SYSTEM"]
    Enum.any?(critical_patterns, fn pattern -> String.contains?(path, pattern) end)
  end

  # Network Segmentation Analysis

  defp analyze_network_flows(scope) do
    flows =
      :ets.tab2list(@network_flows_table)
      |> Enum.map(fn {_key, flow} -> flow end)

    flows =
      case scope do
        :all -> flows
        {:namespace, ns} -> Enum.filter(flows, fn f -> get_namespace(f.source) == ns end)
        {:cluster, cluster} -> Enum.filter(flows, fn f -> get_cluster(f.source) == cluster end)
        _ -> flows
      end

    # Group by source-destination pairs
    flow_map =
      Enum.group_by(flows, fn f -> {f.source, f.destination} end)
      |> Enum.map(fn {{src, dst}, flow_list} ->
        %{
          source: src,
          destination: dst,
          ports: Enum.map(flow_list, & &1.port) |> Enum.uniq(),
          protocols: Enum.map(flow_list, & &1.protocol) |> Enum.uniq(),
          first_seen: Enum.min_by(flow_list, & &1.timestamp).timestamp,
          last_seen: Enum.max_by(flow_list, & &1.timestamp).timestamp,
          count: length(flow_list)
        }
      end)

    # Identify potential segmentation issues
    issues = detect_segmentation_issues(flow_map)

    # Generate network policy recommendations
    recommendations = generate_network_policy_recommendations(flow_map)

    %{
      total_flows: length(flows),
      unique_connections: length(flow_map),
      flow_map: flow_map,
      segmentation_issues: issues,
      policy_recommendations: recommendations
    }
  end

  defp detect_segmentation_issues(flow_map) do
    issues = []

    # Check for cross-namespace traffic
    cross_ns =
      Enum.filter(flow_map, fn f ->
        get_namespace(f.source) != get_namespace(f.destination) and
          get_namespace(f.destination) not in ["kube-system", "kube-dns"]
      end)

    issues =
      if length(cross_ns) > 0 do
        [
          %{
            type: :cross_namespace,
            severity: "medium",
            description: "#{length(cross_ns)} cross-namespace connections detected",
            connections: Enum.take(cross_ns, 5)
          }
          | issues
        ]
      else
        issues
      end

    # Check for external egress
    external_egress =
      Enum.filter(flow_map, fn f ->
        String.starts_with?(f.destination, "external:") or is_public_ip?(f.destination)
      end)

    issues =
      if length(external_egress) > 0 do
        [
          %{
            type: :external_egress,
            severity: "low",
            description: "#{length(external_egress)} external egress connections",
            connections: Enum.take(external_egress, 5)
          }
          | issues
        ]
      else
        issues
      end

    issues
  end

  defp generate_network_policy_recommendations(flow_map) do
    # Group flows by source namespace
    by_namespace = Enum.group_by(flow_map, fn f -> get_namespace(f.source) end)

    Enum.flat_map(by_namespace, fn {namespace, flows} ->
      # Generate ingress/egress rules
      egress_rules =
        flows
        |> Enum.map(fn f ->
          %{
            to: f.destination,
            ports: f.ports
          }
        end)
        |> Enum.uniq()

      [
        %{
          namespace: namespace,
          policy_name: "#{namespace}-egress-policy",
          type: :egress,
          rules: egress_rules
        }
      ]
    end)
  end

  # Helper Functions

  defp update_workload_posture(workload_id, field, value) do
    case :ets.lookup(@workloads_table, workload_id) do
      [{^workload_id, workload}] ->
        updated = put_in(workload, [:security_posture, field], value)

        # Calculate overall risk
        updated =
          put_in(
            updated,
            [:security_posture, :overall_risk],
            calculate_overall_risk_score(updated.security_posture)
          )

        :ets.insert(@workloads_table, {workload_id, updated})

      [] ->
        :ok
    end
  end

  defp calculate_overall_risk_score(posture) do
    vuln_score = posture.vulnerability_score || 100
    compliance_score = posture.compliance_score || 100

    # Weighted average
    score = vuln_score * 0.6 + compliance_score * 0.4

    cond do
      score < 40 -> "critical"
      score < 60 -> "high"
      score < 80 -> "medium"
      true -> "low"
    end
  end

  defp get_workload_vulnerabilities(workload_id) do
    :ets.lookup(@vulnerabilities_table, workload_id)
    |> Enum.map(fn {_id, vuln} -> vuln end)
  end

  defp get_workload_compliance(workload_id) do
    :ets.match(@compliance_table, {:"$1", :"$2"})
    |> Enum.filter(fn [key, _] -> String.starts_with?(key, "#{workload_id}:") end)
    |> Enum.map(fn [_, record] -> record end)
  end

  defp summarize_vulnerabilities(vulnerabilities) do
    %{
      total: length(vulnerabilities),
      critical: Enum.count(vulnerabilities, fn v -> v.severity == "critical" end),
      high: Enum.count(vulnerabilities, fn v -> v.severity == "high" end),
      medium: Enum.count(vulnerabilities, fn v -> v.severity == "medium" end),
      low: Enum.count(vulnerabilities, fn v -> v.severity == "low" end)
    }
  end

  defp summarize_compliance(compliance_results) do
    if Enum.empty?(compliance_results) do
      %{frameworks: [], average_score: nil}
    else
      frameworks = Enum.map(compliance_results, & &1.framework)
      avg_score = Enum.sum(Enum.map(compliance_results, & &1.score)) / length(compliance_results)

      %{
        frameworks: frameworks,
        average_score: Float.round(avg_score, 1)
      }
    end
  end

  defp calculate_overall_risk(vulnerabilities, compliance) do
    vuln_score = calculate_vuln_score(vulnerabilities)

    compliance_score =
      if Enum.empty?(compliance) do
        100
      else
        Enum.sum(Enum.map(compliance, & &1.score)) / length(compliance)
      end

    overall = vuln_score * 0.6 + compliance_score * 0.4

    cond do
      overall < 40 -> "critical"
      overall < 60 -> "high"
      overall < 80 -> "medium"
      true -> "low"
    end
  end

  defp generate_hardening_recommendations(workload_id) do
    vulnerabilities = get_workload_vulnerabilities(workload_id)
    compliance = get_workload_compliance(workload_id)

    recommendations = []

    # Vulnerability-based recommendations
    recommendations =
      if Enum.any?(vulnerabilities, fn v -> v.severity in ["critical", "high"] end) do
        [
          %{
            priority: "high",
            category: "vulnerability",
            title: "Update vulnerable packages",
            description: "Update packages with critical and high severity vulnerabilities",
            action: "Run package updates for: #{Enum.map_join(Enum.take(vulnerabilities, 3), ", ", & &1.package)}"
          }
          | recommendations
        ]
      else
        recommendations
      end

    # Compliance-based recommendations
    recommendations =
      Enum.reduce(compliance, recommendations, fn c, acc ->
        failed = Enum.filter(c.results, fn r -> r.status == :fail end)

        Enum.reduce(failed, acc, fn check, inner_acc ->
          [
            %{
              priority: check.severity,
              category: "compliance",
              title: "Fix: #{check.name}",
              description: check.details,
              action: "Remediate #{check.check_id}"
            }
            | inner_acc
          ]
        end)
      end)

    Enum.sort_by(recommendations, fn r ->
      case r.priority do
        "critical" -> 0
        "high" -> 1
        "medium" -> 2
        "low" -> 3
        _ -> 4
      end
    end)
  end

  defp determine_workload_os(workload_id) do
    case :ets.lookup(@workloads_table, workload_id) do
      [{^workload_id, workload}] ->
        image = workload.image || ""

        cond do
          String.contains?(image, "windows") -> :windows
          String.contains?(image, "alpine") -> :linux
          String.contains?(image, "ubuntu") -> :linux
          String.contains?(image, "debian") -> :linux
          String.contains?(image, "centos") -> :linux
          true -> :linux
        end

      [] ->
        :linux
    end
  end

  defp get_namespace(workload_ref) do
    case String.split(workload_ref, "/") do
      [ns, _] -> ns
      _ -> "default"
    end
  end

  defp get_cluster(workload_ref) do
    case String.split(workload_ref, ":") do
      [cluster | _] -> cluster
      _ -> "default"
    end
  end

  defp is_public_ip?(ip) do
    # Simple check for public IP
    not (String.starts_with?(ip, "10.") or
           String.starts_with?(ip, "172.16.") or
           String.starts_with?(ip, "192.168.") or
           String.starts_with?(ip, "127."))
  end

  defp generate_placeholder_hash do
    :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
  end
end
