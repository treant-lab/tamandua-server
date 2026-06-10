defmodule TamanduaServer.Serverless.SecurityAnalyzer do
  @moduledoc """
  Serverless Security Analyzer Module.

  Provides comprehensive security analysis for serverless functions across
  AWS Lambda, Azure Functions, and GCP Cloud Functions:

  - Overprivileged IAM detection
  - Hardcoded secrets/credential detection
  - Vulnerable dependency scanning
  - Code pattern analysis
  - Network exposure assessment
  - Data exfiltration risk scoring

  ## MITRE ATT&CK Coverage
  - T1552: Unsecured Credentials
  - T1078.004: Valid Accounts - Cloud Accounts
  - T1195.001: Supply Chain Compromise - Compromise Software Dependencies
  - T1041: Exfiltration Over C2 Channel
  - T1567: Exfiltration Over Web Service
  - T1496: Resource Hijacking

  ## Detection Categories
  - Secrets in environment variables
  - Overprivileged IAM roles
  - Vulnerable dependencies (CVEs)
  - Suspicious code patterns
  - Network misconfigurations
  - Data handling risks
  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Serverless.{Lambda, AzureFunctions, CloudFunctions}

  @findings_table :serverless_security_findings
  @scans_table :serverless_security_scans

  # Secret patterns for environment variable and code scanning
  @secret_patterns [
    # AWS credentials
    {~r/AKIA[0-9A-Z]{16}/i, "AWS Access Key ID", :critical},
    {~r/[A-Za-z0-9\/+=]{40}/i, "Potential AWS Secret Key", :high},

    # Azure credentials
    {~r/[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}/i, "Azure Client ID/Tenant ID", :medium},

    # GCP credentials
    {~r/AIza[0-9A-Za-z\-_]{35}/i, "GCP API Key", :high},
    {~r/"private_key":\s*"-----BEGIN/i, "GCP Service Account Key", :critical},

    # Generic secrets
    {~r/-----BEGIN RSA PRIVATE KEY-----/i, "RSA Private Key", :critical},
    {~r/-----BEGIN PRIVATE KEY-----/i, "Private Key", :critical},
    {~r/-----BEGIN EC PRIVATE KEY-----/i, "EC Private Key", :critical},
    {~r/password\s*[=:]\s*['"][^'"]{6,}/i, "Hardcoded Password", :high},
    {~r/secret\s*[=:]\s*['"][^'"]{6,}/i, "Hardcoded Secret", :high},
    {~r/api[_-]?key\s*[=:]\s*['"][^'"]{10,}/i, "Hardcoded API Key", :high},
    {~r/bearer\s+[A-Za-z0-9\-._~+\/]+=*/i, "Bearer Token", :high},
    {~r/ghp_[A-Za-z0-9]{36}/i, "GitHub Personal Access Token", :critical},
    {~r/sk-[A-Za-z0-9]{48}/i, "OpenAI API Key", :high},
    {~r/xox[baprs]-[A-Za-z0-9-]+/i, "Slack Token", :high},
    {~r/SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/i, "SendGrid API Key", :high},
    {~r/sq0[a-z]{3}-[A-Za-z0-9\-_]{22,43}/i, "Square API Key", :high},
    {~r/sk_live_[A-Za-z0-9]{24}/i, "Stripe Secret Key", :critical},
    {~r/pk_live_[A-Za-z0-9]{24}/i, "Stripe Publishable Key", :medium}
  ]

  # Dangerous IAM permissions by provider
  @dangerous_aws_permissions [
    {"iam:*", :critical, "Full IAM access"},
    {"iam:CreateUser", :high, "Can create IAM users"},
    {"iam:CreateRole", :high, "Can create IAM roles"},
    {"iam:AttachRolePolicy", :high, "Can attach policies to roles"},
    {"iam:AttachUserPolicy", :high, "Can attach policies to users"},
    {"iam:PutUserPolicy", :high, "Can create inline user policies"},
    {"iam:PutRolePolicy", :high, "Can create inline role policies"},
    {"iam:PassRole", :high, "Can pass roles to other services"},
    {"sts:AssumeRole", :medium, "Can assume other roles"},
    {"lambda:*", :high, "Full Lambda access"},
    {"lambda:UpdateFunctionCode", :high, "Can modify function code"},
    {"lambda:InvokeFunction", :medium, "Can invoke any function"},
    {"s3:*", :high, "Full S3 access"},
    {"s3:GetObject", :low, "Can read S3 objects"},
    {"s3:PutObject", :low, "Can write S3 objects"},
    {"ec2:*", :high, "Full EC2 access"},
    {"ec2:RunInstances", :high, "Can launch EC2 instances"},
    {"secretsmanager:GetSecretValue", :medium, "Can read secrets"},
    {"ssm:GetParameter", :low, "Can read SSM parameters"},
    {"kms:Decrypt", :medium, "Can decrypt KMS-encrypted data"},
    {"kms:*", :high, "Full KMS access"},
    {"rds:*", :high, "Full RDS access"},
    {"dynamodb:*", :high, "Full DynamoDB access"},
    {"sqs:*", :medium, "Full SQS access"},
    {"sns:*", :medium, "Full SNS access"}
  ]

  @dangerous_azure_permissions [
    {"*", :critical, "Full Azure access"},
    {"Microsoft.Authorization/*", :critical, "Full authorization access"},
    {"Microsoft.KeyVault/vaults/secrets/*", :high, "Key Vault secrets access"},
    {"Microsoft.Storage/storageAccounts/*", :high, "Full storage access"},
    {"Microsoft.Compute/*", :high, "Full compute access"},
    {"Microsoft.Web/sites/*", :high, "Full App Service access"}
  ]

  @dangerous_gcp_permissions [
    {"*", :critical, "Full GCP access"},
    {"iam.serviceAccounts.actAs", :critical, "Can impersonate service accounts"},
    {"iam.serviceAccountKeys.create", :critical, "Can create service account keys"},
    {"storage.objects.*", :high, "Full Cloud Storage access"},
    {"compute.*", :high, "Full Compute Engine access"},
    {"cloudfunctions.*", :high, "Full Cloud Functions access"},
    {"secretmanager.secrets.*", :high, "Secret Manager access"}
  ]

  # Suspicious code patterns
  @suspicious_code_patterns [
    {~r/eval\s*\(/i, "Dynamic code evaluation (eval)", :high, "T1059"},
    {~r/exec\s*\(/i, "Code execution (exec)", :high, "T1059"},
    {~r/child_process\.exec/i, "Child process execution", :high, "T1059"},
    {~r/subprocess\.Popen/i, "Subprocess execution (Python)", :high, "T1059"},
    {~r/os\.system\s*\(/i, "System command execution", :high, "T1059"},
    {~r/shell\s*=\s*True/i, "Shell execution enabled", :medium, "T1059"},
    {~r/curl\s+.*\|.*sh/i, "Curl-pipe-shell pattern", :critical, "T1059"},
    {~r/wget\s+.*\|.*sh/i, "Wget-pipe-shell pattern", :critical, "T1059"},
    {~r/base64\.b64decode/i, "Base64 decoding", :low, "T1140"},
    {~r/Buffer\.from\s*\([^)]+,\s*['"]base64/i, "Base64 decoding (Node)", :low, "T1140"},
    {~r/atob\s*\(/i, "Base64 decoding (atob)", :low, "T1140"},
    {~r/crypto.*mine/i, "Cryptocurrency mining reference", :critical, "T1496"},
    {~r/stratum\+tcp/i, "Mining pool protocol", :critical, "T1496"},
    {~r/xmrig|monero|coinhive/i, "Cryptocurrency miner reference", :critical, "T1496"},
    {~r/reverse.*shell/i, "Reverse shell reference", :critical, "T1059"},
    {~r/nc\s+-[elvnp]+.*\d+/i, "Netcat reverse shell", :critical, "T1059"},
    {~r/\$\{IFS\}/i, "Command injection via IFS", :high, "T1059"},
    {~r/\$\(.*\)/i, "Command substitution", :medium, "T1059"},
    {~r/`.*`/i, "Backtick command execution", :medium, "T1059"}
  ]

  # Vulnerable dependency patterns (simplified - real impl would query CVE databases)
  @vulnerable_packages [
    {"lodash", "< 4.17.21", "CVE-2021-23337", :high, "Prototype Pollution"},
    {"axios", "< 0.21.1", "CVE-2020-28168", :medium, "SSRF vulnerability"},
    {"minimist", "< 1.2.6", "CVE-2021-44906", :high, "Prototype Pollution"},
    {"moment", "< 2.29.4", "CVE-2022-31129", :medium, "ReDoS vulnerability"},
    {"shell-quote", "< 1.7.3", "CVE-2021-42740", :critical, "Command injection"},
    {"urllib3", "< 1.26.5", "CVE-2021-33503", :medium, "ReDoS vulnerability"},
    {"requests", "< 2.25.0", "CVE-2018-18074", :low, "Information disclosure"},
    {"pyyaml", "< 5.4", "CVE-2020-14343", :critical, "Arbitrary code execution"},
    {"jinja2", "< 2.11.3", "CVE-2020-28493", :medium, "XSS vulnerability"},
    {"django", "< 3.2.4", "CVE-2021-33203", :high, "Path traversal"}
  ]

  # Types
  defmodule Finding do
    @moduledoc "Security finding for a serverless function"
    defstruct [
      :id,
      :function_id,
      :provider,
      :category,
      :severity,
      :title,
      :description,
      :resource_path,
      :line_number,
      :evidence,
      :remediation,
      :cve_id,
      :mitre_technique,
      :compliance_frameworks,
      :risk_score,
      :status,  # open, acknowledged, resolved, false_positive
      :detected_at,
      :resolved_at
    ]
  end

  defmodule ScanResult do
    @moduledoc "Result of a security scan"
    defstruct [
      :id,
      :function_id,
      :provider,
      :scan_type,
      :started_at,
      :completed_at,
      :status,
      :findings_count,
      :critical_count,
      :high_count,
      :medium_count,
      :low_count,
      :security_score
    ]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Perform a comprehensive security scan on a function.
  """
  @spec scan_function(String.t(), atom(), keyword()) :: {:ok, ScanResult.t()} | {:error, term()}
  def scan_function(function_id, provider, opts \\ []) do
    GenServer.call(__MODULE__, {:scan_function, function_id, provider, opts}, 120_000)
  end

  @doc """
  Scan all functions for a given provider.
  """
  @spec scan_all(atom(), keyword()) :: {:ok, [ScanResult.t()]} | {:error, term()}
  def scan_all(provider, opts \\ []) do
    GenServer.call(__MODULE__, {:scan_all, provider, opts}, 600_000)
  end

  @doc """
  Detect secrets in code or environment variables.
  """
  @spec detect_secrets(String.t() | map()) :: [Finding.t()]
  def detect_secrets(content) do
    GenServer.call(__MODULE__, {:detect_secrets, content})
  end

  @doc """
  Analyze IAM permissions for overprivileged access.
  """
  @spec analyze_iam(map(), atom()) :: [Finding.t()]
  def analyze_iam(policy, provider) do
    GenServer.call(__MODULE__, {:analyze_iam, policy, provider})
  end

  @doc """
  Scan for vulnerable dependencies.
  """
  @spec scan_dependencies(map()) :: [Finding.t()]
  def scan_dependencies(dependencies) do
    GenServer.call(__MODULE__, {:scan_dependencies, dependencies})
  end

  @doc """
  Scan code for suspicious patterns.
  """
  @spec scan_code(String.t()) :: [Finding.t()]
  def scan_code(code) do
    GenServer.call(__MODULE__, {:scan_code, code})
  end

  @doc """
  Get all findings for a function.
  """
  @spec get_findings(String.t()) :: [Finding.t()]
  def get_findings(function_id) do
    GenServer.call(__MODULE__, {:get_findings, function_id})
  end

  @doc """
  Get findings by severity.
  """
  @spec get_findings_by_severity(atom()) :: [Finding.t()]
  def get_findings_by_severity(severity) do
    GenServer.call(__MODULE__, {:get_findings_by_severity, severity})
  end

  @doc """
  Update finding status.
  """
  @spec update_finding_status(String.t(), atom()) :: :ok | {:error, term()}
  def update_finding_status(finding_id, status) do
    GenServer.call(__MODULE__, {:update_finding_status, finding_id, status})
  end

  @doc """
  Get scan history for a function.
  """
  @spec get_scan_history(String.t()) :: [ScanResult.t()]
  def get_scan_history(function_id) do
    GenServer.call(__MODULE__, {:get_scan_history, function_id})
  end

  @doc """
  Get statistics across all providers.
  """
  @spec get_statistics() :: map()
  def get_statistics do
    GenServer.call(__MODULE__, :get_statistics)
  end

  @doc """
  Calculate risk score for a function based on findings.
  """
  @spec calculate_risk_score(String.t()) :: {:ok, float()} | {:error, term()}
  def calculate_risk_score(function_id) do
    GenServer.call(__MODULE__, {:calculate_risk_score, function_id})
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    :ets.new(@findings_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@scans_table, [:set, :named_table, :public, read_concurrency: true])

    # Schedule periodic scans
    :timer.send_interval(:timer.hours(6), :periodic_scan)

    Logger.info("Serverless Security Analyzer started")
    {:ok, %{scans_in_progress: %{}}}
  end

  @impl true
  def handle_call({:scan_function, function_id, provider, opts}, _from, state) do
    result = do_scan_function(function_id, provider, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:scan_all, provider, opts}, _from, state) do
    result = do_scan_all(provider, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:detect_secrets, content}, _from, state) do
    findings = do_detect_secrets(content)
    {:reply, findings, state}
  end

  @impl true
  def handle_call({:analyze_iam, policy, provider}, _from, state) do
    findings = do_analyze_iam(policy, provider)
    {:reply, findings, state}
  end

  @impl true
  def handle_call({:scan_dependencies, dependencies}, _from, state) do
    findings = do_scan_dependencies(dependencies)
    {:reply, findings, state}
  end

  @impl true
  def handle_call({:scan_code, code}, _from, state) do
    findings = do_scan_code(code)
    {:reply, findings, state}
  end

  @impl true
  def handle_call({:get_findings, function_id}, _from, state) do
    findings = get_findings_internal(function_id)
    {:reply, findings, state}
  end

  @impl true
  def handle_call({:get_findings_by_severity, severity}, _from, state) do
    findings = get_findings_by_severity_internal(severity)
    {:reply, findings, state}
  end

  @impl true
  def handle_call({:update_finding_status, finding_id, status}, _from, state) do
    result = update_finding_status_internal(finding_id, status)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_scan_history, function_id}, _from, state) do
    history = get_scan_history_internal(function_id)
    {:reply, history, state}
  end

  @impl true
  def handle_call(:get_statistics, _from, state) do
    stats = compute_statistics()
    {:reply, stats, state}
  end

  @impl true
  def handle_call({:calculate_risk_score, function_id}, _from, state) do
    result = do_calculate_risk_score(function_id)
    {:reply, result, state}
  end

  @impl true
  def handle_info(:periodic_scan, state) do
    Task.start(fn ->
      do_scan_all(:aws, [])
      do_scan_all(:azure, [])
      do_scan_all(:gcp, [])
    end)
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp do_scan_function(function_id, provider, _opts) do
    scan_id = Ecto.UUID.generate()
    started_at = DateTime.utc_now()

    # Get function details based on provider
    function = case provider do
      :aws -> Lambda.get_function(function_id)
      :azure -> AzureFunctions.get_function(function_id)
      :gcp -> CloudFunctions.get_function(function_id)
      _ -> {:error, :invalid_provider}
    end

    case function do
      {:ok, func} ->
        findings = []

        # Scan environment variables for secrets
        env_findings = if func.environment_variables || func.environment || func.app_settings do
          env = func.environment_variables || func.environment || func.app_settings || %{}
          scan_env_for_secrets(env, function_id, provider)
        else
          []
        end
        findings = findings ++ env_findings

        # Analyze IAM permissions (provider-specific)
        iam_findings = case provider do
          :aws -> analyze_aws_role(func.role, function_id)
          :azure -> analyze_azure_identity(func.managed_identity, function_id)
          :gcp -> analyze_gcp_service_account(func.service_account_email, function_id)
          _ -> []
        end
        findings = findings ++ iam_findings

        # Check network exposure
        network_findings = analyze_network_exposure(func, provider, function_id)
        findings = findings ++ network_findings

        # Check configuration security
        config_findings = analyze_function_config(func, provider, function_id)
        findings = findings ++ config_findings

        # Store findings
        Enum.each(findings, fn finding ->
          :ets.insert(@findings_table, {finding.id, finding})
        end)

        # Create and store scan result
        completed_at = DateTime.utc_now()
        severity_counts = count_by_severity(findings)

        scan_result = %ScanResult{
          id: scan_id,
          function_id: function_id,
          provider: provider,
          scan_type: :full,
          started_at: started_at,
          completed_at: completed_at,
          status: :completed,
          findings_count: length(findings),
          critical_count: severity_counts[:critical] || 0,
          high_count: severity_counts[:high] || 0,
          medium_count: severity_counts[:medium] || 0,
          low_count: severity_counts[:low] || 0,
          security_score: calculate_score_from_findings(findings)
        }

        :ets.insert(@scans_table, {scan_id, scan_result})

        # Generate alerts for critical/high findings
        generate_alerts_for_findings(findings, func)

        {:ok, scan_result}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_scan_all(provider, opts) do
    functions = case provider do
      :aws -> Lambda.list_functions()
      :azure -> AzureFunctions.list_functions()
      :gcp -> CloudFunctions.list_functions()
      _ -> []
    end

    results = Enum.map(functions, fn func ->
      func_id = get_function_id(func, provider)
      case do_scan_function(func_id, provider, opts) do
        {:ok, result} -> result
        {:error, _} -> nil
      end
    end)
    |> Enum.reject(&is_nil/1)

    {:ok, results}
  end

  defp get_function_id(func, :aws), do: func.function_arn || func.function_name
  defp get_function_id(func, :azure), do: func.id || func.name
  defp get_function_id(func, :gcp), do: func.function_id || func.name
  defp get_function_id(_, _), do: nil

  defp do_detect_secrets(content) when is_binary(content) do
    @secret_patterns
    |> Enum.flat_map(fn {pattern, name, severity} ->
      case Regex.scan(pattern, content, capture: :first) do
        [] -> []
        matches ->
          Enum.map(matches, fn [match] ->
            # Mask the actual secret in evidence
            masked = String.slice(match, 0, 4) <> "****" <> String.slice(match, -4, 4)

            %Finding{
              id: Ecto.UUID.generate(),
              category: :secrets,
              severity: severity,
              title: "#{name} Detected",
              description: "Found potential #{name} in code or configuration",
              evidence: masked,
              remediation: "Remove hardcoded credential and use secrets manager",
              mitre_technique: "T1552",
              detected_at: DateTime.utc_now(),
              status: :open
            }
          end)
      end
    end)
  end

  defp do_detect_secrets(content) when is_map(content) do
    # Scan map (environment variables)
    content
    |> Enum.flat_map(fn {key, value} ->
      key_findings = check_key_for_secrets(key, value)
      value_findings = if is_binary(value), do: do_detect_secrets(value), else: []
      key_findings ++ value_findings
    end)
  end

  defp do_detect_secrets(_), do: []

  defp check_key_for_secrets(key, _value) do
    secret_key_patterns = [
      {~r/^AWS_SECRET/i, "AWS Secret"},
      {~r/^API_KEY/i, "API Key"},
      {~r/^API_SECRET/i, "API Secret"},
      {~r/^SECRET_KEY/i, "Secret Key"},
      {~r/^PRIVATE_KEY/i, "Private Key"},
      {~r/^DB_PASSWORD/i, "Database Password"},
      {~r/^PASSWORD/i, "Password"},
      {~r/^AUTH_TOKEN/i, "Auth Token"},
      {~r/^JWT_SECRET/i, "JWT Secret"},
      {~r/^ENCRYPTION_KEY/i, "Encryption Key"}
    ]

    Enum.flat_map(secret_key_patterns, fn {pattern, name} ->
      if Regex.match?(pattern, key) do
        [%Finding{
          id: Ecto.UUID.generate(),
          category: :secrets,
          severity: :high,
          title: "#{name} in Environment Variable",
          description: "Environment variable '#{key}' likely contains sensitive data",
          evidence: "Key: #{key}",
          remediation: "Use secrets manager (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)",
          mitre_technique: "T1552",
          detected_at: DateTime.utc_now(),
          status: :open
        }]
      else
        []
      end
    end)
  end

  defp do_analyze_iam(nil, _provider), do: []
  defp do_analyze_iam(policy, :aws), do: analyze_aws_policy(policy)
  defp do_analyze_iam(policy, :azure), do: analyze_azure_policy(policy)
  defp do_analyze_iam(policy, :gcp), do: analyze_gcp_policy(policy)
  defp do_analyze_iam(_, _), do: []

  defp analyze_aws_policy(policy) when is_map(policy) do
    statements = policy["Statement"] || []

    Enum.flat_map(statements, fn statement ->
      effect = statement["Effect"]
      actions = List.wrap(statement["Action"] || [])
      resources = List.wrap(statement["Resource"] || [])

      if effect == "Allow" do
        check_aws_actions(actions, resources)
      else
        []
      end
    end)
  end
  defp analyze_aws_policy(_), do: []

  defp check_aws_actions(actions, resources) do
    Enum.flat_map(actions, fn action ->
      case find_dangerous_permission(action, @dangerous_aws_permissions) do
        nil -> []
        {_perm, severity, description} ->
          resource_str = Enum.join(resources, ", ")
          [%Finding{
            id: Ecto.UUID.generate(),
            category: :iam,
            severity: severity,
            title: "Overprivileged IAM Permission: #{action}",
            description: "#{description}. Resources: #{resource_str}",
            evidence: "Action: #{action}",
            remediation: "Apply principle of least privilege. Restrict to specific resources.",
            mitre_technique: "T1078.004",
            detected_at: DateTime.utc_now(),
            status: :open
          }]
      end
    end)
  end

  defp find_dangerous_permission(action, permissions) do
    Enum.find(permissions, fn {pattern, _sev, _desc} ->
      pattern == action || (String.contains?(pattern, "*") && matches_wildcard?(action, pattern))
    end)
  end

  defp matches_wildcard?(action, pattern) do
    pattern_regex = pattern
    |> String.replace("*", ".*")
    |> Regex.compile!()

    Regex.match?(pattern_regex, action)
  end

  defp analyze_azure_policy(policy) do
    # Simplified Azure RBAC analysis
    roles = policy["roles"] || []

    Enum.flat_map(roles, fn role ->
      case find_dangerous_permission(role, @dangerous_azure_permissions) do
        nil -> []
        {_perm, severity, description} ->
          [%Finding{
            id: Ecto.UUID.generate(),
            category: :iam,
            severity: severity,
            title: "Overprivileged Azure Role: #{role}",
            description: description,
            remediation: "Use more restrictive built-in roles or create custom roles",
            mitre_technique: "T1078.004",
            detected_at: DateTime.utc_now(),
            status: :open
          }]
      end
    end)
  end

  defp analyze_gcp_policy(policy) do
    # Simplified GCP IAM analysis
    bindings = policy["bindings"] || []

    Enum.flat_map(bindings, fn binding ->
      role = binding["role"] || ""
      permissions = get_gcp_role_permissions(role)

      Enum.flat_map(permissions, fn perm ->
        case find_dangerous_permission(perm, @dangerous_gcp_permissions) do
          nil -> []
          {_p, severity, description} ->
            [%Finding{
              id: Ecto.UUID.generate(),
              category: :iam,
              severity: severity,
              title: "Overprivileged GCP Permission: #{perm}",
              description: "#{description} via role #{role}",
              remediation: "Create custom role with minimal permissions",
              mitre_technique: "T1078.004",
              detected_at: DateTime.utc_now(),
              status: :open
            }]
        end
      end)
    end)
  end

  defp get_gcp_role_permissions("roles/owner"), do: ["*"]
  defp get_gcp_role_permissions("roles/editor"), do: ["*"]
  defp get_gcp_role_permissions(_), do: []

  defp do_scan_dependencies(nil), do: []
  defp do_scan_dependencies(dependencies) when is_map(dependencies) do
    Enum.flat_map(dependencies, fn {package, version} ->
      case find_vulnerable_package(package, version) do
        nil -> []
        {_pkg, _ver, cve, severity, description} ->
          [%Finding{
            id: Ecto.UUID.generate(),
            category: :dependencies,
            severity: severity,
            title: "Vulnerable Dependency: #{package}",
            description: "#{description}",
            cve_id: cve,
            evidence: "#{package}@#{version}",
            remediation: "Upgrade #{package} to the latest secure version",
            mitre_technique: "T1195.001",
            detected_at: DateTime.utc_now(),
            status: :open
          }]
      end
    end)
  end
  defp do_scan_dependencies(_), do: []

  defp find_vulnerable_package(package, version) do
    Enum.find(@vulnerable_packages, fn {pkg, vuln_ver, _cve, _sev, _desc} ->
      pkg == package && version_vulnerable?(version, vuln_ver)
    end)
  end

  defp version_vulnerable?(_version, _vuln_pattern) do
    # Simplified version checking - in production use proper semver comparison
    false
  end

  defp do_scan_code(code) when is_binary(code) do
    @suspicious_code_patterns
    |> Enum.flat_map(fn {pattern, name, severity, technique} ->
      if Regex.match?(pattern, code) do
        # Find line numbers
        lines = String.split(code, "\n")
        line_numbers = lines
        |> Enum.with_index(1)
        |> Enum.filter(fn {line, _idx} -> Regex.match?(pattern, line) end)
        |> Enum.map(fn {_line, idx} -> idx end)

        [%Finding{
          id: Ecto.UUID.generate(),
          category: :code_patterns,
          severity: severity,
          title: "Suspicious Code Pattern: #{name}",
          description: "Found #{name} pattern in function code",
          line_number: List.first(line_numbers),
          evidence: "Lines: #{Enum.join(line_numbers, ", ")}",
          remediation: "Review code for security implications",
          mitre_technique: technique,
          detected_at: DateTime.utc_now(),
          status: :open
        }]
      else
        []
      end
    end)
  end
  defp do_scan_code(_), do: []

  defp scan_env_for_secrets(env, function_id, provider) do
    env
    |> do_detect_secrets()
    |> Enum.map(fn finding ->
      %{finding |
        function_id: function_id,
        provider: provider
      }
    end)
  end

  defp analyze_aws_role(nil, _function_id), do: []
  defp analyze_aws_role(_role_arn, _function_id) do
    # In production, fetch role policy via AWS SDK
    []
  end

  defp analyze_azure_identity(nil, _function_id), do: []
  defp analyze_azure_identity(_identity, _function_id) do
    # In production, fetch identity permissions via Azure SDK
    []
  end

  defp analyze_gcp_service_account(nil, _function_id), do: []
  defp analyze_gcp_service_account(_email, _function_id) do
    # In production, fetch SA permissions via GCP SDK
    []
  end

  defp analyze_network_exposure(func, :aws, function_id) do
    findings = []

    # Check if function is in VPC
    findings = if is_nil(func.vpc_config) || func.vpc_config == %{} do
      [%Finding{
        id: Ecto.UUID.generate(),
        function_id: function_id,
        provider: :aws,
        category: :network,
        severity: :low,
        title: "Function Not in VPC",
        description: "Lambda function runs in public AWS network without VPC isolation",
        remediation: "Place function in VPC for network isolation if accessing private resources",
        detected_at: DateTime.utc_now(),
        status: :open
      } | findings]
    else
      findings
    end

    findings
  end

  defp analyze_network_exposure(func, :azure, function_id) do
    findings = []

    # Check network restrictions
    if is_nil(func.network_restrictions) || func.network_restrictions == %{} do
      [%Finding{
        id: Ecto.UUID.generate(),
        function_id: function_id,
        provider: :azure,
        category: :network,
        severity: :medium,
        title: "No Network Restrictions",
        description: "Function app has no IP restrictions configured",
        remediation: "Configure IP restrictions or VNet integration",
        detected_at: DateTime.utc_now(),
        status: :open
      } | findings]
    else
      findings
    end
  end

  defp analyze_network_exposure(func, :gcp, function_id) do
    findings = []

    # Check ingress settings
    if func.ingress_settings == "ALLOW_ALL" do
      [%Finding{
        id: Ecto.UUID.generate(),
        function_id: function_id,
        provider: :gcp,
        category: :network,
        severity: :medium,
        title: "Public Ingress Allowed",
        description: "Function allows traffic from any source",
        remediation: "Set ingress to ALLOW_INTERNAL_ONLY or ALLOW_INTERNAL_AND_GCLB",
        detected_at: DateTime.utc_now(),
        status: :open
      } | findings]
    else
      findings
    end
  end

  defp analyze_network_exposure(_, _, _), do: []

  defp analyze_function_config(func, :aws, function_id) do
    findings = []

    # Check timeout
    timeout = func.timeout || 3
    if timeout > 300 do
      findings = [%Finding{
        id: Ecto.UUID.generate(),
        function_id: function_id,
        provider: :aws,
        category: :configuration,
        severity: :low,
        title: "High Timeout Value",
        description: "Function timeout of #{timeout}s is unusually high",
        remediation: "Review if long timeout is necessary",
        detected_at: DateTime.utc_now(),
        status: :open
      } | findings]
    end

    # Check memory
    memory = func.memory_size || 128
    if memory > 3008 do
      findings = [%Finding{
        id: Ecto.UUID.generate(),
        function_id: function_id,
        provider: :aws,
        category: :configuration,
        severity: :low,
        title: "High Memory Configuration",
        description: "Function memory of #{memory}MB is unusually high",
        remediation: "Review if high memory is necessary",
        detected_at: DateTime.utc_now(),
        status: :open
      } | findings]
    end

    findings
  end

  defp analyze_function_config(func, :azure, function_id) do
    findings = []

    # Check authentication
    if is_nil(func.authentication) || func.authentication == %{"enabled" => false} do
      findings = [%Finding{
        id: Ecto.UUID.generate(),
        function_id: function_id,
        provider: :azure,
        category: :configuration,
        severity: :medium,
        title: "No Authentication Configured",
        description: "Function app has no authentication/authorization",
        remediation: "Enable Azure AD authentication or API key validation",
        detected_at: DateTime.utc_now(),
        status: :open
      } | findings]
    end

    findings
  end

  defp analyze_function_config(func, :gcp, function_id) do
    findings = []

    # Check HTTPS trigger security
    if func.https_trigger do
      security = func.https_trigger["securityLevel"] || "SECURE_ALWAYS"
      if security == "SECURE_OPTIONAL" do
        findings = [%Finding{
          id: Ecto.UUID.generate(),
          function_id: function_id,
          provider: :gcp,
          category: :configuration,
          severity: :medium,
          title: "HTTPS Not Enforced",
          description: "Function allows HTTP traffic",
          remediation: "Set securityLevel to SECURE_ALWAYS",
          detected_at: DateTime.utc_now(),
          status: :open
        } | findings]
      end
    end

    findings
  end

  defp analyze_function_config(_, _, _), do: []

  defp get_findings_internal(function_id) do
    :ets.foldl(
      fn {_id, finding}, acc ->
        if finding.function_id == function_id do
          [finding | acc]
        else
          acc
        end
      end,
      [],
      @findings_table
    )
    |> Enum.sort_by(& &1.detected_at, {:desc, DateTime})
  end

  defp get_findings_by_severity_internal(severity) do
    :ets.foldl(
      fn {_id, finding}, acc ->
        if finding.severity == severity do
          [finding | acc]
        else
          acc
        end
      end,
      [],
      @findings_table
    )
  end

  defp update_finding_status_internal(finding_id, status) do
    case :ets.lookup(@findings_table, finding_id) do
      [{^finding_id, finding}] ->
        updated = %{finding |
          status: status,
          resolved_at: if(status == :resolved, do: DateTime.utc_now(), else: nil)
        }
        :ets.insert(@findings_table, {finding_id, updated})
        :ok

      [] ->
        {:error, :not_found}
    end
  end

  defp get_scan_history_internal(function_id) do
    :ets.foldl(
      fn {_id, scan}, acc ->
        if scan.function_id == function_id do
          [scan | acc]
        else
          acc
        end
      end,
      [],
      @scans_table
    )
    |> Enum.sort_by(& &1.completed_at, {:desc, DateTime})
  end

  defp count_by_severity(findings) do
    Enum.reduce(findings, %{}, fn finding, acc ->
      Map.update(acc, finding.severity, 1, &(&1 + 1))
    end)
  end

  defp calculate_score_from_findings(findings) do
    # Start from 100, deduct based on findings
    base_score = 100

    deductions = findings
    |> Enum.map(fn finding ->
      case finding.severity do
        :critical -> 20
        :high -> 10
        :medium -> 5
        :low -> 2
        _ -> 0
      end
    end)
    |> Enum.sum()

    max(0, base_score - deductions)
  end

  defp do_calculate_risk_score(function_id) do
    findings = get_findings_internal(function_id)
    score = calculate_score_from_findings(findings)
    {:ok, score}
  end

  defp generate_alerts_for_findings(findings, func) do
    critical_and_high = Enum.filter(findings, fn f ->
      f.severity in [:critical, :high] && f.status == :open
    end)

    Enum.each(critical_and_high, fn finding ->
      Alerts.create_alert(%{
        title: "Serverless Security: #{finding.title}",
        description: """
        Function: #{func.function_name || func.name}
        Provider: #{finding.provider}
        Category: #{finding.category}

        #{finding.description}

        Evidence: #{finding.evidence}
        Remediation: #{finding.remediation}
        """,
        severity: to_string(finding.severity),
        category: "serverless_security",
        source: "security_analyzer",
        mitre_techniques: if(finding.mitre_technique, do: [finding.mitre_technique], else: []),
        metadata: %{
          function_id: finding.function_id,
          provider: finding.provider,
          finding_id: finding.id,
          category: finding.category,
          cve_id: finding.cve_id
        }
      })
    end)
  end

  defp compute_statistics do
    all_findings = :ets.tab2list(@findings_table)
    |> Enum.map(fn {_id, finding} -> finding end)

    all_scans = :ets.tab2list(@scans_table)
    |> Enum.map(fn {_id, scan} -> scan end)

    open_findings = Enum.filter(all_findings, &(&1.status == :open))

    %{
      total_findings: length(all_findings),
      open_findings: length(open_findings),
      critical_findings: Enum.count(open_findings, &(&1.severity == :critical)),
      high_findings: Enum.count(open_findings, &(&1.severity == :high)),
      medium_findings: Enum.count(open_findings, &(&1.severity == :medium)),
      low_findings: Enum.count(open_findings, &(&1.severity == :low)),
      total_scans: length(all_scans),
      findings_by_category: group_by_category(open_findings),
      findings_by_provider: group_by_provider(open_findings),
      average_security_score: calculate_avg_score(all_scans)
    }
  end

  defp group_by_category(findings) do
    findings
    |> Enum.group_by(& &1.category)
    |> Enum.map(fn {category, items} -> {category, length(items)} end)
    |> Map.new()
  end

  defp group_by_provider(findings) do
    findings
    |> Enum.group_by(& &1.provider)
    |> Enum.map(fn {provider, items} -> {provider, length(items)} end)
    |> Map.new()
  end

  defp calculate_avg_score([]), do: 100
  defp calculate_avg_score(scans) do
    total = Enum.sum(Enum.map(scans, & &1.security_score || 100))
    round(total / length(scans))
  end
end
