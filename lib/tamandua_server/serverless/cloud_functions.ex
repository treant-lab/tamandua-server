defmodule TamanduaServer.Serverless.CloudFunctions do
  @moduledoc """
  GCP Cloud Functions Monitoring Module.

  Provides comprehensive monitoring and security analysis for Google Cloud Functions:
  - Cloud Logging integration
  - Function execution monitoring
  - IAM analysis
  - VPC connector analysis
  - Secret Manager integration check

  ## MITRE ATT&CK Coverage
  - T1204.003: User Execution - Malicious Image
  - T1059: Command and Scripting Interpreter
  - T1496: Resource Hijacking (crypto mining)
  - T1041: Exfiltration Over C2 Channel
  - T1078.004: Valid Accounts - Cloud Accounts

  ## Configuration

      config :tamandua_server, :gcp,
        project_id: "...",
        credentials_file: "/path/to/credentials.json"

  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts

  @functions_table :gcp_cloud_functions
  @executions_table :gcp_function_executions
  @logs_table :gcp_function_logs

  # GCP regions
  @gcp_regions [
    "us-central1", "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4",
    "europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-west6",
    "asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3",
    "asia-south1", "asia-southeast1", "asia-southeast2",
    "australia-southeast1", "southamerica-east1"
  ]

  # Types
  defmodule Function do
    @moduledoc "GCP Cloud Function metadata"
    defstruct [
      :name,
      :function_id,
      :project_id,
      :region,
      :runtime,
      :entry_point,
      :status,  # ACTIVE, OFFLINE, DEPLOY_IN_PROGRESS
      :https_trigger,
      :event_trigger,
      :available_memory_mb,
      :timeout,
      :environment_variables,
      :vpc_connector,
      :service_account_email,
      :build_environment_variables,
      :secret_environment_variables,
      :ingress_settings,  # ALLOW_ALL, ALLOW_INTERNAL_ONLY, ALLOW_INTERNAL_AND_GCLB
      :max_instances,
      :min_instances,
      :source_repository,
      :source_archive_url,
      :source_upload_url,
      :kms_key_name,
      :docker_registry,
      :docker_repository,
      # Generation (Gen1 vs Gen2)
      :generation,
      # Security analysis
      :security_score,
      :findings,
      :iam_bindings,
      :last_execution,
      :invocation_count_24h,
      :error_count_24h,
      :avg_duration_ms,
      :last_sync
    ]
  end

  defmodule Execution do
    @moduledoc "GCP Cloud Function execution record"
    defstruct [
      :execution_id,
      :function_name,
      :project_id,
      :region,
      :timestamp,
      :duration_ms,
      :status,  # ok, error, timeout
      :status_code,
      :error_message,
      :trigger_type,  # http, pubsub, storage, firestore
      :source_ip,
      :user_agent,
      :trace_id,
      :memory_used_mb,
      # Security context
      :outbound_requests,
      :file_operations,
      :child_processes,
      :anomaly_score
    ]
  end

  defmodule LogEntry do
    @moduledoc "GCP Cloud Function log entry"
    defstruct [
      :timestamp,
      :execution_id,
      :function_name,
      :severity,  # DEBUG, INFO, WARNING, ERROR, CRITICAL
      :text_payload,
      :json_payload,
      :labels,
      :trace,
      :anomalies
    ]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Sync Cloud Functions from GCP project.
  """
  @spec sync_functions(String.t(), keyword()) :: {:ok, [Function.t()]} | {:error, term()}
  def sync_functions(project_id \\ nil, opts \\ []) do
    GenServer.call(__MODULE__, {:sync_functions, project_id, opts}, 60_000)
  end

  @doc """
  Get all monitored Cloud Functions.
  """
  @spec list_functions(map()) :: [Function.t()]
  def list_functions(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_functions, filters})
  end

  @doc """
  Get a specific Cloud Function.
  """
  @spec get_function(String.t()) :: {:ok, Function.t()} | {:error, :not_found}
  def get_function(function_id) do
    GenServer.call(__MODULE__, {:get_function, function_id})
  end

  @doc """
  Get execution history for a function.
  """
  @spec get_executions(String.t(), keyword()) :: [Execution.t()]
  def get_executions(function_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_executions, function_id, opts})
  end

  @doc """
  Record a Cloud Function execution.
  """
  @spec record_execution(map()) :: :ok
  def record_execution(execution_data) do
    GenServer.cast(__MODULE__, {:record_execution, execution_data})
  end

  @doc """
  Ingest Cloud Logging entries.
  """
  @spec ingest_logs(String.t(), [map()]) :: :ok
  def ingest_logs(function_name, log_entries) do
    GenServer.cast(__MODULE__, {:ingest_logs, function_name, log_entries})
  end

  @doc """
  Get statistics across all Cloud Functions.
  """
  @spec get_statistics() :: map()
  def get_statistics do
    GenServer.call(__MODULE__, :get_statistics)
  end

  @doc """
  Analyze IAM bindings for a function.
  """
  @spec analyze_iam(String.t()) :: {:ok, map()} | {:error, term()}
  def analyze_iam(function_name) do
    GenServer.call(__MODULE__, {:analyze_iam, function_name}, 30_000)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@functions_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@executions_table, [:ordered_set, :named_table, :public, read_concurrency: true])
    :ets.new(@logs_table, [:ordered_set, :named_table, :public, read_concurrency: true])

    # Schedule periodic sync
    if gcp_configured?() do
      Process.send_after(self(), :sync_functions, :timer.minutes(5))
    end

    # Schedule cleanup
    :timer.send_interval(:timer.hours(1), :cleanup_old_data)

    Logger.info("GCP Cloud Functions Monitoring service started")
    {:ok, %{}}
  end

  @impl true
  def handle_call({:sync_functions, project_id, opts}, _from, state) do
    result = do_sync_functions(project_id, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:list_functions, filters}, _from, state) do
    functions = list_functions_internal(filters)
    {:reply, functions, state}
  end

  @impl true
  def handle_call({:get_function, function_id}, _from, state) do
    result = get_function_internal(function_id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_executions, function_id, opts}, _from, state) do
    executions = get_executions_internal(function_id, opts)
    {:reply, executions, state}
  end

  @impl true
  def handle_call(:get_statistics, _from, state) do
    stats = compute_statistics()
    {:reply, stats, state}
  end

  @impl true
  def handle_call({:analyze_iam, function_name}, _from, state) do
    result = do_analyze_iam(function_name)
    {:reply, result, state}
  end

  @impl true
  def handle_cast({:record_execution, execution_data}, state) do
    process_execution(execution_data)
    {:noreply, state}
  end

  @impl true
  def handle_cast({:ingest_logs, function_name, log_entries}, state) do
    process_logs(function_name, log_entries)
    {:noreply, state}
  end

  @impl true
  def handle_info(:sync_functions, state) do
    config = Application.get_env(:tamandua_server, :gcp, [])
    project_id = config[:project_id]

    if project_id do
      Task.start(fn ->
        do_sync_functions(project_id, [])
      end)
    end

    Process.send_after(self(), :sync_functions, :timer.minutes(15))
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup_old_data, state) do
    cutoff = DateTime.add(DateTime.utc_now(), -7 * 24 * 60 * 60, :second)
    cutoff_ts = DateTime.to_unix(cutoff, :millisecond)

    :ets.select_delete(@executions_table, [
      {{:"$1", :"$2"}, [{:<, :"$1", cutoff_ts}], [true]}
    ])

    :ets.select_delete(@logs_table, [
      {{:"$1", :"$2"}, [{:<, :"$1", cutoff_ts}], [true]}
    ])

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp gcp_configured? do
    config = Application.get_env(:tamandua_server, :gcp, [])
    config[:project_id] && (config[:credentials_file] || System.get_env("GOOGLE_APPLICATION_CREDENTIALS"))
  end

  defp do_sync_functions(project_id, _opts) do
    if gcp_configured?() do
      Logger.info("Syncing Cloud Functions from project #{project_id}")
      # In production, use Google Cloud SDK (google_cloud)
      {:ok, []}
    else
      Logger.warning("GCP credentials not configured for Cloud Functions sync")
      {:error, :not_configured}
    end
  end

  defp list_functions_internal(filters) do
    :ets.foldl(
      fn {_key, func}, acc -> [func | acc] end,
      [],
      @functions_table
    )
    |> apply_function_filters(filters)
    |> Enum.sort_by(& &1.name)
  end

  defp apply_function_filters(functions, filters) do
    functions
    |> filter_by_project(filters[:project_id])
    |> filter_by_region(filters[:region])
    |> filter_by_runtime(filters[:runtime])
    |> filter_by_status(filters[:status])
    |> filter_by_generation(filters[:generation])
  end

  defp filter_by_project(functions, nil), do: functions
  defp filter_by_project(functions, project_id) do
    Enum.filter(functions, &(&1.project_id == project_id))
  end

  defp filter_by_region(functions, nil), do: functions
  defp filter_by_region(functions, region) do
    Enum.filter(functions, &(&1.region == region))
  end

  defp filter_by_runtime(functions, nil), do: functions
  defp filter_by_runtime(functions, runtime) do
    Enum.filter(functions, &String.contains?(&1.runtime || "", runtime))
  end

  defp filter_by_status(functions, nil), do: functions
  defp filter_by_status(functions, status) do
    Enum.filter(functions, &(&1.status == status))
  end

  defp filter_by_generation(functions, nil), do: functions
  defp filter_by_generation(functions, gen) do
    Enum.filter(functions, &(&1.generation == gen))
  end

  defp get_function_internal(function_id) do
    case :ets.lookup(@functions_table, function_id) do
      [{^function_id, func}] -> {:ok, func}
      [] ->
        # Search by name
        result = :ets.foldl(
          fn {_key, func}, acc ->
            if func.name == function_id || func.function_id == function_id do
              func
            else
              acc
            end
          end,
          nil,
          @functions_table
        )
        if result, do: {:ok, result}, else: {:error, :not_found}
    end
  end

  defp get_executions_internal(function_id, opts) do
    limit = Keyword.get(opts, :limit, 100)

    :ets.foldl(
      fn {_ts, exec}, acc ->
        if exec.function_name == function_id do
          [exec | acc]
        else
          acc
        end
      end,
      [],
      @executions_table
    )
    |> Enum.sort_by(& &1.timestamp, {:desc, DateTime})
    |> Enum.take(limit)
  end

  defp process_execution(data) do
    execution = build_execution(data)

    ts = DateTime.to_unix(execution.timestamp, :millisecond)
    key = {ts, execution.execution_id}
    :ets.insert(@executions_table, {key, execution})

    # Check for security issues
    check_execution_security(execution)
  end

  defp build_execution(data) do
    %Execution{
      execution_id: data["execution_id"] || Ecto.UUID.generate(),
      function_name: data["function_name"],
      project_id: data["project_id"],
      region: data["region"],
      timestamp: parse_timestamp(data["timestamp"]),
      duration_ms: data["duration_ms"],
      status: parse_status(data["status"]),
      status_code: data["status_code"],
      error_message: data["error_message"],
      trigger_type: data["trigger_type"],
      source_ip: data["source_ip"],
      user_agent: data["user_agent"],
      trace_id: data["trace_id"],
      memory_used_mb: data["memory_used_mb"],
      outbound_requests: data["outbound_requests"] || [],
      file_operations: data["file_operations"] || [],
      child_processes: data["child_processes"] || [],
      anomaly_score: 0.0
    }
  end

  defp parse_timestamp(nil), do: DateTime.utc_now()
  defp parse_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp parse_timestamp(%DateTime{} = dt), do: dt

  defp parse_status("ok"), do: :ok
  defp parse_status("error"), do: :error
  defp parse_status("timeout"), do: :timeout
  defp parse_status(_), do: :unknown

  defp check_execution_security(execution) do
    issues = []

    # Check for suspicious outbound requests
    issues = if has_suspicious_outbound?(execution.outbound_requests) do
      [{:suspicious_outbound, execution.outbound_requests} | issues]
    else
      issues
    end

    # Check for suspicious file operations
    issues = if has_suspicious_file_ops?(execution.file_operations) do
      [{:suspicious_file_ops, execution.file_operations} | issues]
    else
      issues
    end

    # Check for child processes
    issues = if execution.child_processes != [] do
      [{:child_processes, execution.child_processes} | issues]
    else
      issues
    end

    # Check error patterns
    if execution.error_message do
      check_error_patterns(execution)
    end

    if issues != [] do
      generate_security_alert(execution, issues)
    end
  end

  defp has_suspicious_outbound?(nil), do: false
  defp has_suspicious_outbound?([]), do: false
  defp has_suspicious_outbound?(requests) do
    suspicious = [
      "ngrok.io",
      "requestbin",
      "burpcollaborator",
      "pipedream",
      "webhook.site"
    ]

    Enum.any?(requests, fn req ->
      url = req["url"] || req[:url] || ""
      Enum.any?(suspicious, &String.contains?(url, &1))
    end)
  end

  defp has_suspicious_file_ops?(nil), do: false
  defp has_suspicious_file_ops?([]), do: false
  defp has_suspicious_file_ops?(ops) do
    sensitive = ["/etc/passwd", "/etc/shadow", "/proc/", "/sys/"]

    Enum.any?(ops, fn op ->
      path = op["path"] || op[:path] || ""
      Enum.any?(sensitive, &String.starts_with?(path, &1))
    end)
  end

  defp check_error_patterns(execution) do
    message = execution.error_message || ""

    patterns = [
      {~r/PermissionDenied/i, "Permission escalation attempt", "T1078"},
      {~r/OutOfMemory/i, "Memory exhaustion (possible cryptominer)", "T1496"},
      {~r/DEADLINE_EXCEEDED/i, "Function timeout (resource exhaustion)", "T1496"},
      {~r/subprocess.*error/i, "Subprocess execution error", "T1059"},
      {~r/socket.*refused/i, "Suspicious network activity", "T1071"}
    ]

    Enum.each(patterns, fn {pattern, description, technique} ->
      if Regex.match?(pattern, message) do
        Alerts.create_alert(%{
          title: "Cloud Function Security Alert: #{description}",
          description: """
          Function: #{execution.function_name}
          Project: #{execution.project_id}
          Execution ID: #{execution.execution_id}
          Error: #{message}
          """,
          severity: "high",
          category: "serverless_security",
          source: "cloud_functions_monitoring",
          mitre_techniques: [technique],
          metadata: %{
            function_name: execution.function_name,
            project_id: execution.project_id,
            execution_id: execution.execution_id,
            pattern: description
          }
        })
      end
    end)
  end

  defp generate_security_alert(execution, issues) do
    severity = determine_severity(issues)

    Alerts.create_alert(%{
      title: "Cloud Function Anomaly: #{execution.function_name}",
      description: """
      Function: #{execution.function_name}
      Project: #{execution.project_id}
      Issues: #{format_issues(issues)}
      """,
      severity: severity,
      category: "serverless_anomaly",
      source: "cloud_functions_monitoring",
      mitre_techniques: determine_techniques(issues),
      metadata: %{
        function_name: execution.function_name,
        project_id: execution.project_id,
        execution_id: execution.execution_id,
        issues: issues
      }
    })
  end

  defp determine_severity(issues) do
    cond do
      Enum.any?(issues, fn {type, _} -> type in [:suspicious_outbound, :child_processes] end) ->
        "critical"
      Enum.any?(issues, fn {type, _} -> type == :suspicious_file_ops end) ->
        "high"
      true ->
        "medium"
    end
  end

  defp format_issues(issues) do
    Enum.map(issues, fn {type, data} -> "#{type}: #{inspect(data)}" end)
    |> Enum.join("\n")
  end

  defp determine_techniques(issues) do
    issues
    |> Enum.flat_map(fn {type, _} ->
      case type do
        :suspicious_outbound -> ["T1041", "T1071"]
        :suspicious_file_ops -> ["T1005", "T1083"]
        :child_processes -> ["T1059"]
        _ -> []
      end
    end)
    |> Enum.uniq()
  end

  defp process_logs(function_name, log_entries) do
    Enum.each(log_entries, fn entry ->
      log = build_log_entry(function_name, entry)

      ts = DateTime.to_unix(log.timestamp, :millisecond)
      key = {ts, log.execution_id || Ecto.UUID.generate()}
      :ets.insert(@logs_table, {key, log})

      check_log_security(log)
    end)
  end

  defp build_log_entry(function_name, entry) do
    %LogEntry{
      timestamp: parse_timestamp(entry["timestamp"]),
      execution_id: entry["execution_id"] || entry["labels"]["execution_id"],
      function_name: function_name,
      severity: entry["severity"] || "INFO",
      text_payload: entry["textPayload"],
      json_payload: entry["jsonPayload"],
      labels: entry["labels"] || %{},
      trace: entry["trace"],
      anomalies: []
    }
  end

  defp check_log_security(log) do
    message = log.text_payload || ""
    json = log.json_payload || %{}
    combined = "#{message} #{inspect(json)}"

    security_patterns = [
      {~r/exec\s*\(/i, "Code execution", "T1059"},
      {~r/eval\s*\(/i, "Dynamic code evaluation", "T1059"},
      {~r/subprocess/i, "Subprocess spawning", "T1059"},
      {~r/os\.system/i, "System command execution", "T1059"},
      {~r/curl\s+.*http/i, "HTTP request", "T1071"},
      {~r/wget\s+.*http/i, "File download", "T1105"},
      {~r/base64.*decode/i, "Base64 decoding", "T1140"},
      {~r/crypto.*mine|xmr|monero/i, "Cryptocurrency activity", "T1496"},
      {~r/GOOGLE_APPLICATION_CREDENTIALS/i, "Credential exposure", "T1552"},
      {~r/service.*account.*key/i, "Service account key exposure", "T1552"}
    ]

    Enum.each(security_patterns, fn {pattern, description, technique} ->
      if Regex.match?(pattern, combined) do
        Logger.warning("Cloud Function log security pattern: #{description}")

        Alerts.create_alert(%{
          title: "Cloud Function Log Alert: #{description}",
          description: """
          Function: #{log.function_name}
          Execution ID: #{log.execution_id}
          Message: #{String.slice(message, 0, 500)}
          """,
          severity: "high",
          category: "serverless_security",
          source: "cloud_functions_log_analysis",
          mitre_techniques: [technique],
          metadata: %{
            function_name: log.function_name,
            execution_id: log.execution_id,
            pattern: description
          }
        })
      end
    end)
  end

  defp do_analyze_iam(function_name) do
    case get_function_internal(function_name) do
      {:ok, function} ->
        iam_bindings = function.iam_bindings || []
        service_account = function.service_account_email

        findings = []

        # Check IAM bindings for overprivilege
        overprivilege_findings = check_iam_overprivilege(%{
          iam_bindings: iam_bindings,
          service_account_email: service_account,
          function_name: function_name
        })
        findings = findings ++ overprivilege_findings

        # Check service account
        sa_findings = analyze_service_account_permissions(service_account)
        findings = findings ++ sa_findings

        risk_score = compute_iam_risk_score(findings)

        {:ok, %{
          function_name: function_name,
          service_account: service_account,
          iam_bindings: iam_bindings,
          findings: findings,
          risk_score: risk_score,
          overprivileged: risk_score > 50
        }}

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  defp analyze_service_account_permissions(nil), do: []
  defp analyze_service_account_permissions(email) do
    findings = []

    # Flag default compute service account
    findings = if String.contains?(email, "compute@developer.gserviceaccount.com") do
      [%{
        type: :default_compute_sa,
        severity: "medium",
        title: "Default compute service account in use",
        description: "Function uses the default Compute Engine service account '#{email}' which typically has broad Project Editor permissions",
        remediation: "Create a dedicated service account with minimal permissions for this function"
      } | findings]
    else
      findings
    end

    # Flag default App Engine service account
    findings = if String.contains?(email, "@appspot.gserviceaccount.com") do
      [%{
        type: :default_appengine_sa,
        severity: "medium",
        title: "Default App Engine service account in use",
        description: "Function uses the default App Engine service account '#{email}' which may have broad permissions",
        remediation: "Create a dedicated service account with minimal permissions for this function"
      } | findings]
    else
      findings
    end

    findings
  end

  defp compute_iam_risk_score(findings) do
    Enum.reduce(findings, 0, fn finding, score ->
      case finding.severity do
        "critical" -> score + 30
        "high" -> score + 20
        "medium" -> score + 10
        "low" -> score + 5
        _ -> score
      end
    end)
    |> min(100)
  end

  @doc """
  Detect anomalous function executions by comparing against historical baselines.

  Analyzes the following dimensions:
  - Invocation frequency (too many or too few compared to baseline)
  - Execution duration (unusually fast or slow)
  - Memory consumption (higher than normal)
  - Error rates (spikes above baseline)

  Returns a list of anomaly maps with severity scores.
  """
  @spec detect_function_anomalies(Function.t()) :: [map()]
  def detect_function_anomalies(%Function{} = function) do
    function_id = function.function_id || function.name
    executions = get_executions_internal(function_id, limit: 1000)

    if length(executions) < 10 do
      # Not enough data to detect anomalies
      []
    else
      anomalies = []

      # Split executions into recent (last hour) and historical (rest)
      one_hour_ago = DateTime.add(DateTime.utc_now(), -3600, :second)
      {recent, historical} = Enum.split_with(executions, fn exec ->
        DateTime.compare(exec.timestamp, one_hour_ago) == :gt
      end)

      # Detect invocation frequency anomalies
      anomalies = anomalies ++ detect_frequency_anomalies(function_id, recent, historical)

      # Detect duration anomalies
      anomalies = anomalies ++ detect_duration_anomalies(function_id, recent, historical)

      # Detect memory anomalies
      anomalies = anomalies ++ detect_memory_anomalies(function_id, recent, historical)

      # Detect error rate anomalies
      anomalies = anomalies ++ detect_error_rate_anomalies(function_id, recent, historical)

      anomalies
    end
  end

  defp detect_frequency_anomalies(function_id, recent, historical) do
    if length(historical) < 5 do
      []
    else
      # Compute historical hourly rate
      historical_hours = case {List.last(historical), List.first(historical)} do
        {%{timestamp: oldest}, %{timestamp: newest}} ->
          max(DateTime.diff(newest, oldest, :hour), 1)
        _ -> 1
      end

      historical_rate = length(historical) / historical_hours
      recent_count = length(recent)

      cond do
        # Spike: more than 3x the historical hourly rate in the last hour
        historical_rate > 0 and recent_count > historical_rate * 3 ->
          [%{
            type: :invocation_spike,
            function_id: function_id,
            severity: "high",
            title: "Invocation frequency spike detected",
            description: "Function received #{recent_count} invocations in the last hour vs historical average of #{Float.round(historical_rate, 1)}/hour",
            expected_value: Float.round(historical_rate, 1),
            actual_value: recent_count,
            z_score: if(historical_rate > 0, do: Float.round((recent_count - historical_rate) / max(historical_rate * 0.5, 1.0), 2), else: 0.0),
            mitre_technique: "T1498",
            detected_at: DateTime.utc_now()
          }]

        # Drop: no invocations when typically active (could indicate tampering)
        historical_rate > 2 and recent_count == 0 ->
          [%{
            type: :invocation_drop,
            function_id: function_id,
            severity: "medium",
            title: "Unexpected invocation silence",
            description: "Function had zero invocations in the last hour vs historical average of #{Float.round(historical_rate, 1)}/hour",
            expected_value: Float.round(historical_rate, 1),
            actual_value: 0,
            z_score: -3.0,
            mitre_technique: nil,
            detected_at: DateTime.utc_now()
          }]

        true ->
          []
      end
    end
  end

  defp detect_duration_anomalies(function_id, recent, historical) do
    historical_durations = historical
    |> Enum.map(& &1.duration_ms)
    |> Enum.reject(&is_nil/1)

    recent_durations = recent
    |> Enum.map(& &1.duration_ms)
    |> Enum.reject(&is_nil/1)

    if length(historical_durations) < 10 or length(recent_durations) == 0 do
      []
    else
      hist_mean = Enum.sum(historical_durations) / length(historical_durations)
      hist_std = compute_std_dev(historical_durations, hist_mean)
      recent_mean = Enum.sum(recent_durations) / length(recent_durations)

      if hist_std > 0 do
        z_score = (recent_mean - hist_mean) / hist_std

        cond do
          z_score > 3.0 ->
            [%{
              type: :duration_spike,
              function_id: function_id,
              severity: "high",
              title: "Execution duration spike detected",
              description: "Average duration #{round(recent_mean)}ms vs historical #{round(hist_mean)}ms (z-score: #{Float.round(z_score, 2)}). May indicate resource hijacking or code injection.",
              expected_value: round(hist_mean),
              actual_value: round(recent_mean),
              z_score: Float.round(z_score, 2),
              mitre_technique: "T1496",
              detected_at: DateTime.utc_now()
            }]

          z_score < -3.0 ->
            [%{
              type: :duration_drop,
              function_id: function_id,
              severity: "low",
              title: "Execution duration abnormally short",
              description: "Average duration #{round(recent_mean)}ms vs historical #{round(hist_mean)}ms (z-score: #{Float.round(z_score, 2)}). Function may be short-circuiting or failing silently.",
              expected_value: round(hist_mean),
              actual_value: round(recent_mean),
              z_score: Float.round(z_score, 2),
              mitre_technique: nil,
              detected_at: DateTime.utc_now()
            }]

          true ->
            []
        end
      else
        []
      end
    end
  end

  defp detect_memory_anomalies(function_id, recent, historical) do
    historical_memory = historical
    |> Enum.map(& &1.memory_used_mb)
    |> Enum.reject(&is_nil/1)

    recent_memory = recent
    |> Enum.map(& &1.memory_used_mb)
    |> Enum.reject(&is_nil/1)

    if length(historical_memory) < 10 or length(recent_memory) == 0 do
      []
    else
      hist_mean = Enum.sum(historical_memory) / length(historical_memory)
      hist_std = compute_std_dev(historical_memory, hist_mean)
      recent_mean = Enum.sum(recent_memory) / length(recent_memory)

      if hist_std > 0 do
        z_score = (recent_mean - hist_mean) / hist_std

        if z_score > 2.5 do
          [%{
            type: :memory_spike,
            function_id: function_id,
            severity: "high",
            title: "Memory consumption spike detected",
            description: "Average memory #{round(recent_mean)}MB vs historical #{round(hist_mean)}MB (z-score: #{Float.round(z_score, 2)}). May indicate cryptomining or data staging.",
            expected_value: round(hist_mean),
            actual_value: round(recent_mean),
            z_score: Float.round(z_score, 2),
            mitre_technique: "T1496",
            detected_at: DateTime.utc_now()
          }]
        else
          []
        end
      else
        []
      end
    end
  end

  defp detect_error_rate_anomalies(function_id, recent, historical) do
    if length(historical) < 10 or length(recent) == 0 do
      []
    else
      hist_error_count = Enum.count(historical, &(&1.status == :error))
      hist_error_rate = hist_error_count / length(historical)

      recent_error_count = Enum.count(recent, &(&1.status == :error))
      recent_error_rate = recent_error_count / max(length(recent), 1)

      cond do
        # Error rate spike: significantly above historical baseline
        recent_error_rate > 0.5 and recent_error_rate > hist_error_rate * 3 ->
          [%{
            type: :error_rate_spike,
            function_id: function_id,
            severity: "critical",
            title: "Critical error rate spike",
            description: "Error rate #{Float.round(recent_error_rate * 100, 1)}% vs historical #{Float.round(hist_error_rate * 100, 1)}%. #{recent_error_count} errors in last hour.",
            expected_value: Float.round(hist_error_rate * 100, 1),
            actual_value: Float.round(recent_error_rate * 100, 1),
            z_score: 4.0,
            mitre_technique: "T1499",
            detected_at: DateTime.utc_now()
          }]

        recent_error_rate > 0.2 and recent_error_rate > hist_error_rate * 2 ->
          [%{
            type: :error_rate_elevated,
            function_id: function_id,
            severity: "medium",
            title: "Elevated error rate",
            description: "Error rate #{Float.round(recent_error_rate * 100, 1)}% vs historical #{Float.round(hist_error_rate * 100, 1)}%. #{recent_error_count} errors in last hour.",
            expected_value: Float.round(hist_error_rate * 100, 1),
            actual_value: Float.round(recent_error_rate * 100, 1),
            z_score: 2.5,
            mitre_technique: nil,
            detected_at: DateTime.utc_now()
          }]

        true ->
          []
      end
    end
  end

  defp compute_std_dev(values, mean) when length(values) > 1 do
    variance = Enum.reduce(values, 0.0, fn v, acc ->
      diff = v - mean
      acc + diff * diff
    end) / (length(values) - 1)

    :math.sqrt(variance)
  end
  defp compute_std_dev(_, _), do: 0.0

  @doc """
  Check for overprivileged IAM bindings on a Cloud Function.

  Analyzes:
  - Assigned roles against known dangerous roles (roles/editor, roles/owner)
  - Public access bindings (allUsers, allAuthenticatedUsers)
  - Overly broad service account permissions

  Returns a list of overprivilege findings.
  """
  @spec check_iam_overprivilege(map()) :: [map()]
  def check_iam_overprivilege(%{iam_bindings: bindings} = params) when is_list(bindings) do
    function_name = params[:function_name] || "unknown"
    service_account = params[:service_account_email]

    findings = []

    # Check each IAM binding
    binding_findings = Enum.flat_map(bindings, fn binding ->
      role = binding["role"] || binding[:role] || ""
      members = binding["members"] || binding[:members] || []

      role_findings = check_dangerous_gcp_role(role, function_name)
      member_findings = check_public_bindings(members, role, function_name)

      role_findings ++ member_findings
    end)

    findings = findings ++ binding_findings

    # Check service account for known overprivileged roles
    sa_findings = check_service_account_roles(service_account, function_name)
    findings = findings ++ sa_findings

    findings
  end
  def check_iam_overprivilege(_), do: []

  defp check_dangerous_gcp_role(role, function_name) do
    dangerous_roles = %{
      "roles/owner" => {"critical", "Owner role grants full access to all resources in the project"},
      "roles/editor" => {"high", "Editor role grants read/write access to most resources"},
      "roles/iam.securityAdmin" => {"high", "Security Admin can manage IAM policies"},
      "roles/iam.serviceAccountAdmin" => {"high", "Can manage service accounts and keys"},
      "roles/iam.serviceAccountKeyAdmin" => {"high", "Can create and manage service account keys"},
      "roles/iam.serviceAccountTokenCreator" => {"high", "Can create OAuth2 tokens for service accounts"},
      "roles/cloudfunctions.admin" => {"medium", "Full admin access to Cloud Functions"},
      "roles/storage.admin" => {"medium", "Full admin access to Cloud Storage"},
      "roles/compute.admin" => {"high", "Full admin access to Compute Engine"},
      "roles/secretmanager.admin" => {"high", "Full admin access to Secret Manager"}
    }

    case Map.get(dangerous_roles, role) do
      nil ->
        []

      {severity, description} ->
        [%{
          type: :dangerous_iam_role,
          severity: severity,
          title: "Overprivileged IAM role: #{role}",
          description: "Function '#{function_name}' has IAM binding with #{role}. #{description}.",
          remediation: "Apply principle of least privilege. Create a custom role with only the permissions this function needs.",
          mitre_technique: "T1078.004"
        }]
    end
  end

  defp check_public_bindings(members, role, function_name) do
    Enum.flat_map(members, fn member ->
      cond do
        member == "allUsers" ->
          [%{
            type: :public_access_allusers,
            severity: "critical",
            title: "Function publicly accessible to allUsers",
            description: "Function '#{function_name}' has role '#{role}' granted to allUsers (unauthenticated access). Any internet user can invoke this function.",
            remediation: "Remove allUsers binding and require authentication. Use IAM or API Gateway for access control.",
            mitre_technique: "T1190"
          }]

        member == "allAuthenticatedUsers" ->
          [%{
            type: :public_access_all_authenticated,
            severity: "high",
            title: "Function accessible to all authenticated Google users",
            description: "Function '#{function_name}' has role '#{role}' granted to allAuthenticatedUsers. Any Google account holder can access this function.",
            remediation: "Replace allAuthenticatedUsers with specific service accounts or user groups.",
            mitre_technique: "T1078.004"
          }]

        true ->
          []
      end
    end)
  end

  defp check_service_account_roles(nil, _function_name), do: []
  defp check_service_account_roles(email, function_name) do
    cond do
      String.contains?(email, "compute@developer.gserviceaccount.com") ->
        [%{
          type: :default_sa_overprivilege,
          severity: "high",
          title: "Default compute service account with implicit Editor role",
          description: "Function '#{function_name}' uses the default Compute Engine service account '#{email}' which typically has Project Editor permissions.",
          remediation: "Create a dedicated service account with only the permissions this function requires.",
          mitre_technique: "T1078.004"
        }]

      String.contains?(email, "@appspot.gserviceaccount.com") ->
        [%{
          type: :appengine_sa_overprivilege,
          severity: "medium",
          title: "Default App Engine service account",
          description: "Function '#{function_name}' uses the App Engine default service account '#{email}' which may have broad permissions.",
          remediation: "Create a dedicated service account with minimal permissions.",
          mitre_technique: "T1078.004"
        }]

      true ->
        []
    end
  end

  defp compute_statistics do
    functions = list_functions_internal(%{})

    total = length(functions)

    # Group by project
    by_project = functions
    |> Enum.group_by(& &1.project_id)
    |> Enum.map(fn {project, funcs} -> {project, length(funcs)} end)
    |> Map.new()

    # Group by region
    by_region = functions
    |> Enum.group_by(& &1.region)
    |> Enum.map(fn {region, funcs} -> {region, length(funcs)} end)
    |> Map.new()

    # Group by runtime
    by_runtime = functions
    |> Enum.group_by(& &1.runtime)
    |> Enum.map(fn {runtime, funcs} -> {runtime, length(funcs)} end)
    |> Map.new()

    # Generation distribution
    gen1 = Enum.count(functions, &(&1.generation == "1" || &1.generation == 1))
    gen2 = Enum.count(functions, &(&1.generation == "2" || &1.generation == 2))

    %{
      total_functions: total,
      by_project: by_project,
      by_region: by_region,
      by_runtime: by_runtime,
      generation_distribution: %{gen1: gen1, gen2: gen2},
      functions_with_findings: Enum.count(functions, fn f -> (f.findings || []) != [] end),
      average_security_score: if(total > 0,
        do: Enum.sum(Enum.map(functions, & &1.security_score || 100)) / total,
        else: 100
      )
    }
  end

  @doc """
  Analyze a Cloud Function for security issues.
  """
  def analyze_function_security(function) do
    findings = []
    score = 100

    # Check environment variables for secrets
    {env_findings, env_reduction} = check_environment_variables(function.environment_variables)
    findings = findings ++ env_findings
    score = score - env_reduction

    # Check ingress settings
    {ingress_findings, ingress_reduction} = check_ingress_settings(function.ingress_settings)
    findings = findings ++ ingress_findings
    score = score - ingress_reduction

    # Check VPC connector
    {vpc_findings, vpc_reduction} = check_vpc_connector(function.vpc_connector)
    findings = findings ++ vpc_findings
    score = score - vpc_reduction

    # Check service account
    {sa_findings, sa_reduction} = check_service_account(function.service_account_email)
    findings = findings ++ sa_findings
    score = score - sa_reduction

    # Check HTTPS trigger
    {trigger_findings, trigger_reduction} = check_https_trigger(function.https_trigger)
    findings = findings ++ trigger_findings
    score = score - trigger_reduction

    # Check KMS encryption
    {kms_findings, kms_reduction} = check_kms_encryption(function.kms_key_name)
    findings = findings ++ kms_findings
    score = score - kms_reduction

    %{function |
      security_score: max(0, score),
      findings: findings
    }
  end

  defp check_environment_variables(nil), do: {[], 0}
  defp check_environment_variables(env) when map_size(env) == 0, do: {[], 0}
  defp check_environment_variables(env) do
    secret_patterns = [
      ~r/^(API_KEY|API_SECRET|SECRET_KEY|PRIVATE_KEY)/i,
      ~r/^(DB_PASSWORD|DATABASE_URL)/i,
      ~r/^(GOOGLE_.*KEY|GCP_.*SECRET)/i,
      ~r/^(FIREBASE_.*KEY)/i,
      ~r/^(JWT_SECRET|AUTH_TOKEN)/i
    ]

    findings = env
    |> Enum.filter(fn {key, _value} ->
      Enum.any?(secret_patterns, &Regex.match?(&1, key))
    end)
    |> Enum.map(fn {key, _value} ->
      %{
        type: :secret_in_env,
        severity: "high",
        title: "Potential secret in environment variable",
        description: "Environment variable '#{key}' may contain sensitive data",
        remediation: "Use Secret Manager to store secrets"
      }
    end)

    {findings, min(length(findings) * 10, 40)}
  end

  defp check_ingress_settings("ALLOW_ALL") do
    {[%{
      type: :public_ingress,
      severity: "medium",
      title: "Public ingress allowed",
      description: "Function allows traffic from any source",
      remediation: "Set ingress to ALLOW_INTERNAL_ONLY or ALLOW_INTERNAL_AND_GCLB"
    }], 15}
  end
  defp check_ingress_settings(_), do: {[], 0}

  defp check_vpc_connector(nil) do
    {[%{
      type: :no_vpc_connector,
      severity: "low",
      title: "No VPC connector configured",
      description: "Function doesn't use VPC connector for network isolation",
      remediation: "Configure VPC connector for secure network access"
    }], 5}
  end
  defp check_vpc_connector(_), do: {[], 0}

  defp check_service_account(nil) do
    {[%{
      type: :default_service_account,
      severity: "medium",
      title: "Using default service account",
      description: "Function uses default compute service account",
      remediation: "Create dedicated service account with minimal permissions"
    }], 10}
  end
  defp check_service_account(email) do
    if String.contains?(email, "compute@developer.gserviceaccount.com") do
      {[%{
        type: :default_service_account,
        severity: "medium",
        title: "Using default compute service account",
        description: "Function uses default compute service account",
        remediation: "Create dedicated service account with minimal permissions"
      }], 10}
    else
      {[], 0}
    end
  end

  defp check_https_trigger(nil), do: {[], 0}
  defp check_https_trigger(trigger) do
    security_level = trigger["securityLevel"] || trigger[:securityLevel]

    if security_level == "SECURE_OPTIONAL" do
      {[%{
        type: :insecure_trigger,
        severity: "medium",
        title: "HTTPS not enforced",
        description: "Function allows HTTP traffic",
        remediation: "Set securityLevel to SECURE_ALWAYS"
      }], 10}
    else
      {[], 0}
    end
  end

  defp check_kms_encryption(nil) do
    {[%{
      type: :no_cmek,
      severity: "low",
      title: "No customer-managed encryption key",
      description: "Function uses Google-managed encryption",
      remediation: "Configure CMEK for additional security control"
    }], 5}
  end
  defp check_kms_encryption(_), do: {[], 0}
end
