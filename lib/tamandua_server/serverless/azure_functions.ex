defmodule TamanduaServer.Serverless.AzureFunctions do
  @moduledoc """
  Azure Functions Monitoring Module.

  Provides comprehensive monitoring and security analysis for Azure Functions:
  - Application Insights integration
  - Function execution logs
  - Binding analysis
  - Managed identity analysis
  - Network security assessment

  ## MITRE ATT&CK Coverage
  - T1204.003: User Execution - Malicious Image
  - T1059: Command and Scripting Interpreter
  - T1496: Resource Hijacking (crypto mining)
  - T1041: Exfiltration Over C2 Channel
  - T1078.004: Valid Accounts - Cloud Accounts

  ## Configuration

      config :tamandua_server, :azure,
        tenant_id: "...",
        client_id: "...",
        client_secret: "...",
        subscription_id: "..."

  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts

  @functions_table :azure_functions
  @executions_table :azure_function_executions
  @logs_table :azure_function_logs

  # Binding types and their risk levels
  @binding_risk_levels %{
    "httpTrigger" => :medium,  # Public exposure
    "blobTrigger" => :low,
    "queueTrigger" => :low,
    "timerTrigger" => :low,
    "cosmosDBTrigger" => :low,
    "eventHubTrigger" => :low,
    "serviceBusTrigger" => :low,
    "eventGridTrigger" => :medium,  # Can be external
    "webHookTrigger" => :high  # External webhook
  }

  # Types
  defmodule Function do
    @moduledoc "Azure Function metadata"
    defstruct [
      :id,
      :name,
      :function_app_id,
      :function_app_name,
      :resource_group,
      :subscription_id,
      :region,
      :runtime_version,
      :language,
      :state,  # running, stopped, disabled
      :url,
      :bindings,
      :app_settings,
      :managed_identity,
      :connection_strings,
      # Security analysis
      :security_score,
      :findings,
      :network_restrictions,
      :authentication,
      :cors_config,
      :last_execution,
      :invocation_count_24h,
      :error_count_24h,
      :avg_duration_ms,
      :last_sync
    ]
  end

  defmodule Execution do
    @moduledoc "Azure Function execution record"
    defstruct [
      :id,
      :operation_id,
      :function_name,
      :function_app_name,
      :timestamp,
      :duration_ms,
      :success,
      :result_code,
      :exception_type,
      :exception_message,
      :trigger_type,
      :client_ip,
      :user_agent,
      :request_id,
      :invocation_id,
      :custom_dimensions,
      # Security context
      :outbound_dependencies,
      :anomaly_score
    ]
  end

  defmodule LogEntry do
    @moduledoc "Azure Function log entry from Application Insights"
    defstruct [
      :timestamp,
      :operation_id,
      :function_name,
      :severity_level,
      :message,
      :custom_dimensions,
      :exception_details,
      :anomalies
    ]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Sync Azure Functions from subscription.
  """
  @spec sync_functions(String.t(), keyword()) :: {:ok, [Function.t()]} | {:error, term()}
  def sync_functions(subscription_id \\ nil, opts \\ []) do
    GenServer.call(__MODULE__, {:sync_functions, subscription_id, opts}, 60_000)
  end

  @doc """
  Get all monitored Azure Functions.
  """
  @spec list_functions(map()) :: [Function.t()]
  def list_functions(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_functions, filters})
  end

  @doc """
  Get a specific Azure Function.
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
  Record an Azure Function execution from Application Insights.
  """
  @spec record_execution(map()) :: :ok
  def record_execution(execution_data) do
    GenServer.cast(__MODULE__, {:record_execution, execution_data})
  end

  @doc """
  Ingest Application Insights logs.
  """
  @spec ingest_logs(String.t(), [map()]) :: :ok
  def ingest_logs(function_name, log_entries) do
    GenServer.cast(__MODULE__, {:ingest_logs, function_name, log_entries})
  end

  @doc """
  Analyze function bindings for security issues.
  """
  @spec analyze_bindings([map()]) :: [map()]
  def analyze_bindings(bindings) do
    GenServer.call(__MODULE__, {:analyze_bindings, bindings})
  end

  @doc """
  Get statistics across all Azure Functions.
  """
  @spec get_statistics() :: map()
  def get_statistics do
    GenServer.call(__MODULE__, :get_statistics)
  end

  @doc """
  Query Application Insights for function telemetry.
  """
  @spec query_app_insights(String.t(), String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def query_app_insights(app_insights_id, query, opts \\ []) do
    GenServer.call(__MODULE__, {:query_app_insights, app_insights_id, query, opts}, 30_000)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@functions_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@executions_table, [:ordered_set, :named_table, :public, read_concurrency: true])
    :ets.new(@logs_table, [:ordered_set, :named_table, :public, read_concurrency: true])

    # Schedule periodic sync
    if azure_configured?() do
      Process.send_after(self(), :sync_functions, :timer.minutes(5))
    end

    # Schedule cleanup
    :timer.send_interval(:timer.hours(1), :cleanup_old_data)

    Logger.info("Azure Functions Monitoring service started")
    {:ok, %{}}
  end

  @impl true
  def handle_call({:sync_functions, subscription_id, opts}, _from, state) do
    result = do_sync_functions(subscription_id, opts)
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
  def handle_call({:analyze_bindings, bindings}, _from, state) do
    findings = analyze_bindings_internal(bindings)
    {:reply, findings, state}
  end

  @impl true
  def handle_call(:get_statistics, _from, state) do
    stats = compute_statistics()
    {:reply, stats, state}
  end

  @impl true
  def handle_call({:query_app_insights, app_insights_id, query, opts}, _from, state) do
    result = do_query_app_insights(app_insights_id, query, opts)
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
    config = Application.get_env(:tamandua_server, :azure, [])
    subscription_id = config[:subscription_id]

    if subscription_id do
      Task.start(fn ->
        do_sync_functions(subscription_id, [])
      end)
    end

    Process.send_after(self(), :sync_functions, :timer.minutes(15))
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup_old_data, state) do
    # Remove data older than 7 days
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

  defp azure_configured? do
    config = Application.get_env(:tamandua_server, :azure, [])
    config[:tenant_id] && config[:client_id] && config[:client_secret]
  end

  defp do_sync_functions(subscription_id, _opts) do
    if azure_configured?() do
      Logger.info("Syncing Azure Functions from subscription #{subscription_id}")
      # In production, use Azure SDK (ex_microsoft_azure_management)
      {:ok, []}
    else
      Logger.warning("Azure credentials not configured for Functions sync")
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
    |> filter_by_app(filters[:function_app])
    |> filter_by_region(filters[:region])
    |> filter_by_runtime(filters[:runtime])
    |> filter_by_state(filters[:state])
  end

  defp filter_by_app(functions, nil), do: functions
  defp filter_by_app(functions, app_name) do
    Enum.filter(functions, &(&1.function_app_name == app_name))
  end

  defp filter_by_region(functions, nil), do: functions
  defp filter_by_region(functions, region) do
    Enum.filter(functions, &(&1.region == region))
  end

  defp filter_by_runtime(functions, nil), do: functions
  defp filter_by_runtime(functions, runtime) do
    Enum.filter(functions, &String.contains?(&1.runtime_version || "", runtime))
  end

  defp filter_by_state(functions, nil), do: functions
  defp filter_by_state(functions, state) do
    Enum.filter(functions, &(&1.state == state))
  end

  defp get_function_internal(function_id) do
    case :ets.lookup(@functions_table, function_id) do
      [{^function_id, func}] -> {:ok, func}
      [] ->
        # Search by name
        result = :ets.foldl(
          fn {_key, func}, acc ->
            if func.name == function_id, do: func, else: acc
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
        if exec.function_name == function_id || exec.function_app_name == function_id do
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

    # Store execution
    ts = DateTime.to_unix(execution.timestamp, :millisecond)
    key = {ts, execution.id}
    :ets.insert(@executions_table, {key, execution})

    # Check for security issues
    check_execution_security(execution)
  end

  defp build_execution(data) do
    %Execution{
      id: data["id"] || Ecto.UUID.generate(),
      operation_id: data["operation_id"],
      function_name: data["function_name"],
      function_app_name: data["function_app_name"],
      timestamp: parse_timestamp(data["timestamp"]),
      duration_ms: data["duration_ms"],
      success: data["success"],
      result_code: data["result_code"],
      exception_type: data["exception_type"],
      exception_message: data["exception_message"],
      trigger_type: data["trigger_type"],
      client_ip: data["client_ip"],
      user_agent: data["user_agent"],
      request_id: data["request_id"],
      invocation_id: data["invocation_id"],
      custom_dimensions: data["custom_dimensions"] || %{},
      outbound_dependencies: data["outbound_dependencies"] || [],
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

  defp check_execution_security(execution) do
    issues = []

    # Check outbound dependencies for suspicious targets
    issues = if has_suspicious_dependencies?(execution.outbound_dependencies) do
      [{:suspicious_outbound, execution.outbound_dependencies} | issues]
    else
      issues
    end

    # Check for error patterns indicating attacks
    if execution.exception_message do
      check_exception_patterns(execution)
    end

    if issues != [] do
      generate_security_alert(execution, issues)
    end
  end

  defp has_suspicious_dependencies?(nil), do: false
  defp has_suspicious_dependencies?([]), do: false
  defp has_suspicious_dependencies?(deps) do
    suspicious_patterns = [
      "ngrok.io",
      "requestbin",
      "burpcollaborator",
      "pipedream.net",
      "webhook.site"
    ]

    Enum.any?(deps, fn dep ->
      target = dep["target"] || dep[:target] || ""
      Enum.any?(suspicious_patterns, &String.contains?(target, &1))
    end)
  end

  defp check_exception_patterns(execution) do
    message = execution.exception_message || ""

    patterns = [
      {~r/UnauthorizedAccessException/i, "Privilege escalation attempt", "high"},
      {~r/SecurityException/i, "Security policy violation", "high"},
      {~r/System\.IO\.FileNotFoundException.*\/etc\//i, "Sensitive file access", "high"},
      {~r/TimeoutException/i, "Possible resource exhaustion", "medium"},
      {~r/OutOfMemoryException/i, "Memory exhaustion (possible cryptominer)", "high"},
      {~r/SocketException.*refused/i, "Suspicious network activity", "medium"}
    ]

    Enum.each(patterns, fn {pattern, description, severity} ->
      if Regex.match?(pattern, message) do
        Alerts.create_alert(%{
          title: "Azure Function Security Alert: #{description}",
          description: """
          Function: #{execution.function_name}
          App: #{execution.function_app_name}
          Invocation ID: #{execution.invocation_id}
          Exception: #{message}
          """,
          severity: severity,
          category: "serverless_security",
          source: "azure_functions_monitoring",
          mitre_techniques: ["T1059"],
          metadata: %{
            function_name: execution.function_name,
            function_app: execution.function_app_name,
            invocation_id: execution.invocation_id,
            pattern: description
          }
        })
      end
    end)
  end

  defp generate_security_alert(execution, issues) do
    Alerts.create_alert(%{
      title: "Azure Function Security Alert: #{execution.function_name}",
      description: """
      Function: #{execution.function_name}
      App: #{execution.function_app_name}
      Issues: #{inspect(issues)}
      """,
      severity: "high",
      category: "serverless_security",
      source: "azure_functions_monitoring",
      mitre_techniques: ["T1041"],
      metadata: %{
        function_name: execution.function_name,
        function_app: execution.function_app_name,
        invocation_id: execution.invocation_id,
        issues: issues
      }
    })
  end

  defp process_logs(function_name, log_entries) do
    Enum.each(log_entries, fn entry ->
      log = build_log_entry(function_name, entry)

      ts = DateTime.to_unix(log.timestamp, :millisecond)
      key = {ts, log.operation_id || Ecto.UUID.generate()}
      :ets.insert(@logs_table, {key, log})

      # Check for security patterns
      check_log_security(log)
    end)
  end

  defp build_log_entry(function_name, entry) do
    %LogEntry{
      timestamp: parse_timestamp(entry["timestamp"]),
      operation_id: entry["operation_id"],
      function_name: function_name,
      severity_level: entry["severity_level"],
      message: entry["message"],
      custom_dimensions: entry["custom_dimensions"] || %{},
      exception_details: entry["exception_details"],
      anomalies: []
    }
  end

  defp check_log_security(log) do
    message = log.message || ""

    security_patterns = [
      {~r/eval\s*\(/i, "Dynamic code evaluation", "T1059"},
      {~r/Process\.Start/i, "Process execution", "T1059"},
      {~r/PowerShell/i, "PowerShell execution", "T1059.001"},
      {~r/cmd\.exe/i, "Command shell execution", "T1059.003"},
      {~r/WebClient.*Download/i, "File download", "T1105"},
      {~r/Invoke-WebRequest/i, "HTTP request", "T1071"},
      {~r/ConvertTo-SecureString/i, "Credential handling", "T1552"},
      {~r/Get-AzKeyVaultSecret/i, "Key Vault access", "T1552"},
      {~r/crypto|mining|xmr|monero/i, "Cryptocurrency activity", "T1496"}
    ]

    Enum.each(security_patterns, fn {pattern, description, technique} ->
      if Regex.match?(pattern, message) do
        Logger.warning("Azure Function log security pattern: #{description}")

        Alerts.create_alert(%{
          title: "Azure Function Log Alert: #{description}",
          description: """
          Function: #{log.function_name}
          Operation ID: #{log.operation_id}
          Message: #{String.slice(message, 0, 500)}
          """,
          severity: "high",
          category: "serverless_security",
          source: "azure_functions_log_analysis",
          mitre_techniques: [technique],
          metadata: %{
            function_name: log.function_name,
            operation_id: log.operation_id,
            pattern: description
          }
        })
      end
    end)
  end

  defp analyze_bindings_internal(bindings) when is_list(bindings) do
    bindings
    |> Enum.map(&analyze_single_binding/1)
    |> Enum.reject(&is_nil/1)
  end
  defp analyze_bindings_internal(_), do: []

  defp analyze_single_binding(binding) do
    type = binding["type"] || binding[:type]
    direction = binding["direction"] || binding[:direction]

    risk_level = Map.get(@binding_risk_levels, type, :unknown)

    findings = []

    # Check for HTTP trigger without auth
    findings = if type == "httpTrigger" do
      auth_level = binding["authLevel"] || binding[:authLevel] || "anonymous"
      if auth_level == "anonymous" do
        [%{
          type: :anonymous_http,
          severity: "medium",
          title: "Anonymous HTTP trigger",
          description: "HTTP trigger allows anonymous access",
          remediation: "Set authLevel to 'function' or 'admin'"
        } | findings]
      else
        findings
      end
    else
      findings
    end

    # Check for blob trigger with sensitive paths
    findings = if type == "blobTrigger" do
      path = binding["path"] || binding[:path] || ""
      if String.contains?(path, "secrets") || String.contains?(path, "keys") do
        [%{
          type: :sensitive_blob_path,
          severity: "medium",
          title: "Blob trigger on sensitive path",
          description: "Blob trigger monitors potentially sensitive path: #{path}",
          remediation: "Review if this path should be accessible"
        } | findings]
      else
        findings
      end
    else
      findings
    end

    # Check for output bindings with sensitive data
    findings = if direction == "out" && type in ["blob", "cosmosDB", "table"] do
      connection = binding["connection"] || binding[:connection]
      if connection && String.contains?(String.downcase(connection || ""), "secret") do
        [%{
          type: :output_with_secrets,
          severity: "low",
          title: "Output binding references secrets",
          description: "Output binding connection may contain sensitive data",
          remediation: "Ensure connection strings are stored in Key Vault"
        } | findings]
      else
        findings
      end
    else
      findings
    end

    if findings != [] do
      %{
        binding_type: type,
        direction: direction,
        risk_level: risk_level,
        findings: findings
      }
    else
      nil
    end
  end

  defp do_query_app_insights(app_insights_id, query, opts) do
    if azure_configured?() do
      timespan = Keyword.get(opts, :timespan, "PT24H")

      Logger.info("Querying Application Insights #{app_insights_id}: #{String.slice(query, 0, 100)}")

      # Build the query request structure that would be sent to the Azure Monitor Query API
      # POST https://api.applicationinsights.io/v1/apps/{appId}/query
      _request = %{
        app_insights_id: app_insights_id,
        query: query,
        timespan: timespan,
        applications: Keyword.get(opts, :applications, [])
      }

      # In production, this would use the Azure SDK (e.g., ex_microsoft_azure_monitor or HTTP client)
      # to execute the KQL query against Application Insights.
      # For now, return an empty result set with proper structure.
      {:ok, []}
    else
      Logger.warning("Azure credentials not configured for Application Insights queries")
      {:error, :not_configured}
    end
  end

  @doc """
  Detect anomalous function executions by comparing against historical baselines
  stored in the ETS executions table.

  Analyzes:
  - Invocation frequency spikes or drops
  - Execution duration anomalies
  - Error rate changes
  - Unusual outbound dependency patterns

  Returns a list of anomaly maps with severity scores.
  """
  @spec detect_function_anomalies(Function.t()) :: [map()]
  def detect_function_anomalies(%Function{} = function) do
    function_id = function.id || function.name
    executions = get_executions_internal(function_id, limit: 1000)

    if length(executions) < 10 do
      # Insufficient data for anomaly detection
      []
    else
      anomalies = []

      # Split into recent (last hour) and historical baseline
      one_hour_ago = DateTime.add(DateTime.utc_now(), -3600, :second)
      {recent, historical} = Enum.split_with(executions, fn exec ->
        DateTime.compare(exec.timestamp, one_hour_ago) == :gt
      end)

      # Frequency anomalies
      anomalies = anomalies ++ detect_azure_frequency_anomalies(function_id, recent, historical)

      # Duration anomalies
      anomalies = anomalies ++ detect_azure_duration_anomalies(function_id, recent, historical)

      # Error rate anomalies
      anomalies = anomalies ++ detect_azure_error_anomalies(function_id, recent, historical)

      # Outbound dependency anomalies
      anomalies = anomalies ++ detect_azure_dependency_anomalies(function_id, recent, historical)

      anomalies
    end
  end

  defp detect_azure_frequency_anomalies(function_id, recent, historical) do
    if length(historical) < 5 do
      []
    else
      historical_hours = case {List.last(historical), List.first(historical)} do
        {%{timestamp: oldest}, %{timestamp: newest}} ->
          max(DateTime.diff(newest, oldest, :hour), 1)
        _ -> 1
      end

      historical_rate = length(historical) / historical_hours
      recent_count = length(recent)

      cond do
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

  defp detect_azure_duration_anomalies(function_id, recent, historical) do
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

  defp detect_azure_error_anomalies(function_id, recent, historical) do
    if length(historical) < 10 or length(recent) == 0 do
      []
    else
      hist_error_count = Enum.count(historical, &(&1.success == false))
      hist_error_rate = hist_error_count / length(historical)

      recent_error_count = Enum.count(recent, &(&1.success == false))
      recent_error_rate = recent_error_count / max(length(recent), 1)

      cond do
        recent_error_rate > 0.5 and recent_error_rate > hist_error_rate * 3 ->
          [%{
            type: :error_rate_spike,
            function_id: function_id,
            severity: "critical",
            title: "Critical error rate spike",
            description: "Error rate #{Float.round(recent_error_rate * 100, 1)}% vs historical #{Float.round(hist_error_rate * 100, 1)}%. #{recent_error_count} failures in last hour.",
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
            description: "Error rate #{Float.round(recent_error_rate * 100, 1)}% vs historical #{Float.round(hist_error_rate * 100, 1)}%. #{recent_error_count} failures in last hour.",
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

  defp detect_azure_dependency_anomalies(function_id, recent, historical) do
    # Build set of known outbound dependency targets from historical executions
    historical_targets = historical
    |> Enum.flat_map(fn exec -> exec.outbound_dependencies || [] end)
    |> Enum.map(fn dep -> dep["target"] || dep[:target] end)
    |> Enum.reject(&is_nil/1)
    |> MapSet.new()

    # Check recent executions for new/unknown dependency targets
    recent_targets = recent
    |> Enum.flat_map(fn exec -> exec.outbound_dependencies || [] end)
    |> Enum.map(fn dep -> dep["target"] || dep[:target] end)
    |> Enum.reject(&is_nil/1)
    |> MapSet.new()

    new_targets = MapSet.difference(recent_targets, historical_targets)

    if MapSet.size(historical_targets) > 0 and MapSet.size(new_targets) > 0 do
      targets_list = MapSet.to_list(new_targets) |> Enum.join(", ")
      [%{
        type: :new_outbound_dependency,
        function_id: function_id,
        severity: "high",
        title: "New outbound dependency targets detected",
        description: "Function contacted previously unseen targets: #{targets_list}. This may indicate data exfiltration or C2 communication.",
        expected_value: "Known targets: #{MapSet.size(historical_targets)}",
        actual_value: targets_list,
        z_score: 3.0,
        mitre_technique: "T1041",
        detected_at: DateTime.utc_now()
      }]
    else
      []
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
  Analyze function bindings for security issues.

  Performs deep security analysis of Azure Function bindings:
  - Checks webhook triggers for authentication requirements
  - Checks storage bindings for SAS token exposure
  - Checks Event Hub bindings for access policy scope
  - Checks Cosmos DB bindings for connection string exposure
  - Checks Service Bus bindings for shared access policies

  Returns a list of security findings.
  """
  @spec check_binding_security([map()]) :: [map()]
  def check_binding_security(bindings) when is_list(bindings) do
    Enum.flat_map(bindings, &analyze_binding_security/1)
  end
  def check_binding_security(_), do: []

  defp analyze_binding_security(binding) do
    type = binding["type"] || binding[:type]
    direction = binding["direction"] || binding[:direction]

    findings = []

    # Check webhook triggers for auth requirements
    findings = findings ++ check_webhook_auth(binding, type)

    # Check storage bindings for SAS token exposure
    findings = findings ++ check_storage_sas_exposure(binding, type, direction)

    # Check Event Hub bindings for access policy scope
    findings = findings ++ check_event_hub_policy(binding, type)

    # Check Cosmos DB bindings for connection string exposure
    findings = findings ++ check_cosmosdb_security(binding, type)

    # Check Service Bus bindings for shared access policies
    findings = findings ++ check_service_bus_security(binding, type)

    # Check HTTP trigger authentication level
    findings = findings ++ check_http_trigger_auth(binding, type)

    # Check for plaintext connection strings in binding config
    findings = findings ++ check_binding_connection_strings(binding, type)

    findings
  end

  defp check_webhook_auth(binding, "webHookTrigger") do
    webhook_type = binding["webHookType"] || binding[:webHookType]

    cond do
      webhook_type == nil or webhook_type == "" ->
        [%{
          type: :webhook_no_type,
          severity: "high",
          binding_type: "webHookTrigger",
          title: "Webhook trigger without type validation",
          description: "Webhook trigger has no webHookType configured. This means no provider-specific request validation is performed.",
          remediation: "Set webHookType to the appropriate provider (e.g., 'github', 'slack') for signature validation."
        }]

      true ->
        []
    end
  end
  defp check_webhook_auth(_, _), do: []

  defp check_storage_sas_exposure(binding, type, _direction)
       when type in ["blob", "blobTrigger", "table", "queue", "queueTrigger"] do
    connection = binding["connection"] || binding[:connection] || ""
    connection_value = binding["connectionStringValue"] || binding[:connectionStringValue] || ""

    findings = []

    # Check if connection string contains a SAS token inline
    findings = if String.contains?(connection_value, "SharedAccessSignature=") or
                  String.contains?(connection_value, "sig=") do
      [%{
        type: :sas_token_in_binding,
        severity: "high",
        binding_type: type,
        title: "SAS token embedded in binding configuration",
        description: "Storage binding for '#{type}' contains an inline SAS token. SAS tokens in configuration can be leaked through source control or deployment logs.",
        remediation: "Store the connection string in Azure Key Vault and use @Microsoft.KeyVault() reference in app settings."
      } | findings]
    else
      findings
    end

    # Check if connection references a full connection string with AccountKey
    findings = if String.contains?(connection_value, "AccountKey=") do
      [%{
        type: :storage_account_key_in_binding,
        severity: "high",
        binding_type: type,
        title: "Storage account key embedded in binding",
        description: "Storage binding for '#{type}' contains an inline account key. Account keys provide full access to the storage account.",
        remediation: "Use managed identity for storage access or store connection string in Key Vault."
      } | findings]
    else
      findings
    end

    # Check for overly permissive SAS scope
    findings = if String.contains?(connection, "sas") or String.contains?(String.downcase(connection), "sastoken") do
      [%{
        type: :sas_reference_in_connection,
        severity: "medium",
        binding_type: type,
        title: "Binding references SAS token setting",
        description: "Storage binding for '#{type}' references a SAS token app setting '#{connection}'. Ensure the SAS token has minimal permissions and a short expiry.",
        remediation: "Prefer managed identity over SAS tokens. If SAS is required, use minimal scope (read-only, single container, short TTL)."
      } | findings]
    else
      findings
    end

    findings
  end
  defp check_storage_sas_exposure(_, _, _), do: []

  defp check_event_hub_policy(binding, type) when type in ["eventHubTrigger", "eventHub"] do
    connection = binding["connection"] || binding[:connection] || ""
    connection_value = binding["connectionStringValue"] || binding[:connectionStringValue] || ""

    findings = []

    # Check for Manage policy (overly permissive)
    findings = if String.contains?(connection_value, "EntityPath=") and
                  String.contains?(connection_value, "SharedAccessKey=") do
      [%{
        type: :event_hub_inline_key,
        severity: "high",
        binding_type: type,
        title: "Event Hub shared access key in binding",
        description: "Event Hub binding contains an inline connection string with shared access key.",
        remediation: "Store the Event Hub connection string in Key Vault or use managed identity."
      } | findings]
    else
      findings
    end

    # Check if the policy name suggests Manage-level access
    findings = if String.contains?(String.downcase(connection), "manage") or
                  String.contains?(String.downcase(connection_value), "manage") do
      [%{
        type: :event_hub_manage_policy,
        severity: "medium",
        binding_type: type,
        title: "Event Hub binding uses Manage policy",
        description: "Event Hub binding appears to use a Manage access policy. Functions typically only need Send or Listen access.",
        remediation: "Create a dedicated shared access policy with only Send or Listen permission, not Manage."
      } | findings]
    else
      findings
    end

    findings
  end
  defp check_event_hub_policy(_, _), do: []

  defp check_cosmosdb_security(binding, type) when type in ["cosmosDB", "cosmosDBTrigger"] do
    connection_value = binding["connectionStringValue"] || binding[:connectionStringValue] || ""
    _preferred_locations = binding["preferredLocations"] || binding[:preferredLocations]

    findings = []

    # Check for inline master key
    findings = if String.contains?(connection_value, "AccountKey=") do
      [%{
        type: :cosmosdb_master_key_in_binding,
        severity: "high",
        binding_type: type,
        title: "Cosmos DB master key in binding configuration",
        description: "Cosmos DB binding contains an inline master key. Master keys grant full read/write access to the entire database account.",
        remediation: "Use managed identity with RBAC roles, or store the connection string in Key Vault."
      } | findings]
    else
      findings
    end

    # Check if database/collection permissions are scoped
    database_name = binding["databaseName"] || binding[:databaseName]
    collection_name = binding["collectionName"] || binding[:collectionName]

    findings = if is_nil(database_name) or is_nil(collection_name) do
      [%{
        type: :cosmosdb_unscoped,
        severity: "medium",
        binding_type: type,
        title: "Cosmos DB binding missing database/collection scope",
        description: "Cosmos DB binding does not specify both database and collection, which may allow broader access than intended.",
        remediation: "Always specify both databaseName and collectionName in Cosmos DB bindings."
      } | findings]
    else
      findings
    end

    findings
  end
  defp check_cosmosdb_security(_, _), do: []

  defp check_service_bus_security(binding, type) when type in ["serviceBusTrigger", "serviceBus"] do
    connection_value = binding["connectionStringValue"] || binding[:connectionStringValue] || ""

    findings = []

    # Check for inline shared access key
    findings = if String.contains?(connection_value, "SharedAccessKey=") do
      [%{
        type: :service_bus_inline_key,
        severity: "high",
        binding_type: type,
        title: "Service Bus shared access key in binding",
        description: "Service Bus binding contains an inline connection string with shared access key.",
        remediation: "Store the Service Bus connection string in Key Vault or use managed identity."
      } | findings]
    else
      findings
    end

    # Check if policy has Manage rights
    findings = if String.contains?(String.downcase(connection_value), "manage") do
      [%{
        type: :service_bus_manage_policy,
        severity: "medium",
        binding_type: type,
        title: "Service Bus binding uses Manage policy",
        description: "Service Bus binding uses a shared access policy with Manage rights. Functions typically only need Send or Listen.",
        remediation: "Create a dedicated policy with minimal permissions (Send for output, Listen for trigger)."
      } | findings]
    else
      findings
    end

    findings
  end
  defp check_service_bus_security(_, _), do: []

  defp check_http_trigger_auth(binding, "httpTrigger") do
    auth_level = binding["authLevel"] || binding[:authLevel] || "anonymous"

    case auth_level do
      "anonymous" ->
        [%{
          type: :anonymous_http_trigger,
          severity: "medium",
          binding_type: "httpTrigger",
          title: "HTTP trigger allows anonymous access",
          description: "HTTP trigger is configured with 'anonymous' authentication level. Any client can invoke this function without credentials.",
          remediation: "Set authLevel to 'function' (requires function key) or 'admin' (requires master key). For Azure AD authentication, use EasyAuth."
        }]

      _ ->
        []
    end
  end
  defp check_http_trigger_auth(_, _), do: []

  defp check_binding_connection_strings(binding, type) do
    # Check all string values in the binding for credential-like content
    credential_patterns = [
      {~r/password\s*=/i, "password"},
      {~r/pwd\s*=/i, "password (pwd)"},
      {~r/AccountKey=/i, "account key"},
      {~r/SharedAccessKey=/i, "shared access key"},
      {~r/AccessKey=/i, "access key"},
      {~r/Secret=/i, "secret"}
    ]

    binding
    |> Enum.flat_map(fn {key, value} ->
      if is_binary(value) do
        Enum.flat_map(credential_patterns, fn {pattern, credential_type} ->
          if Regex.match?(pattern, value) and key not in ["connection", "connectionStringValue"] do
            # Only flag if not already covered by specific binding checks above
            [%{
              type: :credential_in_binding_field,
              severity: "medium",
              binding_type: type,
              title: "Possible #{credential_type} in binding field '#{key}'",
              description: "Binding field '#{key}' for #{type} appears to contain a #{credential_type}.",
              remediation: "Store credentials in Azure Key Vault and reference via @Microsoft.KeyVault() syntax."
            }]
          else
            []
          end
        end)
      else
        []
      end
    end)
  end

  defp compute_statistics do
    functions = list_functions_internal(%{})

    total_functions = length(functions)

    # Group by function app
    by_app = Enum.group_by(functions, & &1.function_app_name)

    # Group by region
    by_region = functions
    |> Enum.group_by(& &1.region)
    |> Enum.map(fn {region, funcs} -> {region, length(funcs)} end)
    |> Map.new()

    # Security distribution
    findings_count = functions
    |> Enum.map(fn f -> length(f.findings || []) end)
    |> Enum.sum()

    %{
      total_functions: total_functions,
      total_function_apps: map_size(by_app),
      by_region: by_region,
      total_findings: findings_count,
      functions_with_findings: Enum.count(functions, fn f -> (f.findings || []) != [] end),
      average_security_score: if(total_functions > 0,
        do: Enum.sum(Enum.map(functions, & &1.security_score || 100)) / total_functions,
        else: 100
      )
    }
  end

  @doc """
  Analyze an Azure Function for security issues.
  """
  def analyze_function_security(function) do
    findings = []
    score = 100

    # Check bindings
    binding_analysis = analyze_bindings_internal(function.bindings || [])
    binding_findings = Enum.flat_map(binding_analysis, & &1.findings)
    findings = findings ++ binding_findings
    score = score - length(binding_findings) * 5

    # Check app settings for secrets
    {settings_findings, settings_reduction} = check_app_settings(function.app_settings)
    findings = findings ++ settings_findings
    score = score - settings_reduction

    # Check network restrictions
    {network_findings, network_reduction} = check_network_restrictions(function.network_restrictions)
    findings = findings ++ network_findings
    score = score - network_reduction

    # Check authentication
    {auth_findings, auth_reduction} = check_authentication(function.authentication)
    findings = findings ++ auth_findings
    score = score - auth_reduction

    # Check managed identity
    {identity_findings, identity_reduction} = check_managed_identity(function.managed_identity)
    findings = findings ++ identity_findings
    score = score - identity_reduction

    %{function |
      security_score: max(0, score),
      findings: findings
    }
  end

  defp check_app_settings(nil), do: {[], 0}
  defp check_app_settings(settings) when map_size(settings) == 0, do: {[], 0}
  defp check_app_settings(settings) do
    secret_patterns = [
      ~r/^(API_KEY|API_SECRET|SECRET_KEY|PRIVATE_KEY)/i,
      ~r/^(DB_PASSWORD|DATABASE_URL|MONGODB_URI)/i,
      ~r/^(AZURE_.*_KEY|AZURE_.*_SECRET)/i,
      ~r/^(STORAGE_.*KEY|STORAGE_.*CONNECTION)/i,
      ~r/^(JWT_SECRET|AUTH_TOKEN|BEARER_TOKEN)/i
    ]

    findings = settings
    |> Enum.filter(fn {key, _value} ->
      Enum.any?(secret_patterns, &Regex.match?(&1, key))
    end)
    |> Enum.map(fn {key, _value} ->
      %{
        type: :secret_in_settings,
        severity: "high",
        title: "Potential secret in app settings",
        description: "App setting '#{key}' may contain sensitive data",
        remediation: "Store secrets in Azure Key Vault and reference using @Microsoft.KeyVault"
      }
    end)

    {findings, min(length(findings) * 10, 40)}
  end

  defp check_network_restrictions(nil) do
    {[%{
      type: :no_network_restrictions,
      severity: "medium",
      title: "No network restrictions",
      description: "Function app has no IP restrictions configured",
      remediation: "Configure IP restrictions or VNet integration"
    }], 15}
  end
  defp check_network_restrictions(%{"ipSecurityRestrictions" => []}), do: check_network_restrictions(nil)
  defp check_network_restrictions(_), do: {[], 0}

  defp check_authentication(nil) do
    {[%{
      type: :no_authentication,
      severity: "medium",
      title: "No authentication configured",
      description: "Function app has no authentication/authorization",
      remediation: "Enable Azure AD authentication or API key validation"
    }], 15}
  end
  defp check_authentication(%{"enabled" => false}), do: check_authentication(nil)
  defp check_authentication(_), do: {[], 0}

  defp check_managed_identity(nil) do
    {[%{
      type: :no_managed_identity,
      severity: "low",
      title: "No managed identity",
      description: "Function app doesn't use managed identity",
      remediation: "Enable system-assigned or user-assigned managed identity"
    }], 5}
  end
  defp check_managed_identity(_), do: {[], 0}
end
