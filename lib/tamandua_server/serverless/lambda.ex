defmodule TamanduaServer.Serverless.Lambda do
  @moduledoc """
  AWS Lambda Monitoring Module.

  Provides comprehensive monitoring and security analysis for AWS Lambda functions:
  - CloudWatch Logs ingestion
  - Lambda execution events
  - Cold start detection
  - Error/timeout monitoring
  - IAM role analysis
  - Environment variable inspection (detect secrets)

  ## MITRE ATT&CK Coverage
  - T1204.003: User Execution - Malicious Image
  - T1059: Command and Scripting Interpreter
  - T1496: Resource Hijacking (crypto mining)
  - T1041: Exfiltration Over C2 Channel
  - T1567: Exfiltration Over Web Service

  ## Configuration

      config :tamandua_server, :aws,
        access_key_id: "...",
        secret_access_key: "...",
        region: "us-east-1"

  """

  use GenServer
  require Logger

  alias TamanduaServer.Alerts

  @functions_table :lambda_functions
  @executions_table :lambda_executions
  @logs_table :lambda_logs
  @metrics_table :lambda_metrics

  # Secret patterns for environment variable scanning
  defp secret_patterns do
    [
    ~r/^AWS_SECRET/i,
    ~r/^AWS_ACCESS/i,
    ~r/^DB_PASSWORD/i,
    ~r/^DATABASE_URL/i,
    ~r/^MONGODB_URI/i,
    ~r/^REDIS_URL/i,
    ~r/^API_KEY/i,
    ~r/^API_SECRET/i,
    ~r/^PRIVATE_KEY/i,
    ~r/^SECRET_KEY/i,
    ~r/^AUTH_TOKEN/i,
    ~r/^BEARER_TOKEN/i,
    ~r/^JWT_SECRET/i,
    ~r/^ENCRYPTION_KEY/i,
    ~r/^STRIPE_/i,
    ~r/^TWILIO_/i,
    ~r/^SENDGRID_/i,
    ~r/^GITHUB_TOKEN/i,
    ~r/^GITLAB_TOKEN/i,
    ~r/^SLACK_TOKEN/i,
    ~r/^WEBHOOK_SECRET/i
    ]
  end

  # Dangerous IAM permissions
  @dangerous_permissions [
    "iam:*",
    "iam:CreateUser",
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "sts:AssumeRole",
    "lambda:*",
    "lambda:UpdateFunctionCode",
    "lambda:InvokeFunction",
    "s3:*",
    "s3:GetObject",
    "s3:PutObject",
    "ec2:*",
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter",
    "kms:Decrypt"
  ]

  # Suspicious function patterns
  defp suspicious_function_patterns do
    [
    ~r/crypto/i,
    ~r/miner/i,
    ~r/xmr/i,
    ~r/monero/i,
    ~r/bitcoin/i,
    ~r/coinhive/i,
    ~r/shell/i,
    ~r/reverse.*shell/i,
    ~r/c2/i,
    ~r/callback/i,
    ~r/exfil/i
    ]
  end

  # Types
  defmodule Function do
    @moduledoc "Lambda function metadata"
    defstruct [
      :function_arn,
      :function_name,
      :runtime,
      :handler,
      :role,
      :code_size,
      :description,
      :timeout,
      :memory_size,
      :last_modified,
      :code_sha256,
      :version,
      :vpc_config,
      :environment,
      :layers,
      :architectures,
      :ephemeral_storage,
      # Security analysis
      :security_score,
      :findings,
      :iam_analysis,
      :secret_exposure,
      :network_exposure,
      :event_sources,
      :last_invoked,
      :invocation_count_24h,
      :error_count_24h,
      :cold_start_count_24h,
      :avg_duration_ms,
      :last_sync
    ]
  end

  defmodule Execution do
    @moduledoc "Lambda execution record"
    defstruct [
      :request_id,
      :function_arn,
      :function_name,
      :version,
      :timestamp,
      :duration_ms,
      :billed_duration_ms,
      :memory_used_mb,
      :memory_size_mb,
      :init_duration_ms,  # Cold start duration
      :status,  # success, error, timeout
      :error_type,
      :error_message,
      :log_stream,
      :x_ray_trace_id,
      # Security context
      :source_ip,
      :user_agent,
      :trigger_source,  # API Gateway, S3, SNS, etc.
      :outbound_connections,
      :file_operations,
      :process_spawns,
      :anomaly_score
    ]
  end

  defmodule LogEntry do
    @moduledoc "Lambda log entry"
    defstruct [
      :timestamp,
      :request_id,
      :function_name,
      :log_level,
      :message,
      :parsed_data,
      :anomalies
    ]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Sync Lambda functions from AWS account.
  """
  @spec sync_functions(String.t(), keyword()) :: {:ok, [Function.t()]} | {:error, term()}
  def sync_functions(region \\ "us-east-1", opts \\ []) do
    GenServer.call(__MODULE__, {:sync_functions, region, opts}, 60_000)
  end

  @doc """
  Get all monitored Lambda functions.
  """
  @spec list_functions(map()) :: [Function.t()]
  def list_functions(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_functions, filters})
  end

  @doc """
  Get a specific Lambda function by ARN or name.
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
  Record a Lambda execution event.
  """
  @spec record_execution(map()) :: :ok
  def record_execution(execution_data) do
    GenServer.cast(__MODULE__, {:record_execution, execution_data})
  end

  @doc """
  Ingest CloudWatch logs for a function.
  """
  @spec ingest_logs(String.t(), [map()]) :: :ok
  def ingest_logs(function_name, log_events) do
    GenServer.cast(__MODULE__, {:ingest_logs, function_name, log_events})
  end

  @doc """
  Get function metrics summary.
  """
  @spec get_metrics(String.t(), keyword()) :: map()
  def get_metrics(function_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_metrics, function_id, opts})
  end

  @doc """
  Get security findings for a function.
  """
  @spec get_security_findings(String.t()) :: [map()]
  def get_security_findings(function_id) do
    GenServer.call(__MODULE__, {:get_security_findings, function_id})
  end

  @doc """
  Analyze IAM role for overprivileged permissions.
  """
  @spec analyze_iam_role(String.t()) :: {:ok, map()} | {:error, term()}
  def analyze_iam_role(role_arn) do
    GenServer.call(__MODULE__, {:analyze_iam_role, role_arn}, 30_000)
  end

  @doc """
  Get statistics across all Lambda functions.
  """
  @spec get_statistics() :: map()
  def get_statistics do
    GenServer.call(__MODULE__, :get_statistics)
  end

  @doc """
  Detect cold starts from execution data.
  """
  @spec detect_cold_starts(String.t(), DateTime.t(), DateTime.t()) :: [Execution.t()]
  def detect_cold_starts(function_id, start_time, end_time) do
    GenServer.call(__MODULE__, {:detect_cold_starts, function_id, start_time, end_time})
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@functions_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@executions_table, [:ordered_set, :named_table, :public, read_concurrency: true])
    :ets.new(@logs_table, [:ordered_set, :named_table, :public, read_concurrency: true])
    :ets.new(@metrics_table, [:set, :named_table, :public, read_concurrency: true])

    # Schedule periodic sync
    if aws_configured?() do
      Process.send_after(self(), :sync_functions, :timer.minutes(5))
    end

    # Schedule cleanup
    :timer.send_interval(:timer.hours(1), :cleanup_old_data)

    Logger.info("AWS Lambda Monitoring service started")
    {:ok, %{sync_in_progress: false}}
  end

  @impl true
  def handle_call({:sync_functions, region, opts}, _from, state) do
    result = do_sync_functions(region, opts)
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
  def handle_call({:get_metrics, function_id, opts}, _from, state) do
    metrics = calculate_metrics(function_id, opts)
    {:reply, metrics, state}
  end

  @impl true
  def handle_call({:get_security_findings, function_id}, _from, state) do
    findings = get_security_findings_internal(function_id)
    {:reply, findings, state}
  end

  @impl true
  def handle_call({:analyze_iam_role, role_arn}, _from, state) do
    result = do_analyze_iam_role(role_arn)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_statistics, _from, state) do
    stats = compute_statistics()
    {:reply, stats, state}
  end

  @impl true
  def handle_call({:detect_cold_starts, function_id, start_time, end_time}, _from, state) do
    cold_starts = detect_cold_starts_internal(function_id, start_time, end_time)
    {:reply, cold_starts, state}
  end

  @impl true
  def handle_cast({:record_execution, execution_data}, state) do
    process_execution(execution_data)
    {:noreply, state}
  end

  @impl true
  def handle_cast({:ingest_logs, function_name, log_events}, state) do
    process_logs(function_name, log_events)
    {:noreply, state}
  end

  @impl true
  def handle_info(:sync_functions, state) do
    # Sync from all configured regions
    regions = get_configured_regions()

    Enum.each(regions, fn region ->
      Task.start(fn ->
        do_sync_functions(region, [])
      end)
    end)

    # Schedule next sync
    Process.send_after(self(), :sync_functions, :timer.minutes(15))
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup_old_data, state) do
    # Remove executions older than 7 days
    cutoff = DateTime.add(DateTime.utc_now(), -7 * 24 * 60 * 60, :second)
    cutoff_ts = DateTime.to_unix(cutoff, :millisecond)

    # Clean executions table
    :ets.select_delete(@executions_table, [
      {{:"$1", :"$2"}, [{:<, :"$1", cutoff_ts}], [true]}
    ])

    # Clean logs table
    :ets.select_delete(@logs_table, [
      {{:"$1", :"$2"}, [{:<, :"$1", cutoff_ts}], [true]}
    ])

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp aws_configured? do
    config = Application.get_env(:tamandua_server, :aws, [])
    config[:access_key_id] && config[:secret_access_key]
  end

  defp get_configured_regions do
    config = Application.get_env(:tamandua_server, :aws, [])
    config[:regions] || ["us-east-1"]
  end

  defp do_sync_functions(region, _opts) do
    if aws_configured?() do
      Logger.info("Syncing Lambda functions from region #{region}")

      case get_aws_credentials() do
        {:error, reason} ->
          Logger.error("Failed to get AWS credentials: #{inspect(reason)}")
          {:error, reason}

        {:ok, creds} ->
          do_sync_with_pagination(region, creds, nil, [])
      end
    else
      Logger.warning("AWS credentials not configured for Lambda sync")
      {:error, :not_configured}
    end
  end

  defp do_sync_with_pagination(region, creds, marker, acc) do
    case fetch_lambda_page(region, creds, marker) do
      {:ok, functions, next_marker} ->
        # Process and store functions
        synced_functions = Enum.map(functions, fn func_data ->
          process_and_store_function(func_data, region)
        end)

        updated_acc = acc ++ synced_functions

        # Handle pagination
        if next_marker do
          do_sync_with_pagination(region, creds, next_marker, updated_acc)
        else
          Logger.info("Successfully synced #{length(updated_acc)} Lambda functions from #{region}")
          {:ok, updated_acc}
        end

      {:error, reason} ->
        Logger.error("Failed to fetch Lambda functions from #{region}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp fetch_lambda_page(region, creds, marker) do
    url = if marker do
      "https://lambda.#{region}.amazonaws.com/2015-03-31/functions?Marker=#{URI.encode(marker)}"
    else
      "https://lambda.#{region}.amazonaws.com/2015-03-31/functions"
    end

    host = "lambda.#{region}.amazonaws.com"
    headers = [{"Host", host}]

    # Use AWS SigV4 signing
    signed_headers = sign_aws_request("GET", url, headers, "", creds, "lambda", region)

    case make_http_request(:get, url, signed_headers, "") do
      {:ok, %{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, %{"Functions" => functions} = response} ->
            next_marker = response["NextMarker"]
            {:ok, functions, next_marker}

          {:ok, _other} ->
            {:ok, [], nil}

          {:error, reason} ->
            {:error, {:json_decode_error, reason}}
        end

      {:ok, %{status: status, body: body}} ->
        Logger.error("AWS Lambda API returned status #{status}: #{body}")
        {:error, {:api_error, status, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  defp process_and_store_function(func_data, _region) do
    now = DateTime.utc_now()

    function = %Function{
      function_arn: func_data["FunctionArn"],
      function_name: func_data["FunctionName"],
      runtime: func_data["Runtime"],
      handler: func_data["Handler"],
      role: func_data["Role"],
      code_size: func_data["CodeSize"],
      description: func_data["Description"],
      timeout: func_data["Timeout"],
      memory_size: func_data["MemorySize"],
      last_modified: parse_lambda_timestamp(func_data["LastModified"]),
      code_sha256: func_data["CodeSha256"],
      version: func_data["Version"],
      vpc_config: func_data["VpcConfig"],
      environment: extract_environment_variables(func_data["Environment"]),
      layers: func_data["Layers"] || [],
      architectures: func_data["Architectures"] || ["x86_64"],
      ephemeral_storage: func_data["EphemeralStorage"],
      event_sources: [],  # Will be populated separately if needed
      last_sync: now,
      # Initialize metrics
      invocation_count_24h: 0,
      error_count_24h: 0,
      cold_start_count_24h: 0,
      avg_duration_ms: 0
    }

    # Perform security analysis
    analyzed_function = analyze_function_security(function)

    # Store in ETS
    key = analyzed_function.function_arn || analyzed_function.function_name
    :ets.insert(@functions_table, {key, analyzed_function})

    analyzed_function
  end

  defp extract_environment_variables(nil), do: %{}
  defp extract_environment_variables(%{"Variables" => vars}) when is_map(vars), do: vars
  defp extract_environment_variables(_), do: %{}

  defp parse_lambda_timestamp(nil), do: nil
  defp parse_lambda_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _offset} -> dt
      {:error, _} -> nil
    end
  end
  defp parse_lambda_timestamp(_), do: nil

  defp get_aws_credentials do
    config = Application.get_env(:tamandua_server, :aws, [])

    access_key = config[:access_key_id]
    secret_key = config[:secret_access_key]

    if access_key && secret_key do
      {:ok, %{
        access_key_id: access_key,
        secret_access_key: secret_key,
        session_token: config[:session_token]
      }}
    else
      {:error, :not_configured}
    end
  end

  defp sign_aws_request(method, url, headers, body, creds, service, region) do
    now = DateTime.utc_now()
    date_stamp = Calendar.strftime(now, "%Y%m%d")
    amz_date = Calendar.strftime(now, "%Y%m%dT%H%M%SZ")

    uri = URI.parse(url)
    _host = uri.host
    canonical_uri = uri.path || "/"
    canonical_querystring = uri.query || ""

    # Canonical headers
    canonical_headers =
      headers
      |> Enum.map(fn {k, v} -> {String.downcase(k), String.trim(v)} end)
      |> Enum.concat([{"x-amz-date", amz_date}])
      |> Enum.sort()
      |> Enum.map(fn {k, v} -> "#{k}:#{v}\n" end)
      |> Enum.join()

    signed_headers =
      headers
      |> Enum.map(fn {k, _v} -> String.downcase(k) end)
      |> Enum.concat(["x-amz-date"])
      |> Enum.sort()
      |> Enum.join(";")

    # Payload hash
    payload_hash = :crypto.hash(:sha256, body) |> Base.encode16(case: :lower)

    # Canonical request
    canonical_request = "#{method}\n#{canonical_uri}\n#{canonical_querystring}\n#{canonical_headers}\n#{signed_headers}\n#{payload_hash}"

    # String to sign
    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = "#{date_stamp}/#{region}/#{service}/aws4_request"
    canonical_request_hash = :crypto.hash(:sha256, canonical_request) |> Base.encode16(case: :lower)
    string_to_sign = "#{algorithm}\n#{amz_date}\n#{credential_scope}\n#{canonical_request_hash}"

    # Signing key
    k_secret = "AWS4" <> creds.secret_access_key
    k_date = :crypto.mac(:hmac, :sha256, k_secret, date_stamp)
    k_region = :crypto.mac(:hmac, :sha256, k_date, region)
    k_service = :crypto.mac(:hmac, :sha256, k_region, service)
    k_signing = :crypto.mac(:hmac, :sha256, k_service, "aws4_request")

    # Signature
    signature = :crypto.mac(:hmac, :sha256, k_signing, string_to_sign) |> Base.encode16(case: :lower)

    # Authorization header
    authorization = "#{algorithm} Credential=#{creds.access_key_id}/#{credential_scope}, SignedHeaders=#{signed_headers}, Signature=#{signature}"

    headers
    |> Enum.concat([
      {"X-Amz-Date", amz_date},
      {"Authorization", authorization}
    ])
    |> maybe_add_session_token(creds)
  end

  defp maybe_add_session_token(headers, %{session_token: token}) when is_binary(token) do
    headers ++ [{"X-Amz-Security-Token", token}]
  end
  defp maybe_add_session_token(headers, _creds), do: headers

  defp make_http_request(method, url, headers, body) do
    request = Finch.build(method, url, headers, body)

    case Finch.request(request, TamanduaServer.Finch) do
      {:ok, response} ->
        {:ok, response}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp list_functions_internal(filters) do
    :ets.foldl(
      fn {_key, func}, acc -> [func | acc] end,
      [],
      @functions_table
    )
    |> apply_function_filters(filters)
    |> Enum.sort_by(& &1.function_name)
  end

  defp apply_function_filters(functions, filters) do
    functions
    |> filter_by_runtime(filters[:runtime])
    |> filter_by_region(filters[:region])
    |> filter_by_security_score(filters[:min_security_score])
    |> filter_by_has_findings(filters[:has_findings])
  end

  defp filter_by_runtime(functions, nil), do: functions
  defp filter_by_runtime(functions, runtime) do
    Enum.filter(functions, &(&1.runtime == runtime))
  end

  defp filter_by_region(functions, nil), do: functions
  defp filter_by_region(functions, region) do
    Enum.filter(functions, fn f ->
      String.contains?(f.function_arn || "", region)
    end)
  end

  defp filter_by_security_score(functions, nil), do: functions
  defp filter_by_security_score(functions, min_score) do
    Enum.filter(functions, fn f ->
      (f.security_score || 100) >= min_score
    end)
  end

  defp filter_by_has_findings(functions, nil), do: functions
  defp filter_by_has_findings(functions, true) do
    Enum.filter(functions, fn f ->
      (f.findings || []) != []
    end)
  end
  defp filter_by_has_findings(functions, false) do
    Enum.filter(functions, fn f ->
      (f.findings || []) == []
    end)
  end

  defp get_function_internal(function_id) do
    # Try by ARN first, then by name
    case :ets.lookup(@functions_table, function_id) do
      [{^function_id, func}] -> {:ok, func}
      [] ->
        # Search by name
        result = :ets.foldl(
          fn {_key, func}, acc ->
            if func.function_name == function_id, do: func, else: acc
          end,
          nil,
          @functions_table
        )

        if result, do: {:ok, result}, else: {:error, :not_found}
    end
  end

  defp get_executions_internal(function_id, opts) do
    limit = Keyword.get(opts, :limit, 100)
    start_time = Keyword.get(opts, :start_time)
    end_time = Keyword.get(opts, :end_time)

    :ets.foldl(
      fn {_ts, exec}, acc ->
        if matches_execution_filter?(exec, function_id, start_time, end_time) do
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

  defp matches_execution_filter?(exec, function_id, start_time, end_time) do
    matches_function?(exec, function_id) &&
      matches_time_range?(exec.timestamp, start_time, end_time)
  end

  defp matches_function?(exec, function_id) do
    exec.function_arn == function_id || exec.function_name == function_id
  end

  defp matches_time_range?(_ts, nil, nil), do: true
  defp matches_time_range?(ts, start_time, nil) do
    DateTime.compare(ts, start_time) in [:gt, :eq]
  end
  defp matches_time_range?(ts, nil, end_time) do
    DateTime.compare(ts, end_time) in [:lt, :eq]
  end
  defp matches_time_range?(ts, start_time, end_time) do
    DateTime.compare(ts, start_time) in [:gt, :eq] &&
      DateTime.compare(ts, end_time) in [:lt, :eq]
  end

  defp process_execution(data) do
    execution = build_execution(data)

    # Store execution
    ts = DateTime.to_unix(execution.timestamp, :millisecond)
    key = {ts, execution.request_id}
    :ets.insert(@executions_table, {key, execution})

    # Update function metrics
    update_function_metrics(execution)

    # Check for anomalies
    check_execution_anomalies(execution)

    # Detect security issues
    if execution.status == :error do
      check_error_patterns(execution)
    end
  end

  defp build_execution(data) do
    %Execution{
      request_id: data["request_id"] || Ecto.UUID.generate(),
      function_arn: data["function_arn"],
      function_name: data["function_name"],
      version: data["version"] || "$LATEST",
      timestamp: parse_timestamp(data["timestamp"]),
      duration_ms: data["duration_ms"],
      billed_duration_ms: data["billed_duration_ms"],
      memory_used_mb: data["memory_used_mb"],
      memory_size_mb: data["memory_size_mb"],
      init_duration_ms: data["init_duration_ms"],  # Presence indicates cold start
      status: parse_status(data["status"]),
      error_type: data["error_type"],
      error_message: data["error_message"],
      log_stream: data["log_stream"],
      x_ray_trace_id: data["x_ray_trace_id"],
      source_ip: data["source_ip"],
      user_agent: data["user_agent"],
      trigger_source: data["trigger_source"],
      outbound_connections: data["outbound_connections"] || [],
      file_operations: data["file_operations"] || [],
      process_spawns: data["process_spawns"] || [],
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
  defp parse_timestamp(ts) when is_integer(ts) do
    DateTime.from_unix!(ts, :millisecond)
  end
  defp parse_timestamp(%DateTime{} = dt), do: dt

  defp parse_status("success"), do: :success
  defp parse_status("error"), do: :error
  defp parse_status("timeout"), do: :timeout
  defp parse_status(_), do: :unknown

  defp update_function_metrics(execution) do
    function_id = execution.function_arn || execution.function_name

    case :ets.lookup(@metrics_table, function_id) do
      [{^function_id, metrics}] ->
        updated = %{metrics |
          invocation_count: metrics.invocation_count + 1,
          error_count: if(execution.status == :error, do: metrics.error_count + 1, else: metrics.error_count),
          cold_start_count: if(execution.init_duration_ms, do: metrics.cold_start_count + 1, else: metrics.cold_start_count),
          total_duration_ms: metrics.total_duration_ms + (execution.duration_ms || 0),
          last_invoked: execution.timestamp
        }
        :ets.insert(@metrics_table, {function_id, updated})

      [] ->
        metrics = %{
          function_id: function_id,
          invocation_count: 1,
          error_count: if(execution.status == :error, do: 1, else: 0),
          cold_start_count: if(execution.init_duration_ms, do: 1, else: 0),
          total_duration_ms: execution.duration_ms || 0,
          last_invoked: execution.timestamp,
          period_start: DateTime.utc_now()
        }
        :ets.insert(@metrics_table, {function_id, metrics})
    end
  end

  defp check_execution_anomalies(execution) do
    anomalies = []

    # Check for suspicious outbound connections
    anomalies = if has_suspicious_connections?(execution.outbound_connections) do
      [{:suspicious_connections, execution.outbound_connections} | anomalies]
    else
      anomalies
    end

    # Check for suspicious file operations
    anomalies = if has_suspicious_file_ops?(execution.file_operations) do
      [{:suspicious_file_ops, execution.file_operations} | anomalies]
    else
      anomalies
    end

    # Check for process spawning
    anomalies = if execution.process_spawns != [] do
      [{:process_spawns, execution.process_spawns} | anomalies]
    else
      anomalies
    end

    # Check for unusually long duration
    anomalies = if unusually_long_duration?(execution) do
      [{:long_duration, execution.duration_ms} | anomalies]
    else
      anomalies
    end

    if anomalies != [] do
      generate_anomaly_alert(execution, anomalies)
    end
  end

  defp has_suspicious_connections?(nil), do: false
  defp has_suspicious_connections?([]), do: false
  defp has_suspicious_connections?(connections) do
    suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337]
    suspicious_domains = ["ngrok.io", "burpcollaborator", "requestbin", "pipedream"]

    Enum.any?(connections, fn conn ->
      port = conn["port"] || conn[:port]
      host = conn["host"] || conn[:host] || ""

      port in suspicious_ports ||
        Enum.any?(suspicious_domains, &String.contains?(host, &1))
    end)
  end

  defp has_suspicious_file_ops?(nil), do: false
  defp has_suspicious_file_ops?([]), do: false
  defp has_suspicious_file_ops?(ops) do
    suspicious_paths = ["/etc/passwd", "/etc/shadow", "/.ssh/", "/root/"]

    Enum.any?(ops, fn op ->
      path = op["path"] || op[:path] || ""
      Enum.any?(suspicious_paths, &String.contains?(path, &1))
    end)
  end

  defp unusually_long_duration?(execution) do
    # Flag executions taking more than 90% of timeout
    case get_function_internal(execution.function_arn || execution.function_name) do
      {:ok, func} ->
        timeout_ms = (func.timeout || 3) * 1000
        (execution.duration_ms || 0) > timeout_ms * 0.9

      _ ->
        false
    end
  end

  defp check_error_patterns(execution) do
    error_msg = execution.error_message || ""

    # Check for common attack patterns in errors
    attack_patterns = [
      {~r/command.*not found/i, "Possible command injection attempt"},
      {~r/permission denied/i, "Privilege escalation attempt"},
      {~r/ECONNREFUSED.*:4444/i, "Reverse shell connection attempt"},
      {~r/out of memory/i, "Resource exhaustion (possible cryptominer)"},
      {~r/getaddrinfo.*ENOTFOUND/i, "DNS exfiltration attempt"},
      {~r/DEPTH_ZERO_SELF_SIGNED_CERT/i, "Suspicious TLS connection"},
      {~r/certificate.*invalid/i, "C2 connection attempt"}
    ]

    Enum.each(attack_patterns, fn {pattern, description} ->
      if Regex.match?(pattern, error_msg) do
        Logger.warning("Lambda security pattern detected: #{description} in #{execution.function_name}")

        Alerts.create_alert(%{
          title: "Lambda Security Alert: #{description}",
          description: """
          Function: #{execution.function_name}
          Request ID: #{execution.request_id}
          Error: #{error_msg}
          """,
          severity: "high",
          category: "serverless_security",
          source: "lambda_monitoring",
          mitre_techniques: ["T1059", "T1041"],
          metadata: %{
            function_arn: execution.function_arn,
            function_name: execution.function_name,
            request_id: execution.request_id,
            error_type: execution.error_type,
            pattern: description
          }
        })
      end
    end)
  end

  defp generate_anomaly_alert(execution, anomalies) do
    severity = determine_anomaly_severity(anomalies)

    Alerts.create_alert(%{
      title: "Lambda Anomaly: Suspicious behavior in #{execution.function_name}",
      description: """
      Function: #{execution.function_name}
      Request ID: #{execution.request_id}
      Anomalies detected:
      #{format_anomalies(anomalies)}
      """,
      severity: severity,
      category: "serverless_anomaly",
      source: "lambda_monitoring",
      mitre_techniques: determine_mitre_techniques(anomalies),
      metadata: %{
        function_arn: execution.function_arn,
        function_name: execution.function_name,
        request_id: execution.request_id,
        anomalies: anomalies
      }
    })
  end

  defp determine_anomaly_severity(anomalies) do
    cond do
      Enum.any?(anomalies, fn {type, _} -> type in [:suspicious_connections, :process_spawns] end) ->
        "critical"
      Enum.any?(anomalies, fn {type, _} -> type == :suspicious_file_ops end) ->
        "high"
      true ->
        "medium"
    end
  end

  defp format_anomalies(anomalies) do
    Enum.map(anomalies, fn {type, data} ->
      "- #{type}: #{inspect(data)}"
    end)
    |> Enum.join("\n")
  end

  defp determine_mitre_techniques(anomalies) do
    anomalies
    |> Enum.flat_map(fn {type, _} ->
      case type do
        :suspicious_connections -> ["T1041", "T1071"]  # Exfiltration, Application Layer Protocol
        :suspicious_file_ops -> ["T1005", "T1083"]  # Data from Local System, File Discovery
        :process_spawns -> ["T1059", "T1106"]  # Command/Scripting, Native API
        :long_duration -> ["T1496"]  # Resource Hijacking
        _ -> []
      end
    end)
    |> Enum.uniq()
  end

  defp process_logs(function_name, log_events) do
    Enum.each(log_events, fn event ->
      log_entry = parse_log_entry(function_name, event)

      # Store log entry
      ts = DateTime.to_unix(log_entry.timestamp, :millisecond)
      key = {ts, log_entry.request_id || Ecto.UUID.generate()}
      :ets.insert(@logs_table, {key, log_entry})

      # Check for security patterns in logs
      check_log_security_patterns(log_entry)
    end)
  end

  defp parse_log_entry(function_name, event) do
    message = event["message"] || ""
    timestamp = parse_timestamp(event["timestamp"])

    # Extract request ID from log format
    request_id = case Regex.run(~r/RequestId:\s*([\w-]+)/, message) do
      [_, id] -> id
      _ -> nil
    end

    # Parse log level
    log_level = cond do
      String.contains?(message, "ERROR") -> :error
      String.contains?(message, "WARN") -> :warning
      String.contains?(message, "INFO") -> :info
      String.contains?(message, "DEBUG") -> :debug
      true -> :info
    end

    %LogEntry{
      timestamp: timestamp,
      request_id: request_id,
      function_name: function_name,
      log_level: log_level,
      message: message,
      parsed_data: parse_log_data(message),
      anomalies: []
    }
  end

  defp parse_log_data(message) do
    # Try to parse JSON from log message
    json_pattern = ~r/\{[^{}]*\}/

    case Regex.run(json_pattern, message) do
      [json_str] ->
        case Jason.decode(json_str) do
          {:ok, data} -> data
          _ -> %{}
        end
      _ ->
        %{}
    end
  end

  defp check_log_security_patterns(log_entry) do
    message = log_entry.message || ""

    security_patterns = [
      {~r/exec\s*\(/i, "Code execution detected", "T1059"},
      {~r/eval\s*\(/i, "Dynamic code evaluation", "T1059"},
      {~r/shell_exec/i, "Shell command execution", "T1059"},
      {~r/child_process/i, "Child process spawning", "T1059"},
      {~r/curl\s+.*http/i, "HTTP request from function", "T1071"},
      {~r/wget\s+.*http/i, "HTTP download", "T1105"},
      {~r/nc\s+-.*\d+/i, "Netcat usage detected", "T1571"},
      {~r/base64.*decode/i, "Base64 decoding", "T1140"},
      {~r/\\x[0-9a-f]{2}/i, "Hex-encoded payload", "T1027"},
      {~r/crypto.*mine/i, "Cryptocurrency mining", "T1496"},
      {~r/xmr|monero/i, "Monero mining detected", "T1496"},
      {~r/AWS_SECRET_ACCESS_KEY/i, "AWS credential exposure", "T1552"},
      {~r/password.*=.*['\"][^'\"]+['\"]/i, "Hardcoded password", "T1552"}
    ]

    Enum.each(security_patterns, fn {pattern, description, technique} ->
      if Regex.match?(pattern, message) do
        Logger.warning("Lambda log security pattern: #{description} in #{log_entry.function_name}")

        Alerts.create_alert(%{
          title: "Lambda Log Alert: #{description}",
          description: """
          Function: #{log_entry.function_name}
          Request ID: #{log_entry.request_id || "unknown"}
          Log message: #{String.slice(message, 0, 500)}
          """,
          severity: "high",
          category: "serverless_security",
          source: "lambda_log_analysis",
          mitre_techniques: [technique],
          metadata: %{
            function_name: log_entry.function_name,
            request_id: log_entry.request_id,
            pattern: description,
            log_level: log_entry.log_level
          }
        })
      end
    end)
  end

  defp calculate_metrics(function_id, _opts) do
    executions = get_executions_internal(function_id, limit: 1000)

    if executions == [] do
      %{
        function_id: function_id,
        invocation_count: 0,
        error_count: 0,
        error_rate: 0.0,
        cold_start_count: 0,
        cold_start_rate: 0.0,
        avg_duration_ms: 0,
        p50_duration_ms: 0,
        p95_duration_ms: 0,
        p99_duration_ms: 0,
        avg_memory_used_mb: 0,
        last_invoked: nil
      }
    else
      durations = Enum.map(executions, & &1.duration_ms) |> Enum.reject(&is_nil/1) |> Enum.sort()
      memory_used = Enum.map(executions, & &1.memory_used_mb) |> Enum.reject(&is_nil/1)

      total = length(executions)
      errors = Enum.count(executions, &(&1.status == :error))
      cold_starts = Enum.count(executions, &(&1.init_duration_ms != nil))

      %{
        function_id: function_id,
        invocation_count: total,
        error_count: errors,
        error_rate: if(total > 0, do: errors / total * 100, else: 0.0),
        cold_start_count: cold_starts,
        cold_start_rate: if(total > 0, do: cold_starts / total * 100, else: 0.0),
        avg_duration_ms: average(durations),
        p50_duration_ms: percentile(durations, 50),
        p95_duration_ms: percentile(durations, 95),
        p99_duration_ms: percentile(durations, 99),
        avg_memory_used_mb: average(memory_used),
        last_invoked: List.first(executions) && List.first(executions).timestamp
      }
    end
  end

  defp average([]), do: 0
  defp average(list), do: Enum.sum(list) / length(list)

  defp percentile([], _p), do: 0
  defp percentile(sorted_list, p) do
    k = length(sorted_list) * p / 100
    index = trunc(k)
    index = min(index, length(sorted_list) - 1)
    Enum.at(sorted_list, index)
  end

  defp get_security_findings_internal(function_id) do
    case get_function_internal(function_id) do
      {:ok, func} -> func.findings || []
      _ -> []
    end
  end

  defp do_analyze_iam_role(role_arn) do
    Logger.info("Analyzing IAM role: #{role_arn}")

    # Extract role name from ARN (format: arn:aws:iam::account-id:role/role-name)
    role_name = extract_role_name(role_arn)

    if role_name == nil do
      {:error, :invalid_role_arn}
    else
      # Fetch and analyze role policies
      case fetch_role_policies(role_name) do
        {:ok, policies} ->
          analysis = analyze_policies(policies)

          {:ok, %{
            role_arn: role_arn,
            role_name: role_name,
            overprivileged: analysis.overprivileged,
            dangerous_permissions: analysis.dangerous_permissions,
            recommendations: analysis.recommendations,
            risk_score: analysis.risk_score,
            policy_count: length(policies),
            privilege_escalation_vectors: analysis.privilege_escalation_vectors,
            unrestricted_resources: analysis.unrestricted_resources,
            admin_policies: analysis.admin_policies
          }}

        {:error, reason} ->
          Logger.warning("Failed to fetch IAM role policies for #{role_name}: #{inspect(reason)}")
          # Return fallback analysis with limited information
          {:ok, %{
            role_arn: role_arn,
            role_name: role_name,
            overprivileged: false,
            dangerous_permissions: [],
            recommendations: ["Unable to fetch role policies - ensure AWS credentials are configured"],
            risk_score: 0,
            error: inspect(reason)
          }}
      end
    end
  end

  # Privilege escalation permission patterns
  @privilege_escalation_permissions [
    # IAM privilege escalation vectors
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:UpdateAssumeRolePolicy",
    "iam:PassRole",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    # Lambda-based escalation
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "lambda:UpdateFunctionConfiguration",
    "lambda:InvokeFunction",
    "lambda:AddPermission",
    # EC2 privilege escalation
    "ec2:RunInstances",
    "ec2:CreateSnapshot",
    "ec2:ModifyInstanceAttribute",
    # STS privilege escalation
    "sts:AssumeRole",
    # Data access vectors
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "kms:Decrypt"
  ]

  # Admin policy ARNs and patterns
  defp admin_policy_patterns do
    [
      "arn:aws:iam::aws:policy/AdministratorAccess",
      "arn:aws:iam::aws:policy/PowerUserAccess",
      ~r/Admin/i,
      ~r/FullAccess/i
    ]
  end

  defp extract_role_name(role_arn) do
    case String.split(role_arn, "/") do
      [_ | [role_name | _]] -> role_name
      _ ->
        # Try to extract from ARN format
        case Regex.run(~r/role\/([^\/]+)/, role_arn) do
          [_, role_name] -> role_name
          _ -> nil
        end
    end
  end

  defp fetch_role_policies(role_name) do
    # Use ExAws if available to fetch real IAM policies
    if Code.ensure_loaded?(ExAws) and Code.ensure_loaded?(ExAws.IAM) do
      try do
        # Get inline policies
        inline_policies_result =
          apply(ExAws.IAM, :list_role_policies, [role_name])
          |> then(&apply(ExAws, :request, [&1]))

        # Get attached managed policies
        attached_policies_result =
          apply(ExAws.IAM, :list_attached_role_policies, [role_name])
          |> then(&apply(ExAws, :request, [&1]))

        _all_policies = []

        # Process inline policies
        all_policies = case inline_policies_result do
          {:ok, %{body: body}} ->
            inline_policy_names = extract_policy_names_from_response(body)
            fetch_inline_policy_documents(role_name, inline_policy_names)
          _ ->
            []
        end

        # Process attached managed policies
        all_policies = case attached_policies_result do
          {:ok, %{body: body}} ->
            managed_policies = extract_attached_policies_from_response(body)
            all_policies ++ fetch_managed_policy_documents(managed_policies)
          _ ->
            all_policies
        end

        {:ok, all_policies}
      rescue
        e ->
          Logger.debug("ExAws IAM call failed: #{inspect(e)}")
          {:error, {:aws_error, e}}
      end
    else
      Logger.debug("ExAws not available, skipping IAM policy fetch")
      {:error, :exaws_not_available}
    end
  end

  defp extract_policy_names_from_response(body) do
    # Parse XML/JSON response to extract policy names
    # This is a simplified version - actual implementation depends on ExAws response format
    case body do
      %{"PolicyNames" => names} when is_list(names) -> names
      %{"PolicyNames" => %{"member" => names}} when is_list(names) -> names
      %{"PolicyNames" => %{"member" => name}} when is_binary(name) -> [name]
      _ -> []
    end
  end

  defp extract_attached_policies_from_response(body) do
    case body do
      %{"AttachedPolicies" => policies} when is_list(policies) -> policies
      %{"AttachedPolicies" => %{"member" => policies}} when is_list(policies) -> policies
      %{"AttachedPolicies" => %{"member" => policy}} when is_map(policy) -> [policy]
      _ -> []
    end
  end

  defp fetch_inline_policy_documents(role_name, policy_names) do
    Enum.flat_map(policy_names, fn policy_name ->
      try do
        req = apply(ExAws.IAM, :get_role_policy, [role_name, policy_name])
        case apply(ExAws, :request, [req]) do
          {:ok, %{body: body}} ->
            policy_doc = extract_policy_document(body)
            if policy_doc, do: [%{name: policy_name, type: :inline, document: policy_doc}], else: []
          _ ->
            []
        end
      rescue
        _ -> []
      end
    end)
  end

  defp fetch_managed_policy_documents(attached_policies) do
    Enum.flat_map(attached_policies, fn policy_info ->
      policy_arn = policy_info["PolicyArn"] || policy_info[:PolicyArn]
      policy_name = policy_info["PolicyName"] || policy_info[:PolicyName] || policy_arn

      if policy_arn do
        try do
          # Get the default policy version
          req = apply(ExAws.IAM, :get_policy, [policy_arn])
          case apply(ExAws, :request, [req]) do
            {:ok, %{body: body}} ->
              version_id = extract_default_version_id(body)
              if version_id do
                # Fetch the policy document for the default version
                doc_req = apply(ExAws.IAM, :get_policy_version, [policy_arn, version_id])
                case apply(ExAws, :request, [doc_req]) do
                  {:ok, %{body: doc_body}} ->
                    policy_doc = extract_policy_document(doc_body)
                    if policy_doc do
                      [%{name: policy_name, type: :managed, arn: policy_arn, document: policy_doc}]
                    else
                      []
                    end
                  _ ->
                    []
                end
              else
                []
              end
            _ ->
              []
          end
        rescue
          _ -> []
        end
      else
        []
      end
    end)
  end

  defp extract_default_version_id(body) do
    case body do
      %{"Policy" => %{"DefaultVersionId" => version_id}} -> version_id
      %{"DefaultVersionId" => version_id} -> version_id
      _ -> nil
    end
  end

  defp extract_policy_document(body) do
    # Extract and parse the policy document JSON
    policy_doc_str = case body do
      %{"PolicyDocument" => doc} when is_binary(doc) -> URI.decode(doc)
      %{"PolicyDocument" => doc} when is_map(doc) -> Jason.encode!(doc)
      %{"Document" => doc} when is_binary(doc) -> URI.decode(doc)
      %{"Document" => doc} when is_map(doc) -> Jason.encode!(doc)
      %{"PolicyVersion" => %{"Document" => doc}} when is_binary(doc) -> URI.decode(doc)
      %{"PolicyVersion" => %{"Document" => doc}} when is_map(doc) -> Jason.encode!(doc)
      _ -> nil
    end

    if policy_doc_str do
      case Jason.decode(policy_doc_str) do
        {:ok, doc} -> doc
        _ -> nil
      end
    else
      nil
    end
  end

  defp analyze_policies(policies) do
    # Extract all permissions from all policy statements
    all_permissions = extract_all_permissions(policies)
    all_resources = extract_all_resources(policies)

    # Check for dangerous permissions
    dangerous_perms = find_dangerous_permissions(all_permissions)

    # Check for privilege escalation vectors
    escalation_vectors = find_privilege_escalation_vectors(all_permissions)

    # Check for admin policies
    admin_policies = find_admin_policies(policies)

    # Check for unrestricted resource access
    unrestricted = find_unrestricted_resources(all_permissions, all_resources)

    # Calculate risk score
    risk_score = calculate_risk_score(
      dangerous_perms,
      escalation_vectors,
      admin_policies,
      unrestricted,
      all_permissions
    )

    # Determine if overprivileged
    overprivileged = risk_score >= 70 or length(admin_policies) > 0 or has_wildcard_permissions?(all_permissions)

    # Generate recommendations
    recommendations = generate_recommendations(
      dangerous_perms,
      escalation_vectors,
      admin_policies,
      unrestricted,
      overprivileged
    )

    %{
      overprivileged: overprivileged,
      dangerous_permissions: Enum.uniq(dangerous_perms),
      privilege_escalation_vectors: Enum.uniq(escalation_vectors),
      unrestricted_resources: unrestricted,
      admin_policies: admin_policies,
      risk_score: risk_score,
      recommendations: recommendations
    }
  end

  defp extract_all_permissions(policies) do
    Enum.flat_map(policies, fn policy ->
      doc = policy.document

      case doc do
        %{"Statement" => statements} when is_list(statements) ->
          Enum.flat_map(statements, &extract_permissions_from_statement/1)

        %{"Statement" => statement} when is_map(statement) ->
          extract_permissions_from_statement(statement)

        _ ->
          []
      end
    end)
  end

  defp extract_permissions_from_statement(statement) do
    effect = statement["Effect"] || statement[:Effect]

    # Only analyze Allow statements (Deny statements don't grant permissions)
    if effect == "Allow" do
      actions = case statement["Action"] || statement[:Action] do
        actions when is_list(actions) -> actions
        action when is_binary(action) -> [action]
        _ -> []
      end

      # Expand wildcards to known dangerous permissions
      Enum.flat_map(actions, fn action ->
        if String.contains?(action, "*") do
          expand_wildcard_action(action)
        else
          [action]
        end
      end)
    else
      []
    end
  end

  defp extract_all_resources(policies) do
    Enum.flat_map(policies, fn policy ->
      doc = policy.document

      case doc do
        %{"Statement" => statements} when is_list(statements) ->
          Enum.flat_map(statements, &extract_resources_from_statement/1)

        %{"Statement" => statement} when is_map(statement) ->
          extract_resources_from_statement(statement)

        _ ->
          []
      end
    end)
  end

  defp extract_resources_from_statement(statement) do
    case statement["Resource"] || statement[:Resource] do
      resources when is_list(resources) -> resources
      resource when is_binary(resource) -> [resource]
      _ -> []
    end
  end

  defp expand_wildcard_action(action_pattern) do
    # If action is "*" or "service:*", it matches all dangerous permissions
    cond do
      action_pattern == "*" ->
        @dangerous_permissions

      String.ends_with?(action_pattern, ":*") ->
        service = String.replace_suffix(action_pattern, ":*", "")
        Enum.filter(@dangerous_permissions, &String.starts_with?(&1, service <> ":"))

      true ->
        # Handle patterns like "iam:*Policy"
        regex = action_pattern
        |> String.replace("*", ".*")
        |> Regex.compile!()

        Enum.filter(@dangerous_permissions, &Regex.match?(regex, &1))
    end
  end

  defp find_dangerous_permissions(all_permissions) do
    Enum.filter(all_permissions, fn perm ->
      perm in @dangerous_permissions or String.contains?(perm, "*")
    end)
  end

  defp find_privilege_escalation_vectors(all_permissions) do
    Enum.filter(all_permissions, fn perm ->
      perm in @privilege_escalation_permissions
    end)
  end

  defp find_admin_policies(policies) do
    Enum.filter(policies, fn policy ->
      policy_name = policy[:name] || ""
      policy_arn = policy[:arn] || ""

      # Check if it's a known admin policy
      policy_arn in admin_policy_patterns() or
        Enum.any?(admin_policy_patterns(), fn
          pattern when is_binary(pattern) -> pattern == policy_arn
          %Regex{} = pattern -> Regex.match?(pattern, policy_name) or Regex.match?(pattern, policy_arn)
        end)
    end)
    |> Enum.map(fn policy -> policy[:name] || policy[:arn] || "Unknown" end)
  end

  defp find_unrestricted_resources(all_permissions, all_resources) do
    # Find permissions that apply to all resources (Resource: "*")
    if "*" in all_resources do
      # These permissions apply to all resources
      dangerous_unrestricted = Enum.filter(all_permissions, &(&1 in @dangerous_permissions))
      if length(dangerous_unrestricted) > 0 do
        ["All resources (*) with dangerous permissions: #{Enum.join(dangerous_unrestricted, ", ")}"]
      else
        []
      end
    else
      []
    end
  end

  defp has_wildcard_permissions?(all_permissions) do
    Enum.any?(all_permissions, fn perm ->
      perm == "*" or perm == "*:*"
    end)
  end

  defp calculate_risk_score(dangerous_perms, escalation_vectors, admin_policies, unrestricted, all_permissions) do
    score = 0

    # Base score for dangerous permissions (up to 40 points)
    score = score + min(length(dangerous_perms) * 5, 40)

    # Privilege escalation vectors (up to 30 points)
    score = score + min(length(escalation_vectors) * 10, 30)

    # Admin policies (automatic 100)
    score = if length(admin_policies) > 0, do: 100, else: score

    # Unrestricted resource access (up to 20 points)
    score = score + min(length(unrestricted) * 20, 20)

    # Wildcard permissions (automatic high risk)
    score = if has_wildcard_permissions?(all_permissions), do: max(score, 90), else: score

    min(score, 100)
  end

  defp generate_recommendations(dangerous_perms, escalation_vectors, admin_policies, unrestricted, overprivileged) do
    recommendations = []

    recommendations = if length(admin_policies) > 0 do
      ["Remove administrator policies (#{Enum.join(admin_policies, ", ")}) and grant only necessary permissions" | recommendations]
    else
      recommendations
    end

    recommendations = if length(escalation_vectors) > 0 do
      ["Role has privilege escalation vectors: #{Enum.join(Enum.take(escalation_vectors, 5), ", ")}. Review and restrict these permissions" | recommendations]
    else
      recommendations
    end

    recommendations = if length(unrestricted) > 0 do
      ["Restrict resource access from wildcard (*) to specific ARNs" | recommendations]
    else
      recommendations
    end

    recommendations = if length(dangerous_perms) > 10 do
      ["Role has #{length(dangerous_perms)} dangerous permissions. Apply principle of least privilege" | recommendations]
    else
      recommendations
    end

    recommendations = if overprivileged and recommendations == [] do
      ["Review role permissions and apply principle of least privilege" | recommendations]
    else
      recommendations
    end

    recommendations = if recommendations == [] do
      ["Role permissions appear reasonable for a Lambda execution role"]
    else
      recommendations
    end

    recommendations
  end

  @doc false
  def analyze_function_security(function) do
    findings = []
    score = 100

    # Check environment variables for secrets
    {secret_findings, secret_score_reduction} = check_environment_secrets(function.environment)
    findings = findings ++ secret_findings
    score = score - secret_score_reduction

    # Check for dangerous IAM permissions
    {iam_findings, iam_score_reduction} = check_iam_permissions(function.role)
    findings = findings ++ iam_findings
    score = score - iam_score_reduction

    # Check function name for suspicious patterns
    {name_findings, name_score_reduction} = check_function_name_patterns(function.function_name)
    findings = findings ++ name_findings
    score = score - name_score_reduction

    # Check for public triggers (API Gateway without auth)
    {trigger_findings, trigger_score_reduction} = check_event_sources(function.event_sources)
    findings = findings ++ trigger_findings
    score = score - trigger_score_reduction

    # Check VPC configuration
    {vpc_findings, vpc_score_reduction} = check_vpc_config(function.vpc_config)
    findings = findings ++ vpc_findings
    score = score - vpc_score_reduction

    %{function |
      security_score: max(0, score),
      findings: findings
    }
  end

  defp check_environment_secrets(nil), do: {[], 0}
  defp check_environment_secrets(env) when map_size(env) == 0, do: {[], 0}
  defp check_environment_secrets(env) do
    findings = env
    |> Enum.filter(fn {key, _value} ->
      Enum.any?(secret_patterns(), &Regex.match?(&1, key))
    end)
    |> Enum.map(fn {key, _value} ->
      %{
        type: :secret_in_env,
        severity: "high",
        title: "Potential secret in environment variable",
        description: "Environment variable '#{key}' appears to contain sensitive data. Use AWS Secrets Manager or SSM Parameter Store instead.",
        remediation: "Move secret to AWS Secrets Manager and reference via SDK"
      }
    end)

    score_reduction = length(findings) * 10
    {findings, min(score_reduction, 40)}
  end

  defp check_iam_permissions(nil), do: {[], 0}
  defp check_iam_permissions(role_arn) when is_binary(role_arn) do
    # Analyze the IAM role for dangerous permissions
    case do_analyze_iam_role(role_arn) do
      {:ok, analysis} ->
        findings = []
        score_reduction = 0

        # Check for dangerous permissions
        findings = if analysis.dangerous_permissions != [] do
          dangerous_perms = Enum.take(analysis.dangerous_permissions, 5)
          [{:dangerous_iam_permissions,
            %{
              type: :dangerous_iam_permissions,
              severity: "high",
              title: "Lambda function has dangerous IAM permissions",
              description: "Role #{role_arn} has #{length(analysis.dangerous_permissions)} dangerous permission(s): #{Enum.join(dangerous_perms, ", ")}",
              remediation: "Review and reduce IAM role permissions following principle of least privilege"
            }} | findings]
        else
          findings
        end

        score_reduction = score_reduction + min(length(analysis.dangerous_permissions || []) * 5, 25)

        # Check for overprivileged role
        findings = if analysis.overprivileged do
          [{:overprivileged_role,
            %{
              type: :overprivileged_role,
              severity: "high",
              title: "Lambda function role is overprivileged",
              description: "Role #{role_arn} has excessive permissions (risk score: #{analysis.risk_score})",
              remediation: "Apply principle of least privilege and reduce role permissions"
            }} | findings]
        else
          findings
        end

        score_reduction = score_reduction + if analysis.overprivileged, do: 20, else: 0

        # Check for privilege escalation vectors
        findings = if analysis.privilege_escalation_vectors != [] do
          vectors = Enum.take(analysis.privilege_escalation_vectors, 3)
          [{:privilege_escalation_risk,
            %{
              type: :privilege_escalation_risk,
              severity: "critical",
              title: "Lambda function can escalate privileges",
              description: "Role #{role_arn} has #{length(analysis.privilege_escalation_vectors)} privilege escalation vector(s): #{Enum.join(vectors, ", ")}",
              remediation: "Remove privilege escalation permissions immediately"
            }} | findings]
        else
          findings
        end

        score_reduction = score_reduction + min(length(analysis.privilege_escalation_vectors || []) * 8, 30)

        # Check for admin policies
        findings = if analysis.admin_policies != [] do
          admin_list = Enum.take(analysis.admin_policies, 3)
          [{:admin_policy_attached,
            %{
              type: :admin_policy_attached,
              severity: "critical",
              title: "Lambda function has administrative privileges",
              description: "Role #{role_arn} has #{length(analysis.admin_policies)} admin policy/policies attached: #{Enum.join(admin_list, ", ")}",
              remediation: "Remove administrative policies and grant only required permissions"
            }} | findings]
        else
          findings
        end

        score_reduction = score_reduction + if analysis.admin_policies != [], do: 40, else: 0

        # Extract only the finding maps (not the atom keys)
        finding_maps = Enum.map(findings, fn {_key, finding} -> finding end)

        {finding_maps, min(score_reduction, 50)}

      {:error, reason} ->
        Logger.debug("Could not analyze IAM role #{role_arn}: #{inspect(reason)}")
        # Don't penalize if we can't fetch the policies
        {[], 0}
    end
  end
  defp check_iam_permissions(_invalid), do: {[], 0}

  defp check_function_name_patterns(nil), do: {[], 0}
  defp check_function_name_patterns(name) do
    if Enum.any?(suspicious_function_patterns(), &Regex.match?(&1, name)) do
      {[%{
        type: :suspicious_name,
        severity: "medium",
        title: "Suspicious function name",
        description: "Function name '#{name}' matches suspicious patterns",
        remediation: "Review function purpose and rename if legitimate"
      }], 15}
    else
      {[], 0}
    end
  end

  defp check_event_sources(nil), do: {[], 0}
  defp check_event_sources([]), do: {[], 0}
  defp check_event_sources(sources) do
    findings = sources
    |> Enum.filter(fn source ->
      source[:type] == "api_gateway" && source[:authorization] in [nil, "NONE"]
    end)
    |> Enum.map(fn source ->
      %{
        type: :public_api_gateway,
        severity: "medium",
        title: "Publicly accessible API Gateway trigger",
        description: "API Gateway endpoint #{source[:endpoint]} has no authorization configured",
        remediation: "Add IAM, Lambda authorizer, or API key authorization"
      }
    end)

    score_reduction = length(findings) * 15
    {findings, min(score_reduction, 30)}
  end

  defp check_vpc_config(nil) do
    {[%{
      type: :no_vpc,
      severity: "low",
      title: "Function not in VPC",
      description: "Function runs in public AWS network, not a VPC",
      remediation: "Consider placing function in VPC for network isolation"
    }], 5}
  end
  defp check_vpc_config(_vpc), do: {[], 0}

  defp detect_cold_starts_internal(function_id, start_time, end_time) do
    get_executions_internal(function_id, start_time: start_time, end_time: end_time, limit: 10000)
    |> Enum.filter(& &1.init_duration_ms != nil)
  end

  defp compute_statistics do
    functions = list_functions_internal(%{})

    total_functions = length(functions)
    functions_with_findings = Enum.count(functions, fn f -> (f.findings || []) != [] end)

    # Aggregate metrics
    all_metrics = functions
    |> Enum.map(fn f -> calculate_metrics(f.function_arn || f.function_name, []) end)

    total_invocations = Enum.sum(Enum.map(all_metrics, & &1.invocation_count))
    total_errors = Enum.sum(Enum.map(all_metrics, & &1.error_count))
    total_cold_starts = Enum.sum(Enum.map(all_metrics, & &1.cold_start_count))

    # Runtime distribution
    runtime_dist = functions
    |> Enum.group_by(& &1.runtime)
    |> Enum.map(fn {runtime, funcs} -> {runtime, length(funcs)} end)
    |> Map.new()

    # Security score distribution
    score_ranges = %{
      "critical" => Enum.count(functions, fn f -> (f.security_score || 100) < 50 end),
      "high" => Enum.count(functions, fn f ->
        score = f.security_score || 100
        score >= 50 && score < 70
      end),
      "medium" => Enum.count(functions, fn f ->
        score = f.security_score || 100
        score >= 70 && score < 90
      end),
      "low" => Enum.count(functions, fn f -> (f.security_score || 100) >= 90 end)
    }

    %{
      total_functions: total_functions,
      functions_with_findings: functions_with_findings,
      total_invocations_24h: total_invocations,
      total_errors_24h: total_errors,
      total_cold_starts_24h: total_cold_starts,
      overall_error_rate: if(total_invocations > 0, do: total_errors / total_invocations * 100, else: 0.0),
      overall_cold_start_rate: if(total_invocations > 0, do: total_cold_starts / total_invocations * 100, else: 0.0),
      runtime_distribution: runtime_dist,
      security_score_distribution: score_ranges,
      average_security_score: if(total_functions > 0,
        do: Enum.sum(Enum.map(functions, & &1.security_score || 100)) / total_functions,
        else: 100
      )
    }
  end
end
