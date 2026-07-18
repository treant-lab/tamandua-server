defmodule TamanduaServer.Serverless.LambdaExtension do
  @moduledoc """
  Lambda Extension Runtime Monitoring - Design Document & Stub

  ## Overview

  AWS Lambda Extensions provide a way to integrate monitoring, security, and
  observability tools with Lambda functions. This module defines the architecture
  for a Tamandua Lambda Extension that would provide deep runtime monitoring.

  ## Extension Types

  ### 1. Internal Extension (In-Process)
  - Runs within the Lambda runtime process
  - Direct access to function memory and execution context
  - Lower overhead but limited to supported runtimes
  - Best for: Memory scanning, code injection detection

  ### 2. External Extension (Separate Process)
  - Runs as a separate process in the execution environment
  - Communicates via Lambda Extensions API
  - Works with any runtime
  - Best for: Network monitoring, file system monitoring, telemetry

  ## Proposed Architecture

  ```
  +------------------+     +------------------+     +------------------+
  |  Lambda Handler  | --> |   Internal Ext   | --> |  Tamandua Agent  |
  |   (User Code)    |     | (Memory Scanner) |     |   (External)     |
  +------------------+     +------------------+     +------------------+
                                   |                        |
                                   v                        v
                           +------------------+     +------------------+
                           |   Shared Memory  |     |  Extensions API  |
                           |   (Ring Buffer)  |     |   (HTTP Local)   |
                           +------------------+     +------------------+
                                                           |
                                                           v
                                                   +------------------+
                                                   | Tamandua Server  |
                                                   +------------------+
  ```

  ## Extension Components

  ### 1. Telemetry Collector
  - Subscribe to Lambda Telemetry API
  - Capture function start/stop, invocation events
  - Log platform events (init, shutdown, errors)

  ### 2. Network Monitor
  - Intercept outbound connections via eBPF or LD_PRELOAD
  - Track DNS queries, TLS connections
  - Detect C2 beaconing, data exfiltration

  ### 3. File System Monitor
  - Watch /tmp writes (common attack staging area)
  - Detect script drops, tool downloads
  - Monitor sensitive file access attempts

  ### 4. Memory Scanner
  - Periodic memory scanning for malware signatures
  - Detect in-memory threats, shellcode
  - Credential scraping detection

  ### 5. Process Monitor
  - Track child process spawning
  - Detect shell escapes, reverse shells
  - Command-line analysis

  ## Implementation Notes

  ### Deployment as Lambda Layer
  The extension would be packaged as a Lambda Layer:

  ```
  tamandua-extension-layer/
  ├── extensions/
  │   └── tamandua           # External extension binary (must be executable)
  └── lib/
      ├── tamandua/
      │   ├── libscanner.so  # Memory scanning library
      │   └── rules/         # Detection rules
      └── wrapper.sh         # Runtime wrapper (optional)
  ```

  ### Extensions API Integration

  ```rust
  // Extension registration (on cold start)
  POST /2020-01-01/extension/register
  {
    "events": ["INVOKE", "SHUTDOWN"]
  }

  // Wait for next event
  GET /2020-01-01/extension/event/next

  // Telemetry subscription
  PUT /2020-08-15/telemetry
  {
    "destination": {"protocol": "HTTP", "URI": "http://sandbox:9999"},
    "types": ["platform", "function"],
    "buffering": {"maxItems": 1000, "maxBytes": 262144, "timeoutMs": 100}
  }
  ```

  ### Challenges

  1. **Cold Start Impact**: Extensions add to cold start latency
     - Mitigation: Lazy initialization, minimal bootstrap

  2. **Memory Overhead**: Extensions share the function's memory
     - Mitigation: Efficient data structures, shared memory buffers

  3. **Execution Time**: Extensions consume function execution time
     - Mitigation: Async processing, batched telemetry

  4. **Runtime Compatibility**: Not all runtimes support internal extensions
     - Mitigation: External extension as fallback

  5. **VPC Networking**: Extensions in VPC may need NAT for telemetry
     - Mitigation: Local buffering, batch on shutdown

  ## Security Considerations

  - Extension runs with same permissions as function
  - Cannot elevate privileges or escape sandbox
  - Must handle sensitive data (credentials in memory) carefully
  - Telemetry must be encrypted in transit

  ## Future Implementation Roadmap

  ### Phase 1: External Extension (MVP)
  - Basic telemetry collection via Extensions API
  - Network connection logging
  - Process spawning detection
  - Estimated: 2-3 weeks

  ### Phase 2: File System Monitoring
  - /tmp monitoring with inotify
  - Suspicious file detection (scripts, binaries)
  - Hash-based known malware detection
  - Estimated: 1-2 weeks

  ### Phase 3: Internal Extension (Python/Node.js)
  - Runtime-specific hooks for Python and Node.js
  - Memory scanning integration
  - Code injection detection
  - Estimated: 3-4 weeks

  ### Phase 4: Advanced Detection
  - eBPF-based network monitoring (if kernel supports)
  - Behavioral analysis at runtime
  - ML-based anomaly detection
  - Estimated: 4-6 weeks

  ## Configuration

  Environment variables for the extension:

  ```
  TAMANDUA_SERVER_URL=https://your-server.com/api/v1/serverless
  TAMANDUA_API_KEY=your-api-key
  TAMANDUA_FUNCTION_ID=auto-detected
  TAMANDUA_LOG_LEVEL=info
  TAMANDUA_BUFFER_SIZE=1000
  TAMANDUA_FLUSH_INTERVAL_MS=1000
  TAMANDUA_ENABLE_MEMORY_SCAN=true
  TAMANDUA_ENABLE_NETWORK_MONITOR=true
  TAMANDUA_ENABLE_FILE_MONITOR=true
  ```

  ## References

  - [AWS Lambda Extensions API](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-extensions-api.html)
  - [Lambda Telemetry API](https://docs.aws.amazon.com/lambda/latest/dg/telemetry-api.html)
  - [Lambda Layers](https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html)
  - [Extension Examples (GitHub)](https://github.com/aws-samples/aws-lambda-extensions)
  """

  @doc """
  Placeholder for Lambda extension telemetry ingestion.
  The actual extension would run as a Lambda Layer, this module
  handles the server-side processing of extension telemetry.
  """

  require Logger

  alias TamanduaServer.Serverless.BehavioralBaseline
  alias TamanduaServer.Alerts

  # ETS table for tracking function execution state
  @function_state_table :lambda_function_state

  @doc """
  Initialize ETS tables for function state tracking.
  Call this on application startup.
  """
  def init_tables do
    unless :ets.whereis(@function_state_table) != :undefined do
      :ets.new(@function_state_table, [:set, :named_table, :public, read_concurrency: true])
    end
  end

  @doc """
  Process telemetry batch from Lambda extension.

  The extension sends batched telemetry via the Extensions API,
  which is then forwarded to this endpoint.
  """
  @spec ingest_extension_telemetry(map()) :: {:ok, integer()} | {:error, term()}
  def ingest_extension_telemetry(%{"function_arn" => arn, "events" => events}) when is_list(events) do
    Logger.info("Received #{length(events)} events from Lambda extension for #{arn}")

    # Process each event
    processed =
      events
      |> Enum.map(&process_extension_event(&1, arn))
      |> Enum.count(fn result -> match?({:ok, _}, result) end)

    {:ok, processed}
  end

  def ingest_extension_telemetry(_), do: {:error, :invalid_payload}

  @doc """
  Process individual extension event.
  """
  @spec process_extension_event(map(), String.t()) :: {:ok, map()} | {:error, term()}
  def process_extension_event(%{"type" => type} = event, function_arn) do
    case type do
      "platform.start" ->
        handle_function_start(event, function_arn)

      "platform.runtimeDone" ->
        handle_runtime_done(event, function_arn)

      "platform.report" ->
        handle_platform_report(event, function_arn)

      "function" ->
        handle_function_log(event, function_arn)

      "network.connection" ->
        handle_network_event(event, function_arn)

      "file.access" ->
        handle_file_event(event, function_arn)

      "process.spawn" ->
        handle_process_event(event, function_arn)

      "memory.scan" ->
        handle_memory_scan(event, function_arn)

      _ ->
        Logger.debug("Unknown extension event type: #{type}")
        {:ok, event}
    end
  end

  def process_extension_event(event, _arn) do
    Logger.warning("Extension event missing type: #{inspect(event)}")
    {:error, :missing_type}
  end

  # Event handlers with behavioral analysis

  defp handle_function_start(event, arn) do
    # Extract request ID from event
    request_id = event["record"]["requestId"] || Ecto.UUID.generate()
    timestamp = parse_event_timestamp(event["time"])

    Logger.debug("Function start: #{arn} (request: #{request_id})")

    # Initialize function state for this execution
    init_tables()  # Ensure table exists

    # Get previous execution state to detect cold vs warm start
    {is_cold_start, previous_request_id} = case :ets.lookup(@function_state_table, arn) do
      [{^arn, state}] ->
        # Check time since last execution
        time_since_last = DateTime.diff(timestamp, state.last_execution_time, :millisecond)

        # Cold start if:
        # 1. Init duration is present in next platform.report
        # 2. Long gap since last execution (>5 min = likely container recycled)
        # 3. First execution (no previous state)
        cold = time_since_last > 300_000  # 5 minutes

        {cold, state.last_request_id}

      [] ->
        # First time seeing this function
        {true, nil}
    end

    # Update state machine
    state = %{
      function_arn: arn,
      request_id: request_id,
      status: :started,
      start_time: timestamp,
      is_cold_start: is_cold_start,
      previous_request_id: previous_request_id,
      last_execution_time: timestamp,
      last_request_id: request_id,
      metrics: %{}
    }

    :ets.insert(@function_state_table, {arn, state})

    # Start learning baseline if not already started
    BehavioralBaseline.start_learning(arn, :aws_lambda)

    Logger.info("Function #{arn} started (#{if is_cold_start, do: "COLD", else: "WARM"} start)")

    {:ok, Map.merge(event, %{
      parsed_data: %{
        request_id: request_id,
        timestamp: timestamp,
        is_cold_start: is_cold_start
      }
    })}
  end

  defp handle_runtime_done(event, arn) do
    request_id = event["record"]["requestId"]
    timestamp = parse_event_timestamp(event["time"])
    status = event["record"]["status"]  # "success" or "error"
    error_type = event["record"]["errorType"]

    Logger.debug("Runtime done: #{arn} (request: #{request_id}, status: #{status})")

    # Get function state
    case :ets.lookup(@function_state_table, arn) do
      [{^arn, state}] when state.request_id == request_id ->
        # Calculate duration
        duration_ms = DateTime.diff(timestamp, state.start_time, :millisecond)

        # Update state
        updated_state = %{state |
          status: if(status == "success", do: :completed, else: :error),
          end_time: timestamp,
          duration_ms: duration_ms,
          error_type: error_type
        }

        :ets.insert(@function_state_table, {arn, updated_state})

        # Check against baseline (if available)
        case BehavioralBaseline.get_baseline(arn) do
          {:ok, baseline} when baseline.status == :active ->
            # Check for duration anomaly
            if baseline.duration_mean && baseline.duration_std && baseline.duration_std > 0 do
              z_score = (duration_ms - baseline.duration_mean) / baseline.duration_std

              if abs(z_score) > 3.0 do
                severity = if abs(z_score) > 5.0, do: "critical", else: "high"

                Alerts.create_alert(%{
                  title: "Lambda Execution Duration Anomaly",
                  description: """
                  Function: #{arn}
                  Request ID: #{request_id}

                  Execution duration (#{duration_ms}ms) deviates significantly from baseline.

                  Baseline: #{round(baseline.duration_mean)}ms ± #{round(baseline.duration_std)}ms
                  Actual: #{duration_ms}ms
                  Z-Score: #{Float.round(z_score, 2)}

                  Possible causes:
                  - Resource hijacking (cryptomining)
                  - Infinite loops or performance degradation
                  - Unusual workload or attack in progress
                  """,
                  severity: severity,
                  category: "serverless_anomaly",
                  source: "lambda_extension_runtime",
                  mitre_techniques: ["T1496"],
                  metadata: %{
                    function_arn: arn,
                    request_id: request_id,
                    duration_ms: duration_ms,
                    baseline_mean: baseline.duration_mean,
                    baseline_std: baseline.duration_std,
                    z_score: z_score
                  }
                })
              end
            end

          _ ->
            # No baseline yet, just record
            :ok
        end

        {:ok, Map.merge(event, %{
          parsed_data: %{
            request_id: request_id,
            duration_ms: duration_ms,
            status: status,
            error_type: error_type
          }
        })}

      _ ->
        Logger.warning("Runtime done event for #{arn} without matching start event")
        {:ok, event}
    end
  end

  defp handle_platform_report(event, arn) do
    # Contains billing info, max memory used, etc.
    record = event["record"] || %{}
    metrics = record["metrics"] || %{}
    request_id = record["requestId"]

    parsed_metrics = %{
      duration_ms: metrics["durationMs"],
      billed_duration_ms: metrics["billedDurationMs"],
      memory_size_mb: metrics["memorySizeMB"],
      max_memory_used_mb: metrics["maxMemoryUsedMB"],
      init_duration_ms: metrics["initDurationMs"]
    }

    Logger.debug("Platform report for #{arn}: #{inspect(parsed_metrics)}")

    # Update state with init duration (cold start indicator)
    case :ets.lookup(@function_state_table, arn) do
      [{^arn, state}] when state.request_id == request_id ->
        is_cold_start = !is_nil(parsed_metrics.init_duration_ms)

        updated_state = %{state |
          is_cold_start: is_cold_start || state.is_cold_start,
          metrics: parsed_metrics
        }

        :ets.insert(@function_state_table, {arn, updated_state})

        # Record execution for baseline learning
        execution_data = %{
          function_id: arn,
          timestamp: state.start_time,
          duration_ms: parsed_metrics.duration_ms,
          memory_used_mb: parsed_metrics.max_memory_used_mb,
          status: state.status,
          is_cold_start: is_cold_start,
          outbound_connections: [],
          error_type: state.error_type
        }

        BehavioralBaseline.record_execution(execution_data)

        # Analyze execution against baseline
        case BehavioralBaseline.analyze_execution(execution_data) do
          {:ok, anomalies} when length(anomalies) > 0 ->
            Logger.warning("Detected #{length(anomalies)} anomalies in #{arn} execution #{request_id}")
            # Anomalies are automatically alerted by BehavioralBaseline if severity is high/critical

          {:ok, []} ->
            Logger.debug("No anomalies detected for #{arn}")

          {:error, :no_baseline} ->
            Logger.debug("No baseline yet for #{arn}, still learning")
        end

        # Check for specific anomalies in metrics
        check_platform_metrics_anomalies(arn, request_id, parsed_metrics, state)

      _ ->
        Logger.warning("Platform report for #{arn} without matching start event")
    end

    {:ok, Map.put(event, :parsed_metrics, parsed_metrics)}
  end

  defp handle_function_log(event, arn) do
    # Function stdout/stderr logs
    record = event["record"] || event
    message = record["record"] || record["message"] || ""
    request_id = extract_request_id_from_log(message)

    Logger.debug("Function log for #{arn}: #{String.slice(message, 0, 100)}")

    findings = []

    # Scan for credential exposure
    findings = findings ++ scan_for_credentials(message, arn, request_id)

    # Scan for crypto mining patterns
    findings = findings ++ scan_for_cryptomining(message, arn, request_id)

    # Scan for error patterns indicating attacks
    findings = findings ++ scan_for_attack_patterns(message, arn, request_id)

    # Generate alerts for findings
    Enum.each(findings, fn finding ->
      Alerts.create_alert(%{
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
        category: "serverless_security",
        source: "lambda_extension_log",
        mitre_techniques: finding.mitre_techniques,
        metadata: Map.merge(finding.metadata, %{
          function_arn: arn,
          request_id: request_id
        })
      })
    end)

    {:ok, Map.merge(event, %{
      parsed_data: %{
        message: message,
        request_id: request_id,
        findings_count: length(findings)
      }
    })}
  end

  # Helper functions for event handlers

  defp parse_event_timestamp(nil), do: DateTime.utc_now()
  defp parse_event_timestamp(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> DateTime.utc_now()
    end
  end
  defp parse_event_timestamp(%DateTime{} = dt), do: dt
  defp parse_event_timestamp(_), do: DateTime.utc_now()

  defp extract_request_id_from_log(message) do
    case Regex.run(~r/RequestId:\s*([\w-]+)/, message) do
      [_, id] -> id
      _ -> nil
    end
  end

  defp check_platform_metrics_anomalies(arn, request_id, metrics, _state) do
    _findings = []

    # Check for excessive memory usage (>90% of allocated)
    if metrics.max_memory_used_mb && metrics.memory_size_mb do
      memory_usage_pct = metrics.max_memory_used_mb / metrics.memory_size_mb * 100

      if memory_usage_pct > 90 do
        Alerts.create_alert(%{
          title: "Lambda High Memory Usage",
          description: """
          Function: #{arn}
          Request ID: #{request_id}

          Memory usage reached #{round(memory_usage_pct)}% of allocated memory.

          Allocated: #{metrics.memory_size_mb}MB
          Used: #{metrics.max_memory_used_mb}MB

          This could indicate:
          - Memory leak
          - Resource exhaustion attack
          - Cryptomining activity
          - Insufficient memory allocation
          """,
          severity: if(memory_usage_pct > 95, do: "critical", else: "high"),
          category: "serverless_anomaly",
          source: "lambda_extension_platform",
          mitre_techniques: ["T1496"],
          metadata: %{
            function_arn: arn,
            request_id: request_id,
            memory_used_mb: metrics.max_memory_used_mb,
            memory_size_mb: metrics.memory_size_mb,
            usage_percentage: memory_usage_pct
          }
        })
      end
    end

    # Check for unusually long cold start (>3 seconds)
    if metrics.init_duration_ms && metrics.init_duration_ms > 3000 do
      Alerts.create_alert(%{
        title: "Lambda Unusually Long Cold Start",
        description: """
        Function: #{arn}
        Request ID: #{request_id}

        Cold start initialization took #{metrics.init_duration_ms}ms (>3s).

        This could indicate:
        - Downloading external resources during init
        - Crypto miner initialization
        - Malicious code injection during container startup
        - Large deployment package
        """,
        severity: "medium",
        category: "serverless_anomaly",
        source: "lambda_extension_platform",
        mitre_techniques: ["T1204.003"],
        metadata: %{
          function_arn: arn,
          request_id: request_id,
          init_duration_ms: metrics.init_duration_ms
        }
      })
    end

    :ok
  end

  defp scan_for_credentials(message, arn, request_id) do
    credential_patterns = [
      {~r/AWS_SECRET_ACCESS_KEY\s*[=:]\s*[\'\"]?([A-Za-z0-9\/+=]{40})[\'\"]?/i, "AWS Secret Access Key"},
      {~r/AKIA[0-9A-Z]{16}/i, "AWS Access Key ID"},
      {~r/password\s*[=:]\s*[\'\"]([^\'\"]+)[\'\"]?/i, "Hardcoded Password"},
      {~r/api[_-]?key\s*[=:]\s*[\'\"]([^\'\"]+)[\'\"]?/i, "API Key"},
      {~r/private[_-]?key\s*[=:]/i, "Private Key"},
      {~r/-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/i, "Private Key Block"},
      {~r/sk_live_[a-zA-Z0-9]{24,}/i, "Stripe Secret Key"},
      {~r/ghp_[a-zA-Z0-9]{36}/i, "GitHub Personal Access Token"},
      {~r/xox[baprs]-[a-zA-Z0-9-]+/i, "Slack Token"}
    ]

    Enum.flat_map(credential_patterns, fn {pattern, cred_type} ->
      if Regex.match?(pattern, message) do
        [%{
          title: "Lambda Credential Exposure: #{cred_type}",
          description: """
          Function: #{arn}
          Request ID: #{request_id || "unknown"}

          #{cred_type} detected in function logs. This is a critical security issue.

          Log message: #{String.slice(message, 0, 200)}

          Immediate actions:
          1. Rotate the exposed credential immediately
          2. Review function code for hardcoded secrets
          3. Use AWS Secrets Manager or Parameter Store
          4. Enable CloudWatch Logs encryption
          """,
          severity: "critical",
          mitre_techniques: ["T1552.001", "T1552.004"],
          metadata: %{
            credential_type: cred_type,
            pattern_matched: true
          }
        }]
      else
        []
      end
    end)
  end

  defp scan_for_cryptomining(message, arn, request_id) do
    mining_patterns = [
      {~r/xmrig|xmr-stak|minerd|cgminer|bfgminer/i, "Cryptocurrency Miner Binary"},
      {~r/stratum\+tcp:\/\//i, "Mining Pool Connection"},
      {~r/--donate-level|--coin=|--algo=/i, "Mining Configuration"},
      {~r/cryptonight|randomx|ethash/i, "Mining Algorithm"},
      {~r/hashrate|shares accepted|difficulty/i, "Mining Activity Log"},
      {~r/pool\..*\..*:\d{4,5}/i, "Mining Pool Domain"}
    ]

    Enum.flat_map(mining_patterns, fn {pattern, description} ->
      if Regex.match?(pattern, message) do
        [%{
          title: "Lambda Cryptomining Detected: #{description}",
          description: """
          Function: #{arn}
          Request ID: #{request_id || "unknown"}

          Cryptocurrency mining activity detected in function logs.

          Pattern: #{description}
          Log message: #{String.slice(message, 0, 200)}

          This indicates:
          - Resource hijacking for cryptocurrency mining
          - Compromised function or dependency
          - Unauthorized code execution

          Recommended actions:
          1. Terminate the function immediately
          2. Review function code and dependencies
          3. Check for supply chain compromise
          4. Review IAM role permissions
          5. Analyze CloudTrail logs for unauthorized changes
          """,
          severity: "critical",
          mitre_techniques: ["T1496"],
          metadata: %{
            mining_pattern: description
          }
        }]
      else
        []
      end
    end)
  end

  defp scan_for_attack_patterns(message, arn, request_id) do
    attack_patterns = [
      {~r/(exec|eval|shell_exec|system)\s*\(/i, "Code Execution", "T1059", "high"},
      {~r/child_process\.(exec|spawn|fork)/i, "Process Spawning", "T1059", "high"},
      {~r/nc\s+-.*\d+|netcat/i, "Netcat Usage", "T1571", "critical"},
      {~r/bash\s+-i\s+>&\s*\/dev\/tcp/i, "Reverse Shell", "T1059", "critical"},
      {~r/curl\s+.*\|\s*bash/i, "Download and Execute", "T1105", "critical"},
      {~r/wget\s+.*\|\s*sh/i, "Download and Execute", "T1105", "critical"},
      {~r/\/etc\/(passwd|shadow)/i, "Sensitive File Access", "T1003", "high"},
      {~r/\.ssh\/id_rsa/i, "SSH Key Access", "T1552.004", "high"},
      {~r/base64\s+-d|atob\(/i, "Base64 Decoding", "T1140", "medium"},
      {~r/\\x[0-9a-f]{2}/i, "Hex-Encoded Payload", "T1027", "medium"},
      {~r/ECONNREFUSED.*:(4444|5555|6666|7777|8888|9999)/i, "C2 Connection Attempt", "T1071", "critical"},
      {~r/permission denied.*\/root/i, "Privilege Escalation Attempt", "T1068", "high"}
    ]

    Enum.flat_map(attack_patterns, fn {pattern, description, technique, severity} ->
      if Regex.match?(pattern, message) do
        [%{
          title: "Lambda Attack Pattern: #{description}",
          description: """
          Function: #{arn}
          Request ID: #{request_id || "unknown"}

          Attack pattern detected in function logs: #{description}

          Log message: #{String.slice(message, 0, 300)}

          This may indicate:
          - Active exploitation attempt
          - Compromised function or dependency
          - Malicious code execution
          """,
          severity: severity,
          mitre_techniques: [technique],
          metadata: %{
            attack_pattern: description,
            technique: technique
          }
        }]
      else
        []
      end
    end)
  end

  defp handle_network_event(event, arn) do
    # Network connection from extension monitor
    connection = %{
      destination_ip: event["destination_ip"],
      destination_port: event["destination_port"],
      destination_domain: event["destination_domain"],
      protocol: event["protocol"],
      bytes_sent: event["bytes_sent"],
      bytes_received: event["bytes_received"],
      timestamp: event["timestamp"]
    }

    Logger.info("Network connection from #{arn}: #{connection.destination_ip}:#{connection.destination_port}")

    # Cross-reference against threat intelligence
    threat_intel_results = check_network_threat_intel(connection, arn)

    # Check against known suspicious patterns
    pattern_results = check_network_patterns(connection, arn)

    all_findings = threat_intel_results ++ pattern_results

    # Generate alerts for any findings
    Enum.each(all_findings, fn finding ->
      TamanduaServer.Alerts.create_alert(%{
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
        category: "serverless_security",
        source: "lambda_extension_network",
        mitre_techniques: finding.mitre_techniques,
        metadata: Map.merge(finding.metadata, %{
          function_arn: arn,
          destination_ip: connection.destination_ip,
          destination_port: connection.destination_port,
          destination_domain: connection.destination_domain
        })
      })
    end)

    enriched_event = event
    |> Map.put(:parsed_connection, connection)
    |> Map.put(:threat_intel_findings, threat_intel_results)
    |> Map.put(:pattern_findings, pattern_results)

    {:ok, enriched_event}
  end

  @doc false
  defp check_network_threat_intel(connection, arn) do
    findings = []

    # Check destination IP against threat intel
    findings = if connection.destination_ip do
      case TamanduaServer.ThreatIntel.lookup(:ip, connection.destination_ip) do
        {:ok, ioc} ->
          severity = ioc[:severity] || ioc["severity"] || "high"
          source = ioc[:source] || ioc["source"] || "threat_intel"
          tags = ioc[:tags] || ioc["tags"] || []
          description_detail = ioc[:description] || ioc["description"] || "No additional context"

          [%{
            title: "Lambda C2/Malicious IP Connection: #{connection.destination_ip}",
            description: """
            Lambda function #{arn} connected to known malicious IP #{connection.destination_ip}:#{connection.destination_port}.
            Threat Intel Source: #{source}
            Tags: #{Enum.join(List.wrap(tags), ", ")}
            Detail: #{description_detail}
            Protocol: #{connection.protocol}
            Bytes sent: #{connection.bytes_sent || "unknown"}, received: #{connection.bytes_received || "unknown"}
            """,
            severity: severity,
            mitre_techniques: ["T1071", "T1573"],
            metadata: %{
              ioc_type: :ip,
              ioc_value: connection.destination_ip,
              ioc_source: source,
              ioc_tags: tags
            }
          } | findings]

        :not_found ->
          findings
      end
    else
      findings
    end

    # Check destination domain against threat intel
    findings = if connection.destination_domain do
      case TamanduaServer.ThreatIntel.lookup(:domain, connection.destination_domain) do
        {:ok, ioc} ->
          severity = ioc[:severity] || ioc["severity"] || "high"
          source = ioc[:source] || ioc["source"] || "threat_intel"
          tags = ioc[:tags] || ioc["tags"] || []
          description_detail = ioc[:description] || ioc["description"] || "No additional context"

          [%{
            title: "Lambda C2/Malicious Domain Connection: #{connection.destination_domain}",
            description: """
            Lambda function #{arn} connected to known malicious domain #{connection.destination_domain}:#{connection.destination_port}.
            Threat Intel Source: #{source}
            Tags: #{Enum.join(List.wrap(tags), ", ")}
            Detail: #{description_detail}
            Protocol: #{connection.protocol}
            Bytes sent: #{connection.bytes_sent || "unknown"}, received: #{connection.bytes_received || "unknown"}
            """,
            severity: severity,
            mitre_techniques: ["T1071", "T1568"],
            metadata: %{
              ioc_type: :domain,
              ioc_value: connection.destination_domain,
              ioc_source: source,
              ioc_tags: tags
            }
          } | findings]

        :not_found ->
          findings
      end
    else
      findings
    end

    findings
  end

  @doc false
  defp check_network_patterns(connection, arn) do
    findings = []

    # Check for common C2 ports
    c2_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 4443, 8443, 8080]
    findings = if connection.destination_port in c2_ports do
      [%{
        title: "Lambda suspicious port connection: #{connection.destination_port}",
        description: "Lambda function #{arn} connected to port #{connection.destination_port} which is commonly associated with C2 frameworks (Metasploit, Cobalt Strike, etc.).",
        severity: "high",
        mitre_techniques: ["T1571", "T1573"],
        metadata: %{pattern: :suspicious_port, port: connection.destination_port}
      } | findings]
    else
      findings
    end

    # Check for suspicious domains in destination
    suspicious_domains = [
      "ngrok.io", "ngrok-free.app", "burpcollaborator.net", "requestbin.com",
      "pipedream.net", "webhook.site", "interact.sh", "oastify.com",
      "dnslog.cn", "ceye.io", "bxss.me"
    ]

    findings = if connection.destination_domain do
      domain = String.downcase(connection.destination_domain)
      if Enum.any?(suspicious_domains, &String.contains?(domain, &1)) do
        [%{
          title: "Lambda connection to suspicious service: #{connection.destination_domain}",
          description: "Lambda function #{arn} connected to #{connection.destination_domain} which is a known tunneling/exfiltration service.",
          severity: "critical",
          mitre_techniques: ["T1041", "T1567"],
          metadata: %{pattern: :suspicious_domain, domain: connection.destination_domain}
        } | findings]
      else
        findings
      end
    else
      findings
    end

    # Check for DNS exfiltration patterns (high entropy subdomains)
    findings = if connection.destination_domain do
      parts = String.split(connection.destination_domain, ".")
      subdomain = List.first(parts) || ""

      if String.length(subdomain) > 30 and high_entropy?(subdomain) do
        [%{
          title: "Lambda possible DNS exfiltration: #{connection.destination_domain}",
          description: "Lambda function #{arn} resolved a domain with a high-entropy subdomain (#{String.length(subdomain)} chars), which may indicate DNS tunneling or data exfiltration.",
          severity: "high",
          mitre_techniques: ["T1048.003", "T1568.002"],
          metadata: %{pattern: :dns_exfiltration, domain: connection.destination_domain, subdomain_length: String.length(subdomain)}
        } | findings]
      else
        findings
      end
    else
      findings
    end

    # Check for unusual data ratios (more upload than download may indicate exfil)
    findings = if connection.bytes_sent && connection.bytes_received &&
                  connection.bytes_sent > 0 && connection.bytes_received > 0 do
      ratio = connection.bytes_sent / max(connection.bytes_received, 1)
      if ratio > 10 and connection.bytes_sent > 1_000_000 do
        [%{
          title: "Lambda data exfiltration pattern: high upload ratio",
          description: "Lambda function #{arn} sent #{format_bytes(connection.bytes_sent)} but received only #{format_bytes(connection.bytes_received)} (ratio: #{Float.round(ratio, 1)}:1). This upload-heavy pattern may indicate data exfiltration.",
          severity: "high",
          mitre_techniques: ["T1041", "T1567"],
          metadata: %{pattern: :exfil_ratio, bytes_sent: connection.bytes_sent, bytes_received: connection.bytes_received, ratio: ratio}
        } | findings]
      else
        findings
      end
    else
      findings
    end

    findings
  end

  defp high_entropy?(string) when byte_size(string) > 0 do
    # Calculate Shannon entropy of the string
    freqs = string
    |> String.downcase()
    |> String.graphemes()
    |> Enum.frequencies()

    len = String.length(string)

    entropy = freqs
    |> Enum.reduce(0.0, fn {_char, count}, acc ->
      p = count / len
      if p > 0, do: acc - p * :math.log2(p), else: acc
    end)

    # High entropy threshold (random strings typically > 3.5 bits/char)
    entropy > 3.5
  end
  defp high_entropy?(_), do: false

  defp format_bytes(bytes) when bytes >= 1_073_741_824, do: "#{Float.round(bytes / 1_073_741_824, 1)} GB"
  defp format_bytes(bytes) when bytes >= 1_048_576, do: "#{Float.round(bytes / 1_048_576, 1)} MB"
  defp format_bytes(bytes) when bytes >= 1024, do: "#{Float.round(bytes / 1024, 1)} KB"
  defp format_bytes(bytes), do: "#{bytes} B"

  defp handle_file_event(event, arn) do
    # File access from extension monitor
    file_event = %{
      path: event["path"],
      operation: event["operation"],
      success: event["success"],
      hash_sha256: event["hash_sha256"]
    }

    Logger.info("File #{file_event.operation} by #{arn}: #{file_event.path}")

    # Check for suspicious file access patterns
    file_findings = check_file_patterns(file_event, arn)

    # Cross-reference file hashes against threat intel
    hash_findings = check_file_hash_threat_intel(file_event, arn)

    all_findings = file_findings ++ hash_findings

    Enum.each(all_findings, fn finding ->
      TamanduaServer.Alerts.create_alert(%{
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
        category: "serverless_security",
        source: "lambda_extension_file",
        mitre_techniques: finding.mitre_techniques,
        metadata: Map.merge(finding.metadata, %{
          function_arn: arn,
          file_path: file_event.path,
          file_operation: file_event.operation
        })
      })
    end)

    enriched_event = event
    |> Map.put(:parsed_file_event, file_event)
    |> Map.put(:threat_findings, all_findings)

    {:ok, enriched_event}
  end

  defp check_file_patterns(file_event, arn) do
    path = file_event.path || ""
    operation = file_event.operation || ""

    _findings = []

    # Check for sensitive file access
    sensitive_paths = [
      {"/etc/passwd", "Password file access", "T1003"},
      {"/etc/shadow", "Shadow file access", "T1003"},
      {"/.ssh/", "SSH key access", "T1552.004"},
      {"/root/", "Root directory access", "T1083"},
      {"/.aws/credentials", "AWS credentials file access", "T1552.001"},
      {"/.aws/config", "AWS config access", "T1552.001"},
      {"/proc/self/environ", "Process environment access (credential harvesting)", "T1552"},
      {"/var/runtime/", "Lambda runtime access", "T1083"},
      {"/var/task/", "Lambda function code access", "T1005"}
    ]

    findings = Enum.flat_map(sensitive_paths, fn {sensitive_path, description, technique} ->
      if String.contains?(path, sensitive_path) do
        [%{
          title: "Lambda sensitive file access: #{description}",
          description: "Lambda function #{arn} performed #{operation} on #{path}. #{description}.",
          severity: "high",
          mitre_techniques: [technique],
          metadata: %{pattern: :sensitive_file, path: path}
        }]
      else
        []
      end
    end)

    # Check for suspicious file writes to /tmp (staging area for attacks)
    findings = if String.starts_with?(path, "/tmp/") and operation in ["write", "create"] do
      suspicious_extensions = [".sh", ".py", ".pl", ".rb", ".so", ".elf", ".bin", ".exe"]
      if Enum.any?(suspicious_extensions, &String.ends_with?(path, &1)) do
        [%{
          title: "Lambda suspicious file write to /tmp",
          description: "Lambda function #{arn} wrote a potentially executable file to #{path}. Attackers commonly stage tools in /tmp.",
          severity: "high",
          mitre_techniques: ["T1059", "T1105"],
          metadata: %{pattern: :suspicious_tmp_write, path: path}
        } | findings]
      else
        findings
      end
    else
      findings
    end

    findings
  end

  defp check_file_hash_threat_intel(file_event, arn) do
    if file_event.hash_sha256 do
      case TamanduaServer.ThreatIntel.lookup(:hash_sha256, file_event.hash_sha256) do
        {:ok, ioc} ->
          severity = ioc[:severity] || ioc["severity"] || "critical"
          source = ioc[:source] || ioc["source"] || "threat_intel"
          tags = ioc[:tags] || ioc["tags"] || []
          description_detail = ioc[:description] || ioc["description"] || "Known malicious file"

          [%{
            title: "Lambda malicious file detected: #{file_event.path}",
            description: """
            Lambda function #{arn} loaded/accessed a file matching known malicious hash.
            Path: #{file_event.path}
            SHA256: #{file_event.hash_sha256}
            Threat Intel Source: #{source}
            Tags: #{Enum.join(List.wrap(tags), ", ")}
            Detail: #{description_detail}
            """,
            severity: severity,
            mitre_techniques: ["T1204.003", "T1059"],
            metadata: %{
              ioc_type: :hash_sha256,
              ioc_value: file_event.hash_sha256,
              ioc_source: source,
              ioc_tags: tags,
              file_path: file_event.path
            }
          }]

        :not_found ->
          []
      end
    else
      []
    end
  end

  defp handle_process_event(event, arn) do
    # Child process spawn from extension monitor
    process_event = %{
      command: event["command"],
      args: event["args"],
      pid: event["pid"],
      ppid: event["ppid"],
      uid: event["uid"]
    }

    Logger.warning("Process spawn by #{arn}: #{process_event.command} #{Enum.join(process_event.args || [], " ")}")

    # Check for reverse shells and suspicious commands
    process_findings = check_process_patterns(process_event, arn)

    Enum.each(process_findings, fn finding ->
      TamanduaServer.Alerts.create_alert(%{
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
        category: "serverless_security",
        source: "lambda_extension_process",
        mitre_techniques: finding.mitre_techniques,
        metadata: Map.merge(finding.metadata, %{
          function_arn: arn,
          command: process_event.command,
          args: process_event.args
        })
      })
    end)

    enriched_event = event
    |> Map.put(:parsed_process_event, process_event)
    |> Map.put(:process_findings, process_findings)

    {:ok, enriched_event}
  end

  defp check_process_patterns(process_event, arn) do
    command = process_event.command || ""
    args = process_event.args || []
    full_command = "#{command} #{Enum.join(args, " ")}"

    findings = []

    # Check for reverse shell patterns
    reverse_shell_patterns = [
      {~r/\bnc\b.*-e\s*(\/bin\/sh|\/bin\/bash|sh|bash)/i, "Netcat reverse shell"},
      {~r/bash\s+-i\s+>&\s*\/dev\/tcp/i, "Bash reverse shell via /dev/tcp"},
      {~r/python.*socket.*connect.*exec/i, "Python reverse shell"},
      {~r/perl.*socket.*INET/i, "Perl reverse shell"},
      {~r/ruby.*TCPSocket/i, "Ruby reverse shell"},
      {~r/php.*fsockopen.*exec/i, "PHP reverse shell"},
      {~r/mkfifo.*\/tmp\/.*nc\s/i, "Named pipe reverse shell"},
      {~r/socat.*exec.*tcp/i, "Socat reverse shell"}
    ]

    findings = Enum.flat_map(reverse_shell_patterns, fn {pattern, description} ->
      if Regex.match?(pattern, full_command) do
        [%{
          title: "Lambda reverse shell detected: #{description}",
          description: "Lambda function #{arn} spawned a process matching reverse shell pattern: #{description}. Command: #{String.slice(full_command, 0, 200)}",
          severity: "critical",
          mitre_techniques: ["T1059", "T1571"],
          metadata: %{pattern: :reverse_shell, description: description}
        }]
      else
        []
      end
    end) ++ findings

    # Check for crypto mining
    mining_patterns = [
      {~r/xmrig|xmr-stak|minerd|cgminer|bfgminer/i, "Cryptocurrency miner binary"},
      {~r/stratum\+tcp/i, "Mining pool protocol"},
      {~r/--donate-level|--coin=|--algo=/i, "Mining configuration flags"}
    ]

    findings = Enum.flat_map(mining_patterns, fn {pattern, description} ->
      if Regex.match?(pattern, full_command) do
        [%{
          title: "Lambda cryptomining detected: #{description}",
          description: "Lambda function #{arn} spawned a process matching cryptocurrency mining pattern. Command: #{String.slice(full_command, 0, 200)}",
          severity: "critical",
          mitre_techniques: ["T1496"],
          metadata: %{pattern: :cryptominer, description: description}
        }]
      else
        []
      end
    end) ++ findings

    # Check for data exfiltration tools
    exfil_patterns = [
      {~r/curl\s+.*-[dX]\s*POST/i, "Curl POST (possible data exfiltration)"},
      {~r/wget\s+.*--post-data/i, "Wget POST (possible data exfiltration)"},
      {~r/curl\s+.*\|\s*(ba)?sh/i, "Curl pipe to shell (download and execute)"},
      {~r/wget\s+.*-O\s*-\s*\|\s*(ba)?sh/i, "Wget pipe to shell (download and execute)"}
    ]

    findings = Enum.flat_map(exfil_patterns, fn {pattern, description} ->
      if Regex.match?(pattern, full_command) do
        [%{
          title: "Lambda suspicious command: #{description}",
          description: "Lambda function #{arn} spawned: #{description}. Command: #{String.slice(full_command, 0, 200)}",
          severity: "high",
          mitre_techniques: ["T1041", "T1059"],
          metadata: %{pattern: :exfiltration_tool, description: description}
        }]
      else
        []
      end
    end) ++ findings

    # Any child process spawning in Lambda is suspicious by default
    if findings == [] and command != "" do
      [%{
        title: "Lambda child process spawned",
        description: "Lambda function #{arn} spawned child process: #{String.slice(full_command, 0, 200)}. Child process execution in Lambda is unusual and should be reviewed.",
        severity: "medium",
        mitre_techniques: ["T1059"],
        metadata: %{pattern: :child_process}
      }]
    else
      findings
    end
  end

  defp handle_memory_scan(event, arn) do
    # Memory scan results from extension
    scan_result = %{
      threats_found: event["threats_found"] || 0,
      signatures_matched: event["signatures_matched"] || [],
      scan_duration_ms: event["scan_duration_ms"],
      libraries_loaded: event["libraries_loaded"] || []
    }

    findings = []

    # Check for memory-resident threats
    findings = if scan_result.threats_found > 0 do
      Logger.error("Memory scan threats in #{arn}: #{inspect(scan_result.signatures_matched)}")

      [%{
        title: "Lambda memory threat detected",
        description: """
        Lambda function #{arn} memory scan found #{scan_result.threats_found} threat(s).
        Matched signatures: #{Enum.join(scan_result.signatures_matched, ", ")}
        Scan duration: #{scan_result.scan_duration_ms}ms
        """,
        severity: "critical",
        mitre_techniques: ["T1055", "T1204.003"],
        metadata: %{
          threats_found: scan_result.threats_found,
          signatures: scan_result.signatures_matched
        }
      } | findings]
    else
      findings
    end

    # Cross-reference loaded libraries against threat intel
    library_findings = check_libraries_threat_intel(scan_result.libraries_loaded, arn)
    findings = findings ++ library_findings

    # Generate alerts
    Enum.each(findings, fn finding ->
      TamanduaServer.Alerts.create_alert(%{
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
        category: "serverless_security",
        source: "lambda_extension_memory",
        mitre_techniques: finding.mitre_techniques,
        metadata: Map.merge(finding.metadata, %{function_arn: arn})
      })
    end)

    enriched_event = event
    |> Map.put(:parsed_scan_result, scan_result)
    |> Map.put(:memory_findings, findings)

    {:ok, enriched_event}
  end

  @doc false
  defp check_libraries_threat_intel(libraries, arn) when is_list(libraries) do
    Enum.flat_map(libraries, fn lib ->
      hash = lib["hash_sha256"] || lib[:hash_sha256]
      path = lib["path"] || lib[:path] || "unknown"
      name = lib["name"] || lib[:name] || Path.basename(path)

      if hash do
        case TamanduaServer.ThreatIntel.lookup(:hash_sha256, hash) do
          {:ok, ioc} ->
            severity = ioc[:severity] || ioc["severity"] || "critical"
            source = ioc[:source] || ioc["source"] || "threat_intel"
            tags = ioc[:tags] || ioc["tags"] || []

            [%{
              title: "Lambda malicious library detected: #{name}",
              description: """
              Lambda function #{arn} loaded library matching known malicious hash.
              Library: #{name}
              Path: #{path}
              SHA256: #{hash}
              Threat Intel Source: #{source}
              Tags: #{Enum.join(List.wrap(tags), ", ")}
              """,
              severity: severity,
              mitre_techniques: ["T1055", "T1129"],
              metadata: %{
                ioc_type: :hash_sha256,
                ioc_value: hash,
                ioc_source: source,
                library_name: name,
                library_path: path
              }
            }]

          :not_found ->
            []
        end
      else
        []
      end
    end)
  end
  defp check_libraries_threat_intel(_, _), do: []

  @doc """
  Generate extension deployment package info.
  Returns instructions for deploying the Tamandua Lambda extension.
  """
  @spec deployment_instructions() :: map()
  def deployment_instructions do
    %{
      layer_arn: "arn:aws:lambda:REGION:ACCOUNT:layer:tamandua-extension:VERSION",
      supported_runtimes: [
        "python3.9", "python3.10", "python3.11", "python3.12",
        "nodejs18.x", "nodejs20.x",
        "java11", "java17", "java21",
        "dotnet6", "dotnet8",
        "ruby3.2",
        "provided.al2", "provided.al2023"
      ],
      environment_variables: %{
        "TAMANDUA_SERVER_URL" => "https://your-tamandua-server.com",
        "TAMANDUA_API_KEY" => "your-api-key",
        "TAMANDUA_LOG_LEVEL" => "info"
      },
      deployment_steps: [
        "1. Add the Tamandua extension layer to your Lambda function",
        "2. Configure environment variables for server connection",
        "3. Ensure function has outbound network access to Tamandua server",
        "4. (Optional) Increase function timeout to allow for extension overhead",
        "5. (Optional) Increase memory if enabling memory scanning"
      ],
      terraform_example: """
      resource "aws_lambda_function" "example" {
        # ... other configuration ...

        layers = [
          "arn:aws:lambda:us-east-1:123456789012:layer:tamandua-extension:1"
        ]

        environment {
          variables = {
            TAMANDUA_SERVER_URL = "https://tamandua.example.com"
            TAMANDUA_API_KEY    = var.tamandua_api_key
          }
        }
      }
      """,
      sam_example: """
      Resources:
        MyFunction:
          Type: AWS::Serverless::Function
          Properties:
            # ... other properties ...
            Layers:
              - arn:aws:lambda:us-east-1:123456789012:layer:tamandua-extension:1
            Environment:
              Variables:
                TAMANDUA_SERVER_URL: https://tamandua.example.com
                TAMANDUA_API_KEY: !Ref TamanduaApiKey
      """
    }
  end
end
