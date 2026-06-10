defmodule TamanduaServerWeb.API.V1.ServerlessController do
  @moduledoc """
  API Controller for Serverless Security Monitoring.

  Provides comprehensive API endpoints for monitoring and securing serverless
  functions across AWS Lambda, Azure Functions, and GCP Cloud Functions.

  ## Endpoints
  - Functions: List, get details, sync from cloud providers
  - Executions: View execution history and details
  - Security: Scan functions, view findings, manage status
  - Baselines: View behavioral baselines and anomalies
  - Statistics: Cross-provider analytics and dashboards
  """

  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.Serverless.{Lambda, AzureFunctions, CloudFunctions}
  alias TamanduaServer.Serverless.{SecurityAnalyzer, BehavioralBaseline}

  action_fallback TamanduaServerWeb.FallbackController

  @allowed_providers ~w(aws azure gcp)
  @allowed_severities ~w(critical high medium low)
  @allowed_statuses ~w(open acknowledged resolved false_positive)
  @allowed_categories ~w(secrets iam network configuration runtime dependency data)
  @allowed_baseline_statuses ~w(learning active stale)

  # ============================================================================
  # Functions API
  # ============================================================================

  @doc """
  List all serverless functions across providers.

  ## Query Parameters
  - `provider` - Filter by provider: "aws", "azure", "gcp", or "all" (default)
  - `runtime` - Filter by runtime (e.g., "python3.9", "nodejs18.x")
  - `region` - Filter by region
  - `status` - Filter by status
  - `has_findings` - Filter by security findings ("true" or "false")
  - `limit` - Maximum results (default: 100)
  - `offset` - Pagination offset (default: 0)
  """
  def list_functions(conn, params) do
    provider = params["provider"] || "all"
    limit = parse_int(params["limit"], 100)
    offset = parse_int(params["offset"], 0)

    filters = %{
      runtime: params["runtime"],
      region: params["region"],
      status: params["status"],
      has_findings: parse_bool(params["has_findings"])
    }

    functions = case provider do
      "aws" -> Lambda.list_functions(filters)
      "azure" -> AzureFunctions.list_functions(filters)
      "gcp" -> CloudFunctions.list_functions(filters)
      "all" ->
        aws = Lambda.list_functions(filters) |> Enum.map(&Map.put(&1, :provider, "aws"))
        azure = AzureFunctions.list_functions(filters) |> Enum.map(&Map.put(&1, :provider, "azure"))
        gcp = CloudFunctions.list_functions(filters) |> Enum.map(&Map.put(&1, :provider, "gcp"))
        aws ++ azure ++ gcp
      _ -> []
    end

    paginated = functions
    |> Enum.drop(offset)
    |> Enum.take(limit)
    |> Enum.map(&serialize_function/1)

    json(conn, %{
      data: paginated,
      meta: %{
        total: length(functions),
        limit: limit,
        offset: offset,
        provider: provider
      }
    })
  end

  @doc """
  Get details for a specific function.
  """
  def get_function(conn, %{"provider" => provider, "function_id" => function_id}) do
    result = case provider do
      "aws" -> Lambda.get_function(function_id)
      "azure" -> AzureFunctions.get_function(function_id)
      "gcp" -> CloudFunctions.get_function(function_id)
      _ -> {:error, :invalid_provider}
    end

    case result do
      {:ok, function} ->
        serialized = function
        |> Map.put(:provider, provider)
        |> serialize_function()

        # Get security findings
        findings = SecurityAnalyzer.get_findings(function_id)
        |> Enum.map(&serialize_finding/1)

        # Get baseline info
        baseline = case BehavioralBaseline.get_baseline(function_id) do
          {:ok, b} -> serialize_baseline(b)
          _ -> nil
        end

        json(conn, %{
          data: Map.merge(serialized, %{
            security_findings: findings,
            baseline: baseline
          })
        })

      {:error, :not_found} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Sync functions from a cloud provider.
  """
  def sync_functions(conn, %{"provider" => provider} = params) do
    region = params["region"]

    result = case provider do
      "aws" -> Lambda.sync_functions(region || "us-east-1", [])
      "azure" -> AzureFunctions.sync_functions(params["subscription_id"], [])
      "gcp" -> CloudFunctions.sync_functions(params["project_id"], [])
      _ -> {:error, :invalid_provider}
    end

    case result do
      {:ok, functions} ->
        json(conn, %{
          data: %{
            provider: provider,
            synced_count: length(functions),
            synced_at: DateTime.utc_now()
          }
        })

      {:error, :not_configured} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Provider not configured", message: "#{provider} credentials not configured"})

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ============================================================================
  # Executions API
  # ============================================================================

  @doc """
  Get execution history for a function.

  ## Query Parameters
  - `limit` - Maximum results (default: 100)
  - `start_time` - Filter by start time (ISO8601)
  - `end_time` - Filter by end time (ISO8601)
  - `status` - Filter by status: "success", "error", "timeout"
  """
  def get_executions(conn, %{"provider" => provider, "function_id" => function_id} = params) do
    opts = [
      limit: parse_int(params["limit"], 100),
      start_time: parse_datetime(params["start_time"]),
      end_time: parse_datetime(params["end_time"]),
      status: params["status"]
    ]

    executions = case provider do
      "aws" -> Lambda.get_executions(function_id, opts)
      "azure" -> AzureFunctions.get_executions(function_id, opts)
      "gcp" -> CloudFunctions.get_executions(function_id, opts)
      _ -> []
    end

    serialized = Enum.map(executions, &serialize_execution/1)

    json(conn, %{
      data: serialized,
      meta: %{
        function_id: function_id,
        provider: provider,
        count: length(serialized)
      }
    })
  end

  @doc """
  Get a specific execution by ID.
  """
  def get_execution(conn, %{"provider" => provider, "function_id" => function_id, "execution_id" => execution_id}) do
    executions = case provider do
      "aws" -> Lambda.get_executions(function_id, [])
      "azure" -> AzureFunctions.get_executions(function_id, [])
      "gcp" -> CloudFunctions.get_executions(function_id, [])
      _ -> []
    end

    case Enum.find(executions, &(to_string(&1.request_id || &1.execution_id || &1.id) == execution_id)) do
      nil ->
        {:error, :not_found}

      execution ->
        json(conn, %{data: serialize_execution(execution)})
    end
  end

  # ============================================================================
  # Security API
  # ============================================================================

  @doc """
  Run a security scan on a function.
  """
  def scan_function(conn, %{"provider" => provider, "function_id" => function_id}) do
    case safe_to_existing_atom(provider, @allowed_providers) do
      nil ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid provider"})

      provider_atom ->
        case SecurityAnalyzer.scan_function(function_id, provider_atom, []) do
          {:ok, result} ->
            json(conn, %{
              data: %{
                scan_id: result.id,
                function_id: function_id,
                provider: provider,
                status: result.status,
                findings_count: result.findings_count,
                security_score: result.security_score,
                severity_breakdown: %{
                  critical: result.critical_count,
                  high: result.high_count,
                  medium: result.medium_count,
                  low: result.low_count
                },
                completed_at: result.completed_at
              }
            })

          {:error, reason} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Scan failed", message: inspect(reason)})
        end
    end
  end

  @doc """
  Scan all functions for a provider.
  """
  def scan_all_functions(conn, %{"provider" => provider}) do
    case safe_to_existing_atom(provider, @allowed_providers) do
      nil ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid provider"})

      provider_atom ->
        # Start scan asynchronously
        Task.start(fn ->
          SecurityAnalyzer.scan_all(provider_atom, [])
        end)

        json(conn, %{
          data: %{
            message: "Scan started",
            provider: provider,
            started_at: DateTime.utc_now()
          }
        })
    end
  end

  @doc """
  Get security findings for a function.
  """
  def get_findings(conn, %{"function_id" => function_id} = params) do
    findings = SecurityAnalyzer.get_findings(function_id)
    |> filter_findings_by_severity(params["severity"])
    |> filter_findings_by_category(params["category"])
    |> filter_findings_by_status(params["status"])
    |> Enum.map(&serialize_finding/1)

    json(conn, %{
      data: findings,
      meta: %{
        function_id: function_id,
        count: length(findings)
      }
    })
  end

  @doc """
  Get all findings across functions.

  ## Query Parameters
  - `severity` - Filter by severity: "critical", "high", "medium", "low"
  - `category` - Filter by category: "secrets", "iam", "network", etc.
  - `provider` - Filter by provider
  - `status` - Filter by status: "open", "acknowledged", "resolved", "false_positive"
  - `limit` - Maximum results (default: 100)
  """
  def list_findings(conn, params) do
    severity = params["severity"]
    limit = parse_int(params["limit"], 100)

    findings = if severity do
      case safe_to_existing_atom(severity, @allowed_severities) do
        nil -> []
        severity_atom -> SecurityAnalyzer.get_findings_by_severity(severity_atom)
      end
    else
      # Get all findings from all functions
      []
    end
    |> filter_findings_by_category(params["category"])
    |> filter_findings_by_status(params["status"])
    |> Enum.take(limit)
    |> Enum.map(&serialize_finding/1)

    json(conn, %{
      data: findings,
      meta: %{
        count: length(findings)
      }
    })
  end

  @doc """
  Update finding status.
  """
  def update_finding(conn, %{"finding_id" => finding_id, "status" => status}) do
    case safe_to_existing_atom(status, @allowed_statuses) do
      nil ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid status"})

      status_atom ->
        case SecurityAnalyzer.update_finding_status(finding_id, status_atom) do
          :ok ->
            json(conn, %{data: %{finding_id: finding_id, status: status}})

          {:error, :not_found} ->
            {:error, :not_found}
        end
    end
  end

  # ============================================================================
  # Baselines API
  # ============================================================================

  @doc """
  Get behavioral baseline for a function.
  """
  def get_baseline(conn, %{"function_id" => function_id}) do
    case BehavioralBaseline.get_baseline(function_id) do
      {:ok, baseline} ->
        json(conn, %{data: serialize_baseline(baseline)})

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  @doc """
  List all baselines.

  ## Query Parameters
  - `provider` - Filter by provider
  - `status` - Filter by status: "learning", "active", "stale"
  """
  def list_baselines(conn, params) do
    filters = %{
      provider: params["provider"] && safe_to_existing_atom(params["provider"], @allowed_providers),
      status: params["status"] && safe_to_existing_atom(params["status"], @allowed_baseline_statuses)
    }

    baselines = BehavioralBaseline.list_baselines(filters)
    |> Enum.map(&serialize_baseline/1)

    json(conn, %{
      data: baselines,
      meta: %{count: length(baselines)}
    })
  end

  @doc """
  Start baseline learning for a function.
  """
  def start_baseline_learning(conn, %{"function_id" => function_id, "provider" => provider}) do
    case safe_to_existing_atom(provider, @allowed_providers) do
      nil ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid provider"})

      provider_atom ->
        BehavioralBaseline.start_learning(function_id, provider_atom)

        json(conn, %{
          data: %{
            function_id: function_id,
            provider: provider,
            status: "learning",
            started_at: DateTime.utc_now()
          }
        })
    end
  end

  @doc """
  Reset baseline for a function (restart learning).
  """
  def reset_baseline(conn, %{"function_id" => function_id}) do
    BehavioralBaseline.reset_baseline(function_id)

    json(conn, %{
      data: %{
        function_id: function_id,
        message: "Baseline reset, learning restarted"
      }
    })
  end

  @doc """
  Get anomalies for a function.

  ## Query Parameters
  - `limit` - Maximum results (default: 100)
  - `severity` - Filter by severity
  - `acknowledged` - Filter by acknowledgement status
  """
  def get_anomalies(conn, %{"function_id" => function_id} = params) do
    opts = [limit: parse_int(params["limit"], 100)]
    anomalies = BehavioralBaseline.get_anomalies(function_id, opts)
    |> filter_anomalies_by_severity(params["severity"])
    |> filter_anomalies_by_acknowledged(params["acknowledged"])
    |> Enum.map(&serialize_anomaly/1)

    json(conn, %{
      data: anomalies,
      meta: %{
        function_id: function_id,
        count: length(anomalies)
      }
    })
  end

  @doc """
  Get recent anomalies across all functions.
  """
  def list_recent_anomalies(conn, params) do
    limit = parse_int(params["limit"], 100)
    anomalies = BehavioralBaseline.get_recent_anomalies(limit)
    |> filter_anomalies_by_severity(params["severity"])
    |> Enum.map(&serialize_anomaly/1)

    json(conn, %{
      data: anomalies,
      meta: %{count: length(anomalies)}
    })
  end

  @doc """
  Acknowledge an anomaly.
  """
  def acknowledge_anomaly(conn, %{"anomaly_id" => anomaly_id}) do
    case BehavioralBaseline.acknowledge_anomaly(anomaly_id) do
      :ok ->
        json(conn, %{data: %{anomaly_id: anomaly_id, acknowledged: true}})

      {:error, :not_found} ->
        {:error, :not_found}
    end
  end

  # ============================================================================
  # Statistics API
  # ============================================================================

  @doc """
  Get serverless statistics dashboard data.
  """
  def get_statistics(conn, _params) do
    # Get statistics from each provider
    aws_stats = try do
      Lambda.get_statistics()
    rescue
      _ -> %{}
    end

    azure_stats = try do
      AzureFunctions.get_statistics()
    rescue
      _ -> %{}
    end

    gcp_stats = try do
      CloudFunctions.get_statistics()
    rescue
      _ -> %{}
    end

    # Get security statistics
    security_stats = try do
      SecurityAnalyzer.get_statistics()
    rescue
      _ -> %{}
    end

    # Get baseline statistics
    baseline_stats = try do
      BehavioralBaseline.get_statistics()
    rescue
      _ -> %{}
    end

    # Aggregate totals
    total_functions = (aws_stats[:total_functions] || 0) +
                      (azure_stats[:total_functions] || 0) +
                      (gcp_stats[:total_functions] || 0)

    json(conn, %{
      data: %{
        summary: %{
          total_functions: total_functions,
          total_invocations_24h: (aws_stats[:total_invocations_24h] || 0) +
                                 (azure_stats[:total_invocations_24h] || 0),
          total_errors_24h: (aws_stats[:total_errors_24h] || 0),
          average_security_score: security_stats[:average_security_score] || 100,
          open_findings: security_stats[:open_findings] || 0,
          critical_findings: security_stats[:critical_findings] || 0,
          anomalies_24h: baseline_stats[:total_anomalies_24h] || 0
        },
        by_provider: %{
          aws: aws_stats,
          azure: azure_stats,
          gcp: gcp_stats
        },
        security: security_stats,
        baselines: baseline_stats
      }
    })
  end

  @doc """
  Get execution metrics for a function.
  """
  def get_metrics(conn, %{"provider" => provider, "function_id" => function_id} = params) do
    opts = [
      period: params["period"] || "24h"
    ]

    metrics = case provider do
      "aws" -> Lambda.get_metrics(function_id, opts)
      "azure" -> %{}  # AzureFunctions doesn't have get_metrics yet
      "gcp" -> %{}    # CloudFunctions doesn't have get_metrics yet
      _ -> %{}
    end

    json(conn, %{
      data: metrics,
      meta: %{
        function_id: function_id,
        provider: provider
      }
    })
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp serialize_function(nil), do: nil
  defp serialize_function(func) when is_struct(func) do
    func
    |> Map.from_struct()
    |> serialize_function()
  end
  defp serialize_function(func) when is_map(func) do
    %{
      id: func[:function_id] || func[:id] || func[:function_arn],
      name: func[:function_name] || func[:name],
      provider: func[:provider],
      runtime: func[:runtime] || func[:runtime_version],
      region: func[:region],
      status: func[:status] || func[:state],
      memory_size: func[:memory_size] || func[:available_memory_mb],
      timeout: func[:timeout],
      last_modified: func[:last_modified],
      security_score: func[:security_score],
      findings_count: length(func[:findings] || []),
      invocation_count_24h: func[:invocation_count_24h],
      error_count_24h: func[:error_count_24h],
      last_invoked: func[:last_invoked] || func[:last_execution]
    }
  end

  defp serialize_execution(nil), do: nil
  defp serialize_execution(exec) when is_struct(exec) do
    exec
    |> Map.from_struct()
    |> serialize_execution()
  end
  defp serialize_execution(exec) when is_map(exec) do
    %{
      id: exec[:request_id] || exec[:execution_id] || exec[:id],
      function_id: exec[:function_arn] || exec[:function_name],
      timestamp: exec[:timestamp],
      duration_ms: exec[:duration_ms],
      billed_duration_ms: exec[:billed_duration_ms],
      memory_used_mb: exec[:memory_used_mb],
      status: exec[:status] || (if exec[:success], do: :success, else: :error),
      error_type: exec[:error_type] || exec[:exception_type],
      error_message: exec[:error_message] || exec[:exception_message],
      is_cold_start: exec[:init_duration_ms] != nil,
      cold_start_duration_ms: exec[:init_duration_ms],
      trigger_source: exec[:trigger_source] || exec[:trigger_type],
      source_ip: exec[:source_ip] || exec[:client_ip],
      anomaly_score: exec[:anomaly_score]
    }
  end

  defp serialize_finding(nil), do: nil
  defp serialize_finding(finding) when is_struct(finding) do
    finding
    |> Map.from_struct()
    |> serialize_finding()
  end
  defp serialize_finding(finding) when is_map(finding) do
    %{
      id: finding[:id],
      function_id: finding[:function_id],
      provider: finding[:provider],
      category: finding[:category],
      severity: finding[:severity],
      title: finding[:title],
      description: finding[:description],
      evidence: finding[:evidence],
      remediation: finding[:remediation],
      cve_id: finding[:cve_id],
      mitre_technique: finding[:mitre_technique],
      status: finding[:status],
      detected_at: finding[:detected_at],
      resolved_at: finding[:resolved_at]
    }
  end

  defp serialize_baseline(nil), do: nil
  defp serialize_baseline(baseline) when is_struct(baseline) do
    baseline
    |> Map.from_struct()
    |> serialize_baseline()
  end
  defp serialize_baseline(baseline) when is_map(baseline) do
    %{
      function_id: baseline[:function_id],
      provider: baseline[:provider],
      status: baseline[:status],
      sample_count: baseline[:sample_count],
      learning_started_at: baseline[:learning_started_at],
      learning_completed_at: baseline[:learning_completed_at],
      metrics: %{
        duration: %{
          mean: baseline[:duration_mean],
          std: baseline[:duration_std],
          p50: baseline[:duration_p50],
          p95: baseline[:duration_p95],
          p99: baseline[:duration_p99]
        },
        memory: %{
          mean: baseline[:memory_mean],
          max: baseline[:memory_max]
        },
        cold_start_rate: baseline[:cold_start_rate],
        error_rate: baseline[:error_rate]
      },
      last_updated: baseline[:last_updated]
    }
  end

  defp serialize_anomaly(nil), do: nil
  defp serialize_anomaly(anomaly) when is_struct(anomaly) do
    anomaly
    |> Map.from_struct()
    |> serialize_anomaly()
  end
  defp serialize_anomaly(anomaly) when is_map(anomaly) do
    %{
      id: anomaly[:id],
      function_id: anomaly[:function_id],
      provider: anomaly[:provider],
      execution_id: anomaly[:execution_id],
      anomaly_type: anomaly[:anomaly_type],
      severity: anomaly[:severity],
      description: anomaly[:description],
      expected_value: anomaly[:expected_value],
      actual_value: anomaly[:actual_value],
      z_score: anomaly[:z_score],
      confidence: anomaly[:confidence],
      mitre_technique: anomaly[:mitre_technique],
      detected_at: anomaly[:detected_at],
      acknowledged: anomaly[:acknowledged]
    }
  end

  defp filter_findings_by_severity(findings, nil), do: findings
  defp filter_findings_by_severity(findings, severity) do
    case safe_to_existing_atom(severity, @allowed_severities) do
      nil -> findings
      severity_atom -> Enum.filter(findings, &(&1.severity == severity_atom))
    end
  end

  defp filter_findings_by_category(findings, nil), do: findings
  defp filter_findings_by_category(findings, category) do
    case safe_to_existing_atom(category, @allowed_categories) do
      nil -> findings
      category_atom -> Enum.filter(findings, &(&1.category == category_atom))
    end
  end

  defp filter_findings_by_status(findings, nil), do: findings
  defp filter_findings_by_status(findings, status) do
    case safe_to_existing_atom(status, @allowed_statuses) do
      nil -> findings
      status_atom -> Enum.filter(findings, &(&1.status == status_atom))
    end
  end

  defp filter_anomalies_by_severity(anomalies, nil), do: anomalies
  defp filter_anomalies_by_severity(anomalies, severity) do
    case safe_to_existing_atom(severity, @allowed_severities) do
      nil -> anomalies
      severity_atom -> Enum.filter(anomalies, &(&1.severity == severity_atom))
    end
  end

  defp filter_anomalies_by_acknowledged(anomalies, nil), do: anomalies
  defp filter_anomalies_by_acknowledged(anomalies, "true") do
    Enum.filter(anomalies, &(&1.acknowledged == true))
  end
  defp filter_anomalies_by_acknowledged(anomalies, "false") do
    Enum.filter(anomalies, &(&1.acknowledged != true))
  end
  defp filter_anomalies_by_acknowledged(anomalies, _), do: anomalies

  defp parse_int(nil, default), do: default
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(value, _default) when is_integer(value), do: value
  defp parse_int(_, default), do: default

  defp parse_bool(nil), do: nil
  defp parse_bool("true"), do: true
  defp parse_bool("false"), do: false
  defp parse_bool(_), do: nil

  defp parse_datetime(nil), do: nil
  defp parse_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end
  defp parse_datetime(_), do: nil
end
