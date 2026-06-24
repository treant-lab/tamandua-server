defmodule TamanduaServerWeb.API.V1.ResponseController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Agents
  alias TamanduaServer.AuditLog
  alias TamanduaServer.Response
  alias TamanduaServer.Response.Executor
  alias TamanduaServer.Response.Remediation
  alias TamanduaServer.Response.DecisionEngine
  alias TamanduaServer.Detection.DNSAnalyzer

  action_fallback TamanduaServerWeb.FallbackController

  # Helper to authorize agent access within the current organization
  defp authorize_agent!(conn, agent_id) do
    org_id = conn.assigns[:current_organization_id]
    Agents.get_agent_for_org!(org_id, agent_id)
  end

  def kill_process(conn, %{"agent_id" => agent_id, "pid" => pid} = params) do
    user = conn.assigns[:current_user]

    # Validate agent belongs to current organization before executing action
    _agent = authorize_agent!(conn, agent_id)

    force? = truthy_param?(Map.get(params, "force", false))

    case Executor.kill_process(agent_id, pid, force: force?) do
      :ok ->
        # Log the response action
        AuditLog.log_response_action(user, "kill_process", agent_id, %{
          pid: pid,
          force: force?,
          result: "success"
        }, request_metadata(conn))
        record_response_action(conn, user, "kill_process", agent_id, params, "success", %{"message" => "Process kill command sent"})

        json(conn, %{success: true, message: "Process kill command sent"})

      {:ok, result_data} ->
        AuditLog.log_response_action(user, "kill_process", agent_id, %{
          pid: pid,
          force: force?,
          result: "success"
        }, request_metadata(conn))

        record_response_action(
          conn,
          user,
          "kill_process",
          agent_id,
          params,
          "success",
          Map.merge(%{"message" => "Process kill command sent"}, stringify_keys(result_data))
        )

        json(conn, %{success: true, message: "Process kill command sent"})

      {:error, reason} ->
        AuditLog.log_response_action(user, "kill_process", agent_id, %{
          pid: pid,
          force: force?,
          result: "failed",
          error: reason
        }, request_metadata(conn))
        record_response_action(conn, user, "kill_process", agent_id, params, "failed", nil, inspect(reason))

        conn
        |> put_status(400)
        |> json(%{success: false, error: reason})
    end
  end

  defp stringify_keys(map) when is_map(map) do
    Map.new(map, fn {key, value} -> {to_string(key), value} end)
  end

  defp stringify_keys(_), do: %{}

  defp truthy_param?(value) when value in [true, "true", "1", 1, "yes", "on"], do: true
  defp truthy_param?(_), do: false

  def quarantine_file(conn, %{"agent_id" => agent_id, "path" => path} = params) do
    user = conn.assigns[:current_user]

    # Validate agent belongs to current organization before executing action
    _agent = authorize_agent!(conn, agent_id)

    case Executor.quarantine_file(agent_id, path) do
      :ok ->
        AuditLog.log_response_action(user, "quarantine_file", agent_id, %{
          path: path,
          result: "success"
        }, request_metadata(conn))
        record_response_action(conn, user, "quarantine_file", agent_id, params, "success", %{"message" => "File quarantine command sent"})

        json(conn, %{success: true, message: "File quarantine command sent"})

      {:error, reason} ->
        AuditLog.log_response_action(user, "quarantine_file", agent_id, %{
          path: path,
          result: "failed",
          error: reason
        }, request_metadata(conn))
        record_response_action(conn, user, "quarantine_file", agent_id, params, "failed", nil, inspect(reason))

        conn
        |> put_status(400)
        |> json(%{success: false, error: reason})
    end
  end

  def collect_artifact(conn, %{"agent_id" => agent_id, "path" => path} = params) do
    artifact_type = params["type"] || "file"
    user = conn.assigns[:current_user]

    # Validate agent belongs to current organization before executing action
    _agent = authorize_agent!(conn, agent_id)

    case Executor.collect_artifact(agent_id, path, artifact_type) do
      :ok ->
        AuditLog.log_response_action(user, "collect_artifact", agent_id, %{
          path: path,
          artifact_type: artifact_type,
          result: "success"
        }, request_metadata(conn))

        json(conn, %{success: true, message: "Artifact collection command sent"})

      {:error, reason} ->
        AuditLog.log_response_action(user, "collect_artifact", agent_id, %{
          path: path,
          artifact_type: artifact_type,
          result: "failed",
          error: reason
        }, request_metadata(conn))

        conn
        |> put_status(400)
        |> json(%{success: false, error: reason})
    end
  end

  def scan_path(conn, %{"agent_id" => agent_id, "path" => path} = params) do
    user = conn.assigns[:current_user]

    # Validate agent belongs to current organization before executing action
    _agent = authorize_agent!(conn, agent_id)

    opts = [
      recursive: Map.get(params, "recursive", true),
      max_depth: Map.get(params, "max_depth", 5)
    ]

    case Executor.scan_path(agent_id, path, opts) do
      {:ok, result} ->
        AuditLog.log_response_action(user, "scan_path", agent_id, %{
          path: path,
          recursive: opts[:recursive],
          result: "success",
          files_scanned: get_in(result, ["result_data", "files_scanned"]) || 0,
          threats_found: get_in(result, ["result_data", "threats_found"]) || 0
        }, request_metadata(conn))
        record_response_action(conn, user, "scan_path", agent_id, params, "success", result)

        json(conn, %{
          success: true,
          message: "Scan completed",
          files_scanned: get_in(result, ["result_data", "files_scanned"]) || 0,
          threats_found: get_in(result, ["result_data", "threats_found"]) || 0,
          threats: get_in(result, ["result_data", "threats"]) || []
        })

      :ok ->
        AuditLog.log_response_action(user, "scan_path", agent_id, %{
          path: path,
          result: "sent"
        }, request_metadata(conn))
        record_response_action(conn, user, "scan_path", agent_id, params, "success", %{"message" => "Scan command sent"})

        json(conn, %{success: true, message: "Scan command sent"})

      {:error, reason} ->
        AuditLog.log_response_action(user, "scan_path", agent_id, %{
          path: path,
          result: "failed",
          error: reason
        }, request_metadata(conn))
        record_response_action(conn, user, "scan_path", agent_id, params, "failed", nil, inspect(reason))

        conn
        |> put_status(400)
        |> json(%{success: false, error: reason})
    end
  end

  def block_ip(conn, %{"agent_id" => agent_id, "ip" => ip} = params) do
    user = conn.assigns[:current_user]
    _agent = authorize_agent!(conn, agent_id)

    payload = %{
      ip: ip,
      direction: Map.get(params, "direction", "both"),
      reason: Map.get(params, "reason", "manual_block")
    }

    case Executor.execute_action(agent_id, "block_ip", payload) do
      {:ok, result} ->
        AuditLog.log_response_action(user, "block_ip", agent_id, Map.put(payload, :result, "success"), request_metadata(conn))
        record_response_action(conn, user, "block_ip", agent_id, params, "success", result)
        json(conn, %{success: true, message: "IP block command sent", result: result})

      {:error, reason} ->
        AuditLog.log_response_action(user, "block_ip", agent_id, Map.merge(payload, %{result: "failed", error: inspect(reason)}), request_metadata(conn))
        record_response_action(conn, user, "block_ip", agent_id, params, "failed", nil, inspect(reason))

        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  def unblock_ip(conn, %{"agent_id" => agent_id, "ip" => ip}) do
    user = conn.assigns[:current_user]
    _agent = authorize_agent!(conn, agent_id)

    payload = %{ip: ip}

    case Executor.execute_action(agent_id, "unblock_ip", payload) do
      {:ok, result} ->
        AuditLog.log_response_action(user, "unblock_ip", agent_id, Map.put(payload, :result, "success"), request_metadata(conn))
        json(conn, %{success: true, message: "IP unblock command sent", result: result})

      {:error, reason} ->
        AuditLog.log_response_action(user, "unblock_ip", agent_id, Map.merge(payload, %{result: "failed", error: inspect(reason)}), request_metadata(conn))

        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  def block_domain(conn, %{"agent_id" => agent_id, "domain" => domain} = params) do
    user = conn.assigns[:current_user]
    _agent = authorize_agent!(conn, agent_id)

    reason = Map.get(params, "reason", "manual_block")
    payload = %{domain: domain, reason: reason}

    case Executor.execute_action(agent_id, "block_domain", payload) do
      {:ok, result} ->
        DNSAnalyzer.add_to_blocklist([domain], reason, user_identifier(user), current_organization_id(conn))
        AuditLog.log_response_action(user, "block_domain", agent_id, Map.put(payload, :result, "success"), request_metadata(conn))
        record_response_action(conn, user, "block_domain", agent_id, params, "success", result)
        json(conn, %{success: true, message: "Domain block command sent", result: result})

      {:error, reason_error} ->
        AuditLog.log_response_action(user, "block_domain", agent_id, Map.merge(payload, %{result: "failed", error: inspect(reason_error)}), request_metadata(conn))
        record_response_action(conn, user, "block_domain", agent_id, params, "failed", nil, inspect(reason_error))

        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason_error)})
    end
  end

  def unblock_domain(conn, %{"agent_id" => agent_id, "domain" => domain}) do
    user = conn.assigns[:current_user]
    _agent = authorize_agent!(conn, agent_id)

    payload = %{domain: domain}

    case Executor.execute_action(agent_id, "unblock_domain", payload) do
      {:ok, result} ->
        DNSAnalyzer.remove_from_blocklist(domain, current_organization_id(conn))
        AuditLog.log_response_action(user, "unblock_domain", agent_id, Map.put(payload, :result, "success"), request_metadata(conn))
        json(conn, %{success: true, message: "Domain unblock command sent", result: result})

      {:error, reason} ->
        AuditLog.log_response_action(user, "unblock_domain", agent_id, Map.merge(payload, %{result: "failed", error: inspect(reason)}), request_metadata(conn))

        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  # VSS Snapshot endpoints

  @doc """
  Create a VSS snapshot on an agent.
  POST /api/v1/agents/:id/snapshots
  """
  def create_snapshot(conn, %{"id" => agent_id} = params) do
    volume = Map.get(params, "volume", "C:")
    user = conn.assigns[:current_user]

    # Validate agent belongs to current organization before executing action
    _agent = authorize_agent!(conn, agent_id)

    case Remediation.create_snapshot(agent_id, volume) do
      {:ok, result} ->
        AuditLog.log_response_action(user, "create_snapshot", agent_id, %{
          volume: volume,
          result: "success"
        }, request_metadata(conn))

        json(conn, %{
          success: true,
          message: "Snapshot created",
          snapshot: result["snapshot"] || result
        })

      {:error, reason} ->
        AuditLog.log_response_action(user, "create_snapshot", agent_id, %{
          volume: volume,
          result: "failed",
          error: inspect(reason)
        }, request_metadata(conn))

        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  List VSS snapshots on an agent.
  GET /api/v1/agents/:id/snapshots
  """
  def list_snapshots(conn, %{"id" => agent_id} = params) do
    volume = Map.get(params, "volume", "C:")

    # Validate agent belongs to current organization before executing action
    _agent = authorize_agent!(conn, agent_id)

    case Remediation.list_snapshots(agent_id, volume) do
      {:ok, result} ->
        json(conn, %{
          success: true,
          snapshots: result["snapshots"] || [],
          count: result["count"] || 0,
          volume: volume
        })

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  Delete a VSS snapshot on an agent.
  DELETE /api/v1/agents/:id/snapshots/:snapshot_id
  """
  def delete_snapshot(conn, %{"id" => agent_id, "snapshot_id" => snapshot_id}) do
    user = conn.assigns[:current_user]

    # Validate agent belongs to current organization before executing action
    _agent = authorize_agent!(conn, agent_id)

    case Remediation.delete_snapshot(agent_id, snapshot_id) do
      {:ok, _result} ->
        AuditLog.log_response_action(user, "delete_snapshot", agent_id, %{
          snapshot_id: snapshot_id,
          result: "success"
        }, request_metadata(conn))

        json(conn, %{
          success: true,
          message: "Snapshot deleted",
          snapshot_id: snapshot_id
        })

      {:error, reason} ->
        AuditLog.log_response_action(user, "delete_snapshot", agent_id, %{
          snapshot_id: snapshot_id,
          result: "failed",
          error: inspect(reason)
        }, request_metadata(conn))

        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  Restore file(s) from a VSS snapshot.
  POST /api/v1/agents/:id/restore
  """
  def restore_files(conn, %{"id" => agent_id, "snapshot_id" => snapshot_id} = params) do
    user = conn.assigns[:current_user]

    # Validate agent belongs to current organization before executing action
    _agent = authorize_agent!(conn, agent_id)

    # Single file or multiple files
    case params do
      %{"file_path" => file_path} when is_binary(file_path) ->
        # Single file restore
        case Remediation.restore_file(agent_id, snapshot_id, file_path) do
          {:ok, result} ->
            AuditLog.log_response_action(user, "restore_file", agent_id, %{
              snapshot_id: snapshot_id,
              file_path: file_path,
              result: "success"
            }, request_metadata(conn))

            json(conn, %{
              success: true,
              message: "File restored",
              file_path: file_path,
              result: result
            })

          {:error, reason} ->
            AuditLog.log_response_action(user, "restore_file", agent_id, %{
              snapshot_id: snapshot_id,
              file_path: file_path,
              result: "failed",
              error: inspect(reason)
            }, request_metadata(conn))

            conn
            |> put_status(400)
            |> json(%{success: false, error: inspect(reason)})
        end

      %{"file_paths" => file_paths} when is_list(file_paths) ->
        # Multiple files restore
        case Remediation.restore_files(agent_id, snapshot_id, file_paths) do
          {:ok, result} ->
            AuditLog.log_response_action(user, "restore_files", agent_id, %{
              snapshot_id: snapshot_id,
              file_count: length(file_paths),
              restored_count: result["restored_count"] || 0,
              failed_count: result["failed_count"] || 0,
              result: "success"
            }, request_metadata(conn))

            json(conn, %{
              success: true,
              message: "Files restore completed",
              restored_count: result["restored_count"] || 0,
              failed_count: result["failed_count"] || 0,
              result: result
            })

          {:error, reason} ->
            AuditLog.log_response_action(user, "restore_files", agent_id, %{
              snapshot_id: snapshot_id,
              file_count: length(file_paths),
              result: "failed",
              error: inspect(reason)
            }, request_metadata(conn))

            conn
            |> put_status(400)
            |> json(%{success: false, error: inspect(reason)})
        end

      _ ->
        conn
        |> put_status(400)
        |> json(%{success: false, error: "Must provide file_path or file_paths"})
    end
  end

  @doc """
  Find encrypted files (ransomware detection).
  GET /api/v1/agents/:id/encrypted-files
  """
  def find_encrypted_files(conn, %{"id" => agent_id} = params) do
    path = Map.get(params, "path", "C:\\Users")

    # Validate agent belongs to current organization before executing action
    _agent = authorize_agent!(conn, agent_id)

    case Remediation.find_encrypted_files(agent_id, path: path) do
      {:ok, result} ->
        json(conn, %{
          success: true,
          encrypted_files: result["encrypted_files"] || [],
          count: result["count"] || 0,
          path: path
        })

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  Perform ransomware remediation.
  POST /api/v1/agents/:id/remediate
  """
  def ransomware_remediate(conn, %{"id" => agent_id} = params) do
    # Validate agent belongs to current organization before executing action
    _agent = authorize_agent!(conn, agent_id)

    opts = [
      path: Map.get(params, "path", "C:\\Users"),
      encrypted_files: Map.get(params, "encrypted_files"),
      dry_run: Map.get(params, "dry_run", false)
    ]
    |> Enum.filter(fn {_k, v} -> v != nil end)

    user = conn.assigns[:current_user]

    case Remediation.ransomware_remediate(agent_id, opts) do
      {:ok, result} ->
        AuditLog.log_response_action(user, "ransomware_remediate", agent_id, %{
          path: opts[:path],
          dry_run: opts[:dry_run],
          restored_count: result["restored_count"],
          result: "success"
        }, request_metadata(conn))

        json(conn, %{
          success: true,
          message: "Ransomware remediation completed",
          restored_count: result["restored_count"] || 0,
          failed_count: result["failed_count"] || 0,
          bytes_restored: result["bytes_restored"] || 0,
          duration_ms: result["duration_ms"] || 0,
          result: result
        })

      {:error, reason} ->
        AuditLog.log_response_action(user, "ransomware_remediate", agent_id, %{
          path: opts[:path],
          result: "failed",
          error: inspect(reason)
        }, request_metadata(conn))

        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  # ============================================================================
  # Response Metrics
  # ============================================================================

  @doc """
  Get response metrics and timeline.
  GET /api/v1/response/metrics
  """
  def metrics(conn, params) do
    time_range = Map.get(params, "time_range", "24h")

    case DecisionEngine.get_response_metrics() do
      {:ok, metrics} ->
        # Generate sample timeline events (in production, this would come from DB)
        timeline = generate_sample_timeline()

        json(conn, %{
          success: true,
          metrics: metrics,
          timeline: timeline,
          time_range: time_range
        })

      {:error, reason} ->
        conn
        |> put_status(500)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  @doc """
  Rollback a response action.
  POST /api/v1/response/rollback/:response_id
  """
  def rollback(conn, %{"response_id" => response_id}) do
    user = conn.assigns[:current_user]

    case DecisionEngine.rollback_response(response_id) do
      {:ok, result} ->
        AuditLog.log_response_action(user, "rollback", nil, %{
          response_id: response_id,
          result: "success"
        }, request_metadata(conn))

        json(conn, %{
          success: true,
          message: "Rollback completed",
          result: result
        })

      {:error, :not_found} ->
        conn
        |> put_status(404)
        |> json(%{success: false, error: "Response not found"})

      {:error, reason} ->
        AuditLog.log_response_action(user, "rollback", nil, %{
          response_id: response_id,
          result: "failed",
          error: inspect(reason)
        }, request_metadata(conn))

        conn
        |> put_status(400)
        |> json(%{success: false, error: inspect(reason)})
    end
  end

  # Generate timeline data - returns sample data only when DEMO_MODE is enabled
  defp generate_sample_timeline do
    if Application.get_env(:tamandua_server, :demo_mode, false) do
      generate_demo_timeline()
    else
      # Return empty list - real data should come from database
      []
    end
  end

  # Demo timeline data - only shown when DEMO_MODE=true
  defp generate_demo_timeline do
    now = DateTime.utc_now()

    [
      %{
        id: "resp_abc123def456",
        type: "rapid_response",
        agent_id: "agent-001",
        agent_hostname: "WORKSTATION-01",
        alert_id: "alert-789",
        actions: [
          %{action: "kill_process", result: "ok", duration_ms: 45},
          %{action: "quarantine_file", result: "ok", duration_ms: 120},
          %{action: "isolate_network", result: "ok", duration_ms: 85}
        ],
        duration_ms: 250,
        success: true,
        executed_at: DateTime.add(now, -300, :second) |> DateTime.to_iso8601(),
        automated: true,
        _demo: true
      },
      %{
        id: "resp_def456ghi789",
        type: "playbook_execution",
        agent_id: "agent-002",
        agent_hostname: "SERVER-DC01",
        alert_id: "alert-456",
        actions: [
          %{action: "collect_forensics", result: "ok", duration_ms: 2500},
          %{action: "quarantine_file", result: "ok", duration_ms: 150}
        ],
        duration_ms: 2650,
        success: true,
        executed_at: DateTime.add(now, -1800, :second) |> DateTime.to_iso8601(),
        automated: false,
        _demo: true
      },
      %{
        id: "resp_ghi789jkl012",
        type: "manual_action",
        agent_id: "agent-003",
        agent_hostname: "LAPTOP-USER01",
        alert_id: nil,
        actions: [
          %{action: "kill_process", result: "ok", duration_ms: 35}
        ],
        duration_ms: 35,
        success: true,
        executed_at: DateTime.add(now, -3600, :second) |> DateTime.to_iso8601(),
        automated: false,
        _demo: true
      },
      %{
        id: "resp_jkl012mno345",
        type: "rapid_response",
        agent_id: "agent-001",
        agent_hostname: "WORKSTATION-01",
        alert_id: "alert-123",
        actions: [
          %{action: "kill_process", result: "error", duration_ms: 500},
          %{action: "quarantine_file", result: "ok", duration_ms: 100}
        ],
        duration_ms: 600,
        success: false,
        executed_at: DateTime.add(now, -7200, :second) |> DateTime.to_iso8601(),
        automated: true,
        _demo: true
      }
    ]
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp request_metadata(conn) do
    [
      ip_address: get_client_ip(conn),
      user_agent: get_user_agent(conn)
    ]
  end

  defp user_identifier(nil), do: "api"

  defp user_identifier(user) do
    Map.get(user, :email) || Map.get(user, :username) || Map.get(user, :id) || "api"
  end

  defp current_organization_id(conn) do
    conn.assigns[:current_organization_id] ||
      (conn.assigns[:current_user] && conn.assigns[:current_user].organization_id)
  end

  defp record_response_action(conn, user, action_type, agent_id, params, status, result, error_message \\ nil) do
    attrs = %{
      agent_id: agent_id,
      action_type: action_type,
      alert_id: Map.get(params, "alert_id"),
      executed_by_id: user && user.id,
      organization_id: current_organization_id(conn),
      parameters: Map.drop(params, ["agent_id"]),
      status: status,
      result: normalize_response_result(result),
      error_message: error_message,
      executed_at: DateTime.utc_now()
    }

    case Response.create_action(attrs) do
      {:ok, _action} ->
        :ok

      {:error, changeset} ->
        require Logger
        Logger.warning("Failed to persist response action #{action_type}: #{inspect(changeset.errors)}")
        :error
    end
  end

  defp normalize_response_result(nil), do: %{}
  defp normalize_response_result(result) when is_map(result), do: result
  defp normalize_response_result(result), do: %{"value" => inspect(result)}

  defp get_client_ip(conn) do
    case get_req_header(conn, "x-forwarded-for") do
      [forwarded | _] ->
        forwarded
        |> String.split(",")
        |> List.first()
        |> String.trim()

      [] ->
        conn.remote_ip
        |> :inet.ntoa()
        |> to_string()
    end
  end

  defp get_user_agent(conn) do
    case get_req_header(conn, "user-agent") do
      [ua | _] -> ua
      [] -> nil
    end
  end
end
