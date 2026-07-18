defmodule TamanduaServerWeb.API.V1.ResponseController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Agents
  alias TamanduaServer.Alerts
  alias TamanduaServer.AuditLog
  alias TamanduaServer.Response
  alias TamanduaServer.Response.Executor
  alias TamanduaServer.Response.ResponseActor
  alias TamanduaServer.Response.Remediation
  alias TamanduaServer.Response.DecisionEngine
  alias TamanduaServer.Detection.DNSAnalyzer

  action_fallback(TamanduaServerWeb.FallbackController)

  plug(
    TamanduaServerWeb.Plugs.Authorize,
    :response_contain
    when action in [
           :kill_process,
           :quarantine_file,
           :block_ip,
           :unblock_ip,
           :block_domain,
           :unblock_domain
         ]
  )

  plug(
    TamanduaServerWeb.Plugs.Authorize,
    :response_execute
    when action in [
           :collect_artifact,
           :scan_path,
           :create_snapshot,
           :list_snapshots,
           :find_encrypted_files
         ]
  )

  plug(
    TamanduaServerWeb.Plugs.Authorize,
    [
      :response_execute,
      :response_contain,
      :response_remediate,
      :response_approve,
      :response_rollback
    ]
    when action in [:metrics]
  )

  plug(
    TamanduaServerWeb.Plugs.Authorize,
    :response_remediate
    when action in [:delete_snapshot, :restore_files, :ransomware_remediate]
  )

  plug(
    TamanduaServerWeb.Plugs.Authorize,
    :response_rollback
    when action in [:rollback]
  )

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

    executor_opts = [
      force: force?,
      reason: params["reason"],
      alert_id: scoped_alert_id(conn, params["alert_id"]),
      actor: response_actor(conn)
    ]

    case Executor.kill_process(agent_id, pid, executor_opts) do
      :ok ->
        # Log the response action
        AuditLog.log_response_action(
          user,
          "kill_process",
          agent_id,
          %{
            pid: pid,
            force: force?,
            result: "success"
          },
          request_metadata(conn)
        )

        json(conn, %{success: true, message: "Process kill command sent"})

      {:ok, result_data} ->
        AuditLog.log_response_action(
          user,
          "kill_process",
          agent_id,
          %{
            pid: pid,
            force: force?,
            result: "success"
          },
          request_metadata(conn)
        )

        json(conn, %{
          success: true,
          message: "Process kill command sent",
          action_id: result_data[:action_id],
          audit_status: result_data[:audit_status]
        })

      {:error, reason} ->
        AuditLog.log_response_action(
          user,
          "kill_process",
          agent_id,
          %{
            pid: pid,
            force: force?,
            result: "failed",
            error: reason
          },
          request_metadata(conn)
        )

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

    executor_opts = [
      reason: params["reason"],
      delete_after: truthy_param?(Map.get(params, "delete_after", params["delete_original"])),
      alert_id: scoped_alert_id(conn, params["alert_id"]),
      actor: response_actor(conn)
    ]

    case Executor.quarantine_file(agent_id, path, executor_opts) do
      :ok ->
        AuditLog.log_response_action(
          user,
          "quarantine_file",
          agent_id,
          %{
            path: path,
            result: "success"
          },
          request_metadata(conn)
        )

        json(conn, %{success: true, message: "File quarantine command sent"})

      {:ok, result_data} ->
        AuditLog.log_response_action(
          user,
          "quarantine_file",
          agent_id,
          %{
            path: path,
            result: "success"
          },
          request_metadata(conn)
        )

        json(conn, %{
          success: true,
          message: "File quarantine command sent",
          action_id: result_data[:action_id],
          audit_status: result_data[:audit_status]
        })

      {:error, reason} ->
        AuditLog.log_response_action(
          user,
          "quarantine_file",
          agent_id,
          %{
            path: path,
            result: "failed",
            error: reason
          },
          request_metadata(conn)
        )

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

    with {:ok, actor} <-
           ResponseActor.from_user_scope(user, current_organization_id(conn)) do
      case Executor.collect_artifact(agent_id, path, artifact_type, actor: actor) do
        :ok ->
          AuditLog.log_response_action(
            user,
            "collect_artifact",
            agent_id,
            %{
              path: path,
              artifact_type: artifact_type,
              result: "success"
            },
            request_metadata(conn)
          )

          json(conn, %{success: true, message: "Artifact collection command sent"})

        {:error, reason} ->
          AuditLog.log_response_action(
            user,
            "collect_artifact",
            agent_id,
            %{
              path: path,
              artifact_type: artifact_type,
              result: "failed",
              error: reason
            },
            request_metadata(conn)
          )

          conn
          |> put_status(400)
          |> json(%{success: false, error: reason})
      end
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

    with {:ok, actor} <-
           ResponseActor.from_user_scope(user, current_organization_id(conn)) do
      case Executor.scan_path(agent_id, path, Keyword.put(opts, :actor, actor)) do
        {:ok, result} ->
          AuditLog.log_response_action(
            user,
            "scan_path",
            agent_id,
            %{
              path: path,
              recursive: opts[:recursive],
              result: "success",
              files_scanned: get_in(result, ["result_data", "files_scanned"]) || 0,
              threats_found: get_in(result, ["result_data", "threats_found"]) || 0
            },
            request_metadata(conn)
          )

          record_response_action(conn, user, "scan_path", agent_id, params, "success", result)

          json(conn, %{
            success: true,
            message: "Scan completed",
            files_scanned: get_in(result, ["result_data", "files_scanned"]) || 0,
            threats_found: get_in(result, ["result_data", "threats_found"]) || 0,
            threats: get_in(result, ["result_data", "threats"]) || []
          })

        :ok ->
          AuditLog.log_response_action(
            user,
            "scan_path",
            agent_id,
            %{
              path: path,
              result: "sent"
            },
            request_metadata(conn)
          )

          record_response_action(conn, user, "scan_path", agent_id, params, "success", %{
            "message" => "Scan command sent"
          })

          json(conn, %{success: true, message: "Scan command sent"})

        {:error, reason} ->
          AuditLog.log_response_action(
            user,
            "scan_path",
            agent_id,
            %{
              path: path,
              result: "failed",
              error: reason
            },
            request_metadata(conn)
          )

          record_response_action(
            conn,
            user,
            "scan_path",
            agent_id,
            params,
            "failed",
            nil,
            inspect(reason)
          )

          conn
          |> put_status(400)
          |> json(%{success: false, error: reason})
      end
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

    with {:ok, actor} <-
           ResponseActor.from_user_scope(user, current_organization_id(conn)) do
      case Executor.execute_action(agent_id, "block_ip", payload, actor: actor) do
        {:ok, result} ->
          AuditLog.log_response_action(
            user,
            "block_ip",
            agent_id,
            Map.put(payload, :result, "success"),
            request_metadata(conn)
          )

          record_response_action(conn, user, "block_ip", agent_id, params, "success", result)
          json(conn, %{success: true, message: "IP block command sent", result: result})

        {:error, reason} ->
          AuditLog.log_response_action(
            user,
            "block_ip",
            agent_id,
            Map.merge(payload, %{result: "failed", error: inspect(reason)}),
            request_metadata(conn)
          )

          record_response_action(
            conn,
            user,
            "block_ip",
            agent_id,
            params,
            "failed",
            nil,
            inspect(reason)
          )

          conn
          |> put_status(400)
          |> json(%{success: false, error: inspect(reason)})
      end
    end
  end

  def unblock_ip(conn, %{"agent_id" => agent_id, "ip" => ip}) do
    user = conn.assigns[:current_user]
    _agent = authorize_agent!(conn, agent_id)

    payload = %{ip: ip}

    with {:ok, actor} <-
           ResponseActor.from_user_scope(user, current_organization_id(conn)) do
      case Executor.execute_action(agent_id, "unblock_ip", payload, actor: actor) do
        {:ok, result} ->
          AuditLog.log_response_action(
            user,
            "unblock_ip",
            agent_id,
            Map.put(payload, :result, "success"),
            request_metadata(conn)
          )

          json(conn, %{success: true, message: "IP unblock command sent", result: result})

        {:error, reason} ->
          AuditLog.log_response_action(
            user,
            "unblock_ip",
            agent_id,
            Map.merge(payload, %{result: "failed", error: inspect(reason)}),
            request_metadata(conn)
          )

          conn
          |> put_status(400)
          |> json(%{success: false, error: inspect(reason)})
      end
    end
  end

  def block_domain(conn, %{"agent_id" => agent_id, "domain" => domain} = params) do
    user = conn.assigns[:current_user]
    _agent = authorize_agent!(conn, agent_id)

    reason = Map.get(params, "reason", "manual_block")
    organization_id = current_organization_id(conn)

    case DNSAnalyzer.add_to_blocklist(
           [domain],
           reason,
           user_identifier(user),
           organization_id
         ) do
      {:ok, [applied_domain] = applied_domains} ->
        payload = %{domain: applied_domain, reason: reason}

        case Executor.execute_action(agent_id, "block_domain", payload,
               actor: response_actor(conn)
             ) do
          {:ok, result} ->
            AuditLog.log_response_action(
              user,
              "block_domain",
              agent_id,
              Map.put(payload, :result, "success"),
              request_metadata(conn)
            )

            record_response_action(
              conn,
              user,
              "block_domain",
              agent_id,
              params,
              "success",
              result
            )

            json(conn, %{
              success: true,
              message: "Domain block command sent",
              result: result,
              applied_domains: applied_domains
            })

          {:error, dispatch_error} ->
            record_response_action(
              conn,
              user,
              "block_domain",
              agent_id,
              params,
              "partial",
              nil,
              inspect(dispatch_error)
            )

            conn
            |> put_status(:service_unavailable)
            |> json(%{
              success: false,
              durable_applied: true,
              applied_domains: applied_domains,
              error: "Domain persisted but agent command failed"
            })
        end

      {:ok, _unexpected} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{success: false, error: "Durable blocklist returned an invalid result"})

      {:error, persistence_error} ->
        record_response_action(
          conn,
          user,
          "block_domain",
          agent_id,
          params,
          "failed",
          nil,
          inspect(persistence_error)
        )

        conn
        |> put_status(:service_unavailable)
        |> json(%{success: false, error: "Durable blocklist update failed"})
    end
  end

  def unblock_domain(conn, %{"agent_id" => agent_id, "domain" => domain}) do
    user = conn.assigns[:current_user]
    _agent = authorize_agent!(conn, agent_id)

    case DNSAnalyzer.remove_from_blocklist(domain, current_organization_id(conn)) do
      {:ok, [applied_domain] = applied_domains} ->
        payload = %{domain: applied_domain}

        case Executor.execute_action(agent_id, "unblock_domain", payload,
               actor: response_actor(conn)
             ) do
          {:ok, result} ->
            AuditLog.log_response_action(
              user,
              "unblock_domain",
              agent_id,
              Map.put(payload, :result, "success"),
              request_metadata(conn)
            )

            json(conn, %{
              success: true,
              message: "Domain unblock command sent",
              result: result,
              applied_domains: applied_domains
            })

          {:error, dispatch_error} ->
            conn
            |> put_status(:service_unavailable)
            |> json(%{
              success: false,
              durable_applied: true,
              applied_domains: applied_domains,
              error: "Domain removal persisted but agent command failed",
              detail: inspect(dispatch_error)
            })
        end

      {:ok, _unexpected} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{success: false, error: "Durable blocklist returned an invalid result"})

      {:error, persistence_error} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{
          success: false,
          error: "Durable blocklist update failed",
          detail: inspect(persistence_error)
        })
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
        AuditLog.log_response_action(
          user,
          "create_snapshot",
          agent_id,
          %{
            volume: volume,
            result: "success"
          },
          request_metadata(conn)
        )

        json(conn, %{
          success: true,
          message: "Snapshot created",
          snapshot: result["snapshot"] || result
        })

      {:error, reason} ->
        AuditLog.log_response_action(
          user,
          "create_snapshot",
          agent_id,
          %{
            volume: volume,
            result: "failed",
            error: inspect(reason)
          },
          request_metadata(conn)
        )

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
        AuditLog.log_response_action(
          user,
          "delete_snapshot",
          agent_id,
          %{
            snapshot_id: snapshot_id,
            result: "success"
          },
          request_metadata(conn)
        )

        json(conn, %{
          success: true,
          message: "Snapshot deleted",
          snapshot_id: snapshot_id
        })

      {:error, reason} ->
        AuditLog.log_response_action(
          user,
          "delete_snapshot",
          agent_id,
          %{
            snapshot_id: snapshot_id,
            result: "failed",
            error: inspect(reason)
          },
          request_metadata(conn)
        )

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
            AuditLog.log_response_action(
              user,
              "restore_file",
              agent_id,
              %{
                snapshot_id: snapshot_id,
                file_path: file_path,
                result: "success"
              },
              request_metadata(conn)
            )

            json(conn, %{
              success: true,
              message: "File restored",
              file_path: file_path,
              result: result
            })

          {:error, reason} ->
            AuditLog.log_response_action(
              user,
              "restore_file",
              agent_id,
              %{
                snapshot_id: snapshot_id,
                file_path: file_path,
                result: "failed",
                error: inspect(reason)
              },
              request_metadata(conn)
            )

            conn
            |> put_status(400)
            |> json(%{success: false, error: inspect(reason)})
        end

      %{"file_paths" => file_paths} when is_list(file_paths) ->
        # Multiple files restore
        case Remediation.restore_files(agent_id, snapshot_id, file_paths) do
          {:ok, result} ->
            AuditLog.log_response_action(
              user,
              "restore_files",
              agent_id,
              %{
                snapshot_id: snapshot_id,
                file_count: length(file_paths),
                restored_count: result["restored_count"] || 0,
                failed_count: result["failed_count"] || 0,
                result: "success"
              },
              request_metadata(conn)
            )

            json(conn, %{
              success: true,
              message: "Files restore completed",
              restored_count: result["restored_count"] || 0,
              failed_count: result["failed_count"] || 0,
              result: result
            })

          {:error, reason} ->
            AuditLog.log_response_action(
              user,
              "restore_files",
              agent_id,
              %{
                snapshot_id: snapshot_id,
                file_count: length(file_paths),
                result: "failed",
                error: inspect(reason)
              },
              request_metadata(conn)
            )

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

    opts =
      [
        path: Map.get(params, "path", "C:\\Users"),
        encrypted_files: Map.get(params, "encrypted_files"),
        dry_run: Map.get(params, "dry_run", false)
      ]
      |> Enum.filter(fn {_k, v} -> v != nil end)

    user = conn.assigns[:current_user]

    case Remediation.ransomware_remediate(agent_id, opts) do
      {:ok, result} ->
        AuditLog.log_response_action(
          user,
          "ransomware_remediate",
          agent_id,
          %{
            path: opts[:path],
            dry_run: opts[:dry_run],
            restored_count: result["restored_count"],
            result: "success"
          },
          request_metadata(conn)
        )

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
        AuditLog.log_response_action(
          user,
          "ransomware_remediate",
          agent_id,
          %{
            path: opts[:path],
            result: "failed",
            error: inspect(reason)
          },
          request_metadata(conn)
        )

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
    scope = response_scope(conn)

    case DecisionEngine.get_response_metrics(scope) do
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
    scope = response_scope(conn)

    case DecisionEngine.rollback_response(response_id, scope) do
      {:ok, result} ->
        AuditLog.log_response_action(
          user,
          "rollback",
          nil,
          %{
            response_id: response_id,
            result: "success"
          },
          request_metadata(conn)
        )

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
        AuditLog.log_response_action(
          user,
          "rollback",
          nil,
          %{
            response_id: response_id,
            result: "failed",
            error: inspect(reason)
          },
          request_metadata(conn)
        )

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

  defp response_scope(conn) do
    case current_organization_id(conn) do
      org_id when is_binary(org_id) and org_id != "" -> {:organization, org_id}
      _ -> nil
    end
  end

  defp response_actor(conn) do
    %{
      organization_id: current_organization_id(conn),
      user_id: conn.assigns[:current_user] && conn.assigns[:current_user].id
    }
  end

  defp record_response_action(
         conn,
         user,
         action_type,
         agent_id,
         params,
         status,
         result,
         error_message \\ nil
       ) do
    attrs = %{
      agent_id: agent_id,
      action_type: action_type,
      alert_id: scoped_alert_id(conn, Map.get(params, "alert_id")),
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

        Logger.warning(
          "Failed to persist response action #{action_type}: #{inspect(changeset.errors)}"
        )

        :error
    end
  end

  defp scoped_alert_id(_conn, nil), do: nil

  defp scoped_alert_id(conn, alert_id) do
    case Alerts.get_alert_for_org(current_organization_id(conn), alert_id) do
      {:ok, _alert} -> alert_id
      _ -> raise Ecto.NoResultsError
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
