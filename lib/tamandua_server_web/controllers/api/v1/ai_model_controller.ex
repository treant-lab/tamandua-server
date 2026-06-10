defmodule TamanduaServerWeb.API.V1.AIModelController do
  @moduledoc """
  API controller for AI model security operations.

  Provides REST endpoints for:
  - Listing discovered AI models with scan status
  - Viewing individual model details and history
  - Triggering manual security scans (single and bulk)
  - Retrieving scan history
  """
  use TamanduaServerWeb, :controller

  alias TamanduaServer.AISecurity.AIInventory
  alias TamanduaServer.AISecurity.ScanHistory

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  List all AI models with scan status.

  GET /api/v1/ai-security/models

  ## Query Parameters
    * `type` - Filter by component type (e.g., "model_file", "llm")
    * `risk_level` - Filter by risk level ("low", "medium", "high", "critical")
    * `shadow_only` - If "true", only return unapproved/shadow AI
    * `limit` - Maximum results (default 500)

  ## Response
      {
        "data": [...],
        "meta": {
          "total": 42,
          "stats": {...}
        }
      }
  """
  def index(conn, params) do
    opts = [
      type: params["type"],
      risk_level: params["risk_level"],
      shadow_only: params["shadow_only"] == "true",
      limit: parse_int(params["limit"], 500)
    ] |> Enum.reject(fn {_k, v} -> is_nil(v) or v == false end)

    {:ok, models} = AIInventory.list_inventory(opts)

    json(conn, %{
      data: models,
      meta: %{
        total: length(models),
        stats: AIInventory.stats()
      }
    })
  end

  @doc """
  Get single model details with history.

  GET /api/v1/ai-security/models/:id

  ## Response
      {
        "data": {...},
        "risk_assessment": {...},
        "scan_history": [...]
      }
  """
  def show(conn, %{"id" => id}) do
    case AIInventory.assess_risk(id) do
      {:ok, assessment} ->
        history = ScanHistory.list_history(id, limit: 10)

        json(conn, %{
          data: assessment.component,
          risk_assessment: %{
            risk_score: assessment.risk_score,
            risk_level: assessment.risk_level,
            risk_factors: assessment.risk_factors,
            policy_status: assessment.policy_status,
            recommendations: assessment.recommendations
          },
          scan_history: format_scan_history(history)
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Model not found", model_id: id})
    end
  end

  @doc """
  Trigger scan for a single model.

  POST /api/v1/ai-security/models/:id/scan

  Sends a scan command to the agent hosting the model.
  The scan runs asynchronously and results are delivered via PubSub.

  ## Response
      {
        "status": "scanning",
        "model_id": "...",
        "message": "Scan initiated"
      }
  """
  def scan(conn, %{"id" => model_id}) do
    case AIInventory.assess_risk(model_id) do
      {:ok, %{component: model}} ->
        agent_id = model[:agent_id]
        path = model[:path] || model[:install_path]

        case send_scan_command(agent_id, model_id, path) do
          :ok ->
            # Broadcast scan started event for real-time UI updates
            Phoenix.PubSub.broadcast(
              TamanduaServer.PubSub,
              "ai_security:scan_results",
              {:scan_started, %{model_id: model_id, agent_id: agent_id}}
            )

            json(conn, %{
              status: "scanning",
              model_id: model_id,
              agent_id: agent_id,
              message: "Scan initiated"
            })

          {:error, reason} ->
            conn
            |> put_status(:service_unavailable)
            |> json(%{
              error: "Failed to send scan command",
              reason: format_error(reason),
              model_id: model_id
            })
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Model not found", model_id: model_id})
    end
  end

  @doc """
  Trigger scan for multiple models.

  POST /api/v1/ai-security/models/scan

  ## Request Body
      {"model_ids": ["id1", "id2", ...]}

  ## Response
      {
        "status": "bulk_scan_initiated",
        "results": [...],
        "total": 5,
        "scanning": 4,
        "errors": 1
      }
  """
  def bulk_scan(conn, %{"model_ids" => model_ids}) when is_list(model_ids) do
    results = Enum.map(model_ids, fn model_id ->
      case AIInventory.assess_risk(model_id) do
        {:ok, %{component: model}} ->
          agent_id = model[:agent_id]
          path = model[:path] || model[:install_path]

          case send_scan_command(agent_id, model_id, path) do
            :ok ->
              %{model_id: model_id, status: "scanning", agent_id: agent_id}
            {:error, reason} ->
              %{model_id: model_id, status: "error", reason: format_error(reason)}
          end

        {:error, :not_found} ->
          %{model_id: model_id, status: "error", reason: "not_found"}
      end
    end)

    # Broadcast bulk scan started event
    scanning_ids = results
    |> Enum.filter(&(&1.status == "scanning"))
    |> Enum.map(& &1.model_id)

    if length(scanning_ids) > 0 do
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "ai_security:scan_results",
        {:bulk_scan_started, %{model_ids: scanning_ids}}
      )
    end

    json(conn, %{
      status: "bulk_scan_initiated",
      results: results,
      total: length(model_ids),
      scanning: Enum.count(results, &(&1.status == "scanning")),
      errors: Enum.count(results, &(&1.status == "error"))
    })
  end

  def bulk_scan(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "model_ids array required"})
  end

  @doc """
  Get scan history for a model.

  GET /api/v1/ai-security/models/:id/history

  ## Query Parameters
    * `limit` - Maximum records to return (default 20)

  ## Response
      {
        "data": [...],
        "stats": {...}
      }
  """
  def history(conn, %{"id" => model_id} = params) do
    limit = parse_int(params["limit"], 20)
    history = ScanHistory.list_history(model_id, limit: limit)
    stats = ScanHistory.scan_stats(model_id)

    json(conn, %{
      data: format_scan_history(history),
      stats: stats
    })
  end

  @doc """
  Get global scan statistics.

  GET /api/v1/ai-security/models/stats

  ## Response
      {
        "total_scans": 100,
        "unique_models": 25,
        "threats_found": 5,
        "by_status": {...}
      }
  """
  def stats(conn, _params) do
    global_stats = ScanHistory.global_stats()
    by_status = ScanHistory.count_by_status(hours: 24)

    json(conn, %{
      total_scans: global_stats.total_scans,
      unique_models: global_stats.unique_models,
      threats_found: global_stats.threats_found,
      avg_duration_ms: global_stats.avg_duration_ms,
      by_status: by_status,
      inventory_stats: AIInventory.stats()
    })
  end

  # Private helpers

  defp send_scan_command(agent_id, model_id, path) do
    command = %{
      type: "scan_model",
      payload: %{
        model_id: model_id,
        path: path,
        force: true
      }
    }

    try do
      case TamanduaServer.Agents.send_command(agent_id, command) do
        {:ok, _} -> :ok
        :ok -> :ok
        {:error, reason} -> {:error, reason}
        error -> {:error, error}
      end
    rescue
      e -> {:error, e}
    catch
      :exit, reason -> {:error, {:exit, reason}}
    end
  end

  defp format_scan_history(history) do
    Enum.map(history, fn scan ->
      %{
        id: scan.id,
        model_id: scan.model_id,
        agent_id: scan.agent_id,
        file_hash: scan.file_hash,
        scan_status: scan.scan_status,
        threat_score: scan.threat_score,
        threats: scan.threats,
        scan_duration_ms: scan.scan_duration_ms,
        scanner_version: scan.scanner_version,
        scanned_at: scan.scanned_at
      }
    end)
  end

  defp format_error(%{__struct__: _} = struct), do: inspect(struct)
  defp format_error(reason) when is_binary(reason), do: reason
  defp format_error(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp format_error(reason), do: inspect(reason)

  defp parse_int(nil, default), do: default
  defp parse_int(str, default) when is_binary(str) do
    case Integer.parse(str) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(int, _default) when is_integer(int), do: int
  defp parse_int(_, default), do: default

  # ===========================================================================
  # Response Actions
  # ===========================================================================

  alias TamanduaServer.AISecurity.ResponseActions

  @doc """
  Quarantine a model to the agent's encrypted vault.

  POST /api/v1/ai-security/models/:id/quarantine

  ## Request Body (optional)
      {"reason": "Detected malicious pickle operations"}

  ## Response
      {
        "status": "quarantined",
        "model_id": "...",
        "message": "Model quarantined successfully"
      }
  """
  def quarantine(conn, %{"id" => model_id} = params) do
    user_id = get_user_id(conn)
    reason = params["reason"]

    opts = if reason, do: [reason: reason], else: []

    case ResponseActions.quarantine_model(model_id, user_id, opts) do
      {:ok, result} ->
        json(conn, %{
          status: result.status,
          model_id: result.model_id,
          message: "Model quarantined successfully"
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Model not found", model_id: model_id})

      {:error, :agent_not_connected} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: "Agent not connected", model_id: model_id})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Quarantine failed", reason: format_error(reason), model_id: model_id})
    end
  end

  @doc """
  Block a model from being loaded/executed.

  POST /api/v1/ai-security/models/:id/block

  ## Request Body (optional)
      {"reason": "Potential backdoor detected"}

  ## Response
      {
        "status": "blocked",
        "model_id": "...",
        "block_entry_id": "...",
        "message": "Model blocked successfully"
      }
  """
  def block(conn, %{"id" => model_id} = params) do
    user_id = get_user_id(conn)
    reason = params["reason"]

    opts = if reason, do: [reason: reason], else: []

    case ResponseActions.block_model(model_id, user_id, opts) do
      {:ok, result} ->
        json(conn, %{
          status: result.status,
          model_id: result.model_id,
          block_entry_id: result.block_entry_id,
          message: "Model blocked successfully"
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Model not found", model_id: model_id})

      {:error, :already_blocked} ->
        # Idempotent - return success if already blocked
        json(conn, %{
          status: "blocked",
          model_id: model_id,
          message: "Model already blocked"
        })

      {:error, :agent_not_connected} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: "Agent not connected", model_id: model_id})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Block failed", reason: format_error(reason), model_id: model_id})
    end
  end

  @doc """
  Unblock a previously blocked model.

  DELETE /api/v1/ai-security/models/:id/block

  ## Response
      {
        "status": "unblocked",
        "model_id": "...",
        "message": "Model unblocked successfully"
      }
  """
  def unblock(conn, %{"id" => model_id}) do
    user_id = get_user_id(conn)

    case ResponseActions.unblock_model(model_id, user_id) do
      {:ok, result} ->
        json(conn, %{
          status: result.status,
          model_id: result.model_id,
          message: "Model unblocked successfully"
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Model or block entry not found", model_id: model_id})

      {:error, :agent_not_connected} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: "Agent not connected", model_id: model_id})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Unblock failed", reason: format_error(reason), model_id: model_id})
    end
  end

  @doc """
  Restore a quarantined model to its original location.

  POST /api/v1/ai-security/models/:id/restore

  ## Request Body
      {
        "acknowledge_risk": true,    // Required
        "force_restore": false       // Optional - skip re-scan
      }

  ## Response
      {
        "status": "restored",
        "model_id": "...",
        "message": "Model restored successfully"
      }
  """
  def restore(conn, %{"id" => model_id} = params) do
    user_id = get_user_id(conn)
    acknowledge_risk = params["acknowledge_risk"] == true
    force_restore = params["force_restore"] == true

    opts = [acknowledge_risk: acknowledge_risk, force_restore: force_restore]

    case ResponseActions.restore_model(model_id, user_id, opts) do
      {:ok, result} ->
        json(conn, %{
          status: result.status,
          model_id: result.model_id,
          message: "Model restored successfully"
        })

      {:error, :risk_acknowledgment_required} ->
        conn
        |> put_status(:bad_request)
        |> json(%{
          error: "Risk acknowledgment required",
          message: "You must set acknowledge_risk: true to restore a quarantined model",
          model_id: model_id
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Model not found", model_id: model_id})

      {:error, :agent_not_connected} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: "Agent not connected", model_id: model_id})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Restore failed", reason: format_error(reason), model_id: model_id})
    end
  end

  @doc """
  Get response status for a model.

  GET /api/v1/ai-security/models/:id/status

  ## Response
      {
        "model_id": "...",
        "status": "active|blocked|quarantined"
      }
  """
  def status(conn, %{"id" => model_id}) do
    case ResponseActions.get_model_status(model_id) do
      {:ok, result} ->
        json(conn, %{
          model_id: result.model_id,
          status: result.status
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Model not found", model_id: model_id})
    end
  end

  @doc """
  Bulk quarantine multiple models.

  POST /api/v1/ai-security/models/quarantine

  ## Request Body
      {"model_ids": ["id1", "id2", ...], "reason": "..."}

  ## Response
      {
        "status": "bulk_quarantine_initiated",
        "results": [...],
        "total": 5,
        "quarantined": 4,
        "errors": 1
      }
  """
  def bulk_quarantine(conn, %{"model_ids" => model_ids} = params) when is_list(model_ids) do
    user_id = get_user_id(conn)
    reason = params["reason"]
    opts = if reason, do: [reason: reason], else: []

    results = Enum.map(model_ids, fn model_id ->
      case ResponseActions.quarantine_model(model_id, user_id, opts) do
        {:ok, result} -> %{model_id: model_id, status: result.status}
        {:error, reason} -> %{model_id: model_id, status: "error", reason: format_error(reason)}
      end
    end)

    json(conn, %{
      status: "bulk_quarantine_initiated",
      results: results,
      total: length(model_ids),
      quarantined: Enum.count(results, &(&1.status == "quarantined")),
      errors: Enum.count(results, &(&1.status == "error"))
    })
  end

  def bulk_quarantine(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "model_ids array required"})
  end

  @doc """
  Bulk block multiple models.

  POST /api/v1/ai-security/models/block

  ## Request Body
      {"model_ids": ["id1", "id2", ...], "reason": "..."}

  ## Response
      {
        "status": "bulk_block_initiated",
        "results": [...],
        "total": 5,
        "blocked": 4,
        "errors": 1
      }
  """
  def bulk_block(conn, %{"model_ids" => model_ids} = params) when is_list(model_ids) do
    user_id = get_user_id(conn)
    reason = params["reason"]
    opts = if reason, do: [reason: reason], else: []

    results = Enum.map(model_ids, fn model_id ->
      case ResponseActions.block_model(model_id, user_id, opts) do
        {:ok, result} -> %{model_id: model_id, status: result.status}
        {:error, :already_blocked} -> %{model_id: model_id, status: "blocked"}
        {:error, reason} -> %{model_id: model_id, status: "error", reason: format_error(reason)}
      end
    end)

    json(conn, %{
      status: "bulk_block_initiated",
      results: results,
      total: length(model_ids),
      blocked: Enum.count(results, &(&1.status == "blocked")),
      errors: Enum.count(results, &(&1.status == "error"))
    })
  end

  def bulk_block(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "model_ids array required"})
  end

  # Helper to get user ID from connection
  defp get_user_id(conn) do
    case conn.assigns[:current_user] do
      %{id: id} -> id
      _ -> nil
    end
  end
end
