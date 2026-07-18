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
  alias TamanduaServer.Policies.ModelPolicy
  alias TamanduaServer.Registries.ModelProvenance
  alias TamanduaServer.Repo
  alias TamanduaServer.Response.{Executor, ResponseActor}
  import Ecto.Query

  plug(
    TamanduaServerWeb.Plugs.RBAC,
    [permission: :ai_investigate]
    when action in [:index, :show, :scan, :bulk_scan, :history, :stats, :status]
  )

  plug(
    TamanduaServerWeb.Plugs.RBAC,
    [permission: :response_contain]
    when action in [:quarantine, :block, :unblock, :restore, :bulk_quarantine, :bulk_block]
  )

  action_fallback(TamanduaServerWeb.FallbackController)

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
    organization_id = current_organization_id!(conn)

    opts =
      [
        type: params["type"],
        risk_level: params["risk_level"],
        shadow_only: params["shadow_only"] == "true",
        limit: parse_int(params["limit"], 500)
      ]
      |> Enum.reject(fn {_k, v} -> is_nil(v) or v == false end)

    {:ok, models} = AIInventory.list_inventory(organization_id, opts)
    models = attach_model_guard_summaries(organization_id, models)

    json(conn, %{
      data: models,
      meta: %{
        total: length(models),
        stats: elem(AIInventory.stats(organization_id), 1)
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
    organization_id = current_organization_id!(conn)

    case AIInventory.assess_risk(organization_id, id) do
      {:ok, assessment} ->
        history = ScanHistory.list_history(organization_id, id, limit: 10)
        model_guard = model_guard_for_model(organization_id, assessment.component)

        json(conn, %{
          data: Map.put(assessment.component, :model_guard, model_guard),
          risk_assessment: %{
            risk_score: assessment.risk_score,
            risk_level: assessment.risk_level,
            risk_factors: assessment.risk_factors,
            policy_status: assessment.policy_status,
            recommendations: assessment.recommendations,
            model_guard: model_guard
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
    organization_id = current_organization_id!(conn)
    {:ok, actor} = response_actor(conn, organization_id)

    case AIInventory.assess_risk(organization_id, model_id) do
      {:ok, %{component: model}} ->
        agent_id = model[:agent_id]
        path = model[:path] || model[:install_path]

        case send_scan_command(actor, agent_id, model_id, path) do
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
            |> put_status(scan_error_status(reason))
            |> json(scan_error_payload(reason, model_id))
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Model not found", model_id: model_id})
    end
  end

  @doc """
  Bulk scan is unavailable until a durable batch reservation/outbox can
  guarantee all-or-nothing admission before any dispatch.

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
  def bulk_scan(conn, %{"model_ids" => model_ids}) when is_list(model_ids),
    do: bulk_action_unavailable(conn)

  def bulk_scan(conn, _params), do: bulk_action_unavailable(conn)

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
    organization_id = current_organization_id!(conn)
    ensure_model!(conn, organization_id, model_id)
    limit = parse_int(params["limit"], 20)
    history = ScanHistory.list_history(organization_id, model_id, limit: limit)
    stats = ScanHistory.scan_stats(organization_id, model_id)

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
    organization_id = current_organization_id!(conn)
    global_stats = ScanHistory.global_stats(organization_id)
    by_status = ScanHistory.count_by_status(organization_id, hours: 24)

    json(conn, %{
      total_scans: global_stats.total_scans,
      unique_models: global_stats.unique_models,
      threats_found: global_stats.threats_found,
      avg_duration_ms: global_stats.avg_duration_ms,
      by_status: by_status,
      inventory_stats: elem(AIInventory.stats(organization_id), 1)
    })
  end

  # Private helpers

  defp send_scan_command(actor, agent_id, model_id, path) do
    cond do
      is_nil(agent_id) or agent_id == "" ->
        {:error, :unsupported_no_agent}

      is_nil(path) or path == "" ->
        {:error, :unsupported_no_local_model_path}

      true ->
        do_send_scan_command(actor, agent_id, model_id, path)
    end
  end

  defp do_send_scan_command(actor, agent_id, model_id, path) do
    try do
      case Executor.execute_action(
             agent_id,
             "scan_model",
             %{
               model_id: model_id,
               path: path,
               force: true
             },
             actor: actor,
             organization_id: actor.organization_id,
             persist_action: true
           ) do
        {:ok, _} -> :ok
        {:error, reason} -> {:error, reason}
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

  defp scan_error_status(:unsupported_no_agent), do: :unprocessable_entity
  defp scan_error_status(:unsupported_no_local_model_path), do: :unprocessable_entity
  defp scan_error_status(_), do: :service_unavailable

  defp scan_error_payload(reason, model_id)
       when reason in [:unsupported_no_agent, :unsupported_no_local_model_path] do
    %{
      status: "unsupported",
      error: "Model Guard unsupported for this model",
      reason: format_error(reason),
      model_id: model_id,
      model_guard: %{
        status: "unsupported",
        decision: "unknown",
        enforcement: "decision_only",
        action: "none",
        evidence: %{
          error: "Model Guard on-demand scan is unsupported for this model",
          reason: format_error(reason)
        }
      }
    }
  end

  defp scan_error_payload(_reason, model_id) do
    %{
      error: "Failed to send scan command",
      reason: "scan_failed",
      model_id: model_id,
      model_guard: %{
        status: "failed",
        decision: "unknown",
        enforcement: "failed",
        action: "none",
        evidence: %{
          reason: "scan_failed"
        }
      }
    }
  end

  defp attach_model_guard_summaries(organization_id, models) do
    provenances =
      models
      |> Enum.flat_map(&model_lookup_ids/1)
      |> Enum.uniq()
      |> latest_provenances_by_model_id(organization_id)

    Enum.map(models, fn model ->
      provenance =
        model
        |> model_lookup_ids()
        |> Enum.find_value(&Map.get(provenances, &1))

      Map.put(model, :model_guard, ModelPolicy.model_guard_summary(provenance))
    end)
  end

  defp model_guard_for_model(organization_id, model) do
    model
    |> model_lookup_ids()
    |> latest_provenances_by_model_id(organization_id)
    |> Map.values()
    |> List.first()
    |> ModelPolicy.model_guard_summary()
  end

  defp latest_provenances_by_model_id([], _organization_id), do: %{}

  defp latest_provenances_by_model_id(model_ids, organization_id) do
    from(p in ModelProvenance,
      where: p.organization_id == ^organization_id and p.model_id in ^model_ids,
      order_by: [asc: p.model_id, desc: p.downloaded_at],
      select: p
    )
    |> Repo.all()
    |> Enum.reduce(%{}, fn provenance, acc ->
      Map.put_new(acc, provenance.model_id, provenance)
    end)
  end

  defp model_lookup_ids(model) when is_map(model) do
    [
      model[:model_id],
      model["model_id"],
      model[:name],
      model["name"],
      model[:id],
      model["id"]
    ]
    |> Enum.reject(&(is_nil(&1) or &1 == ""))
    |> Enum.map(&to_string/1)
  end

  defp model_lookup_ids(_), do: []

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
    organization_id = current_organization_id!(conn)
    {:ok, actor} = response_actor(conn, organization_id)
    reason = params["reason"]

    opts = if reason, do: [reason: reason], else: []

    case ResponseActions.quarantine_model(model_id, actor, opts) do
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

      {:error, _reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Quarantine failed", reason: "action_failed", model_id: model_id})
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
    organization_id = current_organization_id!(conn)
    {:ok, actor} = response_actor(conn, organization_id)
    reason = params["reason"]

    opts = if reason, do: [reason: reason], else: []

    case ResponseActions.block_model(model_id, actor, opts) do
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

      {:error, _reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Block failed", reason: "action_failed", model_id: model_id})
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
    organization_id = current_organization_id!(conn)
    {:ok, actor} = response_actor(conn, organization_id)

    case ResponseActions.unblock_model(model_id, actor) do
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

      {:error, _reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Unblock failed", reason: "action_failed", model_id: model_id})
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
    organization_id = current_organization_id!(conn)
    {:ok, actor} = response_actor(conn, organization_id)
    acknowledge_risk = params["acknowledge_risk"] == true
    force_restore = params["force_restore"] == true

    opts = [acknowledge_risk: acknowledge_risk, force_restore: force_restore]

    case ResponseActions.restore_model(model_id, actor, opts) do
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

      {:error, _reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Restore failed", reason: "action_failed", model_id: model_id})
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
    organization_id = current_organization_id!(conn)

    case ResponseActions.get_model_status(organization_id, model_id) do
      {:ok, result} ->
        json(conn, %{
          model_id: result.model_id,
          status: result.status,
          model_guard: model_guard_for_model(organization_id, %{model_id: result.model_id})
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Model not found", model_id: model_id})
    end
  end

  @doc """
  Bulk quarantine is unavailable until a durable batch reservation/outbox can
  guarantee all-or-nothing admission before any mutation or dispatch.

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
  def bulk_quarantine(conn, %{"model_ids" => model_ids}) when is_list(model_ids),
    do: bulk_action_unavailable(conn)

  def bulk_quarantine(conn, _params), do: bulk_action_unavailable(conn)

  @doc """
  Bulk block is unavailable until a durable batch reservation/outbox can
  guarantee all-or-nothing admission before any mutation or dispatch.

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
  def bulk_block(conn, %{"model_ids" => model_ids}) when is_list(model_ids),
    do: bulk_action_unavailable(conn)

  def bulk_block(conn, _params), do: bulk_action_unavailable(conn)

  defp bulk_action_unavailable(conn) do
    conn
    |> put_status(:service_unavailable)
    |> json(%{
      error: "Bulk AI model action unavailable",
      code: "bulk_action_unavailable",
      retryable: false
    })
  end

  defp ensure_model!(conn, organization_id, model_id) do
    case AIInventory.assess_risk(organization_id, model_id) do
      {:ok, _assessment} -> :ok
      _ -> raise Phoenix.Router.NoRouteError, conn: conn, router: TamanduaServerWeb.Router
    end
  end

  defp current_organization_id!(conn) do
    user = conn.assigns[:current_user]
    organization_id = conn.assigns[:current_organization_id]

    case ResponseActor.from_user_scope(user, organization_id) do
      {:ok, %{organization_id: canonical}} -> canonical
      _ -> raise Phoenix.Router.NoRouteError, conn: conn, router: TamanduaServerWeb.Router
    end
  end

  defp response_actor(conn, organization_id) do
    ResponseActor.from_user_scope(conn.assigns[:current_user], organization_id)
  end
end
