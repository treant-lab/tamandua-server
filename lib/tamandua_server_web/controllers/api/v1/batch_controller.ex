defmodule TamanduaServerWeb.API.V1.BatchController do
  @moduledoc """
  REST API controller for batch operations.

  ## Endpoints

  ### Alert Batch Operations
  - POST /api/v1/alerts/batch/close - Close up to 1000 alerts
  - POST /api/v1/alerts/batch/assign - Assign alerts in bulk
  - POST /api/v1/alerts/batch/tag - Add/remove tags
  - POST /api/v1/alerts/batch/delete - Delete multiple alerts

  ### IOC Batch Operations
  - POST /api/v1/iocs/batch/import - Import CSV/JSON (10K+ IOCs)
  - POST /api/v1/iocs/batch/delete - Delete multiple IOCs
  - POST /api/v1/iocs/batch/update - Update expiration/tags

  ### Agent Batch Operations
  - POST /api/v1/agents/batch/isolate - Isolate multiple agents
  - POST /api/v1/agents/batch/scan - Trigger scans
  - POST /api/v1/agents/batch/collect-forensics - Collect forensics

  ### Job Tracking
  - GET /api/v1/jobs/:id - Get job status and progress

  ## Rate Limits
  - Maximum 1000 items per batch
  - Maximum 10 batches per minute per organization
  """

  use TamanduaServerWeb, :controller

  import Ecto.Query

  require Logger

  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.BatchOperations
  alias TamanduaServer.Repo
  alias Oban.Job

  action_fallback(TamanduaServerWeb.FallbackController)

  # ===========================================================================
  # Alert Batch Operations
  # ===========================================================================

  @doc """
  Close multiple alerts.

  ## Request Body
  ```json
  {
    "alert_ids": ["uuid1", "uuid2", ...],
    "resolution_notes": "False positive - batch closed"
  }
  ```

  ## Response
  ```json
  {
    "success_count": 100,
    "failed": []
  }
  ```
  """
  def close_alerts(conn, %{"alert_ids" => alert_ids} = params) do
    organization_id = conn.assigns.current_organization_id
    user_id = conn.assigns.current_user.id

    resolution_notes = Map.get(params, "resolution_notes", "Batch closed")

    case BatchOperations.batch_close_alerts(
           organization_id,
           alert_ids,
           user_id: user_id,
           resolution_notes: resolution_notes
         ) do
      {:ok, result} ->
        conn
        |> put_status(:ok)
        |> json(result)

      {:error, {:batch_too_large, max}} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Batch size exceeds maximum of #{max}"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Assign multiple alerts to a user.

  ## Request Body
  ```json
  {
    "alert_ids": ["uuid1", "uuid2", ...],
    "assigned_to_id": "user-uuid"
  }
  ```
  """
  def assign_alerts(conn, %{"alert_ids" => alert_ids, "assigned_to_id" => assigned_to_id}) do
    organization_id = conn.assigns.current_organization_id
    user_id = conn.assigns.current_user.id

    case BatchOperations.batch_assign_alerts(
           organization_id,
           alert_ids,
           assigned_to_id,
           user_id: user_id
         ) do
      {:ok, result} ->
        conn
        |> put_status(:ok)
        |> json(result)

      {:error, {:batch_too_large, max}} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Batch size exceeds maximum of #{max}"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Add or remove tags from multiple alerts.

  ## Request Body
  ```json
  {
    "alert_ids": ["uuid1", "uuid2", ...],
    "add_tags": ["tag1", "tag2"],
    "remove_tags": ["tag3"]
  }
  ```
  """
  def tag_alerts(conn, %{"alert_ids" => alert_ids} = params) do
    organization_id = conn.assigns.current_organization_id
    user_id = conn.assigns.current_user.id

    add_tags = Map.get(params, "add_tags", [])
    remove_tags = Map.get(params, "remove_tags", [])

    case BatchOperations.batch_tag_alerts(
           organization_id,
           alert_ids,
           user_id: user_id,
           add_tags: add_tags,
           remove_tags: remove_tags
         ) do
      {:ok, result} ->
        conn
        |> put_status(:ok)
        |> json(result)

      {:error, {:batch_too_large, max}} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Batch size exceeds maximum of #{max}"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Delete multiple alerts.

  ## Request Body
  ```json
  {
    "alert_ids": ["uuid1", "uuid2", ...]
  }
  ```
  """
  def delete_alerts(conn, %{"alert_ids" => alert_ids}) do
    organization_id = conn.assigns.current_organization_id
    user_id = conn.assigns.current_user.id

    case BatchOperations.batch_delete_alerts(
           organization_id,
           alert_ids,
           user_id: user_id
         ) do
      {:ok, result} ->
        conn
        |> put_status(:ok)
        |> json(result)

      {:error, {:batch_too_large, max}} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Batch size exceeds maximum of #{max}"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: inspect(reason)})
    end
  end

  # ===========================================================================
  # IOC Batch Operations
  # ===========================================================================

  @doc """
  Import IOCs from CSV or JSON.

  Supports large imports (10K+) via background job processing.

  ## Request Body
  ```json
  {
    "iocs": [
      {
        "type": "hash_sha256",
        "value": "abc123...",
        "description": "Malware hash",
        "severity": "high",
        "tags": ["malware", "ransomware"]
      },
      ...
    ],
    "source": "threat_feed",
    "deduplicate": true
  }
  ```

  ## Response (Sync)
  ```json
  {
    "imported": 100,
    "skipped": 5,
    "failed": []
  }
  ```

  ## Response (Async)
  ```json
  {
    "job_id": 12345,
    "message": "Large import queued for background processing"
  }
  ```
  """
  def import_iocs(conn, %{"iocs" => iocs} = params) do
    organization_id = conn.assigns.current_organization_id

    source = Map.get(params, "source", "api_import")
    deduplicate = Map.get(params, "deduplicate", true)

    case BatchOperations.batch_import_iocs(
           organization_id,
           iocs,
           source: source,
           deduplicate: deduplicate
         ) do
      {:ok, %{job_id: job_id}} ->
        conn
        |> put_status(:accepted)
        |> json(%{
          job_id: job_id,
          message: "Large import queued for background processing",
          status_url: "/api/v1/jobs/#{job_id}"
        })

      {:ok, result} ->
        conn
        |> put_status(:ok)
        |> json(result)

      {:error, {:batch_too_large, max}} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Batch size exceeds maximum of #{max}"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Delete multiple IOCs.

  ## Request Body
  ```json
  {
    "ioc_ids": ["uuid1", "uuid2", ...]
  }
  ```
  """
  def delete_iocs(conn, %{"ioc_ids" => ioc_ids}) do
    organization_id = conn.assigns.current_organization_id

    case BatchOperations.batch_delete_iocs(organization_id, ioc_ids) do
      {:ok, result} ->
        conn
        |> put_status(:ok)
        |> json(result)

      {:error, {:batch_too_large, max}} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Batch size exceeds maximum of #{max}"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Update expiration or tags for multiple IOCs.

  ## Request Body
  ```json
  {
    "ioc_ids": ["uuid1", "uuid2", ...],
    "updates": {
      "expires_at": "2026-12-31T23:59:59Z",
      "add_tags": ["confirmed"],
      "remove_tags": ["unverified"]
    }
  }
  ```
  """
  def update_iocs(conn, %{"ioc_ids" => ioc_ids, "updates" => updates}) do
    organization_id = conn.assigns.current_organization_id

    # Parse expires_at if present
    updates =
      if expires_at_str = updates["expires_at"] do
        case DateTime.from_iso8601(expires_at_str) do
          {:ok, dt, _offset} ->
            Map.put(updates, :expires_at, dt)

          _ ->
            updates
        end
      else
        updates
      end

    # Convert string keys to atoms for add_tags/remove_tags
    updates =
      updates
      |> Map.put(:add_tags, updates["add_tags"])
      |> Map.put(:remove_tags, updates["remove_tags"])

    case BatchOperations.batch_update_iocs(organization_id, ioc_ids, updates) do
      {:ok, result} ->
        conn
        |> put_status(:ok)
        |> json(result)

      {:error, {:batch_too_large, max}} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Batch size exceeds maximum of #{max}"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: inspect(reason)})
    end
  end

  # ===========================================================================
  # Agent Batch Operations
  # ===========================================================================

  @doc """
  Isolate multiple agents.

  ## Request Body
  ```json
  {
    "agent_ids": ["uuid1", "uuid2", ...],
    "reason": "Suspected compromise - batch isolation"
  }
  ```

  ## Response
  ```json
  {
    "job_id": 12345,
    "message": "Agent isolation queued",
    "status_url": "/api/v1/jobs/12345"
  }
  ```
  """
  def isolate_agents(conn, %{"agent_ids" => agent_ids} = params) do
    organization_id = conn.assigns.current_organization_id
    user_id = conn.assigns.current_user.id

    reason = Map.get(params, "reason", "Batch isolation")

    result =
      case reject_mobile_batch_isolation(organization_id, agent_ids) do
        :ok ->
          BatchOperations.batch_isolate_agents(
            organization_id,
            agent_ids,
            user_id: user_id,
            reason: reason
          )

        {:error, _reason} = error ->
          error
      end

    case result do
      {:ok, %{job_id: job_id}} ->
        conn
        |> put_status(:accepted)
        |> json(%{
          job_id: job_id,
          message: "Agent isolation queued",
          status_url: "/api/v1/jobs/#{job_id}"
        })

      {:error, {:batch_too_large, max}} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Batch size exceeds maximum of #{max}"})

      {:error, {:mobile_agents_unsupported, mobile_agent_ids}} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{
          error: "Batch network isolation is not available for mobile endpoints",
          platform: "mobile",
          unsupported_agent_ids: mobile_agent_ids,
          supported_surface: "mobile endpoint commands"
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Trigger scans on multiple agents.

  ## Request Body
  ```json
  {
    "agent_ids": ["uuid1", "uuid2", ...]
  }
  ```
  """
  def scan_agents(conn, %{"agent_ids" => agent_ids}) do
    organization_id = conn.assigns.current_organization_id
    user_id = conn.assigns.current_user.id

    case BatchOperations.batch_scan_agents(
           organization_id,
           agent_ids,
           user_id: user_id
         ) do
      {:ok, %{job_id: job_id}} ->
        conn
        |> put_status(:accepted)
        |> json(%{
          job_id: job_id,
          message: "Agent scans queued",
          status_url: "/api/v1/jobs/#{job_id}"
        })

      {:error, {:batch_too_large, max}} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Batch size exceeds maximum of #{max}"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Collect forensics from multiple agents.

  ## Request Body
  ```json
  {
    "agent_ids": ["uuid1", "uuid2", ...]
  }
  ```
  """
  def collect_forensics(conn, %{"agent_ids" => agent_ids}) do
    organization_id = conn.assigns.current_organization_id
    user_id = conn.assigns.current_user.id

    case BatchOperations.batch_collect_forensics(
           organization_id,
           agent_ids,
           user_id: user_id
         ) do
      {:ok, %{job_id: job_id}} ->
        conn
        |> put_status(:accepted)
        |> json(%{
          job_id: job_id,
          message: "Forensics collection queued",
          status_url: "/api/v1/jobs/#{job_id}"
        })

      {:error, {:batch_too_large, max}} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Batch size exceeds maximum of #{max}"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: inspect(reason)})
    end
  end

  # ===========================================================================
  # Job Progress Tracking
  # ===========================================================================

  @doc """
  Get job status and progress.

  ## Response
  ```json
  {
    "id": 12345,
    "state": "executing",
    "progress": 45,
    "message": "Processing chunk 3",
    "attempted_at": "2026-02-20T10:30:00Z",
    "completed_at": null,
    "errors": []
  }
  ```

  States: scheduled, available, executing, retryable, completed, discarded, cancelled
  """
  def get_job(conn, %{"id" => job_id}) do
    case Repo.get(Job, job_id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Job not found"})

      job ->
        # Extract progress from meta
        meta = job.meta || %{}
        progress = meta["progress"] || 0
        message = meta["message"] || ""

        response = %{
          id: job.id,
          state: job.state,
          queue: job.queue,
          worker: job.worker,
          progress: progress,
          message: message,
          attempted_at: job.attempted_at,
          completed_at: job.completed_at,
          scheduled_at: job.scheduled_at,
          errors: format_job_errors(job.errors),
          attempt: job.attempt,
          max_attempts: job.max_attempts
        }

        conn
        |> put_status(:ok)
        |> json(response)
    end
  end

  defp format_job_errors([]), do: []

  defp format_job_errors(errors) when is_list(errors) do
    Enum.map(errors, fn error ->
      %{
        attempt: error["attempt"],
        at: error["at"],
        error: error["error"]
      }
    end)
  end

  defp reject_mobile_batch_isolation(_organization_id, []), do: :ok

  defp reject_mobile_batch_isolation(organization_id, agent_ids) do
    mobile_agent_ids =
      Agent
      |> where([a], a.organization_id == ^organization_id and a.id in ^agent_ids)
      |> select([a], {a.id, a.os_type})
      |> Repo.all()
      |> Enum.filter(fn {_id, os_type} -> mobile_os?(os_type) end)
      |> Enum.map(fn {id, _os_type} -> id end)

    case mobile_agent_ids do
      [] -> :ok
      ids -> {:error, {:mobile_agents_unsupported, ids}}
    end
  end

  defp mobile_os?(os_type) do
    os = String.downcase(to_string(os_type || ""))

    String.contains?(os, "android") or String.contains?(os, "ios") or
      String.contains?(os, "iphone") or String.contains?(os, "ipad")
  end

  defp format_job_errors(_), do: []
end
