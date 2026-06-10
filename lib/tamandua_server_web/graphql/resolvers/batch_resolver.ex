defmodule TamanduaServerWeb.GraphQL.Resolvers.BatchResolver do
  @moduledoc """
  GraphQL resolvers for batch operations.
  """

  require Logger

  alias TamanduaServer.BatchOperations
  alias TamanduaServer.Repo
  alias Oban.Job

  # ===========================================================================
  # Alert Batch Operations
  # ===========================================================================

  def close_alerts(_parent, %{ids: ids} = args, %{context: context}) do
    organization_id = context.current_organization_id
    user_id = context.current_user.id
    resolution_notes = Map.get(args, :resolution_notes, "Batch closed via GraphQL")

    case BatchOperations.batch_close_alerts(
      organization_id,
      ids,
      user_id: user_id,
      resolution_notes: resolution_notes
    ) do
      {:ok, result} ->
        {:ok, format_batch_result(result)}

      {:error, {:batch_too_large, max}} ->
        {:error, "Batch size exceeds maximum of #{max}"}

      {:error, reason} ->
        {:error, inspect(reason)}
    end
  end

  def assign_alerts(_parent, %{ids: ids, assigned_to_id: assigned_to_id}, %{context: context}) do
    organization_id = context.current_organization_id
    user_id = context.current_user.id

    case BatchOperations.batch_assign_alerts(
      organization_id,
      ids,
      assigned_to_id,
      user_id: user_id
    ) do
      {:ok, result} ->
        {:ok, format_batch_result(result)}

      {:error, {:batch_too_large, max}} ->
        {:error, "Batch size exceeds maximum of #{max}"}

      {:error, reason} ->
        {:error, inspect(reason)}
    end
  end

  def tag_alerts(_parent, %{ids: ids} = args, %{context: context}) do
    organization_id = context.current_organization_id
    user_id = context.current_user.id

    add_tags = Map.get(args, :add_tags, [])
    remove_tags = Map.get(args, :remove_tags, [])

    case BatchOperations.batch_tag_alerts(
      organization_id,
      ids,
      user_id: user_id,
      add_tags: add_tags,
      remove_tags: remove_tags
    ) do
      {:ok, result} ->
        {:ok, format_batch_result(result)}

      {:error, {:batch_too_large, max}} ->
        {:error, "Batch size exceeds maximum of #{max}"}

      {:error, reason} ->
        {:error, inspect(reason)}
    end
  end

  def delete_alerts(_parent, %{ids: ids}, %{context: context}) do
    organization_id = context.current_organization_id
    user_id = context.current_user.id

    case BatchOperations.batch_delete_alerts(
      organization_id,
      ids,
      user_id: user_id
    ) do
      {:ok, result} ->
        {:ok, format_batch_result(result)}

      {:error, {:batch_too_large, max}} ->
        {:error, "Batch size exceeds maximum of #{max}"}

      {:error, reason} ->
        {:error, inspect(reason)}
    end
  end

  # ===========================================================================
  # IOC Batch Operations
  # ===========================================================================

  def import_iocs(_parent, %{iocs: iocs} = args, %{context: context}) do
    organization_id = context.current_organization_id

    source = Map.get(args, :source, "graphql_import")
    deduplicate = Map.get(args, :deduplicate, true)

    # Convert Absinthe camelCase keys to snake_case
    iocs_converted = Enum.map(iocs, &convert_ioc_input/1)

    case BatchOperations.batch_import_iocs(
      organization_id,
      iocs_converted,
      source: source,
      deduplicate: deduplicate
    ) do
      {:ok, %{job_id: job_id}} ->
        {:ok, %{
          job_id: job_id,
          status_url: "/api/v1/jobs/#{job_id}",
          imported: nil,
          skipped: nil,
          failed: nil
        }}

      {:ok, result} ->
        {:ok, %{
          imported: result.imported,
          skipped: result.skipped,
          failed: format_ioc_failures(result.failed),
          job_id: nil,
          status_url: nil
        }}

      {:error, {:batch_too_large, max}} ->
        {:error, "Batch size exceeds maximum of #{max}"}

      {:error, reason} ->
        {:error, inspect(reason)}
    end
  end

  def delete_iocs(_parent, %{ids: ids}, %{context: context}) do
    organization_id = context.current_organization_id

    case BatchOperations.batch_delete_iocs(organization_id, ids) do
      {:ok, result} ->
        {:ok, format_batch_result(result)}

      {:error, {:batch_too_large, max}} ->
        {:error, "Batch size exceeds maximum of #{max}"}

      {:error, reason} ->
        {:error, inspect(reason)}
    end
  end

  def update_iocs(_parent, %{ids: ids, updates: updates}, %{context: context}) do
    organization_id = context.current_organization_id

    # Convert camelCase to snake_case
    updates_converted = %{
      expires_at: Map.get(updates, :expires_at),
      add_tags: Map.get(updates, :add_tags),
      remove_tags: Map.get(updates, :remove_tags)
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()

    case BatchOperations.batch_update_iocs(organization_id, ids, updates_converted) do
      {:ok, result} ->
        {:ok, format_batch_result(result)}

      {:error, {:batch_too_large, max}} ->
        {:error, "Batch size exceeds maximum of #{max}"}

      {:error, reason} ->
        {:error, inspect(reason)}
    end
  end

  # ===========================================================================
  # Agent Batch Operations
  # ===========================================================================

  def execute_command(_parent, %{agent_ids: agent_ids, command: command} = args, %{context: context}) do
    organization_id = context.current_organization_id
    user_id = context.current_user.id
    reason = Map.get(args, :reason, "Batch command via GraphQL")

    result = case command do
      "isolate" ->
        BatchOperations.batch_isolate_agents(
          organization_id,
          agent_ids,
          user_id: user_id,
          reason: reason
        )

      "scan" ->
        BatchOperations.batch_scan_agents(
          organization_id,
          agent_ids,
          user_id: user_id
        )

      "collect_forensics" ->
        BatchOperations.batch_collect_forensics(
          organization_id,
          agent_ids,
          user_id: user_id
        )

      _ ->
        {:error, {:invalid_command, command}}
    end

    case result do
      {:ok, %{job_id: job_id}} ->
        {:ok, %{
          job_id: job_id,
          message: "Batch command '#{command}' queued for #{length(agent_ids)} agents",
          status_url: "/api/v1/jobs/#{job_id}"
        }}

      {:error, {:batch_too_large, max}} ->
        {:error, "Batch size exceeds maximum of #{max}"}

      {:error, {:invalid_command, cmd}} ->
        {:error, "Invalid command: #{cmd}. Valid commands: isolate, scan, collect_forensics"}

      {:error, reason} ->
        {:error, inspect(reason)}
    end
  end

  # ===========================================================================
  # Job Status
  # ===========================================================================

  def get_job_status(_parent, %{job_id: job_id}, _resolution) do
    case Repo.get(Job, job_id) do
      nil ->
        {:error, "Job not found"}

      job ->
        meta = job.meta || %{}

        {:ok, %{
          id: job.id,
          state: to_string(job.state),
          queue: job.queue,
          worker: job.worker,
          progress: meta["progress"] || 0,
          message: meta["message"],
          attempted_at: job.attempted_at,
          completed_at: job.completed_at,
          scheduled_at: job.scheduled_at,
          errors: format_job_errors(job.errors),
          attempt: job.attempt,
          max_attempts: job.max_attempts
        }}
    end
  end

  # ===========================================================================
  # Helper Functions
  # ===========================================================================

  defp format_batch_result(%{success_count: count, failed: failed}) do
    %{
      success_count: count,
      failed: Enum.map(failed, fn failure ->
        %{
          id: failure.id,
          reason: failure.reason
        }
      end)
    }
  end

  defp format_ioc_failures([]), do: []
  defp format_ioc_failures(failures) do
    Enum.map(failures, fn failure ->
      %{
        type: failure.type || "unknown",
        value: failure.value || "unknown",
        reason: failure.reason || "unknown error"
      }
    end)
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
  defp format_job_errors(_), do: []

  defp convert_ioc_input(ioc) do
    # Convert camelCase Absinthe keys to snake_case for database
    %{
      "type" => ioc.type,
      "value" => ioc.value,
      "description" => Map.get(ioc, :description),
      "severity" => Map.get(ioc, :severity),
      "confidence" => Map.get(ioc, :confidence),
      "tags" => Map.get(ioc, :tags),
      "malware_family" => Map.get(ioc, :malware_family),
      "threat_actor" => Map.get(ioc, :threat_actor),
      "campaign" => Map.get(ioc, :campaign),
      "expires_at" => Map.get(ioc, :expires_at)
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end
end
