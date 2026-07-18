defmodule TamanduaServer.Workers.BatchJobWorker do
  @moduledoc """
  Oban worker for long-running batch operations.

  Handles:
  - Large IOC imports (10K+)
  - Batch agent commands (async execution)
  - Progress tracking via job meta

  Job status is tracked in Oban's jobs table. Query with:
      Oban.Job |> Repo.get(job_id)
  """

  use Oban.Worker,
    queue: :batch_operations,
    max_attempts: 3,
    priority: 1

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents
  alias TamanduaServer.Response
  alias TamanduaServer.BatchOperations
  alias TamanduaServer.Webhooks

  @impl Oban.Worker
  def perform(%Oban.Job{args: args} = job) do
    operation = args["operation"]
    organization_id = args["organization_id"]

    Logger.info("[BatchJobWorker] Starting #{operation} for org #{organization_id}, job #{job.id}")

    result = case operation do
      "import_iocs" ->
        handle_import_iocs(args, job)

      "agent_command" ->
        handle_agent_command(args, job)

      other ->
        {:error, {:unknown_operation, other}}
    end

    case result do
      {:ok, stats} ->
        Logger.info("[BatchJobWorker] Completed #{operation}: #{inspect(stats)}")

        # Send webhook notification
        send_webhook_notification(organization_id, operation, stats, job.id)

        :ok

      {:error, reason} ->
        Logger.error("[BatchJobWorker] Failed #{operation}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # ===========================================================================
  # Operation Handlers
  # ===========================================================================

  defp handle_import_iocs(args, job) do
    organization_id = args["organization_id"]
    iocs = args["data"]
    opts = Map.get(args, "opts", %{}) |> Map.to_list()

    total = length(iocs)
    Logger.info("[BatchJobWorker] Importing #{total} IOCs")

    # Process in chunks to avoid memory issues
    chunk_size = 500

    iocs
    |> Enum.chunk_every(chunk_size)
    |> Enum.with_index()
    |> Enum.reduce({:ok, %{imported: 0, skipped: 0, failed: []}}, fn {chunk, chunk_idx}, acc ->
      case acc do
        {:ok, stats} ->
          # Update progress
          progress = ((chunk_idx * chunk_size) / total * 100) |> round()
          update_job_progress(job.id, progress, "Processing chunk #{chunk_idx + 1}")

          # Import chunk
          case BatchOperations.import_iocs_sync(organization_id, chunk, opts) do
            {:ok, chunk_stats} ->
              merged_stats = %{
                imported: stats.imported + chunk_stats.imported,
                skipped: stats.skipped + chunk_stats.skipped,
                failed: stats.failed ++ chunk_stats.failed
              }
              {:ok, merged_stats}

            {:error, reason} ->
              Logger.error("[BatchJobWorker] Chunk #{chunk_idx} failed: #{inspect(reason)}")
              # Continue with next chunk, track failures
              failed_items = Enum.map(chunk, fn ioc ->
                %{type: ioc["type"], value: ioc["value"], reason: inspect(reason)}
              end)
              merged_stats = Map.update!(stats, :failed, &(&1 ++ failed_items))
              {:ok, merged_stats}
          end

        error ->
          error
      end
    end)
  end

  defp handle_agent_command(args, job) do
    organization_id = args["organization_id"]
    command = args["command"]
    agent_ids = args["agent_ids"]
    opts = Map.get(args, "opts", %{}) |> Map.to_list()

    user_id = Keyword.get(opts, :user_id)
    reason = Keyword.get(opts, :reason, "Batch operation")

    total = length(agent_ids)
    Logger.info("[BatchJobWorker] Executing #{command} on #{total} agents")

    # Execute commands in parallel with concurrency limit
    agent_ids
    |> Enum.with_index()
    |> Task.async_stream(
      fn {agent_id, idx} ->
        # Update progress every 10 agents
        if rem(idx, 10) == 0 do
          progress = (idx / total * 100) |> round()
          update_job_progress(job.id, progress, "Processing agent #{idx + 1}/#{total}")
        end

        execute_agent_command(organization_id, agent_id, command, user_id, reason)
      end,
      max_concurrency: 10,
      timeout: 30_000,
      on_timeout: :kill_task
    )
    |> Enum.reduce(%{success: 0, failed: []}, fn
      {:ok, {:ok, _result}}, acc ->
        Map.update!(acc, :success, &(&1 + 1))

      {:ok, {:error, {agent_id, reason}}}, acc ->
        Map.update!(acc, :failed, &(&1 ++ [%{agent_id: agent_id, reason: reason}]))

      {:exit, _reason}, acc ->
        Map.update!(acc, :failed, &(&1 ++ [%{agent_id: "unknown", reason: "timeout"}]))
    end)
    |> then(fn stats -> {:ok, stats} end)
  end

  defp execute_agent_command(organization_id, agent_id, command, user_id, reason) do
    case Agents.get_agent_for_org(organization_id, agent_id) do
      {:ok, agent} ->
        execute_command_for_agent(agent, command, user_id, reason)

      {:error, :not_found} ->
        {:error, {agent_id, :not_found}}
    end
  end

  defp execute_command_for_agent(agent, "isolate", user_id, _reason) do
    case Response.Executor.isolate_network(agent.id, actor: build_actor(agent, user_id)) do
      {:ok, _} -> {:ok, :isolated}
      {:error, reason} -> {:error, {agent.id, reason}}
    end
  end

  defp execute_command_for_agent(agent, "scan", _user_id, _reason) do
    # Batch scans carry no per-agent path input; mirror the group batch-scan
    # default (agent_groups_live) of scanning from the OS root.
    case Response.Executor.trigger_scan(agent.id, default_scan_path(agent.os_type)) do
      {:ok, _} -> {:ok, :scan_triggered}
      {:error, reason} -> {:error, {agent.id, reason}}
    end
  end

  defp execute_command_for_agent(agent, "collect_forensics", user_id, _reason) do
    case Response.Executor.collect_forensics(agent.id, %{actor: build_actor(agent, user_id)}) do
      {:ok, _} -> {:ok, :forensics_collected}
      {:error, reason} -> {:error, {agent.id, reason}}
    end
  end

  defp execute_command_for_agent(agent, command, _user_id, _reason) do
    {:error, {agent.id, {:unknown_command, command}}}
  end

  # The agent was already resolved through get_agent_for_org/2, so scoping the
  # actor to the agent's organization matches the authorization the Executor
  # enforces for org-scoped actors.
  defp build_actor(agent, user_id) do
    %{organization_id: agent.organization_id, user_id: user_id}
  end

  defp default_scan_path("windows"), do: "C:\\"
  defp default_scan_path(_), do: "/"

  # ===========================================================================
  # Progress Tracking
  # ===========================================================================

  defp update_job_progress(job_id, progress, message) do
    # Update job meta with progress
    # This allows clients to query job status via GET /api/v1/jobs/:id
    try do
      job = Repo.get(Oban.Job, job_id)

      if job do
        meta = Map.merge(job.meta || %{}, %{
          "progress" => progress,
          "message" => message,
          "updated_at" => DateTime.utc_now() |> DateTime.to_iso8601()
        })

        job
        |> Ecto.Changeset.change(meta: meta)
        |> Repo.update()
      end
    rescue
      e ->
        Logger.warning("[BatchJobWorker] Failed to update progress: #{inspect(e)}")
    end
  end

  # ===========================================================================
  # Webhook Notifications
  # ===========================================================================

  defp send_webhook_notification(organization_id, operation, stats, job_id) do
    # Send webhook notification on completion
    # This allows external systems to be notified of batch operation completion
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      try do
        Webhooks.Dispatcher.dispatch_event(
          "batch_operation_completed",
          to_string(job_id),
          %{
            operation: operation,
            stats: stats,
            completed_at: DateTime.utc_now()
          },
          organization_id: organization_id
        )
      rescue
        e ->
          Logger.debug("[BatchJobWorker] Webhook notification failed: #{inspect(e)}")
      end
    end)
  end
end
