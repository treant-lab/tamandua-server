defmodule TamanduaServer.Workers.ShadowInvestigationWorker do
  @moduledoc """
  Executes one durable investigation observation.

  The worker is restricted to `ShadowOrchestrator`, which records bounded,
  tenant-scoped observational evidence and never calls response, remediation,
  live-response, LLM or action execution modules.
  """

  use Oban.Worker,
    queue: :ai_investigations,
    max_attempts: 3,
    unique: [
      period: :infinity,
      fields: [:worker, :args],
      keys: [:organization_id, :run_id],
      states: [:available, :scheduled, :executing, :retryable, :completed]
    ]

  alias TamanduaServer.Investigations.ShadowOrchestrator

  @finalization_grace_ms 30_000

  @impl Oban.Worker
  def timeout(_job) do
    worker_timeout_ms() + @finalization_grace_ms
  end

  @impl Oban.Worker
  def perform(
        %Oban.Job{
          args: %{"organization_id" => _organization_id, "run_id" => _run_id}
        } = job
      ) do
    perform_result(job, &ShadowOrchestrator.process/2)
  end

  def perform(%Oban.Job{}), do: {:discard, :invalid_job_arguments}

  @doc false
  def perform_result(
        %Oban.Job{
          args: %{"organization_id" => organization_id, "run_id" => run_id},
          attempt: attempt,
          max_attempts: max_attempts
        },
        process_fun
      )
      when is_function(process_fun, 2) do
    result =
      run_bounded(
        fn -> process_fun.(organization_id, run_id) end,
        worker_timeout_ms()
      )

    case result do
      {:ok, _run} ->
        :ok

      {:error, reason} when reason in [:run_not_found_in_organization, :invalid_run_id] ->
        {:discard, reason}

      {:error, reason} when attempt >= max_attempts ->
        _ = ShadowOrchestrator.mark_failed(organization_id, run_id, reason)
        {:discard, :retries_exhausted}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp run_bounded(fun, timeout_ms) do
    case Process.whereis(TamanduaServer.TaskSupervisor) do
      nil ->
        {:error, :task_supervisor_unavailable}

      _pid ->
        task = Task.Supervisor.async_nolink(TamanduaServer.TaskSupervisor, fun)

        case Task.yield(task, timeout_ms) || Task.shutdown(task, :brutal_kill) do
          {:ok, result} -> result
          {:exit, reason} -> {:error, {:worker_exit, reason}}
          nil -> {:error, :worker_timeout}
        end
    end
  end

  defp worker_timeout_ms do
    :tamandua_server
    |> Application.get_env(ShadowOrchestrator, [])
    |> Keyword.get(:worker_timeout_ms, 30_000)
    |> min(120_000)
    |> max(1_000)
  end
end
