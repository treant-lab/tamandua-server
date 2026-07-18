defmodule TamanduaServer.Detection.DNSCommandDispatch do
  @moduledoc """
  Bounded request-lane dispatch for tenant DNS enforcement commands.

  Durable DNS blocklist persistence remains the source of truth. This module
  reports only whether endpoint commands were queued during the bounded
  request window; it never upgrades a queue failure or timeout to success.
  A durable outbox/reconciler remains production hardening beyond this lane.
  """

  @default_max_jobs 500
  @hard_max_jobs 2_000
  @default_max_concurrency 4
  @hard_max_concurrency 16
  @default_deadline_ms 5_000
  @hard_deadline_ms 30_000

  @type result_status :: :queued | :failed | :timed_out
  @type job_result :: %{
          required(:agent_id) => String.t(),
          required(:domain) => String.t(),
          required(:status) => result_status(),
          optional(:command_id) => term(),
          optional(:reason) => atom()
        }

  @spec dispatch(:block | :unblock, [String.t()], String.t(), String.t(), keyword()) ::
          {:ok, map()} | {:error, map()}
  def dispatch(action, domains, organization_id, reason, opts \\ [])

  def dispatch(action, domains, organization_id, reason, opts)
      when action in [:block, :unblock] and is_list(domains) and is_binary(organization_id) and
             is_binary(reason) and is_list(opts) do
    limits = limits(opts)
    registry_fun = Keyword.get(opts, :registry_fun, &default_registry/1)

    result =
      with {:ok, organization_id} <- canonical_organization_id(organization_id),
           {:ok, domains} <- validate_domains(domains, reason),
           {:ok, agents} <- online_agents(registry_fun, organization_id),
           {:ok, fence} <- validate_fence_option(opts, organization_id, domains, agents) do
        total_jobs = length(agents) * length(domains)

        cond do
          total_jobs == 0 ->
            # Persistence succeeded, but no endpoint command was queued and this
            # request lane has no durable outbox for later delivery. Report the
            # outcome as partial instead of upgrading it to delivery success.
            {:error, summary(:no_online_agents, [], 0, limits)}

          total_jobs > limits.max_jobs ->
            {:error,
             summary(:rejected, [], total_jobs, limits)
             |> Map.put(:reason, :job_limit_exceeded)}

          true ->
            jobs = build_jobs(agents, domains, action, organization_id, reason, fence, opts)
            queue_fun = Keyword.get(opts, :queue_fun, &default_queue/4)
            task_supervisor = Keyword.get(opts, :task_supervisor, TamanduaServer.TaskSupervisor)

            case with_node_admission(fn ->
                   jobs
                   |> run_jobs(queue_fun, task_supervisor, limits)
                   |> summarize(total_jobs, limits)
                 end) do
              :dispatch_busy ->
                {:error,
                 summary(:rejected, [], total_jobs, limits)
                 |> Map.put(:reason, :dispatch_busy)}

              result ->
                result
            end
        end
      else
        {:error, reason} ->
          {:error,
           summary(:failed, [], 0, limits)
           |> Map.put(:reason, reason)}
      end

    emit_dispatch_telemetry(result, action, organization_id)
    result
  rescue
    _error ->
      {:error,
       summary(:failed, [], 0, limits(opts))
       |> Map.put(:reason, :dispatch_unavailable)}
  catch
    :exit, _reason ->
      {:error,
       summary(:failed, [], 0, limits(opts))
       |> Map.put(:reason, :dispatch_unavailable)}
  end

  def dispatch(_action, _domains, _organization_id, _reason, opts) do
    {:error,
     summary(:rejected, [], 0, limits(if(is_list(opts), do: opts, else: [])))
     |> Map.put(:reason, :invalid_dispatch_request)}
  end

  defp validate_domains(domains, reason) do
    # Dispatch is a public internal boundary and must not rely on every caller
    # having persisted through DNSBlocklist first. Reuse the same strict DNS
    # and payload contract before values can reach the endpoint hosts file.
    case TamanduaServer.Detection.DNSBlocklist.prepare_batch(
           domains,
           reason,
           "dns_command_dispatch",
           "dns_command_dispatch"
         ) do
      {:ok, normalized_domains} -> {:ok, normalized_domains}
      {:error, reason} -> {:error, reason}
    end
  end

  defp canonical_organization_id(organization_id) do
    case Ecto.UUID.cast(organization_id) do
      {:ok, canonical} -> {:ok, canonical}
      :error -> {:error, :invalid_organization}
    end
  end

  defp online_agents(registry_fun, organization_id) do
    case registry_fun.(organization_id) do
      agents when is_list(agents) ->
        {:ok,
         agents
         |> Enum.filter(&online_agent?/1)
         |> Enum.uniq_by(& &1.agent_id)}

      _unexpected ->
        {:error, :invalid_registry_result}
    end
  rescue
    _error -> {:error, :registry_unavailable}
  catch
    :exit, _reason -> {:error, :registry_unavailable}
  end

  defp online_agent?(%{agent_id: agent_id, status: status})
       when is_binary(agent_id) and status in [:online, "online"],
       do: true

  defp online_agent?(_agent), do: false

  defp build_jobs(agents, domains, action, organization_id, reason, fence, opts) do
    seed = to_string(Keyword.get(opts, :idempotency_key) || random_dispatch_seed())

    for agent <- agents, domain <- domains do
      %{
        agent_id: agent.agent_id,
        domain: domain,
        action: action,
        reason: reason,
        dns_policy_fence: fence_payload(fence, domain),
        idempotency_key:
          job_idempotency_key(seed, organization_id, action, agent.agent_id, domain)
      }
    end
  end

  defp validate_fence_option(opts, organization_id, domains, agents) do
    case Keyword.fetch(opts, :dns_policy_fence) do
      :error ->
        {:ok, nil}

      {:ok,
       %{
         schema_version: "dns_policy_fence/v1",
         policy_stream_id: stream_id,
         entry_versions: versions
       }}
      when is_binary(stream_id) and is_map(versions) ->
        with {:ok, canonical_stream} <- canonical_organization_id(stream_id),
             true <- canonical_stream == organization_id,
             true <- map_size(versions) == length(domains),
             true <-
               Enum.all?(
                 domains,
                 &(is_integer(versions[&1]) and versions[&1] > 0 and
                     versions[&1] <= 9_223_372_036_854_775_807)
               ),
             true <- Enum.all?(Map.keys(versions), &(&1 in domains)),
             true <- Enum.all?(agents, &fence_capable?/1) do
          {:ok, %{policy_stream_id: canonical_stream, entry_versions: versions}}
        else
          false -> {:error, :dns_policy_fence_not_ready}
          _ -> {:error, :invalid_dns_policy_fence}
        end

      {:ok, _invalid} ->
        {:error, :invalid_dns_policy_fence}
    end
  end

  defp fence_capable?(agent) do
    capabilities = Map.get(agent, :capabilities) || Map.get(agent, "capabilities") || []
    is_list(capabilities) and "dns_policy_fence_v1" in capabilities
  end

  defp fence_payload(nil, _domain), do: nil

  defp fence_payload(fence, domain) do
    %{
      schema_version: "dns_policy_fence/v1",
      policy_stream_id: fence.policy_stream_id,
      entry_version: Map.fetch!(fence.entry_versions, domain)
    }
  end

  defp run_jobs(jobs, queue_fun, task_supervisor, limits) do
    deadline = System.monotonic_time(:millisecond) + limits.deadline_ms

    {pending, running, start_failures} =
      start_available_jobs(jobs, %{}, queue_fun, task_supervisor, limits.max_concurrency)

    collect_results(
      pending,
      running,
      start_failures,
      queue_fun,
      task_supervisor,
      limits,
      deadline
    )
  rescue
    _error -> Enum.map(jobs, &failed_result(&1, :task_supervisor_unavailable))
  catch
    :exit, _reason -> Enum.map(jobs, &failed_result(&1, :task_supervisor_unavailable))
  end

  defp start_available_jobs(
         pending,
         running,
         queue_fun,
         task_supervisor,
         max_concurrency,
         failures \\ []
       )

  defp start_available_jobs(
         pending,
         running,
         queue_fun,
         task_supervisor,
         max_concurrency,
         failures
       )
       when pending != [] and map_size(running) < max_concurrency do
    [job | rest] = pending

    case start_queue_task(task_supervisor, job, queue_fun) do
      {:ok, task} ->
        start_available_jobs(
          rest,
          Map.put(running, task.ref, %{task: task, job: job}),
          queue_fun,
          task_supervisor,
          max_concurrency,
          failures
        )

      {:error, reason} ->
        start_available_jobs(
          rest,
          running,
          queue_fun,
          task_supervisor,
          max_concurrency,
          [failed_result(job, reason) | failures]
        )
    end
  end

  defp start_available_jobs(
         pending,
         running,
         _queue_fun,
         _task_supervisor,
         _max_concurrency,
         failures
       ),
       do: {pending, running, failures}

  defp start_queue_task(task_supervisor, job, queue_fun) do
    owner = self()

    {:ok,
     Task.Supervisor.async_nolink(task_supervisor, fn ->
       queue_one_with_owner(job, queue_fun, owner)
     end)}
  rescue
    _error -> {:error, :task_supervisor_unavailable}
  catch
    :exit, _reason -> {:error, :task_supervisor_unavailable}
  end

  # The supervised task is intentionally not linked to the HTTP/Playbook
  # caller, so a queue crash cannot take that caller down. Monitor the owner
  # explicitly and run the potentially blocking queue call in a linked worker:
  # owner death or deadline shutdown then terminates the worker as well.
  defp queue_one_with_owner(job, queue_fun, owner) do
    previous_trap_exit = Process.flag(:trap_exit, true)
    owner_ref = Process.monitor(owner)
    task = self()

    worker =
      spawn_link(fn ->
        send(task, {:dns_queue_result, self(), queue_one(job, queue_fun)})
      end)

    try do
      receive do
        {:dns_queue_result, ^worker, result} ->
          result

        {:EXIT, ^worker, reason} ->
          failed_result(job, normalize_worker_exit(reason))

        {:DOWN, ^owner_ref, :process, ^owner, _reason} ->
          Process.exit(worker, :kill)
          failed_result(job, :dispatch_owner_down)
      end
    after
      Process.demonitor(owner_ref, [:flush])
      if Process.alive?(worker), do: Process.exit(worker, :kill)
      Process.flag(:trap_exit, previous_trap_exit)
    end
  end

  defp collect_results([], running, results, _queue_fun, _task_supervisor, _limits, _deadline)
       when map_size(running) == 0,
       do: Enum.reverse(results)

  defp collect_results(
         pending,
         running,
         results,
         queue_fun,
         task_supervisor,
         limits,
         deadline
       ) do
    remaining_ms = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {ref, result} when is_reference(ref) ->
        case Map.pop(running, ref) do
          {nil, _running} ->
            collect_results(
              pending,
              running,
              results,
              queue_fun,
              task_supervisor,
              limits,
              deadline
            )

          {%{task: task}, remaining} ->
            Process.demonitor(task.ref, [:flush])

            {pending, running, start_failures} =
              start_available_jobs(
                pending,
                remaining,
                queue_fun,
                task_supervisor,
                limits.max_concurrency
              )

            collect_results(
              pending,
              running,
              start_failures ++ [result | results],
              queue_fun,
              task_supervisor,
              limits,
              deadline
            )
        end

      {:DOWN, ref, :process, _pid, _reason} when is_reference(ref) ->
        case Map.pop(running, ref) do
          {nil, _running} ->
            collect_results(
              pending,
              running,
              results,
              queue_fun,
              task_supervisor,
              limits,
              deadline
            )

          {%{job: job}, remaining} ->
            {pending, running, start_failures} =
              start_available_jobs(
                pending,
                remaining,
                queue_fun,
                task_supervisor,
                limits.max_concurrency
              )

            collect_results(
              pending,
              running,
              start_failures ++ [failed_result(job, :task_crashed) | results],
              queue_fun,
              task_supervisor,
              limits,
              deadline
            )
        end
    after
      remaining_ms ->
        timed_out =
          Enum.map(running, fn {_ref, %{task: task, job: job}} ->
            _ = Task.shutdown(task, :brutal_kill)
            timed_out_result(job)
          end)

        Enum.reverse(results) ++ timed_out ++ Enum.map(pending, &timed_out_result/1)
    end
  end

  defp queue_one(job, queue_fun) do
    command_type = if job.action == :block, do: "block_domain", else: "unblock_domain"

    case queue_fun.(
           job.agent_id,
           command_type,
           command_params(job),
           idempotency_key: job.idempotency_key
         ) do
      {:ok, command} ->
        %{
          agent_id: job.agent_id,
          domain: job.domain,
          status: :queued,
          command_id: command_id(command)
        }

      {:error, reason} ->
        failed_result(job, normalize_reason(reason))

      _unexpected ->
        failed_result(job, :invalid_queue_result)
    end
  rescue
    _error -> failed_result(job, :queue_unavailable)
  catch
    :exit, _reason -> failed_result(job, :queue_unavailable)
  end

  defp command_params(%{dns_policy_fence: nil} = job),
    do: %{domain: job.domain, reason: job.reason}

  defp command_params(job),
    do: %{
      domain: job.domain,
      reason: job.reason,
      dns_policy_fence: job.dns_policy_fence
    }

  defp summarize(results, total_jobs, limits) do
    queued = Enum.count(results, &(&1.status == :queued))
    failed = Enum.count(results, &(&1.status == :failed))
    timed_out = Enum.count(results, &(&1.status == :timed_out))

    status =
      cond do
        queued == total_jobs -> :queued
        queued > 0 -> :partial
        timed_out > 0 and failed == 0 -> :timed_out
        true -> :failed
      end

    response = summary(status, results, total_jobs, limits)

    if status == :queued, do: {:ok, response}, else: {:error, response}
  end

  defp summary(status, results, total_jobs, limits) do
    %{
      status: status,
      total_jobs: total_jobs,
      queued: Enum.count(results, &(&1.status == :queued)),
      failed: Enum.count(results, &(&1.status == :failed)),
      timed_out: Enum.count(results, &(&1.status == :timed_out)),
      max_jobs: limits.max_jobs,
      deadline_ms: limits.deadline_ms,
      delivery: :bounded_request_lane,
      durable_outbox: false,
      results: Enum.sort_by(results, &{&1.agent_id, &1.domain})
    }
  end

  defp failed_result(job, reason),
    do: %{agent_id: job.agent_id, domain: job.domain, status: :failed, reason: reason}

  defp timed_out_result(job),
    do: %{
      agent_id: job.agent_id,
      domain: job.domain,
      status: :timed_out,
      reason: :queue_outcome_unknown
    }

  defp command_id(command) when is_map(command),
    do: Map.get(command, :id) || Map.get(command, "id")

  defp command_id(_command), do: nil

  defp normalize_reason(reason) when is_atom(reason), do: reason
  defp normalize_reason(_reason), do: :queue_failed

  defp normalize_worker_exit(:normal), do: :invalid_queue_result
  defp normalize_worker_exit(_reason), do: :queue_unavailable

  defp emit_dispatch_telemetry({outcome, summary}, action, organization_id)
       when outcome in [:ok, :error] and is_map(summary) do
    :telemetry.execute(
      [:tamandua, :dns, :command_dispatch],
      %{
        total_jobs: Map.get(summary, :total_jobs, 0),
        queued: Map.get(summary, :queued, 0),
        failed: Map.get(summary, :failed, 0),
        timed_out: Map.get(summary, :timed_out, 0)
      },
      %{
        outcome: outcome,
        status: Map.get(summary, :status, :unknown),
        reason: Map.get(summary, :reason),
        action: action,
        organization_id: organization_id,
        delivery: :bounded_request_lane,
        durable_outbox: false
      }
    )
  rescue
    _error -> :ok
  end

  # One bounded dispatch owns the node-local lane at a time. The VM lock is
  # released automatically when the request/Playbook owner dies, preventing
  # concurrent requests from multiplying the per-request concurrency cap.
  defp with_node_admission(fun) do
    lock = {{__MODULE__, :node_dispatch_lane, node()}, self()}

    case :global.trans(lock, fun, [node()], 0) do
      :aborted -> :dispatch_busy
      {:aborted, _reason} -> :dispatch_busy
      result -> result
    end
  catch
    :exit, _reason -> :dispatch_busy
  end

  defp job_idempotency_key(seed, organization_id, action, agent_id, domain) do
    :crypto.hash(
      :sha256,
      [
        "dns-dispatch-v1\0",
        seed,
        "\0",
        organization_id,
        "\0",
        to_string(action),
        "\0",
        agent_id,
        "\0",
        domain
      ]
    )
    |> Base.encode16(case: :lower)
  end

  defp random_dispatch_seed do
    16
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  defp limits(opts) do
    config =
      case Application.get_env(:tamandua_server, :dns_command_dispatch, []) do
        value when is_list(value) -> value
        _invalid -> []
      end

    %{
      max_jobs: bounded(opts, config, :max_jobs, @default_max_jobs, @hard_max_jobs),
      max_concurrency:
        bounded(
          opts,
          config,
          :max_concurrency,
          @default_max_concurrency,
          @hard_max_concurrency
        ),
      deadline_ms: bounded(opts, config, :deadline_ms, @default_deadline_ms, @hard_deadline_ms)
    }
  end

  defp bounded(opts, config, key, default, hard_max) do
    value = Keyword.get(opts, key, Keyword.get(config, key, default))
    if is_integer(value) and value > 0, do: min(value, hard_max), else: default
  end

  defp default_registry(organization_id),
    do: TamanduaServer.Agents.Registry.list_for_org(organization_id)

  defp default_queue(agent_id, command_type, params, opts),
    do: TamanduaServer.Agents.CommandManager.queue_command(agent_id, command_type, params, opts)
end
