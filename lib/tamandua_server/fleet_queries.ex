defmodule TamanduaServer.FleetQueries do
  @moduledoc """
  Fleet-wide live osquery runs.

  This context intentionally reuses the existing `agent_commands` delivery path:
  a fleet query run owns metadata and target aggregation, while each endpoint
  execution remains an `osquery_query` command handled by the agent runtime.
  """

  import Ecto.Query

  alias TamanduaServer.Agents.{AgentCommand, CommandManager, Registry}
  alias TamanduaServer.FleetQueries.{FleetQueryRun, FleetQueryTarget}
  alias TamanduaServer.Repo

  @default_timeout_seconds 300
  @default_max_rows 500
  @default_max_output_bytes 262_144
  @default_max_targets 100
  @terminal_command_statuses ~w(completed failed)

  @doc """
  Create a fleet osquery run and queue one `osquery_query` command per eligible
  connected agent.
  """
  def create_osquery_run(organization_id, attrs, opts \\ [])
      when is_binary(organization_id) and is_map(attrs) do
    query = attrs["query"] || attrs[:query]

    with :ok <- validate_query(query) do
      requested_agent_ids = normalize_agent_ids(attrs["agent_ids"] || attrs[:agent_ids])
      options = build_options(attrs)
      run_attrs = build_run_attrs(organization_id, query, requested_agent_ids, options, opts)

      Repo.transaction(fn ->
        run =
          %FleetQueryRun{}
          |> FleetQueryRun.changeset(run_attrs)
          |> Repo.insert!()

        queue_result =
          CommandManager.queue_fleet_osquery(organization_id, query,
            agent_ids: empty_to_nil(requested_agent_ids),
            priority: Map.fetch!(options, "priority"),
            timeout: Map.fetch!(options, "timeout_seconds"),
            max_rows: Map.fetch!(options, "max_rows"),
            max_output_bytes: Map.fetch!(options, "max_output_bytes"),
            max_targets: Map.fetch!(options, "max_targets"),
            require_capability: Map.fetch!(options, "require_capability"),
            fleet_query_run_id: run.id
          )

        insert_targets!(run, queue_result)
        refresh_run!(run.id)
      end)
    end
  end

  @doc """
  List recent fleet query runs for one organization.
  """
  def list_runs(organization_id, opts \\ []) when is_binary(organization_id) do
    limit = opts |> Keyword.get(:limit, 50) |> clamp_int(1, 200)

    FleetQueryRun
    |> where([r], r.organization_id == ^organization_id)
    |> order_by([r], desc: r.inserted_at)
    |> limit(^limit)
    |> Repo.all()
  end

  @doc """
  Fetch and refresh one run for an organization.
  """
  def get_run(organization_id, run_id) when is_binary(organization_id) and is_binary(run_id) do
    FleetQueryRun
    |> where([r], r.organization_id == ^organization_id and r.id == ^run_id)
    |> Repo.one()
    |> case do
      nil -> {:error, :not_found}
      run -> {:ok, refresh_run!(run.id)}
    end
  end

  @doc """
  Return targets for a run, refreshing command-derived states first.
  """
  def list_targets(organization_id, run_id) do
    with {:ok, run} <- get_run(organization_id, run_id) do
      targets =
        FleetQueryTarget
        |> where([t], t.fleet_query_run_id == ^run.id)
        |> order_by([t], asc: t.inserted_at)
        |> Repo.all()

      {:ok, targets}
    end
  end

  @doc """
  Cancel pending target commands for a fleet query run.

  The underlying command queue only supports cancelling commands that have not
  been dispatched yet. Sent or acknowledged commands are reported as
  non-cancellable instead of pretending the endpoint execution was stopped.
  """
  def cancel_run(organization_id, run_id) when is_binary(organization_id) and is_binary(run_id) do
    with {:ok, run} <- get_run(organization_id, run_id),
         {:ok, targets} <- list_targets(organization_id, run_id) do
      result =
        Enum.reduce(targets, %{cancelled: [], already_sent: [], skipped: [], not_cancellable: []}, fn target, acc ->
          cancel_target(target, acc)
        end)

      refreshed_run = refresh_run!(run.id)
      {:ok, refreshed_run, result}
    end
  end

  @doc """
  Refresh target and run status from associated `agent_commands`.
  """
  def refresh_run!(run_id) do
    targets =
      FleetQueryTarget
      |> where([t], t.fleet_query_run_id == ^run_id)
      |> Repo.all()

    Enum.each(targets, &refresh_target!/1)

    refreshed_targets =
      FleetQueryTarget
      |> where([t], t.fleet_query_run_id == ^run_id)
      |> Repo.all()

    counts = Enum.frequencies_by(refreshed_targets, & &1.status)
    target_count = length(refreshed_targets)
    queued_count = count_statuses(counts, ~w(queued sent acknowledged))
    skipped_count = Map.get(counts, "skipped", 0)
    completed_count = Map.get(counts, "completed", 0)
    failed_count = Map.get(counts, "failed", 0)

    status =
      cond do
        target_count == 0 -> "failed"
        queued_count > 0 -> "running"
        failed_count > 0 or skipped_count > 0 -> "completed_with_errors"
        true -> "completed"
      end

    run = Repo.get!(FleetQueryRun, run_id)
    completed_at = run.completed_at || terminal_run_completed_at(status)

    run
    |> FleetQueryRun.changeset(%{
      status: status,
      target_count: target_count,
      queued_count: queued_count,
      skipped_count: skipped_count,
      completed_count: completed_count,
      failed_count: failed_count,
      completed_at: completed_at
    })
    |> Repo.update!()
  end

  defp validate_query(query) when is_binary(query) do
    if String.trim(query) == "" do
      {:error, :missing_query}
    else
      :ok
    end
  end

  defp validate_query(_), do: {:error, :missing_query}

  defp build_run_attrs(organization_id, query, requested_agent_ids, options, opts) do
    %{
      organization_id: organization_id,
      created_by_user_id: Keyword.get(opts, :created_by_user_id),
      query: query,
      query_hash: hash_query(query),
      status: "queued",
      requested_agent_ids: requested_agent_ids,
      filters: %{},
      options: options,
      started_at: DateTime.utc_now() |> DateTime.truncate(:second)
    }
  end

  defp build_options(attrs) do
    %{
      "timeout_seconds" =>
        attrs
        |> get_any(["timeout_seconds", :timeout_seconds, "timeout", :timeout], @default_timeout_seconds)
        |> clamp_int(5, 3600),
      "max_rows" =>
        attrs
        |> get_any(["max_rows", :max_rows], @default_max_rows)
        |> clamp_int(1, 10_000),
      "max_output_bytes" =>
        attrs
        |> get_any(["max_output_bytes", :max_output_bytes], @default_max_output_bytes)
        |> clamp_int(1024, 5_242_880),
      "max_targets" =>
        attrs
        |> get_any(["max_targets", :max_targets], @default_max_targets)
        |> clamp_int(1, 10_000),
      "priority" => attrs |> get_any(["priority", :priority], 1) |> clamp_int(0, 10),
      "require_capability" => get_any(attrs, ["require_capability", :require_capability], true)
    }
  end

  defp insert_targets!(run, queue_result) do
    Enum.each(queue_result.queued, fn command ->
      agent_info = registry_agent(command.agent_id)

      %FleetQueryTarget{}
      |> FleetQueryTarget.changeset(%{
        fleet_query_run_id: run.id,
        agent_id: command.agent_id,
        hostname: map_get_any(agent_info, [:hostname, "hostname"]),
        os_type: map_get_any(agent_info, [:os_type, "os_type"]),
        status: target_status(command.status),
        agent_command_id: command.id
      })
      |> Repo.insert!()
    end)

    Enum.each(queue_result.skipped, fn skipped ->
      agent_info = registry_agent(skipped.agent_id)

      %FleetQueryTarget{}
      |> FleetQueryTarget.changeset(%{
        fleet_query_run_id: run.id,
        agent_id: skipped.agent_id,
        hostname: map_get_any(agent_info, [:hostname, "hostname"]),
        os_type: map_get_any(agent_info, [:os_type, "os_type"]),
        status: "skipped",
        skip_reason: to_string(skipped.reason)
      })
      |> Repo.insert!()
    end)
  end

  defp cancel_target(%FleetQueryTarget{status: "skipped"} = target, acc) do
    %{acc | skipped: [target.id | acc.skipped]}
  end

  defp cancel_target(%FleetQueryTarget{status: status} = target, acc)
       when status in ["completed", "failed"] do
    %{acc | not_cancellable: [target.id | acc.not_cancellable]}
  end

  defp cancel_target(%FleetQueryTarget{agent_command_id: nil} = target, acc) do
    %{acc | not_cancellable: [target.id | acc.not_cancellable]}
  end

  defp cancel_target(%FleetQueryTarget{agent_command_id: command_id} = target, acc) do
    case CommandManager.cancel_command(command_id) do
      :ok -> %{acc | cancelled: [target.id | acc.cancelled]}
      {:error, :already_sent} -> %{acc | already_sent: [target.id | acc.already_sent]}
      {:error, _reason} -> %{acc | not_cancellable: [target.id | acc.not_cancellable]}
    end
  end

  defp refresh_target!(%FleetQueryTarget{agent_command_id: nil} = target), do: target

  defp refresh_target!(%FleetQueryTarget{} = target) do
    case Repo.get(AgentCommand, target.agent_command_id) do
      nil ->
        target

      command ->
        command = fail_expired_command!(command)

        target
        |> FleetQueryTarget.changeset(%{
          status: target_status(command.status),
          error: command.error,
          result_summary: summarize_result(command.result),
          completed_at: completed_at(command)
        })
        |> Repo.update!()
    end
  end

  defp fail_expired_command!(%AgentCommand{} = command) do
    if expired_command?(command) do
      command
      |> AgentCommand.mark_failed("Command expired before completion")
      |> Repo.update!()
    else
      command
    end
  end

  defp expired_command?(%AgentCommand{status: status, expires_at: %DateTime{} = expires_at})
       when status not in @terminal_command_statuses do
    DateTime.compare(expires_at, AgentCommand.utc_now_second()) == :lt
  end

  defp expired_command?(_), do: false

  defp completed_at(%AgentCommand{status: status, completed_at: completed_at})
       when status in @terminal_command_statuses,
       do: completed_at

  defp completed_at(_), do: nil

  defp summarize_result(nil), do: nil

  defp summarize_result(result) when is_map(result) do
    rows = result["rows"] || result[:rows] || result["data"] || result[:data] || []

    %{
      "row_count" => row_count(rows),
      "result_status" => result["result_status"] || result[:result_status],
      "truncated" => result["truncated"] || result[:truncated] || false
    }
  end

  defp summarize_result(_), do: %{"row_count" => nil}

  defp row_count(rows) when is_list(rows), do: length(rows)
  defp row_count(_), do: nil

  defp target_status(status) when status in ["sent", "acknowledged", "completed", "failed"],
    do: status

  defp target_status("pending"), do: "queued"
  defp target_status(_), do: "queued"

  defp terminal_run_completed_at(status)
       when status in ["completed", "completed_with_errors", "failed"],
       do: DateTime.utc_now() |> DateTime.truncate(:second)

  defp terminal_run_completed_at(_), do: nil

  defp registry_agent(nil), do: %{}

  defp registry_agent(agent_id) do
    case Registry.get(agent_id) do
      {:ok, agent} -> agent
      _ -> %{}
    end
  end

  defp normalize_agent_ids(nil), do: []
  defp normalize_agent_ids(agent_ids) when is_list(agent_ids), do: Enum.map(agent_ids, &to_string/1)
  defp normalize_agent_ids(agent_id) when is_binary(agent_id), do: [agent_id]
  defp normalize_agent_ids(_), do: []

  defp empty_to_nil([]), do: nil
  defp empty_to_nil(value), do: value

  defp hash_query(query), do: :crypto.hash(:sha256, query) |> Base.encode16(case: :lower)

  defp get_any(map, keys, default) do
    Enum.find_value(keys, default, &Map.get(map, &1))
  end

  defp clamp_int(value, min, max) do
    value
    |> parse_int(min)
    |> Kernel.max(min)
    |> Kernel.min(max)
  end

  defp parse_int(value, _default) when is_integer(value), do: value

  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(_, default), do: default

  defp count_statuses(counts, statuses) do
    Enum.reduce(statuses, 0, fn status, acc -> acc + Map.get(counts, status, 0) end)
  end

  defp map_get_any(nil, _keys), do: nil

  defp map_get_any(map, keys) when is_map(map) do
    Enum.find_value(keys, &Map.get(map, &1))
  end

  defp map_get_any(_, _keys), do: nil
end
