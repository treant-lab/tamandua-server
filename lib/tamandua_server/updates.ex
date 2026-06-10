defmodule TamanduaServer.Updates do
  @moduledoc """
  The Updates context.

  Manages agent update packages, rollout strategies, and per-agent update
  tracking. Supports canary deployments with automatic rollback when failure
  rates exceed the safety threshold.

  ## Rollout Strategies

  - **immediate** -- All agents receive the update at once.
  - **canary** -- A configurable percentage of agents receive the update first.
    If failure rate stays below 5%, the rollout is promoted to all agents.
  - **staged** -- Rollout advances through predefined stages (e.g. 10% -> 50% -> 100%).
  - **manual** -- Admin must explicitly advance each stage.

  ## Auto-Rollback

  If more than 5% of canary agents report failure, the rollout is
  automatically rolled back and all agents in the rollout are marked
  as `rolled_back`.
  """

  import Ecto.Query, warn: false
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.TenantScope
  alias TamanduaServer.Updates.UpdatePackage
  alias TamanduaServer.Updates.Rollout
  alias TamanduaServer.Updates.AgentUpdate
  alias TamanduaServer.Agents.Agent

  # If more than this percentage of canary agents fail, auto-rollback
  @canary_failure_threshold 5.0
  # Minimum number of canary reports before evaluating failure rate
  @canary_min_reports 3

  # ---------------------------------------------------------------------------
  # Update Packages -- CRUD
  # ---------------------------------------------------------------------------

  @doc """
  List all update packages for an organization, newest first.

  ## Options
  - `:platform` - Filter by platform
  - `:limit` - Maximum results (default 50)
  - `:offset` - Pagination offset
  """
  def list_packages(organization_id, opts \\ []) do
    query =
      UpdatePackage
      |> TenantScope.scope_to_tenant(organization_id)
      |> order_by([p], desc: p.released_at, desc: p.inserted_at)

    query =
      case Keyword.get(opts, :platform) do
        nil -> query
        platform -> where(query, [p], p.platform == ^platform)
      end

    query =
      case Keyword.get(opts, :limit, 50) do
        nil -> query
        limit -> limit(query, ^limit)
      end

    query =
      case Keyword.get(opts, :offset) do
        nil -> query
        offset -> offset(query, ^offset)
      end

    Repo.all(query)
  end

  @doc """
  Get a single update package by ID, scoped to organization.
  """
  def get_package(organization_id, id) do
    UpdatePackage
    |> TenantScope.scope_to_tenant(organization_id)
    |> Repo.get(id)
    |> case do
      nil -> {:error, :not_found}
      package -> {:ok, package}
    end
  end

  @doc """
  Get a single update package by ID (no org scoping). Used internally.
  """
  def get_package!(id) do
    Repo.get!(UpdatePackage, id)
  end

  @doc """
  Create a new update package.
  """
  def create_package(organization_id, attrs) do
    %UpdatePackage{}
    |> UpdatePackage.changeset(Map.put(attrs, "organization_id", organization_id))
    |> Repo.insert()
  end

  @doc """
  Update an existing update package.
  """
  def update_package(%UpdatePackage{} = package, attrs) do
    package
    |> UpdatePackage.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete an update package. Fails if there are active rollouts.
  """
  def delete_package(%UpdatePackage{} = package) do
    active_rollouts =
      Rollout
      |> where([r], r.update_package_id == ^package.id)
      |> where([r], r.status in ~w(pending rolling_out paused))
      |> Repo.aggregate(:count)

    if active_rollouts > 0 do
      {:error, "cannot delete package with active rollouts"}
    else
      Repo.delete(package)
    end
  end

  # ---------------------------------------------------------------------------
  # Rollouts
  # ---------------------------------------------------------------------------

  @doc """
  Create a rollout for an update package.

  Automatically sets `started_at` and transitions to `rolling_out` for
  immediate strategy. For other strategies, remains in `pending` until
  explicitly started or the RolloutSupervisor picks it up.

  ## Parameters

  - `organization_id` - The tenant organization
  - `attrs` - Must include `update_package_id` and optionally `strategy`,
    `canary_percentage`, `stages`.
  """
  def create_rollout(organization_id, attrs) do
    attrs =
      attrs
      |> Map.put("organization_id", organization_id)
      |> maybe_set_immediate_start()

    %Rollout{}
    |> Rollout.changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, rollout} ->
        Logger.info("[Updates] Rollout #{rollout.id} created (strategy=#{rollout.strategy})")

        if rollout.strategy == "immediate" do
          Task.Supervisor.start_child(
            TamanduaServer.TaskSupervisor,
            fn -> assign_all_agents_to_rollout(rollout) end
          )
        end

        {:ok, rollout}

      error ->
        error
    end
  end

  defp maybe_set_immediate_start(attrs) do
    case Map.get(attrs, "strategy", Map.get(attrs, :strategy)) do
      "immediate" ->
        attrs
        |> Map.put("status", "rolling_out")
        |> Map.put("started_at", DateTime.utc_now())

      _ ->
        attrs
    end
  end

  @doc """
  List rollouts for an organization, newest first.
  """
  def list_rollouts(organization_id, opts \\ []) do
    query =
      Rollout
      |> TenantScope.scope_to_tenant(organization_id)
      |> order_by([r], desc: r.inserted_at)
      |> preload(:update_package)

    query =
      case Keyword.get(opts, :status) do
        nil -> query
        status -> where(query, [r], r.status == ^status)
      end

    query =
      case Keyword.get(opts, :limit, 50) do
        nil -> query
        limit -> limit(query, ^limit)
      end

    Repo.all(query)
  end

  @doc """
  Get a single rollout by ID with preloaded associations.
  """
  def get_rollout(organization_id, id) do
    Rollout
    |> TenantScope.scope_to_tenant(organization_id)
    |> preload([:update_package, :agent_updates])
    |> Repo.get(id)
    |> case do
      nil -> {:error, :not_found}
      rollout -> {:ok, rollout}
    end
  end

  @doc """
  Get a rollout by ID (no org scoping). Used internally by the supervisor.
  """
  def get_rollout!(id) do
    Rollout
    |> preload([:update_package, :agent_updates])
    |> Repo.get!(id)
  end

  # ---------------------------------------------------------------------------
  # Agent Update Check (called by agent via controller)
  # ---------------------------------------------------------------------------

  @doc """
  Check whether an agent should receive an update.

  Given an agent ID and its current version, finds the latest applicable
  update package for the agent's platform/architecture and checks whether
  this agent is included in any active rollout for that package.

  Returns `{:ok, manifest}` if an update is available, or `:up_to_date`.
  """
  def check_for_update(agent_id, current_version) do
    with {:ok, agent} <- fetch_agent(agent_id),
         {:ok, package} <- find_latest_package(agent, current_version),
         {:ok, rollout} <- find_active_rollout(package),
         true <- agent_in_rollout?(agent_id, rollout) do
      # Ensure this agent has an agent_update record
      ensure_agent_update_record(agent, rollout, package, current_version)

      {:ok,
       %{
         version: package.version,
         platform: package.platform,
         architecture: package.architecture,
         sha256: package.sha256_hash,
         signature: package.signature,
         download_url: package.download_url,
         size: package.size_bytes,
         release_notes: package.release_notes,
         is_critical: package.is_critical,
         rollout_id: rollout.id,
         package_id: package.id
       }}
    else
      false -> :up_to_date
      :up_to_date -> :up_to_date
      {:error, _} = err -> err
    end
  end

  defp fetch_agent(agent_id) do
    case Repo.get(Agent, agent_id) do
      nil -> {:error, :agent_not_found}
      agent -> {:ok, agent}
    end
  end

  defp find_latest_package(agent, current_version) do
    platform = normalize_platform(agent.os_type)

    query =
      UpdatePackage
      |> where([p], p.platform == ^platform)
      |> where([p], p.organization_id == ^agent.organization_id)
      |> order_by([p], desc: p.released_at, desc: p.inserted_at)
      |> limit(1)

    case Repo.one(query) do
      nil ->
        :up_to_date

      package ->
        if version_newer?(package.version, current_version) and
             meets_min_version?(package, current_version) do
          {:ok, package}
        else
          :up_to_date
        end
    end
  end

  defp find_active_rollout(package) do
    query =
      Rollout
      |> where([r], r.update_package_id == ^package.id)
      |> where([r], r.status == "rolling_out")
      |> order_by([r], desc: r.inserted_at)
      |> limit(1)

    case Repo.one(query) do
      nil -> :up_to_date
      rollout -> {:ok, rollout}
    end
  end

  defp agent_in_rollout?(agent_id, rollout) do
    case rollout.strategy do
      "immediate" ->
        true

      "canary" ->
        in_percentage?(agent_id, rollout.canary_percentage)

      "staged" ->
        current_percentage = get_current_stage_percentage(rollout)
        in_percentage?(agent_id, current_percentage)

      "manual" ->
        # For manual, check if agent has been explicitly assigned
        agent_explicitly_assigned?(agent_id, rollout.id)
    end
  end

  defp in_percentage?(_agent_id, percentage) when percentage >= 100, do: true
  defp in_percentage?(_agent_id, percentage) when percentage <= 0, do: false

  defp in_percentage?(agent_id, percentage) do
    # Deterministic hash-based selection: same agent always gets same bucket
    <<hash_int::unsigned-32, _rest::binary>> = :crypto.hash(:md5, to_string(agent_id))
    bucket = rem(hash_int, 10_000) / 100.0
    bucket < percentage
  end

  defp get_current_stage_percentage(rollout) do
    case Enum.at(rollout.stages, rollout.current_stage) do
      %{"percentage" => p} -> p
      %{percentage: p} -> p
      nil -> 0
    end
  end

  defp agent_explicitly_assigned?(agent_id, rollout_id) do
    AgentUpdate
    |> where([au], au.agent_id == ^agent_id and au.rollout_id == ^rollout_id)
    |> Repo.exists?()
  end

  defp ensure_agent_update_record(agent, rollout, package, current_version) do
    case Repo.get_by(AgentUpdate, agent_id: agent.id, rollout_id: rollout.id) do
      nil ->
        %AgentUpdate{}
        |> AgentUpdate.changeset(%{
          agent_id: agent.id,
          rollout_id: rollout.id,
          update_package_id: package.id,
          previous_version: current_version,
          new_version: package.version,
          status: "pending"
        })
        |> Repo.insert(on_conflict: :nothing)

      _existing ->
        :ok
    end
  end

  # ---------------------------------------------------------------------------
  # Agent Status Reports
  # ---------------------------------------------------------------------------

  @doc """
  Record an agent's update status report.

  Agents call this to report download/install progress or final success/failure.
  If the agent reports `completed` or `failed`, timestamps are set accordingly.

  After recording a failure, this function checks the canary failure rate
  and triggers auto-rollback if the threshold is exceeded.
  """
  def report_update_status(agent_id, rollout_id, attrs) do
    status = Map.get(attrs, "status", Map.get(attrs, :status))

    agent_update =
      AgentUpdate
      |> where([au], au.agent_id == ^agent_id and au.rollout_id == ^rollout_id)
      |> Repo.one()

    case agent_update do
      nil ->
        {:error, :not_found}

      au ->
        update_attrs =
          attrs
          |> maybe_set_timestamps(status)

        au
        |> AgentUpdate.report_changeset(update_attrs)
        |> Repo.update()
        |> tap(fn
          {:ok, updated} ->
            Logger.info(
              "[Updates] Agent #{agent_id} reported status=#{updated.status} " <>
                "for rollout #{rollout_id}"
            )

            if updated.status == "failed" do
              check_canary_failure_rate(rollout_id)
            end

          _ ->
            :ok
        end)
    end
  end

  defp maybe_set_timestamps(attrs, status) when status in ["completed", "rolled_back"] do
    Map.put(attrs, "completed_at", DateTime.utc_now())
  end

  defp maybe_set_timestamps(attrs, status) when status in ["downloading", "installing"] do
    Map.put_new(attrs, "started_at", DateTime.utc_now())
  end

  defp maybe_set_timestamps(attrs, _status), do: attrs

  # ---------------------------------------------------------------------------
  # Rollout Progress & Controls
  # ---------------------------------------------------------------------------

  @doc """
  Get the progress of a rollout as a percentage and detailed counts.
  """
  def get_rollout_progress(rollout_id) do
    stats =
      AgentUpdate
      |> where([au], au.rollout_id == ^rollout_id)
      |> group_by([au], au.status)
      |> select([au], {au.status, count(au.id)})
      |> Repo.all()
      |> Map.new()

    total = stats |> Map.values() |> Enum.sum()

    completed = Map.get(stats, "completed", 0)
    failed = Map.get(stats, "failed", 0)
    rolled_back = Map.get(stats, "rolled_back", 0)
    in_progress = Map.get(stats, "downloading", 0) + Map.get(stats, "installing", 0)
    pending = Map.get(stats, "pending", 0)

    success_rate =
      if completed + failed > 0 do
        Float.round(completed / (completed + failed) * 100, 1)
      else
        100.0
      end

    %{
      total: total,
      completed: completed,
      failed: failed,
      rolled_back: rolled_back,
      in_progress: in_progress,
      pending: pending,
      completion_percentage:
        if(total > 0, do: Float.round((completed + failed + rolled_back) / total * 100, 1), else: 0.0),
      success_rate: success_rate
    }
  end

  @doc """
  Pause an active rollout. No new agents will receive the update.
  """
  def pause_rollout(rollout_id) do
    with {:ok, rollout} <- get_rollout_by_id(rollout_id),
         :ok <- validate_status(rollout, "rolling_out") do
      rollout
      |> Rollout.status_changeset(%{status: "paused"})
      |> Repo.update()
      |> tap_log("Rollout #{rollout_id} paused")
    end
  end

  @doc """
  Resume a paused rollout.
  """
  def resume_rollout(rollout_id) do
    with {:ok, rollout} <- get_rollout_by_id(rollout_id),
         :ok <- validate_status(rollout, "paused") do
      rollout
      |> Rollout.status_changeset(%{status: "rolling_out", started_at: DateTime.utc_now()})
      |> Repo.update()
      |> tap_log("Rollout #{rollout_id} resumed")
    end
  end

  @doc """
  Rollback a rollout. Marks the rollout as `rolled_back` and all pending/in-progress
  agent updates as `rolled_back`.
  """
  def rollback_rollout(rollout_id, reason \\ "manual rollback") do
    with {:ok, rollout} <- get_rollout_by_id(rollout_id),
         :ok <- validate_rollbackable(rollout) do
      Repo.transaction(fn ->
        # Mark rollout as rolled back
        {:ok, updated_rollout} =
          rollout
          |> Rollout.status_changeset(%{
            status: "rolled_back",
            completed_at: DateTime.utc_now(),
            rollback_reason: reason
          })
          |> Repo.update()

        # Mark all non-completed agent updates as rolled back
        {count, _} =
          AgentUpdate
          |> where([au], au.rollout_id == ^rollout_id)
          |> where([au], au.status in ~w(pending downloading installing))
          |> Repo.update_all(
            set: [status: "rolled_back", completed_at: DateTime.utc_now()]
          )

        Logger.warning(
          "[Updates] Rollout #{rollout_id} rolled back: #{reason}. " <>
            "#{count} agent updates marked as rolled_back."
        )

        updated_rollout
      end)
    end
  end

  @doc """
  Advance a staged rollout to the next stage.

  Only valid for `staged` strategy rollouts that are currently `rolling_out`.
  """
  def advance_rollout_stage(rollout_id) do
    with {:ok, rollout} <- get_rollout_by_id(rollout_id),
         :ok <- validate_status(rollout, "rolling_out"),
         :ok <- validate_strategy(rollout, "staged") do
      next_stage = rollout.current_stage + 1

      if next_stage >= length(rollout.stages) do
        # All stages complete
        rollout
        |> Rollout.status_changeset(%{
          status: "completed",
          completed_at: DateTime.utc_now(),
          current_stage: next_stage
        })
        |> Repo.update()
        |> tap_log("Rollout #{rollout_id} completed all stages")
      else
        rollout
        |> Rollout.status_changeset(%{current_stage: next_stage})
        |> Repo.update()
        |> tap_log("Rollout #{rollout_id} advanced to stage #{next_stage}")
      end
    end
  end

  @doc """
  Promote a canary rollout to 100% (all agents).
  """
  def promote_canary(rollout_id) do
    with {:ok, rollout} <- get_rollout_by_id(rollout_id),
         :ok <- validate_status(rollout, "rolling_out"),
         :ok <- validate_strategy(rollout, "canary") do
      rollout
      |> Rollout.status_changeset(%{status: "completed", completed_at: DateTime.utc_now()})
      |> Ecto.Changeset.put_change(:canary_percentage, 100)
      |> Repo.update()
      |> tap_log("Canary rollout #{rollout_id} promoted to 100%")
    end
  end

  @doc """
  Mark a rollout as completed (all agents updated successfully).
  """
  def complete_rollout(rollout_id) do
    with {:ok, rollout} <- get_rollout_by_id(rollout_id) do
      rollout
      |> Rollout.status_changeset(%{status: "completed", completed_at: DateTime.utc_now()})
      |> Repo.update()
      |> tap_log("Rollout #{rollout_id} completed")
    end
  end

  # ---------------------------------------------------------------------------
  # Canary Auto-Rollback Logic
  # ---------------------------------------------------------------------------

  @doc """
  Check the failure rate for a rollout's canary group.
  If failure rate exceeds the threshold, auto-rollback.
  """
  def check_canary_failure_rate(rollout_id) do
    with {:ok, rollout} <- get_rollout_by_id(rollout_id),
         true <- rollout.status == "rolling_out",
         true <- rollout.strategy in ["canary", "staged"] do
      progress = get_rollout_progress(rollout_id)
      total_finished = progress.completed + progress.failed

      if total_finished >= @canary_min_reports do
        failure_rate =
          if total_finished > 0 do
            progress.failed / total_finished * 100
          else
            0.0
          end

        if failure_rate > @canary_failure_threshold do
          Logger.error(
            "[Updates] Auto-rollback triggered for rollout #{rollout_id}: " <>
              "failure rate #{Float.round(failure_rate, 1)}% exceeds threshold #{@canary_failure_threshold}% " <>
              "(#{progress.failed}/#{total_finished} agents failed)"
          )

          rollback_rollout(
            rollout_id,
            "auto-rollback: failure rate #{Float.round(failure_rate, 1)}% exceeded #{@canary_failure_threshold}% threshold"
          )
        else
          :ok
        end
      else
        :ok
      end
    else
      _ -> :ok
    end
  end

  # ---------------------------------------------------------------------------
  # Active Rollouts (used by RolloutSupervisor)
  # ---------------------------------------------------------------------------

  @doc """
  Get all active rollouts (rolling_out status) across all organizations.
  Used by the RolloutSupervisor for periodic monitoring.
  """
  def list_active_rollouts do
    Rollout
    |> where([r], r.status == "rolling_out")
    |> preload(:update_package)
    |> Repo.all()
  end

  @doc """
  Assign all eligible agents in the organization to a rollout.
  Used for immediate strategy.
  """
  def assign_all_agents_to_rollout(rollout) do
    package = Repo.preload(rollout, :update_package).update_package
    platform = package.platform

    agents =
      Agent
      |> where([a], a.organization_id == ^rollout.organization_id)
      |> where([a], a.status != "offline")
      |> Repo.all()
      |> Enum.filter(fn a -> normalize_platform(a.os_type) == platform end)

    Enum.each(agents, fn agent ->
      %AgentUpdate{}
      |> AgentUpdate.changeset(%{
        agent_id: agent.id,
        rollout_id: rollout.id,
        update_package_id: package.id,
        previous_version: agent.agent_version,
        new_version: package.version,
        status: "pending"
      })
      |> Repo.insert(on_conflict: :nothing)
    end)

    Logger.info(
      "[Updates] Assigned #{length(agents)} agents to rollout #{rollout.id}"
    )
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp get_rollout_by_id(rollout_id) do
    case Repo.get(Rollout, rollout_id) do
      nil -> {:error, :not_found}
      rollout -> {:ok, rollout}
    end
  end

  defp validate_status(rollout, expected) do
    if rollout.status == expected do
      :ok
    else
      {:error, "rollout is #{rollout.status}, expected #{expected}"}
    end
  end

  defp validate_strategy(rollout, expected) do
    if rollout.strategy == expected do
      :ok
    else
      {:error, "rollout strategy is #{rollout.strategy}, expected #{expected}"}
    end
  end

  defp validate_rollbackable(rollout) do
    if rollout.status in ~w(rolling_out paused pending) do
      :ok
    else
      {:error, "cannot rollback rollout in #{rollout.status} state"}
    end
  end

  defp version_newer?(latest, current) do
    case {Version.parse(latest), Version.parse(current)} do
      {{:ok, l}, {:ok, c}} -> Version.compare(l, c) == :gt
      _ -> latest > current
    end
  end

  defp meets_min_version?(package, current_version) do
    case package.min_agent_version do
      nil ->
        true

      min_version ->
        case {Version.parse(current_version), Version.parse(min_version)} do
          {{:ok, current}, {:ok, min}} -> Version.compare(current, min) != :lt
          _ -> true
        end
    end
  end

  defp normalize_platform(os_type) when is_binary(os_type) do
    os_type
    |> String.downcase()
    |> case do
      "windows" <> _ -> "windows"
      "linux" <> _ -> "linux"
      "macos" <> _ -> "macos"
      "darwin" <> _ -> "macos"
      other -> other
    end
  end

  defp normalize_platform(_), do: "unknown"

  defp tap_log({:ok, _} = result, message) do
    Logger.info("[Updates] #{message}")
    result
  end

  defp tap_log(error, _message), do: error
end
