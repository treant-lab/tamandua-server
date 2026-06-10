defmodule TamanduaServer.Agents.GroupManager do
  @moduledoc """
  Context module for managing agent groups and batch operations.

  Provides functions for:
  - Creating, updating, deleting groups
  - Managing group membership
  - Executing batch commands on groups
  - Importing/exporting group definitions
  - Group hierarchy operations
  """

  import Ecto.Query, warn: false
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.TenantScope
  alias TamanduaServer.Agents.{
    Group,
    GroupMember,
    BatchCommand,
    BatchCommandResult,
    Agent,
    CommandManager
  }

  # ===========================================================================
  # Group Management
  # ===========================================================================

  @doc """
  Lists all groups for an organization.

  ## Options
  - `:include_children` - Include child groups (default: false)
  - `:parent_id` - Filter by parent group ID
  - `:tags` - Filter by tags (list)
  """
  def list_groups(organization_id, opts \\ []) do
    query = Group
    |> TenantScope.scope_to_tenant(organization_id)
    |> preload([:parent, :children])

    query = if parent_id = Keyword.get(opts, :parent_id) do
      where(query, [g], g.parent_id == ^parent_id)
    else
      query
    end

    query = if tags = Keyword.get(opts, :tags) do
      Enum.reduce(tags, query, fn tag, q ->
        where(q, [g], ^tag in g.tags)
      end)
    else
      query
    end

    Repo.all(query)
  end

  @doc """
  Lists root-level groups (no parent) for an organization.
  """
  def list_root_groups(organization_id) do
    Group
    |> TenantScope.scope_to_tenant(organization_id)
    |> where([g], is_nil(g.parent_id))
    |> preload([:children])
    |> order_by([g], g.name)
    |> Repo.all()
  end

  @doc """
  Gets a single group by ID for an organization.
  """
  def get_group(organization_id, group_id) do
    case TenantScope.get_scoped(Group, organization_id, group_id) do
      nil -> {:error, :not_found}
      group -> {:ok, Repo.preload(group, [:parent, :children, :group_members])}
    end
  end

  @doc """
  Gets a single group by ID, raises if not found.
  """
  def get_group!(organization_id, group_id) do
    group = TenantScope.get_scoped!(Group, organization_id, group_id)
    Repo.preload(group, [:parent, :children, :group_members])
  end

  @doc """
  Creates a group for an organization.
  """
  def create_group(organization_id, attrs) do
    %Group{}
    |> Group.changeset(attrs)
    |> TenantScope.put_tenant(organization_id)
    |> Repo.insert()
  end

  @doc """
  Updates a group.
  """
  def update_group(%Group{} = group, attrs) do
    group
    |> Group.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a group.

  If the group has children, you can either:
  - Set `reassign_to` to move children to another parent
  - Set `cascade: true` to delete children recursively
  """
  def delete_group(%Group{} = group, opts \\ []) do
    reassign_to = Keyword.get(opts, :reassign_to)
    cascade = Keyword.get(opts, :cascade, false)

    Repo.transaction(fn ->
      # Handle children
      if reassign_to do
        Group
        |> where([g], g.parent_id == ^group.id)
        |> Repo.update_all(set: [parent_id: reassign_to])
      end

      if cascade do
        # Recursively delete children
        children = Repo.all(from g in Group, where: g.parent_id == ^group.id)
        Enum.each(children, &delete_group(&1, cascade: true))
      end

      # Delete group members
      Repo.delete_all(from gm in GroupMember, where: gm.group_id == ^group.id)

      # Delete the group
      case Repo.delete(group) do
        {:ok, deleted} -> deleted
        {:error, changeset} -> Repo.rollback(changeset)
      end
    end)
  end

  @doc """
  Counts groups for an organization.
  """
  def count_groups(organization_id) do
    TenantScope.count_for_tenant(Group, organization_id)
  end

  # ===========================================================================
  # Group Membership
  # ===========================================================================

  @doc """
  Adds an agent to a group.
  """
  def add_agent_to_group(agent_id, group_id, opts \\ []) do
    attrs = %{
      agent_id: agent_id,
      group_id: group_id,
      added_by: Keyword.get(opts, :added_by),
      metadata: Keyword.get(opts, :metadata, %{})
    }

    %GroupMember{}
    |> GroupMember.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Removes an agent from a group.
  """
  def remove_agent_from_group(agent_id, group_id) do
    case Repo.get_by(GroupMember, agent_id: agent_id, group_id: group_id) do
      nil -> {:error, :not_found}
      member -> Repo.delete(member)
    end
  end

  @doc """
  Adds multiple agents to a group in a single transaction.
  """
  def add_agents_to_group(agent_ids, group_id, opts \\ []) when is_list(agent_ids) do
    added_by = Keyword.get(opts, :added_by)
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    entries = Enum.map(agent_ids, fn agent_id ->
      %{
        id: Ecto.UUID.generate(),
        agent_id: agent_id,
        group_id: group_id,
        added_by: added_by,
        metadata: %{},
        inserted_at: now,
        updated_at: now
      }
    end)

    Repo.insert_all(GroupMember, entries,
      on_conflict: :nothing,
      conflict_target: [:agent_id, :group_id]
    )

    {:ok, length(entries)}
  end

  @doc """
  Removes multiple agents from a group.
  """
  def remove_agents_from_group(agent_ids, group_id) when is_list(agent_ids) do
    {count, _} = GroupMember
    |> where([gm], gm.group_id == ^group_id)
    |> where([gm], gm.agent_id in ^agent_ids)
    |> Repo.delete_all()

    {:ok, count}
  end

  @doc """
  Lists all agents in a group.

  Returns a list of agent maps with group membership metadata.
  """
  def list_group_agents(group_id, opts \\ []) do
    query = from gm in GroupMember,
      where: gm.group_id == ^group_id,
      join: a in assoc(gm, :agent),
      select: %{
        agent_id: a.id,
        hostname: a.hostname,
        ip_address: a.ip_address,
        os_type: a.os_type,
        os_version: a.os_version,
        status: a.status,
        last_seen_at: a.last_seen_at,
        tags: a.tags,
        added_to_group_at: gm.inserted_at,
        added_by: gm.added_by
      }

    query = if status = Keyword.get(opts, :status) do
      where(query, [gm, a], a.status == ^to_string(status))
    else
      query
    end

    Repo.all(query)
  end

  @doc """
  Lists all groups an agent belongs to.
  """
  def list_agent_groups(agent_id) do
    from(gm in GroupMember,
      where: gm.agent_id == ^agent_id,
      join: g in assoc(gm, :group),
      select: g,
      preload: [:parent]
    )
    |> Repo.all()
  end

  @doc """
  Counts agents in a group.
  """
  def count_group_agents(group_id, opts \\ []) do
    query = from gm in GroupMember,
      where: gm.group_id == ^group_id

    query = if status = Keyword.get(opts, :status) do
      query
      |> join(:inner, [gm], a in Agent, on: gm.agent_id == a.id)
      |> where([gm, a], a.status == ^to_string(status))
    else
      query
    end

    Repo.aggregate(query, :count)
  end

  @doc """
  Gets group statistics including agent counts by status.
  """
  def get_group_stats(group_id) do
    # Get all agents in group with their status
    agents = from(gm in GroupMember,
      where: gm.group_id == ^group_id,
      join: a in Agent, on: gm.agent_id == a.id,
      select: %{status: a.status}
    )
    |> Repo.all()

    total = length(agents)
    online = Enum.count(agents, &(&1.status == "online"))
    offline = Enum.count(agents, &(&1.status == "offline"))
    isolated = Enum.count(agents, &(&1.status == "isolated"))

    %{
      total: total,
      online: online,
      offline: offline,
      isolated: isolated
    }
  end

  # ===========================================================================
  # Batch Commands
  # ===========================================================================

  @doc """
  Executes a batch command on a group of agents.

  ## Options
  - `:timeout_seconds` - Command timeout (default: 3600)
  - `:initiated_by` - User who initiated the command

  Returns `{:ok, batch_command}` with the batch command record that can be
  used to track progress.
  """
  def execute_batch_command_on_group(group_id, command_type, params \\ %{}, opts \\ []) do
    with {:ok, group} <- Repo.fetch(Group, group_id),
         agent_ids <- get_group_agent_ids(group_id) do
      execute_batch_command(
        group.organization_id,
        command_type,
        params,
        target_type: "group",
        group_id: group_id,
        target_ids: agent_ids,
        initiated_by: Keyword.get(opts, :initiated_by),
        timeout_seconds: Keyword.get(opts, :timeout_seconds, 3600)
      )
    end
  end

  @doc """
  Executes a batch command on a list of agents.

  ## Options
  - `:timeout_seconds` - Command timeout (default: 3600)
  - `:initiated_by` - User who initiated the command
  """
  def execute_batch_command_on_agents(organization_id, agent_ids, command_type, params \\ %{}, opts \\ []) when is_list(agent_ids) do
    execute_batch_command(
      organization_id,
      command_type,
      params,
      target_type: "agents",
      target_ids: agent_ids,
      initiated_by: Keyword.get(opts, :initiated_by),
      timeout_seconds: Keyword.get(opts, :timeout_seconds, 3600)
    )
  end

  defp execute_batch_command(organization_id, command_type, params, opts) do
    target_type = Keyword.fetch!(opts, :target_type)
    target_ids = Keyword.fetch!(opts, :target_ids)
    timeout_seconds = Keyword.get(opts, :timeout_seconds, 3600)

    if Enum.empty?(target_ids) do
      {:error, :no_targets}
    else
      Repo.transaction(fn ->
        # Create batch command record
        batch_attrs = %{
          command_type: to_string(command_type),
          command_params: params,
          target_type: target_type,
          target_ids: target_ids,
          total_count: length(target_ids),
          organization_id: organization_id,
          group_id: Keyword.get(opts, :group_id),
          initiated_by: Keyword.get(opts, :initiated_by),
          timeout_seconds: timeout_seconds,
          expires_at: DateTime.add(DateTime.utc_now(), timeout_seconds, :second)
        }

        batch_command = case Repo.insert(BatchCommand.changeset(%BatchCommand{}, batch_attrs)) do
          {:ok, bc} -> bc
          {:error, changeset} -> Repo.rollback(changeset)
        end

        # Create result records for each agent
        now = DateTime.utc_now() |> DateTime.truncate(:second)
        result_entries = Enum.map(target_ids, fn agent_id ->
          %{
            id: Ecto.UUID.generate(),
            batch_command_id: batch_command.id,
            agent_id: agent_id,
            status: "pending",
            inserted_at: now,
            updated_at: now
          }
        end)

        Repo.insert_all(BatchCommandResult, result_entries)

        # Mark as running
        batch_command = batch_command
        |> BatchCommand.mark_running()
        |> Repo.update!()

        # Execute commands asynchronously
        Task.start(fn ->
          execute_batch_async(batch_command.id, command_type, params, target_ids)
        end)

        batch_command
      end)
    end
  end

  defp execute_batch_async(batch_command_id, command_type, params, agent_ids) do
    Logger.info("Executing batch command #{batch_command_id} on #{length(agent_ids)} agents")

    # Execute commands in parallel with limited concurrency
    agent_ids
    |> Task.async_stream(
      fn agent_id ->
        execute_single_command(batch_command_id, agent_id, command_type, params)
      end,
      max_concurrency: 10,
      timeout: 120_000,
      on_timeout: :kill_task
    )
    |> Enum.to_list()

    # Update batch command final status
    update_batch_command_status(batch_command_id)
  end

  defp execute_single_command(batch_command_id, agent_id, command_type, params) do
    # Get the result record
    result = Repo.get_by!(BatchCommandResult,
      batch_command_id: batch_command_id,
      agent_id: agent_id
    )

    # Mark as running
    result = result
    |> BatchCommandResult.mark_running()
    |> Repo.update!()

    # Execute the command
    case CommandManager.queue_command(agent_id, command_type, params) do
      {:ok, command} ->
        # Poll for completion
        wait_for_command_completion(result, command.id)

      {:error, reason} ->
        result
        |> BatchCommandResult.mark_failed(inspect(reason))
        |> Repo.update!()

        update_batch_counters(batch_command_id)
    end
  end

  defp wait_for_command_completion(result, command_id, attempts \\ 0) do
    max_attempts = 60  # 60 * 2 seconds = 2 minutes

    if attempts >= max_attempts do
      result
      |> BatchCommandResult.mark_failed("Command timed out")
      |> Repo.update!()

      update_batch_counters(result.batch_command_id)
    else
      Process.sleep(2000)  # Wait 2 seconds

      case CommandManager.get_command(command_id) do
        {:ok, command} ->
          case command.status do
            "completed" ->
              result
              |> BatchCommandResult.mark_completed(command.result)
              |> Repo.update!()

              update_batch_counters(result.batch_command_id)

            "failed" ->
              result
              |> BatchCommandResult.mark_failed(command.error || "Command failed")
              |> Repo.update!()

              update_batch_counters(result.batch_command_id)

            _ ->
              # Still pending or sent, keep waiting
              wait_for_command_completion(result, command_id, attempts + 1)
          end

        {:error, _} ->
          wait_for_command_completion(result, command_id, attempts + 1)
      end
    end
  end

  defp update_batch_counters(batch_command_id) do
    # Count results by status
    results = from(r in BatchCommandResult,
      where: r.batch_command_id == ^batch_command_id,
      group_by: r.status,
      select: {r.status, count(r.id)}
    )
    |> Repo.all()
    |> Map.new()

    completed = Map.get(results, "completed", 0)
    failed = Map.get(results, "failed", 0)
    total_finished = completed + failed

    # Update batch command
    batch_command = Repo.get!(BatchCommand, batch_command_id)

    batch_command
    |> BatchCommand.update_progress(
      completed: total_finished,
      success: completed,
      failed: failed
    )
    |> Repo.update!()
  end

  defp update_batch_command_status(batch_command_id) do
    batch_command = Repo.get!(BatchCommand, batch_command_id)

    batch_command
    |> BatchCommand.mark_completed()
    |> Repo.update!()
  end

  @doc """
  Gets a batch command by ID.
  """
  def get_batch_command(batch_command_id) do
    case Repo.get(BatchCommand, batch_command_id) do
      nil -> {:error, :not_found}
      batch -> {:ok, Repo.preload(batch, [:group, :results])}
    end
  end

  @doc """
  Lists batch commands for an organization.

  ## Options
  - `:status` - Filter by status
  - `:limit` - Maximum results
  - `:offset` - Pagination offset
  """
  def list_batch_commands(organization_id, opts \\ []) do
    query = BatchCommand
    |> TenantScope.scope_to_tenant(organization_id)
    |> order_by([bc], [desc: bc.inserted_at])

    query = if status = Keyword.get(opts, :status) do
      where(query, [bc], bc.status == ^status)
    else
      query
    end

    query = if limit = Keyword.get(opts, :limit) do
      limit(query, ^limit)
    else
      query
    end

    query = if offset = Keyword.get(opts, :offset) do
      offset(query, ^offset)
    else
      query
    end

    Repo.all(query)
  end

  @doc """
  Cancels a pending batch command.
  """
  def cancel_batch_command(batch_command_id) do
    batch_command = Repo.get!(BatchCommand, batch_command_id)

    if batch_command.status in ["pending", "running"] do
      batch_command
      |> BatchCommand.mark_cancelled()
      |> Repo.update()
    else
      {:error, :cannot_cancel}
    end
  end

  # ===========================================================================
  # Import/Export
  # ===========================================================================

  @doc """
  Exports groups to JSON format.

  ## Options
  - `:include_members` - Include agent memberships (default: true)
  - `:include_hierarchy` - Include parent-child relationships (default: true)
  """
  def export_groups(organization_id, opts \\ []) do
    include_members = Keyword.get(opts, :include_members, true)

    groups = list_groups(organization_id, include_children: true)

    exported = Enum.map(groups, fn group ->
      base = %{
        name: group.name,
        description: group.description,
        color: group.color,
        tags: group.tags,
        metadata: group.metadata,
        parent_name: group.parent && group.parent.name
      }

      if include_members do
        member_ids = get_group_agent_ids(group.id)
        Map.put(base, :agent_ids, member_ids)
      else
        base
      end
    end)

    {:ok, exported}
  end

  @doc """
  Exports groups to CSV format.

  Returns CSV string with columns: name, description, color, tags, parent, agent_count
  """
  def export_groups_csv(organization_id) do
    groups = list_groups(organization_id, include_children: true)

    header = "name,description,color,tags,parent,agent_count\n"

    rows = Enum.map(groups, fn group ->
      count = count_group_agents(group.id)
      tags = Enum.join(group.tags || [], ";")
      parent = group.parent && group.parent.name || ""

      [
        escape_csv(group.name),
        escape_csv(group.description || ""),
        group.color || "",
        escape_csv(tags),
        escape_csv(parent),
        to_string(count)
      ]
      |> Enum.join(",")
    end)
    |> Enum.join("\n")

    {:ok, header <> rows}
  end

  defp escape_csv(str) when is_binary(str) do
    if String.contains?(str, [",", "\"", "\n"]) do
      "\"#{String.replace(str, "\"", "\"\"")}\""
    else
      str
    end
  end

  @doc """
  Imports groups from JSON format.

  Expects a list of group definitions with optional agent_ids.
  Creates groups and memberships in a transaction.
  """
  def import_groups(organization_id, groups_data) when is_list(groups_data) do
    Repo.transaction(fn ->
      Enum.map(groups_data, fn group_data ->
        # Find parent if specified
        parent_id = if parent_name = group_data["parent_name"] do
          case Repo.get_by(Group, organization_id: organization_id, name: parent_name) do
            nil -> nil
            parent -> parent.id
          end
        else
          nil
        end

        attrs = %{
          name: group_data["name"],
          description: group_data["description"],
          color: group_data["color"],
          tags: group_data["tags"] || [],
          metadata: group_data["metadata"] || %{},
          parent_id: parent_id
        }

        case create_group(organization_id, attrs) do
          {:ok, group} ->
            # Add members if provided
            if agent_ids = group_data["agent_ids"] do
              add_agents_to_group(agent_ids, group.id)
            end
            group

          {:error, changeset} ->
            Repo.rollback(changeset)
        end
      end)
    end)
  end

  # ===========================================================================
  # Helper Functions
  # ===========================================================================

  defp get_group_agent_ids(group_id) do
    from(gm in GroupMember,
      where: gm.group_id == ^group_id,
      select: gm.agent_id
    )
    |> Repo.all()
  end

  @doc """
  Gets all descendant groups (children, grandchildren, etc.) for a group.
  """
  def get_descendant_groups(group_id) do
    get_descendants_recursive(group_id, [])
  end

  defp get_descendants_recursive(group_id, acc) do
    children = Repo.all(from g in Group, where: g.parent_id == ^group_id)

    Enum.reduce(children, acc ++ children, fn child, acc ->
      get_descendants_recursive(child.id, acc)
    end)
  end

  @doc """
  Gets all agents in a group including nested subgroups.
  """
  def get_all_group_agents_recursive(group_id) do
    descendants = get_descendant_groups(group_id)
    all_group_ids = [group_id | Enum.map(descendants, & &1.id)]

    from(gm in GroupMember,
      where: gm.group_id in ^all_group_ids,
      select: gm.agent_id,
      distinct: true
    )
    |> Repo.all()
  end
end
