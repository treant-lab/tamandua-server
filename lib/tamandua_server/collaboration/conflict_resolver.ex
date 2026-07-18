defmodule TamanduaServer.Collaboration.ConflictResolver do
  @moduledoc """
  Conflict resolution for concurrent updates to shared resources.

  Implements:
  - Optimistic locking with version tracking
  - Conflict detection for simultaneous edits
  - Multiple merge strategies (last-write-wins, manual resolution)
  - Change notifications and alerts
  """

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.Alert
  alias Ecto.Changeset
  require Logger

  @type conflict_resolution :: :last_write_wins | :first_write_wins | :manual | :merge
  @type conflict_result ::
          {:ok, term()}
          | {:conflict, %{
              current: term(),
              attempted: term(),
              conflicting_fields: [atom()],
              other_user: map()
            }}

  @doc """
  Update a resource with conflict detection.

  Uses optimistic locking to detect concurrent modifications.
  """
  def update_with_conflict_detection(schema, id, attrs, user, opts \\ []) do
    strategy = Keyword.get(opts, :strategy, :last_write_wins)
    version_field = Keyword.get(opts, :version_field, :lock_version)

    Repo.transaction(fn ->
      # Load current version with FOR UPDATE lock
      current = load_for_update(schema, id)

      if current do
        # Check version if provided in attrs
        case check_version_conflict(current, attrs, version_field) do
          :ok ->
            # No conflict, proceed with update
            perform_update(current, attrs, user, version_field)

          {:conflict, details} ->
            # Conflict detected
            handle_conflict(current, attrs, user, details, strategy)
        end
      else
        Repo.rollback({:error, :not_found})
      end
    end)
    |> case do
      {:ok, result} -> result
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Detect conflicts between two changesets.
  """
  def detect_conflicts(current, changeset) do
    _current_changes = extract_changes(current)
    new_changes = Changeset.get_field(changeset, :__struct__)

    conflicts =
      Enum.reduce(new_changes, [], fn {field, new_value}, acc ->
        current_value = Map.get(current, field)

        if current_value != new_value && field in tracked_fields(current.__struct__) do
          [{field, current_value, new_value} | acc]
        else
          acc
        end
      end)

    if conflicts == [] do
      :no_conflict
    else
      {:conflict, conflicts}
    end
  end

  @doc """
  Get the last user who modified a resource.
  """
  def get_last_modifier(resource) do
    # Check for various modifier tracking fields
    cond do
      Map.has_key?(resource, :updated_by_id) && resource.updated_by_id ->
        load_user(resource.updated_by_id)

      Map.has_key?(resource, :state_changed_by_id) && resource.state_changed_by_id ->
        load_user(resource.state_changed_by_id)

      true ->
        nil
    end
  end

  @doc """
  Broadcast a conflict notification to users viewing the resource.
  """
  def notify_conflict(resource_type, resource_id, conflict_details) do
    topic = "#{resource_type}:#{resource_id}"

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      topic,
      {:conflict_detected, conflict_details}
    )
  end

  @doc """
  Attempt to auto-merge non-conflicting changes.
  """
  def auto_merge(base, theirs, ours) do
    base_map = Map.from_struct(base)
    theirs_map = Map.from_struct(theirs)
    ours_map = Map.from_struct(ours)

    # Find fields changed by each side
    their_changes = find_changes(base_map, theirs_map)
    our_changes = find_changes(base_map, ours_map)

    # Find conflicting fields (both sides changed the same field)
    conflicting_fields =
      MapSet.intersection(
        MapSet.new(Map.keys(their_changes)),
        MapSet.new(Map.keys(our_changes))
      )
      |> MapSet.to_list()

    if conflicting_fields == [] do
      # No conflicts, merge changes
      merged = Map.merge(base_map, Map.merge(their_changes, our_changes))
      {:ok, merged}
    else
      # Conflicts detected
      {:conflict,
       %{
         conflicting_fields: conflicting_fields,
         base: base,
         theirs: theirs,
         ours: ours,
         their_changes: their_changes,
         our_changes: our_changes
       }}
    end
  end

  @doc """
  Create a conflict resolution record for manual review.
  """
  def create_conflict_record(resource_type, resource_id, conflict_data) do
    # Store conflict for manual resolution
    %{
      resource_type: resource_type,
      resource_id: resource_id,
      conflict_data: conflict_data,
      status: :pending,
      created_at: DateTime.utc_now()
    }
    # In production, this would be saved to a conflicts table
  end

  # Private Functions

  defp load_for_update(schema, id) do
    import Ecto.Query

    schema
    |> where([r], r.id == ^id)
    |> lock("FOR UPDATE")
    |> Repo.one()
  end

  defp check_version_conflict(current, attrs, version_field) do
    provided_version = Map.get(attrs, version_field) || Map.get(attrs, to_string(version_field))
    current_version = Map.get(current, version_field, 0)

    cond do
      # No version provided, skip check
      is_nil(provided_version) ->
        :ok

      # Version matches, no conflict
      provided_version == current_version ->
        :ok

      # Version mismatch, conflict detected
      true ->
        {:conflict,
         %{
           expected_version: provided_version,
           current_version: current_version,
           message: "Resource has been modified by another user"
         }}
    end
  end

  defp perform_update(current, attrs, user, version_field) do
    # Increment version
    attrs_with_version =
      attrs
      |> Map.put(version_field, (Map.get(current, version_field, 0) || 0) + 1)
      |> Map.put(:updated_by_id, user.id)

    changeset = current.__struct__.changeset(current, attrs_with_version)

    case Repo.update(changeset) do
      {:ok, updated} ->
        # Broadcast update notification
        broadcast_update(current, updated, user)
        {:ok, updated}

      {:error, changeset} ->
        Repo.rollback({:error, changeset})
    end
  end

  defp handle_conflict(current, attrs, user, details, strategy) do
    case strategy do
      :last_write_wins ->
        # Override conflict, update anyway
        Logger.warning("Conflict resolved with last-write-wins for user #{user.id}")
        perform_update(current, Map.delete(attrs, :lock_version), user, :lock_version)

      :first_write_wins ->
        # Reject update, return conflict
        Repo.rollback(
          {:conflict,
           %{
             current: current,
             attempted: attrs,
             details: details,
             other_user: get_last_modifier(current)
           }}
        )

      :manual ->
        # Return conflict for manual resolution
        Repo.rollback(
          {:conflict,
           %{
             current: current,
             attempted: attrs,
             details: details,
             other_user: get_last_modifier(current),
             resolution_required: true
           }}
        )

      :merge ->
        # Attempt auto-merge
        # This would need more sophisticated field-level merging
        Repo.rollback({:error, :merge_not_implemented})
    end
  end

  defp extract_changes(struct) do
    Map.from_struct(struct)
  end

  defp tracked_fields(Alert) do
    [:status, :severity, :assigned_to_id, :resolution_notes, :verdict, :workflow_state]
  end

  defp tracked_fields(_schema), do: []

  defp find_changes(base, modified) do
    Enum.reduce(modified, %{}, fn {key, value}, acc ->
      base_value = Map.get(base, key)

      if base_value != value && key not in [:__struct__, :__meta__, :updated_at, :lock_version] do
        Map.put(acc, key, value)
      else
        acc
      end
    end)
  end

  defp load_user(user_id) do
    Repo.get(TamanduaServer.Accounts.User, user_id)
  end

  defp broadcast_update(old_resource, new_resource, user) do
    resource_type = old_resource.__struct__ |> Module.split() |> List.last() |> String.downcase()
    topic = "#{resource_type}:#{old_resource.id}"

    changes = find_changes(Map.from_struct(old_resource), Map.from_struct(new_resource))

    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      topic,
      {:resource_updated, %{user: user, changes: changes, resource: new_resource}}
    )
  end
end
