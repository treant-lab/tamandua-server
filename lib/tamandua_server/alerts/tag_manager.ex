defmodule TamanduaServer.Alerts.TagManager do
  @moduledoc """
  Context for managing alert tags.

  Provides functionality for:
  - Creating, updating, and deleting tags
  - Assigning/unassigning tags to alerts
  - Bulk tag operations
  - Tag statistics and autocomplete
  - Tag filtering
  """

  import Ecto.Query, warn: false

  alias TamanduaServer.Repo
  alias TamanduaServer.TenantScope
  alias TamanduaServer.Alerts.Tag
  alias TamanduaServer.Alerts.TagAssignment
  alias TamanduaServer.Alerts.Alert

  require Logger

  # ===========================================================================
  # Tag Management
  # ===========================================================================

  @doc """
  Lists all tags for an organization.
  """
  def list_tags(organization_id, opts \\ []) do
    query =
      Tag
      |> TenantScope.scope_to_tenant(organization_id)
      |> order_by([t], t.name)

    query =
      if category = Keyword.get(opts, :category) do
        where(query, [t], t.category == ^category)
      else
        query
      end

    query =
      if search = Keyword.get(opts, :search) do
        search_term = "%#{search}%"
        where(query, [t], ilike(t.name, ^search_term) or ilike(t.description, ^search_term))
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Gets a single tag by ID for an organization.
  """
  def get_tag(organization_id, tag_id) do
    case TenantScope.get_scoped(Tag, organization_id, tag_id) do
      nil -> {:error, :not_found}
      tag -> {:ok, tag}
    end
  end

  @doc """
  Gets a tag by name for an organization.
  """
  def get_tag_by_name(organization_id, name) do
    Tag
    |> TenantScope.scope_to_tenant(organization_id)
    |> where([t], t.name == ^name)
    |> Repo.one()
    |> case do
      nil -> {:error, :not_found}
      tag -> {:ok, tag}
    end
  end

  @doc """
  Creates a new tag.
  """
  def create_tag(organization_id, attrs, user) do
    attrs =
      attrs
      |> Map.put(:organization_id, organization_id)
      |> Map.put(:created_by_id, user.id)

    %Tag{}
    |> Tag.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a tag.
  """
  def update_tag(organization_id, tag_id, attrs) do
    with {:ok, tag} <- get_tag(organization_id, tag_id) do
      tag
      |> Tag.changeset(attrs)
      |> Repo.update()
    end
  end

  @doc """
  Deletes a tag. This will also remove all tag assignments.
  """
  def delete_tag(organization_id, tag_id) do
    with {:ok, tag} <- get_tag(organization_id, tag_id) do
      Repo.delete(tag)
    end
  end

  # ===========================================================================
  # Tag Assignment
  # ===========================================================================

  @doc """
  Assigns a tag to an alert.
  """
  def assign_tag(alert_id, tag_id, user_id \\ nil) do
    attrs = %{
      alert_id: alert_id,
      tag_id: tag_id,
      assigned_by_id: user_id
    }

    %TagAssignment{}
    |> TagAssignment.changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, assignment} ->
        # Broadcast tag assignment event
        broadcast_tag_event(alert_id, :tag_assigned, tag_id)
        {:ok, assignment}

      {:error, %Ecto.Changeset{errors: [alert_id: {"has already been taken", _}]} = _changeset} ->
        # Tag already assigned, return ok
        {:ok, :already_assigned}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Unassigns a tag from an alert.
  """
  def unassign_tag(alert_id, tag_id) do
    case Repo.get_by(TagAssignment, alert_id: alert_id, tag_id: tag_id) do
      nil ->
        {:error, :not_found}

      assignment ->
        Repo.delete(assignment)
        broadcast_tag_event(alert_id, :tag_unassigned, tag_id)
        {:ok, :deleted}
    end
  end

  @doc """
  Lists all tags assigned to an alert.
  """
  def list_alert_tags(alert_id) do
    TagAssignment
    |> where([ta], ta.alert_id == ^alert_id)
    |> join(:inner, [ta], t in Tag, on: ta.tag_id == t.id)
    |> select([ta, t], t)
    |> order_by([ta, t], t.name)
    |> Repo.all()
  end

  @doc """
  Lists all alerts with a specific tag.
  """
  def list_alerts_by_tag(organization_id, tag_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)

    Alert
    |> TenantScope.scope_to_tenant(organization_id)
    |> join(:inner, [a], ta in TagAssignment, on: ta.alert_id == a.id)
    |> where([a, ta], ta.tag_id == ^tag_id)
    |> order_by([a, ta], [desc: a.inserted_at])
    |> limit(^limit)
    |> Repo.all()
  end

  # ===========================================================================
  # Bulk Operations
  # ===========================================================================

  @doc """
  Assigns tags to multiple alerts.

  Returns {:ok, count} where count is the number of successful assignments.
  """
  def bulk_assign_tags(alert_ids, tag_names, organization_id, user) when is_list(tag_names) do
    # Resolve tag names to tag IDs, creating tags if they don't exist
    tag_ids =
      Enum.map(tag_names, fn name ->
        case get_or_create_tag(organization_id, name, user) do
          {:ok, tag} -> tag.id
          _ -> nil
        end
      end)
      |> Enum.reject(&is_nil/1)

    bulk_assign_tag_ids(alert_ids, tag_ids, user.id)
  end

  @doc """
  Assigns tag IDs to multiple alerts.
  """
  def bulk_assign_tag_ids(alert_ids, tag_ids, user_id \\ nil) do
    timestamp = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    assignments =
      for alert_id <- alert_ids, tag_id <- tag_ids do
        %{
          id: Ecto.UUID.generate(),
          alert_id: alert_id,
          tag_id: tag_id,
          assigned_by_id: user_id,
          inserted_at: timestamp
        }
      end

    {count, _} =
      Repo.insert_all(
        TagAssignment,
        assignments,
        on_conflict: :nothing,
        conflict_target: [:alert_id, :tag_id]
      )

    # Broadcast events
    for alert_id <- alert_ids, tag_id <- tag_ids do
      broadcast_tag_event(alert_id, :tag_assigned, tag_id)
    end

    {:ok, count}
  end

  @doc """
  Removes tags from multiple alerts.

  Returns {:ok, count} where count is the number of deleted assignments.
  """
  def bulk_unassign_tags(alert_ids, tag_names, organization_id) when is_list(tag_names) do
    # Resolve tag names to tag IDs
    tag_ids =
      Enum.map(tag_names, fn name ->
        case get_tag_by_name(organization_id, name) do
          {:ok, tag} -> tag.id
          _ -> nil
        end
      end)
      |> Enum.reject(&is_nil/1)

    bulk_unassign_tag_ids(alert_ids, tag_ids)
  end

  @doc """
  Removes tag IDs from multiple alerts.
  """
  def bulk_unassign_tag_ids(alert_ids, tag_ids) do
    {count, _} =
      TagAssignment
      |> where([ta], ta.alert_id in ^alert_ids and ta.tag_id in ^tag_ids)
      |> Repo.delete_all()

    # Broadcast events
    for alert_id <- alert_ids, tag_id <- tag_ids do
      broadcast_tag_event(alert_id, :tag_unassigned, tag_id)
    end

    {:ok, count}
  end

  # ===========================================================================
  # Tag Statistics
  # ===========================================================================

  @doc """
  Returns tag usage statistics for an organization.
  """
  def tag_statistics(organization_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 20)
    time_range_days = Keyword.get(opts, :time_range_days, 30)

    cutoff_date =
      DateTime.utc_now()
      |> DateTime.add(-time_range_days * 24 * 60 * 60, :second)

    Tag
    |> TenantScope.scope_to_tenant(organization_id)
    |> join(:left, [t], ta in TagAssignment, on: ta.tag_id == t.id)
    |> where([t, ta], is_nil(ta.inserted_at) or ta.inserted_at >= ^cutoff_date)
    |> group_by([t], t.id)
    |> select([t, ta], %{
      id: t.id,
      name: t.name,
      color: t.color,
      category: t.category,
      usage_count: count(ta.id)
    })
    |> order_by([t, ta], [desc: count(ta.id)])
    |> limit(^limit)
    |> Repo.all()
  end

  @doc """
  Returns trending tags (tags with increasing usage).
  """
  def trending_tags(organization_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 10)
    recent_days = Keyword.get(opts, :recent_days, 7)
    baseline_days = Keyword.get(opts, :baseline_days, 30)

    recent_cutoff =
      DateTime.utc_now()
      |> DateTime.add(-recent_days * 24 * 60 * 60, :second)

    baseline_cutoff =
      DateTime.utc_now()
      |> DateTime.add(-baseline_days * 24 * 60 * 60, :second)

    # Get recent usage
    recent_usage =
      TagAssignment
      |> join(:inner, [ta], t in Tag, on: ta.tag_id == t.id)
      |> where([ta, t], t.organization_id == ^organization_id)
      |> where([ta, t], ta.inserted_at >= ^recent_cutoff)
      |> group_by([ta, t], t.id)
      |> select([ta, t], {t.id, count(ta.id)})
      |> Repo.all()
      |> Map.new()

    # Get baseline usage
    baseline_usage =
      TagAssignment
      |> join(:inner, [ta], t in Tag, on: ta.tag_id == t.id)
      |> where([ta, t], t.organization_id == ^organization_id)
      |> where([ta, t], ta.inserted_at >= ^baseline_cutoff and ta.inserted_at < ^recent_cutoff)
      |> group_by([ta, t], t.id)
      |> select([ta, t], {t.id, count(ta.id)})
      |> Repo.all()
      |> Map.new()

    # Calculate trend scores
    Tag
    |> TenantScope.scope_to_tenant(organization_id)
    |> Repo.all()
    |> Enum.map(fn tag ->
      recent = Map.get(recent_usage, tag.id, 0)
      baseline = Map.get(baseline_usage, tag.id, 0)

      # Calculate percentage increase (with baseline protection)
      trend_score =
        if baseline > 0 do
          ((recent - baseline) / baseline) * 100
        else
          if recent > 0, do: 100, else: 0
        end

      %{
        id: tag.id,
        name: tag.name,
        color: tag.color,
        category: tag.category,
        recent_usage: recent,
        baseline_usage: baseline,
        trend_score: trend_score
      }
    end)
    |> Enum.filter(fn tag -> tag.trend_score > 0 end)
    |> Enum.sort_by(& &1.trend_score, :desc)
    |> Enum.take(limit)
  end

  @doc """
  Returns tag suggestions for autocomplete based on partial name.
  """
  def autocomplete_tags(organization_id, query, opts \\ []) do
    limit = Keyword.get(opts, :limit, 10)
    search_term = "%#{query}%"

    Tag
    |> TenantScope.scope_to_tenant(organization_id)
    |> where([t], ilike(t.name, ^search_term))
    |> order_by([t], t.name)
    |> limit(^limit)
    |> select([t], %{id: t.id, name: t.name, color: t.color, category: t.category})
    |> Repo.all()
  end

  # ===========================================================================
  # Helper Functions
  # ===========================================================================

  defp get_or_create_tag(organization_id, name, user) do
    case get_tag_by_name(organization_id, name) do
      {:ok, tag} ->
        {:ok, tag}

      {:error, :not_found} ->
        create_tag(organization_id, %{name: name}, user)
    end
  end

  defp broadcast_tag_event(alert_id, event, tag_id) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alerts:#{alert_id}",
      {event, %{alert_id: alert_id, tag_id: tag_id}}
    )
  end
end
