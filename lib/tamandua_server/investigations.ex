defmodule TamanduaServer.Investigations do
  @moduledoc """
  Context module for managing case investigations.

  Provides functions to create, read, update, and delete investigations,
  as well as managing linked alerts, events, and notes.
  """

  import Ecto.Query, warn: false

  alias TamanduaServer.Repo
  alias TamanduaServer.Investigations.CaseInvestigation

  @doc """
  Lists all case investigations with optional filters.

  ## Options

    * `:status` - Filter by status (open, in_progress, closed, archived)
    * `:severity` - Filter by severity (critical, high, medium, low, info)
    * `:assigned_to` - Filter by assigned user ID
    * `:created_by` - Filter by creator user ID
    * `:search` - Search in title and description
    * `:limit` - Limit results (default: 50)
    * `:offset` - Offset for pagination (default: 0)
    * `:organization_id` - Filter by organization

  """
  @spec list_investigations(keyword()) :: [CaseInvestigation.t()]
  def list_investigations(opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)
    offset = Keyword.get(opts, :offset, 0)

    CaseInvestigation
    |> apply_filters(opts)
    |> order_by([i], desc: i.inserted_at)
    |> limit(^limit)
    |> offset(^offset)
    |> Repo.all()
    |> Repo.preload([:assigned_user, :creator])
  end

  @doc """
  Counts investigations matching the given filters.
  """
  @spec count_investigations(keyword()) :: non_neg_integer()
  def count_investigations(opts \\ []) do
    CaseInvestigation
    |> apply_filters(opts)
    |> Repo.aggregate(:count, :id)
  end

  @doc """
  Gets a single case investigation by ID.
  """
  @spec get_investigation(String.t()) :: {:ok, CaseInvestigation.t()} | {:error, :not_found}
  def get_investigation(id) do
    case Repo.get(CaseInvestigation, id) |> Repo.preload([:assigned_user, :creator]) do
      nil -> {:error, :not_found}
      investigation -> {:ok, investigation}
    end
  end

  @doc """
  Gets a case investigation by ID, raising if not found.
  """
  @spec get_investigation!(String.t()) :: CaseInvestigation.t()
  def get_investigation!(id) do
    Repo.get!(CaseInvestigation, id) |> Repo.preload([:assigned_user, :creator])
  end

  @doc """
  Creates a new case investigation.
  """
  @spec create_investigation(map()) :: {:ok, CaseInvestigation.t()} | {:error, Ecto.Changeset.t()}
  def create_investigation(attrs) do
    %CaseInvestigation{}
    |> CaseInvestigation.create_changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, investigation} -> {:ok, Repo.preload(investigation, [:assigned_user, :creator])}
      error -> error
    end
  end

  @doc """
  Updates a case investigation.
  """
  @spec update_investigation(CaseInvestigation.t(), map()) ::
          {:ok, CaseInvestigation.t()} | {:error, Ecto.Changeset.t()}
  def update_investigation(%CaseInvestigation{} = investigation, attrs) do
    investigation
    |> CaseInvestigation.update_changeset(attrs)
    |> Repo.update()
    |> case do
      {:ok, investigation} -> {:ok, Repo.preload(investigation, [:assigned_user, :creator], force: true)}
      error -> error
    end
  end

  @doc """
  Deletes a case investigation.
  """
  @spec delete_investigation(CaseInvestigation.t()) ::
          {:ok, CaseInvestigation.t()} | {:error, Ecto.Changeset.t()}
  def delete_investigation(%CaseInvestigation{} = investigation) do
    Repo.delete(investigation)
  end

  @doc """
  Adds an alert to a case investigation.
  """
  @spec add_alert_to_investigation(String.t(), String.t()) ::
          {:ok, CaseInvestigation.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def add_alert_to_investigation(investigation_id, alert_id) do
    with {:ok, investigation} <- get_investigation(investigation_id) do
      current_ids = investigation.alert_ids || []

      if alert_id in current_ids do
        {:ok, investigation}
      else
        update_investigation(investigation, %{alert_ids: current_ids ++ [alert_id]})
      end
    end
  end

  @doc """
  Removes an alert from a case investigation.
  """
  @spec remove_alert_from_investigation(String.t(), String.t()) ::
          {:ok, CaseInvestigation.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def remove_alert_from_investigation(investigation_id, alert_id) do
    with {:ok, investigation} <- get_investigation(investigation_id) do
      current_ids = investigation.alert_ids || []
      new_ids = Enum.reject(current_ids, &(&1 == alert_id))
      update_investigation(investigation, %{alert_ids: new_ids})
    end
  end

  @doc """
  Adds multiple alerts to a case investigation (bulk operation).
  """
  @spec add_alerts_to_investigation(String.t(), [String.t()]) ::
          {:ok, CaseInvestigation.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def add_alerts_to_investigation(investigation_id, alert_ids) when is_list(alert_ids) do
    with {:ok, investigation} <- get_investigation(investigation_id) do
      current_ids = investigation.alert_ids || []
      # Combine and deduplicate
      new_ids = Enum.uniq(current_ids ++ alert_ids)
      update_investigation(investigation, %{alert_ids: new_ids})
    end
  end

  @doc """
  Adds a note to a case investigation.
  Appends the note with a timestamp to the existing notes.
  """
  @spec add_note(String.t(), String.t(), String.t() | nil) ::
          {:ok, CaseInvestigation.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def add_note(investigation_id, note_content, author_name \\ nil) do
    with {:ok, investigation} <- get_investigation(investigation_id) do
      timestamp = DateTime.utc_now() |> DateTime.to_iso8601()
      author = if author_name, do: " (#{author_name})", else: ""
      formatted_note = "[#{timestamp}]#{author}: #{note_content}"

      current_notes = investigation.notes || ""
      new_notes = if current_notes == "", do: formatted_note, else: "#{current_notes}\n\n#{formatted_note}"

      update_investigation(investigation, %{notes: new_notes})
    end
  end

  @doc """
  Updates the status of a case investigation.
  """
  @spec update_status(String.t(), String.t()) ::
          {:ok, CaseInvestigation.t()} | {:error, :not_found | :invalid_status | Ecto.Changeset.t()}
  def update_status(investigation_id, new_status) do
    if new_status in CaseInvestigation.statuses() do
      with {:ok, investigation} <- get_investigation(investigation_id) do
        update_investigation(investigation, %{status: new_status})
      end
    else
      {:error, :invalid_status}
    end
  end

  @doc """
  Assigns a case investigation to a user.
  """
  @spec assign_investigation(String.t(), String.t() | nil) ::
          {:ok, CaseInvestigation.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def assign_investigation(investigation_id, user_id) do
    with {:ok, investigation} <- get_investigation(investigation_id) do
      update_investigation(investigation, %{assigned_to: user_id})
    end
  end

  @doc """
  Gets investigation statistics.
  """
  @spec get_stats(keyword()) :: map()
  def get_stats(opts \\ []) do
    base_query = CaseInvestigation
    |> apply_org_filter(opts[:organization_id])

    total = Repo.aggregate(base_query, :count, :id)

    by_status = base_query
    |> group_by([i], i.status)
    |> select([i], {i.status, count(i.id)})
    |> Repo.all()
    |> Map.new()

    by_severity = base_query
    |> group_by([i], i.severity)
    |> select([i], {i.severity, count(i.id)})
    |> Repo.all()
    |> Map.new()

    %{
      total: total,
      by_status: by_status,
      by_severity: by_severity,
      open: Map.get(by_status, "open", 0),
      in_progress: Map.get(by_status, "in_progress", 0),
      closed: Map.get(by_status, "closed", 0)
    }
  end

  # Private functions

  defp apply_filters(query, opts) do
    query
    |> apply_status_filter(opts[:status])
    |> apply_severity_filter(opts[:severity])
    |> apply_assigned_filter(opts[:assigned_to])
    |> apply_created_by_filter(opts[:created_by])
    |> apply_search_filter(opts[:search])
    |> apply_org_filter(opts[:organization_id])
  end

  defp apply_status_filter(query, nil), do: query
  defp apply_status_filter(query, status) do
    where(query, [i], i.status == ^status)
  end

  defp apply_severity_filter(query, nil), do: query
  defp apply_severity_filter(query, severity) do
    where(query, [i], i.severity == ^severity)
  end

  defp apply_assigned_filter(query, nil), do: query
  defp apply_assigned_filter(query, "unassigned"), do: where(query, [i], is_nil(i.assigned_to))
  defp apply_assigned_filter(query, user_id) do
    where(query, [i], i.assigned_to == ^user_id)
  end

  defp apply_created_by_filter(query, nil), do: query
  defp apply_created_by_filter(query, user_id) do
    where(query, [i], i.created_by == ^user_id)
  end

  defp apply_search_filter(query, nil), do: query
  defp apply_search_filter(query, ""), do: query
  defp apply_search_filter(query, search) do
    search_term = "%#{search}%"
    where(query, [i], ilike(i.title, ^search_term) or ilike(i.description, ^search_term))
  end

  defp apply_org_filter(query, nil), do: query
  defp apply_org_filter(query, org_id) do
    where(query, [i], i.organization_id == ^org_id)
  end
end
