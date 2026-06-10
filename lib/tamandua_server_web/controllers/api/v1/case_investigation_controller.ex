defmodule TamanduaServerWeb.API.V1.CaseInvestigationController do
  @moduledoc """
  API controller for managing case investigations.

  Provides endpoints for CRUD operations on security investigations,
  as well as managing linked alerts, events, and notes.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Investigations
  alias TamanduaServer.Investigations.CaseInvestigation

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Lists all case investigations with optional filters.

  ## Query Parameters

    * `status` - Filter by status (open, in_progress, closed, archived)
    * `severity` - Filter by severity (critical, high, medium, low, info)
    * `assigned_to` - Filter by assigned user ID
    * `search` - Search in title and description
    * `limit` - Limit results (default: 50)
    * `offset` - Offset for pagination
  """
  def index(conn, params) do
    opts = [
      status: params["status"],
      severity: params["severity"],
      assigned_to: params["assigned_to"],
      search: params["search"],
      limit: parse_int(params["limit"], 50),
      offset: parse_int(params["offset"], 0),
      organization_id: get_org_id(conn)
    ]
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)

    investigations = Investigations.list_investigations(opts)
    total = Investigations.count_investigations(opts)

    json(conn, %{
      data: Enum.map(investigations, &serialize_investigation/1),
      meta: %{
        total: total,
        limit: opts[:limit] || 50,
        offset: opts[:offset] || 0
      }
    })
  end

  @doc """
  Gets a single case investigation by ID.
  """
  def show(conn, %{"id" => id}) do
    case Investigations.get_investigation(id) do
      {:ok, investigation} ->
        json(conn, %{data: serialize_investigation(investigation)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Investigation not found"})
    end
  end

  @doc """
  Creates a new case investigation.

  ## Parameters

    * `title` - Required. Title of the investigation.
    * `description` - Optional. Description of the investigation.
    * `severity` - Optional. Severity level (default: medium).
    * `assigned_to` - Optional. User ID to assign the investigation to.
    * `alert_ids` - Optional. Array of alert IDs to link.
    * `event_ids` - Optional. Array of event IDs to link.
    * `tags` - Optional. Array of tags.
  """
  def create(conn, params) do
    user_id = get_current_user_id(conn)

    attrs = %{
      title: params["title"],
      description: params["description"],
      severity: params["severity"] || "medium",
      assigned_to: params["assigned_to"],
      created_by: user_id,
      alert_ids: params["alert_ids"] || [],
      event_ids: params["event_ids"] || [],
      tags: params["tags"] || [],
      mitre_tactics: params["mitre_tactics"] || [],
      mitre_techniques: params["mitre_techniques"] || [],
      organization_id: get_org_id(conn)
    }

    case Investigations.create_investigation(attrs) do
      {:ok, investigation} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_investigation(investigation)})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  @doc """
  Updates a case investigation.
  """
  def update(conn, %{"id" => id} = params) do
    with {:ok, investigation} <- Investigations.get_investigation(id) do
      attrs = params
      |> Map.take(~w(title description status severity assigned_to notes findings tags mitre_tactics mitre_techniques))
      |> Map.new(fn {k, v} -> {String.to_existing_atom(k), v} end)

      case Investigations.update_investigation(investigation, attrs) do
        {:ok, updated} ->
          json(conn, %{data: serialize_investigation(updated)})

        {:error, changeset} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{errors: format_errors(changeset)})
      end
    end
  end

  @doc """
  Deletes a case investigation.
  """
  def delete(conn, %{"id" => id}) do
    with {:ok, investigation} <- Investigations.get_investigation(id),
         {:ok, _} <- Investigations.delete_investigation(investigation) do
      send_resp(conn, :no_content, "")
    end
  end

  @doc """
  Adds a note to a case investigation.

  ## Parameters

    * `content` - Required. The note content.
  """
  def add_note(conn, %{"id" => id, "content" => content}) do
    author_name = get_current_user_name(conn)

    case Investigations.add_note(id, content, author_name) do
      {:ok, investigation} ->
        json(conn, %{data: serialize_investigation(investigation)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Investigation not found"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  def add_note(conn, %{"id" => _id}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameter: content"})
  end

  @doc """
  Links an alert to a case investigation.

  ## Parameters

    * `alert_id` - Required. The alert ID to link.
  """
  def add_alert(conn, %{"id" => id, "alert_id" => alert_id}) do
    case Investigations.add_alert_to_investigation(id, alert_id) do
      {:ok, investigation} ->
        json(conn, %{data: serialize_investigation(investigation)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Investigation not found"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  def add_alert(conn, %{"id" => _id}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameter: alert_id"})
  end

  @doc """
  Removes an alert from a case investigation.
  """
  def remove_alert(conn, %{"id" => id, "alert_id" => alert_id}) do
    case Investigations.remove_alert_from_investigation(id, alert_id) do
      {:ok, investigation} ->
        json(conn, %{data: serialize_investigation(investigation)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Investigation not found"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  @doc """
  Updates the status of a case investigation.

  ## Parameters

    * `status` - Required. The new status (open, in_progress, closed, archived).
  """
  def update_status(conn, %{"id" => id, "status" => status}) do
    case Investigations.update_status(id, status) do
      {:ok, investigation} ->
        json(conn, %{data: serialize_investigation(investigation)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Investigation not found"})

      {:error, :invalid_status} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid status. Must be one of: #{Enum.join(CaseInvestigation.statuses(), ", ")}"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  def update_status(conn, %{"id" => _id}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameter: status"})
  end

  @doc """
  Assigns a case investigation to a user.

  ## Parameters

    * `user_id` - The user ID to assign to (null to unassign).
  """
  def assign(conn, %{"id" => id} = params) do
    user_id = params["user_id"]  # Can be nil to unassign

    case Investigations.assign_investigation(id, user_id) do
      {:ok, investigation} ->
        json(conn, %{data: serialize_investigation(investigation)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Investigation not found"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  @doc """
  Gets investigation statistics.
  """
  def stats(conn, _params) do
    stats = Investigations.get_stats(organization_id: get_org_id(conn))
    json(conn, %{data: stats})
  end

  # Private functions

  defp serialize_investigation(%CaseInvestigation{} = investigation) do
    %{
      id: investigation.id,
      title: investigation.title,
      description: investigation.description,
      status: investigation.status,
      severity: investigation.severity,
      assigned_to: investigation.assigned_to,
      assigned_user: serialize_user(investigation.assigned_user),
      created_by: investigation.created_by,
      creator: serialize_user(investigation.creator),
      alert_ids: investigation.alert_ids || [],
      event_ids: investigation.event_ids || [],
      notes: investigation.notes,
      findings: investigation.findings,
      timeline: investigation.timeline || %{},
      tags: investigation.tags || [],
      mitre_tactics: investigation.mitre_tactics || [],
      mitre_techniques: investigation.mitre_techniques || [],
      inserted_at: investigation.inserted_at,
      updated_at: investigation.updated_at
    }
  end

  defp serialize_user(nil), do: nil
  defp serialize_user(user) do
    %{
      id: user.id,
      name: user.name,
      email: user.email
    }
  end

  defp format_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end

  defp parse_int(nil, default), do: default
  defp parse_int(val, _default) when is_integer(val), do: val
  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end

  defp get_current_user_id(conn) do
    case conn.assigns[:current_user] do
      nil -> nil
      user -> user.id
    end
  end

  defp get_current_user_name(conn) do
    case conn.assigns[:current_user] do
      nil -> nil
      user -> user.name || user.email
    end
  end

  defp get_org_id(conn) do
    case conn.assigns[:current_user] do
      nil -> nil
      user -> user.organization_id
    end
  end
end
