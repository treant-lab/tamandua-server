defmodule TamanduaServerWeb.API.V1.NotificationTemplateController do
  @moduledoc """
  REST API for notification template management.

  Allows organizations to customize notification templates for different channels.

  ## Endpoints

  - GET /api/v1/notification_templates - List templates (filter by channel, type)
  - GET /api/v1/notification_templates/:id - Get a single template
  - POST /api/v1/notification_templates - Create a custom template
  - PUT /api/v1/notification_templates/:id - Update a template
  - DELETE /api/v1/notification_templates/:id - Delete a template

  ## Query Parameters (for index)

  - `channel` - Filter by channel (email, slack, discord, etc.)
  - `type` - Filter by notification type
  - `include_defaults` - Include system default templates (default: true)

  ## Business Rules

  - Cannot modify or delete is_default=true templates
  - Organizations can only access their own templates + defaults
  - Template validation ensures required fields present
  - Custom templates override defaults for same type+channel
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Repo
  alias TamanduaServer.NotificationCenter.NotificationTemplate

  import Ecto.Query

  action_fallback TamanduaServerWeb.FallbackController

  @doc "List notification templates"
  def index(conn, params) do
    organization_id = get_organization_id(conn)
    channel = params["channel"]
    type = params["type"]
    include_defaults = params["include_defaults"] != "false"

    templates = list_templates(
      organization_id: organization_id,
      channel: channel,
      type: type,
      include_defaults: include_defaults
    )

    json(conn, %{
      data: Enum.map(templates, &serialize/1),
      count: length(templates),
      channels: NotificationTemplate.channels()
    })
  end

  @doc "Get a single template"
  def show(conn, %{"id" => id}) do
    organization_id = get_organization_id(conn)

    case get_template(id) do
      {:ok, template} ->
        # Verify organization access or default template
        if template.organization_id == organization_id || is_nil(template.organization_id) do
          json(conn, %{data: serialize(template)})
        else
          conn
          |> put_status(:not_found)
          |> json(%{error: "Template not found"})
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Template not found"})
    end
  end

  @doc "Create a new template"
  def create(conn, %{"template" => template_params}) do
    organization_id = get_organization_id(conn)

    # Ensure organization_id is set and is_default is false for custom templates
    template_params =
      template_params
      |> Map.put("organization_id", organization_id)
      |> Map.put("is_default", false)

    case create_template(template_params) do
      {:ok, template} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize(template)})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_changeset_errors(changeset)})
    end
  end

  @doc "Update a template"
  def update(conn, %{"id" => id, "template" => template_params}) do
    organization_id = get_organization_id(conn)

    with {:ok, template} <- get_template(id),
         :ok <- verify_template_ownership(template, organization_id),
         {:ok, updated} <- update_template(template, template_params) do
      json(conn, %{data: serialize(updated)})
    else
      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Template not found"})

      {:error, :forbidden} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Cannot modify default templates"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_changeset_errors(changeset)})
    end
  end

  @doc "Delete a template"
  def delete(conn, %{"id" => id}) do
    organization_id = get_organization_id(conn)

    with {:ok, template} <- get_template(id),
         :ok <- verify_template_ownership(template, organization_id),
         {:ok, _} <- delete_template(template) do
      json(conn, %{deleted: true})
    else
      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Template not found"})

      {:error, :forbidden} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Cannot delete default templates"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: inspect(reason)})
    end
  end

  # === Private Helpers ===

  defp get_organization_id(conn) do
    # Extract from current_user
    case conn.assigns[:current_user] do
      %{organization_id: org_id} when not is_nil(org_id) -> org_id
      _ -> nil
    end
  end

  defp verify_template_ownership(template, organization_id) do
    cond do
      template.is_default -> {:error, :forbidden}
      template.organization_id == organization_id -> :ok
      true -> {:error, :forbidden}
    end
  end

  defp list_templates(opts) do
    organization_id = Keyword.get(opts, :organization_id)
    channel = Keyword.get(opts, :channel)
    type = Keyword.get(opts, :type)
    include_defaults = Keyword.get(opts, :include_defaults, true)

    query = from(t in NotificationTemplate)

    # Include both org templates and optionally defaults
    query =
      if include_defaults do
        from(t in query, where: t.organization_id == ^organization_id or is_nil(t.organization_id))
      else
        from(t in query, where: t.organization_id == ^organization_id)
      end

    # Filter by channel
    query =
      if channel do
        from(t in query, where: t.channel == ^channel)
      else
        query
      end

    # Filter by type
    query =
      if type do
        from(t in query, where: t.type == ^type)
      else
        query
      end

    query
    |> order_by([t], [asc: t.type, asc: t.channel, desc: t.is_default])
    |> Repo.all()
  end

  defp get_template(id) do
    case Repo.get(NotificationTemplate, id) do
      nil -> {:error, :not_found}
      template -> {:ok, template}
    end
  end

  defp create_template(attrs) do
    %NotificationTemplate{}
    |> NotificationTemplate.changeset(attrs)
    |> Repo.insert()
  end

  defp update_template(template, attrs) do
    # Don't allow changing is_default
    attrs = Map.delete(attrs, "is_default")

    template
    |> NotificationTemplate.changeset(attrs)
    |> Repo.update()
  end

  defp delete_template(template) do
    Repo.delete(template)
  end

  defp serialize(template) do
    %{
      id: template.id,
      type: template.type,
      channel: template.channel,
      name: template.name,
      description: template.description,
      subject_template: template.subject_template,
      body_template: template.body_template,
      is_default: template.is_default,
      organization_id: template.organization_id,
      inserted_at: template.inserted_at,
      updated_at: template.updated_at
    }
  end

  defp format_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
