defmodule TamanduaServer.Reports.TemplateManager do
  @moduledoc """
  Manages custom report templates created via the designer.
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Reports.{ReportTemplate, WidgetRegistry}

  @doc """
  List all templates, optionally filtered by organization or category.
  """
  def list_templates(opts \\ []) do
    query = from t in ReportTemplate, order_by: [desc: t.updated_at]

    query = if org_id = opts[:organization_id] do
      where(query, [t], t.organization_id == ^org_id or t.is_public == true)
    else
      query
    end

    query = if category = opts[:category] do
      where(query, [t], t.category == ^category)
    else
      query
    end

    query = if opts[:public_only] do
      where(query, [t], t.is_public == true)
    else
      query
    end

    Repo.all(query)
  end

  @doc """
  Get a template by ID.
  """
  def get_template(id) do
    case Repo.get(ReportTemplate, id) do
      nil -> {:error, :not_found}
      template -> {:ok, template}
    end
  end

  @doc """
  Create a new template.
  """
  def create_template(attrs) do
    %ReportTemplate{}
    |> ReportTemplate.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a template.
  """
  def update_template(id, attrs) do
    with {:ok, template} <- get_template(id) do
      template
      |> ReportTemplate.changeset(attrs)
      |> Repo.update()
    end
  end

  @doc """
  Delete a template.
  """
  def delete_template(id) do
    with {:ok, template} <- get_template(id) do
      if template.is_system do
        {:error, :cannot_delete_system_template}
      else
        Repo.delete(template)
      end
    end
  end

  @doc """
  Duplicate a template.
  """
  def duplicate_template(id, new_name) do
    with {:ok, template} <- get_template(id) do
      attrs = %{
        name: new_name,
        description: template.description,
        category: template.category,
        layout: template.layout,
        widgets: template.widgets,
        branding: template.branding,
        is_public: false,
        organization_id: template.organization_id
      }

      create_template(attrs)
    end
  end

  @doc """
  Generate a report from a custom template.
  """
  def generate_from_template(template_id, date_from, date_to, opts \\ []) do
    with {:ok, template} <- get_template(template_id) do
      context = %{
        date_from: date_from,
        date_to: date_to,
        organization_id: opts[:organization_id],
        user: opts[:user]
      }

      # Render all widgets
      case WidgetRegistry.render_widgets(template.widgets, context) do
        {:ok, sections} ->
          report_data = %{
            "title" => template.name,
            "description" => template.description,
            "template_id" => template.id,
            "template_name" => template.name,
            "category" => template.category,
            "sections" => sections,
            "branding" => template.branding,
            "layout" => template.layout,
            "period" => %{"from" => date_from, "to" => date_to},
            "generated_at" => DateTime.utc_now() |> DateTime.to_iso8601(),
            "generated_by" => opts[:user] && opts[:user].name || "System"
          }

          {:ok, report_data}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @doc """
  Export template as JSON.
  """
  def export_template(id) do
    with {:ok, template} <- get_template(id) do
      export_data = %{
        name: template.name,
        description: template.description,
        category: template.category,
        layout: template.layout,
        widgets: template.widgets,
        branding: template.branding,
        tags: template.tags,
        version: template.version,
        exported_at: DateTime.utc_now() |> DateTime.to_iso8601()
      }

      {:ok, Jason.encode!(export_data, pretty: true)}
    end
  end

  @doc """
  Import template from JSON.
  """
  def import_template(json_data, opts \\ []) do
    with {:ok, data} <- Jason.decode(json_data) do
      attrs = %{
        name: data["name"],
        description: data["description"],
        category: data["category"],
        layout: data["layout"],
        widgets: data["widgets"],
        branding: data["branding"],
        tags: data["tags"] || [],
        organization_id: opts[:organization_id],
        user_id: opts[:user_id],
        created_by: opts[:user] && opts[:user].name || "System"
      }

      create_template(attrs)
    end
  end

  @doc """
  Get template statistics.
  """
  def get_template_stats(template_id) do
    with {:ok, template} <- get_template(template_id) do
      # Count reports generated from this template
      report_count = from(r in TamanduaServer.Reports.Report,
        where: r.template_id == ^template.id,
        select: count(r.id)
      ) |> Repo.one()

      {:ok, %{
        total_reports: report_count,
        widget_count: length(template.widgets),
        version: template.version,
        last_updated: template.updated_at
      }}
    end
  end

  @doc """
  Validate template before saving.
  """
  def validate_template(attrs) do
    changeset = ReportTemplate.changeset(%ReportTemplate{}, attrs)

    if changeset.valid? do
      # Additional validation: check all widgets are valid
      widgets = get_change(changeset, :widgets) || []

      validation_results = Enum.map(widgets, fn widget ->
        WidgetRegistry.validate_widget(widget)
      end)

      errors = Enum.filter(validation_results, fn
        {:error, _} -> true
        _ -> false
      end)

      if Enum.empty?(errors) do
        {:ok, changeset}
      else
        {:error, {:invalid_widgets, errors}}
      end
    else
      {:error, changeset}
    end
  end

  defp get_change(changeset, field) do
    Ecto.Changeset.get_change(changeset, field)
  end
end
