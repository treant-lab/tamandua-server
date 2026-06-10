defmodule TamanduaServer.Dashboard.LayoutManager do
  @moduledoc """
  Context for managing dashboard layouts.

  Handles:
  - Layout CRUD operations
  - Layout templates
  - User/role-based layouts
  - Layout versioning
  - Layout cloning
  - Layout import/export
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Dashboard.{Layout, LayoutVersion}

  @doc """
  Gets the active layout for a user.

  Resolution order:
  1. User's default layout
  2. User's most recently created layout
  3. Role default layout
  4. System default for role
  """
  def get_active_layout(user_id, organization_id, role) do
    # Try user's default layout
    case get_user_default_layout(user_id, organization_id) do
      nil ->
        # Try role default layout
        case get_role_default_layout(role, organization_id) do
          nil ->
            # Return built-in template for role
            get_builtin_template_for_role(role, organization_id)

          layout ->
            layout
        end

      layout ->
        layout
    end
  end

  @doc """
  Gets user's default layout.
  """
  def get_user_default_layout(user_id, organization_id) do
    from(l in Layout,
      where: l.user_id == ^user_id,
      where: l.organization_id == ^organization_id,
      where: l.is_default == true
    )
    |> Repo.one()
  end

  @doc """
  Gets role default layout.
  """
  def get_role_default_layout(role, organization_id) do
    from(l in Layout,
      where: l.role == ^role,
      where: l.organization_id == ^organization_id,
      where: is_nil(l.user_id),
      where: l.is_default == true
    )
    |> Repo.one()
  end

  @doc """
  Lists all layouts for a user.
  """
  def list_user_layouts(user_id, organization_id) do
    from(l in Layout,
      where: l.user_id == ^user_id,
      where: l.organization_id == ^organization_id,
      order_by: [desc: l.updated_at]
    )
    |> Repo.all()
  end

  @doc """
  Lists all role-based layouts.
  """
  def list_role_layouts(role, organization_id) do
    from(l in Layout,
      where: l.role == ^role,
      where: l.organization_id == ^organization_id,
      where: is_nil(l.user_id),
      order_by: [desc: l.updated_at]
    )
    |> Repo.all()
  end

  @doc """
  Lists all public templates.
  """
  def list_public_templates(organization_id) do
    from(l in Layout,
      where: l.is_public == true,
      where: l.is_template == true,
      where: l.organization_id == ^organization_id,
      order_by: [desc: l.view_count, desc: l.clone_count]
    )
    |> Repo.all()
  end

  @doc """
  Lists templates by category.
  """
  def list_templates_by_category(category, organization_id) do
    from(l in Layout,
      where: l.is_template == true,
      where: l.template_category == ^category,
      where: l.organization_id == ^organization_id,
      order_by: [desc: l.clone_count]
    )
    |> Repo.all()
  end

  @doc """
  Searches layouts by name, tags, or description.
  """
  def search_layouts(query, organization_id, opts \\ []) do
    user_id = Keyword.get(opts, :user_id)
    include_public = Keyword.get(opts, :include_public, true)

    base_query =
      from l in Layout,
        where: l.organization_id == ^organization_id

    base_query =
      if user_id do
        from l in base_query,
          where: l.user_id == ^user_id or (l.is_public == true and ^include_public)
      else
        from l in base_query,
          where: l.is_public == true
      end

    from(l in base_query,
      where:
        ilike(l.name, ^"%#{query}%") or
        ilike(l.description, ^"%#{query}%") or
        fragment("? && ?", l.tags, ^[query]),
      order_by: [desc: l.updated_at]
    )
    |> Repo.all()
  end

  @doc """
  Gets a layout by ID.
  """
  def get_layout(id) do
    Repo.get(Layout, id)
  end

  @doc """
  Gets a layout by ID with preloaded associations.
  """
  def get_layout!(id, preload \\ []) do
    Layout
    |> Repo.get!(id)
    |> Repo.preload(preload)
  end

  @doc """
  Creates a new layout.
  """
  def create_layout(attrs) do
    %Layout{}
    |> Layout.changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, layout} ->
        # Create initial version
        create_version(layout, attrs[:created_by_id], "Initial version")
        {:ok, layout}

      error ->
        error
    end
  end

  @doc """
  Updates a layout and creates a version.
  """
  def update_layout(layout, attrs, user_id \\ nil, change_description \\ nil) do
    changeset = Layout.changeset(layout, attrs)

    if changeset.valid? do
      Repo.transaction(fn ->
        # Increment version
        new_version = layout.version + 1

        # Update layout
        layout =
          changeset
          |> Ecto.Changeset.put_change(:version, new_version)
          |> Repo.update!()

        # Create version snapshot
        create_version(layout, user_id, change_description)

        layout
      end)
    else
      {:error, changeset}
    end
  end

  @doc """
  Deletes a layout.
  """
  def delete_layout(layout) do
    Repo.delete(layout)
  end

  @doc """
  Sets a layout as the default for a user.
  """
  def set_user_default(layout_id, user_id, organization_id) do
    Repo.transaction(fn ->
      # Clear existing default
      from(l in Layout,
        where: l.user_id == ^user_id,
        where: l.organization_id == ^organization_id,
        where: l.is_default == true
      )
      |> Repo.update_all(set: [is_default: false])

      # Set new default
      layout = Repo.get!(Layout, layout_id)

      layout
      |> Ecto.Changeset.change(is_default: true)
      |> Repo.update!()
    end)
  end

  @doc """
  Sets a layout as the default for a role.
  """
  def set_role_default(layout_id, role, organization_id) do
    Repo.transaction(fn ->
      # Clear existing default
      from(l in Layout,
        where: l.role == ^role,
        where: l.organization_id == ^organization_id,
        where: is_nil(l.user_id),
        where: l.is_default == true
      )
      |> Repo.update_all(set: [is_default: false])

      # Set new default
      layout = Repo.get!(Layout, layout_id)

      layout
      |> Ecto.Changeset.change(is_default: true)
      |> Repo.update!()
    end)
  end

  @doc """
  Resets user to role default layout.
  """
  def reset_to_default(user_id, organization_id) do
    from(l in Layout,
      where: l.user_id == ^user_id,
      where: l.organization_id == ^organization_id,
      where: l.is_default == true
    )
    |> Repo.update_all(set: [is_default: false])
  end

  @doc """
  Clones a layout for a user.
  """
  def clone_layout(source_layout_id, user_id, organization_id, name \\ nil) do
    source = Repo.get!(Layout, source_layout_id)

    # Increment clone count
    from(l in Layout, where: l.id == ^source_layout_id)
    |> Repo.update_all(inc: [clone_count: 1])

    attrs = %{
      name: name || "#{source.name} (Copy)",
      description: source.description,
      widgets: source.widgets,
      settings: source.settings,
      tags: source.tags,
      user_id: user_id,
      organization_id: organization_id,
      cloned_from_id: source_layout_id,
      is_template: false,
      is_public: false
    }

    create_layout(attrs)
  end

  @doc """
  Exports a layout to JSON.
  """
  def export_layout(layout_id) do
    layout = get_layout!(layout_id)

    export_data = %{
      name: layout.name,
      description: layout.description,
      widgets: layout.widgets,
      settings: layout.settings,
      template_category: layout.template_category,
      tags: layout.tags,
      author_name: layout.author_name,
      version: layout.version,
      exported_at: DateTime.utc_now()
    }

    {:ok, Jason.encode!(export_data, pretty: true)}
  end

  @doc """
  Imports a layout from JSON.
  """
  def import_layout(json_data, user_id, organization_id) do
    with {:ok, data} <- Jason.decode(json_data),
         {:ok, layout} <- create_layout(Map.merge(data, %{
           "user_id" => user_id,
           "organization_id" => organization_id
         })) do
      {:ok, layout}
    else
      {:error, %Jason.DecodeError{}} ->
        {:error, :invalid_json}

      error ->
        error
    end
  end

  @doc """
  Gets layout version history.
  """
  def list_versions(layout_id) do
    from(v in LayoutVersion,
      where: v.layout_id == ^layout_id,
      order_by: [desc: v.version],
      preload: [:created_by]
    )
    |> Repo.all()
  end

  @doc """
  Restores a layout to a previous version.
  """
  def restore_version(layout_id, version_number, user_id) do
    version =
      from(v in LayoutVersion,
        where: v.layout_id == ^layout_id,
        where: v.version == ^version_number
      )
      |> Repo.one!()

    layout = get_layout!(layout_id)

    attrs = %{
      widgets: version.widgets,
      settings: version.settings
    }

    update_layout(layout, attrs, user_id, "Restored to version #{version_number}")
  end

  @doc """
  Increments view count for a layout.
  """
  def increment_view_count(layout_id) do
    from(l in Layout, where: l.id == ^layout_id)
    |> Repo.update_all(inc: [view_count: 1])
  end

  # Private helpers

  defp create_version(layout, user_id, description) do
    %LayoutVersion{}
    |> LayoutVersion.changeset(%{
      layout_id: layout.id,
      version: layout.version,
      widgets: layout.widgets,
      settings: layout.settings,
      created_by_id: user_id,
      change_description: description
    })
    |> Repo.insert!()
  end

  defp get_builtin_template_for_role(role, organization_id) do
    # Check if built-in template exists for this org
    case Repo.get_by(Layout,
      template_category: role_to_category(role),
      is_template: true,
      organization_id: organization_id
    ) do
      nil ->
        # Create default template for role
        create_default_template_for_role(role, organization_id)

      template ->
        template
    end
  end

  defp role_to_category("admin"), do: "executive"
  defp role_to_category("manager"), do: "executive"
  defp role_to_category("analyst"), do: "soc_analyst"
  defp role_to_category("hunter"), do: "threat_hunting"
  defp role_to_category("responder"), do: "incident_response"
  defp role_to_category("compliance_officer"), do: "compliance"
  defp role_to_category(_), do: "soc_analyst"

  defp create_default_template_for_role(role, organization_id) do
    templates = default_templates()
    category = role_to_category(role)
    template_data = Map.get(templates, category)

    attrs = Map.merge(template_data, %{
      organization_id: organization_id,
      is_template: true,
      is_public: true,
      template_category: category
    })

    case create_layout(attrs) do
      {:ok, layout} -> layout
      {:error, _} -> nil
    end
  end

  defp default_templates do
    %{
      "soc_analyst" => %{
        name: "SOC Analyst Dashboard",
        description: "Real-time threat monitoring and alert triage",
        widgets: [
          %{"type" => "threat_gauge", "x" => 0, "y" => 0, "w" => 4, "h" => 3, "settings" => %{}},
          %{"type" => "alert_volume", "x" => 4, "y" => 0, "w" => 8, "h" => 3, "settings" => %{"period" => "24h"}},
          %{"type" => "recent_alerts", "x" => 0, "y" => 3, "w" => 6, "h" => 4, "settings" => %{"limit" => 10}},
          %{"type" => "top_threats", "x" => 6, "y" => 3, "w" => 6, "h" => 4, "settings" => %{"limit" => 5}},
          %{"type" => "agent_status", "x" => 0, "y" => 7, "w" => 4, "h" => 3, "settings" => %{}},
          %{"type" => "mitre_coverage", "x" => 4, "y" => 7, "w" => 8, "h" => 3, "settings" => %{}}
        ],
        settings: %{
          "gridColumns" => 12,
          "rowHeight" => 60,
          "margins" => [10, 10]
        }
      },
      "executive" => %{
        name: "Executive Dashboard",
        description: "High-level security posture and KPIs",
        widgets: [
          %{"type" => "threat_gauge", "x" => 0, "y" => 0, "w" => 3, "h" => 3, "settings" => %{}},
          %{"type" => "compliance_score", "x" => 3, "y" => 0, "w" => 3, "h" => 3, "settings" => %{}},
          %{"type" => "sla_metrics", "x" => 6, "y" => 0, "w" => 6, "h" => 3, "settings" => %{}},
          %{"type" => "alert_trend", "x" => 0, "y" => 3, "w" => 12, "h" => 4, "settings" => %{"period" => "30d"}},
          %{"type" => "geo_map", "x" => 0, "y" => 7, "w" => 12, "h" => 5, "settings" => %{}}
        ],
        settings: %{
          "gridColumns" => 12,
          "rowHeight" => 60,
          "margins" => [10, 10]
        }
      },
      "compliance" => %{
        name: "Compliance Dashboard",
        description: "Compliance monitoring and audit reports",
        widgets: [
          %{"type" => "compliance_score", "x" => 0, "y" => 0, "w" => 4, "h" => 3, "settings" => %{}},
          %{"type" => "asset_inventory", "x" => 4, "y" => 0, "w" => 8, "h" => 3, "settings" => %{}},
          %{"type" => "user_activity", "x" => 0, "y" => 3, "w" => 12, "h" => 4, "settings" => %{}},
          %{"type" => "agent_status", "x" => 0, "y" => 7, "w" => 6, "h" => 3, "settings" => %{}},
          %{"type" => "system_health", "x" => 6, "y" => 7, "w" => 6, "h" => 3, "settings" => %{}}
        ],
        settings: %{
          "gridColumns" => 12,
          "rowHeight" => 60,
          "margins" => [10, 10]
        }
      },
      "incident_response" => %{
        name: "Incident Response Dashboard",
        description: "Active incident tracking and response metrics",
        widgets: [
          %{"type" => "recent_alerts", "x" => 0, "y" => 0, "w" => 6, "h" => 4, "settings" => %{"status" => "open"}},
          %{"type" => "response_times", "x" => 6, "y" => 0, "w" => 6, "h" => 4, "settings" => %{}},
          %{"type" => "storyline_viewer", "x" => 0, "y" => 4, "w" => 12, "h" => 4, "settings" => %{}},
          %{"type" => "correlation_graph", "x" => 0, "y" => 8, "w" => 12, "h" => 5, "settings" => %{}}
        ],
        settings: %{
          "gridColumns" => 12,
          "rowHeight" => 60,
          "margins" => [10, 10]
        }
      },
      "threat_hunting" => %{
        name: "Threat Hunting Dashboard",
        description: "Proactive threat hunting and anomaly detection",
        widgets: [
          %{"type" => "behavioral_anomalies", "x" => 0, "y" => 0, "w" => 6, "h" => 3, "settings" => %{}},
          %{"type" => "ml_predictions", "x" => 6, "y" => 0, "w" => 6, "h" => 3, "settings" => %{}},
          %{"type" => "ioc_matches", "x" => 0, "y" => 3, "w" => 12, "h" => 4, "settings" => %{}},
          %{"type" => "network_connections", "x" => 0, "y" => 7, "w" => 6, "h" => 4, "settings" => %{}},
          %{"type" => "process_tree", "x" => 6, "y" => 7, "w" => 6, "h" => 4, "settings" => %{}}
        ],
        settings: %{
          "gridColumns" => 12,
          "rowHeight" => 60,
          "margins" => [10, 10]
        }
      }
    }
  end
end
