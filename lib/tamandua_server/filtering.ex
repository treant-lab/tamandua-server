defmodule TamanduaServer.Filtering do
  @moduledoc """
  Context module for advanced filtering functionality.

  Provides:
  - Saved filter management
  - Filter validation and building
  - Field metadata and suggestions
  - Filter templates
  - Usage analytics
  """

  import Ecto.Query, warn: false

  alias TamanduaServer.Repo
  alias TamanduaServer.Filtering.{SavedFilter, FilterParser, QueryBuilder}

  @doc """
  Returns list of saved filters for a user.

  ## Options
  - `:scope` - Filter by scope (alerts, agents, events, etc.)
  - `:category` - Filter by category
  - `:pinned_only` - Only return pinned filters
  - `:templates_only` - Only return templates
  - `:include_public` - Include public/shared filters
  """
  def list_saved_filters(user_id, organization_id, opts \\ []) do
    base_query =
      from f in SavedFilter,
        where: f.user_id == ^user_id and f.organization_id == ^organization_id,
        where: is_nil(f.parent_id),
        order_by: [desc: f.is_pinned, desc: f.last_used_at, desc: f.inserted_at]

    base_query
    |> apply_list_filters(opts)
    |> Repo.all()
  end

  defp apply_list_filters(query, []), do: query

  defp apply_list_filters(query, [{:scope, scope} | rest]) do
    query
    |> where([f], f.scope == ^scope)
    |> apply_list_filters(rest)
  end

  defp apply_list_filters(query, [{:category, category} | rest]) do
    query
    |> where([f], f.category == ^category)
    |> apply_list_filters(rest)
  end

  defp apply_list_filters(query, [{:pinned_only, true} | rest]) do
    query
    |> where([f], f.is_pinned == true)
    |> apply_list_filters(rest)
  end

  defp apply_list_filters(query, [{:templates_only, true} | rest]) do
    query
    |> where([f], f.is_template == true)
    |> apply_list_filters(rest)
  end

  defp apply_list_filters(query, [{:include_public, true} | rest]) do
    # Include public filters from other users in the same organization
    query
    |> or_where([f], f.is_public == true and f.organization_id == ^query.wheres)
    |> apply_list_filters(rest)
  end

  defp apply_list_filters(query, [_ | rest]), do: apply_list_filters(query, rest)

  @doc """
  Gets a saved filter by ID.
  """
  def get_saved_filter(id) do
    Repo.get(SavedFilter, id)
  end

  @doc """
  Gets a saved filter by ID for a specific user (with access check).
  """
  def get_saved_filter(id, user_id, organization_id) do
    from(f in SavedFilter,
      where: f.id == ^id,
      where:
        f.user_id == ^user_id or f.is_public == true or f.shared_with_team == true,
      where: f.organization_id == ^organization_id
    )
    |> Repo.one()
  end

  @doc """
  Creates a new saved filter.

  ## Examples

      iex> create_saved_filter(%{
      ...>   name: "Critical Alerts",
      ...>   filter_json: %{"logic" => "AND", "conditions" => [...]},
      ...>   user_id: user_id,
      ...>   organization_id: org_id
      ...> })
      {:ok, %SavedFilter{}}
  """
  def create_saved_filter(attrs) do
    %SavedFilter{}
    |> SavedFilter.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a saved filter.
  """
  def update_saved_filter(%SavedFilter{} = saved_filter, attrs) do
    saved_filter
    |> SavedFilter.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a saved filter.
  """
  def delete_saved_filter(%SavedFilter{} = saved_filter) do
    Repo.delete(saved_filter)
  end

  @doc """
  Toggles pinned status of a filter.
  """
  def toggle_pin(saved_filter_id, user_id) do
    case get_saved_filter(saved_filter_id) do
      %SavedFilter{user_id: ^user_id} = filter ->
        update_saved_filter(filter, %{is_pinned: !filter.is_pinned})

      _ ->
        {:error, :not_found}
    end
  end

  @doc """
  Records usage of a saved filter.
  """
  def record_usage(%SavedFilter{} = saved_filter) do
    saved_filter
    |> SavedFilter.record_usage_changeset()
    |> Repo.update()
  end

  @doc """
  Creates a new version of a saved filter.
  """
  def create_version(%SavedFilter{} = saved_filter, attrs) do
    saved_filter
    |> SavedFilter.create_version_changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Gets all versions of a saved filter.
  """
  def list_versions(%SavedFilter{} = saved_filter) do
    parent_id = saved_filter.parent_id || saved_filter.id

    from(f in SavedFilter,
      where: f.parent_id == ^parent_id or f.id == ^parent_id,
      order_by: [desc: f.version]
    )
    |> Repo.all()
  end

  @doc """
  Returns popular saved filters (most used).
  """
  def list_popular_filters(organization_id, limit \\ 10) do
    from(f in SavedFilter,
      where: f.organization_id == ^organization_id,
      where: is_nil(f.parent_id),
      where: f.is_public == true or f.shared_with_team == true,
      order_by: [desc: f.usage_count],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Returns recently used filters.
  """
  def list_recent_filters(user_id, organization_id, limit \\ 5) do
    from(f in SavedFilter,
      where: f.user_id == ^user_id and f.organization_id == ^organization_id,
      where: not is_nil(f.last_used_at),
      where: is_nil(f.parent_id),
      order_by: [desc: f.last_used_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Returns default filter templates.
  """
  def list_filter_templates(scope \\ "alerts") do
    [
      %{
        name: "Unresolved High Severity",
        description: "High and critical severity alerts that are not resolved",
        category: "alerts",
        scope: scope,
        filter_json: %{
          "logic" => "AND",
          "conditions" => [
            %{"field" => "severity", "operator" => "in", "value" => ["critical", "high"]},
            %{"field" => "status", "operator" => "in", "value" => ["new", "investigating"]}
          ]
        },
        is_template: true
      },
      %{
        name: "Last 24 Hours",
        description: "All items from the last 24 hours",
        category: scope,
        scope: scope,
        filter_json: %{
          "logic" => "AND",
          "conditions" => [
            %{"field" => "created_at", "operator" => "last_n_hours", "value" => 24}
          ]
        },
        is_template: true
      },
      %{
        name: "Unassigned",
        description: "Items not assigned to anyone",
        category: scope,
        scope: scope,
        filter_json: %{
          "logic" => "AND",
          "conditions" => [
            %{"field" => "assigned_to_id", "operator" => "is_null"}
          ]
        },
        is_template: true
      },
      %{
        name: "MITRE ATT&CK: Persistence",
        description: "Alerts related to persistence techniques",
        category: "threats",
        scope: "alerts",
        filter_json: %{
          "logic" => "AND",
          "conditions" => [
            %{
              "field" => "mitre_tactic",
              "operator" => "array_contains",
              "value" => "persistence"
            }
          ]
        },
        is_template: true
      },
      %{
        name: "ML Detections",
        description: "Alerts from machine learning detection engine",
        category: "detection",
        scope: "alerts",
        filter_json: %{
          "logic" => "AND",
          "conditions" => [
            %{"field" => "detection_source", "operator" => "eq", "value" => "ml"}
          ]
        },
        is_template: true
      },
      %{
        name: "Threat Score > 0.8",
        description: "High confidence threats",
        category: "threats",
        scope: "alerts",
        filter_json: %{
          "logic" => "AND",
          "conditions" => [
            %{"field" => "threat_score", "operator" => "gte", "value" => 0.8}
          ]
        },
        is_template: true
      }
    ]
  end

  @doc """
  Validates a filter structure.
  """
  def validate_filter(filter) do
    FilterParser.validate(filter)
  end

  @doc """
  Builds an Ecto query from a filter.
  """
  def build_query(base_query, filter) do
    QueryBuilder.build(base_query, filter)
  end

  @doc """
  Returns field metadata with auto-suggest capabilities.
  """
  def get_field_metadata(scope \\ "alerts") do
    case scope do
      "alerts" -> alert_field_metadata()
      "agents" -> agent_field_metadata()
      "events" -> event_field_metadata()
      "telemetry" -> telemetry_field_metadata()
      _ -> alert_field_metadata()
    end
  end

  defp alert_field_metadata do
    [
      %{
        name: "severity",
        display_name: "Severity",
        type: :enum,
        operators: ["eq", "ne", "in", "not_in"],
        values: ["critical", "high", "medium", "low", "info"],
        popular: true
      },
      %{
        name: "status",
        display_name: "Status",
        type: :enum,
        operators: ["eq", "ne", "in", "not_in"],
        values: ["new", "investigating", "resolved", "false_positive"],
        popular: true
      },
      %{
        name: "verdict",
        display_name: "Verdict",
        type: :enum,
        operators: ["eq", "ne", "in", "not_in"],
        values: ["unconfirmed", "true_positive", "false_positive", "benign", "suspicious"],
        popular: false
      },
      %{
        name: "mitre_technique",
        display_name: "MITRE ATT&CK Technique",
        type: :string,
        operators: ["eq", "contains", "array_contains", "array_overlaps"],
        popular: true
      },
      %{
        name: "mitre_tactic",
        display_name: "MITRE ATT&CK Tactic",
        type: :string,
        operators: ["eq", "contains", "array_contains"],
        popular: true
      },
      %{
        name: "process_name",
        display_name: "Process Name",
        type: :string,
        operators: ["eq", "ne", "contains", "starts_with", "ends_with", "regex"],
        popular: true
      },
      %{
        name: "file_path",
        display_name: "File Path",
        type: :string,
        operators: ["eq", "contains", "starts_with", "ends_with", "regex"],
        popular: true
      },
      %{
        name: "file_hash",
        display_name: "File Hash",
        type: :string,
        operators: ["eq", "in"],
        popular: false
      },
      %{
        name: "ip_address",
        display_name: "IP Address",
        type: :ip,
        operators: ["eq", "cidr", "ip_range"],
        popular: true
      },
      %{
        name: "domain",
        display_name: "Domain",
        type: :string,
        operators: ["eq", "contains", "starts_with", "ends_with", "regex"],
        popular: true
      },
      %{
        name: "user",
        display_name: "User",
        type: :string,
        operators: ["eq", "contains", "starts_with"],
        popular: true
      },
      %{
        name: "agent_id",
        display_name: "Agent ID",
        type: :uuid,
        operators: ["eq", "ne", "in", "not_in"],
        popular: false
      },
      %{
        name: "agent_hostname",
        display_name: "Agent Hostname",
        type: :string,
        operators: ["eq", "contains", "starts_with", "regex"],
        popular: true
      },
      %{
        name: "assigned_to_id",
        display_name: "Assigned To",
        type: :uuid,
        operators: ["eq", "ne", "is_null", "is_not_null"],
        popular: true
      },
      %{
        name: "threat_score",
        display_name: "Threat Score",
        type: :float,
        operators: ["eq", "ne", "gt", "gte", "lt", "lte", "between"],
        popular: true
      },
      %{
        name: "confidence_score",
        display_name: "Confidence Score",
        type: :float,
        operators: ["gt", "gte", "lt", "lte", "between"],
        popular: false
      },
      %{
        name: "occurrence_count",
        display_name: "Occurrence Count",
        type: :integer,
        operators: ["eq", "gt", "gte", "lt", "lte", "between"],
        popular: false
      },
      %{
        name: "created_at",
        display_name: "Created At",
        type: :datetime,
        operators: [
          "before",
          "after",
          "date_between",
          "last_n_days",
          "last_n_hours",
          "last_n_minutes"
        ],
        popular: true
      },
      %{
        name: "updated_at",
        display_name: "Updated At",
        type: :datetime,
        operators: ["before", "after", "date_between", "last_n_days"],
        popular: false
      },
      %{
        name: "last_seen_at",
        display_name: "Last Seen",
        type: :datetime,
        operators: ["before", "after", "date_between", "last_n_days"],
        popular: false
      },
      %{
        name: "detection_source",
        display_name: "Detection Source",
        type: :enum,
        operators: ["eq", "in"],
        values: ["yara", "sigma", "ml", "ioc", "behavior"],
        popular: true
      }
    ]
  end

  defp agent_field_metadata do
    [
      %{
        name: "hostname",
        display_name: "Hostname",
        type: :string,
        operators: ["eq", "contains", "starts_with", "regex"],
        popular: true
      },
      %{
        name: "os",
        display_name: "Operating System",
        type: :enum,
        operators: ["eq", "in"],
        values: ["windows", "linux", "macos"],
        popular: true
      },
      %{
        name: "status",
        display_name: "Status",
        type: :enum,
        operators: ["eq", "in"],
        values: ["online", "offline", "isolated"],
        popular: true
      },
      %{
        name: "version",
        display_name: "Agent Version",
        type: :string,
        operators: ["eq", "gt", "gte", "lt", "lte"],
        popular: false
      },
      %{
        name: "last_seen_at",
        display_name: "Last Seen",
        type: :datetime,
        operators: ["before", "after", "last_n_days", "last_n_hours"],
        popular: true
      }
    ]
  end

  defp event_field_metadata do
    [
      %{
        name: "event_type",
        display_name: "Event Type",
        type: :enum,
        operators: ["eq", "in"],
        values: ["process", "file", "network", "registry", "dns"],
        popular: true
      },
      %{
        name: "timestamp",
        display_name: "Timestamp",
        type: :datetime,
        operators: ["before", "after", "date_between", "last_n_days"],
        popular: true
      }
    ]
  end

  defp telemetry_field_metadata do
    event_field_metadata()
  end

  @doc """
  Gets value suggestions for a specific field.

  Returns top values from the database for auto-complete.
  """
  def get_value_suggestions(_field_name, _scope, _organization_id, _limit \\ 100) do
    # This would query the actual data
    # For now, return empty list
    []
  end
end
