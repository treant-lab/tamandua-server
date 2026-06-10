defmodule TamanduaServer.Dashboard.Layout do
  @moduledoc """
  Schema for dashboard layouts.

  Supports:
  - User-specific layouts (user_id set)
  - Role-based layouts (role set, user_id nil)
  - Public templates (is_template = true, is_public = true)
  - Organization-scoped layouts
  - Layout versioning
  - Layout cloning
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{User, Organization}
  alias TamanduaServer.Dashboard.LayoutVersion

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @widget_types ~w(
    threat_gauge
    alert_volume
    alert_trend
    agent_status
    recent_alerts
    top_threats
    geo_map
    mitre_coverage
    detection_efficacy
    response_times
    event_timeline
    process_tree
    network_connections
    ioc_matches
    ml_predictions
    behavioral_anomalies
    user_activity
    asset_inventory
    compliance_score
    sla_metrics
    system_health
    custom_query
    metric_card
    bar_chart
    line_chart
    pie_chart
    table_widget
    heatmap
    correlation_graph
    storyline_viewer
  )a

  @template_categories ~w(
    soc_analyst
    executive
    compliance
    incident_response
    threat_hunting
    vulnerability_management
    network_security
    endpoint_security
    cloud_security
    identity_security
    custom
  )

  @roles ~w(admin manager analyst viewer responder hunter compliance_officer api_only)

  schema "dashboard_layouts" do
    field :name, :string
    field :description, :string
    field :widgets, {:array, :map}, default: []
    field :settings, :map, default: %{}
    field :is_template, :boolean, default: false
    field :is_default, :boolean, default: false
    field :is_public, :boolean, default: false
    field :template_category, :string
    field :tags, {:array, :string}, default: []
    field :thumbnail_url, :string
    field :version, :integer, default: 1
    field :author_name, :string
    field :view_count, :integer, default: 0
    field :clone_count, :integer, default: 0
    field :role, :string

    belongs_to :user, User
    belongs_to :organization, Organization
    belongs_to :cloned_from, __MODULE__

    has_many :versions, LayoutVersion, foreign_key: :layout_id
    has_many :clones, __MODULE__, foreign_key: :cloned_from_id

    timestamps(type: :utc_datetime_usec)
  end

  @doc """
  Changeset for creating/updating layouts.
  """
  def changeset(layout, attrs) do
    layout
    |> cast(attrs, [
      :name, :description, :widgets, :settings, :is_template, :is_default,
      :is_public, :template_category, :tags, :thumbnail_url, :author_name,
      :role, :user_id, :organization_id, :cloned_from_id
    ])
    |> validate_required([:name, :organization_id])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_length(:description, max: 2000)
    |> validate_inclusion(:template_category, @template_categories)
    |> validate_inclusion(:role, @roles)
    |> validate_widgets()
    |> validate_settings()
    |> validate_layout_scope()
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:cloned_from_id)
  end

  @doc """
  Validates widget configuration.
  """
  defp validate_widgets(changeset) do
    case get_field(changeset, :widgets) do
      nil ->
        changeset

      widgets when is_list(widgets) ->
        if Enum.all?(widgets, &valid_widget?/1) do
          changeset
        else
          add_error(changeset, :widgets, "contains invalid widget configuration")
        end

      _ ->
        add_error(changeset, :widgets, "must be a list")
    end
  end

  @doc """
  Validates a single widget configuration.
  """
  defp valid_widget?(widget) when is_map(widget) do
    required_keys = ["type", "x", "y", "w", "h"]
    type = Map.get(widget, "type")

    Enum.all?(required_keys, &Map.has_key?(widget, &1)) and
      is_atom_or_string_widget_type?(type) and
      is_integer(Map.get(widget, "x")) and
      is_integer(Map.get(widget, "y")) and
      is_integer(Map.get(widget, "w")) and
      is_integer(Map.get(widget, "h"))
  end

  defp valid_widget?(_), do: false

  defp is_atom_or_string_widget_type?(type) when is_binary(type) do
    String.to_existing_atom(type) in @widget_types
  rescue
    ArgumentError -> false
  end

  defp is_atom_or_string_widget_type?(type) when is_atom(type) do
    type in @widget_types
  end

  defp is_atom_or_string_widget_type?(_), do: false

  @doc """
  Validates layout settings (grid config, responsive breakpoints, etc.).
  """
  defp validate_settings(changeset) do
    case get_field(changeset, :settings) do
      nil ->
        changeset

      settings when is_map(settings) ->
        changeset

      _ ->
        add_error(changeset, :settings, "must be a map")
    end
  end

  @doc """
  Validates that layout has proper scope (user OR role, not both).
  """
  defp validate_layout_scope(changeset) do
    user_id = get_field(changeset, :user_id)
    role = get_field(changeset, :role)

    cond do
      user_id && role ->
        add_error(changeset, :base, "layout cannot be both user-specific and role-based")

      !user_id && !role && !get_field(changeset, :is_template) ->
        add_error(changeset, :base, "layout must be user-specific, role-based, or a template")

      true ->
        changeset
    end
  end

  @doc """
  Returns available widget types.
  """
  def widget_types, do: @widget_types

  @doc """
  Returns available template categories.
  """
  def template_categories, do: @template_categories
end
