defmodule TamanduaServer.Alerts.Tag do
  @moduledoc """
  Schema for alert tags.

  Tags allow analysts to categorize and organize alerts with custom labels.
  Each tag has a name, optional description, color for UI display, and can
  belong to predefined categories.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Alerts.TagAssignment

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "alert_tags" do
    field :name, :string
    field :description, :string
    field :color, :string, default: "#6B7280"
    field :category, :string
    field :metadata, :map, default: %{}

    belongs_to :organization, Organization
    belongs_to :created_by, User, foreign_key: :created_by_id

    many_to_many :alerts, Alert, join_through: TagAssignment

    timestamps()
  end

  @predefined_categories ~w(
    malware
    phishing
    lateral_movement
    data_exfiltration
    privilege_escalation
    persistence
    credential_access
    defense_evasion
    discovery
    collection
    command_control
    impact
    false_positive
    informational
    investigation
    escalated
    external_threat
    internal_threat
  )

  @color_palette [
    "#EF4444", # red
    "#F97316", # orange
    "#F59E0B", # amber
    "#EAB308", # yellow
    "#84CC16", # lime
    "#22C55E", # green
    "#10B981", # emerald
    "#14B8A6", # teal
    "#06B6D4", # cyan
    "#0EA5E9", # sky
    "#3B82F6", # blue
    "#6366F1", # indigo
    "#8B5CF6", # violet
    "#A855F7", # purple
    "#D946EF", # fuchsia
    "#EC4899", # pink
    "#F43F5E", # rose
    "#6B7280", # gray
  ]

  def predefined_categories, do: @predefined_categories
  def color_palette, do: @color_palette

  @doc false
  def changeset(tag, attrs) do
    tag
    |> cast(attrs, [:name, :description, :color, :category, :metadata, :organization_id, :created_by_id])
    |> validate_required([:name, :organization_id])
    |> validate_length(:name, min: 1, max: 50)
    |> validate_length(:description, max: 500)
    |> validate_color()
    |> validate_category()
    |> unique_constraint([:organization_id, :name], name: :alert_tags_org_name_unique)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:created_by_id)
  end

  defp validate_color(changeset) do
    color = get_change(changeset, :color)

    if color && !valid_color?(color) do
      add_error(changeset, :color, "must be a valid hex color (e.g., #FF5733)")
    else
      changeset
    end
  end

  defp valid_color?(color) do
    Regex.match?(~r/^#[0-9A-Fa-f]{6}$/, color)
  end

  defp validate_category(changeset) do
    category = get_change(changeset, :category)

    if category && category not in @predefined_categories do
      add_error(changeset, :category, "must be one of the predefined categories")
    else
      changeset
    end
  end
end
