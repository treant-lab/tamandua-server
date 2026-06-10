defmodule TamanduaServer.Agents.GeofencingRule do
  @moduledoc """
  Geofencing rule that defines expected, allowed, and restricted regions
  for agents based on scope (all, group, agent, tag).
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "geofencing_rules" do
    field :name, :string
    field :description, :string
    field :scope_type, :string
    field :scope_ids, {:array, :binary_id}, default: []
    field :scope_tags, {:array, :string}, default: []
    field :expected_region_ids, {:array, :binary_id}, default: []
    field :allowed_region_ids, {:array, :binary_id}, default: []
    field :restricted_region_ids, {:array, :binary_id}, default: []
    field :alert_on_unexpected, :boolean, default: true
    field :alert_severity, :string, default: "medium"
    field :auto_isolate_restricted, :boolean, default: false
    field :priority, :integer, default: 0
    field :is_enabled, :boolean, default: true

    belongs_to :organization, Organization

    timestamps()
  end

  @doc false
  def changeset(rule, attrs) do
    rule
    |> cast(attrs, [
      :organization_id,
      :name,
      :description,
      :scope_type,
      :scope_ids,
      :scope_tags,
      :expected_region_ids,
      :allowed_region_ids,
      :restricted_region_ids,
      :alert_on_unexpected,
      :alert_severity,
      :auto_isolate_restricted,
      :priority,
      :is_enabled
    ])
    |> validate_required([:organization_id, :name, :scope_type])
    |> validate_inclusion(:scope_type, ~w(all group agent tag))
    |> validate_inclusion(:alert_severity, ~w(low medium high critical))
    |> validate_scope()
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_scope(changeset) do
    scope_type = get_change(changeset, :scope_type)
    scope_ids = get_change(changeset, :scope_ids) || []
    scope_tags = get_change(changeset, :scope_tags) || []

    case scope_type do
      "all" ->
        changeset

      "tag" ->
        if Enum.empty?(scope_tags) do
          add_error(changeset, :scope_tags, "must specify at least one tag for tag scope")
        else
          changeset
        end

      scope_type when scope_type in ["group", "agent"] ->
        if Enum.empty?(scope_ids) do
          add_error(changeset, :scope_ids, "must specify at least one ID for #{scope_type} scope")
        else
          changeset
        end

      _ ->
        changeset
    end
  end
end
