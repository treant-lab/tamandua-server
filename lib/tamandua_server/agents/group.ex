defmodule TamanduaServer.Agents.Group do
  @moduledoc """
  Schema for agent groups.

  Groups allow organizing agents by department, OS, criticality, or custom tags.
  Groups support parent-child hierarchy for nested organization.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Agents.{Group, GroupMember}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "agent_groups" do
    field :name, :string
    field :description, :string
    field :color, :string
    field :tags, {:array, :string}, default: []
    field :metadata, :map, default: %{}

    # RBAC: which roles can view/manage this group
    field :visible_to_roles, {:array, :string}, default: []
    field :manageable_by_roles, {:array, :string}, default: []

    belongs_to :organization, Organization
    belongs_to :parent, Group, foreign_key: :parent_id

    has_many :children, Group, foreign_key: :parent_id
    has_many :group_members, GroupMember
    many_to_many :agents, TamanduaServer.Agents.Agent, join_through: GroupMember

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(group, attrs) do
    group
    |> cast(attrs, [
      :name,
      :description,
      :color,
      :tags,
      :metadata,
      :visible_to_roles,
      :manageable_by_roles,
      :organization_id,
      :parent_id
    ])
    |> validate_required([:name, :organization_id])
    |> validate_length(:name, min: 1, max: 100)
    |> validate_length(:description, max: 500)
    |> validate_color()
    |> validate_no_circular_parent()
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:parent_id)
    |> unique_constraint([:name, :organization_id],
      name: :agent_groups_name_organization_id_index,
      message: "Group name must be unique within organization"
    )
  end

  defp validate_color(changeset) do
    case get_field(changeset, :color) do
      nil ->
        changeset

      color ->
        if String.match?(color, ~r/^#[0-9A-Fa-f]{6}$/) do
          changeset
        else
          add_error(changeset, :color, "must be a valid hex color (e.g. #FF5733)")
        end
    end
  end

  defp validate_no_circular_parent(changeset) do
    case {get_field(changeset, :id), get_change(changeset, :parent_id)} do
      {id, parent_id} when not is_nil(id) and id == parent_id ->
        add_error(changeset, :parent_id, "cannot be the same as the group itself")

      _ ->
        changeset
    end
  end
end
