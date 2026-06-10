defmodule TamanduaServer.Alerts.AutoAssignmentRule do
  @moduledoc """
  Schema for auto-assignment rules.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "auto_assignment_rules" do
    field :name, :string
    field :description, :string
    field :enabled, :boolean, default: true
    field :strategy, :string, default: "round_robin"
    field :severity_filter, {:array, :string}, default: []
    field :mitre_techniques, {:array, :string}, default: []
    field :mitre_tactics, {:array, :string}, default: []
    field :source_filter, {:array, :string}, default: []
    field :analyst_pool, {:array, :binary_id}, default: []
    field :expertise_map, :map, default: %{}
    field :priority, :integer, default: 0

    belongs_to :organization, Organization

    timestamps()
  end

  def changeset(rule, attrs) do
    rule
    |> cast(attrs, [
      :name,
      :description,
      :enabled,
      :strategy,
      :severity_filter,
      :mitre_techniques,
      :mitre_tactics,
      :source_filter,
      :analyst_pool,
      :expertise_map,
      :priority,
      :organization_id
    ])
    |> validate_required([:name, :strategy])
    |> validate_inclusion(:strategy, ~w(round_robin least_busy expertise random))
    |> validate_subset(:severity_filter, ~w(critical high medium low info))
    |> foreign_key_constraint(:organization_id)
  end
end
