defmodule TamanduaServer.Alerts.SLAPolicy do
  @moduledoc """
  Schema for SLA policies.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "sla_policies" do
    field :name, :string
    field :description, :string
    field :enabled, :boolean, default: true

    field :critical_acknowledge_minutes, :integer, default: 15
    field :critical_resolve_minutes, :integer, default: 240
    field :high_acknowledge_minutes, :integer, default: 60
    field :high_resolve_minutes, :integer, default: 480
    field :medium_acknowledge_minutes, :integer, default: 240
    field :medium_resolve_minutes, :integer, default: 1440
    field :low_acknowledge_minutes, :integer, default: 480
    field :low_resolve_minutes, :integer, default: 2880

    field :business_hours_only, :boolean, default: false
    field :business_hours_start, :time
    field :business_hours_end, :time
    field :business_days, {:array, :integer}, default: [1, 2, 3, 4, 5]
    field :timezone, :string, default: "UTC"

    field :priority, :integer, default: 0

    belongs_to :organization, Organization

    timestamps()
  end

  def changeset(policy, attrs) do
    policy
    |> cast(attrs, [
      :name,
      :description,
      :enabled,
      :critical_acknowledge_minutes,
      :critical_resolve_minutes,
      :high_acknowledge_minutes,
      :high_resolve_minutes,
      :medium_acknowledge_minutes,
      :medium_resolve_minutes,
      :low_acknowledge_minutes,
      :low_resolve_minutes,
      :business_hours_only,
      :business_hours_start,
      :business_hours_end,
      :business_days,
      :timezone,
      :priority,
      :organization_id
    ])
    |> validate_required([:name])
    |> validate_number(:critical_acknowledge_minutes, greater_than: 0)
    |> validate_number(:critical_resolve_minutes, greater_than: 0)
    |> validate_number(:high_acknowledge_minutes, greater_than: 0)
    |> validate_number(:high_resolve_minutes, greater_than: 0)
    |> validate_number(:medium_acknowledge_minutes, greater_than: 0)
    |> validate_number(:medium_resolve_minutes, greater_than: 0)
    |> validate_number(:low_acknowledge_minutes, greater_than: 0)
    |> validate_number(:low_resolve_minutes, greater_than: 0)
    |> foreign_key_constraint(:organization_id)
  end
end
