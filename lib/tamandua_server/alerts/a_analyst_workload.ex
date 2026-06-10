defmodule TamanduaServer.Alerts.AnalystWorkload do
  @moduledoc """
  Schema for tracking analyst workload and capacity.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{User, Organization}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "analyst_workload" do
    field :assigned_count, :integer, default: 0
    field :critical_count, :integer, default: 0
    field :high_count, :integer, default: 0
    field :medium_count, :integer, default: 0
    field :low_count, :integer, default: 0
    field :total_workload_score, :float, default: 0.0
    field :last_assignment_at, :utc_datetime_usec
    field :is_available, :boolean, default: true
    field :max_capacity, :integer, default: 50

    belongs_to :user, User
    belongs_to :organization, Organization

    timestamps()
  end

  def changeset(workload, attrs) do
    workload
    |> cast(attrs, [
      :user_id,
      :organization_id,
      :assigned_count,
      :critical_count,
      :high_count,
      :medium_count,
      :low_count,
      :total_workload_score,
      :last_assignment_at,
      :is_available,
      :max_capacity
    ])
    |> validate_required([:user_id])
    |> validate_number(:max_capacity, greater_than: 0)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:organization_id)
    |> unique_constraint([:user_id, :organization_id])
  end
end
