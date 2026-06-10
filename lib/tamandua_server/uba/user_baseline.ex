defmodule TamanduaServer.UBA.UserBaseline do
  @moduledoc """
  Schema for user behavioral baselines.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "user_baselines" do
    field :behavior_type, :string

    # Statistical measures
    field :mean, :float
    field :stddev, :float
    field :median, :float
    field :p95, :float
    field :p99, :float
    field :min, :float
    field :max, :float
    field :count, :integer

    # Time-based patterns
    field :hourly_pattern, :map
    field :daily_pattern, :map
    field :common_locations, {:array, :string}
    field :common_devices, {:array, :string}

    # Learning status
    field :baseline_start, :utc_datetime_usec
    field :baseline_end, :utc_datetime_usec
    field :is_complete, :boolean
    field :last_updated, :utc_datetime_usec

    belongs_to :user, TamanduaServer.Accounts.User
    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(baseline, attrs) do
    baseline
    |> cast(attrs, [
      :user_id,
      :behavior_type,
      :organization_id,
      :mean,
      :stddev,
      :median,
      :p95,
      :p99,
      :min,
      :max,
      :count,
      :hourly_pattern,
      :daily_pattern,
      :common_locations,
      :common_devices,
      :baseline_start,
      :baseline_end,
      :is_complete,
      :last_updated
    ])
    |> validate_required([:user_id, :behavior_type])
    |> unique_constraint([:user_id, :behavior_type])
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:organization_id)
  end
end
