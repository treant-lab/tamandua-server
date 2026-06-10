defmodule TamanduaServer.UBA.UserAnomaly do
  @moduledoc """
  Schema for detected user behavioral anomalies.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "user_anomalies" do
    field :behavior_type, :string
    field :timestamp, :utc_datetime_usec
    field :anomaly_type, :string
    field :severity, :string
    field :score, :float

    field :baseline_value, :float
    field :observed_value, :float
    field :deviation, :float

    field :metadata, :map
    field :is_acknowledged, :boolean
    field :acknowledged_at, :utc_datetime_usec
    field :notes, :string

    belongs_to :user, TamanduaServer.Accounts.User
    belongs_to :organization, TamanduaServer.Accounts.Organization
    belongs_to :acknowledged_by_user, TamanduaServer.Accounts.User, foreign_key: :acknowledged_by

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(anomaly, attrs) do
    anomaly
    |> cast(attrs, [
      :user_id,
      :behavior_type,
      :timestamp,
      :organization_id,
      :anomaly_type,
      :severity,
      :score,
      :baseline_value,
      :observed_value,
      :deviation,
      :metadata,
      :is_acknowledged,
      :acknowledged_by,
      :acknowledged_at,
      :notes
    ])
    |> validate_required([:user_id, :behavior_type, :timestamp])
    |> validate_inclusion(:severity, ["low", "medium", "high", "critical"])
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:acknowledged_by)
  end
end
