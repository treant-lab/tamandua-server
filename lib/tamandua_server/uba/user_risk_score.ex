defmodule TamanduaServer.UBA.UserRiskScore do
  @moduledoc """
  Schema for user risk scores.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "user_risk_scores" do
    field :risk_score, :integer
    field :risk_level, :string

    # Risk factors
    field :off_hours_activity, :integer
    field :new_location, :integer
    field :excessive_data_access, :integer
    field :privilege_escalation, :integer
    field :failed_logins, :integer
    field :anomalous_app_usage, :integer
    field :peer_group_outlier, :integer

    field :contributing_anomalies, {:array, :binary_id}
    field :last_calculated, :utc_datetime_usec

    belongs_to :user, TamanduaServer.Accounts.User
    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(risk_score, attrs) do
    risk_score
    |> cast(attrs, [
      :user_id,
      :organization_id,
      :risk_score,
      :risk_level,
      :off_hours_activity,
      :new_location,
      :excessive_data_access,
      :privilege_escalation,
      :failed_logins,
      :anomalous_app_usage,
      :peer_group_outlier,
      :contributing_anomalies,
      :last_calculated
    ])
    |> validate_required([:user_id, :risk_score, :risk_level])
    |> validate_inclusion(:risk_level, ["low", "medium", "high", "critical"])
    |> validate_number(:risk_score, greater_than_or_equal_to: 0, less_than_or_equal_to: 100)
    |> unique_constraint(:user_id)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:organization_id)
  end
end
