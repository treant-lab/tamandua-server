defmodule TamanduaServer.UBA.UBAAlert do
  @moduledoc """
  Schema for UBA alerts.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "uba_alerts" do
    field :alert_type, :string
    field :severity, :string
    field :status, :string
    field :risk_score, :integer
    field :description, :string
    field :evidence, :map
    field :resolved_at, :utc_datetime_usec
    field :resolution_notes, :string

    belongs_to :user, TamanduaServer.Accounts.User
    belongs_to :organization, TamanduaServer.Accounts.Organization
    belongs_to :assigned_to_user, TamanduaServer.Accounts.User, foreign_key: :assigned_to

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(alert, attrs) do
    alert
    |> cast(attrs, [
      :user_id,
      :organization_id,
      :alert_type,
      :severity,
      :status,
      :risk_score,
      :description,
      :evidence,
      :assigned_to,
      :resolved_at,
      :resolution_notes
    ])
    |> validate_required([:user_id, :alert_type, :severity])
    |> validate_inclusion(:severity, ["low", "medium", "high", "critical"])
    |> validate_inclusion(:status, ["open", "investigating", "closed"])
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:assigned_to)
  end
end
