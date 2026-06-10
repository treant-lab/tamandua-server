defmodule TamanduaServer.Alerts.CampaignAlert do
  @moduledoc """
  Join table linking alerts to attack campaigns.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Alerts.{Alert, AttackCampaign}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  @roles ~w(initial pivot lateral impact reconnaissance credential_access
            persistence privilege_escalation defense_evasion discovery
            collection exfiltration command_control)

  schema "campaign_alerts" do
    field :role, :string
    field :sequence_order, :integer
    field :added_at, :utc_datetime_usec

    belongs_to :campaign, AttackCampaign
    belongs_to :alert, Alert

    timestamps()
  end

  @doc false
  def changeset(campaign_alert, attrs) do
    campaign_alert
    |> cast(attrs, [:campaign_id, :alert_id, :role, :sequence_order, :added_at])
    |> validate_required([:campaign_id, :alert_id])
    |> validate_inclusion(:role, @roles, allow_nil: true)
    |> unique_constraint([:campaign_id, :alert_id])
    |> foreign_key_constraint(:campaign_id)
    |> foreign_key_constraint(:alert_id)
  end
end
