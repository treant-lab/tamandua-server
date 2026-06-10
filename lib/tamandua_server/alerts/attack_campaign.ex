defmodule TamanduaServer.Alerts.AttackCampaign do
  @moduledoc """
  Schema for attack campaigns - groups of correlated alerts representing coordinated attacks.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Alerts.{Alert, CampaignAlert, Timestamp}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  @severities ~w(critical high medium low info)
  @statuses ~w(active contained resolved)
  @attack_patterns ~w(lateral_movement ransomware exfiltration credential_theft
                      reconnaissance persistence privilege_escalation ddos
                      data_destruction supply_chain insider_threat)

  @valid_attrs [:name, :description, :severity, :status, :agent_count, :alert_count,
                :affected_users, :affected_hosts, :start_time, :end_time, :last_activity,
                :mitre_tactics, :mitre_techniques, :attack_pattern, :confidence_score,
                :network_graph, :metadata, :organization_id, :created_by_id, :assigned_to_id]

  schema "attack_campaigns" do
    field :name, :string
    field :description, :string
    field :severity, :string, default: "medium"
    field :status, :string, default: "active"

    field :agent_count, :integer, default: 0
    field :alert_count, :integer, default: 0
    field :affected_users, {:array, :string}, default: []
    field :affected_hosts, {:array, :string}, default: []

    field :start_time, :utc_datetime_usec
    field :end_time, :utc_datetime_usec
    field :last_activity, :utc_datetime_usec

    field :mitre_tactics, {:array, :string}, default: []
    field :mitre_techniques, {:array, :string}, default: []

    field :attack_pattern, :string
    field :confidence_score, :float, default: 0.0

    field :network_graph, :map, default: %{}
    field :metadata, :map, default: %{}

    belongs_to :organization, Organization
    belongs_to :created_by, User
    belongs_to :assigned_to, User

    has_many :campaign_alerts, CampaignAlert
    many_to_many :alerts, Alert, join_through: CampaignAlert

    timestamps()
  end

  @doc false
  def changeset(campaign, attrs) do
    campaign
    |> cast(attrs, @valid_attrs)
    |> validate_required([:name, :organization_id])
    |> validate_inclusion(:severity, @severities)
    |> validate_inclusion(:status, @statuses)
    |> validate_inclusion(:attack_pattern, @attack_patterns, allow_nil: true)
    |> validate_number(:confidence_score, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> validate_number(:agent_count, greater_than_or_equal_to: 0)
    |> validate_number(:alert_count, greater_than_or_equal_to: 0)
    |> validate_time_order()
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:created_by_id)
    |> foreign_key_constraint(:assigned_to_id)
  end

  defp validate_time_order(changeset) do
    start_time = get_field(changeset, :start_time)
    end_time = get_field(changeset, :end_time)

    if Timestamp.compare(start_time, end_time) == :gt do
      add_error(changeset, :end_time, "must be after start_time")
    else
      changeset
    end
  end
end
