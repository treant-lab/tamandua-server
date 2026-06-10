defmodule TamanduaServer.Alerts.SuppressedAlert do
  @moduledoc """
  Schema for suppressed alerts.

  Stores alerts that were suppressed by suppression rules, manual suppression,
  or contextual auto-suppression. These can be unsuppressed later if needed.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Alerts.{Alert, SuppressionRule}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "suppressed_alerts" do
    # Original alert data
    field :title, :string
    field :description, :string
    field :severity, :string
    field :original_severity, :string
    field :mitre_tactics, {:array, :string}, default: []
    field :mitre_techniques, {:array, :string}, default: []
    field :threat_score, :float
    field :evidence, :map, default: %{}
    field :process_chain, {:array, :map}, default: []
    field :raw_event, :map
    field :detection_metadata, :map, default: %{}

    # Suppression details
    field :suppression_reason, :string
    field :suppression_type, :string  # "rule", "manual", "auto_contextual"
    field :suppressed_at, :utc_datetime_usec

    # For auto-unsuppression
    field :unsuppress_at, :utc_datetime_usec
    field :unsuppressed, :boolean, default: false
    field :unsuppressed_at, :utc_datetime_usec

    # Relationships
    belongs_to :organization, Organization
    belongs_to :agent, Agent
    belongs_to :suppression_rule, SuppressionRule
    belongs_to :suppressed_by, User, foreign_key: :suppressed_by_id, type: :binary_id
    belongs_to :unsuppressed_by, User, foreign_key: :unsuppressed_by_id, type: :binary_id
    belongs_to :unsuppressed_alert, Alert, foreign_key: :unsuppressed_alert_id, type: :binary_id

    timestamps(type: :utc_datetime_usec)
  end

  @valid_suppression_types ~w(rule manual auto_contextual)
  @valid_severities ~w(critical high medium low info)

  @doc false
  def changeset(suppressed_alert, attrs) do
    suppressed_alert
    |> cast(attrs, [
      :title, :description, :severity, :original_severity,
      :mitre_tactics, :mitre_techniques, :threat_score,
      :evidence, :process_chain, :raw_event, :detection_metadata,
      :suppression_reason, :suppression_type, :suppressed_at,
      :unsuppress_at, :unsuppressed, :unsuppressed_at,
      :organization_id, :agent_id, :suppression_rule_id,
      :suppressed_by_id, :unsuppressed_by_id, :unsuppressed_alert_id
    ])
    |> validate_required([:title, :severity, :suppression_reason, :suppression_type, :suppressed_at])
    |> validate_inclusion(:severity, @valid_severities)
    |> validate_inclusion(:original_severity, @valid_severities ++ [nil])
    |> validate_inclusion(:suppression_type, @valid_suppression_types)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:agent_id)
    |> foreign_key_constraint(:suppression_rule_id)
    |> foreign_key_constraint(:suppressed_by_id)
    |> foreign_key_constraint(:unsuppressed_by_id)
    |> foreign_key_constraint(:unsuppressed_alert_id)
  end

  @doc """
  Create a suppressed alert from alert data and suppression details.
  """
  def from_alert_data(alert_data, suppression_details) do
    attrs = %{
      title: alert_data[:title] || alert_data["title"],
      description: alert_data[:description] || alert_data["description"],
      severity: alert_data[:severity] || alert_data["severity"],
      original_severity: suppression_details[:original_severity],
      mitre_tactics: alert_data[:mitre_tactics] || alert_data["mitre_tactics"] || [],
      mitre_techniques: alert_data[:mitre_techniques] || alert_data["mitre_techniques"] || [],
      threat_score: alert_data[:threat_score] || alert_data["threat_score"],
      evidence: alert_data[:evidence] || alert_data["evidence"] || %{},
      process_chain: alert_data[:process_chain] || alert_data["process_chain"] || [],
      raw_event: alert_data[:raw_event] || alert_data["raw_event"],
      detection_metadata: alert_data[:detection_metadata] || alert_data["detection_metadata"] || %{},
      suppression_reason: suppression_details[:reason],
      suppression_type: suppression_details[:type],
      suppressed_at: DateTime.utc_now(),
      unsuppress_at: suppression_details[:unsuppress_at],
      organization_id: alert_data[:organization_id] || alert_data["organization_id"],
      agent_id: alert_data[:agent_id] || alert_data["agent_id"],
      suppression_rule_id: suppression_details[:rule_id],
      suppressed_by_id: suppression_details[:user_id]
    }

    changeset(%__MODULE__{}, attrs)
  end

  @type t :: %__MODULE__{}
end
