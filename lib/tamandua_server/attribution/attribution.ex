defmodule TamanduaServer.Attribution.Attribution do
  @moduledoc """
  Schema for threat actor attribution records.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "attributions" do
    field :primary_actor, :string
    field :confidence, :float
    field :alternative_actors, {:array, :map}, default: []
    field :explanation, :string
    field :feature_contributions, :map, default: %{}
    field :mitre_techniques, {:array, :string}, default: []
    field :mitre_tactics, {:array, :string}, default: []
    field :iocs, {:array, :map}, default: []
    field :campaign_id, :string
    field :attack_patterns, {:array, :string}, default: []
    field :source, :string, default: "ml"
    field :validated, :boolean, default: false
    field :validated_by_id, :binary_id
    field :validated_at, :utc_datetime
    field :analyst_notes, :string

    belongs_to :alert, TamanduaServer.Alerts.Alert
    belongs_to :event, TamanduaServer.Telemetry.Event

    # There is no `tenants` table nor a `TamanduaServer.Tenants.Tenant` schema
    # in this codebase (the CreateAttributions migration notes: "`tenants` has
    # no backing table — the association is resolved logically"). Keep the raw
    # column as a plain field instead of a belongs_to to a phantom module.
    field :tenant_id, :binary_id

    timestamps()
  end

  @required_fields [:primary_actor, :confidence]
  @optional_fields [
    :alternative_actors,
    :explanation,
    :feature_contributions,
    :mitre_techniques,
    :mitre_tactics,
    :iocs,
    :campaign_id,
    :attack_patterns,
    :source,
    :validated,
    :validated_by_id,
    :validated_at,
    :analyst_notes,
    :alert_id,
    :event_id,
    :tenant_id
  ]

  def changeset(attribution, attrs) do
    attribution
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_number(:confidence, greater_than_or_equal_to: 0, less_than_or_equal_to: 1)
    |> validate_inclusion(:source, ["ml", "manual", "threat_intel", "ioc_match"])
    |> foreign_key_constraint(:alert_id)
    |> foreign_key_constraint(:event_id)
  end
end
