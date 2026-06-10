defmodule TamanduaServer.Detection.GeneratedYaraRule do
  @moduledoc """
  Schema for auto-generated YARA rules produced by the ML-driven YaraGenerator.

  These rules are created when the ML engine detects malware with high confidence
  and the file hash is not already covered by an existing YARA rule. Rules follow
  a lifecycle:

    staged -> reviewed -> active -> expired

  - `staged`   - Auto-generated, not yet active in detection (30-day TTL)
  - `reviewed` - Analyst has reviewed but not yet promoted
  - `active`   - Promoted to active detection, distributed to agents
  - `expired`  - TTL exceeded without promotion, auto-cleaned
  - `rejected` - Analyst rejected the rule; source hash will not trigger regeneration
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @valid_statuses ~w(staged reviewed active expired rejected)

  schema "generated_yara_rules" do
    field :name, :string
    field :rule_content, :string
    field :source_hash, :string
    field :malware_family, :string
    field :ml_confidence, :float
    field :status, :string, default: "staged"
    field :expires_at, :utc_datetime_usec
    field :reviewed_at, :utc_datetime_usec
    field :metadata, :map, default: %{}

    belongs_to :reviewed_by, User, foreign_key: :reviewed_by_id, type: :binary_id
    belongs_to :organization, Organization

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(name rule_content source_hash ml_confidence status expires_at)a
  @optional_fields ~w(malware_family reviewed_at reviewed_by_id organization_id metadata)a

  def changeset(rule, attrs) do
    rule
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, @valid_statuses)
    |> validate_number(:ml_confidence, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> unique_constraint(:name)
    |> foreign_key_constraint(:reviewed_by_id)
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Changeset for promoting a rule to a new status.
  """
  def promote_changeset(rule, attrs) do
    rule
    |> cast(attrs, [:status, :reviewed_by_id, :reviewed_at])
    |> validate_required([:status])
    |> validate_inclusion(:status, @valid_statuses)
  end
end
