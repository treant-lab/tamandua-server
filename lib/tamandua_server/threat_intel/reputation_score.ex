defmodule TamanduaServer.ThreatIntel.ReputationScore do
  @moduledoc """
  Schema for storing reputation scores over time.

  Tracks score history for indicators to enable trend analysis,
  alerting on score changes, and historical investigation.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "reputation_scores" do
    field :indicator_type, :string  # ip, domain, url, hash_sha256, hash_md5, email
    field :indicator_value, :string
    field :score, :integer  # 0-100
    field :confidence, :float  # 0.0-1.0
    field :verdict, :string  # clean, unknown, suspicious, malicious
    field :sources_queried, :integer
    field :sources_used, :integer
    field :breakdown, :map  # Source-specific scores
    field :weighted_breakdown, :map  # Weighted scores
    field :majority_bonus, :integer
    field :metadata, :map  # Additional context
    field :scored_at, :utc_datetime_usec

    timestamps()
  end

  @required_fields [:indicator_type, :indicator_value, :score, :confidence, :verdict, :scored_at]
  @optional_fields [
    :sources_queried, :sources_used, :breakdown, :weighted_breakdown,
    :majority_bonus, :metadata
  ]

  def changeset(score, attrs) do
    score
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:indicator_type, ["ip", "domain", "url", "hash_sha256", "hash_md5", "email"])
    |> validate_inclusion(:verdict, ["clean", "unknown", "suspicious", "malicious"])
    |> validate_number(:score, greater_than_or_equal_to: 0, less_than_or_equal_to: 100)
    |> validate_number(:confidence, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> validate_number(:sources_queried, greater_than_or_equal_to: 0)
    |> validate_number(:sources_used, greater_than_or_equal_to: 0)
    # Note: indexes should be defined in migrations, not changesets
  end
end
