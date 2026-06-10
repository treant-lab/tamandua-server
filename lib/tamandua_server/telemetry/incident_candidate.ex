defmodule TamanduaServer.Telemetry.IncidentCandidate do
  @moduledoc """
  Persisted investigation candidate derived from conservative event correlation.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "incident_candidates" do
    field(:fingerprint, :string)
    field(:title, :string)
    field(:status, :string, default: "candidate")
    field(:severity, :string, default: "info")
    field(:score, :integer, default: 0)
    field(:scoring_version, :string)
    field(:event_ids, {:array, :binary_id}, default: [])
    field(:relation_types, {:array, :string}, default: [])
    field(:supporting_entities, {:array, :string}, default: [])
    field(:metadata, :map, default: %{})
    field(:feedback_verdict, :string)
    field(:feedback_notes, :string)
    field(:feedback_at, :utc_datetime_usec)

    belongs_to(:organization, Organization)
    belongs_to(:feedback_by, User)

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(candidate, attrs) do
    candidate
    |> cast(attrs, [
      :organization_id,
      :fingerprint,
      :title,
      :status,
      :severity,
      :score,
      :scoring_version,
      :event_ids,
      :relation_types,
      :supporting_entities,
      :metadata,
      :feedback_verdict,
      :feedback_notes,
      :feedback_by_id,
      :feedback_at
    ])
    |> validate_required([
      :organization_id,
      :fingerprint,
      :title,
      :status,
      :severity,
      :score,
      :scoring_version
    ])
    |> validate_inclusion(:status, ~w(candidate promoted dismissed false_positive))
    |> validate_inclusion(:severity, ~w(critical high medium low info))
    |> validate_inclusion(:feedback_verdict, ~w(true_positive false_positive benign suspicious),
      allow_nil: true
    )
    |> validate_number(:score, greater_than_or_equal_to: 0, less_than_or_equal_to: 100)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:feedback_by_id)
    |> unique_constraint([:organization_id, :fingerprint],
      name: :incident_candidates_unique_org_fingerprint
    )
  end
end
