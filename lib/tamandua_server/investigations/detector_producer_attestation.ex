defmodule TamanduaServer.Investigations.DetectorProducerAttestation do
  @moduledoc "Tenant-scoped authorization for one immutable detector artifact revision."

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  @detector_types ~w(model rule heuristic reputation sandbox human ensemble other)
  @evidence_classes ~w(contract_smoke synthetic_parity bootstrap_calibration governed_holdout production_telemetry)
  @claim_scopes ~w(contract_only parity_only calibration_only efficacy)

  schema "detector_producer_attestations" do
    field(:producer_id, :string)
    field(:detector_id, :string)
    field(:detector_type, :string)
    field(:detector_version, :string)
    field(:source, :string)
    field(:revision, :string)
    field(:artifact_sha256, :string)
    field(:input_schema_sha256, :string)
    field(:allowed_evidence_classes, {:array, :string}, default: [])
    field(:allowed_claim_scopes, {:array, :string}, default: [])
    field(:attestation_sha256, :string)
    field(:status, :string, default: "active")
    field(:attested_at, :utc_datetime_usec)
    field(:expires_at, :utc_datetime_usec)
    field(:revoked_at, :utc_datetime_usec)

    belongs_to(:organization, TamanduaServer.Accounts.Organization)
    belongs_to(:attested_by, TamanduaServer.Accounts.User)
    timestamps()
  end

  def create_changeset(record, attrs) do
    record
    |> cast(attrs, [
      :organization_id,
      :attested_by_id,
      :producer_id,
      :detector_id,
      :detector_type,
      :detector_version,
      :source,
      :revision,
      :artifact_sha256,
      :input_schema_sha256,
      :allowed_evidence_classes,
      :allowed_claim_scopes,
      :attestation_sha256,
      :status,
      :attested_at,
      :expires_at
    ])
    |> validate_required([
      :organization_id,
      :producer_id,
      :detector_id,
      :detector_type,
      :detector_version,
      :source,
      :revision,
      :artifact_sha256,
      :input_schema_sha256,
      :allowed_evidence_classes,
      :allowed_claim_scopes,
      :attestation_sha256,
      :attested_at
    ])
    |> validate_length(:producer_id, min: 1, max: 256)
    |> validate_length(:detector_id, min: 1, max: 256)
    |> validate_length(:detector_version, min: 1, max: 128)
    |> validate_length(:source, min: 1, max: 256)
    |> validate_length(:revision, min: 1, max: 256)
    |> validate_inclusion(:detector_type, @detector_types)
    |> validate_inclusion(:status, ~w(active revoked))
    |> validate_format(:artifact_sha256, ~r/^[a-f0-9]{64}$/)
    |> validate_format(:input_schema_sha256, ~r/^[a-f0-9]{64}$/)
    |> validate_format(:attestation_sha256, ~r/^[a-f0-9]{64}$/)
    |> validate_subset(:allowed_evidence_classes, @evidence_classes)
    |> validate_subset(:allowed_claim_scopes, @claim_scopes)
    |> validate_change(:allowed_evidence_classes, &nonempty_bounded_list/2)
    |> validate_change(:allowed_claim_scopes, &nonempty_bounded_list/2)
    |> unique_constraint([:organization_id, :attestation_sha256],
      name: :detector_producer_attestations_org_hash_idx
    )
  end

  defp nonempty_bounded_list(field, values) do
    if length(values) in 1..5 and Enum.all?(values, &(is_binary(&1) and byte_size(&1) <= 64)),
      do: [],
      else: [{field, "must be a non-empty bounded list"}]
  end
end
