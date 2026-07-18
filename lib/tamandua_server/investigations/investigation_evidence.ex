defmodule TamanduaServer.Investigations.InvestigationEvidence do
  @moduledoc """
  Append-only evidence captured by a governed investigation run.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Investigations.InvestigationRun

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec, updated_at: false]

  schema "ai_investigation_evidence" do
    field(:kind, :string)
    field(:source, :string)
    field(:source_ref, :string)
    field(:dedupe_key, :string)
    field(:payload, :map, default: %{})
    field(:observed_at, :utc_datetime_usec)

    belongs_to(:organization, Organization)
    belongs_to(:run, InvestigationRun)

    timestamps(updated_at: false)
  end

  def changeset(evidence, attrs) do
    evidence
    |> cast(attrs, [
      :organization_id,
      :run_id,
      :kind,
      :source,
      :source_ref,
      :dedupe_key,
      :payload,
      :observed_at
    ])
    |> validate_required([
      :organization_id,
      :run_id,
      :kind,
      :source,
      :source_ref,
      :dedupe_key,
      :observed_at
    ])
    |> validate_length(:dedupe_key, min: 1, max: 255)
    |> unique_constraint([:organization_id, :run_id, :dedupe_key],
      name: :ai_investigation_evidence_org_run_dedupe_idx
    )
  end
end
