defmodule TamanduaServer.LiveResponse.EvidenceSessionDiff do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "evidence_session_diffs" do
    field(:metrics, :map)
    field(:expires_at, :utc_datetime_usec)
    belongs_to(:organization, TamanduaServer.Accounts.Organization)
    belongs_to(:evidence_session, TamanduaServer.LiveResponse.EvidenceSession)
    belongs_to(:left_artifact, TamanduaServer.LiveResponse.ScreenCaptureArtifact)
    belongs_to(:right_artifact, TamanduaServer.LiveResponse.ScreenCaptureArtifact)
    timestamps(type: :utc_datetime_usec)
  end

  def changeset(diff, attrs) do
    diff
    |> cast(attrs, [
      :organization_id,
      :evidence_session_id,
      :left_artifact_id,
      :right_artifact_id,
      :metrics,
      :expires_at
    ])
    |> validate_required([
      :organization_id,
      :evidence_session_id,
      :left_artifact_id,
      :right_artifact_id,
      :metrics,
      :expires_at
    ])
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:evidence_session_id)
    |> foreign_key_constraint(:left_artifact_id)
    |> foreign_key_constraint(:right_artifact_id)
  end
end
