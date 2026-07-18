defmodule TamanduaServer.LiveResponse.EvidenceSessionExport do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "evidence_session_exports" do
    field(:sha256, :string)
    field(:size, :integer)
    field(:content, :binary, redact: true)
    field(:expires_at, :utc_datetime_usec)
    field(:requested_by_id, :binary_id)
    belongs_to(:organization, TamanduaServer.Accounts.Organization)
    belongs_to(:evidence_session, TamanduaServer.LiveResponse.EvidenceSession)
    timestamps(type: :utc_datetime_usec)
  end

  def changeset(export, attrs) do
    export
    |> cast(attrs, [
      :organization_id,
      :evidence_session_id,
      :requested_by_id,
      :sha256,
      :size,
      :content,
      :expires_at
    ])
    |> validate_required([
      :organization_id,
      :evidence_session_id,
      :sha256,
      :size,
      :content,
      :expires_at
    ])
    |> validate_format(:sha256, ~r/\A[0-9a-f]{64}\z/)
    |> validate_number(:size, greater_than: 0, less_than_or_equal_to: 67_108_864)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:evidence_session_id)
  end
end
