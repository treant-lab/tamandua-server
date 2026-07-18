defmodule TamanduaServer.AISecurity.AgenticInvestigationSnapshot do
  @moduledoc """
  Durable tenant-scoped snapshot for the in-memory AgenticAnalyst state.

  The JSON payload is versioned and contains data only. It never stores an
  executable term or an encoded Elixir struct.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Alerts.Alert

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "ai_agentic_investigation_snapshots" do
    field(:investigation_id, :string)
    field(:state, :string)
    field(:terminal, :boolean, default: false)
    field(:snapshot_version, :integer, default: 1)
    field(:snapshot, :map)
    field(:snapshot_sha256, :string)

    belongs_to(:organization, Organization)
    belongs_to(:alert, Alert)

    timestamps()
  end

  def changeset(snapshot, attrs) do
    snapshot
    |> cast(attrs, [
      :organization_id,
      :investigation_id,
      :alert_id,
      :state,
      :terminal,
      :snapshot_version,
      :snapshot,
      :snapshot_sha256
    ])
    |> validate_required([
      :organization_id,
      :investigation_id,
      :alert_id,
      :state,
      :terminal,
      :snapshot_version,
      :snapshot,
      :snapshot_sha256
    ])
    |> validate_number(:snapshot_version, equal_to: 1)
    |> validate_format(:snapshot_sha256, ~r/^[a-f0-9]{64}$/)
    |> unique_constraint([:organization_id, :investigation_id],
      name: :ai_agentic_investigation_snapshots_org_investigation_idx
    )
  end
end
