defmodule TamanduaServer.Bounties.BountyClaim do
  @moduledoc """
  Represents a bounty payment claim for a validated submission.

  Tracks the lifecycle of bounty payments through Solana, storing transaction IDs
  and handling failure cases.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Bounties.Submission
  alias TamanduaServer.Alerts.Alert

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "bounty_claims" do
    field :amount_lamports, :integer
    field :status, :string, default: "pending"
    field :tx_id, :string
    field :failure_reason, :string
    field :paid_at, :utc_datetime_usec

    # Admin override audit fields
    field :admin_override, :boolean, default: false
    field :admin_override_reason, :string
    field :admin_override_by_id, :binary_id

    belongs_to :submission, Submission
    belongs_to :alert, Alert

    timestamps()
  end

  @doc false
  def changeset(bounty_claim, attrs) do
    bounty_claim
    |> cast(attrs, [
      :submission_id,
      :alert_id,
      :amount_lamports,
      :status,
      :tx_id,
      :failure_reason,
      :paid_at,
      :admin_override,
      :admin_override_reason,
      :admin_override_by_id
    ])
    |> validate_required([:submission_id, :amount_lamports])
    |> validate_number(:amount_lamports, greater_than: 0)
    |> validate_inclusion(:status, ~w(pending processing paid failed))
    |> foreign_key_constraint(:submission_id)
    |> foreign_key_constraint(:alert_id)
    |> unique_constraint(:submission_id, name: :bounty_claims_submission_id_index)
  end
end
