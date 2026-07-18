defmodule TamanduaServer.Agents.AgentUninstallIntent do
  @moduledoc "Authoritative audit record for a one-time agent uninstall authorization."

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @type t :: %__MODULE__{}

  schema "agent_uninstall_intents" do
    belongs_to(:organization, TamanduaServer.Accounts.Organization)
    belongs_to(:agent, TamanduaServer.Agents.Agent)
    belongs_to(:issued_by_user, TamanduaServer.Accounts.User)
    field(:action, :string, default: "agent_uninstall")
    field(:reason, :string)
    field(:idempotency_key_sha256, :binary)
    field(:nonce_sha256, :binary)
    field(:verifier_version, :string)
    field(:platform, :string)
    field(:consumer, :string)
    field(:token_generation, :integer)
    field(:state, :string, default: "pending")
    field(:issued_at, :utc_datetime_usec)
    field(:expires_at, :utc_datetime_usec)
    field(:consumed_at, :utc_datetime_usec)
    field(:superseded_at, :utc_datetime_usec)
    timestamps(type: :utc_datetime_usec)
  end

  @required ~w(organization_id agent_id issued_by_user_id action reason state issued_at expires_at)a

  def issue_changeset(intent, attrs) do
    intent
    |> cast(attrs, @required ++ [:idempotency_key_sha256])
    |> validate_required(@required)
    |> validate_inclusion(:action, ["agent_uninstall"])
    |> validate_inclusion(:reason, ~w(operator_requested device_retirement incident_response agent_replacement))
    |> validate_inclusion(:state, ["pending"])
    |> validate_change(:idempotency_key_sha256, fn :idempotency_key_sha256, digest ->
      if byte_size(digest) == 32, do: [], else: [idempotency_key_sha256: "must be 32 bytes"]
    end)
    |> unique_constraint([:organization_id, :agent_id, :action],
      name: :agent_uninstall_intents_one_pending_uidx
    )
    |> unique_constraint([:organization_id, :agent_id, :action, :idempotency_key_sha256],
      name: :agent_uninstall_intents_idempotency_uidx
    )
    |> check_constraint(:expires_at, name: :agent_uninstall_intents_ttl_check)
    |> check_constraint(:state, name: :agent_uninstall_intents_state_check)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:agent_id, name: :agent_uninstall_intents_agent_tenant_fkey)
    |> foreign_key_constraint(:issued_by_user_id,
      name: :agent_uninstall_intents_issuer_tenant_fkey
    )
  end
end
