defmodule TamanduaServer.Mobile.MobileMutationAuthorization do
  @moduledoc """
  Durable, one-shot authorization for a hardware-bound mobile mutation.

  Cleartext challenges and nonces are intentionally never persisted. The row
  keeps their domain-separated SHA-256 digests and the exact active identity
  key snapshot against which a later proof must be verified.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Mobile.MobileDeviceIdentityKey

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "mobile_mutation_authorizations" do
    field(:actor_id, :string)
    field(:installation_id, :string)
    field(:platform, :string)
    field(:device_key_id, :string)
    field(:key_scope_id, :string)
    field(:request_id, :string)
    field(:challenge_digest, :binary)
    field(:nonce_digest, :binary)
    field(:operation, :string)
    field(:http_method, :string)
    field(:route_id, :string)
    field(:resource_id, :string)
    field(:body_sha256, :binary)
    field(:algorithm, :string)
    field(:issued_at, :utc_datetime_usec)
    field(:expires_at, :utc_datetime_usec)
    field(:consumed_at, :utc_datetime_usec)
    field(:result_resource_id, :string)
    field(:result_outcome, :string)

    belongs_to(:organization, Organization)
    belongs_to(:identity_key, MobileDeviceIdentityKey)

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @required ~w(
    organization_id identity_key_id actor_id installation_id platform
    device_key_id key_scope_id request_id challenge_digest nonce_digest
    operation http_method route_id resource_id body_sha256 algorithm
    issued_at expires_at
  )a

  def changeset(authorization, attrs) do
    authorization
    |> cast(attrs, @required ++ [:consumed_at, :result_resource_id, :result_outcome])
    |> validate_required(@required)
    |> validate_length(:actor_id, min: 1, max: 255)
    |> validate_length(:installation_id, min: 1, max: 255)
    |> validate_length(:resource_id, min: 1, max: 255)
    |> validate_length(:request_id, min: 16, max: 96)
    |> validate_inclusion(:platform, ~w(android ios))
    |> validate_inclusion(:operation, ["mobile_device_v2_upsert"])
    |> validate_inclusion(:http_method, ["POST"])
    |> validate_inclusion(:route_id, ["mobile_v2_devices_upsert"])
    |> validate_inclusion(:algorithm, ["ecdsa-p256-sha256"])
    |> validate_inclusion(:result_outcome, ~w(created updated))
    |> validate_binary_size(:challenge_digest, 32)
    |> validate_binary_size(:nonce_digest, 32)
    |> validate_binary_size(:body_sha256, 32)
    |> validate_expiry()
    |> validate_result_consistency()
    |> unique_constraint([:organization_id, :request_id])
    |> unique_constraint([:organization_id, :challenge_digest])
    |> unique_constraint([:organization_id, :nonce_digest])
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:identity_key_id)
  end

  defp validate_binary_size(changeset, field, size) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value) and byte_size(value) == size,
        do: [],
        else: [{field, "must be exactly #{size} bytes"}]
    end)
  end

  defp validate_expiry(changeset) do
    issued_at = get_field(changeset, :issued_at)
    expires_at = get_field(changeset, :expires_at)

    cond do
      is_nil(issued_at) or is_nil(expires_at) ->
        changeset

      DateTime.compare(expires_at, issued_at) != :gt ->
        add_error(changeset, :expires_at, "must be after issued_at")

      DateTime.diff(expires_at, issued_at, :second) > 300 ->
        add_error(changeset, :expires_at, "must be at most 300 seconds after issued_at")

      true ->
        changeset
    end
  end

  defp validate_result_consistency(changeset) do
    consumed_at = get_field(changeset, :consumed_at)
    result_resource_id = get_field(changeset, :result_resource_id)
    result_outcome = get_field(changeset, :result_outcome)

    cond do
      is_nil(result_resource_id) and is_nil(result_outcome) ->
        changeset

      is_binary(result_resource_id) and result_resource_id != "" and
        result_outcome in ~w(created updated) and not is_nil(consumed_at) ->
        changeset

      true ->
        add_error(changeset, :result_outcome, "requires a consumed authorization and resource")
    end
  end
end
