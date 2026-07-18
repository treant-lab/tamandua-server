defmodule TamanduaServer.Mobile.MobileDeviceIdentityChallenge do
  @moduledoc """
  One-time, tenant-bound challenge for mobile device proof of possession.

  Only the SHA-256 digest of the random challenge is persisted. The cleartext
  value is returned once to the authenticated caller and must be presented when
  the proof is completed.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @platforms ~w(android ios)
  @purposes ~w(enroll rotate)
  @states ~w(pending consumed)

  schema "mobile_device_identity_challenges" do
    field(:installation_id, :string)
    field(:platform, :string)
    field(:purpose, :string)
    field(:key_scope_id, :string)
    field(:challenge_digest, :binary)
    field(:state, :string, default: "pending")
    field(:issued_at, :utc_datetime_usec)
    field(:expires_at, :utc_datetime_usec)
    field(:consumed_at, :utc_datetime_usec)

    belongs_to(:organization, Organization)

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @required_fields ~w(
    organization_id installation_id platform purpose key_scope_id
    challenge_digest state issued_at expires_at
  )a

  def changeset(challenge, attrs) do
    challenge
    |> cast(attrs, @required_fields ++ [:consumed_at])
    |> validate_required(@required_fields)
    |> validate_length(:installation_id, min: 1, max: 255)
    |> validate_format(:installation_id, ~r/\S/)
    |> validate_length(:key_scope_id, min: 16, max: 96)
    |> validate_binary_size(:challenge_digest, 32, 32)
    |> validate_inclusion(:platform, @platforms)
    |> validate_inclusion(:purpose, @purposes)
    |> validate_inclusion(:state, @states)
    |> validate_expiry_after_issue()
    |> unique_constraint([:organization_id, :challenge_digest])
    |> foreign_key_constraint(:organization_id)
  end

  def pending_for_organization(query \\ __MODULE__, organization_id, challenge_id) do
    from(challenge in query,
      where:
        challenge.organization_id == ^organization_id and challenge.id == ^challenge_id and
          challenge.state == "pending"
    )
  end

  defp validate_expiry_after_issue(changeset) do
    issued_at = get_field(changeset, :issued_at)
    expires_at = get_field(changeset, :expires_at)

    if issued_at && expires_at && DateTime.compare(expires_at, issued_at) != :gt do
      add_error(changeset, :expires_at, "must be after issued_at")
    else
      changeset
    end
  end

  defp validate_binary_size(changeset, field, minimum, maximum) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value) and byte_size(value) >= minimum and byte_size(value) <= maximum do
        []
      else
        [{field, "must be a binary of #{minimum}..#{maximum} bytes"}]
      end
    end)
  end
end
