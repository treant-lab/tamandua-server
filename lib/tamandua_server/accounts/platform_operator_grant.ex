defmodule TamanduaServer.Accounts.PlatformOperatorGrant do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{PlatformOperatorCapabilities, User}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "platform_operator_grants" do
    field(:capabilities, {:array, :string}, default: [])
    field(:reason, :string)
    field(:expires_at, :utc_datetime_usec)
    field(:revoked_at, :utc_datetime_usec)
    field(:revoke_reason, :string)

    belongs_to(:user, User)
    belongs_to(:granted_by_user, User)
    belongs_to(:revoked_by_user, User)

    timestamps(type: :utc_datetime_usec)
  end

  def create_changeset(grant, attrs, now \\ DateTime.utc_now()) do
    grant
    |> cast(attrs, [:user_id, :granted_by_user_id, :capabilities, :reason, :expires_at])
    |> validate_required([:user_id, :granted_by_user_id, :capabilities, :reason, :expires_at])
    |> validate_not_self_granted()
    |> validate_length(:reason, min: 8, max: 1_000)
    |> validate_capabilities()
    |> validate_future(:expires_at, now)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:granted_by_user_id)
  end

  def revoke_changeset(grant, attrs, now \\ DateTime.utc_now()) do
    grant
    |> cast(attrs, [:revoked_by_user_id, :revoke_reason])
    |> validate_required([:revoked_by_user_id, :revoke_reason])
    |> validate_length(:revoke_reason, min: 8, max: 1_000)
    |> put_change(:revoked_at, now)
    |> foreign_key_constraint(:revoked_by_user_id)
  end

  defp validate_capabilities(changeset) do
    case get_field(changeset, :capabilities) do
      capabilities when is_list(capabilities) and capabilities != [] ->
        normalized = Enum.uniq(capabilities)

        if length(normalized) == length(capabilities) and
             Enum.all?(normalized, &PlatformOperatorCapabilities.known?/1) do
          put_change(changeset, :capabilities, normalized)
        else
          add_error(changeset, :capabilities, "must be unique values from the platform allowlist")
        end

      _ ->
        add_error(changeset, :capabilities, "must contain at least one platform capability")
    end
  end

  defp validate_not_self_granted(changeset) do
    if get_field(changeset, :user_id) == get_field(changeset, :granted_by_user_id),
      do: add_error(changeset, :granted_by_user_id, "must be a distinct approver"),
      else: changeset
  end

  defp validate_future(changeset, field, now) do
    validate_change(changeset, field, fn ^field, value ->
      if DateTime.compare(value, now) == :gt, do: [], else: [{field, "must be in the future"}]
    end)
  end
end
