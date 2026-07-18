defmodule TamanduaServer.Accounts.PlatformOperatorEvent do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{
    PlatformOperatorElevationProof,
    PlatformOperatorGrant,
    User
  }

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @event_types ~w(grant_requested grant_approved grant_created grant_revoked elevation_issued authorization_intent authorization_allowed authorization_denied operation_succeeded operation_failed)
  @outcomes ~w(pending success failed denied)
  @sensitive_fragments ~w(token secret proof session_binding password totp mfa_code)

  schema "platform_operator_events" do
    field(:event_type, :string)
    field(:capability, :string)
    field(:outcome, :string)
    field(:reason, :string)
    field(:operation_id, :string)
    field(:request_id, :string)
    field(:target, :string)
    field(:metadata, :map, default: %{})
    field(:occurred_at, :utc_datetime_usec)

    belongs_to(:actor_user, User)
    belongs_to(:subject_user, User)
    belongs_to(:grant, PlatformOperatorGrant)
    belongs_to(:elevation_proof, PlatformOperatorElevationProof)

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  def changeset(event, attrs) do
    event
    |> cast(attrs, [
      :event_type,
      :actor_user_id,
      :subject_user_id,
      :grant_id,
      :elevation_proof_id,
      :capability,
      :outcome,
      :reason,
      :operation_id,
      :request_id,
      :target,
      :metadata,
      :occurred_at
    ])
    |> validate_required([:event_type, :outcome, :reason, :occurred_at])
    |> validate_inclusion(:event_type, @event_types)
    |> validate_inclusion(:outcome, @outcomes)
    |> validate_length(:reason, min: 1, max: 1_000)
    |> validate_length(:operation_id, min: 8, max: 128)
    |> validate_length(:request_id, max: 128)
    |> validate_length(:target, max: 256)
    |> validate_safe_text(:reason)
    |> validate_safe_text(:operation_id)
    |> validate_safe_text(:request_id)
    |> validate_safe_text(:target)
    |> validate_metadata()
    |> foreign_key_constraint(:actor_user_id)
    |> foreign_key_constraint(:subject_user_id)
    |> foreign_key_constraint(:grant_id)
    |> foreign_key_constraint(:elevation_proof_id)
  end

  defp validate_metadata(changeset) do
    metadata = get_field(changeset, :metadata) || %{}

    if contains_sensitive_key?(metadata) do
      add_error(changeset, :metadata, "must not contain authentication secrets or tokens")
    else
      changeset
    end
  end

  defp contains_sensitive_key?(value) when is_map(value) do
    Enum.any?(value, fn {key, nested} ->
      normalized_key = key |> to_string() |> String.downcase()

      Enum.any?(@sensitive_fragments, &String.contains?(normalized_key, &1)) or
        contains_sensitive_key?(nested)
    end)
  end

  defp contains_sensitive_key?(value) when is_list(value),
    do: Enum.any?(value, &contains_sensitive_key?/1)

  defp contains_sensitive_key?(_value), do: false

  defp validate_safe_text(changeset, field) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value) and String.match?(value, ~r/[\x00-\x1F\x7F]/u),
        do: [{field, "contains forbidden control characters"}],
        else: []
    end)
  end
end
