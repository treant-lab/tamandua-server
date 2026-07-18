defmodule TamanduaServer.Agents.AgentUninstallBreakglassIssuance do
  @moduledoc "Authoritative append-only record of an offline uninstall authority issuance."

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @type t :: %__MODULE__{}

  schema "agent_uninstall_breakglass_issuances" do
    field(:intent_id, Ecto.UUID)
    belongs_to(:organization, TamanduaServer.Accounts.Organization)
    belongs_to(:agent, TamanduaServer.Agents.Agent)
    belongs_to(:issued_by_user, TamanduaServer.Accounts.User)
    field(:platform, :string)
    field(:consumer, :string)
    field(:reason, :string)
    field(:key_id, :string)
    field(:issued_at, :utc_datetime_usec)
    field(:not_before, :utc_datetime_usec)
    field(:expires_at, :utc_datetime_usec)
    field(:nonce_sha256, :binary)
    field(:payload_sha256, :binary)
    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  @required ~w(intent_id organization_id agent_id issued_by_user_id platform consumer reason key_id issued_at not_before expires_at nonce_sha256 payload_sha256)a

  def issuance_changeset(issuance, attrs) do
    issuance
    |> cast(attrs, @required)
    |> validate_required(@required)
    |> validate_inclusion(:platform, ~w(windows linux macos))
    |> validate_inclusion(:consumer, ~w(native_cli windows_msi))
    |> validate_format(:key_id, ~r/^[a-z0-9][a-z0-9._-]{0,63}$/)
    |> validate_byte_length(:reason, 8, 512)
    |> validate_reason_controls()
    |> validate_consumer_platform()
    |> validate_digest(:nonce_sha256)
    |> validate_digest(:payload_sha256)
    |> validate_time_contract()
    |> unique_constraint([:organization_id, :intent_id],
      name: :agent_uninstall_breakglass_issuances_org_intent_uidx
    )
    |> unique_constraint([:organization_id, :nonce_sha256],
      name: :agent_uninstall_breakglass_issuances_org_nonce_uidx
    )
    |> unique_constraint([:organization_id, :payload_sha256],
      name: :agent_uninstall_breakglass_issuances_org_payload_uidx
    )
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:agent_id,
      name: :agent_uninstall_breakglass_issuances_agent_tenant_fkey
    )
    |> foreign_key_constraint(:issued_by_user_id,
      name: :agent_uninstall_breakglass_issuances_issuer_tenant_fkey
    )
    |> check_constraint(:consumer,
      name: :agent_uninstall_breakglass_issuances_consumer_platform_check
    )
    |> check_constraint(:reason, name: :agent_uninstall_breakglass_issuances_reason_check)
    |> check_constraint(:key_id, name: :agent_uninstall_breakglass_issuances_key_id_check)
    |> check_constraint(:expires_at, name: :agent_uninstall_breakglass_issuances_time_check)
    |> check_constraint(:nonce_sha256,
      name: :agent_uninstall_breakglass_issuances_digest_check
    )
  end

  defp validate_byte_length(changeset, field, minimum, maximum) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value) and byte_size(value) in minimum..maximum,
        do: [],
        else: [{field, "must be between #{minimum} and #{maximum} UTF-8 bytes"}]
    end)
  end

  defp validate_reason_controls(changeset) do
    validate_change(changeset, :reason, fn :reason, value ->
      valid? =
        is_binary(value) and String.valid?(value) and value == String.trim(value) and
          not Regex.match?(~r/[\x{0000}-\x{001F}\x{007F}-\x{009F}]/u, value)

      if valid?, do: [], else: [reason: "must be trimmed UTF-8 without control characters"]
    end)
  end

  defp validate_consumer_platform(changeset) do
    case {get_field(changeset, :consumer), get_field(changeset, :platform)} do
      {"windows_msi", platform} when platform != "windows" ->
        add_error(changeset, :consumer, "windows_msi requires windows")

      _ ->
        changeset
    end
  end

  defp validate_digest(changeset, field) do
    validate_change(changeset, field, fn ^field, digest ->
      if is_binary(digest) and byte_size(digest) == 32,
        do: [],
        else: [{field, "must be a 32-byte SHA-256 digest"}]
    end)
  end

  defp validate_time_contract(changeset) do
    issued_at = get_field(changeset, :issued_at)
    not_before = get_field(changeset, :not_before)
    expires_at = get_field(changeset, :expires_at)

    valid? =
      match?(%DateTime{}, issued_at) and match?(%DateTime{}, not_before) and
        match?(%DateTime{}, expires_at) and
        whole_second?(issued_at) and whole_second?(not_before) and whole_second?(expires_at) and
        DateTime.compare(issued_at, not_before) in [:lt, :eq] and
        DateTime.compare(not_before, expires_at) == :lt and
        DateTime.diff(expires_at, issued_at, :second) in 1..86_400

    if valid?, do: changeset, else: add_error(changeset, :expires_at, "invalid issuance window")
  end

  defp whole_second?(%DateTime{microsecond: {0, _precision}}), do: true
  defp whole_second?(_timestamp), do: false
end
