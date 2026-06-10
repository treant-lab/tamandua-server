defmodule TamanduaServer.Auth.MFA.Policy do
  @moduledoc """
  Schema for organization-level MFA policies.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Bitwise

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @enforcement_modes ~w(optional required_all required_admins required_roles)
  @mfa_methods ~w(totp sms email webauthn)

  schema "mfa_policies" do
    field :enforcement_mode, :string, default: "optional"
    field :required_roles, {:array, :string}, default: []
    field :grace_period_days, :integer, default: 7
    field :allowed_methods, {:array, :string}, default: ["totp", "sms", "email", "webauthn"]
    field :require_webauthn_for_admins, :boolean, default: false
    field :trusted_ip_ranges, {:array, :string}, default: []
    field :step_up_actions, {:array, :string}, default: []

    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(policy, attrs) do
    policy
    |> cast(attrs, [
      :organization_id,
      :enforcement_mode,
      :required_roles,
      :grace_period_days,
      :allowed_methods,
      :require_webauthn_for_admins,
      :trusted_ip_ranges,
      :step_up_actions
    ])
    |> validate_required([:organization_id, :enforcement_mode])
    |> validate_inclusion(:enforcement_mode, @enforcement_modes)
    |> validate_mfa_methods()
    |> validate_number(:grace_period_days, greater_than_or_equal_to: 0, less_than_or_equal_to: 365)
    |> unique_constraint(:organization_id)
  end

  defp validate_mfa_methods(changeset) do
    allowed_methods = get_field(changeset, :allowed_methods)

    if allowed_methods && !Enum.empty?(allowed_methods) do
      invalid_methods = allowed_methods -- @mfa_methods

      if Enum.empty?(invalid_methods) do
        changeset
      else
        add_error(changeset, :allowed_methods, "contains invalid methods: #{inspect(invalid_methods)}")
      end
    else
      add_error(changeset, :allowed_methods, "must have at least one allowed method")
    end
  end

  @doc """
  Check if MFA is required for a user based on policy.
  """
  def mfa_required?(%__MODULE__{enforcement_mode: "optional"}, _user), do: false
  def mfa_required?(%__MODULE__{enforcement_mode: "required_all"}, _user), do: true

  def mfa_required?(%__MODULE__{enforcement_mode: "required_admins"}, user) do
    user.role in ["admin", "compliance_officer"]
  end

  def mfa_required?(%__MODULE__{enforcement_mode: "required_roles", required_roles: roles}, user) do
    user.role in roles
  end

  @doc """
  Check if IP address is in trusted range.
  """
  def ip_trusted?(%__MODULE__{trusted_ip_ranges: []}, _ip), do: false

  def ip_trusted?(%__MODULE__{trusted_ip_ranges: ranges}, ip) when is_binary(ip) do
    Enum.any?(ranges, fn cidr ->
      case parse_cidr(cidr) do
        {:ok, network, netmask} ->
          ip_in_cidr?(ip, network, netmask)

        :error ->
          false
      end
    end)
  end

  def ip_trusted?(_, _), do: false

  # Simple CIDR parsing (supports IPv4 only for now)
  defp parse_cidr(cidr) do
    case String.split(cidr, "/") do
      [ip_str, prefix_len_str] ->
        with {:ok, ip_tuple} <- parse_ip(ip_str),
             {prefix_len, ""} <- Integer.parse(prefix_len_str),
             true <- prefix_len >= 0 and prefix_len <= 32 do
          netmask = calculate_netmask(prefix_len)
          network = ip_tuple |> tuple_to_int() |> Bitwise.&&&(netmask)
          {:ok, network, netmask}
        else
          _ -> :error
        end

      _ ->
        :error
    end
  end

  defp parse_ip(ip_str) do
    case :inet.parse_address(String.to_charlist(ip_str)) do
      {:ok, {a, b, c, d}} -> {:ok, {a, b, c, d}}
      _ -> :error
    end
  end

  defp tuple_to_int({a, b, c, d}) do
    (a <<< 24) ||| (b <<< 16) ||| (c <<< 8) ||| d
  end

  defp calculate_netmask(prefix_len) do
    if prefix_len == 0 do
      0
    else
      Bitwise.bsl(0xFFFFFFFF, 32 - prefix_len) |> Bitwise.&&&(0xFFFFFFFF)
    end
  end

  defp ip_in_cidr?(ip_str, network, netmask) do
    case parse_ip(ip_str) do
      {:ok, ip_tuple} ->
        ip_int = tuple_to_int(ip_tuple)
        (ip_int |> Bitwise.&&&(netmask)) == network

      :error ->
        false
    end
  end
end
