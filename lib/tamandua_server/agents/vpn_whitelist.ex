defmodule TamanduaServer.Agents.VpnWhitelist do
  @moduledoc """
  Whitelist of trusted VPN providers to avoid false positives in geofencing.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "vpn_whitelist" do
    field :name, :string
    field :vpn_provider, :string
    field :ip_ranges, {:array, :string}, default: []
    field :asn_numbers, {:array, :integer}, default: []
    field :domains, {:array, :string}, default: []
    field :trust_level, :string, default: "trusted"
    field :notes, :string
    field :is_active, :boolean, default: true

    belongs_to :organization, Organization

    timestamps()
  end

  @doc false
  def changeset(whitelist, attrs) do
    whitelist
    |> cast(attrs, [
      :organization_id,
      :name,
      :vpn_provider,
      :ip_ranges,
      :asn_numbers,
      :domains,
      :trust_level,
      :notes,
      :is_active
    ])
    |> validate_required([:organization_id, :name, :trust_level])
    |> validate_inclusion(:trust_level, ~w(trusted monitored blocked))
    |> validate_ip_ranges()
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_ip_ranges(changeset) do
    case get_change(changeset, :ip_ranges) do
      nil ->
        changeset

      ip_ranges ->
        if Enum.all?(ip_ranges, &valid_cidr?/1) do
          changeset
        else
          add_error(changeset, :ip_ranges, "must be valid CIDR notation")
        end
    end
  end

  defp valid_cidr?(cidr) when is_binary(cidr) do
    case String.split(cidr, "/") do
      [ip, prefix] ->
        valid_ip?(ip) && valid_prefix?(prefix)

      [ip] ->
        valid_ip?(ip)

      _ ->
        false
    end
  end

  defp valid_ip?(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, _} -> true
      _ -> false
    end
  end

  defp valid_prefix?(prefix) do
    case Integer.parse(prefix) do
      {num, ""} when num >= 0 and num <= 128 -> true
      _ -> false
    end
  end
end
