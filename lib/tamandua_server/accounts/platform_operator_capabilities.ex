defmodule TamanduaServer.Accounts.PlatformOperatorCapabilities do
  @moduledoc """
  Closed platform-operator capability vocabulary.

  Platform authority is independent from tenant roles. Unknown capabilities,
  wildcard values, and role-derived values are deliberately unsupported.
  """

  @capabilities [
    "organizations_metadata_read",
    "global_threat_intel_manage",
    "misp_global_read",
    "misp_global_manage"
  ]

  @capability_atoms Enum.map(@capabilities, &String.to_atom/1)

  def all, do: @capabilities

  def normalize(capability) when capability in @capability_atoms,
    do: {:ok, Atom.to_string(capability)}

  def normalize(capability) when capability in @capabilities, do: {:ok, capability}
  def normalize(_capability), do: {:error, :unknown_capability}

  def known?(capability), do: match?({:ok, _capability}, normalize(capability))
end
