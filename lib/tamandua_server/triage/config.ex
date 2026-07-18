defmodule TamanduaServer.Triage.Config do
  @moduledoc """
  Runtime configuration for the triage assistant.

  The default provider is local and deterministic. BYO LLM providers can be
  supplied per call or through application config, but no networked provider is
  selected by default.
  """

  @default_provider TamanduaServer.Triage.LocalProvider

  def default_provider, do: @default_provider

  def provider(opts \\ []) do
    Keyword.get(opts, :provider) ||
      Application.get_env(:tamandua_server, :triage_provider, @default_provider)
  end

  def provider_opts(opts \\ []) do
    opts
    |> Keyword.get(:provider_opts, [])
    |> Keyword.put_new(:network_allowed, Keyword.get(opts, :network_allowed, false))
  end
end
