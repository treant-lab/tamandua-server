defmodule TamanduaServer.Triage do
  @moduledoc """
  MVP backend for SOC alert triage.

  `analyze/2` accepts an existing alert/event map or struct, builds a safe
  context package, and returns a recommendation. By default this is fully local
  and deterministic; BYO LLM providers can be injected explicitly.
  """

  alias TamanduaServer.Triage.{Config, ContextBuilder, Guardrails}

  @doc """
  Analyze an alert/event without network calls by default.

  Options:
  - `:provider` - module implementing `TamanduaServer.Triage.Provider`
  - `:provider_opts` - options passed to the provider
  - `:network_allowed` - guardrail flag for future providers, default `false`
  """
  def analyze(alert, opts \\ []) do
    with {:ok, context} <- ContextBuilder.build(alert, opts),
         package <- Guardrails.package(context, Config.provider_opts(opts)),
         provider <- Config.provider(opts),
         :ok <- validate_provider(provider),
         {:ok, recommendation} <- provider.recommend(package, Config.provider_opts(opts)) do
      {:ok,
       %{
         context: context,
         guarded_package: package,
         recommendation: recommendation
       }}
    end
  end

  defp validate_provider(provider) when is_atom(provider) do
    if Code.ensure_loaded?(provider) and function_exported?(provider, :recommend, 2) do
      :ok
    else
      {:error, {:invalid_provider, provider}}
    end
  end

  defp validate_provider(provider), do: {:error, {:invalid_provider, provider}}
end
