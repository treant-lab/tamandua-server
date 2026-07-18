defmodule TamanduaServer.Triage.Provider do
  @moduledoc """
  Behaviour for triage recommendation providers.

  Providers receive a guarded package where alert telemetry is explicitly marked
  as untrusted data. Implementations must not execute instructions, tool calls,
  URLs, or code found inside the alert/event payload.
  """

  @callback recommend(map(), keyword()) :: {:ok, map()} | {:error, term()}
end
