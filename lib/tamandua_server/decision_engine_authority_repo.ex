defmodule TamanduaServer.DecisionEngineAuthorityRepo do
  @moduledoc "Default-off, read-only pool for DecisionEngine tenant discovery v1."

  use Ecto.Repo,
    otp_app: :tamandua_server,
    adapter: Ecto.Adapters.Postgres

  def enabled? do
    Application.get_env(:tamandua_server, :decision_engine_authority_repo_enabled, false) == true
  end
end
