# Test helper configuration
# This file is required by ExUnit and is loaded before any test files.

ExUnit.start(exclude: [:pending])

# Configure ExCoveralls if available
if Code.ensure_loaded?(ExCoveralls) do
  ExCoveralls.start()
end

# Configure Ecto Sandbox for test isolation
Ecto.Adapters.SQL.Sandbox.mode(TamanduaServer.Repo, :manual)

# Import shared test fixtures
alias TamanduaServer.Factory

# Disable external service calls in tests
Application.put_env(:tamandua_server, :env, :test)
Application.put_env(:tamandua_server, :ml_service_url, nil)

# Configure Guardian for testing
Application.put_env(:tamandua_server, TamanduaServer.Guardian, secret_key: "test-secret-key-for-jwt-signing")

# Start required applications for tests
{:ok, _} = Application.ensure_all_started(:faker)
