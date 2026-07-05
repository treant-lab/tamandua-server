defmodule TamanduaServer.CredentialsEnforcementTest do
  @moduledoc """
  Tests for the production credential hard-fail (Workstream A1).

  `TamanduaServer.Credentials.enforce_production_credentials!/1` must raise
  when credential validation reported errors in a production environment,
  unless the operator explicitly opted into degraded boot via the
  `TAMANDUA_ALLOW_DEGRADED_CREDENTIALS=true` environment variable or the
  `:allow_degraded_credentials` application config (lab/dev profiles only).
  """

  use ExUnit.Case, async: false

  alias TamanduaServer.Credentials

  @env_var "TAMANDUA_ALLOW_DEGRADED_CREDENTIALS"
  @errors [
    {:error, "SECRET_KEY_BASE appears to be a default/placeholder value"},
    {:error, "GUARDIAN_SECRET is missing"}
  ]

  setup do
    original_env = System.get_env(@env_var)
    original_cfg = Application.get_env(:tamandua_server, :allow_degraded_credentials)

    System.delete_env(@env_var)
    Application.delete_env(:tamandua_server, :allow_degraded_credentials)

    on_exit(fn ->
      if original_env do
        System.put_env(@env_var, original_env)
      else
        System.delete_env(@env_var)
      end

      if is_nil(original_cfg) do
        Application.delete_env(:tamandua_server, :allow_degraded_credentials)
      else
        Application.put_env(:tamandua_server, :allow_degraded_credentials, original_cfg)
      end
    end)

    :ok
  end

  test "raises on credential errors when no escape hatch is set" do
    assert_raise RuntimeError, ~r/Credential validation failed in production: 2 error/, fn ->
      Credentials.enforce_production_credentials!(@errors)
    end
  end

  test "boots degraded when the environment variable escape hatch is set" do
    System.put_env(@env_var, "true")

    assert :ok = Credentials.enforce_production_credentials!(@errors)
  end

  test "boots degraded when the application config escape hatch is set" do
    Application.put_env(:tamandua_server, :allow_degraded_credentials, true)

    assert :ok = Credentials.enforce_production_credentials!(@errors)
  end

  test "non-'true' environment variable values do NOT enable the escape hatch" do
    for value <- ["1", "yes", "TRUE", "false", ""] do
      System.put_env(@env_var, value)

      assert_raise RuntimeError, fn ->
        Credentials.enforce_production_credentials!(@errors)
      end
    end
  end
end
