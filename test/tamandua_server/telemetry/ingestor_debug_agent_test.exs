defmodule TamanduaServer.Telemetry.IngestorDebugAgentTest do
  @moduledoc """
  Tests that the ingestor's debug agent id resolves exclusively from
  env/config with no baked-in default (previously a hardcoded lab UUID).

  async: false because tests mutate the process environment and
  application config.
  """

  use ExUnit.Case, async: false

  alias TamanduaServer.Telemetry.Ingestor

  setup do
    original_env = System.get_env("TAMANDUA_DEBUG_AGENT_ID")
    original_cfg = Application.get_env(:tamandua_server, :debug_agent_id)

    System.delete_env("TAMANDUA_DEBUG_AGENT_ID")
    Application.delete_env(:tamandua_server, :debug_agent_id)

    on_exit(fn ->
      if original_env do
        System.put_env("TAMANDUA_DEBUG_AGENT_ID", original_env)
      else
        System.delete_env("TAMANDUA_DEBUG_AGENT_ID")
      end

      if original_cfg do
        Application.put_env(:tamandua_server, :debug_agent_id, original_cfg)
      else
        Application.delete_env(:tamandua_server, :debug_agent_id)
      end
    end)

    :ok
  end

  test "defaults to nil when env and config are unset (no baked-in id)" do
    assert Ingestor.debug_agent_id() == nil
  end

  test "resolves from TAMANDUA_DEBUG_AGENT_ID env var" do
    System.put_env("TAMANDUA_DEBUG_AGENT_ID", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    assert Ingestor.debug_agent_id() == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  end

  test "falls back to :debug_agent_id application config" do
    Application.put_env(:tamandua_server, :debug_agent_id, "cfg-agent-id")
    assert Ingestor.debug_agent_id() == "cfg-agent-id"
  end

  test "env var takes precedence over application config" do
    System.put_env("TAMANDUA_DEBUG_AGENT_ID", "env-agent-id")
    Application.put_env(:tamandua_server, :debug_agent_id, "cfg-agent-id")
    assert Ingestor.debug_agent_id() == "env-agent-id"
  end

  test "treats empty env var as unset" do
    System.put_env("TAMANDUA_DEBUG_AGENT_ID", "")
    assert Ingestor.debug_agent_id() == nil
  end
end
