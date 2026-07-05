defmodule TamanduaServer.Agents.TokenManagerConfigTest do
  @moduledoc """
  Database-free tests for TokenManager token-lifecycle configuration:
  the refresh grace period (tightened from 30 days to 7 days) and the
  refresh-count anomaly warning threshold.
  """

  # async: false because these tests mutate application environment.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias TamanduaServer.Agents.TokenManager
  alias TamanduaServer.Agents.TokenManager.AgentToken

  setup do
    grace = Application.fetch_env(:tamandua_server, :agent_token_refresh_grace_seconds)
    threshold = Application.fetch_env(:tamandua_server, :agent_token_refresh_count_warning_threshold)

    on_exit(fn ->
      restore_env(:agent_token_refresh_grace_seconds, grace)
      restore_env(:agent_token_refresh_count_warning_threshold, threshold)
    end)

    :ok
  end

  defp restore_env(key, {:ok, value}), do: Application.put_env(:tamandua_server, key, value)
  defp restore_env(key, :error), do: Application.delete_env(:tamandua_server, key)

  describe "refresh_grace_seconds/0" do
    test "defaults to 7 days (not the previous 30 days)" do
      Application.delete_env(:tamandua_server, :agent_token_refresh_grace_seconds)

      assert TokenManager.refresh_grace_seconds() == 7 * 24 * 3600
    end

    test "is configurable via application env" do
      Application.put_env(:tamandua_server, :agent_token_refresh_grace_seconds, 3600)

      assert TokenManager.refresh_grace_seconds() == 3600
    end
  end

  describe "refresh_count_warning_threshold/0" do
    test "defaults to 100" do
      Application.delete_env(
        :tamandua_server,
        :agent_token_refresh_count_warning_threshold
      )

      assert TokenManager.refresh_count_warning_threshold() == 100
    end

    test "is configurable via application env" do
      Application.put_env(
        :tamandua_server,
        :agent_token_refresh_count_warning_threshold,
        5
      )

      assert TokenManager.refresh_count_warning_threshold() == 5
    end
  end

  describe "maybe_warn_refresh_count_anomaly/3" do
    test "logs a warning when refresh_count exceeds the threshold" do
      Application.put_env(
        :tamandua_server,
        :agent_token_refresh_count_warning_threshold,
        10
      )

      agent_id = Ecto.UUID.generate()
      record = %AgentToken{refresh_count: 11}

      log =
        capture_log(fn ->
          assert :ok = TokenManager.maybe_warn_refresh_count_anomaly(record, agent_id, 1)
        end)

      assert log =~ "Anomalous token refresh count"
      assert log =~ agent_id
    end

    test "stays silent at or below the threshold" do
      Application.put_env(
        :tamandua_server,
        :agent_token_refresh_count_warning_threshold,
        10
      )

      agent_id = Ecto.UUID.generate()

      log =
        capture_log(fn ->
          assert :ok =
                   TokenManager.maybe_warn_refresh_count_anomaly(
                     %AgentToken{refresh_count: 10},
                     agent_id,
                     1
                   )

          assert :ok =
                   TokenManager.maybe_warn_refresh_count_anomaly(
                     %AgentToken{refresh_count: nil},
                     agent_id,
                     1
                   )
        end)

      refute log =~ "Anomalous token refresh count"
    end
  end
end
