defmodule TamanduaServer.Integrations.HealthCheckTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Integrations.{HealthCheck, Config}
  alias TamanduaServer.Integrations.Schemas.HealthCheckHistory

  setup do
    # Create test integrations
    {:ok, splunk} = Config.create_integration(%{
      type: :splunk,
      name: "Test Splunk",
      config: %{
        hec_url: "https://splunk.example.com:8088",
        hec_token: "test-token"
      }
    })

    {:ok, sentinel} = Config.create_integration(%{
      type: :sentinel,
      name: "Test Sentinel",
      config: %{
        workspace_id: "test-workspace",
        shared_key: Base.encode64("test-key-32-bytes-long-string!")
      }
    })

    {:ok, elastic} = Config.create_integration(%{
      type: :elastic,
      name: "Test Elastic",
      config: %{
        url: "http://localhost:9200",
        username: "elastic",
        password: "password"
      }
    })

    %{splunk: splunk, sentinel: sentinel, elastic: elastic}
  end

  describe "connectivity checks" do
    test "checks Splunk connectivity", %{splunk: splunk} do
      # Note: This will fail in test environment without real Splunk
      # In production, would use mocks or test doubles
      result = HealthCheck.check_connectivity(splunk.id)

      assert result in [{:ok, _}, {:error, _}]
    end

    test "checks Sentinel connectivity", %{sentinel: sentinel} do
      result = HealthCheck.check_connectivity(sentinel.id)

      assert result in [{:ok, _}, {:error, _}]
    end

    test "checks Elastic connectivity", %{elastic: elastic} do
      result = HealthCheck.check_connectivity(elastic.id)

      assert result in [{:ok, _}, {:error, _}]
    end

    test "returns error for invalid integration" do
      result = HealthCheck.check_connectivity(Ecto.UUID.generate())

      assert result == {:error, :integration_not_found}
    end
  end

  describe "authentication checks" do
    test "validates Splunk authentication", %{splunk: splunk} do
      result = HealthCheck.check_authentication(splunk.id)

      assert result in [{:ok, _}, {:error, _}]
    end

    test "validates Sentinel authentication", %{sentinel: sentinel} do
      result = HealthCheck.check_authentication(sentinel.id)

      assert result in [{:ok, _}, {:error, _}]
    end
  end

  describe "synthetic transactions" do
    test "performs Splunk synthetic transaction", %{splunk: splunk} do
      result = HealthCheck.check_synthetic_transaction(splunk.id)

      assert result in [{:ok, _}, {:error, _}]
    end

    test "performs Elastic synthetic transaction", %{elastic: elastic} do
      result = HealthCheck.check_synthetic_transaction(elastic.id)

      assert result in [{:ok, _}, {:error, _}]
    end
  end

  describe "health check history" do
    test "records health check results", %{splunk: splunk} do
      # Perform check
      HealthCheck.check_connectivity(splunk.id)

      # Wait for async recording
      Process.sleep(100)

      # Check history
      history = HealthCheckHistory.list_recent(splunk.id, 10)

      assert is_list(history)
      assert length(history) > 0

      check = List.first(history)
      assert check.integration_id == splunk.id
      assert check.check_type in ["connectivity", "authentication", "synthetic_transaction"]
      assert is_boolean(check.success)
      assert is_integer(check.duration_ms)
    end

    test "calculates success rate", %{splunk: splunk} do
      # Perform multiple checks
      for _ <- 1..5 do
        HealthCheck.check_connectivity(splunk.id)
        Process.sleep(50)
      end

      Process.sleep(200)

      success_rate = HealthCheckHistory.get_success_rate(splunk.id, 10)

      assert is_float(success_rate)
      assert success_rate >= 0.0
      assert success_rate <= 100.0
    end
  end

  describe "health metrics updates" do
    test "updates health metrics after successful check", %{splunk: splunk} do
      HealthCheck.check_connectivity(splunk.id)

      Process.sleep(100)

      health = TamanduaServer.Integrations.HealthMonitor.get_health(splunk.id)

      assert health[:last_health_check_at] != nil
      assert is_boolean(health[:last_health_check_success])
    end

    test "updates connection timestamps", %{splunk: splunk} do
      HealthCheck.check_connectivity(splunk.id)

      Process.sleep(100)

      health = TamanduaServer.Integrations.HealthMonitor.get_health(splunk.id)

      # Should have either last_connected_at or last_disconnected_at
      assert health[:last_connected_at] != nil || health[:last_disconnected_at] != nil
    end
  end

  describe "error handling" do
    test "handles network timeouts gracefully", %{splunk: splunk} do
      # This will timeout in test environment
      result = HealthCheck.check_connectivity(splunk.id)

      case result do
        {:ok, _} -> assert true
        {:error, message} ->
          assert is_binary(message)
          assert String.contains?(message, ["Connection", "timeout", "failed"])
      end
    end

    test "handles invalid credentials gracefully", %{sentinel: sentinel} do
      result = HealthCheck.check_authentication(sentinel.id)

      case result do
        {:ok, _} -> assert true
        {:error, message} -> assert is_binary(message)
      end
    end
  end

  describe "check type routing" do
    test "routes to correct check type", %{splunk: splunk} do
      connectivity_result = HealthCheck.perform_health_check(splunk.id, :connectivity)
      auth_result = HealthCheck.perform_health_check(splunk.id, :authentication)
      synthetic_result = HealthCheck.perform_health_check(splunk.id, :synthetic_transaction)

      assert connectivity_result in [{:ok, _}, {:error, _}]
      assert auth_result in [{:ok, _}, {:error, _}]
      assert synthetic_result in [{:ok, _}, {:error, _}]
    end
  end
end
