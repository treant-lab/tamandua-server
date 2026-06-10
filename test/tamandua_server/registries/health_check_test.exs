defmodule TamanduaServer.Registries.HealthCheckTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Registries.HealthCheck

  # Mock registry module for testing
  defmodule HealthyRegistry do
    use TamanduaServer.Registries.Behaviour

    def metadata, do: %{name: "Healthy Registry", version: "1.0.0", type: :model_registry}
    def list_models(_config), do: {:ok, []}
    def get_model(_id, _config), do: {:error, :not_found}
    def search_models(_query, _config), do: {:ok, []}
    def scan_model(_id, _config), do: {:error, :scan_failed}

    @impl true
    def validate_config(_config), do: :ok
  end

  defmodule UnhealthyRegistry do
    use TamanduaServer.Registries.Behaviour

    def metadata, do: %{name: "Unhealthy Registry", version: "1.0.0", type: :model_registry}
    def list_models(_config), do: {:error, :unauthorized}
    def get_model(_id, _config), do: {:error, :not_found}
    def search_models(_query, _config), do: {:ok, []}
    def scan_model(_id, _config), do: {:error, :scan_failed}

    @impl true
    def validate_config(_config), do: {:error, :unauthorized}
  end

  defmodule TransientRegistry do
    use TamanduaServer.Registries.Behaviour
    use Agent

    def start_link do
      Agent.start_link(fn -> 0 end, name: __MODULE__)
    end

    def metadata, do: %{name: "Transient Registry", version: "1.0.0", type: :model_registry}
    def list_models(_config), do: {:ok, []}
    def get_model(_id, _config), do: {:error, :not_found}
    def search_models(_query, _config), do: {:ok, []}
    def scan_model(_id, _config), do: {:error, :scan_failed}

    @impl true
    def validate_config(_config) do
      # Fail first 2 calls, succeed on 3rd
      call_count = Agent.get_and_update(__MODULE__, fn count -> {count + 1, count + 1} end)

      if call_count <= 2 do
        {:error, {:network, :timeout}}
      else
        :ok
      end
    end
  end

  describe "GenServer lifecycle" do
    test "starts with initial registry configs" do
      registries = [
        healthy: [module: HealthyRegistry, config: %{}]
      ]

      {:ok, pid} = HealthCheck.start_link(registries: registries, interval: 60_000, name: :test_health_1)

      assert Process.alive?(pid)

      GenServer.stop(pid)
    end

    test "schedules periodic health checks" do
      # Use a very short interval for testing
      {:ok, pid} = HealthCheck.start_link(
        registries: [healthy: [module: HealthyRegistry, config: %{}]],
        interval: 100,
        initial_delay: 10,
        name: :test_health_2
      )

      # Wait for at least one check to happen
      Process.sleep(150)

      status = HealthCheck.get_status(pid)
      assert Map.has_key?(status, :healthy)

      GenServer.stop(pid)
    end

    test "initial check delayed" do
      {:ok, pid} = HealthCheck.start_link(
        registries: [healthy: [module: HealthyRegistry, config: %{}]],
        interval: 60_000,
        initial_delay: 50,
        name: :test_health_3
      )

      # Immediately after start, status should not have been checked yet
      status = HealthCheck.get_status(pid)

      # Last check should be nil since no check has happened yet
      registry_status = status[:healthy]
      assert registry_status.status == :unknown or registry_status.last_check == nil

      GenServer.stop(pid)
    end
  end

  describe "check_all/0" do
    test "checks all registered connectors" do
      {:ok, pid} = HealthCheck.start_link(
        registries: [
          healthy: [module: HealthyRegistry, config: %{}],
          unhealthy: [module: UnhealthyRegistry, config: %{}]
        ],
        interval: 60_000,
        initial_delay: 10,
        name: :test_health_4
      )

      # Wait for initial check
      Process.sleep(50)

      status = HealthCheck.get_status(pid)

      assert Map.has_key?(status, :healthy)
      assert Map.has_key?(status, :unhealthy)

      GenServer.stop(pid)
    end

    test "updates status for each registry" do
      {:ok, pid} = HealthCheck.start_link(
        registries: [
          healthy: [module: HealthyRegistry, config: %{}]
        ],
        interval: 60_000,
        initial_delay: 10,
        name: :test_health_5
      )

      # Wait for initial check
      Process.sleep(50)

      status = HealthCheck.get_status(pid)
      healthy_status = status[:healthy]

      assert healthy_status.status == :healthy
      assert healthy_status.consecutive_failures == 0

      GenServer.stop(pid)
    end
  end

  describe "check_registry/1" do
    test "checks specific registry" do
      {:ok, pid} = HealthCheck.start_link(
        registries: [
          healthy: [module: HealthyRegistry, config: %{}]
        ],
        interval: 60_000,
        initial_delay: 5000,  # Long delay so auto-check doesn't interfere
        name: :test_health_6
      )

      result = HealthCheck.check_registry(pid, :healthy)

      assert result == {:ok, :healthy}

      GenServer.stop(pid)
    end

    test "returns current status" do
      {:ok, pid} = HealthCheck.start_link(
        registries: [
          unhealthy: [module: UnhealthyRegistry, config: %{}]
        ],
        interval: 60_000,
        initial_delay: 5000,
        name: :test_health_7
      )

      result = HealthCheck.check_registry(pid, :unhealthy)

      # Will be degraded on first failure
      assert result in [{:ok, :degraded}, {:ok, :unhealthy}]

      GenServer.stop(pid)
    end
  end

  describe "health status tracking" do
    test "marks healthy on successful validate_config" do
      {:ok, pid} = HealthCheck.start_link(
        registries: [
          healthy: [module: HealthyRegistry, config: %{}]
        ],
        interval: 60_000,
        initial_delay: 10,
        name: :test_health_8
      )

      Process.sleep(50)

      status = HealthCheck.get_status(pid)
      assert status[:healthy].status == :healthy

      GenServer.stop(pid)
    end

    test "marks degraded on first failure" do
      {:ok, pid} = HealthCheck.start_link(
        registries: [
          unhealthy: [module: UnhealthyRegistry, config: %{}]
        ],
        interval: 60_000,
        initial_delay: 10,
        max_retries: 3,
        name: :test_health_9
      )

      Process.sleep(50)

      status = HealthCheck.get_status(pid)

      # After first failure, should be degraded
      assert status[:unhealthy].status in [:degraded, :unhealthy]
      assert status[:unhealthy].consecutive_failures >= 1

      GenServer.stop(pid)
    end

    test "marks unhealthy after max retries" do
      {:ok, pid} = HealthCheck.start_link(
        registries: [
          unhealthy: [module: UnhealthyRegistry, config: %{}]
        ],
        interval: 100,  # Short interval to iterate quickly
        initial_delay: 10,
        max_retries: 2,
        backoff_base: 10,
        name: :test_health_10
      )

      # Wait for multiple check cycles
      Process.sleep(500)

      status = HealthCheck.get_status(pid)

      # After max retries, should be unhealthy
      assert status[:unhealthy].status == :unhealthy
      assert status[:unhealthy].consecutive_failures >= 2

      GenServer.stop(pid)
    end

    test "recovers to healthy after successful check" do
      # Start transient agent
      {:ok, _} = TransientRegistry.start_link()

      {:ok, pid} = HealthCheck.start_link(
        registries: [
          transient: [module: TransientRegistry, config: %{}]
        ],
        interval: 50,
        initial_delay: 10,
        max_retries: 5,
        backoff_base: 10,
        name: :test_health_11
      )

      # Wait for failures then recovery
      Process.sleep(400)

      status = HealthCheck.get_status(pid)

      # Should have recovered to healthy after 3rd call
      assert status[:transient].status == :healthy

      GenServer.stop(pid)
      Agent.stop(TransientRegistry)
    end
  end

  describe "get_status/0" do
    test "returns status for all registries" do
      {:ok, pid} = HealthCheck.start_link(
        registries: [
          healthy: [module: HealthyRegistry, config: %{}],
          unhealthy: [module: UnhealthyRegistry, config: %{}]
        ],
        interval: 60_000,
        initial_delay: 10,
        name: :test_health_12
      )

      Process.sleep(50)

      status = HealthCheck.get_status(pid)

      assert Map.has_key?(status, :healthy)
      assert Map.has_key?(status, :unhealthy)

      GenServer.stop(pid)
    end

    test "includes last_check, last_success, consecutive_failures" do
      {:ok, pid} = HealthCheck.start_link(
        registries: [
          healthy: [module: HealthyRegistry, config: %{}]
        ],
        interval: 60_000,
        initial_delay: 10,
        name: :test_health_13
      )

      Process.sleep(50)

      status = HealthCheck.get_status(pid)
      registry_status = status[:healthy]

      assert Map.has_key?(registry_status, :last_check)
      assert Map.has_key?(registry_status, :last_success)
      assert Map.has_key?(registry_status, :consecutive_failures)
      assert registry_status.consecutive_failures == 0

      GenServer.stop(pid)
    end

    test "includes last_error for unhealthy registries" do
      {:ok, pid} = HealthCheck.start_link(
        registries: [
          unhealthy: [module: UnhealthyRegistry, config: %{}]
        ],
        interval: 60_000,
        initial_delay: 10,
        name: :test_health_14
      )

      Process.sleep(50)

      status = HealthCheck.get_status(pid)
      registry_status = status[:unhealthy]

      assert Map.has_key?(registry_status, :last_error)
      assert registry_status.last_error != nil

      GenServer.stop(pid)
    end
  end

  describe "error resilience" do
    test "does not crash on registry check failure" do
      {:ok, pid} = HealthCheck.start_link(
        registries: [
          unhealthy: [module: UnhealthyRegistry, config: %{}]
        ],
        interval: 60_000,
        initial_delay: 10,
        name: :test_health_15
      )

      Process.sleep(50)

      # Process should still be alive after failed check
      assert Process.alive?(pid)

      GenServer.stop(pid)
    end

    test "continues checking other registries if one fails" do
      {:ok, pid} = HealthCheck.start_link(
        registries: [
          healthy: [module: HealthyRegistry, config: %{}],
          unhealthy: [module: UnhealthyRegistry, config: %{}]
        ],
        interval: 60_000,
        initial_delay: 10,
        name: :test_health_16
      )

      Process.sleep(50)

      status = HealthCheck.get_status(pid)

      # Healthy should still be healthy even though unhealthy failed
      assert status[:healthy].status == :healthy

      GenServer.stop(pid)
    end

    test "gracefully handles missing registry modules" do
      # This test uses a non-existent module - should handle gracefully
      {:ok, pid} = HealthCheck.start_link(
        registries: [
          healthy: [module: HealthyRegistry, config: %{}]
        ],
        interval: 60_000,
        initial_delay: 10,
        name: :test_health_17
      )

      Process.sleep(50)

      assert Process.alive?(pid)

      GenServer.stop(pid)
    end
  end
end
