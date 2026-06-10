defmodule TamanduaServer.Connectors.RegistryTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Connectors.Registry

  defmodule TestConnector do
    @moduledoc false
    use TamanduaServer.Connectors.Behaviour

    @impl true
    def metadata do
      %{
        name: "Test Connector",
        version: "1.0.0",
        type: :ioc_source,
        description: "Test connector for unit tests",
        author: "Test Suite",
        config_schema: %{
          required: [:api_key],
          properties: %{
            api_key: %{type: :string, min_length: 10}
          }
        }
      }
    end

    @impl true
    def init(config) do
      {:ok, %{api_key: config.api_key, initialized: true}}
    end

    @impl true
    def start(_state), do: :ok

    @impl true
    def stop(_state), do: :ok

    @impl true
    def health(_state) do
      {:ok, %{status: :healthy}}
    end

    @impl true
    def handle_inbound(_event, state) do
      {:ok, %{processed: true, state: state}}
    end
  end

  setup do
    # Start a fresh registry for each test
    start_supervised!(Registry)
    :ok
  end

  describe "register/1" do
    test "registers a valid connector" do
      assert {:ok, metadata} = Registry.register(TestConnector)
      assert metadata.name == "Test Connector"
      assert metadata.version == "1.0.0"
    end

    test "returns error for invalid module" do
      assert {:error, :module_not_found} = Registry.register(NonExistentModule)
    end
  end

  describe "list_connectors/0" do
    test "lists all registered connectors" do
      Registry.register(TestConnector)
      connectors = Registry.list_connectors()

      assert Enum.any?(connectors, fn c -> c.name == "Test Connector" end)
    end
  end

  describe "start_connector/2" do
    setup do
      Registry.register(TestConnector)
      :ok
    end

    test "starts connector with valid config" do
      config = %{api_key: "valid-api-key-1234"}
      assert {:ok, info} = Registry.start_connector("Test Connector", config)
      assert info.status == :running
      assert info.metadata.name == "Test Connector"
    end

    test "returns error for invalid config" do
      config = %{api_key: "short"}
      assert {:error, {:validation_failed, _}} = Registry.start_connector("Test Connector", config)
    end

    test "returns error if already running" do
      config = %{api_key: "valid-api-key-1234"}
      Registry.start_connector("Test Connector", config)

      assert {:error, :already_running} = Registry.start_connector("Test Connector", config)
    end
  end

  describe "stop_connector/1" do
    setup do
      Registry.register(TestConnector)
      config = %{api_key: "valid-api-key-1234"}
      Registry.start_connector("Test Connector", config)
      :ok
    end

    test "stops a running connector" do
      assert :ok = Registry.stop_connector("Test Connector")
      assert {:error, :not_running} = Registry.health("Test Connector")
    end

    test "returns error if not running" do
      assert {:error, :not_running} = Registry.stop_connector("Non-existent Connector")
    end
  end

  describe "health/1" do
    setup do
      Registry.register(TestConnector)
      config = %{api_key: "valid-api-key-1234"}
      Registry.start_connector("Test Connector", config)
      :ok
    end

    test "returns health status for running connector" do
      assert {:ok, health} = Registry.health("Test Connector")
      assert health.status == :healthy
    end

    test "returns error for stopped connector" do
      Registry.stop_connector("Test Connector")
      assert {:error, :not_running} = Registry.health("Test Connector")
    end
  end

  describe "route_event/3" do
    setup do
      Registry.register(TestConnector)
      config = %{api_key: "valid-api-key-1234"}
      Registry.start_connector("Test Connector", config)
      :ok
    end

    test "routes inbound event to connector" do
      event = %{type: "test", data: %{value: "test"}}
      assert {:ok, result} = Registry.route_event("Test Connector", event, :inbound)
      assert result.processed == true
    end

    test "returns error for non-running connector" do
      event = %{type: "test", data: %{}}
      assert {:error, :connector_not_running} = Registry.route_event("Unknown", event, :inbound)
    end
  end

  describe "list_instances/0" do
    test "lists running connector instances" do
      Registry.register(TestConnector)
      config = %{api_key: "valid-api-key-1234"}
      Registry.start_connector("Test Connector", config)

      instances = Registry.list_instances()
      assert length(instances) > 0
      assert Enum.any?(instances, fn i -> i.name == "Test Connector" end)
    end
  end
end
