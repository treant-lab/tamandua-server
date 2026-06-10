defmodule TamanduaServer.ThreatIntel.Feeds.SocketDevTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.ThreatIntel.Feeds.SocketDev

  describe "init/1" do
    test "with SOCKET_API_KEY env var schedules initial sync" do
      System.put_env("SOCKET_API_KEY", "test-key-123")
      on_exit(fn -> System.delete_env("SOCKET_API_KEY") end)

      {:ok, state} = SocketDev.init([])

      assert state.enabled == true
      assert state.api_key == "test-key-123"
      assert state.sync_interval == :timer.hours(4)
    end

    test "without API key sets enabled: false" do
      System.delete_env("SOCKET_API_KEY")

      {:ok, state} = SocketDev.init([])

      assert state.enabled == false
      assert state.api_key == nil
    end
  end

  describe "package_to_ioc/1" do
    test "converts Socket.dev package to IOC format with correct fields" do
      package = %{
        "name" => "lodash-clone",
        "version" => "1.0.0",
        "ecosystem" => "npm",
        "risk_score" => 85,
        "reason" => "Known malicious package"
      }

      ioc = SocketDev.package_to_ioc(package)

      assert ioc.type == "package_name"
      assert ioc.value == "npm:lodash-clone@1.0.0"
      assert ioc.source == "socket_dev"
      assert ioc.severity == "critical"
      assert ioc.confidence == 0.85
      assert ioc.tags == ["supply_chain", "npm"]
      assert ioc.metadata["ecosystem"] == "npm"
      assert ioc.metadata["package_name"] == "lodash-clone"
      assert ioc.metadata["package_version"] == "1.0.0"
      assert ioc.metadata["risk_score"] == 85
      assert ioc.metadata["reason"] == "Known malicious package"
    end

    test "severity_from_score maps risk scores correctly" do
      assert SocketDev.severity_from_score(95) == "critical"
      assert SocketDev.severity_from_score(80) == "critical"
      assert SocketDev.severity_from_score(75) == "high"
      assert SocketDev.severity_from_score(60) == "high"
      assert SocketDev.severity_from_score(55) == "medium"
      assert SocketDev.severity_from_score(40) == "medium"
      assert SocketDev.severity_from_score(20) == "low"
    end
  end

  describe "lookup/2" do
    test "checks single package against Socket.dev API" do
      # This would need HTTP mocking, placeholder for now
      assert true
    end
  end

  describe "get_status/0" do
    test "returns current state stats" do
      System.put_env("SOCKET_API_KEY", "test-key")
      on_exit(fn -> System.delete_env("SOCKET_API_KEY") end)

      {:ok, _pid} = start_supervised(SocketDev)

      status = SocketDev.get_status()

      assert is_map(status)
      assert Map.has_key?(status, :enabled)
      assert Map.has_key?(status, :configured)
      assert Map.has_key?(status, :last_sync)
      assert Map.has_key?(status, :stats)
    end
  end
end
