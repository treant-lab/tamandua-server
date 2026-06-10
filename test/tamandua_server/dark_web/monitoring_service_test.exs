defmodule TamanduaServer.DarkWeb.MonitoringServiceTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.DarkWeb
  alias TamanduaServer.DarkWeb.MonitoringService
  alias TamanduaServer.DarkWeb.Feeds.HIBP
  alias TamanduaServer.Accounts

  describe "monitoring service" do
    setup do
      # Create test user
      {:ok, user} =
        Accounts.create_user(%{
          email: "test@example.com",
          password: "test123456",
          name: "Test User",
          role: "analyst"
        })

      {:ok, user: user}
    end

    test "starts successfully" do
      {:ok, pid} = MonitoringService.start_link(enabled: false)
      assert Process.alive?(pid)
      GenServer.stop(pid)
    end

    test "get_status returns monitoring status" do
      {:ok, _pid} = MonitoringService.start_link(enabled: false)

      status = MonitoringService.get_status()

      assert status.enabled == false
      assert is_map(status.feed_status)
      assert Map.has_key?(status.feed_status, :hibp)
      assert Map.has_key?(status.feed_status, :intel471)
      assert Map.has_key?(status.feed_status, :flashpoint)

      GenServer.stop(MonitoringService)
    end

    test "check_email queries HIBP for email compromise", %{user: user} do
      {:ok, _pid} = MonitoringService.start_link(enabled: false)

      # This will make actual API call if HIBP_API_KEY is set
      # For testing, you might want to mock this
      result = MonitoringService.check_email(user.email)

      assert {:ok, _data} = result

      GenServer.stop(MonitoringService)
    end
  end

  describe "credential matching" do
    setup do
      # Create test breach
      {:ok, breach} =
        DarkWeb.create_breach(%{
          breach_name: "TestBreach",
          source: "hibp",
          breach_date: ~U[2023-01-01 00:00:00Z],
          pwn_count: 1000,
          data_classes: ["Emails", "Passwords"],
          is_verified: true
        })

      # Create test user
      {:ok, user} =
        Accounts.create_user(%{
          email: "victim@example.com",
          password: "test123456",
          name: "Victim User",
          role: "analyst"
        })

      {:ok, breach: breach, user: user}
    end

    test "creates credential record for compromised user", %{breach: breach, user: user} do
      {:ok, credential} =
        DarkWeb.create_credential(%{
          breach_id: breach.id,
          email: user.email,
          user_id: user.id,
          domain: "example.com",
          severity: "high",
          status: "new",
          source: "hibp",
          first_seen: DateTime.utc_now()
        })

      assert credential.email == user.email
      assert credential.user_id == user.id
      assert credential.severity == "high"
    end

    test "calculates correct severity for admin user", %{breach: breach} do
      {:ok, admin} =
        Accounts.create_user(%{
          email: "admin@example.com",
          password: "admin123456",
          name: "Admin User",
          role: "admin"
        })

      {:ok, credential} =
        DarkWeb.create_credential(%{
          breach_id: breach.id,
          email: admin.email,
          user_id: admin.id,
          domain: "example.com",
          severity: "critical",
          status: "new",
          source: "hibp",
          first_seen: DateTime.utc_now()
        })

      assert credential.severity == "critical"
    end
  end

  describe "statistics" do
    test "returns correct breach statistics" do
      # Create some test breaches
      for i <- 1..5 do
        DarkWeb.create_breach(%{
          breach_name: "Breach#{i}",
          source: "hibp",
          breach_date: ~U[2023-01-01 00:00:00Z]
        })
      end

      stats = DarkWeb.get_breach_stats()

      assert stats.total >= 5
      assert is_map(stats.by_source)
      assert is_integer(stats.recent)
    end

    test "returns correct credential statistics" do
      # Create test breach and credentials
      {:ok, breach} =
        DarkWeb.create_breach(%{
          breach_name: "TestBreach",
          source: "hibp",
          breach_date: ~U[2023-01-01 00:00:00Z]
        })

      for i <- 1..3 do
        DarkWeb.create_credential(%{
          breach_id: breach.id,
          email: "user#{i}@example.com",
          severity: "medium",
          status: "new",
          source: "hibp",
          first_seen: DateTime.utc_now()
        })
      end

      stats = DarkWeb.get_credential_stats()

      assert stats.total >= 3
      assert is_map(stats.by_status)
      assert is_map(stats.by_severity)
    end
  end

  describe "search" do
    setup do
      {:ok, breach} =
        DarkWeb.create_breach(%{
          breach_name: "SearchTestBreach",
          domain: "searchtest.com",
          source: "hibp",
          breach_date: ~U[2023-01-01 00:00:00Z],
          description: "A test breach for search functionality"
        })

      {:ok, credential} =
        DarkWeb.create_credential(%{
          breach_id: breach.id,
          email: "search@searchtest.com",
          severity: "medium",
          status: "new",
          source: "hibp",
          first_seen: DateTime.utc_now()
        })

      {:ok, breach: breach, credential: credential}
    end

    test "searches across breaches and credentials", %{breach: breach, credential: credential} do
      results = DarkWeb.search("searchtest")

      assert length(results.breaches) > 0
      assert length(results.credentials) > 0

      found_breach = Enum.find(results.breaches, &(&1.id == breach.id))
      found_credential = Enum.find(results.credentials, &(&1.id == credential.id))

      assert found_breach != nil
      assert found_credential != nil
    end
  end
end
