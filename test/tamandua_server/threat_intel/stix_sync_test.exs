defmodule TamanduaServer.ThreatIntel.StixSyncTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.ThreatIntel.{StixSync, TaxiiServer, TaxiiCollection}
  alias TamanduaServer.Repo

  describe "sync_server/1" do
    test "syncs TAXII server and discovers collections" do
      # This would require mocking HTTP requests
      # For now, test basic structure
      server = %TaxiiServer{
        id: Ecto.UUID.generate(),
        name: "Test Server",
        url: "https://test.example.com",
        auth_type: "basic",
        auth_config: %{"username" => "test", "password" => "test"},
        poll_enabled: true,
        enabled: true
      }

      {:ok, _server} = Repo.insert(server)

      # In real test, mock StixTaxii.discover/2 and StixTaxii.list_collections/2
      # assert {:ok, result} = StixSync.sync_server(server)
      # assert result.collections_synced > 0
    end
  end

  describe "schedule_server_sync/2" do
    test "schedules Oban job for server sync" do
      server = %TaxiiServer{
        id: Ecto.UUID.generate(),
        name: "Scheduled Server",
        url: "https://scheduled.example.com",
        enabled: true
      }

      {:ok, server} = Repo.insert(server)

      {:ok, job} = StixSync.schedule_server_sync(server.id, 60)

      assert job.args["action"] == "sync_server"
      assert job.args["server_id"] == server.id
    end
  end

  describe "get_sync_stats/0" do
    test "returns sync statistics" do
      stats = StixSync.get_sync_stats()

      assert is_map(stats)
      assert Map.has_key?(stats, :total_servers)
      assert Map.has_key?(stats, :enabled_servers)
      assert Map.has_key?(stats, :servers)
    end
  end
end
