defmodule TamanduaServer.Repo.MigrationGlobalLockSourceTest do
  use ExUnit.Case, async: true

  @migrations_path "priv/repo/migrations"

  test "Repo uses a PostgreSQL advisory migration lock" do
    source = File.read!("config/config.exs")

    assert source =~ "config :tamandua_server, TamanduaServer.Repo"
    assert source =~ "migration_lock: :pg_advisory_lock"

    assert Application.fetch_env!(:tamandua_server, TamanduaServer.Repo)
           |> Keyword.fetch!(:migration_lock) == :pg_advisory_lock
  end

  test "no migration opts out of the global lock" do
    offenders =
      @migrations_path
      |> Path.join("**/*.exs")
      |> Path.wildcard()
      |> Enum.filter(&(File.read!(&1) =~ ~r/@disable_migration_lock\s*(?:\(\s*)?true/))

    assert offenders == []
  end

  test "the complete non-transactional migration set retains global serialization" do
    migrations = [
      "20260129000001_add_enterprise_indexes.exs",
      "20260527090000_add_events_created_at_benchmark_indexes.exs",
      "20260626020000_add_events_org_timeline_indexes.exs",
      "20260628000001_add_dns_feed_indexes.exs",
      "20260707000100_add_alerts_org_inserted_at_index.exs"
    ]

    discovered =
      @migrations_path
      |> Path.join("**/*.exs")
      |> Path.wildcard()
      |> Enum.filter(&(File.read!(&1) =~ ~r/@disable_ddl_transaction\s*(?:\(\s*)?true/))
      |> Enum.map(&Path.basename/1)
      |> Enum.sort()

    assert discovered == Enum.sort(migrations)

    for migration <- migrations do
      source = File.read!(Path.join(@migrations_path, migration))
      assert source =~ "@disable_ddl_transaction true"
      refute source =~ "@disable_migration_lock true"
    end
  end

  test "release migration preflight rejects explicit transaction-pooling URLs without exposing them" do
    source = File.read!("lib/tamandua_server/release.ex")

    assert source =~ "System.get_env(\"MIGRATOR_DATABASE_URL\")"
    assert source =~ "DATABASE_URL is never used for migrations"
    assert source =~ "pool_mode pooling_mode pgbouncer_pool_mode"
    assert source =~ "direct or session-pooled PostgreSQL endpoint"
    refute source =~ "raise \"transaction pooling URL: \#{url}\""
  end

  test "release preflight checks pooling hints without claiming to validate the connection" do
    missing_error =
      assert_raise RuntimeError, fn ->
        TamanduaServer.Release.migration_connection_preflight!(nil)
      end

    assert Exception.message(missing_error) =~ "MIGRATOR_DATABASE_URL is required"
    assert :ok = TamanduaServer.Release.migration_connection_preflight!("not a URL")

    secret_url =
      "ecto://migration:do-not-log@db/tamandua?pool_mode=transaction&pool_mode=session"

    error =
      assert_raise RuntimeError, fn ->
        TamanduaServer.Release.migration_connection_preflight!(secret_url)
      end

    assert Exception.message(error) ==
             "migration connection must use a direct or session-pooled PostgreSQL endpoint"

    refute Exception.message(error) =~ "do-not-log"

    malformed_error =
      assert_raise RuntimeError, fn ->
        TamanduaServer.Release.migration_connection_preflight!(
          "ecto://migration:still-secret@db/tamandua?pool_mode=%ZZ"
        )
      end

    assert Exception.message(malformed_error) ==
             "MIGRATOR_DATABASE_URL contains an invalid query"

    refute Exception.message(malformed_error) =~ "still-secret"
  end
end
