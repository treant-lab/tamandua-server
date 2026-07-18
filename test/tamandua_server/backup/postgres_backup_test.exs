defmodule TamanduaServer.Backup.PostgresBackupTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Backup.PostgresBackup

  defmodule CommandRunner do
    def run(command, args, opts \\ []) do
      send(self(), {:command, command, args, opts})
      {"ok", 0}
    end
  end

  setup do
    original_repo = Application.get_env(:tamandua_server, TamanduaServer.Repo)
    original_runner = Application.get_env(:tamandua_server, :postgres_backup_command_runner)

    Application.put_env(:tamandua_server, :postgres_backup_command_runner, CommandRunner)

    on_exit(fn ->
      restore_env(TamanduaServer.Repo, original_repo)
      restore_env(:postgres_backup_command_runner, original_runner)
    end)

    :ok
  end

  test "resolves Repo options at operation time" do
    Application.put_env(:tamandua_server, TamanduaServer.Repo,
      username: "first-user",
      password: "first-password",
      hostname: "first-db",
      port: 5433,
      database: "first_database"
    )

    assert {:ok, "ok"} = PostgresBackup.dump_database()

    assert_received {:command, "pg_dump",
                     ["postgresql://first-user@first-db:5433/first_database", "--format=plain"],
                     env: [{"PGPASSWORD", "first-password"}]}

    Application.put_env(:tamandua_server, TamanduaServer.Repo,
      username: "second-user",
      password: "second-password",
      hostname: "second-db",
      port: 5434,
      database: "second_database"
    )

    assert {:ok, "ok"} = PostgresBackup.dump_database()

    assert_received {:command, "pg_dump",
                     [
                       "postgresql://second-user@second-db:5434/second_database",
                       "--format=plain"
                     ], env: [{"PGPASSWORD", "second-password"}]}
  end

  test "uses DATABASE_URL at runtime without exposing its password in argv" do
    Application.put_env(:tamandua_server, TamanduaServer.Repo,
      url: "ecto://backup-user:p%40ssword@postgres.internal:5432/production_db?ssl=true"
    )

    assert {:ok, "ok"} = PostgresBackup.dump_database()

    assert_received {:command, "pg_dump", [database_url, "--format=plain"],
                     env: [{"PGPASSWORD", "p@ssword"}]}

    assert database_url ==
             "postgresql://backup-user@postgres.internal:5432/production_db?ssl=true"

    refute database_url =~ "p%40ssword"

    assert {:ok, "ok"} = PostgresBackup.restore_from_dump("/tmp/backup.sql")

    assert_received {:command, "psql",
                     [
                       "-d",
                       "postgresql://backup-user@postgres.internal:5432/production_db?ssl=true",
                       "-f",
                       "/tmp/backup.sql"
                     ], env: [{"PGPASSWORD", "p@ssword"}]}

    assert {:ok, "ok"} = PostgresBackup.restore_from_dump("/tmp/backup.sql", "restored_db")

    assert_received {:command, "psql",
                     [
                       "-d",
                       "postgresql://backup-user@postgres.internal:5432/restored_db?ssl=true",
                       "-f",
                       "/tmp/backup.sql"
                     ], env: [{"PGPASSWORD", "p@ssword"}]}
  end

  test "rejects an incomplete DATABASE_URL before executing a command" do
    Application.put_env(:tamandua_server, TamanduaServer.Repo,
      url: "postgres.internal/production_db"
    )

    assert {:error, :invalid_postgres_database_url} = PostgresBackup.dump_database()
    refute_received {:command, _, _, _}
  end

  defp restore_env(key, nil), do: Application.delete_env(:tamandua_server, key)
  defp restore_env(key, value), do: Application.put_env(:tamandua_server, key, value)
end
