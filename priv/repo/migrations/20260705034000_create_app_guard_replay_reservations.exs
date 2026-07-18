defmodule TamanduaServer.Repo.Migrations.CreateAppGuardReplayReservations do
  use Ecto.Migration

  def change do
    create table(:app_guard_replay_reservations, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all), null: false

      add :signing_key_id, :string, null: false
      add :reservation_type, :string, null: false
      add :reservation_value, :string, null: false
      add :expires_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:app_guard_replay_reservations, [
             :organization_id,
             :signing_key_id,
             :reservation_type,
             :reservation_value
           ])

    create index(:app_guard_replay_reservations, [:organization_id])
    create index(:app_guard_replay_reservations, [:signing_key_id])
    create index(:app_guard_replay_reservations, [:expires_at])
  end
end
