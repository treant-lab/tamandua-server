defmodule TamanduaServer.Repo.Migrations.CreateEventCorrelations do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:event_correlations, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      # `events` is a Timescale hypertable in deployed lab environments. A
      # normal FK is not portable there because the referenced key does not have
      # a standalone unique constraint compatible with Postgres FK rules.
      add(:source_event_id, :binary_id, null: false)
      add(:target_event_id, :binary_id, null: false)

      add(:organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:score, :integer, null: false)
      add(:relation_types, {:array, :string}, default: [], null: false)
      add(:reasons, {:array, :string}, default: [], null: false)
      add(:shared_entities, {:array, :string}, default: [], null: false)
      add(:metadata, :map, default: %{}, null: false)

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists(index(:event_correlations, [:organization_id, :inserted_at]))
    create_if_not_exists(index(:event_correlations, [:source_event_id]))
    create_if_not_exists(index(:event_correlations, [:target_event_id]))

    create_if_not_exists(
      unique_index(
        :event_correlations,
        [:source_event_id, :target_event_id],
        name: :event_correlations_unique_pair
      )
    )
  end
end
