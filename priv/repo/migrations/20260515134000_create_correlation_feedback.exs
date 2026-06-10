defmodule TamanduaServer.Repo.Migrations.CreateCorrelationFeedback do
  use Ecto.Migration

  def change do
    create_if_not_exists table(:correlation_feedback, primary_key: false) do
      add(:id, :binary_id, primary_key: true)

      add(:organization_id, references(:organizations, type: :binary_id, on_delete: :delete_all),
        null: false
      )

      add(:target_type, :string, null: false)
      add(:target_id, :binary_id, null: false)
      add(:verdict, :string, null: false)
      add(:notes, :text)
      add(:user_id, references(:users, type: :binary_id, on_delete: :nilify_all))
      add(:metadata, :map, null: false, default: %{})

      timestamps(type: :utc_datetime_usec)
    end

    create_if_not_exists(index(:correlation_feedback, [:organization_id, :inserted_at]))
    create_if_not_exists(index(:correlation_feedback, [:target_type, :target_id]))
    create_if_not_exists(index(:correlation_feedback, [:verdict]))
  end
end
