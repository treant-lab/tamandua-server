defmodule TamanduaServer.Repo.Migrations.CreateAiConversations do
  use Ecto.Migration

  def change do
    create table(:ai_conversations, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, :string, null: false
      add :title, :string, null: false
      add :messages, {:array, :map}, null: false, default: []

      timestamps(type: :utc_datetime_usec)
    end

    create index(:ai_conversations, [:user_id, :updated_at])
  end
end
