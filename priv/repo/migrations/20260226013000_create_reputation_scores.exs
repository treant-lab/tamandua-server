defmodule TamanduaServer.Repo.Migrations.CreateReputationScores do
  use Ecto.Migration

  def change do
    create table(:reputation_scores, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :indicator_type, :string, null: false
      add :indicator_value, :string, null: false
      add :score, :integer, null: false
      add :confidence, :float, null: false
      add :verdict, :string, null: false
      add :sources_queried, :integer
      add :sources_used, :integer
      add :breakdown, :map
      add :weighted_breakdown, :map
      add :majority_bonus, :integer
      add :metadata, :map
      add :scored_at, :utc_datetime_usec, null: false

      timestamps()
    end

    # Indexes for efficient querying
    create index(:reputation_scores, [:indicator_type, :indicator_value])
    create index(:reputation_scores, [:scored_at])
    create index(:reputation_scores, [:verdict])
    create index(:reputation_scores, [:score])

    # Composite index for trend queries
    create index(:reputation_scores, [:indicator_type, :indicator_value, :scored_at])
  end
end
