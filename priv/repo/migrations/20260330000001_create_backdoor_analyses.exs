defmodule TamanduaServer.Repo.Migrations.CreateBackdoorAnalyses do
  @moduledoc """
  Creates the ai_model_backdoor_analyses table for storing backdoor analysis results.

  This table stores the results of deep backdoor analysis performed on AI/ML models,
  including weight statistics, spectral analysis (SVD), and combined risk scores.
  """
  use Ecto.Migration

  def change do
    create table(:ai_model_backdoor_analyses, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :model_id, :string, null: false
      add :agent_id, :string
      add :file_hash, :string

      # Scores from analysis (all 0.0-1.0)
      add :weight_score, :float
      add :spectral_score, :float
      add :backdoor_score, :float  # combined score

      # Suspicious flag
      add :is_suspicious, :boolean, default: false

      # Detailed results for charts/inspection
      add :weight_details, :map, default: %{}  # Per-layer weight stats
      add :spectral_details, :map, default: %{}  # SVD results

      # Outlier layers identified
      add :weight_outlier_layers, {:array, :string}, default: []
      add :spectral_outlier_layers, {:array, :string}, default: []

      # Analysis metadata
      add :analysis_time_ms, :integer

      # Multi-tenancy support
      add :organization_id, :binary_id

      timestamps()
    end

    # Index for querying by model
    create index(:ai_model_backdoor_analyses, [:model_id])

    # Index for cache lookup by file hash
    create index(:ai_model_backdoor_analyses, [:file_hash])

    # Index for multi-tenant queries
    create index(:ai_model_backdoor_analyses, [:organization_id])

    # Index for time-based queries (e.g., recent analyses)
    create index(:ai_model_backdoor_analyses, [:inserted_at])

    # Composite index for efficient "latest analysis per model" queries
    create index(:ai_model_backdoor_analyses, [:model_id, :inserted_at])
  end
end
