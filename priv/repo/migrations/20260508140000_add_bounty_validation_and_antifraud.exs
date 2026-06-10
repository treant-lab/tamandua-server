defmodule TamanduaServer.Repo.Migrations.AddBountyValidationAndAntifraud do
  @moduledoc """
  Adds anti-fraud validation fields to submissions for bounty eligibility.

  This migration supports the bounty validation pipeline:
  - Syntax validation
  - Benchmark testing (Atomic Red Team / Caldera)
  - Duplicate detection
  - Risk flagging
  - Eligibility determination
  """
  use Ecto.Migration

  def change do
    alter table(:submissions) do
      # Validation results from benchmark tests
      add :validation_results, :map, default: %{}

      # MITRE techniques covered by this submission
      add :techniques_covered, {:array, :string}, default: []

      # Whether the submission's techniques are testable via Atomic Red Team/Caldera
      # NOTE: This does NOT mean the rule was actually tested - only that tests exist
      add :benchmark_testable, :boolean, default: false

      # Source of benchmark validation (atomic_red_team, caldera, manual_lab, etc.)
      add :benchmark_source, :string

      # Bounty eligibility status: eligible, ineligible, pending_review
      add :bounty_eligibility, :string, default: "pending_review"

      # Human-readable reason for eligibility decision
      add :bounty_eligibility_reason, :string

      # Risk flags for fraud detection (array of flag names)
      add :risk_flags, {:array, :string}, default: []

      # Similarity hash for duplicate detection
      add :similarity_hash, :string

      # False positive rate from benchmark (0.0 to 1.0)
      add :false_positive_rate, :float

      # Coverage delta vs baseline (positive = improvement)
      add :coverage_delta, :float

      # External correlation sources (threat_intel, multi_org, etc.)
      add :external_correlations, {:array, :string}, default: []

      # Number of distinct organizations that observed this
      add :org_observation_count, :integer, default: 0

      # Syntax validation passed
      add :syntax_valid, :boolean
    end

    # Index for deduplication
    create index(:submissions, [:similarity_hash])

    # Index for eligibility queries
    create index(:submissions, [:bounty_eligibility])

    # Index for benchmark filtering
    create index(:submissions, [:benchmark_testable])
  end
end
