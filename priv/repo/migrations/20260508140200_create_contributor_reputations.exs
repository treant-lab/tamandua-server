defmodule TamanduaServer.Repo.Migrations.CreateContributorReputations do
  @moduledoc """
  Creates the contributor reputation tracking table for bounty anti-fraud.
  """
  use Ecto.Migration

  def change do
    create table(:contributor_reputations, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :wallet_address, :string, null: false

      # Submission counts
      add :total_submissions, :integer, default: 0
      add :validated_count, :integer, default: 0
      add :rejected_count, :integer, default: 0
      add :duplicate_count, :integer, default: 0
      add :paid_count, :integer, default: 0

      # Bounty stats
      add :total_bounty_lamports, :bigint, default: 0
      add :avg_bounty_lamports, :bigint, default: 0

      # Quality metrics
      add :avg_fp_rate, :float, default: 0.0
      add :avg_coverage_delta, :float, default: 0.0
      add :rules_reused_count, :integer, default: 0

      # Violations
      add :pii_violation_count, :integer, default: 0
      add :fraud_flag_count, :integer, default: 0

      # Computed
      add :reputation_score, :integer, default: 0
      add :trust_tier, :string, default: "new"

      # Timestamps
      add :first_submission_at, :utc_datetime_usec
      add :last_submission_at, :utc_datetime_usec
      add :last_paid_at, :utc_datetime_usec

      # Admin actions
      add :manually_restricted, :boolean, default: false
      add :restriction_reason, :string
      add :notes, :text

      timestamps()
    end

    # One reputation record per wallet
    create unique_index(:contributor_reputations, [:wallet_address])

    # For leaderboard queries
    create index(:contributor_reputations, [:reputation_score])
    create index(:contributor_reputations, [:trust_tier])

    # For finding restricted contributors
    create index(:contributor_reputations, [:manually_restricted])
  end
end
