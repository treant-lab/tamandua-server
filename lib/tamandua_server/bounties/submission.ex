defmodule TamanduaServer.Bounties.Submission do
  @moduledoc """
  Represents a security researcher's contribution submission for bounty evaluation.

  Submissions can be IOCs, detection rules, or sample hashes that contribute to threat intelligence.

  ## Security Boundary: Test vs Real Submissions

  The bounty system distinguishes between testable and validated submissions:

  ### `benchmark_testable` - Informational Only, NOT Validation

  - `benchmark_testable: true` means tests EXIST for the MITRE techniques the rule covers
  - This does NOT mean the rule was actually tested or validated
  - This does NOT qualify a submission for bounty payment
  - This is purely informational for reviewer convenience

  ### Real Validation for Bounty Eligibility

  A submission is only eligible for bounty payment if it has at least ONE of:

  1. **External TI correlation** - Third-party threat intel confirms the IOC/technique
  2. **Multi-org observation** - 2+ organizations independently observed the indicator

  The `bounty_eligibility` field tracks this:
  - `"eligible"` - Has real validation, can receive bounty
  - `"ineligible"` - Failed validation (duplicate, PII, syntax error, etc.)
  - `"pending_review"` - Awaiting automated validation
  - `"manual_review_required"` - Needs human reviewer decision

  ### Risk Flags

  The `risk_flags` field tracks fraud indicators:
  - `"benchmark_only_no_real_validation"` - Has testability but no real validation
  - `"no_external_correlation"` - No external TI confirmation
  - `"single_org_only"` - Observed by only one organization
  - `"synthetic_only"` - Tested only in lab environment
  - Other flags for duplicates, PII, excessive FP rate, etc.

  ### Admin Override

  For legitimate edge cases, admins can use `Bounties.admin_override_pay_bounty/4`
  which requires an explicit reason and creates an audit trail.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Alerts.Alert

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  @type t :: %__MODULE__{}

  schema "submissions" do
    field :type, :string
    field :contributor_wallet, :string
    field :payload, :map
    field :status, :string, default: "submitted"
    field :title, :string
    field :description, :string
    field :rejection_reason, :string
    field :validated_at, :utc_datetime_usec

    # Anti-fraud validation fields
    field :validation_results, :map, default: %{}
    field :techniques_covered, {:array, :string}, default: []
    field :benchmark_testable, :boolean, default: false
    field :benchmark_source, :string
    field :bounty_eligibility, :string, default: "pending_review"
    field :bounty_eligibility_reason, :string
    field :risk_flags, {:array, :string}, default: []
    field :similarity_hash, :string
    field :false_positive_rate, :float
    field :coverage_delta, :float
    field :external_correlations, {:array, :string}, default: []
    field :org_observation_count, :integer, default: 0
    field :syntax_valid, :boolean

    # Admin override for bounty payment (bypasses automated eligibility)
    field :admin_override_reason, :string
    field :admin_override_at, :utc_datetime_usec
    field :admin_override_by_id, :binary_id

    belongs_to :organization, Organization
    belongs_to :submitted_by, User
    belongs_to :linked_alert, Alert
    belongs_to :validated_by, User

    timestamps()
  end

  @risk_flag_values ~w(
    self_reported_only
    duplicate_ioc
    duplicate_rule
    private_or_pii_ioc
    no_external_correlation
    low_confidence
    single_org_only
    synthetic_only
    excessive_fp_rate
    unverified_source
    suspicious_wallet
    rapid_submission_rate
    benchmark_only_no_real_validation
  )

  @eligibility_values ~w(eligible ineligible pending_review manual_review_required)
  @benchmark_sources ~w(atomic_red_team caldera manual_lab production_telemetry external_ti)

  @doc false
  def changeset(submission, attrs) do
    submission
    |> cast(attrs, [
      :type,
      :contributor_wallet,
      :payload,
      :status,
      :title,
      :description,
      :rejection_reason,
      :validated_at,
      :organization_id,
      :submitted_by_id,
      :linked_alert_id,
      :validated_by_id,
      # Anti-fraud fields
      :validation_results,
      :techniques_covered,
      :benchmark_testable,
      :benchmark_source,
      :bounty_eligibility,
      :bounty_eligibility_reason,
      :risk_flags,
      :similarity_hash,
      :false_positive_rate,
      :coverage_delta,
      :external_correlations,
      :org_observation_count,
      :syntax_valid,
      # Admin override fields
      :admin_override_reason,
      :admin_override_at,
      :admin_override_by_id
    ])
    |> validate_required([:type, :contributor_wallet, :payload, :title, :organization_id])
    |> validate_inclusion(:type, ~w(ioc rule sample_hash report pack))
    |> validate_inclusion(:status, ~w(submitted triaged validated rejected paid))
    |> validate_inclusion(:bounty_eligibility, @eligibility_values)
    |> validate_wallet_format()
    |> validate_length(:title, min: 3, max: 200)
    |> validate_risk_flags()
    |> validate_benchmark_source()
    |> validate_number(:false_positive_rate, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> compute_similarity_hash()
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:submitted_by_id)
    |> foreign_key_constraint(:linked_alert_id)
    |> foreign_key_constraint(:validated_by_id)
  end

  @doc """
  Changeset for updating validation results after benchmark testing.
  """
  def validation_changeset(submission, attrs) do
    submission
    |> cast(attrs, [
      :validation_results,
      :techniques_covered,
      :benchmark_testable,
      :benchmark_source,
      :bounty_eligibility,
      :bounty_eligibility_reason,
      :risk_flags,
      :false_positive_rate,
      :coverage_delta,
      :external_correlations,
      :org_observation_count,
      :syntax_valid
    ])
    |> validate_inclusion(:bounty_eligibility, @eligibility_values)
    |> validate_risk_flags()
    |> validate_benchmark_source()
  end

  defp validate_wallet_format(changeset) do
    wallet = get_change(changeset, :contributor_wallet)

    if wallet do
      # Solana addresses are base58 encoded, typically 32-44 characters
      if String.match?(wallet, ~r/^[1-9A-HJ-NP-Za-km-z]{32,44}$/) do
        changeset
      else
        add_error(changeset, :contributor_wallet, "must be a valid Solana wallet address (base58, 32-44 chars)")
      end
    else
      changeset
    end
  end

  defp validate_risk_flags(changeset) do
    flags = get_change(changeset, :risk_flags) || []

    invalid_flags = Enum.reject(flags, &(&1 in @risk_flag_values))

    if Enum.empty?(invalid_flags) do
      changeset
    else
      add_error(changeset, :risk_flags, "contains invalid flags: #{Enum.join(invalid_flags, ", ")}")
    end
  end

  defp validate_benchmark_source(changeset) do
    source = get_change(changeset, :benchmark_source)

    if source && source not in @benchmark_sources do
      add_error(changeset, :benchmark_source, "must be one of: #{Enum.join(@benchmark_sources, ", ")}")
    else
      changeset
    end
  end

  defp compute_similarity_hash(changeset) do
    if get_change(changeset, :similarity_hash) do
      # Already set, don't override
      changeset
    else
      type = get_field(changeset, :type)
      payload = get_field(changeset, :payload)

      if type && payload do
        hash = compute_hash(type, payload)
        put_change(changeset, :similarity_hash, hash)
      else
        changeset
      end
    end
  end

  defp compute_hash("rule", payload) do
    # For rules, hash the rule content
    content = payload["content"] || payload["rule"] || Jason.encode!(payload)
    :crypto.hash(:sha256, content) |> Base.encode16(case: :lower)
  end

  defp compute_hash("ioc", payload) do
    # For IOCs, hash type + value
    ioc_type = payload["ioc_type"] || payload["type"] || "unknown"
    ioc_value = payload["value"] || payload["ioc_value"] || ""
    :crypto.hash(:sha256, "#{ioc_type}:#{ioc_value}") |> Base.encode16(case: :lower)
  end

  defp compute_hash("sample_hash", payload) do
    # For samples, use the hash itself
    payload["hash"] || payload["sha256"] || payload["sha1"] || payload["md5"] || ""
  end

  defp compute_hash(_type, payload) do
    :crypto.hash(:sha256, Jason.encode!(payload)) |> Base.encode16(case: :lower)
  end

  # Public API for risk flag values
  def risk_flag_values, do: @risk_flag_values

  # Public API for eligibility values
  def eligibility_values, do: @eligibility_values

  # Public API for benchmark sources
  def benchmark_sources, do: @benchmark_sources
end
