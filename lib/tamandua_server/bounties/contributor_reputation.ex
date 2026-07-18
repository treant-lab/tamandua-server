defmodule TamanduaServer.Bounties.ContributorReputation do
  @moduledoc """
  Contributor Reputation System for the Tamandua bounty ecosystem.

  Tracks contributor quality and trustworthiness to:
  - Reduce bounty fraud
  - Prioritize good contributions
  - Create incentives for quality
  - Enable trust tiers for faster approval

  ## Reputation Score

  The score is calculated from weighted factors:

  ```
  reputation_score =
    validated_submissions * 10 +
    bounties_paid * 20 +
    rules_reused * 5 +
    low_fp_bonus -
    rejected_submissions * 15 -
    duplicate_submissions * 10 -
    pii_violations * 50 -
    fraud_flags * 100
  ```

  ## Trust Tiers

  | Tier | Score Range | Benefits |
  |------|-------------|----------|
  | new | 0-49 | Manual review required |
  | trusted | 50-199 | Faster approval |
  | expert | 200-499 | High-value bounties eligible |
  | partner | 500+ | Auto-approval for benchmarked submissions |
  | restricted | <0 | All submissions require manual review, bounties paused |

  ## Consensus for High-Value Bounties

  High-value bounties (>0.5 SOL) require 2-of-3 validation:
  - Human reviewer approved (manual review)
  - External TI correlation (third-party threat intel confirmation)
  - Multi-org observation (2+ organizations independently observed the indicator)

  SECURITY NOTE: `benchmark_testable` is explicitly EXCLUDED from validation count.
  It only indicates that tests EXIST for the techniques, not that the rule was
  actually tested or detected anything. This prevents bounty fraud where someone
  submits rules covering testable techniques without actual detection capability.

  ## Bounty Pools (Future)

  Planned pool types:
  - `global_community` - Tamandua treasury for general bounties
  - `customer_sponsored` - Customer-funded for specific threats
  - `pack_revenue` - Revenue share from marketplace
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Bounties.{Submission, BountyClaim}

  @primary_key {:id, :binary_id, autogenerate: true}
  @timestamps_opts [type: :utc_datetime_usec]

  @type t :: %__MODULE__{}

  schema "contributor_reputations" do
    field :wallet_address, :string

    # Counts
    field :total_submissions, :integer, default: 0
    field :validated_count, :integer, default: 0
    field :rejected_count, :integer, default: 0
    field :duplicate_count, :integer, default: 0
    field :paid_count, :integer, default: 0

    # Bounty stats
    field :total_bounty_lamports, :integer, default: 0
    field :avg_bounty_lamports, :integer, default: 0

    # Quality metrics
    field :avg_fp_rate, :float, default: 0.0
    field :avg_coverage_delta, :float, default: 0.0
    field :rules_reused_count, :integer, default: 0

    # Violations
    field :pii_violation_count, :integer, default: 0
    field :fraud_flag_count, :integer, default: 0

    # Computed
    field :reputation_score, :integer, default: 0
    field :trust_tier, :string, default: "new"

    # Timestamps
    field :first_submission_at, :utc_datetime_usec
    field :last_submission_at, :utc_datetime_usec
    field :last_paid_at, :utc_datetime_usec

    # Admin actions
    field :manually_restricted, :boolean, default: false
    field :restriction_reason, :string
    field :notes, :string

    timestamps()
  end

  @trust_tiers %{
    "restricted" => {-999_999, -1},
    "new" => {0, 49},
    "trusted" => {50, 199},
    "expert" => {200, 499},
    "partner" => {500, 999_999}
  }

  @high_value_threshold_lamports 500_000_000  # 0.5 SOL

  @doc false
  def changeset(reputation, attrs) do
    reputation
    |> cast(attrs, [
      :wallet_address,
      :total_submissions,
      :validated_count,
      :rejected_count,
      :duplicate_count,
      :paid_count,
      :total_bounty_lamports,
      :avg_bounty_lamports,
      :avg_fp_rate,
      :avg_coverage_delta,
      :rules_reused_count,
      :pii_violation_count,
      :fraud_flag_count,
      :reputation_score,
      :trust_tier,
      :first_submission_at,
      :last_submission_at,
      :last_paid_at,
      :manually_restricted,
      :restriction_reason,
      :notes
    ])
    |> validate_required([:wallet_address])
    |> unique_constraint(:wallet_address)
    |> compute_reputation_score()
    |> compute_trust_tier()
  end

  @doc """
  Get reputation for a wallet address without creating a placeholder row.
  """
  @spec get_by_wallet(String.t() | nil) :: t() | nil
  def get_by_wallet(wallet_address) when is_binary(wallet_address) do
    wallet_address
    |> normalize_wallet_address()
    |> case do
      nil -> nil
      wallet -> Repo.get_by(__MODULE__, wallet_address: wallet)
    end
  end

  def get_by_wallet(_), do: nil

  @doc """
  Builds the default reputation policy for a wallet that has no persisted history.
  """
  @spec default_for_wallet(String.t() | nil) :: t() | nil
  def default_for_wallet(wallet_address) when is_binary(wallet_address) do
    case normalize_wallet_address(wallet_address) do
      nil -> nil
      wallet -> %__MODULE__{wallet_address: wallet, trust_tier: "new", reputation_score: 0}
    end
  end

  def default_for_wallet(_), do: nil

  @doc """
  Get persisted reputation or the default new-contributor policy for a wallet.
  This does not write to the database.
  """
  @spec get_or_default(String.t() | nil) :: t() | nil
  def get_or_default(wallet_address) do
    get_by_wallet(wallet_address) || default_for_wallet(wallet_address)
  end

  @doc """
  Returns persisted reputations keyed by wallet address.
  """
  @spec by_wallets([String.t()]) :: %{String.t() => t()}
  def by_wallets([]), do: %{}

  def by_wallets(wallets) when is_list(wallets) do
    wallets =
      wallets
      |> Enum.map(&normalize_wallet_address/1)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    if Enum.empty?(wallets) do
      %{}
    else
      from(r in __MODULE__, where: r.wallet_address in ^wallets)
      |> Repo.all()
      |> Map.new(&{&1.wallet_address, &1})
    end
  end

  @doc """
  Get or create reputation for a wallet address after a real contributor event.
  """
  @spec get_or_create(String.t() | nil) :: {:ok, t()} | {:error, term()}
  def get_or_create(nil), do: {:error, :missing_wallet_address}

  def get_or_create(wallet_address) do
    with wallet when is_binary(wallet) <- normalize_wallet_address(wallet_address) do
      case Repo.get_by(__MODULE__, wallet_address: wallet) do
        nil ->
          %__MODULE__{}
          |> changeset(%{wallet_address: wallet})
          |> Repo.insert()

        reputation ->
          {:ok, reputation}
      end
    else
      nil ->
        {:error, :missing_wallet_address}
    end
  end

  @doc """
  Update reputation after a submission event.
  """
  @spec record_submission(String.t() | nil, atom(), map()) :: {:ok, t()} | {:error, term()}
  def record_submission(wallet_address, event, metadata \\ %{}) do
    with {:ok, reputation} <- get_or_create(wallet_address) do
      now = DateTime.utc_now()

      updates = case event do
        :submitted ->
          %{
            total_submissions: reputation.total_submissions + 1,
            last_submission_at: now,
            first_submission_at: reputation.first_submission_at || now
          }

        :validated ->
          fp_rate = metadata[:false_positive_rate] || 0.0
          coverage = metadata[:coverage_delta] || 0.0

          new_avg_fp = if reputation.validated_count > 0 do
            (reputation.avg_fp_rate * reputation.validated_count + fp_rate) /
              (reputation.validated_count + 1)
          else
            fp_rate
          end

          new_avg_coverage = if reputation.validated_count > 0 do
            (reputation.avg_coverage_delta * reputation.validated_count + coverage) /
              (reputation.validated_count + 1)
          else
            coverage
          end

          %{
            validated_count: reputation.validated_count + 1,
            avg_fp_rate: Float.round(new_avg_fp, 4),
            avg_coverage_delta: Float.round(new_avg_coverage, 4)
          }

        :rejected ->
          %{rejected_count: reputation.rejected_count + 1}

        :duplicate ->
          %{duplicate_count: reputation.duplicate_count + 1}

        :paid ->
          amount = metadata[:amount_lamports] || 0
          new_total = reputation.total_bounty_lamports + amount
          new_paid = reputation.paid_count + 1
          new_avg = div(new_total, new_paid)

          %{
            paid_count: new_paid,
            total_bounty_lamports: new_total,
            avg_bounty_lamports: new_avg,
            last_paid_at: now
          }

        :pii_violation ->
          %{pii_violation_count: reputation.pii_violation_count + 1}

        :fraud_flag ->
          %{fraud_flag_count: reputation.fraud_flag_count + 1}

        :rule_reused ->
          %{rules_reused_count: reputation.rules_reused_count + 1}

        _ ->
          %{}
      end

      reputation
      |> changeset(updates)
      |> Repo.update()
    end
  end

  @doc """
  Recalculate reputation from scratch based on all submissions.
  """
  @spec recalculate(String.t()) :: {:ok, t()} | {:error, term()}
  def recalculate(wallet_address) do
    # Get all submissions for this wallet
    submissions = Repo.all(
      from s in Submission,
        where: s.contributor_wallet == ^wallet_address
    )

    # Get all claims for this wallet
    claims = Repo.all(
      from c in BountyClaim,
        join: s in Submission, on: c.submission_id == s.id,
        where: s.contributor_wallet == ^wallet_address,
        where: c.status == "paid"
    )

    total = length(submissions)
    validated = Enum.count(submissions, &(&1.status in ["validated", "paid"]))
    rejected = Enum.count(submissions, &(&1.status == "rejected"))
    duplicates = submissions |> Enum.flat_map(&(&1.risk_flags || [])) |> Enum.count(&(&1 in ["duplicate_rule", "duplicate_ioc"]))
    pii_violations = submissions |> Enum.flat_map(&(&1.risk_flags || [])) |> Enum.count(&(&1 == "private_or_pii_ioc"))

    total_bounty = claims |> Enum.map(&(&1.amount_lamports || 0)) |> Enum.sum()
    paid_count = length(claims)
    avg_bounty = if paid_count > 0, do: div(total_bounty, paid_count), else: 0

    fp_rates = submissions |> Enum.map(&(&1.false_positive_rate || 0.0)) |> Enum.filter(&(&1 > 0))
    avg_fp = if length(fp_rates) > 0, do: Enum.sum(fp_rates) / length(fp_rates), else: 0.0

    coverage_deltas = submissions |> Enum.map(&(&1.coverage_delta || 0.0)) |> Enum.filter(&(&1 > 0))
    avg_coverage = if length(coverage_deltas) > 0, do: Enum.sum(coverage_deltas) / length(coverage_deltas), else: 0.0

    first_at = earliest_datetime(Enum.map(submissions, & &1.inserted_at))
    last_at = latest_datetime(Enum.map(submissions, & &1.inserted_at))
    last_paid = latest_datetime(Enum.map(claims, & &1.paid_at))

    with {:ok, reputation} <- get_or_create(wallet_address) do
      reputation
      |> changeset(%{
        total_submissions: total,
        validated_count: validated,
        rejected_count: rejected,
        duplicate_count: duplicates,
        paid_count: paid_count,
        total_bounty_lamports: total_bounty,
        avg_bounty_lamports: avg_bounty,
        avg_fp_rate: Float.round(avg_fp, 4),
        avg_coverage_delta: Float.round(avg_coverage, 4),
        pii_violation_count: pii_violations,
        first_submission_at: first_at,
        last_submission_at: last_at,
        last_paid_at: last_paid
      })
      |> Repo.update()
    end
  end

  @doc """
  Get the leaderboard of top contributors by reputation.
  """
  @spec leaderboard(keyword()) :: [t()]
  def leaderboard(opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)
    min_score = Keyword.get(opts, :min_score, 0)

    from(r in __MODULE__,
      where: r.reputation_score >= ^min_score,
      where: r.trust_tier != "restricted",
      order_by: [desc: r.reputation_score],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Check if a wallet can receive high-value bounties.
  """
  @spec can_receive_high_value_bounty?(String.t() | nil) :: boolean()
  def can_receive_high_value_bounty?(wallet_address) do
    case get_by_wallet(wallet_address) do
      nil -> false
      %{trust_tier: tier, manually_restricted: restricted} -> high_value_tier?(tier) and restricted != true
    end
  end

  @doc """
  Check bounty eligibility requirements based on amount and contributor reputation.
  """
  @spec check_bounty_requirements(String.t() | nil, integer(), Submission.t()) :: {:ok, :approved} | {:error, String.t()}
  def check_bounty_requirements(wallet_address, _amount_lamports, _submission)
      when not is_binary(wallet_address) do
    {:error, "Contributor wallet is required before bounty payment"}
  end

  def check_bounty_requirements(_wallet_address, amount_lamports, _submission)
      when not is_integer(amount_lamports) or amount_lamports <= 0 do
    {:error, "Bounty amount must be a positive integer number of lamports"}
  end

  def check_bounty_requirements(wallet_address, amount_lamports, submission) do
    case get_or_default(wallet_address) do
      nil ->
        {:error, "Contributor wallet is required before bounty payment"}

      reputation ->
      cond do
        # Restricted contributors cannot receive bounties
        reputation.trust_tier == "restricted" or reputation.manually_restricted ->
          {:error, "Contributor is restricted: #{reputation.restriction_reason || "manual restriction"}"}

        # High-value bounties require proven reputation.
        amount_lamports >= @high_value_threshold_lamports and not high_value_tier?(reputation.trust_tier) ->
          {:error, "High-value bounties (>0.5 SOL) require expert or partner trust tier"}

        # High-value bounties require 2-of-3 validation
        amount_lamports >= @high_value_threshold_lamports ->
          validations = count_validations(submission)
          if validations >= 2 do
            {:ok, :approved}
          else
            {:error, "High-value bounties require 2-of-3 validations (benchmark, reviewer, external correlation). Current: #{validations}"}
          end

        # Standard bounties for new contributors require manual review
        reputation.trust_tier == "new" and !submission.validated_by_id ->
          {:error, "New contributors require manual review before payment"}

        # All checks passed
        true ->
          {:ok, :approved}
      end
    end
  end

  @doc """
  Restrict a contributor (admin action).
  """
  @spec restrict(String.t(), String.t()) :: {:ok, t()} | {:error, term()}
  def restrict(wallet_address, reason) do
    with {:ok, reputation} <- get_or_create(wallet_address) do
      reputation
      |> changeset(%{
        manually_restricted: true,
        restriction_reason: reason,
        trust_tier: "restricted"
      })
      |> Repo.update()
    end
  end

  @doc """
  Unrestrict a contributor (admin action).
  """
  @spec unrestrict(String.t()) :: {:ok, t()} | {:error, term()}
  def unrestrict(wallet_address) do
    with {:ok, reputation} <- get_or_create(wallet_address) do
      reputation
      |> changeset(%{
        manually_restricted: false,
        restriction_reason: nil
      })
      |> compute_trust_tier()
      |> Repo.update()
    end
  end

  @doc """
  Get trust tier display name.
  """
  @spec tier_display_name(String.t()) :: String.t()
  def tier_display_name("restricted"), do: "Restricted"
  def tier_display_name("new"), do: "New Contributor"
  def tier_display_name("trusted"), do: "Trusted"
  def tier_display_name("expert"), do: "Expert"
  def tier_display_name("partner"), do: "Partner"
  def tier_display_name(_), do: "Unknown"

  @doc """
  Get high value bounty threshold in lamports.
  """
  def high_value_threshold_lamports, do: @high_value_threshold_lamports

  # Private helpers

  defp compute_reputation_score(changeset) do
    if changeset.valid? do
      validated = get_field(changeset, :validated_count) || 0
      rejected = get_field(changeset, :rejected_count) || 0
      duplicates = get_field(changeset, :duplicate_count) || 0
      paid = get_field(changeset, :paid_count) || 0
      reused = get_field(changeset, :rules_reused_count) || 0
      pii = get_field(changeset, :pii_violation_count) || 0
      fraud = get_field(changeset, :fraud_flag_count) || 0
      avg_fp = get_field(changeset, :avg_fp_rate) || 0.0

      # Bonus for low FP rate
      low_fp_bonus = if avg_fp < 0.02 and validated > 3, do: 25, else: 0

      score =
        validated * 10 +
        paid * 20 +
        reused * 5 +
        low_fp_bonus -
        rejected * 15 -
        duplicates * 10 -
        pii * 50 -
        fraud * 100

      put_change(changeset, :reputation_score, max(score, -1000))
    else
      changeset
    end
  end

  defp compute_trust_tier(changeset) do
    if changeset.valid? do
      manually_restricted = get_field(changeset, :manually_restricted) || false

      if manually_restricted do
        put_change(changeset, :trust_tier, "restricted")
      else
        score = get_field(changeset, :reputation_score) || 0

        tier = @trust_tiers
        |> Enum.find(fn {_tier, {min, max}} -> score >= min and score <= max end)
        |> case do
          {tier, _} -> tier
          nil -> "new"
        end

        put_change(changeset, :trust_tier, tier)
      end
    else
      changeset
    end
  end

  defp count_validations(%Submission{} = submission) do
    validations = 0

    # SECURITY: benchmark_testable does NOT count as a validation!
    # It only means tests EXIST for the MITRE techniques, not that the rule
    # was actually tested or detected anything. This prevents fraud where
    # someone submits a rule that covers testable techniques but doesn't
    # actually detect the attack.
    #
    # Valid validations that prove the rule/IOC works:
    # 1. Human reviewer validation (manual review)
    # 2. External threat intel correlation (third-party confirmation)
    # 3. Multi-org observation (independent confirmation)

    # Human reviewer validation
    validations = if submission.validated_by_id, do: validations + 1, else: validations

    # External threat intel correlation (real-world confirmation)
    has_external_ti = length(submission.external_correlations || []) > 0
    validations = if has_external_ti, do: validations + 1, else: validations

    # Multi-org observation (independent confirmation from multiple organizations)
    has_multi_org = (submission.org_observation_count || 0) >= 2
    validations = if has_multi_org, do: validations + 1, else: validations

    validations
  end

  defp high_value_tier?(tier), do: tier in ["expert", "partner"]

  defp normalize_wallet_address(wallet_address) when is_binary(wallet_address) do
    wallet_address
    |> String.trim()
    |> case do
      "" -> nil
      wallet ->
        if String.match?(wallet, ~r/^[1-9A-HJ-NP-Za-km-z]{32,44}$/), do: wallet, else: nil
    end
  end

  defp normalize_wallet_address(_), do: nil

  defp earliest_datetime(values) do
    values
    |> Enum.reject(&is_nil/1)
    |> Enum.min_by(&DateTime.to_unix(&1, :microsecond), fn -> nil end)
  end

  defp latest_datetime(values) do
    values
    |> Enum.reject(&is_nil/1)
    |> Enum.max_by(&DateTime.to_unix(&1, :microsecond), fn -> nil end)
  end
end
