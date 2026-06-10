defmodule TamanduaServer.Bounties do
  @moduledoc """
  The Bounties context for managing security researcher submissions and bounty claims.
  """

  import Ecto.Query, warn: false
  alias TamanduaServer.Repo

  alias TamanduaServer.Bounties.Submission
  alias TamanduaServer.Bounties.BountyClaim

  @doc """
  Returns the list of submissions with optional filters.

  ## Options

    * `:status` - Filter by status
    * `:type` - Filter by submission type
    * `:organization_id` - Filter by organization
    * `:contributor_wallet` - Filter by contributor wallet

  ## Examples

      iex> list_submissions()
      [%Submission{}, ...]

      iex> list_submissions(status: "validated")
      [%Submission{status: "validated"}, ...]

  """
  def list_submissions(opts \\ []) do
    Submission
    |> apply_filters(opts)
    |> Repo.all()
  end

  defp apply_filters(query, []), do: query
  defp apply_filters(query, [{:status, status} | rest]) do
    query
    |> where([s], s.status == ^status)
    |> apply_filters(rest)
  end
  defp apply_filters(query, [{:type, type} | rest]) do
    query
    |> where([s], s.type == ^type)
    |> apply_filters(rest)
  end
  defp apply_filters(query, [{:organization_id, org_id} | rest]) do
    query
    |> where([s], s.organization_id == ^org_id)
    |> apply_filters(rest)
  end
  defp apply_filters(query, [{:contributor_wallet, wallet} | rest]) do
    query
    |> where([s], s.contributor_wallet == ^wallet)
    |> apply_filters(rest)
  end
  defp apply_filters(query, [_unknown | rest]) do
    apply_filters(query, rest)
  end

  @doc """
  Gets a single submission.

  Raises `Ecto.NoResultsError` if the Submission does not exist.

  ## Examples

      iex> get_submission!(123)
      %Submission{}

      iex> get_submission!(456)
      ** (Ecto.NoResultsError)

  """
  def get_submission!(id) do
    Submission
    |> Repo.get!(id)
    |> Repo.preload([:organization, :submitted_by, :linked_alert])
  end

  @doc """
  Gets a submission scoped to an organization.
  Raises Ecto.NoResultsError if not found or belongs to different org.
  """
  def get_submission_for_org!(organization_id, id) do
    Submission
    |> where([s], s.organization_id == ^organization_id)
    |> Repo.get!(id)
    |> Repo.preload([:organization, :submitted_by, :linked_alert])
  end

  @doc """
  Creates a submission.

  ## Examples

      iex> create_submission(%{field: value})
      {:ok, %Submission{}}

      iex> create_submission(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_submission(attrs \\ %{}) do
    %Submission{}
    |> Submission.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a submission.

  ## Examples

      iex> update_submission(submission, %{field: new_value})
      {:ok, %Submission{}}

      iex> update_submission(submission, %{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def update_submission(%Submission{} = submission, attrs) do
    submission
    |> Submission.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a submission.

  ## Examples

      iex> delete_submission(submission)
      {:ok, %Submission{}}

      iex> delete_submission(submission)
      {:error, %Ecto.Changeset{}}

  """
  def delete_submission(%Submission{} = submission) do
    Repo.delete(submission)
  end

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking submission changes.

  ## Examples

      iex> change_submission(submission)
      %Ecto.Changeset{data: %Submission{}}

  """
  def change_submission(%Submission{} = submission, attrs \\ %{}) do
    Submission.changeset(submission, attrs)
  end

  # Bounty Claims

  @doc """
  Gets a single bounty claim.

  Raises `Ecto.NoResultsError` if the BountyClaim does not exist.

  ## Examples

      iex> get_claim!(123)
      %BountyClaim{}

  """
  def get_claim!(id) do
    BountyClaim
    |> Repo.get!(id)
    |> Repo.preload([:submission, :alert])
  end

  @doc """
  Creates a bounty claim.

  ## Examples

      iex> create_claim(%{field: value})
      {:ok, %BountyClaim{}}

      iex> create_claim(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_claim(attrs \\ %{}) do
    %BountyClaim{}
    |> BountyClaim.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a bounty claim.

  ## Examples

      iex> update_claim(claim, %{field: new_value})
      {:ok, %BountyClaim{}}

  """
  def update_claim(%BountyClaim{} = claim, attrs) do
    claim
    |> BountyClaim.changeset(attrs)
    |> Repo.update()
  end

  # Validation and Payment

  @doc """
  Returns the list of pending submissions (submitted or triaged).

  ## Examples

      iex> list_pending_submissions()
      [%Submission{status: "submitted"}, ...]

  """
  def list_pending_submissions(opts \\ []) do
    Submission
    |> where([s], s.status in ["submitted", "triaged"])
    |> apply_filters(opts)
    |> order_by([s], desc: s.inserted_at)
    |> Repo.all()
  end

  @doc """
  Validates a submission and records the validator.

  ## Examples

      iex> validate_submission(submission_id, admin_user_id)
      {:ok, %Submission{status: "validated"}}

  """
  def validate_submission(submission_id, validated_by_id) do
    submission = get_submission!(submission_id)

    update_submission(submission, %{
      status: "validated",
      validated_by_id: validated_by_id,
      validated_at: DateTime.utc_now()
    })
  end

  @doc """
  Validates a submission scoped to an organization.
  """
  def validate_submission_for_org(organization_id, submission_id, validated_by_id) do
    submission = get_submission_for_org!(organization_id, submission_id)

    update_submission(submission, %{
      status: "validated",
      validated_by_id: validated_by_id,
      validated_at: DateTime.utc_now()
    })
  end

  @doc """
  Rejects a submission with a reason.

  ## Examples

      iex> reject_submission(submission_id, admin_user_id, "Duplicate submission")
      {:ok, %Submission{status: "rejected"}}

  """
  def reject_submission(submission_id, validated_by_id, reason) do
    submission = get_submission!(submission_id)

    update_submission(submission, %{
      status: "rejected",
      validated_by_id: validated_by_id,
      validated_at: DateTime.utc_now(),
      rejection_reason: reason
    })
  end

  @doc """
  Rejects a submission scoped to an organization.
  """
  def reject_submission_for_org(organization_id, submission_id, validated_by_id, reason) do
    submission = get_submission_for_org!(organization_id, submission_id)

    update_submission(submission, %{
      status: "rejected",
      validated_by_id: validated_by_id,
      validated_at: DateTime.utc_now(),
      rejection_reason: reason
    })
  end

  @doc """
  Pays a bounty for a validated submission.

  ## Process

  1. Validates submission is in "validated" status
  2. Checks no existing paid claim exists
  3. Creates BountyClaim with "processing" status
  4. Calls Solana.Client.pay_bounty/3
  5. On success: updates claim, submission, and linked alert
  6. On failure: updates claim with failure reason

  ## Examples

      iex> pay_bounty(submission_id, 5_000_000)
      {:ok, %BountyClaim{status: "paid", tx_id: "..."}}

  """
  def pay_bounty(submission_id, amount_lamports) when is_integer(amount_lamports) and amount_lamports > 0 do
    require Logger

    submission = get_submission!(submission_id) |> Repo.preload(:linked_alert)

    with :ok <- validate_payment_eligible(submission),
         {:ok, claim} <- create_claim(%{
           submission_id: submission.id,
           alert_id: submission.linked_alert_id,
           amount_lamports: amount_lamports,
           status: "processing"
         }),
         incident_hash <- get_incident_hash(submission),
         {:ok, tx_id} <- TamanduaServer.Solana.Client.pay_bounty(
           incident_hash,
           submission.contributor_wallet,
           amount_lamports
         ) do
      # Payment succeeded
      now = DateTime.utc_now()

      # Update claim
      {:ok, updated_claim} = update_claim(claim, %{
        status: "paid",
        tx_id: tx_id,
        paid_at: now
      })

      # Update submission status
      update_submission(submission, %{status: "paid"})

      # Update linked alert if present
      if submission.linked_alert do
        update_alert_bounty(submission.linked_alert, tx_id, amount_lamports, now, submission.contributor_wallet)
      end

      Logger.info("[Bounties] Bounty paid: submission=#{submission.id}, tx=#{tx_id}, amount=#{amount_lamports}")

      {:ok, updated_claim}
    else
      {:error, :not_validated} ->
        {:error, "Submission must be validated before payment"}

      {:error, :not_bounty_eligible} ->
        {:error, "Submission bounty_eligibility must be 'eligible'. Use admin_override_pay_bounty/3 with explicit reason if override is justified."}

      {:error, :benchmark_only_not_validated} ->
        {:error, "Submission has benchmark_testable=true but no real validation (external TI or multi-org). Testability alone does not qualify for bounty payment. Use admin_override_pay_bounty/3 with explicit reason if override is justified."}

      {:error, :already_paid} ->
        {:error, "Bounty already paid for this submission"}

      {:error, reason} when is_atom(reason) ->
        Logger.error("[Bounties] Payment failed: submission=#{submission_id}, reason=#{inspect(reason)}")

        # Find the processing claim and mark as failed
        if claim = Repo.get_by(BountyClaim, submission_id: submission.id, status: "processing") do
          update_claim(claim, %{
            status: "failed",
            failure_reason: "Solana payment failed: #{inspect(reason)}"
          })
        end

        {:error, "Payment failed: #{inspect(reason)}"}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:error, changeset}

      {:error, reason} ->
        Logger.error("[Bounties] Payment failed: submission=#{submission_id}, reason=#{inspect(reason)}")

        if claim = Repo.get_by(BountyClaim, submission_id: submission.id, status: "processing") do
          update_claim(claim, %{
            status: "failed",
            failure_reason: "Solana payment failed: #{inspect(reason)}"
          })
        end

        {:error, "Payment failed: #{inspect(reason)}"}
    end
  end

  @doc """
  Pays a bounty for a validated submission scoped to an organization.
  """
  def pay_bounty_for_org(organization_id, submission_id, amount_lamports) when is_integer(amount_lamports) and amount_lamports > 0 do
    require Logger

    submission = get_submission_for_org!(organization_id, submission_id) |> Repo.preload(:linked_alert)

    with :ok <- validate_payment_eligible(submission),
         {:ok, claim} <- create_claim(%{
           submission_id: submission.id,
           alert_id: submission.linked_alert_id,
           amount_lamports: amount_lamports,
           status: "processing"
         }),
         incident_hash <- get_incident_hash(submission),
         {:ok, tx_id} <- TamanduaServer.Solana.Client.pay_bounty(
           incident_hash,
           submission.contributor_wallet,
           amount_lamports
         ) do
      # Payment succeeded
      now = DateTime.utc_now()

      # Update claim
      {:ok, updated_claim} = update_claim(claim, %{
        status: "paid",
        tx_id: tx_id,
        paid_at: now
      })

      # Update submission status
      update_submission(submission, %{status: "paid"})

      # Update linked alert if present
      if submission.linked_alert do
        update_alert_bounty(submission.linked_alert, tx_id, amount_lamports, now, submission.contributor_wallet)
      end

      Logger.info("[Bounties] Bounty paid: submission=#{submission.id}, tx=#{tx_id}, amount=#{amount_lamports}")

      {:ok, updated_claim}
    else
      {:error, :not_validated} ->
        {:error, "Submission must be validated before payment"}

      {:error, :not_bounty_eligible} ->
        {:error, "Submission bounty_eligibility must be 'eligible'. Use admin_override_pay_bounty/3 with explicit reason if override is justified."}

      {:error, :benchmark_only_not_validated} ->
        {:error, "Submission has benchmark_testable=true but no real validation (external TI or multi-org). Testability alone does not qualify for bounty payment. Use admin_override_pay_bounty/3 with explicit reason if override is justified."}

      {:error, :already_paid} ->
        {:error, "Bounty already paid for this submission"}

      {:error, reason} when is_atom(reason) ->
        Logger.error("[Bounties] Payment failed: submission=#{submission_id}, reason=#{inspect(reason)}")

        # Find the processing claim and mark as failed
        if claim = Repo.get_by(BountyClaim, submission_id: submission.id, status: "processing") do
          update_claim(claim, %{
            status: "failed",
            failure_reason: "Solana payment failed: #{inspect(reason)}"
          })
        end

        {:error, "Payment failed: #{inspect(reason)}"}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:error, changeset}

      {:error, reason} ->
        Logger.error("[Bounties] Payment failed: submission=#{submission_id}, reason=#{inspect(reason)}")

        if claim = Repo.get_by(BountyClaim, submission_id: submission.id, status: "processing") do
          update_claim(claim, %{
            status: "failed",
            failure_reason: "Solana payment failed: #{inspect(reason)}"
          })
        end

        {:error, "Payment failed: #{inspect(reason)}"}
    end
  end

  defp validate_payment_eligible(submission) do
    cond do
      submission.status != "validated" ->
        {:error, :not_validated}

      # SECURITY: Require bounty_eligibility == "eligible" before payment.
      # This prevents paying bounties for submissions that haven't passed
      # external correlation or multi-org verification.
      # Admin can use admin_override_pay_bounty/4 with explicit reason if needed.
      # STRICT: Only "eligible" status is accepted - nil is NOT allowed.
      submission.bounty_eligibility != "eligible" ->
        {:error, :not_bounty_eligible}

      # SECURITY: Explicitly block benchmark-only submissions from bounty payments.
      # benchmark_testable means tests EXIST for techniques, NOT that the rule works.
      # This is a critical anti-fraud check - testability alone is NOT validation.
      "benchmark_only_no_real_validation" in (submission.risk_flags || []) ->
        {:error, :benchmark_only_not_validated}

      Repo.exists?(from c in BountyClaim, where: c.submission_id == ^submission.id and c.status == "paid") ->
        {:error, :already_paid}

      true ->
        :ok
    end
  end

  @doc """
  Admin override for bounty payment on submissions that failed automated eligibility.

  Requires explicit reason and admin user ID that will be logged for audit purposes.
  Use sparingly - this bypasses automated anti-fraud checks.

  ## Parameters
    - submission_id: The submission to pay bounty for
    - amount_lamports: Amount in lamports to pay
    - admin_user_id: ID of the admin performing the override
    - admin_override_reason: Explanation (min 10 chars) for why override is justified
  """
  def admin_override_pay_bounty(submission_id, amount_lamports, admin_user_id, admin_override_reason)
      when is_binary(admin_override_reason) and byte_size(admin_override_reason) > 10 do
    require Logger

    submission = get_submission!(submission_id) |> Repo.preload(:linked_alert)

    # Log the override for audit
    Logger.warning(
      "[Bounties] ADMIN OVERRIDE: submission=#{submission_id}, " <>
      "eligibility=#{submission.bounty_eligibility}, " <>
      "admin_id=#{admin_user_id}, " <>
      "reason=#{admin_override_reason}"
    )

    # Store override in submission
    update_submission(submission, %{
      admin_override_reason: admin_override_reason,
      admin_override_at: DateTime.utc_now(),
      admin_override_by_id: admin_user_id
    })

    # Proceed with payment (bypasses eligibility check)
    with :ok <- validate_payment_eligible_override(submission),
         {:ok, claim} <- create_claim(%{
           submission_id: submission.id,
           alert_id: submission.linked_alert_id,
           amount_lamports: amount_lamports,
           status: "processing",
           admin_override: true,
           admin_override_reason: admin_override_reason,
           admin_override_by_id: admin_user_id
         }),
         incident_hash <- get_incident_hash(submission),
         {:ok, tx_id} <- TamanduaServer.Solana.Client.pay_bounty(
           incident_hash,
           submission.contributor_wallet,
           amount_lamports
         ) do
      now = DateTime.utc_now()

      {:ok, updated_claim} = update_claim(claim, %{
        status: "paid",
        tx_id: tx_id,
        paid_at: now
      })

      update_submission(submission, %{status: "paid"})

      if submission.linked_alert do
        update_alert_bounty(submission.linked_alert, tx_id, amount_lamports, now, submission.contributor_wallet)
      end

      Logger.info("[Bounties] ADMIN OVERRIDE paid: submission=#{submission.id}, tx=#{tx_id}, amount=#{amount_lamports}")

      {:ok, updated_claim}
    end
  end

  def admin_override_pay_bounty(_submission_id, _amount, _admin_user_id, reason) when is_binary(reason) do
    {:error, "Admin override reason must be at least 10 characters explaining why this override is justified"}
  end

  def admin_override_pay_bounty(_submission_id, _amount, _admin_user_id, _reason) do
    {:error, "Admin override reason is required and must be a string"}
  end

  defp validate_payment_eligible_override(submission) do
    cond do
      submission.status != "validated" ->
        {:error, :not_validated}

      Repo.exists?(from c in BountyClaim, where: c.submission_id == ^submission.id and c.status == "paid") ->
        {:error, :already_paid}

      true ->
        :ok
    end
  end

  defp get_incident_hash(%Submission{linked_alert: %{id: alert_id}}) when not is_nil(alert_id) do
    # Use alert ID as incident hash if linked
    :crypto.hash(:sha256, alert_id)
  end
  defp get_incident_hash(%Submission{id: submission_id}) do
    # Generate hash from submission ID
    :crypto.hash(:sha256, submission_id)
  end

  defp update_alert_bounty(alert, tx_id, amount_lamports, paid_at, rule_author_pubkey) do
    alias TamanduaServer.Alerts

    Alerts.update_alert(alert, %{
      bounty_tx_id: tx_id,
      bounty_amount_lamports: amount_lamports,
      bounty_paid_at: paid_at,
      rule_author_pubkey: rule_author_pubkey
    })
  end

  # Leaderboard and Wallet History

  @doc """
  Returns aggregated leaderboard statistics for contributors.

  Groups by wallet address and returns total lamports, submission count, and last payment date.
  Results are sorted by total lamports in descending order.

  ## Options

    * `:limit` - Maximum number of results (default: 50)

  ## Examples

      iex> leaderboard_stats()
      [%{wallet: "ABC...", total_lamports: 5000000000, submission_count: 3, last_payment: ~U[...]}, ...]

  """
  def leaderboard_stats(opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)

    from(c in BountyClaim,
      join: s in Submission, on: c.submission_id == s.id,
      where: c.status == "paid",
      group_by: s.contributor_wallet,
      select: %{
        wallet: s.contributor_wallet,
        total_lamports: sum(c.amount_lamports),
        submission_count: count(c.id),
        last_payment: max(c.paid_at)
      },
      order_by: [desc: sum(c.amount_lamports)],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Returns payment history for a specific wallet address.

  Lists all paid bounty claims associated with submissions from this wallet.

  ## Examples

      iex> wallet_history("ABC123...")
      [%{submission_id: "...", title: "...", type: "ioc", amount_lamports: 1000000000, tx_id: "...", paid_at: ~U[...]}, ...]

  """
  def wallet_history(wallet) do
    from(c in BountyClaim,
      join: s in Submission, on: c.submission_id == s.id,
      where: s.contributor_wallet == ^wallet and c.status == "paid",
      select: %{
        submission_id: s.id,
        title: s.title,
        type: s.type,
        amount_lamports: c.amount_lamports,
        tx_id: c.tx_id,
        paid_at: c.paid_at
      },
      order_by: [desc: c.paid_at]
    )
    |> Repo.all()
  end

  @doc """
  Returns all submissions from a specific wallet address.

  ## Examples

      iex> wallet_submissions("ABC123...")
      [%Submission{}, ...]

  """
  def wallet_submissions(wallet) do
    list_submissions(contributor_wallet: wallet)
  end
end
