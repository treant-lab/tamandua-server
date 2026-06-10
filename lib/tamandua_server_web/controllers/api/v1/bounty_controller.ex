defmodule TamanduaServerWeb.API.V1.BountyController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Bounties
  alias TamanduaServer.Bounties.{ContributorReputation, SubmissionValidator}
  alias TamanduaServer.Repo
  alias TamanduaServer.Solana.Client, as: SolanaClient

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Lists submissions with optional filters.
  """
  def index(conn, params) do
    filters = build_filters(params)
    submissions = Bounties.list_submissions(filters)
    render(conn, :index, submissions: submissions)
  end

  @doc """
  Shows a specific submission with claim information.
  """
  def show(conn, %{"id" => id}) do
    org_id = conn.assigns[:current_organization_id]
    submission = Bounties.get_submission_for_org!(org_id, id)

    # Try to load associated claim if exists
    claim = case Repo.get_by(TamanduaServer.Bounties.BountyClaim, submission_id: id) do
      nil -> nil
      c -> Repo.preload(c, [:submission, :alert])
    end

    render(conn, :show, submission: submission, claim: claim)
  end

  @doc """
  Validates a submission (admin only).
  Records the validation in contributor reputation.
  """
  def validate(conn, %{"id" => id} = params) do
    current_user = conn.assigns.current_user

    with :ok <- require_admin(conn) do
      org_id = conn.assigns[:current_organization_id]
      validation_result =
        id
        |> Bounties.get_submission_for_org!(org_id)
        |> SubmissionValidator.validate()

      case validation_result do
        {:ok, %{bounty_eligibility: "ineligible"} = submission} ->
          ContributorReputation.record_submission(submission.contributor_wallet, :rejected)

          conn
          |> put_status(:unprocessable_entity)
          |> json(%{
            error: "Submission is not bounty eligible",
            reason: submission.bounty_eligibility_reason,
            risk_flags: submission.risk_flags || [],
            bounty_eligibility: submission.bounty_eligibility
          })

        {:ok, _checked_submission} ->
          validate_reviewed_submission(conn, org_id, id, current_user.id, params)

        {:error, %Ecto.Changeset{} = changeset} ->
          conn
          |> put_status(:unprocessable_entity)
          |> put_view(TamanduaServerWeb.ChangesetJSON)
          |> render(:error, changeset: changeset)

        {:error, reason} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{error: "Submission validation failed", reason: inspect(reason)})
      end
    else
      {:error, :forbidden} -> forbidden(conn)
    end
  end

  defp validate_reviewed_submission(conn, org_id, id, user_id, params) do
    case Bounties.validate_submission_for_org(org_id, id, user_id) do
      {:ok, submission} ->
        fp_rate = parse_float(params["false_positive_rate"], submission.false_positive_rate || 0.0)
        coverage_delta = parse_float(params["coverage_delta"], submission.coverage_delta || 0.0)

        ContributorReputation.record_submission(
          submission.contributor_wallet,
          :validated,
          %{false_positive_rate: fp_rate, coverage_delta: coverage_delta}
        )

        conn
        |> put_status(:ok)
        |> render(:show, submission: submission, claim: nil)

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> put_view(TamanduaServerWeb.ChangesetJSON)
        |> render(:error, changeset: changeset)
    end
  end

  @doc """
  Rejects a submission with a reason (admin only).
  Records the rejection in contributor reputation.
  """
  def reject(conn, %{"id" => id, "reason" => reason}) do
    current_user = conn.assigns.current_user

    with :ok <- require_admin(conn) do
      org_id = conn.assigns[:current_organization_id]
      case Bounties.reject_submission_for_org(org_id, id, current_user.id, reason) do
        {:ok, submission} ->
          # Record rejection in reputation
          event_type = cond do
            String.contains?(reason, "duplicate") -> :duplicate
            String.contains?(reason, "pii") or String.contains?(reason, "PII") -> :pii_violation
            String.contains?(reason, "fraud") -> :fraud_flag
            true -> :rejected
          end

          ContributorReputation.record_submission(submission.contributor_wallet, event_type)

          conn
          |> put_status(:ok)
          |> render(:show, submission: submission, claim: nil)

        {:error, %Ecto.Changeset{} = changeset} ->
          conn
          |> put_status(:unprocessable_entity)
          |> put_view(TamanduaServerWeb.ChangesetJSON)
          |> render(:error, changeset: changeset)
      end
    else
      {:error, :forbidden} -> forbidden(conn)
    end
  end

  @doc """
  Pays a bounty for a validated submission (admin only).

  This function checks:
  1. Admin access required
  2. Submission must be validated
  3. Contributor reputation must allow this bounty amount
  4. High-value bounties (>0.5 SOL) require 2-of-3 validation
  """
  def pay(conn, %{"id" => id} = params) do
    with :ok <- require_admin(conn) do
      case parse_lamports(params["amount_lamports"]) do
        {:ok, amount} ->
          pay_valid_amount(conn, id, amount)

        {:error, reason} ->
          conn
          |> put_status(:bad_request)
          |> json(%{error: reason})
      end
    else
      {:error, :forbidden} -> forbidden(conn)
    end
  end

  defp pay_valid_amount(conn, id, amount) do
    org_id = conn.assigns[:current_organization_id]
    submission = Bounties.get_submission_for_org!(org_id, id)
    wallet = submission.contributor_wallet

    case ContributorReputation.check_bounty_requirements(wallet, amount, submission) do
      {:ok, :approved} ->
        case Bounties.pay_bounty_for_org(org_id, id, amount) do
          {:ok, claim} ->
            ContributorReputation.record_submission(wallet, :paid, %{amount_lamports: amount})

            solscan_url = SolanaClient.solscan_url(claim.tx_id)

            conn
            |> put_status(:ok)
            |> json(%{
              claim_id: claim.id,
              tx_id: claim.tx_id,
              solscan_url: solscan_url,
              amount_lamports: claim.amount_lamports,
              status: claim.status,
              paid_at: claim.paid_at,
              submission: %{
                id: submission.id,
                title: submission.title,
                status: submission.status
              },
              contributor: contributor_summary(wallet)
            })

          {:error, reason} when is_binary(reason) ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: reason})

          {:error, %Ecto.Changeset{} = changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> put_view(TamanduaServerWeb.ChangesetJSON)
            |> render(:error, changeset: changeset)
        end

      {:error, reason} when is_binary(reason) ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{
          error: "Bounty requirements not met",
          reason: reason,
          contributor: contributor_summary(wallet),
          high_value_threshold_sol: ContributorReputation.high_value_threshold_lamports() / 1_000_000_000
        })
    end
  end

  # Private helpers

  defp build_filters(params) do
    params
    |> Enum.filter(fn {key, _} -> key in ["status", "type", "organization_id", "contributor_wallet"] end)
    |> Enum.map(fn {key, value} -> {String.to_existing_atom(key), value} end)
  end

  defp require_admin(conn) do
    role = conn.assigns.current_user && conn.assigns.current_user.role

    if role in ["admin", "superadmin", "super_admin", "owner", :admin, :superadmin, :super_admin, :owner] do
      :ok
    else
      {:error, :forbidden}
    end
  end

  defp forbidden(conn) do
    conn
    |> put_status(:forbidden)
    |> json(%{error: "Admin access required"})
  end

  defp contributor_summary(wallet_address) when is_binary(wallet_address) do
    case ContributorReputation.get_or_default(wallet_address) do
      nil ->
        %{wallet: wallet_address, trust_tier: "unknown", error: "Could not fetch reputation"}

      reputation ->
        total_bounty_lamports = reputation.total_bounty_lamports || 0

        %{
          wallet: wallet_address,
          trust_tier: reputation.trust_tier,
          trust_tier_display: ContributorReputation.tier_display_name(reputation.trust_tier),
          reputation_score: reputation.reputation_score,
          validated_count: reputation.validated_count,
          paid_count: reputation.paid_count,
          total_bounty_sol: total_bounty_lamports / 1_000_000_000,
          can_receive_high_value: ContributorReputation.can_receive_high_value_bounty?(wallet_address),
          restricted: reputation.manually_restricted
        }
    end
  end

  defp contributor_summary(nil), do: nil

  # JSON rendering (inline for simplicity)

  def render("index.json", %{submissions: submissions}) do
    %{
      data: Enum.map(submissions, &submission_json/1)
    }
  end

  def render("show.json", %{submission: submission, claim: claim}) do
    %{
      data: submission
        |> submission_json()
        |> Map.put(:claim, claim_json(claim))
    }
  end

  defp submission_json(submission) do
    # SECURITY NOTE: benchmark_testable is informational only.
    # It does NOT qualify a submission for bounty payment.
    # Only external_correlations or org_observation_count count as real validation.
    has_real_validation = length(submission.external_correlations || []) > 0 or
                          (submission.org_observation_count || 0) >= 2

    benchmark_warning = if submission.benchmark_testable and not has_real_validation do
      "benchmark_testable=true is informational only. This submission needs external TI correlation or multi-org observation to be eligible for bounty payment."
    else
      nil
    end

    %{
      id: submission.id,
      type: submission.type,
      title: submission.title,
      description: submission.description,
      status: submission.status,
      contributor_wallet: submission.contributor_wallet,
      payload: submission.payload,
      linked_alert_id: submission.linked_alert_id,
      validated_by_id: submission.validated_by_id,
      validated_at: submission.validated_at,
      rejection_reason: submission.rejection_reason,
      bounty_eligibility: submission.bounty_eligibility,
      bounty_eligibility_reason: submission.bounty_eligibility_reason,
      risk_flags: submission.risk_flags || [],
      # SECURITY: benchmark_testable does NOT count as validation for bounty eligibility
      benchmark_testable: submission.benchmark_testable,
      benchmark_testable_warning: benchmark_warning,
      benchmark_source: submission.benchmark_source,
      has_real_validation: has_real_validation,
      false_positive_rate: submission.false_positive_rate,
      coverage_delta: submission.coverage_delta,
      external_correlations: submission.external_correlations || [],
      org_observation_count: submission.org_observation_count,
      syntax_valid: submission.syntax_valid,
      contributor: contributor_summary(submission.contributor_wallet),
      inserted_at: submission.inserted_at,
      updated_at: submission.updated_at
    }
  end

  defp claim_json(nil), do: nil
  defp claim_json(claim) do
    %{
      id: claim.id,
      amount_lamports: claim.amount_lamports,
      status: claim.status,
      tx_id: claim.tx_id,
      solscan_url: if(claim.tx_id, do: SolanaClient.solscan_url(claim.tx_id)),
      failure_reason: claim.failure_reason,
      paid_at: claim.paid_at
    }
  end

  defp parse_lamports(nil), do: {:error, "amount_lamports is required"}
  defp parse_lamports(value) when is_integer(value) and value > 0, do: {:ok, value}
  defp parse_lamports(value) when is_binary(value) do
    case Integer.parse(value) do
      {amount, ""} when amount > 0 -> {:ok, amount}
      _ -> {:error, "amount_lamports must be a positive integer"}
    end
  end
  defp parse_lamports(_), do: {:error, "amount_lamports must be a positive integer"}

  defp parse_float(nil, default), do: default
  defp parse_float(value, _default) when is_float(value), do: value
  defp parse_float(value, _default) when is_integer(value), do: value / 1
  defp parse_float(value, default) when is_binary(value) do
    case Float.parse(value) do
      {number, ""} -> number
      _ -> default
    end
  end
  defp parse_float(_value, default), do: default
end
