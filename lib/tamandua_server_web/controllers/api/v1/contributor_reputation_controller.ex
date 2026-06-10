defmodule TamanduaServerWeb.API.V1.ContributorReputationController do
  @moduledoc """
  API controller for contributor reputation management.
  """
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Bounties.ContributorReputation

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Gets the leaderboard of top contributors.
  """
  def leaderboard(conn, params) do
    limit = params["limit"] |> parse_int(50)
    min_score = params["min_score"] |> parse_int(0)

    contributors = ContributorReputation.leaderboard(limit: limit, min_score: min_score)

    json(conn, %{
      data: Enum.map(contributors, &reputation_json/1),
      meta: %{
        limit: limit,
        min_score: min_score,
        count: length(contributors)
      }
    })
  end

  @doc """
  Gets a specific contributor's reputation.
  """
  def show(conn, %{"wallet" => wallet_address}) do
    case ContributorReputation.get_or_default(wallet_address) do
      nil ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "wallet parameter is required"})

      reputation ->
        persisted = not is_nil(reputation.id)
        json(conn, %{data: reputation_json(reputation, persisted: persisted)})
    end
  end

  @doc """
  Recalculates a contributor's reputation from scratch (admin only).
  """
  def recalculate(conn, %{"wallet" => wallet_address}) do
    with :ok <- require_admin(conn) do
      case ContributorReputation.recalculate(wallet_address) do
        {:ok, reputation} ->
          json(conn, %{
            message: "Reputation recalculated",
            data: reputation_json(reputation)
          })

        {:error, reason} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{error: inspect(reason)})
      end
    else
      {:error, :forbidden} -> forbidden(conn)
    end
  end

  @doc """
  Restricts a contributor (admin only).
  """
  def restrict(conn, %{"wallet" => wallet_address, "reason" => reason}) do
    with :ok <- require_admin(conn) do
      case ContributorReputation.restrict(wallet_address, reason) do
        {:ok, reputation} ->
          json(conn, %{
            message: "Contributor restricted",
            data: reputation_json(reputation)
          })

        {:error, reason} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{error: inspect(reason)})
      end
    else
      {:error, :forbidden} -> forbidden(conn)
    end
  end

  # Fallback for missing reason
  def restrict(conn, %{"wallet" => _wallet}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "reason parameter is required"})
  end

  @doc """
  Unrestricts a contributor (admin only).
  """
  def unrestrict(conn, %{"wallet" => wallet_address}) do
    with :ok <- require_admin(conn) do
      case ContributorReputation.unrestrict(wallet_address) do
        {:ok, reputation} ->
          json(conn, %{
            message: "Contributor unrestricted",
            data: reputation_json(reputation)
          })

        {:error, reason} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{error: inspect(reason)})
      end
    else
      {:error, :forbidden} -> forbidden(conn)
    end
  end

  @doc """
  Checks if a contributor can receive high-value bounties.
  """
  def can_high_value(conn, %{"wallet" => wallet_address}) do
    can = ContributorReputation.can_receive_high_value_bounty?(wallet_address)
    threshold = ContributorReputation.high_value_threshold_lamports()
    reputation = ContributorReputation.get_or_default(wallet_address)

    json(conn, %{
      wallet: wallet_address,
      can_receive_high_value: can,
      trust_tier: reputation && reputation.trust_tier,
      threshold_lamports: threshold,
      threshold_sol: threshold / 1_000_000_000
    })
  end

  # Private helpers

  defp reputation_json(reputation, opts \\ []) do
    total_bounty_lamports = reputation.total_bounty_lamports || 0

    %{
      id: reputation.id,
      wallet_address: reputation.wallet_address,
      persisted: Keyword.get(opts, :persisted, true),
      # Counts
      total_submissions: reputation.total_submissions,
      validated_count: reputation.validated_count,
      rejected_count: reputation.rejected_count,
      duplicate_count: reputation.duplicate_count,
      paid_count: reputation.paid_count,
      # Bounty stats
      total_bounty_lamports: total_bounty_lamports,
      total_bounty_sol: total_bounty_lamports / 1_000_000_000,
      avg_bounty_lamports: reputation.avg_bounty_lamports,
      # Quality metrics
      avg_fp_rate: reputation.avg_fp_rate,
      avg_coverage_delta: reputation.avg_coverage_delta,
      rules_reused_count: reputation.rules_reused_count,
      # Violations
      pii_violation_count: reputation.pii_violation_count,
      fraud_flag_count: reputation.fraud_flag_count,
      # Computed
      reputation_score: reputation.reputation_score,
      trust_tier: reputation.trust_tier,
      trust_tier_display: ContributorReputation.tier_display_name(reputation.trust_tier),
      can_receive_high_value: ContributorReputation.can_receive_high_value_bounty?(reputation.wallet_address),
      # Timestamps
      first_submission_at: reputation.first_submission_at,
      last_submission_at: reputation.last_submission_at,
      last_paid_at: reputation.last_paid_at,
      # Admin
      manually_restricted: reputation.manually_restricted,
      restriction_reason: reputation.restriction_reason,
      notes: reputation.notes
    }
  end

  defp parse_int(nil, default), do: default
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {n, _} -> n
      :error -> default
    end
  end
  defp parse_int(value, _default) when is_integer(value), do: value

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
end
