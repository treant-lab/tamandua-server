defmodule TamanduaServer.Solana.Bounty do
  @moduledoc """
  Detection bounty system for Tamanduá Sentinel.

  Rule authors can become eligible for gated rewards only when their detection rules
  successfully identify security incidents.

  ## How It Works

  1. A detection rule triggers an alert
  2. The alert is verified (automatically or by human review)
  3. The rule author receives a bounty payment

  ## Configuration

      config :tamandua_server, TamanduaServer.Solana.Bounty,
        default_bounty_lamports: 100_000_000,  # 0.1 SOL
        bounty_pool_pubkey: "...",
        enabled: true

  ## Bounty Tiers

  | Severity | Bounty (SOL) |
  |----------|--------------|
  | Info     | 0.01         |
  | Low      | 0.02         |
  | Medium   | 0.05         |
  | High     | 0.10         |
  | Critical | 0.25         |

  """

  require Logger

  alias TamanduaServer.Solana.{Client, Attestation}
  alias TamanduaServer.Alerts.Alert

  @lamports_per_sol 1_000_000_000

  @severity_bounties %{
    1 => 0.01 * @lamports_per_sol,  # Info
    2 => 0.02 * @lamports_per_sol,  # Low
    3 => 0.05 * @lamports_per_sol,  # Medium
    4 => 0.10 * @lamports_per_sol,  # High
    5 => 0.25 * @lamports_per_sol   # Critical
  }

  @doc """
  Pay a detection bounty for an alert.

  Returns `{:ok, tx_signature}` on success.
  """
  @spec pay_bounty(Alert.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def pay_bounty(%Alert{} = alert, rule_author_pubkey) do
    if enabled?() do
      do_pay_bounty(alert, rule_author_pubkey)
    else
      Logger.debug("Bounty system disabled")
      _ = rule_author_pubkey
      {:error, :bounty_disabled}
    end
  end

  @doc """
  Calculate the bounty amount for an alert based on severity.
  """
  @spec calculate_bounty(Alert.t() | integer()) :: non_neg_integer()
  def calculate_bounty(%Alert{severity: severity}) do
    calculate_bounty(severity_to_int(severity))
  end
  def calculate_bounty(severity) when is_integer(severity) do
    Map.get(@severity_bounties, severity, @severity_bounties[3])
    |> trunc()
  end

  @doc """
  Get bounty amount in SOL (human-readable).
  """
  @spec bounty_in_sol(Alert.t() | integer()) :: float()
  def bounty_in_sol(alert_or_severity) do
    calculate_bounty(alert_or_severity) / @lamports_per_sol
  end

  @doc """
  Format bounty for display.
  """
  @spec format_bounty(Alert.t() | integer()) :: String.t()
  def format_bounty(alert_or_severity) do
    sol = bounty_in_sol(alert_or_severity)
    "#{:erlang.float_to_binary(sol, decimals: 2)} SOL"
  end

  @doc """
  Check if bounty system is enabled.
  """
  def enabled? do
    config()[:enabled] != false
  end

  @doc """
  Get bounty statistics.
  """
  @spec stats() :: map()
  def stats do
    # In production, this would query the database
    %{
      total_paid_lamports: 0,
      total_paid_sol: 0.0,
      total_bounties: 0,
      top_hunters: [],
      top_rules: []
    }
  end

  # Private functions

  defp do_pay_bounty(%Alert{} = alert, rule_author_pubkey) do
    incident_hash = Attestation.compute_incident_hash(alert)
    amount_lamports = calculate_bounty(alert)

    case Client.pay_bounty(incident_hash, rule_author_pubkey, amount_lamports) do
      {:ok, signature} ->
        Logger.info("""
        Detection bounty paid!
          Alert: #{alert.id}
          Rule Author: #{rule_author_pubkey}
          Amount: #{format_bounty(alert)}
          TX: #{signature}
        """)

        {:ok, %{
          tx_signature: signature,
          amount_lamports: amount_lamports,
          amount_sol: amount_lamports / @lamports_per_sol,
          rule_author: rule_author_pubkey,
          solscan_url: Client.solscan_url(signature)
        }}

      {:error, reason} ->
        Logger.error("Failed to pay bounty for alert #{alert.id}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp severity_to_int(severity) when is_binary(severity) do
    case String.downcase(severity) do
      "info" -> 1
      "low" -> 2
      "medium" -> 3
      "high" -> 4
      "critical" -> 5
      _ -> 3
    end
  end
  defp severity_to_int(severity) when is_integer(severity), do: severity
  defp severity_to_int(_), do: 3

  defp config do
    Application.get_env(:tamandua_server, __MODULE__, [])
  end
end
