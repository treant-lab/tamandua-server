defmodule TamanduaServer.InsiderThreat.RiskScorer do
  @moduledoc """
  Risk scoring engine for insider threat detection.
  Calculates risk scores based on indicators and peer group comparison.
  """

  alias TamanduaServer.InsiderThreat.Indicator
  alias TamanduaServer.InsiderThreat.PeerGroup
  alias TamanduaServer.Repo

  import Ecto.Query

  @type risk_score :: %{
          total: float(),
          components: map(),
          indicators: [Indicator.t()],
          timestamp: DateTime.t(),
          trend: :increasing | :decreasing | :stable,
          threshold_exceeded: boolean()
        }

  @max_score 100.0
  @high_risk_threshold 70.0
  @medium_risk_threshold 40.0

  @doc """
  Calculate risk score for a user.
  """
  @spec calculate_score(Ecto.UUID.t(), [Indicator.t()], map()) :: risk_score()
  def calculate_score(user_id, indicators, opts \\ %{}) do
    # Base score from indicators
    indicator_score = calculate_indicator_score(indicators)

    # Peer group outlier score
    peer_group_score =
      case opts[:peer_group_id] do
        nil -> 0.0
        peer_group_id -> calculate_peer_group_score(user_id, peer_group_id, opts)
      end

    # Historical trend
    trend = calculate_trend(user_id, opts)

    # Combine scores
    total_score =
      (indicator_score + peer_group_score)
      |> min(@max_score)

    %{
      total: total_score,
      components: %{
        indicators: indicator_score,
        peer_group: peer_group_score
      },
      indicators: indicators,
      timestamp: DateTime.utc_now(),
      trend: trend,
      threshold_exceeded: total_score >= @high_risk_threshold,
      severity: get_severity(total_score)
    }
  end

  @doc """
  Calculate score from indicators only.
  """
  @spec calculate_indicator_score([Indicator.t()]) :: float()
  def calculate_indicator_score(indicators) do
    indicators
    |> Enum.map(& &1.weight)
    |> Enum.sum()
    |> min(@max_score)
  end

  @doc """
  Calculate peer group outlier contribution to risk score.
  """
  @spec calculate_peer_group_score(Ecto.UUID.t(), Ecto.UUID.t(), map()) :: float()
  def calculate_peer_group_score(user_id, peer_group_id, opts) do
    case PeerGroup.get(peer_group_id) do
      nil ->
        0.0

      peer_group ->
        metrics = opts[:user_metrics] || %{}
        deviations = calculate_deviations(peer_group, metrics)

        # Score based on number and magnitude of deviations
        deviations
        |> Enum.map(fn {_metric, deviation} ->
          cond do
            abs(deviation) > 3.0 -> 10.0
            abs(deviation) > 2.0 -> 5.0
            abs(deviation) > 1.5 -> 2.5
            true -> 0.0
          end
        end)
        |> Enum.sum()
        |> min(30.0)
    end
  end

  @doc """
  Calculate deviations from peer group baseline for all metrics.
  """
  @spec calculate_deviations(PeerGroup.t(), map()) :: map()
  def calculate_deviations(%PeerGroup{} = peer_group, user_metrics) do
    user_metrics
    |> Enum.map(fn {metric, value} ->
      deviation = PeerGroup.calculate_deviation(peer_group, metric, value)
      {metric, deviation}
    end)
    |> Map.new()
  end

  @doc """
  Calculate risk score trend (increasing/decreasing/stable).
  """
  @spec calculate_trend(Ecto.UUID.t(), map()) :: :increasing | :decreasing | :stable
  def calculate_trend(user_id, opts) do
    lookback_days = opts[:lookback_days] || 7

    query =
      from(a in "insider_threat_alerts",
        where:
          a.user_id == ^user_id and
            a.inserted_at >= ago(^lookback_days, "day"),
        select: %{
          risk_score: a.risk_score,
          inserted_at: a.inserted_at
        },
        order_by: [asc: a.inserted_at]
      )

    scores = Repo.all(query)

    case length(scores) do
      0 ->
        :stable

      1 ->
        :stable

      _ ->
        first_half_avg = calculate_average(Enum.take(scores, div(length(scores), 2)))
        second_half_avg = calculate_average(Enum.drop(scores, div(length(scores), 2)))

        cond do
          second_half_avg > first_half_avg * 1.2 -> :increasing
          second_half_avg < first_half_avg * 0.8 -> :decreasing
          true -> :stable
        end
    end
  end

  @doc """
  Get severity level from risk score.
  """
  @spec get_severity(float()) :: :critical | :high | :medium | :low
  def get_severity(score) when score >= @high_risk_threshold, do: :critical
  def get_severity(score) when score >= @medium_risk_threshold, do: :high
  def get_severity(score) when score >= 20.0, do: :medium
  def get_severity(_score), do: :low

  @doc """
  Check if score exceeds threshold.
  """
  @spec exceeds_threshold?(float(), atom()) :: boolean()
  def exceeds_threshold?(score, :high), do: score >= @high_risk_threshold
  def exceeds_threshold?(score, :medium), do: score >= @medium_risk_threshold
  def exceeds_threshold?(_score, _level), do: false

  @doc """
  Calculate risk factor breakdown.
  """
  @spec breakdown([Indicator.t()]) :: map()
  def breakdown(indicators) do
    indicators
    |> Enum.group_by(& &1.type)
    |> Enum.map(fn {type, inds} ->
      {type,
       %{
         count: length(inds),
         total_weight: Enum.sum(Enum.map(inds, & &1.weight)),
         severity: Indicator.get_severity(type)
       }}
    end)
    |> Map.new()
  end

  @doc """
  Get high risk threshold.
  """
  @spec high_risk_threshold() :: float()
  def high_risk_threshold, do: @high_risk_threshold

  @doc """
  Get medium risk threshold.
  """
  @spec medium_risk_threshold() :: float()
  def medium_risk_threshold, do: @medium_risk_threshold

  @doc """
  Calculate aggregated risk score for time window.
  """
  @spec aggregate_score(Ecto.UUID.t(), DateTime.t(), DateTime.t()) :: float()
  def aggregate_score(user_id, start_time, end_time) do
    query =
      from(a in "insider_threat_alerts",
        where:
          a.user_id == ^user_id and
            a.inserted_at >= ^start_time and
            a.inserted_at <= ^end_time,
        select: a.risk_score
      )

    scores = Repo.all(query)

    case scores do
      [] -> 0.0
      scores -> Enum.max(scores)
    end
  end

  # Private helpers

  defp calculate_average([]), do: 0.0

  defp calculate_average(scores) do
    Enum.sum(Enum.map(scores, & &1.risk_score)) / length(scores)
  end
end
