defmodule TamanduaServer.FPAnalysis.RuleQualityMetrics do
  @moduledoc """
  Schema for rule quality metrics.

  Tracks per-rule false positive and true positive statistics to calculate
  precision, quality scores, and detect patterns that indicate a rule needs
  tuning.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "rule_quality_metrics" do
    # Rule identification
    field :detection_source, :string
    field :rule_id, :string
    field :rule_name, :string
    field :rule_version, :string

    # Core metrics
    field :total_alerts, :integer, default: 0
    field :true_positives, :integer, default: 0
    field :false_positives, :integer, default: 0
    field :benign_count, :integer, default: 0
    field :suspicious_count, :integer, default: 0
    field :unclassified_count, :integer, default: 0

    # Calculated metrics
    field :precision, :float
    field :fp_rate, :float
    field :quality_score, :float

    # Trend data
    field :fp_rate_7d, :float
    field :fp_rate_30d, :float
    field :fp_rate_trend, :string

    # Time-based patterns
    field :fp_by_hour, :map, default: %{}
    field :fp_by_day_of_week, :map, default: %{}

    # Environment patterns
    field :fp_by_os, :map, default: %{}
    field :fp_by_asset_criticality, :map, default: %{}

    # Common FP contexts
    field :top_fp_processes, {:array, :map}, default: []
    field :top_fp_paths, {:array, :map}, default: []
    field :top_fp_users, {:array, :map}, default: []
    field :top_fp_agents, {:array, :map}, default: []

    # Suppression effectiveness
    field :suppressed_alerts, :integer, default: 0
    field :unsuppressed_fp_alerts, :integer, default: 0

    # Recommendation status
    field :tuning_recommendation, :string
    field :recommended_action, :map, default: %{}
    field :last_recommendation_at, :utc_datetime_usec

    # Metadata
    field :last_alert_at, :utc_datetime_usec
    field :first_alert_at, :utc_datetime_usec
    field :metrics_window_start, :utc_datetime_usec
    field :metrics_window_end, :utc_datetime_usec

    belongs_to :organization, Organization

    timestamps(type: :utc_datetime_usec)
  end

  @valid_detection_sources ~w(yara sigma ml behavioral ioc threat_intel)
  @valid_trends ~w(improving stable degrading unknown)
  @valid_recommendations ~w(tune_threshold add_exclusion disable modify none)

  @doc false
  def changeset(metrics, attrs) do
    metrics
    |> cast(attrs, [
      :organization_id, :detection_source, :rule_id, :rule_name, :rule_version,
      :total_alerts, :true_positives, :false_positives,
      :benign_count, :suspicious_count, :unclassified_count,
      :precision, :fp_rate, :quality_score,
      :fp_rate_7d, :fp_rate_30d, :fp_rate_trend,
      :fp_by_hour, :fp_by_day_of_week, :fp_by_os, :fp_by_asset_criticality,
      :top_fp_processes, :top_fp_paths, :top_fp_users, :top_fp_agents,
      :suppressed_alerts, :unsuppressed_fp_alerts,
      :tuning_recommendation, :recommended_action, :last_recommendation_at,
      :last_alert_at, :first_alert_at, :metrics_window_start, :metrics_window_end
    ])
    |> validate_required([:detection_source, :rule_id])
    |> validate_inclusion(:detection_source, @valid_detection_sources)
    |> validate_inclusion(:fp_rate_trend, @valid_trends ++ [nil])
    |> validate_inclusion(:tuning_recommendation, @valid_recommendations ++ [nil])
    |> validate_number(:precision, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> validate_number(:fp_rate, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> validate_number(:quality_score, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> foreign_key_constraint(:organization_id)
    |> unique_constraint([:organization_id, :detection_source, :rule_id])
  end

  @doc """
  Calculate derived metrics from raw counts.
  """
  def calculate_metrics(metrics) do
    total = metrics.total_alerts || 0
    tp = metrics.true_positives || 0
    fp = metrics.false_positives || 0

    precision = if tp + fp > 0, do: tp / (tp + fp), else: nil
    fp_rate = if total > 0, do: fp / total, else: nil

    # Quality score: weighted combination of precision and volume-adjusted factors
    quality_score = calculate_quality_score(precision, fp_rate, total)

    %{
      precision: precision && Float.round(precision, 4),
      fp_rate: fp_rate && Float.round(fp_rate, 4),
      quality_score: quality_score && Float.round(quality_score, 4)
    }
  end

  defp calculate_quality_score(nil, _, _), do: nil
  defp calculate_quality_score(_, nil, _), do: nil
  defp calculate_quality_score(precision, fp_rate, total) do
    # Confidence factor based on sample size
    confidence = min(1.0, total / 100)

    # Base quality from precision
    base_quality = precision

    # Penalty for high FP rate
    fp_penalty = min(fp_rate * 0.5, 0.3)

    # Final score
    (base_quality - fp_penalty) * confidence
    |> max(0.0)
    |> min(1.0)
  end

  @doc """
  Determine the trend direction based on 7d vs 30d FP rates.
  """
  def calculate_trend(fp_rate_7d, fp_rate_30d) do
    cond do
      is_nil(fp_rate_7d) or is_nil(fp_rate_30d) -> "unknown"
      fp_rate_7d < fp_rate_30d * 0.8 -> "improving"
      fp_rate_7d > fp_rate_30d * 1.2 -> "degrading"
      true -> "stable"
    end
  end

  @doc """
  Determine if a rule needs tuning based on its metrics.
  """
  def needs_tuning?(metrics) do
    cond do
      # High FP rate with sufficient sample size
      metrics.fp_rate && metrics.fp_rate > 0.3 && metrics.total_alerts >= 20 ->
        {:yes, :high_fp_rate, "FP rate of #{Float.round(metrics.fp_rate * 100, 1)}% exceeds 30%"}

      # Low precision
      metrics.precision && metrics.precision < 0.5 && metrics.total_alerts >= 20 ->
        {:yes, :low_precision, "Precision of #{Float.round(metrics.precision * 100, 1)}% is below 50%"}

      # Degrading trend
      metrics.fp_rate_trend == "degrading" && metrics.fp_rate_7d && metrics.fp_rate_7d > 0.2 ->
        {:yes, :degrading_trend, "FP rate is increasing (#{Float.round(metrics.fp_rate_7d * 100, 1)}% in last 7 days)"}

      # Very low quality score
      metrics.quality_score && metrics.quality_score < 0.3 && metrics.total_alerts >= 10 ->
        {:yes, :low_quality, "Quality score of #{Float.round(metrics.quality_score * 100, 1)}% is below threshold"}

      true ->
        {:no, nil, nil}
    end
  end

  @type t :: %__MODULE__{}
end
