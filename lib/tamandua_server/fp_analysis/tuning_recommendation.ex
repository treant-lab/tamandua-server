defmodule TamanduaServer.FPAnalysis.TuningRecommendation do
  @moduledoc """
  Schema for AI-generated tuning recommendations.

  Tuning recommendations are suggestions for improving detection accuracy,
  generated based on analysis of FP reports, rule quality metrics, and
  detected patterns.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "tuning_recommendations" do
    # Recommendation type
    field :recommendation_type, :string
    field :target_type, :string
    field :target_id, :string
    field :target_name, :string

    # Recommendation details
    field :title, :string
    field :description, :string
    field :rationale, :string
    field :impact_assessment, :string

    # Specific action
    field :action_data, :map, default: %{}

    # Supporting data
    field :supporting_metrics, :map, default: %{}
    field :related_fp_report_ids, {:array, :binary_id}, default: []
    field :related_pattern_ids, {:array, :binary_id}, default: []

    # Confidence and priority
    field :confidence, :float, default: 0.5
    field :priority, :string, default: "medium"
    field :estimated_fp_reduction, :float

    # Status
    field :status, :string, default: "pending"
    field :expires_at, :utc_datetime_usec

    # Application tracking
    field :applied_at, :utc_datetime_usec
    field :applied_result, :map, default: %{}

    # Review
    field :reviewed_at, :utc_datetime_usec
    field :review_notes, :string

    # Effectiveness tracking
    field :effectiveness_measured, :boolean, default: false
    field :effectiveness_score, :float
    field :measured_at, :utc_datetime_usec

    belongs_to :organization, Organization
    belongs_to :applied_by, User, foreign_key: :applied_by_id, type: :binary_id
    belongs_to :reviewed_by, User, foreign_key: :reviewed_by_id, type: :binary_id

    timestamps(type: :utc_datetime_usec)
  end

  @valid_types ~w(threshold_adjustment exclusion_rule disable_rule modify_rule baseline_update)
  @valid_target_types ~w(rule detection_source agent environment organization)
  @valid_priorities ~w(critical high medium low)
  @valid_statuses ~w(pending approved rejected applied expired)

  @doc false
  def changeset(recommendation, attrs) do
    recommendation
    |> cast(attrs, [
      :organization_id, :recommendation_type, :target_type, :target_id, :target_name,
      :title, :description, :rationale, :impact_assessment,
      :action_data, :supporting_metrics, :related_fp_report_ids, :related_pattern_ids,
      :confidence, :priority, :estimated_fp_reduction,
      :status, :expires_at,
      :applied_at, :applied_by_id, :applied_result,
      :reviewed_at, :reviewed_by_id, :review_notes,
      :effectiveness_measured, :effectiveness_score, :measured_at
    ])
    |> validate_required([:recommendation_type, :target_type, :title, :action_data])
    |> validate_inclusion(:recommendation_type, @valid_types)
    |> validate_inclusion(:target_type, @valid_target_types)
    |> validate_inclusion(:priority, @valid_priorities)
    |> validate_inclusion(:status, @valid_statuses)
    |> validate_number(:confidence, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> validate_number(:estimated_fp_reduction, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> validate_number(:effectiveness_score, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:applied_by_id)
    |> foreign_key_constraint(:reviewed_by_id)
  end

  @doc """
  Create a threshold adjustment recommendation.
  """
  def threshold_adjustment(opts) do
    %__MODULE__{}
    |> changeset(%{
      recommendation_type: "threshold_adjustment",
      target_type: "rule",
      target_id: opts[:rule_id],
      target_name: opts[:rule_name],
      title: "Adjust detection threshold for #{opts[:rule_name]}",
      description: "Increase the detection threshold to reduce false positives",
      rationale: opts[:rationale],
      action_data: %{
        "type" => "threshold",
        "current_value" => opts[:current_threshold],
        "recommended_value" => opts[:recommended_threshold],
        "detection_source" => opts[:detection_source]
      },
      supporting_metrics: opts[:metrics] || %{},
      confidence: opts[:confidence] || 0.7,
      priority: calculate_priority(opts[:fp_rate], opts[:alert_volume]),
      estimated_fp_reduction: estimate_threshold_impact(opts[:current_threshold], opts[:recommended_threshold]),
      organization_id: opts[:organization_id],
      expires_at: DateTime.add(DateTime.utc_now(), 30 * 24 * 3600, :second)
    })
  end

  @doc """
  Create an exclusion rule recommendation.
  """
  def exclusion_rule(opts) do
    %__MODULE__{}
    |> changeset(%{
      recommendation_type: "exclusion_rule",
      target_type: opts[:target_type] || "rule",
      target_id: opts[:target_id],
      target_name: opts[:target_name],
      title: "Create exclusion rule for #{opts[:target_name]}",
      description: "Add an exclusion rule to filter known false positive patterns",
      rationale: opts[:rationale],
      action_data: %{
        "type" => "exclusion",
        "criteria" => opts[:criteria],
        "action" => "suppress",
        "ttl_days" => opts[:ttl_days] || 30
      },
      supporting_metrics: opts[:metrics] || %{},
      related_pattern_ids: opts[:pattern_ids] || [],
      confidence: opts[:confidence] || 0.8,
      priority: opts[:priority] || "medium",
      estimated_fp_reduction: opts[:estimated_reduction] || 0.5,
      organization_id: opts[:organization_id],
      expires_at: DateTime.add(DateTime.utc_now(), 14 * 24 * 3600, :second)
    })
  end

  @doc """
  Create a disable rule recommendation.
  """
  def disable_rule(opts) do
    %__MODULE__{}
    |> changeset(%{
      recommendation_type: "disable_rule",
      target_type: "rule",
      target_id: opts[:rule_id],
      target_name: opts[:rule_name],
      title: "Consider disabling rule: #{opts[:rule_name]}",
      description: "This rule has a very high false positive rate and may not be providing value",
      rationale: opts[:rationale],
      impact_assessment: "Disabling will eliminate #{opts[:alert_count]} alerts/week. " <>
                         "Review for potential true positives before disabling.",
      action_data: %{
        "type" => "disable",
        "rule_id" => opts[:rule_id],
        "detection_source" => opts[:detection_source]
      },
      supporting_metrics: opts[:metrics] || %{},
      confidence: opts[:confidence] || 0.6,
      priority: "low",
      estimated_fp_reduction: opts[:fp_rate] || 0.9,
      organization_id: opts[:organization_id],
      expires_at: DateTime.add(DateTime.utc_now(), 7 * 24 * 3600, :second)
    })
  end

  defp calculate_priority(fp_rate, alert_volume) do
    cond do
      fp_rate && fp_rate > 0.7 && alert_volume && alert_volume > 100 -> "critical"
      fp_rate && fp_rate > 0.5 && alert_volume && alert_volume > 50 -> "high"
      fp_rate && fp_rate > 0.3 -> "medium"
      true -> "low"
    end
  end

  defp estimate_threshold_impact(current, recommended) when is_number(current) and is_number(recommended) do
    # Rough estimate: each 0.1 increase in threshold reduces ~20% of alerts
    diff = recommended - current
    min(1.0, diff * 2.0)
    |> max(0.0)
    |> Float.round(2)
  end
  defp estimate_threshold_impact(_, _), do: 0.2

  @type t :: %__MODULE__{}
end
