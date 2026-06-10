defmodule TamanduaServer.FPAnalysis.FPPattern do
  @moduledoc """
  Schema for detected false positive patterns.

  FP Patterns represent recurring patterns in false positive reports that can
  be used to automatically generate suppression rules or tuning recommendations.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "fp_patterns" do
    # Pattern identification
    field :pattern_type, :string
    field :pattern_key, :string
    field :pattern_data, :map, default: %{}
    field :description, :string

    # Detection source association
    field :detection_source, :string
    field :associated_rules, {:array, :string}, default: []

    # Statistics
    field :fp_count, :integer, default: 0
    field :tp_count, :integer, default: 0
    field :total_matches, :integer, default: 0
    field :fp_confidence, :float, default: 0.0

    # Example alerts
    field :example_alert_ids, {:array, :binary_id}, default: []

    # Auto-tuning status
    field :suppression_created, :boolean, default: false
    field :suppression_rule_id, :binary_id
    field :auto_tuned_at, :utc_datetime_usec

    # Manual review
    field :reviewed, :boolean, default: false
    field :reviewed_at, :utc_datetime_usec
    field :review_action, :string

    # Time window
    field :first_seen_at, :utc_datetime_usec
    field :last_seen_at, :utc_datetime_usec

    # Status
    field :status, :string, default: "detected"

    belongs_to :organization, Organization
    belongs_to :reviewed_by, User, foreign_key: :reviewed_by_id, type: :binary_id

    timestamps(type: :utc_datetime_usec)
  end

  @valid_pattern_types ~w(process path time user rule agent host combined)
  @valid_detection_sources ~w(yara sigma ml behavioral ioc threat_intel)
  @valid_statuses ~w(detected confirmed rejected tuned)
  @valid_review_actions ~w(approve_suppression reject modify pending)

  @doc false
  def changeset(pattern, attrs) do
    pattern
    |> cast(attrs, [
      :organization_id, :pattern_type, :pattern_key, :pattern_data, :description,
      :detection_source, :associated_rules,
      :fp_count, :tp_count, :total_matches, :fp_confidence,
      :example_alert_ids,
      :suppression_created, :suppression_rule_id, :auto_tuned_at,
      :reviewed, :reviewed_by_id, :reviewed_at, :review_action,
      :first_seen_at, :last_seen_at, :status
    ])
    |> validate_required([:pattern_type, :pattern_key, :pattern_data])
    |> validate_inclusion(:pattern_type, @valid_pattern_types)
    |> validate_inclusion(:detection_source, @valid_detection_sources ++ [nil])
    |> validate_inclusion(:status, @valid_statuses)
    |> validate_inclusion(:review_action, @valid_review_actions ++ [nil])
    |> validate_number(:fp_confidence, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:reviewed_by_id)
    |> unique_constraint([:organization_id, :pattern_type, :pattern_key])
  end

  @doc """
  Calculate FP confidence based on counts.
  """
  def calculate_fp_confidence(fp_count, tp_count, total_matches) do
    if total_matches > 0 do
      # Base confidence from FP ratio
      fp_ratio = fp_count / total_matches

      # Confidence factor based on sample size
      sample_confidence = min(1.0, total_matches / 20)

      # Penalty if there are any TPs
      tp_penalty = if tp_count > 0, do: tp_count / total_matches * 0.5, else: 0

      (fp_ratio * sample_confidence - tp_penalty)
      |> max(0.0)
      |> min(1.0)
      |> Float.round(4)
    else
      0.0
    end
  end

  @doc """
  Check if this pattern is ready for auto-tuning.
  """
  def ready_for_auto_tuning?(%__MODULE__{} = pattern) do
    # Must have high FP confidence
    high_confidence = pattern.fp_confidence >= 0.8

    # Must have sufficient sample size
    sufficient_samples = pattern.fp_count >= 5

    # Must not have significant TP count
    low_tp = pattern.tp_count <= 1

    # Must not already be tuned
    not_tuned = not pattern.suppression_created

    high_confidence and sufficient_samples and low_tp and not_tuned
  end

  @doc """
  Generate a suppression rule criteria from this pattern.
  """
  def to_suppression_criteria(%__MODULE__{} = pattern) do
    pattern_data = pattern.pattern_data

    criteria = %{}

    criteria = case pattern.pattern_type do
      "process" ->
        Map.merge(criteria, %{
          "process_name_pattern" => pattern_data["process_name"],
          "parent_process_pattern" => pattern_data["parent_process"]
        })

      "path" ->
        Map.merge(criteria, %{
          "file_path_pattern" => pattern_data["path_pattern"]
        })

      "rule" ->
        Map.merge(criteria, %{
          "rule_name_pattern" => pattern_data["rule_name"]
        })

      "user" ->
        Map.merge(criteria, %{
          "criteria" => %{"event_user" => pattern_data["user"]}
        })

      "host" ->
        Map.merge(criteria, %{
          "criteria" => %{"hostname" => pattern_data["hostname"]}
        })

      "combined" ->
        Map.merge(criteria, pattern_data)

      _ ->
        criteria
    end

    # Add detection source filter if specific
    if pattern.detection_source do
      Map.put(criteria, "criteria", Map.merge(
        criteria["criteria"] || %{},
        %{"detection_source" => pattern.detection_source}
      ))
    else
      criteria
    end
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  @type t :: %__MODULE__{}
end
