defmodule TamanduaServer.FPAnalysis.BaselineProfile do
  @moduledoc """
  Schema for environment-specific behavioral baselines.

  Baseline profiles capture normal behavior patterns for organizations, agents,
  users, or asset types. These baselines help distinguish true positives from
  false positives by identifying what is "normal" for a specific context.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "baseline_profiles" do
    # Profile identification
    field :profile_type, :string
    field :profile_key, :string
    field :profile_name, :string

    # Status
    field :status, :string, default: "learning"
    field :learning_started_at, :utc_datetime_usec
    field :learning_completed_at, :utc_datetime_usec
    field :learning_days, :integer, default: 7

    # Event statistics
    field :total_events_processed, :integer, default: 0
    field :events_per_day_avg, :float, default: 0.0
    field :events_per_hour_histogram, :map, default: %{}

    # Process baselines
    field :normal_processes, {:array, :string}, default: []
    field :process_frequencies, :map, default: %{}
    field :process_parent_pairs, {:array, :map}, default: []

    # Network baselines
    field :normal_destinations, {:array, :string}, default: []
    field :normal_ports, {:array, :integer}, default: []
    field :network_volume_baseline, :map, default: %{}

    # File access baselines
    field :normal_file_paths, {:array, :string}, default: []
    field :normal_file_extensions, {:array, :string}, default: []

    # Authentication baselines
    field :normal_login_hours, {:array, :integer}, default: []
    field :normal_login_days, {:array, :integer}, default: []
    field :normal_auth_sources, {:array, :string}, default: []

    # Detection baselines
    field :expected_rules, {:array, :string}, default: []
    field :rule_frequencies, :map, default: %{}

    # Anomaly thresholds
    field :thresholds, :map, default: %{}

    # Metadata
    field :last_updated_at, :utc_datetime_usec
    field :metadata, :map, default: %{}

    belongs_to :organization, Organization

    timestamps(type: :utc_datetime_usec)
  end

  @valid_profile_types ~w(organization agent_group agent user asset_type)
  @valid_statuses ~w(learning active frozen stale)

  @doc false
  def changeset(profile, attrs) do
    profile
    |> cast(attrs, [
      :organization_id, :profile_type, :profile_key, :profile_name,
      :status, :learning_started_at, :learning_completed_at, :learning_days,
      :total_events_processed, :events_per_day_avg, :events_per_hour_histogram,
      :normal_processes, :process_frequencies, :process_parent_pairs,
      :normal_destinations, :normal_ports, :network_volume_baseline,
      :normal_file_paths, :normal_file_extensions,
      :normal_login_hours, :normal_login_days, :normal_auth_sources,
      :expected_rules, :rule_frequencies, :thresholds,
      :last_updated_at, :metadata
    ])
    |> validate_required([:profile_type, :profile_key])
    |> validate_inclusion(:profile_type, @valid_profile_types)
    |> validate_inclusion(:status, @valid_statuses)
    |> validate_number(:learning_days, greater_than_or_equal_to: 1, less_than_or_equal_to: 90)
    |> foreign_key_constraint(:organization_id)
    |> unique_constraint([:organization_id, :profile_type, :profile_key])
  end

  @doc """
  Check if a process is in the baseline for this profile.
  """
  def process_in_baseline?(%__MODULE__{} = profile, process_name) do
    normalized = String.downcase(process_name || "")
    Enum.any?(profile.normal_processes, fn p ->
      String.downcase(p) == normalized
    end)
  end

  @doc """
  Check if a destination is in the baseline for this profile.
  """
  def destination_in_baseline?(%__MODULE__{} = profile, destination) do
    normalized = String.downcase(destination || "")
    Enum.any?(profile.normal_destinations, fn d ->
      String.downcase(d) == normalized or String.ends_with?(normalized, "." <> String.downcase(d))
    end)
  end

  @doc """
  Check if a rule commonly fires for this profile (expected detection).
  """
  def rule_expected?(%__MODULE__{} = profile, rule_id) do
    rule_id in (profile.expected_rules || [])
  end

  @doc """
  Calculate how anomalous a value is compared to the baseline.
  Returns a score from 0.0 (normal) to 1.0 (highly anomalous).
  """
  def calculate_anomaly_score(%__MODULE__{} = profile, metric_name, value) do
    case Map.get(profile.thresholds, metric_name) do
      nil ->
        # No baseline for this metric, neutral score
        0.5

      %{"mean" => mean, "stddev" => stddev} when stddev > 0 ->
        # Z-score based anomaly detection
        z_score = abs(value - mean) / stddev
        # Convert to 0-1 range, capping at 3 standard deviations
        min(1.0, z_score / 3.0)

      %{"mean" => mean} ->
        # No variance, check if value matches mean
        if value == mean, do: 0.0, else: 0.7

      _ ->
        0.5
    end
  end

  @doc """
  Check if the profile has completed learning.
  """
  def learning_complete?(%__MODULE__{status: "active"}), do: true
  def learning_complete?(%__MODULE__{status: "frozen"}), do: true
  def learning_complete?(%__MODULE__{} = profile) do
    if profile.learning_started_at do
      days_elapsed = DateTime.diff(DateTime.utc_now(), profile.learning_started_at, :day)
      days_elapsed >= (profile.learning_days || 7)
    else
      false
    end
  end

  @type t :: %__MODULE__{}
end
