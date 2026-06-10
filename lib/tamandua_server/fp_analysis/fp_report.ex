defmodule TamanduaServer.FPAnalysis.FPReport do
  @moduledoc """
  Schema for False Positive reports submitted by analysts.

  FP Reports capture analyst feedback on alerts, including classification,
  reasoning, and contextual information that can be used to improve detection
  accuracy and reduce alert fatigue.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Alerts.Alert

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "fp_reports" do
    field :classification, :string
    field :confidence, :float, default: 1.0
    field :reason, :string
    field :reason_detail, :string
    field :tags, {:array, :string}, default: []

    # Alert snapshot
    field :alert_snapshot, :map, default: %{}

    # Detection info
    field :detection_source, :string
    field :rule_id, :string
    field :rule_name, :string

    # Environment context
    field :agent_id, :binary_id
    field :hostname, :string
    field :os_type, :string
    field :asset_criticality, :string

    # Process/file context
    field :process_name, :string
    field :file_path, :string
    field :file_hash, :string
    field :command_line, :string

    # User context
    field :event_user, :string
    field :user_role, :string

    # Actions taken
    field :suppression_rule_created, :boolean, default: false
    field :suppression_rule_id, :binary_id
    field :baseline_updated, :boolean, default: false
    field :threshold_adjusted, :boolean, default: false

    # Review workflow
    field :reviewed, :boolean, default: false
    field :reviewed_at, :utc_datetime_usec
    field :review_notes, :string

    belongs_to :alert, Alert
    belongs_to :organization, Organization
    belongs_to :reported_by, User, foreign_key: :reported_by_id, type: :binary_id
    belongs_to :reviewed_by, User, foreign_key: :reviewed_by_id, type: :binary_id

    timestamps(type: :utc_datetime_usec)
  end

  @valid_classifications ~w(true_positive false_positive benign suspicious)
  @valid_reasons ~w(
    known_good_software authorized_activity baseline_normal
    test_environment false_detection rule_too_broad
    expected_behavior user_verified other
  )
  @valid_detection_sources ~w(yara sigma ml behavioral ioc threat_intel)
  @valid_os_types ~w(windows linux macos)
  @valid_criticalities ~w(critical high medium low)

  @doc false
  def changeset(report, attrs) do
    report
    |> cast(attrs, [
      :alert_id, :organization_id, :reported_by_id,
      :classification, :confidence, :reason, :reason_detail, :tags,
      :alert_snapshot,
      :detection_source, :rule_id, :rule_name,
      :agent_id, :hostname, :os_type, :asset_criticality,
      :process_name, :file_path, :file_hash, :command_line,
      :event_user, :user_role,
      :suppression_rule_created, :suppression_rule_id,
      :baseline_updated, :threshold_adjusted,
      :reviewed, :reviewed_by_id, :reviewed_at, :review_notes
    ])
    |> validate_required([:classification])
    |> validate_inclusion(:classification, @valid_classifications)
    |> validate_inclusion(:reason, @valid_reasons ++ [nil])
    |> validate_inclusion(:detection_source, @valid_detection_sources ++ [nil])
    |> validate_inclusion(:os_type, @valid_os_types ++ [nil])
    |> validate_inclusion(:asset_criticality, @valid_criticalities ++ [nil])
    |> validate_number(:confidence, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> foreign_key_constraint(:alert_id)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:reported_by_id)
    |> foreign_key_constraint(:reviewed_by_id)
  end

  @doc """
  Create an FP report from an alert with extracted context.
  """
  def from_alert(alert, classification, opts \\ []) do
    user_id = Keyword.get(opts, :user_id)
    reason = Keyword.get(opts, :reason)
    reason_detail = Keyword.get(opts, :reason_detail)
    tags = Keyword.get(opts, :tags, [])

    # Extract context from alert
    evidence = alert.evidence || %{}
    process = evidence["process"] || evidence[:process] || %{}
    detection_meta = alert.detection_metadata || %{}

    %__MODULE__{}
    |> changeset(%{
      alert_id: alert.id,
      organization_id: alert.organization_id,
      reported_by_id: user_id,
      classification: classification,
      confidence: Keyword.get(opts, :confidence, 1.0),
      reason: reason,
      reason_detail: reason_detail,
      tags: tags,
      alert_snapshot: %{
        title: alert.title,
        severity: alert.severity,
        threat_score: alert.threat_score,
        mitre_tactics: alert.mitre_tactics,
        mitre_techniques: alert.mitre_techniques
      },
      detection_source: detection_meta["source"] || detection_meta[:source],
      rule_id: detection_meta["rule_id"] || detection_meta[:rule_id],
      rule_name: detection_meta["rule_name"] || detection_meta[:rule_name],
      agent_id: alert.agent_id,
      hostname: evidence["hostname"] || evidence[:hostname],
      process_name: process["name"] || process[:name],
      file_path: process["path"] || process[:path],
      file_hash: process["sha256"] || process[:sha256],
      command_line: process["command_line"] || process[:command_line],
      event_user: evidence["user"] || evidence[:user]
    })
  end

  @type t :: %__MODULE__{}
end
