defmodule TamanduaServer.MlRules.MlRule do
  @moduledoc """
  Schema for ML-generated detection rules.

  These rules are automatically generated from threat hunting campaigns
  and optimized using historical data.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @rule_types ~w(yara sigma ml_custom)
  @severities ~w(low medium high critical)
  @ab_test_groups ~w(control variant_a variant_b)

  schema "ml_rules" do
    field :rule_id, :string
    field :rule_type, :string
    field :name, :string
    field :description, :string
    field :content, :string
    field :severity, :string, default: "medium"
    field :enabled, :boolean, default: false
    field :approved, :boolean, default: false
    field :approved_at, :utc_datetime_usec
    belongs_to :approved_by, TamanduaServer.Accounts.User

    # Generation metadata
    field :hunt_campaign, :string
    belongs_to :hunt_session, TamanduaServer.Hunting.HuntSession
    field :finding_count, :integer
    field :confidence_score, :float

    # MITRE ATT&CK
    field :mitre_techniques, {:array, :string}, default: []
    field :tags, {:array, :string}, default: []

    # Optimization metrics
    field :precision, :float
    field :recall, :float
    field :f1_score, :float
    field :true_positives, :integer
    field :false_positives, :integer
    field :true_negatives, :integer
    field :false_negatives, :integer

    # Optimization parameters
    field :optimized_params, :map, default: %{}
    field :optimization_trials, :integer
    field :validation_passed, :boolean, default: false

    # A/B testing
    field :ab_test_group, :string
    field :ab_test_start, :utc_datetime_usec
    field :ab_test_end, :utc_datetime_usec
    field :ab_test_metrics, :map, default: %{}

    # Version control
    field :version, :integer, default: 1
    belongs_to :parent_rule, __MODULE__

    # Metadata
    field :metadata, :map, default: %{}

    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(rule_id rule_type name content)a
  @optional_fields ~w(description severity enabled approved approved_at approved_by_id
                      hunt_campaign hunt_session_id finding_count confidence_score
                      mitre_techniques tags precision recall f1_score true_positives
                      false_positives true_negatives false_negatives optimized_params
                      optimization_trials validation_passed ab_test_group ab_test_start
                      ab_test_end ab_test_metrics version parent_rule_id metadata
                      organization_id)a

  @doc false
  def changeset(ml_rule, attrs) do
    ml_rule
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:rule_type, @rule_types)
    |> validate_inclusion(:severity, @severities)
    |> validate_inclusion(:ab_test_group, @ab_test_groups, allow_nil: true)
    |> validate_number(:confidence_score, greater_than_or_equal_to: 0, less_than_or_equal_to: 1)
    |> validate_number(:precision, greater_than_or_equal_to: 0, less_than_or_equal_to: 1)
    |> validate_number(:recall, greater_than_or_equal_to: 0, less_than_or_equal_to: 1)
    |> validate_number(:f1_score, greater_than_or_equal_to: 0, less_than_or_equal_to: 1)
    |> validate_number(:version, greater_than: 0)
    |> unique_constraint([:rule_id, :organization_id])
  end

  def approval_changeset(ml_rule, attrs) do
    ml_rule
    |> cast(attrs, [:approved, :approved_at, :approved_by_id, :enabled])
    |> validate_required([:approved])
  end

  def ab_test_changeset(ml_rule, attrs) do
    ml_rule
    |> cast(attrs, [:ab_test_group, :ab_test_start, :ab_test_end, :ab_test_metrics])
    |> validate_inclusion(:ab_test_group, @ab_test_groups)
  end
end
