defmodule TamanduaServer.AISecurity.BackdoorAnalysis.AnalysisRecord do
  @moduledoc """
  Ecto schema for AI model backdoor analysis records.

  Stores the results of deep backdoor analysis performed on AI/ML model files,
  including weight-based analysis and spectral (SVD) analysis results.

  ## Scores

  All scores are normalized to 0.0-1.0:
  - `weight_score` - Anomaly score from weight distribution analysis
  - `spectral_score` - Anomaly score from SVD/spectral analysis
  - `backdoor_score` - Combined score (0.4 * weight + 0.6 * spectral)

  A model is flagged as `is_suspicious` when `backdoor_score > 0.5`.

  ## Details Maps

  - `weight_details` - Per-layer statistics (mean, std, skewness, kurtosis)
  - `spectral_details` - SVD results (singular values, dominance, clustering)

  ## Outlier Layers

  Lists of layer names that were identified as statistical outliers:
  - `weight_outlier_layers` - Layers with abnormal weight distributions
  - `spectral_outlier_layers` - Layers with abnormal spectral signatures
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "ai_model_backdoor_analyses" do
    field :model_id, :string
    field :agent_id, :string
    field :file_hash, :string

    # Scores (0.0-1.0)
    field :weight_score, :float
    field :spectral_score, :float
    field :backdoor_score, :float

    # Suspicious flag
    field :is_suspicious, :boolean, default: false

    # Detailed results
    field :weight_details, :map, default: %{}
    field :spectral_details, :map, default: %{}

    # Outlier layers
    field :weight_outlier_layers, {:array, :string}, default: []
    field :spectral_outlier_layers, {:array, :string}, default: []

    # Metadata
    field :analysis_time_ms, :integer

    # Multi-tenancy
    field :organization_id, :binary_id

    timestamps()
  end

  @required_fields [:model_id]
  @optional_fields [
    :agent_id,
    :file_hash,
    :weight_score,
    :spectral_score,
    :backdoor_score,
    :is_suspicious,
    :weight_details,
    :spectral_details,
    :weight_outlier_layers,
    :spectral_outlier_layers,
    :analysis_time_ms,
    :organization_id
  ]

  @doc """
  Creates a changeset for inserting or updating an analysis record.

  Validates:
  - `model_id` is required
  - All scores are between 0.0 and 1.0
  - `analysis_time_ms` is non-negative if provided
  """
  @spec changeset(t() | Ecto.Changeset.t(), map()) :: Ecto.Changeset.t()
  def changeset(record, attrs) do
    record
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_score(:weight_score)
    |> validate_score(:spectral_score)
    |> validate_score(:backdoor_score)
    |> validate_number(:analysis_time_ms, greater_than_or_equal_to: 0)
  end

  # Validates that a score field is between 0.0 and 1.0
  defp validate_score(changeset, field) do
    validate_number(changeset, field,
      greater_than_or_equal_to: 0.0,
      less_than_or_equal_to: 1.0
    )
  end

  @type t :: %__MODULE__{
    id: binary() | nil,
    model_id: String.t() | nil,
    agent_id: String.t() | nil,
    file_hash: String.t() | nil,
    weight_score: float() | nil,
    spectral_score: float() | nil,
    backdoor_score: float() | nil,
    is_suspicious: boolean(),
    weight_details: map(),
    spectral_details: map(),
    weight_outlier_layers: [String.t()],
    spectral_outlier_layers: [String.t()],
    analysis_time_ms: integer() | nil,
    organization_id: binary() | nil,
    inserted_at: NaiveDateTime.t() | nil,
    updated_at: NaiveDateTime.t() | nil
  }
end
