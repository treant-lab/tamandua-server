defmodule TamanduaServer.Samples.Sample do
  @moduledoc """
  Schema for file samples submitted for ML analysis.

  Samples are uniquely identified by their SHA256 hash. When the same
  file is submitted multiple times, the submission_count is incremented
  and last_seen is updated rather than creating duplicate entries.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "samples" do
    field :sha256, :string
    field :sha1, :string
    field :md5, :string
    field :file_size, :integer
    field :file_type, :string
    field :file_name, :string
    field :source_agent_id, :binary_id
    field :source_path, :string

    # ML analysis results
    field :ml_score, :float
    field :ml_verdict, :string
    field :ml_family, :string
    field :ml_confidence, :float
    field :ml_analyzed_at, :utc_datetime_usec

    # Metadata
    field :is_signed, :boolean
    field :signer, :string
    field :entropy, :float
    field :first_seen, :utc_datetime_usec
    field :last_seen, :utc_datetime_usec
    field :submission_count, :integer, default: 1

    # Storage
    field :stored_path, :string

    # Virtual field for upload (not persisted)
    field :content_gzip, :binary, virtual: true

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields [:sha256]
  @optional_fields [
    :sha1,
    :md5,
    :file_size,
    :file_type,
    :file_name,
    :source_agent_id,
    :source_path,
    :ml_score,
    :ml_verdict,
    :ml_family,
    :ml_confidence,
    :ml_analyzed_at,
    :is_signed,
    :signer,
    :entropy,
    :first_seen,
    :last_seen,
    :submission_count,
    :stored_path
  ]

  @valid_verdicts ["malicious", "suspicious", "clean", "unknown"]

  @doc """
  Changeset for creating a new sample.
  """
  def changeset(sample, attrs) do
    sample
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_length(:sha256, is: 64)
    |> maybe_validate_length(:sha1, 40)
    |> maybe_validate_length(:md5, 32)
    |> validate_inclusion(:ml_verdict, @valid_verdicts)
    |> validate_number(:ml_score, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> validate_number(:ml_confidence, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> validate_number(:entropy, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 8.0)
    |> unique_constraint(:sha256)
  end

  # Only validate length if the field has a value
  defp maybe_validate_length(changeset, field, length) do
    case get_change(changeset, field) do
      nil -> changeset
      _ -> validate_length(changeset, field, is: length)
    end
  end

  @doc """
  Changeset for updating ML analysis results.
  """
  def ml_result_changeset(sample, attrs) do
    sample
    |> cast(attrs, [:ml_score, :ml_verdict, :ml_family, :ml_confidence, :ml_analyzed_at])
    |> validate_inclusion(:ml_verdict, @valid_verdicts)
    |> validate_number(:ml_score, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> validate_number(:ml_confidence, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
  end

  @doc """
  Changeset for updating submission metadata (when same hash is re-submitted).
  """
  def resubmit_changeset(sample, attrs) do
    sample
    |> cast(attrs, [:last_seen, :submission_count, :source_agent_id, :source_path])
    |> put_change(:submission_count, (sample.submission_count || 0) + 1)
    |> put_change(:last_seen, DateTime.utc_now())
  end

  @doc """
  Returns whether the sample has been analyzed by ML.
  """
  def analyzed?(%__MODULE__{ml_analyzed_at: nil}), do: false
  def analyzed?(%__MODULE__{}), do: true

  @doc """
  Returns whether the sample is considered malicious.
  """
  def malicious?(%__MODULE__{ml_verdict: "malicious"}), do: true
  def malicious?(%__MODULE__{}), do: false

  @doc """
  Returns the threat level based on ML results.
  """
  def threat_level(%__MODULE__{ml_verdict: "malicious", ml_confidence: conf}) when conf >= 0.9, do: :critical
  def threat_level(%__MODULE__{ml_verdict: "malicious", ml_confidence: conf}) when conf >= 0.7, do: :high
  def threat_level(%__MODULE__{ml_verdict: "malicious"}), do: :medium
  def threat_level(%__MODULE__{ml_verdict: "suspicious"}), do: :low
  def threat_level(%__MODULE__{}), do: :safe
end
