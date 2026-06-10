defmodule TamanduaServer.Registries.ModelProvenance do
  @moduledoc """
  Ecto schema for tracking AI model provenance and security scan results.

  Maintains an audit trail of all AI models downloaded from registries (HuggingFace,
  MLflow, W&B, Ollama), including their security scan results, risk scores, and metadata.

  ## Fields

  - `model_id` - Registry model identifier (e.g., "meta-llama/Llama-2-7b")
  - `registry` - Source registry ("huggingface", "mlflow", "wandb", "ollama")
  - `sha256` - Model file hash for integrity verification
  - `version` - Model version/revision (registry-specific)
  - `downloaded_at` - When the model was first downloaded
  - `scanned_at` - When security scanning completed
  - `scan_result` - Full scan result from ML service (map)
  - `risk_score` - Extracted risk score for quick queries (0.0-1.0)
  - `findings_count` - Number of security findings detected
  - `status` - Scan status ("pending", "scanning", "clean", "suspicious", "malicious")
  - `metadata` - Additional model metadata from registry
  - `organization_id` - Associated organization (multi-tenant support)

  ## Status Workflow

  1. "pending" - Download event recorded, scan not started
  2. "scanning" - Security scan in progress
  3. "clean" - Scan completed, risk_score < 0.1
  4. "suspicious" - Scan completed, 0.1 ≤ risk_score < 0.3
  5. "malicious" - Scan completed, risk_score ≥ 0.3
  6. "error" - Scan failed (check scan_result for error details)

  ## Examples

      # Create provenance record for downloaded model
      %ModelProvenance{}
      |> ModelProvenance.changeset(%{
        model_id: "meta-llama/Llama-2-7b-chat-hf",
        registry: "huggingface",
        sha256: "abc123...",
        version: "main",
        downloaded_at: DateTime.utc_now(),
        organization_id: org_id
      })
      |> Repo.insert()

      # Update with scan results
      provenance
      |> ModelProvenance.update_scan_result(%{
        scanned_at: DateTime.utc_now(),
        scan_result: %{findings: [...], details: ...},
        risk_score: 0.05,
        findings_count: 0,
        status: "clean"
      })
      |> Repo.update()

      # Query high-risk models
      ModelProvenance.by_risk_score(0.3)
      |> Repo.all()
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Organizations.Organization
  alias TamanduaServer.Registries.ProvenanceEntry

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  @valid_registries ["huggingface", "mlflow", "wandb", "ollama"]
  @valid_statuses ["pending", "scanning", "clean", "suspicious", "malicious", "error", "active"]

  @type t :: %__MODULE__{}

  schema "model_provenance" do
    field :model_id, :string
    field :registry, :string
    field :sha256, :string
    field :version, :string
    field :downloaded_at, :utc_datetime_usec
    field :scanned_at, :utc_datetime_usec
    field :scan_result, :map
    field :risk_score, :float
    field :findings_count, :integer, default: 0
    field :status, :string, default: "pending"
    field :metadata, :map, default: %{}

    belongs_to :organization, Organization

    # Provenance chain entries (SLSA-style)
    has_many :provenance_entries, ProvenanceEntry

    timestamps()
  end

  @doc """
  Changeset for creating a new model provenance record.

  ## Required fields
  - `model_id` - Model identifier
  - `registry` - Source registry
  - `downloaded_at` - Download timestamp

  ## Optional fields
  - `sha256` - Model file hash
  - `version` - Model version
  - `metadata` - Additional metadata
  - `organization_id` - Organization reference
  """
  @spec changeset(t(), map()) :: Ecto.Changeset.t()
  def changeset(provenance \\ %__MODULE__{}, attrs) do
    provenance
    |> cast(attrs, [
      :model_id,
      :registry,
      :sha256,
      :version,
      :downloaded_at,
      :scanned_at,
      :scan_result,
      :risk_score,
      :findings_count,
      :status,
      :metadata,
      :organization_id
    ])
    |> validate_required([:model_id, :registry, :downloaded_at])
    |> validate_inclusion(:registry, @valid_registries)
    |> validate_inclusion(:status, @valid_statuses)
    |> validate_number(:risk_score, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> validate_number(:findings_count, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:organization_id)
    |> unique_constraint([:model_id, :registry, :sha256],
      name: :model_provenance_model_id_registry_sha256_index
    )
  end

  @doc """
  Changeset for updating scan results.

  Updates the scan-related fields after security scanning completes.

  ## Fields
  - `scanned_at` - Scan completion timestamp
  - `scan_result` - Full scan result from ML service
  - `risk_score` - Risk score (0.0-1.0)
  - `findings_count` - Number of findings
  - `status` - Updated status based on risk score
  """
  @spec update_scan_result(t(), map()) :: Ecto.Changeset.t()
  def update_scan_result(provenance, attrs) do
    provenance
    |> cast(attrs, [:scanned_at, :scan_result, :risk_score, :findings_count, :status])
    |> validate_inclusion(:status, @valid_statuses)
    |> validate_number(:risk_score, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> validate_number(:findings_count, greater_than_or_equal_to: 0)
  end

  @doc """
  Query helper to find provenance records by model_id and registry.

  ## Examples

      iex> ModelProvenance.by_model_id("meta-llama/Llama-2-7b", "huggingface")
      #Ecto.Query<...>
  """
  @spec by_model_id(String.t(), String.t()) :: Ecto.Query.t()
  def by_model_id(model_id, registry) do
    from p in __MODULE__,
      where: p.model_id == ^model_id and p.registry == ^registry,
      order_by: [desc: p.downloaded_at]
  end

  @doc """
  Query helper to find all pending scan records.

  Returns provenance records with status "pending" or "scanning".

  ## Examples

      iex> ModelProvenance.pending_scans() |> Repo.all()
      [%ModelProvenance{status: "pending", ...}, ...]
  """
  @spec pending_scans() :: Ecto.Query.t()
  def pending_scans do
    from p in __MODULE__,
      where: p.status in ["pending", "scanning"],
      order_by: [asc: p.downloaded_at]
  end

  @doc """
  Query helper to filter by minimum risk score.

  Returns provenance records with risk_score >= minimum.

  ## Examples

      iex> ModelProvenance.by_risk_score(0.3) |> Repo.all()
      [%ModelProvenance{risk_score: 0.85, ...}, ...]
  """
  @spec by_risk_score(float()) :: Ecto.Query.t()
  def by_risk_score(min_score) when is_float(min_score) do
    from p in __MODULE__,
      where: p.risk_score >= ^min_score,
      order_by: [desc: p.risk_score]
  end

  @doc """
  Query helper to get provenance by status.

  ## Examples

      iex> ModelProvenance.by_status("malicious") |> Repo.all()
      [%ModelProvenance{status: "malicious", ...}, ...]
  """
  @spec by_status(String.t()) :: Ecto.Query.t()
  def by_status(status) when status in @valid_statuses do
    from p in __MODULE__,
      where: p.status == ^status,
      order_by: [desc: p.downloaded_at]
  end

  @doc """
  Query helper to get provenance by registry.

  ## Examples

      iex> ModelProvenance.by_registry("huggingface") |> Repo.all()
      [%ModelProvenance{registry: "huggingface", ...}, ...]
  """
  @spec by_registry(String.t()) :: Ecto.Query.t()
  def by_registry(registry) when registry in @valid_registries do
    from p in __MODULE__,
      where: p.registry == ^registry,
      order_by: [desc: p.downloaded_at]
  end
end
