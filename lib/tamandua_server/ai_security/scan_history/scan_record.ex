defmodule TamanduaServer.AISecurity.ScanHistory.ScanRecord do
  @moduledoc """
  Ecto schema for AI model scan history records.

  Tracks the results of security scans performed on AI/ML model files,
  including threat detection results, scan duration, and timestamps.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "ai_model_scan_history" do
    field :model_id, :string
    field :agent_id, :string
    field :file_hash, :string
    field :scan_status, :string  # "safe", "threats", "suspicious", "error"
    field :threat_score, :float
    field :threats, :map, default: %{}
    field :scan_duration_ms, :integer
    field :scanner_version, :string
    field :scanned_at, :utc_datetime
    field :organization_id, :binary_id
  end

  @required_fields [:model_id, :agent_id, :file_hash, :scan_status, :scanned_at]
  @optional_fields [:threat_score, :threats, :scan_duration_ms, :scanner_version, :organization_id]
  @valid_statuses ["safe", "threats", "suspicious", "error"]

  @doc """
  Creates a changeset for inserting or updating a scan record.
  """
  @spec changeset(t() | Ecto.Changeset.t(), map()) :: Ecto.Changeset.t()
  def changeset(record, attrs) do
    record
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:scan_status, @valid_statuses)
    |> validate_number(:threat_score, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> validate_number(:scan_duration_ms, greater_than_or_equal_to: 0)
  end

  @type t :: %__MODULE__{
    id: binary() | nil,
    model_id: String.t() | nil,
    agent_id: String.t() | nil,
    file_hash: String.t() | nil,
    scan_status: String.t() | nil,
    threat_score: float() | nil,
    threats: map() | nil,
    scan_duration_ms: integer() | nil,
    scanner_version: String.t() | nil,
    scanned_at: DateTime.t() | nil,
    organization_id: binary() | nil
  }
end
