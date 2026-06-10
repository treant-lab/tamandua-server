defmodule TamanduaServer.Forensics.Artifact do
  @moduledoc """
  Schema for forensic artifacts collected from agents.

  Tracks collection progress, chain of custody, and upload metadata.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Organizations.Organization
  alias TamanduaServer.Accounts.User

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @artifact_types ~w(
    memory_dump
    disk_image
    registry_hive
    event_logs
    browser_artifacts
    prefetch_files
    mft
    network_capture
    process_memory
    process_list
    file_timeline
    network_snapshot
    loaded_modules
    startup_items
    scheduled_tasks
    services_list
    user_accounts
    custom_file
  )

  @statuses ~w(
    pending
    queued
    collecting
    compressing
    encrypting
    uploading
    completed
    failed
    cancelled
  )

  @compression_types ~w(gzip zstd none)

  schema "forensic_artifacts" do
    field :case_id, :string
    field :artifact_type, :string
    field :artifact_subtype, :string

    # Collection parameters
    field :parameters, :map

    # Status tracking
    field :status, :string, default: "pending"
    field :progress_percent, :integer, default: 0
    field :progress_bytes, :integer, default: 0
    field :total_bytes, :integer
    field :eta_seconds, :integer
    field :transfer_speed_mbps, :float

    # Error tracking
    field :error_message, :string
    field :error_details, :map

    # Collection metadata
    field :collection_started_at, :utc_datetime
    field :collection_completed_at, :utc_datetime
    field :collection_duration_ms, :integer

    # File information
    field :file_path, :string
    field :file_size, :integer
    field :sha256_hash, :string
    field :compression_type, :string
    field :encrypted, :boolean, default: false
    field :encryption_key_id, :string

    # Chain of custody
    field :collector_name, :string
    field :collector_email, :string
    field :collection_method, :string, default: "automated"
    field :custody_chain, {:array, :map}, default: []
    field :evidence_seal_hash, :string
    field :evidence_integrity_verified, :boolean, default: false

    # Upload tracking
    field :upload_destination, :string
    field :s3_bucket, :string
    field :s3_key, :string
    field :s3_url, :string
    field :upload_started_at, :utc_datetime
    field :upload_completed_at, :utc_datetime
    field :download_url, :string
    field :download_expires_at, :utc_datetime

    # Metadata
    field :tags, {:array, :string}, default: []
    field :notes, :string
    field :metadata, :map, default: %{}

    # Relationships
    belongs_to :agent, Agent, type: :string, foreign_key: :agent_id
    belongs_to :organization, Organization
    belongs_to :requested_by, User
    belongs_to :approved_by, User

    timestamps(type: :utc_datetime)
  end

  @doc """
  Changeset for creating a new artifact collection request.
  """
  def changeset(artifact, attrs) do
    artifact
    |> cast(attrs, [
      :agent_id,
      :organization_id,
      :case_id,
      :artifact_type,
      :artifact_subtype,
      :parameters,
      :status,
      :compression_type,
      :encrypted,
      :encryption_key_id,
      :collector_name,
      :collector_email,
      :collection_method,
      :upload_destination,
      :s3_bucket,
      :tags,
      :notes,
      :metadata,
      :requested_by_id,
      :approved_by_id
    ])
    |> validate_required([
      :agent_id,
      :organization_id,
      :artifact_type,
      :collector_name
    ])
    |> validate_inclusion(:artifact_type, @artifact_types)
    |> validate_inclusion(:status, @statuses)
    |> validate_inclusion(:compression_type, @compression_types, allow_nil: true)
    |> validate_number(:progress_percent, greater_than_or_equal_to: 0, less_than_or_equal_to: 100)
    |> foreign_key_constraint(:agent_id)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:requested_by_id)
    |> foreign_key_constraint(:approved_by_id)
  end

  @doc """
  Update artifact progress.
  """
  def update_progress(artifact, attrs) do
    artifact
    |> cast(attrs, [
      :status,
      :progress_percent,
      :progress_bytes,
      :total_bytes,
      :eta_seconds,
      :transfer_speed_mbps
    ])
    |> validate_required([:progress_percent])
    |> validate_number(:progress_percent, greater_than_or_equal_to: 0, less_than_or_equal_to: 100)
  end

  @doc """
  Mark artifact collection as started.
  """
  def mark_started(artifact) do
    artifact
    |> change(%{
      status: "collecting",
      collection_started_at: DateTime.utc_now()
    })
  end

  @doc """
  Mark artifact collection as completed.
  """
  def mark_completed(artifact, attrs) do
    now = DateTime.utc_now()
    duration_ms = if artifact.collection_started_at do
      DateTime.diff(now, artifact.collection_started_at, :millisecond)
    else
      nil
    end

    artifact
    |> cast(attrs, [
      :file_path,
      :file_size,
      :sha256_hash,
      :compression_type,
      :encrypted,
      :encryption_key_id,
      :evidence_seal_hash,
      :metadata
    ])
    |> change(%{
      status: "completed",
      progress_percent: 100,
      collection_completed_at: now,
      collection_duration_ms: duration_ms,
      evidence_integrity_verified: true
    })
    |> validate_required([:file_path, :file_size, :sha256_hash])
  end

  @doc """
  Mark artifact collection as failed.
  """
  def mark_failed(artifact, error_message, error_details \\ %{}) do
    artifact
    |> change(%{
      status: "failed",
      error_message: error_message,
      error_details: error_details
    })
  end

  @doc """
  Mark artifact as uploading.
  """
  def mark_uploading(artifact) do
    artifact
    |> change(%{
      status: "uploading",
      upload_started_at: DateTime.utc_now()
    })
  end

  @doc """
  Mark artifact upload as completed.
  """
  def mark_uploaded(artifact, upload_info) do
    artifact
    |> cast(upload_info, [
      :s3_bucket,
      :s3_key,
      :s3_url,
      :download_url,
      :download_expires_at
    ])
    |> change(%{
      upload_completed_at: DateTime.utc_now()
    })
  end

  @doc """
  Add chain of custody entry.
  """
  def add_custody_entry(artifact, entry) do
    timestamp = DateTime.utc_now()
    custody_entry = Map.merge(entry, %{
      "timestamp" => DateTime.to_iso8601(timestamp)
    })

    artifact
    |> change(%{
      custody_chain: artifact.custody_chain ++ [custody_entry]
    })
  end

  @doc """
  Query helpers
  """

  def by_organization(query \\ __MODULE__, organization_id) do
    from a in query,
      where: a.organization_id == ^organization_id
  end

  def by_agent(query \\ __MODULE__, agent_id) do
    from a in query,
      where: a.agent_id == ^agent_id
  end

  def by_status(query \\ __MODULE__, status) do
    from a in query,
      where: a.status == ^status
  end

  def by_artifact_type(query \\ __MODULE__, artifact_type) do
    from a in query,
      where: a.artifact_type == ^artifact_type
  end

  def by_case(query \\ __MODULE__, case_id) do
    from a in query,
      where: a.case_id == ^case_id
  end

  def pending(query \\ __MODULE__) do
    from a in query,
      where: a.status in ["pending", "queued"]
  end

  def in_progress(query \\ __MODULE__) do
    from a in query,
      where: a.status in ["collecting", "compressing", "encrypting", "uploading"]
  end

  def completed(query \\ __MODULE__) do
    from a in query,
      where: a.status == "completed"
  end

  def failed(query \\ __MODULE__) do
    from a in query,
      where: a.status == "failed"
  end

  def recent(query \\ __MODULE__, limit \\ 50) do
    from a in query,
      order_by: [desc: a.inserted_at],
      limit: ^limit
  end

  def with_preloads(query \\ __MODULE__) do
    from a in query,
      preload: [:agent, :organization, :requested_by, :approved_by]
  end

  @doc """
  Get artifact types list.
  """
  def artifact_types, do: @artifact_types

  @doc """
  Get statuses list.
  """
  def statuses, do: @statuses

  @doc """
  Get compression types list.
  """
  def compression_types, do: @compression_types
end
