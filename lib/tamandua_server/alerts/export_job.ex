defmodule TamanduaServer.Alerts.ExportJob do
  @moduledoc """
  Schema for tracking alert export jobs.

  Tracks export job status, progress, download URLs, and metadata.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Alerts.ExportTemplate

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "alert_export_jobs" do
    field :status, :string, default: "pending"  # pending, processing, completed, failed
    field :format, :string
    field :filter_json, :map, default: %{}
    field :columns, {:array, :string}, default: []

    # Progress tracking
    field :progress, :integer, default: 0
    field :total_records, :integer
    field :processed_records, :integer, default: 0
    field :message, :string

    # Output
    field :file_path, :string
    field :file_size, :integer
    field :download_url, :string
    field :url_expires_at, :utc_datetime_usec

    # Metadata
    field :triggered_by, :string  # manual, scheduled
    field :delivery_method, :string
    field :delivery_status, :string  # pending, delivered, failed
    field :delivery_error, :string

    # Error handling
    field :error_message, :string
    field :error_details, :map

    # Completion
    field :started_at, :utc_datetime_usec
    field :completed_at, :utc_datetime_usec

    belongs_to :organization, Organization
    belongs_to :user, User
    belongs_to :template, ExportTemplate

    timestamps()
  end

  @doc false
  def changeset(job, attrs) do
    job
    |> cast(attrs, [
      :status,
      :format,
      :filter_json,
      :columns,
      :progress,
      :total_records,
      :processed_records,
      :message,
      :file_path,
      :file_size,
      :download_url,
      :url_expires_at,
      :triggered_by,
      :delivery_method,
      :delivery_status,
      :delivery_error,
      :error_message,
      :error_details,
      :started_at,
      :completed_at,
      :organization_id,
      :user_id,
      :template_id
    ])
    |> validate_required([:format, :organization_id])
    |> validate_inclusion(:status, ~w(pending processing completed failed cancelled))
    |> validate_inclusion(:format, ~w(csv json pdf))
    |> validate_inclusion(:delivery_status, ~w(pending delivered failed))
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:template_id)
  end

  @doc """
  Marks job as started.
  """
  def start_changeset(job, total_records) do
    job
    |> change(%{
      status: "processing",
      started_at: DateTime.utc_now(),
      total_records: total_records,
      progress: 0,
      processed_records: 0
    })
  end

  @doc """
  Updates job progress.
  """
  def progress_changeset(job, processed_records, message \\ nil) do
    progress = if job.total_records > 0 do
      round((processed_records / job.total_records) * 100)
    else
      0
    end

    changes = %{
      processed_records: processed_records,
      progress: progress
    }

    changes = if message, do: Map.put(changes, :message, message), else: changes

    change(job, changes)
  end

  @doc """
  Marks job as completed.
  """
  def complete_changeset(job, attrs) do
    job
    |> change(%{
      status: "completed",
      completed_at: DateTime.utc_now(),
      progress: 100
    })
    |> cast(attrs, [:file_path, :file_size, :download_url, :url_expires_at])
  end

  @doc """
  Marks job as failed.
  """
  def fail_changeset(job, error_message, error_details \\ nil) do
    changes = %{
      status: "failed",
      completed_at: DateTime.utc_now(),
      error_message: error_message
    }

    changes = if error_details, do: Map.put(changes, :error_details, error_details), else: changes

    change(job, changes)
  end

  @doc """
  Updates delivery status.
  """
  def delivery_changeset(job, status, error \\ nil) do
    changes = %{delivery_status: status}
    changes = if error, do: Map.put(changes, :delivery_error, error), else: changes
    change(job, changes)
  end
end
