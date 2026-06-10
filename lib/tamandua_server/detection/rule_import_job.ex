defmodule TamanduaServer.Detection.RuleImportJob do
  @moduledoc """
  Schema for tracking rule import operations.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "rule_import_jobs" do
    field :type, :string
    field :source_type, :string
    field :source_url, :string
    field :status, :string, default: "pending"
    field :total_rules, :integer, default: 0
    field :imported_rules, :integer, default: 0
    field :skipped_rules, :integer, default: 0
    field :failed_rules, :integer, default: 0
    field :error_message, :string
    field :conflict_resolution, :string, default: "skip"
    field :validation_enabled, :boolean, default: true
    field :metadata, :map, default: %{}
    field :started_at, :utc_datetime_usec
    field :completed_at, :utc_datetime_usec

    belongs_to :organization, Organization
    belongs_to :user, User

    timestamps(type: :utc_datetime_usec)
  end

  @doc false
  def changeset(job, attrs) do
    job
    |> cast(attrs, [
      :type,
      :source_type,
      :source_url,
      :status,
      :total_rules,
      :imported_rules,
      :skipped_rules,
      :failed_rules,
      :error_message,
      :conflict_resolution,
      :validation_enabled,
      :metadata,
      :started_at,
      :completed_at,
      :organization_id,
      :user_id
    ])
    |> validate_required([:type, :source_type, :organization_id])
    |> validate_inclusion(:type, ["yara", "sigma", "ioc"])
    |> validate_inclusion(:source_type, ["file", "directory", "github", "url"])
    |> validate_inclusion(:status, ["pending", "processing", "completed", "failed", "cancelled"])
    |> validate_inclusion(:conflict_resolution, ["skip", "overwrite", "rename"])
  end

  @doc """
  Mark job as started.
  """
  def mark_started(job) do
    changeset(job, %{
      status: "processing",
      started_at: DateTime.utc_now()
    })
  end

  @doc """
  Mark job as completed.
  """
  def mark_completed(job) do
    changeset(job, %{
      status: "completed",
      completed_at: DateTime.utc_now()
    })
  end

  @doc """
  Mark job as failed.
  """
  def mark_failed(job, error_message) do
    changeset(job, %{
      status: "failed",
      error_message: error_message,
      completed_at: DateTime.utc_now()
    })
  end

  @doc """
  Update progress counters.
  """
  def update_progress(job, attrs) do
    changeset(job, attrs)
  end
end
