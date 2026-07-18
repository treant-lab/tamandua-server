defmodule TamanduaServer.Investigations.InvestigationRun do
  @moduledoc """
  Durable, tenant-scoped record for a non-enforcing AI investigation observation.

  This schema deliberately supports only `shadow` and `recommendation` modes. It
  has no response/action fields and therefore cannot represent an execution.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Investigations.InvestigationEvidence

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  @modes ~w(shadow recommendation)
  @statuses ~w(queued running observed abstained failed)
  @admission_dispositions ~w(enqueued ineligible capacity_limited disabled degraded)

  schema "ai_investigation_runs" do
    field(:idempotency_key, :string)
    field(:mode, :string, default: "shadow")
    field(:status, :string, default: "queued")
    field(:source, :string, default: "explicit")
    field(:policy_version, :string, default: "shadow-v2")
    field(:admission_disposition, :string, default: "enqueued")
    field(:admission_reason, :string, default: "explicit_request")
    field(:summary, :map, default: %{})
    field(:error_code, :string)
    field(:started_at, :utc_datetime_usec)
    field(:completed_at, :utc_datetime_usec)

    belongs_to(:organization, Organization)
    belongs_to(:alert, Alert)
    has_many(:evidence, InvestigationEvidence, foreign_key: :run_id)

    timestamps()
  end

  def create_changeset(run, attrs) do
    run
    |> cast(attrs, [
      :organization_id,
      :alert_id,
      :idempotency_key,
      :mode,
      :status,
      :source,
      :policy_version,
      :admission_disposition,
      :admission_reason,
      :summary,
      :error_code,
      :started_at,
      :completed_at
    ])
    |> validate_required([
      :organization_id,
      :alert_id,
      :idempotency_key,
      :mode,
      :status,
      :source,
      :policy_version,
      :admission_disposition,
      :admission_reason
    ])
    |> validate_inclusion(:mode, @modes)
    |> validate_inclusion(:status, @statuses)
    |> validate_inclusion(:admission_disposition, @admission_dispositions)
    |> validate_length(:admission_reason, min: 1, max: 128)
    |> validate_length(:idempotency_key, min: 64, max: 64)
    |> unique_constraint([:organization_id, :idempotency_key],
      name: :ai_investigation_runs_org_idempotency_idx
    )
  end

  def modes, do: @modes
  def statuses, do: @statuses
  def admission_dispositions, do: @admission_dispositions
end
