defmodule TamanduaServer.AISecurity.ApprovalExecution do
  @moduledoc "Durable, tenant-scoped idempotency record for one approved response execution."

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  @statuses ~w(pending running succeeded failed reconciliation_required)

  schema "ai_approval_executions" do
    field(:investigation_id, :string)
    field(:recommendation_id, :string)
    field(:idempotency_key, :string)
    field(:status, :string, default: "pending")
    field(:action_type, :string)
    field(:target, :map, default: %{})
    field(:result, :map)
    field(:error, :map)
    field(:started_at, :utc_datetime_usec)
    field(:completed_at, :utc_datetime_usec)
    field(:lease_expires_at, :utc_datetime_usec)
    field(:reconciled_at, :utc_datetime_usec)
    field(:reconciliation_evidence_ref, :string)

    belongs_to(:organization, Organization)
    belongs_to(:approver, User)
    belongs_to(:reconciled_by, User)

    timestamps()
  end

  def create_changeset(execution, attrs) do
    execution
    |> cast(attrs, [
      :organization_id,
      :investigation_id,
      :recommendation_id,
      :approver_id,
      :idempotency_key,
      :status,
      :action_type,
      :target,
      :result,
      :error,
      :started_at,
      :completed_at,
      :lease_expires_at
    ])
    |> validate_required([
      :organization_id,
      :investigation_id,
      :recommendation_id,
      :approver_id,
      :idempotency_key,
      :status,
      :action_type,
      :target
    ])
    |> validate_inclusion(:status, @statuses)
    |> validate_length(:idempotency_key, is: 64)
    |> unique_constraint([:organization_id, :investigation_id, :recommendation_id],
      name: :ai_approval_executions_org_investigation_recommendation_idx
    )
  end

  def outcome_changeset(execution, attrs) do
    execution
    |> cast(attrs, [:status, :result, :error, :completed_at])
    |> validate_required([:status, :completed_at])
    |> validate_inclusion(:status, ~w(succeeded failed))
  end

  def stale_changeset(execution, attrs) do
    execution
    |> cast(attrs, [:status, :completed_at])
    |> validate_required([:status, :completed_at])
    |> validate_inclusion(:status, ["reconciliation_required"])
  end

  def reconciliation_changeset(execution, attrs) do
    execution
    |> cast(attrs, [
      :status,
      :result,
      :error,
      :completed_at,
      :reconciled_by_id,
      :reconciled_at,
      :reconciliation_evidence_ref
    ])
    |> validate_required([
      :status,
      :completed_at,
      :reconciled_by_id,
      :reconciled_at,
      :reconciliation_evidence_ref
    ])
    |> validate_inclusion(:status, ~w(succeeded failed))
    |> unique_constraint(:reconciliation_evidence_ref,
      name: :ai_approval_executions_reconciliation_evidence_ref_idx
    )
  end

  def statuses, do: @statuses
end
