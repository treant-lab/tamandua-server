defmodule TamanduaServer.Alerts.SeverityManager do
  @moduledoc """
  Context for managing alert severity adjustments.

  Provides functionality for:
  - Manual severity overrides with audit trail
  - Approval workflow for critical downgrades
  - Bulk severity adjustments
  - Severity adjustment history
  """

  import Ecto.Query, warn: false

  alias TamanduaServer.Repo
  alias TamanduaServer.TenantScope
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Alerts.SeverityAdjustment

  require Logger

  # ===========================================================================
  # Severity Adjustment
  # ===========================================================================

  @doc """
  Adjusts the severity of an alert.

  Creates an audit record and updates the alert's severity.
  If the adjustment requires approval (critical downgrade), the severity
  is not changed until approved.
  """
  def adjust_severity(alert_id, new_severity, reason, user, opts \\ []) do
    notes = Keyword.get(opts, :notes)
    organization_id = Keyword.get(opts, :organization_id)

    with {:ok, alert} <- get_alert(alert_id, organization_id),
         :ok <- validate_severity_change(alert.severity, new_severity) do
      Repo.transaction(fn ->
        # Create adjustment record
        adjustment_attrs = %{
          alert_id: alert_id,
          old_severity: alert.original_severity || alert.severity,
          new_severity: new_severity,
          reason: reason,
          notes: notes,
          adjusted_by_id: user.id,
          organization_id: organization_id || alert.organization_id
        }

        case create_adjustment(adjustment_attrs) do
          {:ok, adjustment} ->
            if adjustment.requires_approval do
              # Don't change severity yet - needs approval
              Logger.info(
                "Severity adjustment created, pending approval: alert=#{alert_id}, adjustment=#{adjustment.id}"
              )

              {:ok, adjustment, :pending_approval}
            else
              # Apply severity change immediately
              case apply_severity_change(alert, new_severity, user.id) do
                {:ok, updated_alert} ->
                  broadcast_severity_changed(alert_id, alert.severity, new_severity)
                  {:ok, adjustment, updated_alert}

                {:error, reason} ->
                  Repo.rollback({:update_failed, reason})
              end
            end

          {:error, changeset} ->
            Repo.rollback({:adjustment_failed, changeset})
        end
      end)
      |> case do
        {:ok, result} -> {:ok, result}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  @doc """
  Approves a severity adjustment.

  Updates the alert severity and marks the adjustment as approved.
  """
  def approve_adjustment(adjustment_id, approver, organization_id \\ nil) do
    with {:ok, adjustment} <- get_adjustment(adjustment_id, organization_id),
         :ok <- validate_can_approve(adjustment, approver) do
      Repo.transaction(fn ->
        # Mark adjustment as approved
        approval_attrs = %{
          approved: true,
          approved_at: DateTime.utc_now() |> DateTime.truncate(:microsecond),
          approved_by_id: approver.id
        }

        case update_adjustment_approval(adjustment, approval_attrs) do
          {:ok, updated_adjustment} ->
            # Apply severity change
            case get_alert(adjustment.alert_id, organization_id) do
              {:ok, alert} ->
                case apply_severity_change(alert, adjustment.new_severity, approver.id) do
                  {:ok, updated_alert} ->
                    broadcast_severity_changed(
                      alert.id,
                      adjustment.old_severity,
                      adjustment.new_severity
                    )

                    {:ok, updated_adjustment, updated_alert}

                  {:error, reason} ->
                    Repo.rollback({:update_failed, reason})
                end

              {:error, reason} ->
                Repo.rollback({:alert_not_found, reason})
            end

          {:error, changeset} ->
            Repo.rollback({:approval_failed, changeset})
        end
      end)
      |> case do
        {:ok, result} -> {:ok, result}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  @doc """
  Rejects a severity adjustment.

  Marks the adjustment as rejected without changing alert severity.
  """
  def reject_adjustment(adjustment_id, rejection_reason, approver, organization_id \\ nil) do
    with {:ok, adjustment} <- get_adjustment(adjustment_id, organization_id),
         :ok <- validate_can_approve(adjustment, approver) do
      approval_attrs = %{
        approved: false,
        rejection_reason: rejection_reason
      }

      update_adjustment_approval(adjustment, approval_attrs)
    end
  end

  @doc """
  Lists severity adjustments for an alert.
  """
  def list_alert_adjustments(alert_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)

    SeverityAdjustment
    |> where([sa], sa.alert_id == ^alert_id)
    |> order_by([sa], [desc: sa.inserted_at])
    |> limit(^limit)
    |> preload([:adjusted_by, :approved_by])
    |> Repo.all()
  end

  @doc """
  Lists pending severity adjustments (requiring approval).
  """
  def list_pending_adjustments(organization_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)

    SeverityAdjustment
    |> TenantScope.scope_to_tenant(organization_id)
    |> where([sa], sa.requires_approval == true and is_nil(sa.approved))
    |> order_by([sa], [asc: sa.inserted_at])
    |> limit(^limit)
    |> preload([:alert, :adjusted_by])
    |> Repo.all()
  end

  # ===========================================================================
  # Bulk Operations
  # ===========================================================================

  @doc """
  Bulk adjusts severity for multiple alerts.

  Creates adjustment records for all alerts. If any require approval,
  returns the list of adjustments pending approval.
  """
  def bulk_adjust_severity(alert_ids, new_severity, reason, user, opts \\ []) do
    _organization_id = Keyword.get(opts, :organization_id)

    results =
      Enum.map(alert_ids, fn alert_id ->
        case adjust_severity(alert_id, new_severity, reason, user, opts) do
          {:ok, {adjustment, :pending_approval}} ->
            {:pending, adjustment}

          {:ok, {adjustment, _updated_alert}} ->
            {:ok, adjustment}

          {:error, reason} ->
            {:error, alert_id, reason}
        end
      end)

    succeeded = Enum.count(results, &match?({:ok, _}, &1))
    pending = results |> Enum.filter(&match?({:pending, _}, &1)) |> Enum.map(fn {:pending, a} -> a end)
    errors = Enum.filter(results, &match?({:error, _, _}, &1))

    %{
      succeeded: succeeded,
      pending: pending,
      errors: errors
    }
  end

  # ===========================================================================
  # Statistics
  # ===========================================================================

  @doc """
  Returns severity adjustment statistics for an organization.
  """
  def adjustment_statistics(organization_id, opts \\ []) do
    time_range_days = Keyword.get(opts, :time_range_days, 30)

    cutoff_date =
      DateTime.utc_now()
      |> DateTime.add(-time_range_days * 24 * 60 * 60, :second)

    stats =
      SeverityAdjustment
      |> TenantScope.scope_to_tenant(organization_id)
      |> where([sa], sa.inserted_at >= ^cutoff_date)
      |> group_by([sa], [sa.old_severity, sa.new_severity])
      |> select([sa], %{
        old_severity: sa.old_severity,
        new_severity: sa.new_severity,
        count: count(sa.id)
      })
      |> Repo.all()

    pending_count =
      SeverityAdjustment
      |> TenantScope.scope_to_tenant(organization_id)
      |> where([sa], sa.requires_approval == true and is_nil(sa.approved))
      |> Repo.aggregate(:count)

    %{
      adjustments: stats,
      pending_approvals: pending_count
    }
  end

  # ===========================================================================
  # Helper Functions
  # ===========================================================================

  defp get_alert(alert_id, nil) do
    case Repo.get(Alert, alert_id) do
      nil -> {:error, :not_found}
      alert -> {:ok, alert}
    end
  end

  defp get_alert(alert_id, organization_id) do
    case TenantScope.get_scoped(Alert, organization_id, alert_id) do
      nil -> {:error, :not_found}
      alert -> {:ok, alert}
    end
  end

  defp get_adjustment(adjustment_id, nil) do
    case Repo.get(SeverityAdjustment, adjustment_id) do
      nil -> {:error, :not_found}
      adjustment -> {:ok, adjustment}
    end
  end

  defp get_adjustment(adjustment_id, organization_id) do
    case TenantScope.get_scoped(SeverityAdjustment, organization_id, adjustment_id) do
      nil -> {:error, :not_found}
      adjustment -> {:ok, adjustment}
    end
  end

  defp validate_severity_change(old_severity, new_severity) do
    valid_severities = SeverityAdjustment.valid_severities()

    cond do
      old_severity == new_severity ->
        {:error, :same_severity}

      new_severity not in valid_severities ->
        {:error, :invalid_severity}

      true ->
        :ok
    end
  end

  defp validate_can_approve(adjustment, approver) do
    cond do
      !adjustment.requires_approval ->
        {:error, :no_approval_required}

      !is_nil(adjustment.approved) ->
        {:error, :already_processed}

      adjustment.adjusted_by_id == approver.id ->
        {:error, :cannot_approve_own_adjustment}

      true ->
        :ok
    end
  end

  defp create_adjustment(attrs) do
    %SeverityAdjustment{}
    |> SeverityAdjustment.changeset(attrs)
    |> Repo.insert()
  end

  defp update_adjustment_approval(adjustment, attrs) do
    adjustment
    |> SeverityAdjustment.approval_changeset(attrs)
    |> Repo.update()
  end

  defp apply_severity_change(alert, new_severity, user_id) do
    # Store original severity if not already set
    original_severity = alert.original_severity || alert.severity

    attrs = %{
      severity: new_severity,
      original_severity: original_severity,
      severity_adjusted: true,
      severity_adjusted_at: DateTime.utc_now() |> DateTime.truncate(:microsecond),
      severity_adjusted_by_id: user_id
    }

    alert
    |> Ecto.Changeset.change(attrs)
    |> Repo.update()
  end

  defp broadcast_severity_changed(alert_id, old_severity, new_severity) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "alerts:#{alert_id}",
      {:severity_changed, %{alert_id: alert_id, old_severity: old_severity, new_severity: new_severity}}
    )
  end
end
