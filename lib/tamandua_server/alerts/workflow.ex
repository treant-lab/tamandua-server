defmodule TamanduaServer.Alerts.Workflow do
  @moduledoc """
  Alert workflow state management with transition validation and audit logging.

  ## States

  - `new` - Alert just created, unassigned
  - `assigned` - Alert assigned to an analyst
  - `investigating` - Analyst actively investigating
  - `pending_info` - Waiting for additional information
  - `resolved` - Issue resolved
  - `false_positive` - Determined to be false positive
  - `escalated` - Escalated to higher tier
  - `closed` - Final closed state

  ## State Transitions

  Valid transitions are defined in `@allowed_transitions`. Attempting
  an invalid transition will return an error.

  Each transition can include:
  - `reason` - Required for certain transitions
  - `notes` - Optional detailed notes
  - `metadata` - Additional structured data
  """

  use Ecto.Schema
  import Ecto.{Changeset, Query}
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.{Alert, StateTransition}
  alias TamanduaServer.Accounts.User

  # Valid workflow states
  @states ~w(new assigned investigating pending_info resolved false_positive escalated closed)

  # Valid state transitions (from => [to, ...])
  @allowed_transitions %{
    "new" => ~w(assigned investigating escalated closed),
    "assigned" => ~w(investigating pending_info resolved false_positive escalated closed),
    "investigating" => ~w(pending_info resolved false_positive escalated closed),
    "pending_info" => ~w(investigating resolved false_positive escalated closed),
    "resolved" => ~w(closed investigating), # Can reopen
    "false_positive" => ~w(closed investigating), # Can reopen
    "escalated" => ~w(assigned investigating resolved false_positive closed),
    "closed" => ~w(investigating) # Can reopen
  }

  # Transitions that require a reason
  @transitions_requiring_reason ~w(resolved false_positive escalated closed)

  # ===========================================================================
  # Public API
  # ===========================================================================

  @doc """
  Transition an alert to a new workflow state.

  ## Options

  - `:user_id` - ID of user making the transition (required)
  - `:reason` - Reason for transition (required for certain states)
  - `:notes` - Additional notes
  - `:metadata` - Additional structured metadata

  ## Examples

      iex> transition_state(alert, "investigating", user_id: user.id)
      {:ok, updated_alert}

      iex> transition_state(alert, "resolved", user_id: user.id, reason: "Whitelisted process")
      {:ok, updated_alert}

      iex> transition_state(alert, "invalid_state", user_id: user.id)
      {:error, :invalid_transition}
  """
  def transition_state(%Alert{} = alert, new_state, opts \\ []) do
    user_id = Keyword.fetch!(opts, :user_id)
    reason = Keyword.get(opts, :reason)
    notes = Keyword.get(opts, :notes)
    metadata = Keyword.get(opts, :metadata, %{})

    current_state = alert.workflow_state || alert.status || "new"

    with :ok <- validate_state(new_state),
         :ok <- validate_transition(current_state, new_state),
         :ok <- validate_reason(new_state, reason) do

      Ecto.Multi.new()
      |> Ecto.Multi.update(:alert, update_alert_state(alert, new_state, user_id))
      |> Ecto.Multi.insert(:transition, create_transition(alert, current_state, new_state, user_id, reason, notes, metadata))
      |> Ecto.Multi.run(:post_transition, fn _repo, %{alert: updated_alert} ->
        post_transition_actions(updated_alert, current_state, new_state)
        {:ok, updated_alert}
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{alert: updated_alert}} ->
          Logger.info("[Workflow] Alert #{alert.id} transitioned from #{current_state} to #{new_state} by user #{user_id}")
          {:ok, updated_alert}

        {:error, _operation, changeset, _changes} ->
          {:error, changeset}
      end
    end
  end

  @doc """
  Check if a state transition is valid.
  """
  def valid_transition?(from_state, to_state) do
    allowed = Map.get(@allowed_transitions, from_state, [])
    to_state in allowed
  end

  @doc """
  Get all valid next states for a given state.
  """
  def valid_next_states(state) do
    Map.get(@allowed_transitions, state, [])
  end

  @doc """
  Get all workflow states.
  """
  def states, do: @states

  @doc """
  Get state transition history for an alert.
  """
  def get_transition_history(alert_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)

    from(t in StateTransition,
      where: t.alert_id == ^alert_id,
      order_by: [desc: t.inserted_at],
      limit: ^limit,
      preload: [:transitioned_by]
    )
    |> Repo.all()
  end

  @doc """
  Get statistics for state transitions.

  Returns counts of transitions between states.
  """
  def get_transition_stats(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)
    days = Keyword.get(opts, :days, 30)
    since = DateTime.utc_now() |> DateTime.add(-days * 24 * 60 * 60, :second)

    query = from(t in StateTransition,
      where: t.inserted_at >= ^since,
      group_by: [t.from_state, t.to_state],
      select: {t.from_state, t.to_state, count(t.id)}
    )

    query = if organization_id do
      from(t in query,
        join: a in Alert, on: a.id == t.alert_id,
        where: a.organization_id == ^organization_id
      )
    else
      query
    end

    Repo.all(query)
    |> Enum.map(fn {from, to, count} ->
      %{from_state: from, to_state: to, count: count}
    end)
  end

  @doc """
  Get alerts by workflow state.
  """
  def get_alerts_by_state(state, opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)
    assigned_to_id = Keyword.get(opts, :assigned_to_id)
    limit = Keyword.get(opts, :limit, 100)

    query = from(a in Alert,
      where: a.workflow_state == ^state,
      order_by: [desc: a.inserted_at],
      limit: ^limit,
      preload: [:assigned_to, :agent]
    )

    query = if organization_id do
      from(a in query, where: a.organization_id == ^organization_id)
    else
      query
    end

    query = if assigned_to_id do
      from(a in query, where: a.assigned_to_id == ^assigned_to_id)
    else
      query
    end

    Repo.all(query)
  end

  @doc """
  Get workflow state distribution.

  Returns count of alerts in each state.
  """
  def get_state_distribution(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)

    query = from(a in Alert,
      group_by: a.workflow_state,
      select: {a.workflow_state, count(a.id)}
    )

    query = if organization_id do
      from(a in query, where: a.organization_id == ^organization_id)
    else
      query
    end

    Repo.all(query)
    |> Enum.map(fn {state, count} ->
      %{state: state || "new", count: count}
    end)
  end

  @doc """
  Bulk transition alerts to a new state.

  Returns `{success_count, failure_count}`.
  """
  def bulk_transition(alert_ids, new_state, opts \\ []) when is_list(alert_ids) do
    user_id = Keyword.fetch!(opts, :user_id)
    reason = Keyword.get(opts, :reason)
    notes = Keyword.get(opts, :notes)

    results = Enum.map(alert_ids, fn alert_id ->
      case TamanduaServer.Alerts.get_alert(alert_id) do
        {:ok, alert} ->
          transition_state(alert, new_state, user_id: user_id, reason: reason, notes: notes)

        error ->
          error
      end
    end)

    success_count = Enum.count(results, fn result -> match?({:ok, _}, result) end)
    failure_count = length(results) - success_count

    {success_count, failure_count}
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp validate_state(state) do
    if state in @states do
      :ok
    else
      {:error, :invalid_state}
    end
  end

  defp validate_transition(from_state, to_state) do
    if valid_transition?(from_state, to_state) do
      :ok
    else
      {:error, :invalid_transition}
    end
  end

  defp validate_reason(state, reason) do
    if state in @transitions_requiring_reason and is_nil(reason) do
      {:error, :reason_required}
    else
      :ok
    end
  end

  defp update_alert_state(alert, new_state, user_id) do
    now = DateTime.utc_now()

    alert
    |> change(%{
      previous_state: alert.workflow_state || alert.status,
      workflow_state: new_state,
      state_changed_at: now,
      state_changed_by_id: user_id
    })
    # Also update legacy status field for backward compatibility
    |> put_change(:status, map_state_to_legacy_status(new_state))
  end

  defp create_transition(alert, from_state, to_state, user_id, reason, notes, metadata) do
    %StateTransition{
      alert_id: alert.id,
      from_state: from_state,
      to_state: to_state,
      transition_reason: reason,
      transition_notes: notes,
      transitioned_by_id: user_id,
      metadata: metadata
    }
  end

  defp post_transition_actions(alert, _from_state, new_state) do
    # Trigger notifications based on state change
    case new_state do
      "escalated" ->
        # Notify escalation targets
        TamanduaServer.Alerts.Notifier.send_escalation_notification(alert)

      "resolved" ->
        # Update SLA metrics
        TamanduaServer.Alerts.SLATracker.mark_resolved(alert)

      "closed" ->
        # Final cleanup
        TamanduaServer.Alerts.SLATracker.mark_closed(alert)

      _ ->
        :ok
    end
  end

  # Map new workflow states to legacy status field
  defp map_state_to_legacy_status(state) do
    case state do
      "new" -> "new"
      "assigned" -> "new"
      "investigating" -> "investigating"
      "pending_info" -> "investigating"
      "resolved" -> "resolved"
      "false_positive" -> "false_positive"
      "escalated" -> "investigating"
      "closed" -> "resolved"
      _ -> "new"
    end
  end
end

# Schema moved to separate file: a_state_transition.ex (TamanduaServer.Alerts.StateTransition)
