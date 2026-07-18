defmodule TamanduaServer.Alerts.Assignment do
  @moduledoc """
  Alert assignment management with auto-assignment strategies and workload balancing.

  ## Assignment Strategies

  - **Round Robin** - Distribute alerts evenly across analysts in rotation
  - **Least Busy** - Assign to analyst with lowest current workload
  - **Expertise** - Match alert characteristics to analyst expertise
  - **Random** - Random assignment (for testing)

  ## Auto-Assignment

  Rules can be configured to automatically assign alerts based on:
  - Alert severity
  - MITRE techniques/tactics
  - Alert source (YARA, Sigma, ML, etc.)
  - Time of day / business hours

  ## Workload Balancing

  Tracks analyst workload using weighted scoring:
  - Critical alerts: 4 points
  - High alerts: 2 points
  - Medium alerts: 1 point
  - Low alerts: 0.5 points
  """

  use Ecto.Schema
  import Ecto.{Changeset, Query}
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Alerts.{Alert, AlertAssignment, AnalystWorkload, AutoAssignmentRule}
  alias TamanduaServer.Accounts.User


  # Severity weights for workload calculation
  @severity_weights %{
    "critical" => 4.0,
    "high" => 2.0,
    "medium" => 1.0,
    "low" => 0.5,
    "info" => 0.25
  }

  # ===========================================================================
  # Public API - Manual Assignment
  # ===========================================================================

  @doc """
  Manually assign an alert to an analyst.

  ## Options

  - `:assigned_by_id` - ID of user making the assignment (required)
  - `:notes` - Optional assignment notes
  - `:transition_state` - Whether to transition workflow state (default: true)

  ## Examples

      iex> assign(alert, analyst.id, assigned_by_id: admin.id, notes: "SME for this attack type")
      {:ok, updated_alert}
  """
  def assign(%Alert{} = alert, analyst_id, opts \\ []) do
    assigned_by_id = Keyword.fetch!(opts, :assigned_by_id)
    notes = Keyword.get(opts, :notes)
    transition_state = Keyword.get(opts, :transition_state, true)

    with {:ok, analyst} <- get_analyst(analyst_id),
         :ok <- validate_analyst_capacity(analyst_id) do

      now = DateTime.utc_now()

      Ecto.Multi.new()
      |> Ecto.Multi.update(:alert, update_alert_assignment(alert, analyst_id, now, assigned_by_id, notes))
      |> Ecto.Multi.insert(:assignment_history, create_assignment_record(alert, analyst_id, assigned_by_id, "manual", notes))
      |> Ecto.Multi.run(:update_workload, fn _repo, _ ->
        update_analyst_workload(analyst_id, alert.severity, :increment)
      end)
      |> Ecto.Multi.run(:transition_state, fn _repo, %{alert: updated_alert} ->
        if transition_state and updated_alert.workflow_state == "new" do
          TamanduaServer.Alerts.Workflow.transition_state(
            updated_alert,
            "assigned",
            user_id: assigned_by_id,
            notes: "Auto-transitioned on assignment"
          )
        else
          {:ok, updated_alert}
        end
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{transition_state: updated_alert}} ->
          Logger.info("[Assignment] Alert #{alert.id} manually assigned to #{analyst_id} by #{assigned_by_id}")
          notify_assignment(updated_alert, analyst)
          {:ok, updated_alert}

        {:error, _operation, reason, _changes} ->
          {:error, reason}
      end
    end
  end

  @doc """
  Unassign an alert from an analyst.

  ## Options

  - `:unassigned_by_id` - ID of user making the unassignment (required)
  - `:reason` - Reason for unassignment
  """
  def unassign(%Alert{} = alert, opts \\ []) do
    unassigned_by_id = Keyword.fetch!(opts, :unassigned_by_id)
    reason = Keyword.get(opts, :reason)

    if is_nil(alert.assigned_to_id) do
      {:error, :not_assigned}
    else
      _now = DateTime.utc_now()

      Ecto.Multi.new()
      |> Ecto.Multi.update(:alert, change(alert, %{assigned_to_id: nil, assigned_at: nil}))
      |> Ecto.Multi.run(:update_assignment_history, fn _repo, _ ->
        close_assignment_record(alert, unassigned_by_id, reason)
      end)
      |> Ecto.Multi.run(:update_workload, fn _repo, _ ->
        update_analyst_workload(alert.assigned_to_id, alert.severity, :decrement)
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{alert: updated_alert}} ->
          Logger.info("[Assignment] Alert #{alert.id} unassigned from #{alert.assigned_to_id}")
          {:ok, updated_alert}

        {:error, _operation, reason, _changes} ->
          {:error, reason}
      end
    end
  end

  @doc """
  Reassign an alert to a different analyst with handoff notes.
  """
  def reassign(%Alert{} = alert, new_analyst_id, opts \\ []) do
    assigned_by_id = Keyword.fetch!(opts, :assigned_by_id)
    handoff_notes = Keyword.get(opts, :handoff_notes)

    with {:ok, _analyst} <- get_analyst(new_analyst_id),
         :ok <- validate_analyst_capacity(new_analyst_id) do

      # First unassign from current analyst
      if alert.assigned_to_id do
        update_analyst_workload(alert.assigned_to_id, alert.severity, :decrement)
        close_assignment_record(alert, assigned_by_id, "Reassigned")
      end

      # Then assign to new analyst
      now = DateTime.utc_now()

      Ecto.Multi.new()
      |> Ecto.Multi.update(:alert, update_alert_assignment(alert, new_analyst_id, now, assigned_by_id, nil))
      |> Ecto.Multi.insert(:assignment_history, create_assignment_record(alert, new_analyst_id, assigned_by_id, "manual", handoff_notes))
      |> Ecto.Multi.run(:update_workload, fn _repo, _ ->
        update_analyst_workload(new_analyst_id, alert.severity, :increment)
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{alert: updated_alert}} ->
          Logger.info("[Assignment] Alert #{alert.id} reassigned from #{alert.assigned_to_id} to #{new_analyst_id}")
          {:ok, updated_alert}

        {:error, _operation, reason, _changes} ->
          {:error, reason}
      end
    end
  end

  # ===========================================================================
  # Public API - Auto-Assignment
  # ===========================================================================

  @doc """
  Auto-assign an alert based on configured rules.

  Checks all enabled auto-assignment rules and applies the highest priority
  matching rule.

  Returns `{:ok, alert}` if assigned, or `{:ok, :no_matching_rule}` if no
  rule matches.
  """
  def auto_assign(%Alert{} = alert) do
    case get_matching_auto_assignment_rule(alert) do
      nil ->
        {:ok, :no_matching_rule}

      rule ->
        apply_auto_assignment_rule(alert, rule)
    end
  end

  @doc """
  Bulk auto-assign multiple alerts.

  Returns `{assigned_count, failed_count}`.
  """
  def bulk_auto_assign(alert_ids) when is_list(alert_ids) do
    results = Enum.map(alert_ids, fn alert_id ->
      case TamanduaServer.Alerts.get_alert(alert_id) do
        {:ok, alert} -> auto_assign(alert)
        error -> error
      end
    end)

    assigned_count = Enum.count(results, fn result ->
      match?({:ok, %Alert{}}, result)
    end)
    failed_count = length(results) - assigned_count

    {assigned_count, failed_count}
  end

  # ===========================================================================
  # Public API - Assignment Rules
  # ===========================================================================

  @doc """
  Create an auto-assignment rule.
  """
  def create_auto_assignment_rule(attrs) do
    struct(AutoAssignmentRule)
    |> AutoAssignmentRule.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update an auto-assignment rule.
  """
  def update_auto_assignment_rule(rule, attrs) when is_map(rule) do
    rule
    |> AutoAssignmentRule.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete an auto-assignment rule.
  """
  def delete_auto_assignment_rule(rule) when is_map(rule) do
    Repo.delete(rule)
  end

  @doc """
  List auto-assignment rules.
  """
  def list_auto_assignment_rules(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)
    enabled_only = Keyword.get(opts, :enabled_only, false)

    query = from(r in AutoAssignmentRule, order_by: [desc: r.priority, asc: r.inserted_at])

    query = if organization_id do
      from(r in query, where: r.organization_id == ^organization_id)
    else
      query
    end

    query = if enabled_only do
      from(r in query, where: r.enabled == true)
    else
      query
    end

    Repo.all(query)
  end

  # ===========================================================================
  # Public API - Workload Management
  # ===========================================================================

  @doc """
  Get current workload for an analyst.
  """
  def get_analyst_workload(analyst_id, organization_id \\ nil) do
    case Repo.get_by(AnalystWorkload, user_id: analyst_id, organization_id: organization_id) do
      nil ->
        # Initialize if not exists
        {:ok, workload} = create_analyst_workload(analyst_id, organization_id)
        workload

      workload ->
        workload
    end
  end

  @doc """
  Get workload for all analysts in an organization.

  Returns list sorted by total_workload_score (ascending - least busy first).
  """
  def list_analyst_workloads(organization_id, opts \\ []) do
    only_available = Keyword.get(opts, :only_available, false)

    query = from(w in AnalystWorkload,
      where: w.organization_id == ^organization_id,
      order_by: [asc: w.total_workload_score],
      preload: :user
    )

    query = if only_available do
      from(w in query, where: w.is_available == true and w.assigned_count < w.max_capacity)
    else
      query
    end

    Repo.all(query)
  end

  @doc """
  Set analyst availability status.
  """
  def set_analyst_availability(analyst_id, is_available, organization_id \\ nil) do
    workload = get_analyst_workload(analyst_id, organization_id)

    workload
    |> change(%{is_available: is_available})
    |> Repo.update()
  end

  @doc """
  Get assignment history for an alert.
  """
  def get_assignment_history(alert_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)

    from(a in AlertAssignment,
      where: a.alert_id == ^alert_id,
      order_by: [desc: a.inserted_at],
      limit: ^limit,
      preload: [:assigned_to, :assigned_by, :unassigned_by]
    )
    |> Repo.all()
  end

  @doc """
  Get alerts assigned to an analyst.
  """
  def get_assigned_alerts(analyst_id, opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)
    states = Keyword.get(opts, :states, ["assigned", "investigating", "pending_info"])
    limit = Keyword.get(opts, :limit, 100)

    query = from(a in Alert,
      where: a.assigned_to_id == ^analyst_id,
      where: a.workflow_state in ^states,
      order_by: [desc: a.severity, desc: a.inserted_at],
      limit: ^limit,
      preload: [:agent]
    )

    query = if organization_id do
      from(a in query, where: a.organization_id == ^organization_id)
    else
      query
    end

    Repo.all(query)
  end

  # ===========================================================================
  # Private Helpers - Auto-Assignment
  # ===========================================================================

  defp get_matching_auto_assignment_rule(%Alert{} = alert) do
    rules = list_auto_assignment_rules(
      organization_id: alert.organization_id,
      enabled_only: true
    )

    # Find first matching rule (sorted by priority)
    Enum.find(rules, fn rule ->
      rule_matches_alert?(rule, alert)
    end)
  end

  defp rule_matches_alert?(rule, %Alert{} = alert) when is_map(rule) do
    severity_filter = rule.severity_filter || []
    source_filter = rule.source_filter || []
    alert_source = alert_source(alert)

    severity_match = length(severity_filter) == 0 or alert.severity in severity_filter
    source_match = length(source_filter) == 0 or source_matches_filter?(alert_source, source_filter)

    mitre_techniques = rule.mitre_techniques || []
    mitre_tactics = rule.mitre_tactics || []

    technique_match = length(mitre_techniques) == 0 or
      Enum.any?(mitre_techniques, fn tech -> tech in (alert.mitre_techniques || []) end)

    tactic_match = length(mitre_tactics) == 0 or
      Enum.any?(mitre_tactics, fn tactic -> tactic in (alert.mitre_tactics || []) end)

    severity_match and source_match and technique_match and tactic_match
  end

  defp alert_source(%Alert{} = alert) do
    explicit_source =
      [
        map_value(alert.detection_metadata, "source"),
        map_value(alert.detection_metadata, "detection_source"),
        map_value(alert.raw_event, "source"),
        map_value(alert.raw_event, "alert_source"),
        map_value(nested_map(alert.raw_event, "payload"), "detection_source"),
        map_value(nested_map(alert.raw_event, "payload"), "source"),
        map_value(nested_map(alert.raw_event, "metadata"), "detection_source"),
        map_value(nested_map(alert.raw_event, "metadata"), "source"),
        map_value(alert.evidence, "source"),
        map_value(alert.evidence, "detection_source"),
        map_value(alert.evidence, "alert_source")
      ]
      |> Enum.find(&(is_binary(&1) and String.trim(&1) != ""))

    explicit_source || inferred_alert_source(alert) || "behavioral"
  end

  defp inferred_alert_source(%Alert{} = alert) do
    [
      alert.detection_metadata,
      alert.raw_event,
      nested_map(alert.raw_event, "payload"),
      alert.evidence
    ]
    |> Enum.find_value(&inferred_map_source/1)
  end

  defp inferred_map_source(metadata) when is_map(metadata) do
    detection_type = map_value(metadata, "detection_type")
    rule_type = map_value(metadata, "rule_type")
    rule_name = map_value(metadata, "rule_name")
    onnx_model_version = map_value(metadata, "onnx_model_version")
    ml_model = map_value(metadata, "ml_model")

    cond do
      ml_source_value?(detection_type) -> "ml"
      ml_source_value?(rule_type) -> "ml"
      present_string?(onnx_model_version) -> "ml"
      present_string?(ml_model) -> "ml"
      is_binary(rule_name) and String.starts_with?(String.upcase(rule_name), "ML_") -> "ml"
      is_binary(rule_name) and String.starts_with?(String.upcase(rule_name), "OFFLINE_ML") -> "ml"
      true -> nil
    end
  end

  defp inferred_map_source(_metadata), do: nil

  defp nested_map(map, key) do
    case map_value(map, key) do
      nested when is_map(nested) -> nested
      _ -> nil
    end
  end

  defp map_value(map, key) when is_map(map) and is_binary(key) do
    Map.get(map, key) ||
      Enum.find_value(map, fn
        {map_key, value} when is_atom(map_key) ->
          if Atom.to_string(map_key) == key, do: value, else: nil

        _ ->
          nil
      end)
  end

  defp map_value(_map, _key), do: nil

  defp source_matches_filter?(source, filters) when is_binary(source) do
    normalized_source = source |> String.trim() |> String.downcase()

    Enum.any?(filters, fn filter ->
      is_binary(filter) and String.downcase(String.trim(filter)) == normalized_source
    end)
  end

  defp source_matches_filter?(_source, _filters), do: false

  defp ml_source_value?(value) when is_binary(value), do: String.downcase(String.trim(value)) == "ml"
  defp ml_source_value?(_value), do: false

  defp present_string?(value), do: is_binary(value) and String.trim(value) != ""

  defp apply_auto_assignment_rule(%Alert{} = alert, rule) when is_map(rule) do
    analyst_id = case rule.strategy do
      "round_robin" -> select_analyst_round_robin(rule.analyst_pool, alert.organization_id)
      "least_busy" -> select_analyst_least_busy(rule.analyst_pool, alert.organization_id)
      "expertise" -> select_analyst_by_expertise(rule.expertise_map, alert)
      "random" -> select_analyst_random(rule.analyst_pool)
      _ -> nil
    end

    if analyst_id do
      now = DateTime.utc_now()
      assignment_type = "auto_#{rule.strategy}"

      Ecto.Multi.new()
      |> Ecto.Multi.update(:alert, update_alert_assignment(alert, analyst_id, now, nil, "Auto-assigned via rule: #{rule.name}"))
      |> Ecto.Multi.insert(:assignment_history, create_assignment_record(alert, analyst_id, nil, assignment_type, "Rule: #{rule.name}"))
      |> Ecto.Multi.run(:update_workload, fn _repo, _ ->
        update_analyst_workload(analyst_id, alert.severity, :increment)
      end)
      |> Ecto.Multi.run(:transition_state, fn _repo, %{alert: updated_alert} ->
        if updated_alert.workflow_state == "new" do
          TamanduaServer.Alerts.Workflow.transition_state(
            updated_alert,
            "assigned",
            user_id: analyst_id,
            notes: "Auto-assigned by system"
          )
        else
          {:ok, updated_alert}
        end
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{transition_state: updated_alert}} ->
          Logger.info("[Assignment] Alert #{alert.id} auto-assigned to #{analyst_id} via #{rule.strategy}")
          {:ok, updated_alert}

        {:error, _operation, reason, _changes} ->
          {:error, reason}
      end
    else
      {:ok, :no_available_analyst}
    end
  end

  defp select_analyst_round_robin(analyst_pool, organization_id) do
    # Find analyst with oldest last_assignment_at
    workloads = from(w in AnalystWorkload,
      where: w.user_id in ^analyst_pool,
      where: w.organization_id == ^organization_id,
      where: w.is_available == true,
      where: w.assigned_count < w.max_capacity,
      order_by: [asc: w.last_assignment_at],
      limit: 1
    )
    |> Repo.all()

    case workloads do
      [workload | _] -> workload.user_id
      [] -> nil
    end
  end

  defp select_analyst_least_busy(analyst_pool, organization_id) do
    # Find analyst with lowest workload score
    workloads = from(w in AnalystWorkload,
      where: w.user_id in ^analyst_pool,
      where: w.organization_id == ^organization_id,
      where: w.is_available == true,
      where: w.assigned_count < w.max_capacity,
      order_by: [asc: w.total_workload_score],
      limit: 1
    )
    |> Repo.all()

    case workloads do
      [workload | _] -> workload.user_id
      [] -> nil
    end
  end

  defp select_analyst_by_expertise(expertise_map, %Alert{} = alert) do
    # Find analysts with expertise in the MITRE techniques
    matching_analysts = alert.mitre_techniques
    |> Enum.flat_map(fn tech ->
      Map.get(expertise_map, tech, [])
    end)
    |> Enum.uniq()

    if length(matching_analysts) > 0 do
      # Among matching analysts, pick least busy
      select_analyst_least_busy(matching_analysts, alert.organization_id)
    else
      nil
    end
  end

  defp select_analyst_random(analyst_pool) do
    Enum.random(analyst_pool)
  end

  # ===========================================================================
  # Private Helpers - Workload Management
  # ===========================================================================

  defp create_analyst_workload(analyst_id, organization_id) do
    %AnalystWorkload{
      user_id: analyst_id,
      organization_id: organization_id,
      assigned_count: 0,
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      total_workload_score: 0.0
    }
    |> Repo.insert(on_conflict: :nothing)
  end

  defp update_analyst_workload(analyst_id, severity, operation) when operation in [:increment, :decrement] do
    workload = get_analyst_workload(analyst_id)

    delta = if operation == :increment, do: 1, else: -1
    score_delta = delta * Map.get(@severity_weights, severity, 0.5)

    severity_field = severity_to_count_field(severity)

    updates = %{
      assigned_count: max(0, workload.assigned_count + delta),
      total_workload_score: max(0.0, workload.total_workload_score + score_delta),
      last_assignment_at: DateTime.utc_now()
    }

    updates = Map.put(updates, severity_field, max(0, Map.get(workload, severity_field, 0) + delta))

    workload
    |> change(updates)
    |> Repo.update()
  end

  defp severity_to_count_field("critical"), do: :critical_count
  defp severity_to_count_field("high"), do: :high_count
  defp severity_to_count_field("medium"), do: :medium_count
  defp severity_to_count_field("low"), do: :low_count
  defp severity_to_count_field(_), do: :low_count

  # ===========================================================================
  # Private Helpers - Database Operations
  # ===========================================================================

  defp get_analyst(analyst_id) do
    case Repo.get(User, analyst_id) do
      nil -> {:error, :analyst_not_found}
      analyst -> {:ok, analyst}
    end
  end

  defp validate_analyst_capacity(analyst_id) do
    workload = get_analyst_workload(analyst_id)

    cond do
      not workload.is_available ->
        {:error, :analyst_unavailable}

      workload.assigned_count >= workload.max_capacity ->
        {:error, :analyst_at_capacity}

      true ->
        :ok
    end
  end

  defp update_alert_assignment(alert, analyst_id, assigned_at, assigned_by_id, notes) do
    alert
    |> change(%{
      assigned_to_id: analyst_id,
      assigned_at: assigned_at,
      assigned_by_id: assigned_by_id,
      assignment_notes: notes
    })
  end

  defp create_assignment_record(alert, analyst_id, assigned_by_id, assignment_type, handoff_notes) do
    %AlertAssignment{
      alert_id: alert.id,
      assigned_to_id: analyst_id,
      assigned_by_id: assigned_by_id,
      assignment_type: assignment_type,
      handoff_notes: handoff_notes
    }
  end

  defp close_assignment_record(alert, unassigned_by_id, reason) do
    # Find most recent open assignment
    assignment = from(a in AlertAssignment,
      where: a.alert_id == ^alert.id,
      where: is_nil(a.unassigned_at),
      order_by: [desc: a.inserted_at],
      limit: 1
    )
    |> Repo.one()

    if assignment do
      assignment
      |> change(%{
        unassigned_at: DateTime.utc_now(),
        unassigned_by_id: unassigned_by_id,
        unassignment_reason: reason
      })
      |> Repo.update()
    else
      {:ok, nil}
    end
  end

  defp notify_assignment(alert, analyst) do
    # Send notification to analyst
    TamanduaServer.Alerts.Notifier.send_assignment_notification(alert, analyst)
  end
end

# Schemas moved to separate files:
# - a_alert_assignment.ex (TamanduaServer.Alerts.AlertAssignment)
# - a_analyst_workload.ex (TamanduaServer.Alerts.AnalystWorkload)
# - a_auto_assignment_rule.ex (TamanduaServer.Alerts.AutoAssignmentRule)
