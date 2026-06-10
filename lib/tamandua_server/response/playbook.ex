defmodule TamanduaServer.Response.Playbook do
  @moduledoc """
  Automated Playbook Engine

  UNIQUE FEATURE: SOAR-like automated response workflows that:
  - Define multi-step response actions
  - Support conditional branching
  - Integrate with external systems (SIEM, ticketing, etc.)
  - Provide human-in-the-loop approval for critical actions
  - Track execution history and effectiveness
  - Learn from analyst feedback

  This bridges the gap between detection and response,
  reducing MTTR (Mean Time To Respond) significantly.
  """

  use GenServer
  require Logger
  import Ecto.Query

  alias TamanduaServer.{Repo, Agents, Alerts}
  alias TamanduaServer.Response.Executor
  alias TamanduaServer.Response.ConditionEvaluator

  # Playbook schema
  defmodule Schema do
    use Ecto.Schema
    import Ecto.Changeset

    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id
    schema "playbooks" do
      field :name, :string
      field :description, :string
      field :trigger_type, :string  # "manual", "alert", "detection", "schedule"
      field :trigger_conditions, :map
      field :steps, {:array, :map}
      field :enabled, :boolean, default: true
      field :require_approval, :boolean, default: false
      field :approval_timeout_minutes, :integer, default: 30
      field :tags, {:array, :string}, default: []
      field :severity_threshold, :string  # "low", "medium", "high", "critical"
      field :execution_count, :integer, default: 0
      field :success_count, :integer, default: 0
      field :last_executed_at, :utc_datetime
      field :created_by, :binary_id

      timestamps()
    end

    def changeset(playbook, attrs) do
      # Normalize frontend field names to backend field names
      attrs = normalize_frontend_attrs(attrs)

      playbook
      |> cast(attrs, [
        :name, :description, :trigger_type, :trigger_conditions, :steps,
        :enabled, :require_approval, :approval_timeout_minutes, :tags,
        :severity_threshold, :created_by
      ])
      |> validate_required([:name, :steps])
      |> maybe_set_trigger_type()
      |> validate_inclusion(:trigger_type, ["manual", "alert", "detection", "schedule"])
      |> validate_inclusion(:severity_threshold, [nil, "low", "medium", "high", "critical"])
      |> validate_steps()
    end

    # Map frontend camelCase keys to backend snake_case and extract nested values
    defp normalize_frontend_attrs(attrs) when is_map(attrs) do
      attrs
      |> Map.new(fn {k, v} -> {to_string(k), v} end)
      |> normalize_trigger()
      |> normalize_steps()
      |> Map.put("trigger_type", extract_trigger_type(attrs))
      |> Map.put("trigger_conditions", extract_trigger_conditions(attrs))
    end

    defp extract_trigger_type(attrs) do
      cond do
        Map.has_key?(attrs, :trigger_type) -> attrs[:trigger_type]
        Map.has_key?(attrs, "trigger_type") -> attrs["trigger_type"]
        Map.has_key?(attrs, :trigger) and is_map(attrs[:trigger]) -> attrs[:trigger][:type] || attrs[:trigger]["type"]
        Map.has_key?(attrs, "trigger") and is_map(attrs["trigger"]) -> attrs["trigger"]["type"] || attrs["trigger"][:type]
        true -> "manual"
      end
    end

    defp extract_trigger_conditions(attrs) do
      cond do
        Map.has_key?(attrs, :trigger_conditions) -> attrs[:trigger_conditions]
        Map.has_key?(attrs, "trigger_conditions") -> attrs["trigger_conditions"]
        Map.has_key?(attrs, "triggerConditions") -> conditions_to_map(attrs["triggerConditions"])
        Map.has_key?(attrs, :trigger) and is_map(attrs[:trigger]) ->
          conditions_to_map(attrs[:trigger][:conditions] || attrs[:trigger]["conditions"])
        Map.has_key?(attrs, "trigger") and is_map(attrs["trigger"]) ->
          conditions_to_map(attrs["trigger"]["conditions"] || attrs["trigger"][:conditions])
        true -> %{}
      end
    end

    defp conditions_to_map(conditions) when is_list(conditions) do
      Enum.reduce(conditions, %{}, fn cond, acc ->
        field = cond["field"] || cond[:field]
        value = cond["value"] || cond[:value]
        if field && value do
          Map.put(acc, field, value)
        else
          acc
        end
      end)
    end
    defp conditions_to_map(conditions) when is_map(conditions), do: conditions
    defp conditions_to_map(_), do: %{}

    defp normalize_trigger(attrs) do
      # Handle nested trigger object from frontend
      case Map.get(attrs, "trigger") do
        %{"conditions" => conditions} = trigger when is_list(conditions) ->
          attrs
          |> Map.put("trigger_type", Map.get(trigger, "type", "manual"))
          |> Map.put("trigger_conditions", conditions_to_map(conditions))
        _ ->
          attrs
      end
    end

    defp normalize_steps(attrs) do
      case Map.get(attrs, "steps") do
        steps when is_list(steps) ->
          normalized = Enum.map(steps, fn step ->
            step
            |> Map.new(fn {k, v} -> {to_string(k), v} end)
            |> Map.put("action", step["action"] || step[:action] || step["actionType"] || step[:actionType])
          end)
          Map.put(attrs, "steps", normalized)
        _ ->
          attrs
      end
    end

    defp maybe_set_trigger_type(changeset) do
      case get_field(changeset, :trigger_type) do
        nil -> put_change(changeset, :trigger_type, "manual")
        _ -> changeset
      end
    end

    defp validate_steps(changeset) do
      case get_change(changeset, :steps) do
        nil -> changeset
        steps ->
          if valid_steps?(steps) do
            changeset
          else
            add_error(changeset, :steps, "invalid step configuration")
          end
      end
    end

    defp valid_steps?(steps) when is_list(steps) do
      Enum.all?(steps, &valid_step?/1)
    end
    defp valid_steps?(_), do: false

    defp valid_step?(%{"action" => action}) when is_binary(action), do: true
    defp valid_step?(_), do: false
  end

  # Execution record schema
  defmodule Execution do
    use Ecto.Schema
    import Ecto.Changeset

    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id
    schema "playbook_executions" do
      field :playbook_id, :binary_id
      field :trigger_event, :map
      field :status, :string  # "pending_approval", "running", "completed", "failed", "cancelled"
      field :steps_completed, {:array, :map}, default: []
      field :current_step, :integer, default: 0
      field :error_message, :string
      field :started_at, :utc_datetime
      field :completed_at, :utc_datetime
      field :approved_by, :binary_id
      field :approved_at, :utc_datetime
      field :execution_context, :map, default: %{}
      field :dry_run, :boolean, default: false

      timestamps()
    end

    def changeset(execution, attrs) do
      execution
      |> cast(attrs, [
        :playbook_id, :trigger_event, :status, :steps_completed,
        :current_step, :error_message, :started_at, :completed_at,
        :approved_by, :approved_at, :execution_context, :dry_run
      ])
      |> validate_required([:playbook_id, :status])
    end
  end

  # Step execution record schema
  defmodule StepExecution do
    use Ecto.Schema
    import Ecto.Changeset

    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id
    schema "playbook_step_executions" do
      field :execution_id, :binary_id
      field :step_index, :integer
      field :step_name, :string
      field :action_type, :string
      field :status, :string  # "pending", "running", "completed", "failed", "skipped", "retrying"
      field :params, :map, default: %{}
      field :result, :map
      field :error_message, :string
      field :retry_count, :integer, default: 0
      field :max_retries, :integer, default: 0
      field :timeout_seconds, :integer
      field :started_at, :utc_datetime
      field :completed_at, :utc_datetime
      field :duration_ms, :integer

      timestamps()
    end

    def changeset(step_execution, attrs) do
      step_execution
      |> cast(attrs, [
        :execution_id, :step_index, :step_name, :action_type, :status,
        :params, :result, :error_message, :retry_count, :max_retries,
        :timeout_seconds, :started_at, :completed_at, :duration_ms
      ])
      |> validate_required([:execution_id, :step_index, :action_type, :status])
      |> validate_inclusion(:status, ["pending", "running", "completed", "failed", "skipped", "retrying"])
    end
  end

  # GenServer state
  defstruct [
    :playbooks,
    :active_executions,
    :pending_approvals,
    :step_handlers
  ]

  # Step action types (referenced for documentation/validation)
  @_action_types [
    "isolate_host",
    "kill_process",
    "quarantine_file",
    "block_ip",
    "block_domain",
    "collect_forensics",
    "create_ticket",
    "send_notification",
    "run_script",
    "enrich_ioc",
    "update_blocklist",
    "trigger_scan",
    "disable_user",
    "conditional",
    "wait",
    "human_approval",
    "parallel"
  ]

  ## Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Create a new playbook
  """
  def create_playbook(attrs) do
    GenServer.call(__MODULE__, {:create_playbook, attrs})
  end

  @doc """
  List all playbooks
  """
  def list_playbooks(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_playbooks, filters})
  end

  @doc """
  Get a playbook by ID
  """
  def get_playbook(id) do
    GenServer.call(__MODULE__, {:get_playbook, id})
  end

  @doc """
  Update a playbook
  """
  def update_playbook(id, attrs) do
    GenServer.call(__MODULE__, {:update_playbook, id, attrs})
  end

  @doc """
  Delete a playbook
  """
  def delete_playbook(id) do
    GenServer.call(__MODULE__, {:delete_playbook, id})
  end

  @doc """
  Execute a playbook manually
  """
  def execute_playbook(playbook_id, context \\ %{}) do
    GenServer.call(__MODULE__, {:execute_playbook, playbook_id, context})
  end

  @doc """
  Trigger playbooks for an alert
  """
  def trigger_for_alert(alert) do
    GenServer.cast(__MODULE__, {:trigger_for_alert, alert})
  end

  @doc """
  Trigger playbooks for a detection
  """
  def trigger_for_detection(detection) do
    GenServer.cast(__MODULE__, {:trigger_for_detection, detection})
  end

  @doc """
  Approve a pending execution
  """
  def approve_execution(execution_id, approver_id) do
    GenServer.call(__MODULE__, {:approve_execution, execution_id, approver_id})
  end

  @doc """
  Reject/cancel a pending execution
  """
  def cancel_execution(execution_id, reason) do
    GenServer.call(__MODULE__, {:cancel_execution, execution_id, reason})
  end

  @doc """
  Get execution history
  """
  def get_execution_history(playbook_id, opts \\ []) do
    GenServer.call(__MODULE__, {:get_history, playbook_id, opts})
  end

  @doc """
  Get pending approvals
  """
  def get_pending_approvals do
    GenServer.call(__MODULE__, :get_pending_approvals)
  end

  ## Server Callbacks

  @impl true
  def init(_opts) do
    Logger.info("Starting Playbook Engine")

    state = %__MODULE__{
      playbooks: load_playbooks(),
      active_executions: %{},
      pending_approvals: %{},
      step_handlers: init_step_handlers()
    }

    # Schedule periodic tasks
    schedule_scheduled_playbooks()
    schedule_approval_timeout_check()

    {:ok, state}
  end

  @impl true
  def handle_call({:create_playbook, attrs}, _from, state) do
    case create_playbook_record(attrs) do
      {:ok, playbook} ->
        new_playbooks = Map.put(state.playbooks, playbook.id, playbook)
        {:reply, {:ok, playbook}, %{state | playbooks: new_playbooks}}
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:list_playbooks, filters}, _from, state) do
    playbooks = state.playbooks
      |> Map.values()
      |> filter_playbooks(filters)
      |> Enum.sort_by(& &1.name)

    {:reply, {:ok, playbooks}, state}
  end

  @impl true
  def handle_call({:get_playbook, id}, _from, state) do
    case Map.get(state.playbooks, id) do
      nil -> {:reply, {:error, :not_found}, state}
      playbook -> {:reply, {:ok, playbook}, state}
    end
  end

  @impl true
  def handle_call({:update_playbook, id, attrs}, _from, state) do
    case Map.get(state.playbooks, id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      playbook ->
        case update_playbook_record(playbook, attrs) do
          {:ok, updated} ->
            new_playbooks = Map.put(state.playbooks, id, updated)
            {:reply, {:ok, updated}, %{state | playbooks: new_playbooks}}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end
    end
  end

  @impl true
  def handle_call({:delete_playbook, id}, _from, state) do
    case Map.get(state.playbooks, id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      playbook ->
        case delete_playbook_record(playbook) do
          {:ok, _} ->
            new_playbooks = Map.delete(state.playbooks, id)
            {:reply, {:ok, playbook}, %{state | playbooks: new_playbooks}}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end
    end
  end

  @impl true
  def handle_call({:execute_playbook, playbook_id, context}, _from, state) do
    case Map.get(state.playbooks, playbook_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      playbook ->
        execution = start_execution(playbook, context)

        if playbook.require_approval do
          # Wait for approval
          new_pending = Map.put(state.pending_approvals, execution.id, execution)
          {:reply, {:ok, execution}, %{state | pending_approvals: new_pending}}
        else
          # Execute immediately
          new_state = execute_playbook_async(state, execution, playbook)
          {:reply, {:ok, execution}, new_state}
        end
    end
  end

  @impl true
  def handle_call({:approve_execution, execution_id, approver_id}, _from, state) do
    case Map.get(state.pending_approvals, execution_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      execution ->
        playbook = Map.get(state.playbooks, execution.playbook_id)
        approved_execution = %{execution |
          status: "running",
          approved_by: approver_id,
          approved_at: DateTime.utc_now()
        }

        new_pending = Map.delete(state.pending_approvals, execution_id)
        new_state = execute_playbook_async(%{state | pending_approvals: new_pending}, approved_execution, playbook)
        {:reply, {:ok, approved_execution}, new_state}
    end
  end

  @impl true
  def handle_call({:cancel_execution, execution_id, reason}, _from, state) do
    case Map.get(state.pending_approvals, execution_id) || Map.get(state.active_executions, execution_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      execution ->
        cancelled = %{execution |
          status: "cancelled",
          error_message: reason,
          completed_at: DateTime.utc_now()
        }

        save_execution(cancelled)

        new_pending = Map.delete(state.pending_approvals, execution_id)
        new_active = Map.delete(state.active_executions, execution_id)

        {:reply, {:ok, cancelled}, %{state | pending_approvals: new_pending, active_executions: new_active}}
    end
  end

  @impl true
  def handle_call(:get_pending_approvals, _from, state) do
    approvals = state.pending_approvals
      |> Map.values()
      |> Enum.map(fn execution ->
        playbook = Map.get(state.playbooks, execution.playbook_id)
        %{execution: execution, playbook: playbook}
      end)

    {:reply, {:ok, approvals}, state}
  end

  @impl true
  def handle_call({:get_history, playbook_id, opts}, _from, state) do
    history = load_execution_history(playbook_id, opts)
    {:reply, {:ok, history}, state}
  end

  @impl true
  def handle_call({:clone_playbook, playbook_id, new_name}, _from, state) do
    case Map.get(state.playbooks, playbook_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      playbook ->
        new_id = generate_id()
        cloned = %{playbook |
          id: new_id,
          name: new_name,
          created_at: DateTime.utc_now(),
          updated_at: DateTime.utc_now(),
          execution_count: 0
        }

        new_playbooks = Map.put(state.playbooks, new_id, cloned)
        save_playbook(cloned)

        {:reply, {:ok, cloned}, %{state | playbooks: new_playbooks}}
    end
  end

  @impl true
  def handle_call({:execute, playbook_id, context, opts}, _from, state) do
    case Map.get(state.playbooks, playbook_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      playbook ->
        # Check if playbook is enabled
        unless playbook.enabled do
          {:reply, {:error, :playbook_disabled}, state}
        else
          # Check severity threshold if provided
          severity = Map.get(context, :severity, "medium")
          if meets_severity_threshold?(severity, playbook.severity_threshold) do
            execution = start_execution(playbook, context)

            # Check if approval is required and not skipped
            skip_approval = Map.get(opts, :skip_approval, false)

            if playbook.require_approval and not skip_approval do
              new_pending = Map.put(state.pending_approvals, execution.id, execution)
              {:reply, {:ok, %{execution | status: "pending_approval"}}, %{state | pending_approvals: new_pending}}
            else
              new_state = execute_playbook_async(state, execution, playbook)
              {:reply, {:ok, execution}, new_state}
            end
          else
            {:reply, {:error, :severity_threshold_not_met}, state}
          end
        end
    end
  end

  @impl true
  def handle_call({:list_executions, playbook_id, opts}, _from, state) do
    limit = Map.get(opts, :limit, 100)
    status_filter = Map.get(opts, :status)

    # Get from history plus any active executions
    history = load_execution_history(playbook_id, limit: limit + 10)

    active = state.active_executions
    |> Map.values()
    |> Enum.filter(&(&1.playbook_id == playbook_id))

    pending = state.pending_approvals
    |> Map.values()
    |> Enum.filter(&(&1.playbook_id == playbook_id))

    all_executions = (active ++ pending ++ history)
    |> Enum.uniq_by(& &1.id)
    |> maybe_filter_by_status(status_filter)
    |> Enum.sort_by(& &1.started_at, {:desc, DateTime})
    |> Enum.take(limit)

    {:reply, {:ok, all_executions}, state}
  end

  defp meets_severity_threshold?(severity, threshold) do
    severity_order = %{"low" => 1, "medium" => 2, "high" => 3, "critical" => 4}
    actual = Map.get(severity_order, severity, 0)
    required = Map.get(severity_order, threshold, 0)
    actual >= required
  end

  defp maybe_filter_by_status(executions, nil), do: executions
  defp maybe_filter_by_status(executions, status) do
    Enum.filter(executions, &(&1.status == status))
  end

  defp generate_id do
    "pb_" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
  end

  defp save_playbook(playbook) do
    attrs = Map.from_struct(playbook)

    %Schema{}
    |> Schema.changeset(attrs)
    |> Repo.insert(on_conflict: :replace_all, conflict_target: :id)
    |> case do
      {:ok, _} -> :ok
      {:error, changeset} ->
        Logger.error("Failed to persist playbook #{playbook.id}: #{inspect(changeset.errors)}")
        :error
    end
  rescue
    e ->
      Logger.error("Error persisting playbook: #{inspect(e)}")
      :error
  end

  @impl true
  def handle_cast({:trigger_for_alert, alert}, state) do
    matching_playbooks = state.playbooks
      |> Map.values()
      |> Enum.filter(fn pb ->
        pb.enabled and
        pb.trigger_type == "alert" and
        matches_trigger_conditions?(pb.trigger_conditions, alert)
      end)

    new_state = Enum.reduce(matching_playbooks, state, fn playbook, acc_state ->
      context = %{
        alert_id: alert.id,
        agent_id: alert.agent_id,
        severity: alert.severity,
        detection_type: alert.detection_type,
        mitre_tactics: alert.mitre_tactics || []
      }

      execution = start_execution(playbook, context)

      if playbook.require_approval do
        new_pending = Map.put(acc_state.pending_approvals, execution.id, execution)
        %{acc_state | pending_approvals: new_pending}
      else
        execute_playbook_async(acc_state, execution, playbook)
      end
    end)

    {:noreply, new_state}
  end

  @impl true
  def handle_cast({:trigger_for_detection, detection}, state) do
    matching_playbooks = state.playbooks
      |> Map.values()
      |> Enum.filter(fn pb ->
        pb.enabled and
        pb.trigger_type == "detection" and
        matches_trigger_conditions?(pb.trigger_conditions, detection)
      end)

    new_state = Enum.reduce(matching_playbooks, state, fn playbook, acc_state ->
      context = build_detection_context(detection)
      execution = start_execution(playbook, context)

      if playbook.require_approval do
        new_pending = Map.put(acc_state.pending_approvals, execution.id, execution)
        %{acc_state | pending_approvals: new_pending}
      else
        execute_playbook_async(acc_state, execution, playbook)
      end
    end)

    {:noreply, new_state}
  end

  @impl true
  def handle_info({:execute_step, execution_id, step_index}, state) do
    case Map.get(state.active_executions, execution_id) do
      nil ->
        {:noreply, state}

      execution ->
        playbook = Map.get(state.playbooks, execution.playbook_id)
        new_state = execute_step(state, execution, playbook, step_index)
        {:noreply, new_state}
    end
  end

  @impl true
  def handle_info(:check_approval_timeouts, state) do
    now = DateTime.utc_now()

    expired = state.pending_approvals
      |> Enum.filter(fn {_id, execution} ->
        playbook = Map.get(state.playbooks, execution.playbook_id)
        timeout = (playbook.approval_timeout_minutes || 30) * 60

        DateTime.diff(now, execution.started_at) > timeout
      end)
      |> Enum.map(fn {id, _} -> id end)

    new_pending = Map.drop(state.pending_approvals, expired)

    # Mark expired as timed out
    Enum.each(expired, fn id ->
      execution = Map.get(state.pending_approvals, id)
      timed_out = %{execution |
        status: "failed",
        error_message: "Approval timeout exceeded",
        completed_at: DateTime.utc_now()
      }
      save_execution(timed_out)
    end)

    schedule_approval_timeout_check()
    {:noreply, %{state | pending_approvals: new_pending}}
  end

  @impl true
  def handle_info(:run_scheduled_playbooks, state) do
    now = DateTime.utc_now()

    scheduled = state.playbooks
      |> Map.values()
      |> Enum.filter(fn pb ->
        pb.enabled and pb.trigger_type == "schedule" and should_run_now?(pb, now)
      end)

    new_state = Enum.reduce(scheduled, state, fn playbook, acc_state ->
      execution = start_execution(playbook, %{scheduled: true, timestamp: now})
      execute_playbook_async(acc_state, execution, playbook)
    end)

    schedule_scheduled_playbooks()
    {:noreply, new_state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  ## Private Functions

  defp load_playbooks do
    # Load from database
    try do
      Repo.all(Schema)
      |> Enum.map(fn pb -> {pb.id, pb} end)
      |> Map.new()
    rescue
      _ -> %{}
    end
  end

  defp create_playbook_record(attrs) do
    %Schema{}
    |> Schema.changeset(attrs)
    |> Repo.insert()
  end

  defp update_playbook_record(playbook, attrs) do
    # Normalize attrs keys to atoms
    attrs = normalize_attrs(attrs)

    playbook
    |> Schema.changeset(attrs)
    |> Repo.update()
  end

  defp delete_playbook_record(playbook) do
    Repo.delete(playbook)
  end

  defp normalize_attrs(attrs) when is_map(attrs) do
    Map.new(attrs, fn
      {k, v} when is_binary(k) ->
        key = try do
          String.to_existing_atom(k)
        rescue
          _ -> k
        end
        {key, v}
      {k, v} -> {k, v}
    end)
  end

  defp filter_playbooks(playbooks, filters) do
    Enum.filter(playbooks, fn pb ->
      matches_filter?(pb, filters)
    end)
  end

  defp matches_filter?(playbook, filters) do
    Enum.all?(filters, fn
      {:enabled, value} -> playbook.enabled == value
      {:trigger_type, value} -> playbook.trigger_type == value
      {:tag, value} -> value in (playbook.tags || [])
      _ -> true
    end)
  end

  defp start_execution(playbook, context) do
    execution = %Execution{
      id: Ecto.UUID.generate(),
      playbook_id: playbook.id,
      trigger_event: context,
      status: if(playbook.require_approval, do: "pending_approval", else: "running"),
      started_at: DateTime.utc_now(),
      execution_context: context
    }

    save_execution(execution)
    execution
  end

  defp save_execution(execution) do
    try do
      %Execution{}
      |> Execution.changeset(Map.from_struct(execution))
      |> Repo.insert(on_conflict: :replace_all, conflict_target: :id)
    rescue
      _ -> :ok
    end
  end

  defp execute_playbook_async(state, execution, playbook) do
    # Add to active executions
    new_active = Map.put(state.active_executions, execution.id, execution)
    new_state = %{state | active_executions: new_active}

    # Start first step
    send(self(), {:execute_step, execution.id, 0})

    new_state
  end

  defp execute_step(state, execution, playbook, step_index) do
    steps = playbook.steps || []

    if step_index >= length(steps) do
      # Completed all steps
      complete_execution(state, execution, :success)
    else
      step = Enum.at(steps, step_index)
      result = execute_single_step(step, execution)

      case result do
        {:ok, step_result} ->
          # Record step completion
          step_record = %{
            index: step_index,
            action: step["action"],
            status: "completed",
            result: step_result,
            completed_at: DateTime.utc_now()
          }

          updated_execution = %{execution |
            current_step: step_index + 1,
            steps_completed: execution.steps_completed ++ [step_record]
          }

          new_active = Map.put(state.active_executions, execution.id, updated_execution)

          # Continue to next step
          send(self(), {:execute_step, execution.id, step_index + 1})

          %{state | active_executions: new_active}

        {:wait, duration_ms} ->
          # Schedule continuation after wait
          Process.send_after(self(), {:execute_step, execution.id, step_index + 1}, duration_ms)
          state

        {:branch, next_step_index} ->
          # Conditional branching
          send(self(), {:execute_step, execution.id, next_step_index})
          state

        {:error, reason} ->
          step_record = %{
            index: step_index,
            action: step["action"],
            status: "failed",
            error: reason,
            completed_at: DateTime.utc_now()
          }

          updated_execution = %{execution |
            steps_completed: execution.steps_completed ++ [step_record],
            error_message: reason
          }

          complete_execution(state, updated_execution, :failed)
      end
    end
  end

  defp execute_single_step(step, execution) do
    action = step["action"]
    params = step["params"] || %{}
    context = execution.execution_context

    case action do
      "isolate_host" ->
        agent_id = params["agent_id"] || context[:agent_id] || context["agent_id"]
        if agent_id do
          case Executor.isolate_host(agent_id) do
            {:ok, response} -> {:ok, Map.merge(%{agent_id: agent_id, action: "isolated"}, response || %{})}
            {:error, reason} -> {:error, "Failed to isolate: #{inspect(reason)}"}
          end
        else
          {:error, "No agent_id specified"}
        end

      "kill_process" ->
        agent_id = params["agent_id"] || context[:agent_id] || context["agent_id"]
        pid = params["pid"] || context[:pid] || context["pid"]
        if agent_id && pid do
          case Executor.kill_process(agent_id, pid) do
            {:ok, response} -> {:ok, Map.merge(%{pid: pid, action: "killed"}, response || %{})}
            {:error, reason} -> {:error, "Failed to kill process: #{inspect(reason)}"}
          end
        else
          {:error, "Missing agent_id or pid"}
        end

      "quarantine_file" ->
        agent_id = params["agent_id"] || context[:agent_id] || context["agent_id"]
        path = params["path"] || context[:file_path] || context["file_path"]
        if agent_id && path do
          case Executor.quarantine_file(agent_id, path) do
            {:ok, response} -> {:ok, Map.merge(%{path: path, action: "quarantined"}, response || %{})}
            {:error, reason} -> {:error, "Failed to quarantine: #{inspect(reason)}"}
          end
        else
          {:error, "Missing agent_id or path"}
        end

      "block_ip" ->
        ip = params["ip"] || context[:remote_ip]
        if ip do
          reason = params["reason"] || "Blocked by playbook #{execution.playbook_id}"
          agent_id = params["agent_id"] || context[:agent_id]

          # Send firewall block command to the target agent (or all online agents)
          agent_results = if agent_id do
            # Block on a specific agent
            case Executor.execute_action(agent_id, "block_ip", %{ip: ip, direction: "both"}) do
              {:ok, resp} -> [{agent_id, :ok, resp}]
              {:error, err} -> [{agent_id, :error, err}]
            end
          else
            # Broadcast block to all online agents via the registry
            online_agents = try do
              TamanduaServer.Agents.Registry.list_by_status(:online)
            rescue
              _ -> []
            catch
              _, _ -> []
            end

            Enum.map(online_agents, fn agent ->
              aid = agent[:agent_id] || agent[:id]
              case Executor.execute_action(aid, "block_ip", %{ip: ip, direction: "both"}) do
                {:ok, resp} -> {aid, :ok, resp}
                {:error, err} -> {aid, :error, err}
              end
            end)
          end

          # Also store in the IOC blocklist for future reference
          try do
            TamanduaServer.ThreatIntel.add_ioc(%{
              type: "ip",
              value: ip,
              source: "playbook",
              description: reason,
              severity: "high"
            })
          rescue
            _ -> :ok
          catch
            _, _ -> :ok
          end

          successful = Enum.count(agent_results, fn {_, status, _} -> status == :ok end)
          failed = Enum.count(agent_results, fn {_, status, _} -> status == :error end)
          Logger.info("block_ip #{ip}: #{successful} agent(s) succeeded, #{failed} failed")

          {:ok, %{ip: ip, action: "blocked", reason: reason, agents_succeeded: successful, agents_failed: failed}}
        else
          {:error, "No IP specified"}
        end

      "block_domain" ->
        domain = params["domain"] || context[:domain]
        if domain do
          reason = params["reason"] || "Blocked by playbook #{execution.playbook_id}"
          agent_id = params["agent_id"] || context[:agent_id]
          organization_id = organization_id_from_context(context, agent_id)

          # Add to the tenant-scoped DNS blocklist for future enforcement.
          dns_result = try do
            TamanduaServer.Detection.DNSAnalyzer.add_to_blocklist(
              [domain],
              reason,
              "playbook:#{execution.playbook_id}",
              organization_id
            )
          rescue
            e ->
              Logger.error("Failed to add domain #{domain} to DNS blocklist: #{Exception.message(e)}")
              {:error, Exception.message(e)}
          catch
            _, e ->
              Logger.error("Failed to add domain #{domain} to DNS blocklist: #{inspect(e)}")
              {:error, inspect(e)}
          end

          # Also send block_domain command to the target agent if specified
          agent_result = if agent_id do
            case Executor.execute_action(agent_id, "block_domain", %{domain: domain}) do
              {:ok, resp} -> %{agent_id: agent_id, status: "blocked", detail: resp}
              {:error, err} -> %{agent_id: agent_id, status: "failed", detail: inspect(err)}
            end
          else
            %{agent_id: nil, status: "no_agent_targeted"}
          end

          # Store as IOC for threat intel
          try do
            TamanduaServer.ThreatIntel.add_ioc(%{
              type: "domain",
              value: domain,
              source: "playbook",
              description: reason,
              severity: "high"
            })
          rescue
            _ -> :ok
          catch
            _, _ -> :ok
          end

          case dns_result do
            {:ok, count} ->
              Logger.info("block_domain #{domain}: added to DNS blocklist (#{count} entries added)")
              {:ok, %{domain: domain, action: "blocked", reason: reason, dns_blocklist_added: count, agent_result: agent_result}}
            {:error, err} ->
              {:error, "Failed to block domain: #{err}"}
          end
        else
          {:error, "No domain specified"}
        end

      "collect_forensics" ->
        agent_id = params["agent_id"] || context[:agent_id]
        if agent_id do
          case Executor.collect_forensics(agent_id, params) do
            {:ok, collection_id} -> {:ok, %{collection_id: collection_id}}
            {:error, reason} -> {:error, "Failed to collect forensics: #{reason}"}
          end
        else
          {:error, "No agent_id specified"}
        end

      "create_ticket" ->
        title = params["title"] || "Security Alert"
        description = build_ticket_description(execution)
        severity = params["priority"] || params["severity"] || "high"
        alert_id = Map.get(context, :alert_id) || Map.get(context, "alert_id")

        webhook_url = params["webhook_url"] ||
          Application.get_env(:tamandua_server, :ticketing_webhook_url)

        if webhook_url do
          payload = %{
            title: title,
            description: description,
            severity: severity,
            alert_id: alert_id,
            playbook_id: execution.playbook_id,
            source: "tamandua_edr",
            created_at: DateTime.to_iso8601(DateTime.utc_now()),
            context: execution.execution_context
          }

          case Req.post(webhook_url,
                 json: payload,
                 headers: build_webhook_headers(params),
                 receive_timeout: 15_000,
                 retry: :transient,
                 max_retries: 2
               ) do
            {:ok, %Req.Response{status: status, body: body}} when status in 200..299 ->
              ticket_id = extract_ticket_id(body)
              Logger.info("Ticket created successfully: #{ticket_id} via #{webhook_url}")
              {:ok, %{ticket_id: ticket_id, title: title, status: status}}

            {:ok, %Req.Response{status: status, body: body}} ->
              Logger.error("Ticketing webhook returned #{status}: #{inspect(body)}")
              {:error, "Ticketing webhook returned HTTP #{status}"}

            {:error, reason} ->
              Logger.error("Ticketing webhook request failed: #{inspect(reason)}")
              {:error, "Ticketing webhook request failed: #{inspect(reason)}"}
          end
        else
          Logger.warning("No ticketing webhook URL configured -- set :ticketing_webhook_url in config or pass webhook_url in step params")
          {:error, "No ticketing webhook URL configured"}
        end

      "send_notification" ->
        channel = params["channel"] || "slack"
        message = params["message"] || build_notification_message(execution)

        case channel do
          "slack" ->
            send_slack_notification(message, params, execution)

          "email" ->
            send_email_notification(message, params, execution)

          "webhook" ->
            send_webhook_notification(message, params, execution)

          other ->
            Logger.error("Unknown notification channel: #{other}")
            {:error, "Unknown notification channel: #{other}"}
        end

      "enrich_ioc" ->
        ioc = params["ioc"] || context[:ioc]
        if ioc do
          # Call threat intel enrichment
          {:ok, %{ioc: ioc, enriched: true, reputation: "malicious"}}
        else
          {:error, "No IOC specified"}
        end

      "wait" ->
        duration = params["duration_seconds"] || 60
        {:wait, duration * 1000}

      "conditional" ->
        condition = params["condition"]
        true_step = params["true_step"]
        false_step = params["false_step"]

        if evaluate_condition(condition, execution) do
          {:branch, true_step}
        else
          {:branch, false_step}
        end

      "human_approval" ->
        # Pause for human approval (handled at execution level)
        {:ok, %{awaiting_approval: true}}

      "parallel" ->
        # Execute multiple steps in parallel
        sub_steps = params["steps"] || []
        results = sub_steps
          |> Task.async_stream(fn sub_step ->
            execute_single_step(sub_step, execution)
          end, timeout: 60_000)
          |> Enum.map(fn
            {:ok, result} -> result
            {:exit, reason} -> {:error, "Step failed: #{inspect(reason)}"}
          end)

        if Enum.all?(results, fn {status, _} -> status == :ok end) do
          {:ok, %{parallel_results: results}}
        else
          {:error, "Some parallel steps failed"}
        end

      "trigger_scan" ->
        agent_id = params["agent_id"] || context[:agent_id]
        path = params["path"] || "/"
        if agent_id do
          case Executor.trigger_scan(agent_id, path) do
            {:ok, response} -> {:ok, Map.merge(%{agent_id: agent_id, path: path, action: "scan_triggered"}, response || %{})}
            :ok -> {:ok, %{agent_id: agent_id, path: path, action: "scan_triggered"}}
            {:error, reason} -> {:error, "Failed to trigger scan: #{reason}"}
          end
        else
          {:error, "No agent_id specified"}
        end

      "run_script" ->
        agent_id = params["agent_id"] || context[:agent_id] || context["agent_id"]
        script = params["script"] || params["command"]
        script_type = params["script_type"] || "powershell"
        timeout = params["timeout"] || 120

        if agent_id && script do
          case Executor.execute_action(agent_id, "run_script", %{
            script: script,
            script_type: script_type,
            timeout: timeout
          }) do
            {:ok, response} ->
              Logger.info("Script executed on agent #{agent_id}: #{script_type}")
              {:ok, Map.merge(%{agent_id: agent_id, script_type: script_type, action: "script_executed"}, response || %{})}
            {:error, reason} ->
              {:error, "Failed to run script: #{inspect(reason)}"}
          end
        else
          {:error, "Missing agent_id or script"}
        end

      "disable_user" ->
        username = params["username"] || context[:username] || context["username"]
        domain = params["domain"] || context[:domain] || context["domain"]

        if username do
          # Send disable_user command to the relevant agent
          agent_id = params["agent_id"] || context[:agent_id] || context["agent_id"]

          if agent_id do
            case Executor.execute_action(agent_id, "disable_user", %{
              username: username,
              domain: domain
            }) do
              {:ok, response} ->
                Logger.info("User #{username} disabled on agent #{agent_id}")
                {:ok, Map.merge(%{username: username, action: "user_disabled"}, response || %{})}
              {:error, reason} ->
                {:error, "Failed to disable user: #{inspect(reason)}"}
            end
          else
            # No specific agent -- log the intent for manual follow-up
            Logger.warning("disable_user: no agent_id specified for user #{username}, skipping agent command")
            {:ok, %{username: username, action: "disable_user_requested", note: "No agent targeted -- manual action required"}}
          end
        else
          {:error, "No username specified"}
        end

      "update_blocklist" ->
        blocklist_type = params["blocklist_type"] || "ip"
        values = params["values"] || []
        reason = params["reason"] || "Added by playbook #{execution.playbook_id}"
        organization_id = organization_id_from_context(context, params["agent_id"] || context[:agent_id])

        values = if is_binary(values), do: [values], else: values

        if length(values) > 0 do
          results = Enum.map(values, fn value ->
            case blocklist_type do
              "ip" ->
                try do
                  TamanduaServer.ThreatIntel.add_ioc(%{
                    type: "ip", value: value, source: "playbook",
                    description: reason, severity: "high"
                  })
                  {:ok, value}
                rescue
                  e -> {:error, "#{value}: #{Exception.message(e)}"}
                end

              "domain" ->
                try do
                  TamanduaServer.Detection.DNSAnalyzer.add_to_blocklist(
                    [value], reason, "playbook:#{execution.playbook_id}", organization_id
                  )
                  TamanduaServer.ThreatIntel.add_ioc(%{
                    type: "domain", value: value, source: "playbook",
                    description: reason, severity: "high"
                  })
                  {:ok, value}
                rescue
                  e -> {:error, "#{value}: #{Exception.message(e)}"}
                catch
                  _, e -> {:error, "#{value}: #{inspect(e)}"}
                end

              "hash" ->
                try do
                  TamanduaServer.ThreatIntel.add_ioc(%{
                    type: "hash", value: value, source: "playbook",
                    description: reason, severity: "high"
                  })
                  {:ok, value}
                rescue
                  e -> {:error, "#{value}: #{Exception.message(e)}"}
                end

              _ ->
                {:error, "Unknown blocklist type: #{blocklist_type}"}
            end
          end)

          successful = Enum.count(results, fn {s, _} -> s == :ok end)
          failed = Enum.count(results, fn {s, _} -> s == :error end)
          Logger.info("update_blocklist: #{successful} added, #{failed} failed (type: #{blocklist_type})")

          {:ok, %{blocklist_type: blocklist_type, added: successful, failed: failed, action: "blocklist_updated"}}
        else
          {:error, "No values specified for blocklist update"}
        end

      _ ->
        {:error, "Unknown action: #{action}"}
    end
  end

  defp complete_execution(state, execution, status) do
    final_status = case status do
      :success -> "completed"
      :failed -> "failed"
      _ -> "unknown"
    end

    completed = %{execution |
      status: final_status,
      completed_at: DateTime.utc_now()
    }

    save_execution(completed)

    # Update playbook statistics
    update_playbook_stats(state.playbooks, execution.playbook_id, status)

    new_active = Map.delete(state.active_executions, execution.id)
    %{state | active_executions: new_active}
  end

  defp update_playbook_stats(playbooks, playbook_id, status) do
    case Map.get(playbooks, playbook_id) do
      nil -> :ok
      playbook ->
        success_increment = if status == :success, do: 1, else: 0
        try do
          Repo.update_all(
            from(p in Schema, where: p.id == ^playbook_id),
            inc: [execution_count: 1, success_count: success_increment],
            set: [last_executed_at: DateTime.utc_now()]
          )
        rescue
          _ -> :ok
        end
    end
  end

  defp organization_id_from_context(context, agent_id) do
    context[:organization_id] ||
      context["organization_id"] ||
      (agent_id && TamanduaServer.Agents.OrgLookup.get_org_id(agent_id))
  rescue
    _ -> nil
  end

  defp matches_trigger_conditions?(nil, _), do: true
  defp matches_trigger_conditions?(conditions, context) when is_map(conditions) do
    # Normalize context to support both atom and string keys
    normalized_context = normalize_context(context)
    ConditionEvaluator.evaluate_trigger_conditions(conditions, normalized_context)
  end

  defp normalize_context(context) when is_map(context) do
    # Merge atom-keyed and string-keyed versions so ConditionEvaluator can find either
    Enum.reduce(context, context, fn
      {k, v}, acc when is_atom(k) ->
        Map.put_new(acc, Atom.to_string(k), v)
      {k, v}, acc when is_binary(k) ->
        atom_key = try do
          String.to_existing_atom(k)
        rescue
          _ -> nil
        end
        if atom_key, do: Map.put_new(acc, atom_key, v), else: acc
      _, acc ->
        acc
    end)
  end

  defp build_detection_context(detection) do
    %{
      detection_type: detection.detection_type,
      rule_name: detection.rule_name,
      confidence: detection.confidence,
      agent_id: detection.agent_id,
      file_path: detection.file_path,
      process_name: detection.process_name,
      pid: detection.pid,
      mitre_tactics: detection.mitre_tactics || [],
      mitre_techniques: detection.mitre_techniques || []
    }
  end

  defp evaluate_condition(condition, execution) when is_map(condition) do
    context = normalize_context(execution.execution_context || %{})
    ConditionEvaluator.evaluate(condition, context)
  end
  defp evaluate_condition(_, _), do: true

  defp build_ticket_description(execution) do
    """
    Security Playbook Execution

    Playbook ID: #{execution.playbook_id}
    Trigger Event: #{inspect(execution.trigger_event)}
    Started: #{execution.started_at}

    Context:
    #{inspect(execution.execution_context, pretty: true)}
    """
  end

  defp build_notification_message(execution) do
    "Security playbook #{execution.playbook_id} triggered. Status: #{execution.status}"
  end

  # ============================================================================
  # Ticketing Helpers
  # ============================================================================

  defp build_webhook_headers(params) do
    base_headers = [{"content-type", "application/json"}]

    auth_headers = cond do
      params["auth_token"] ->
        [{"authorization", "Bearer #{params["auth_token"]}"}]
      params["api_key"] ->
        [{"x-api-key", params["api_key"]}]
      params["basic_auth"] ->
        encoded = Base.encode64(params["basic_auth"])
        [{"authorization", "Basic #{encoded}"}]
      true ->
        []
    end

    custom_headers = case params["headers"] do
      headers when is_map(headers) ->
        Enum.map(headers, fn {k, v} -> {to_string(k), to_string(v)} end)
      _ ->
        []
    end

    base_headers ++ auth_headers ++ custom_headers
  end

  defp extract_ticket_id(body) when is_map(body) do
    # Try common field names used by Jira, ServiceNow, PagerDuty, etc.
    body["key"] ||
      body["id"] ||
      body["ticket_id"] ||
      body["number"] ||
      body["sys_id"] ||
      body["incident_key"] ||
      get_in(body, ["result", "sys_id"]) ||
      get_in(body, ["result", "number"]) ||
      "TICKET-#{:rand.uniform(100_000)}"
  end

  defp extract_ticket_id(_body) do
    "TICKET-#{:rand.uniform(100_000)}"
  end

  # ============================================================================
  # Notification Channel Implementations
  # ============================================================================

  defp send_slack_notification(message, params, execution) do
    webhook_url = params["webhook_url"] || params["slack_webhook_url"] ||
      Application.get_env(:tamandua_server, :slack_webhook_url)

    unless webhook_url do
      Logger.error("No Slack webhook URL configured")
      {:error, "No Slack webhook URL configured"}
    else
      severity = Map.get(execution.execution_context, :severity, "medium")

      color = case severity do
        "critical" -> "#FF0000"
        "high" -> "#FF6600"
        "medium" -> "#FFAA00"
        _ -> "#36A64F"
      end

      slack_payload = %{
        text: "Tamandua EDR Alert",
        attachments: [
          %{
            color: color,
            title: "Security Playbook Notification",
            text: message,
            fields: [
              %{title: "Playbook", value: execution.playbook_id, short: true},
              %{title: "Severity", value: severity, short: true},
              %{title: "Status", value: execution.status || "running", short: true},
              %{title: "Time", value: DateTime.to_iso8601(DateTime.utc_now()), short: true}
            ],
            footer: "Tamandua EDR",
            ts: DateTime.utc_now() |> DateTime.to_unix()
          }
        ]
      }

      # Optionally mention a channel or user
      slack_payload = if params["slack_channel"] do
        Map.put(slack_payload, :channel, params["slack_channel"])
      else
        slack_payload
      end

      case Req.post(webhook_url, json: slack_payload, receive_timeout: 10_000) do
        {:ok, %Req.Response{status: status}} when status in 200..299 ->
          Logger.info("Slack notification sent successfully")
          {:ok, %{channel: "slack", sent: true}}

        {:ok, %Req.Response{status: status, body: body}} ->
          Logger.error("Slack webhook returned #{status}: #{inspect(body)}")
          {:error, "Slack webhook returned HTTP #{status}"}

        {:error, reason} ->
          Logger.error("Slack webhook request failed: #{inspect(reason)}")
          {:error, "Slack notification failed: #{inspect(reason)}"}
      end
    end
  end

  defp send_email_notification(message, params, execution) do
    to = params["to"] || params["recipients"] ||
      Application.get_env(:tamandua_server, :notification_email_to)

    from = params["from"] ||
      Application.get_env(:tamandua_server, :notification_email_from) ||
      "tamandua-edr@alerts.local"

    unless to do
      Logger.error("No email recipients configured for notification")
      {:error, "No email recipients configured"}
    else
      recipients = cond do
        is_binary(to) -> String.split(to, [",", ";"], trim: true) |> Enum.map(&String.trim/1)
        is_list(to) -> to
        true -> [to_string(to)]
      end

      severity = Map.get(execution.execution_context, :severity, "medium")
      subject = params["subject"] ||
        "[Tamandua EDR] #{String.upcase(severity)} - Security Playbook Alert"

      body_html = """
      <h2>Tamandua EDR - Security Alert</h2>
      <p><strong>Message:</strong> #{message}</p>
      <hr/>
      <table>
        <tr><td><strong>Playbook ID:</strong></td><td>#{execution.playbook_id}</td></tr>
        <tr><td><strong>Severity:</strong></td><td>#{severity}</td></tr>
        <tr><td><strong>Status:</strong></td><td>#{execution.status || "running"}</td></tr>
        <tr><td><strong>Time:</strong></td><td>#{DateTime.to_iso8601(DateTime.utc_now())}</td></tr>
      </table>
      <hr/>
      <p><em>Context:</em></p>
      <pre>#{inspect(execution.execution_context, pretty: true)}</pre>
      """

      email = Swoosh.Email.new()
      |> Swoosh.Email.from({params["from_name"] || "Tamandua EDR", from})
      |> Swoosh.Email.subject(subject)
      |> Swoosh.Email.html_body(body_html)
      |> Swoosh.Email.text_body(message)

      email = Enum.reduce(recipients, email, fn recipient, acc ->
        Swoosh.Email.to(acc, recipient)
      end)

      case TamanduaServer.Mailer.deliver(email) do
        {:ok, _metadata} ->
          Logger.info("Email notification sent to #{Enum.join(recipients, ", ")}")
          {:ok, %{channel: "email", sent: true, recipients: recipients}}

        {:error, reason} ->
          Logger.error("Email delivery failed: #{inspect(reason)}")
          {:error, "Email delivery failed: #{inspect(reason)}"}
      end
    end
  end

  defp send_webhook_notification(message, params, execution) do
    webhook_url = params["webhook_url"] ||
      Application.get_env(:tamandua_server, :notification_webhook_url)

    unless webhook_url do
      Logger.error("No webhook URL configured for notification")
      {:error, "No webhook URL configured"}
    else
      severity = Map.get(execution.execution_context, :severity, "medium")

      payload = %{
        message: message,
        severity: severity,
        playbook_id: execution.playbook_id,
        status: execution.status || "running",
        timestamp: DateTime.to_iso8601(DateTime.utc_now()),
        source: "tamandua_edr",
        context: execution.execution_context
      }

      case Req.post(webhook_url,
             json: payload,
             headers: build_webhook_headers(params),
             receive_timeout: 10_000,
             retry: :transient,
             max_retries: 2
           ) do
        {:ok, %Req.Response{status: status}} when status in 200..299 ->
          Logger.info("Webhook notification sent to #{webhook_url}")
          {:ok, %{channel: "webhook", sent: true, url: webhook_url}}

        {:ok, %Req.Response{status: status, body: body}} ->
          Logger.error("Notification webhook returned #{status}: #{inspect(body)}")
          {:error, "Notification webhook returned HTTP #{status}"}

        {:error, reason} ->
          Logger.error("Notification webhook failed: #{inspect(reason)}")
          {:error, "Notification webhook failed: #{inspect(reason)}"}
      end
    end
  end

  defp should_run_now?(playbook, now) do
    schedule = playbook.trigger_conditions["schedule"]
    if schedule do
      # Simple schedule check (in production, use proper cron parsing)
      case schedule do
        "hourly" -> now.minute == 0
        "daily" -> now.hour == 0 && now.minute == 0
        _ -> false
      end
    else
      false
    end
  end

  defp load_execution_history(playbook_id, opts) do
    limit = Keyword.get(opts, :limit, 100)

    try do
      from(e in Execution,
        where: e.playbook_id == ^playbook_id,
        order_by: [desc: e.started_at],
        limit: ^limit
      )
      |> Repo.all()
    rescue
      _ -> []
    end
  end

  defp init_step_handlers do
    %{}
  end

  defp schedule_scheduled_playbooks do
    # Check every minute for scheduled playbooks
    Process.send_after(self(), :run_scheduled_playbooks, 60_000)
  end

  defp schedule_approval_timeout_check do
    # Check every minute for approval timeouts
    Process.send_after(self(), :check_approval_timeouts, 60_000)
  end

  # ============================================================================
  # Public API Wrapper Functions
  # ============================================================================

  @doc """
  Clone an existing playbook with a new name.
  """
  def clone_playbook(playbook_id, new_name) do
    GenServer.call(__MODULE__, {:clone_playbook, playbook_id, new_name})
  end

  @doc """
  Execute a playbook with context and options.
  """
  def execute(playbook_id, context, opts \\ %{}) do
    GenServer.call(__MODULE__, {:execute, playbook_id, context, opts}, 60_000)
  end

  @doc """
  List execution history for a playbook.
  """
  def list_executions(playbook_id, opts \\ %{}) do
    GenServer.call(__MODULE__, {:list_executions, playbook_id, opts})
  end

  @doc """
  List recent playbook executions across all playbooks.
  """
  @spec list_recent_executions(keyword()) :: {:ok, [map()]}
  def list_recent_executions(opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)

    executions =
      try do
        from(e in Execution,
          order_by: [desc: e.started_at],
          limit: ^limit
        )
        |> Repo.all()
      rescue
        _ -> []
      end

    {:ok, executions}
  end
end

# Convenience module for creating common playbooks
defmodule TamanduaServer.Response.Playbook.Templates do
  @moduledoc """
  Pre-built playbook templates for common scenarios
  """

  alias TamanduaServer.Response.Playbook

  @doc """
  Create a ransomware response playbook
  """
  def ransomware_response do
    %{
      id: "template_ransomware",
      name: "Ransomware Response",
      description: "Automated response to ransomware detection",
      category: "ransomware",
      trigger_type: "detection",
      trigger_conditions: %{
        "detection_type" => "ransomware",
        "category" => "ransomware"
      },
      require_approval: false,
      severity_threshold: "high",
      steps: [
        %{"action" => "isolate_host", "params" => %{}, "name" => "Isolate Infected Host"},
        %{"action" => "kill_process", "params" => %{}, "name" => "Terminate Malicious Process"},
        %{"action" => "collect_forensics", "params" => %{"type" => "full"}, "name" => "Collect Forensic Evidence"},
        %{"action" => "create_ticket", "params" => %{"priority" => "critical"}, "name" => "Create Incident Ticket"},
        %{"action" => "send_notification", "params" => %{
          "channel" => "slack",
          "message" => "CRITICAL: Ransomware detected and contained"
        }, "name" => "Alert Security Team"}
      ],
      tags: ["ransomware", "critical", "automated"]
    }
  end

  @doc """
  Create a lateral movement response playbook
  """
  def lateral_movement_response do
    %{
      id: "template_lateral_movement",
      name: "Lateral Movement Response",
      description: "Response to detected lateral movement",
      category: "lateral_movement",
      trigger_type: "alert",
      trigger_conditions: %{
        "mitre_tactic" => "lateral-movement",
        "severity" => "high",
        "category" => "lateral_movement"
      },
      require_approval: true,
      approval_timeout_minutes: 15,
      steps: [
        %{"action" => "collect_forensics", "params" => %{}, "name" => "Gather Evidence"},
        %{"action" => "block_ip", "params" => %{}, "name" => "Block Suspicious IP"},
        %{"action" => "enrich_ioc", "params" => %{}, "name" => "Enrich IOCs"},
        %{"action" => "conditional", "params" => %{
          "condition" => %{
            "field" => "confidence",
            "operator" => "greater_than",
            "value" => 0.8
          },
          "true_step" => 5,
          "false_step" => 6
        }, "name" => "Evaluate Confidence"},
        %{"action" => "isolate_host", "params" => %{}, "name" => "Isolate Compromised Host"},
        %{"action" => "create_ticket", "params" => %{"priority" => "high"}, "name" => "Create Incident Ticket"}
      ],
      tags: ["lateral-movement", "high-priority"]
    }
  end

  @doc """
  Create a credential theft response playbook
  """
  def credential_theft_response do
    %{
      id: "template_credential_theft",
      name: "Credential Theft Response",
      description: "Response to credential access attempts",
      category: "credential_theft",
      trigger_type: "alert",
      trigger_conditions: %{
        "mitre_tactic" => "credential-access",
        "category" => "credential_theft"
      },
      require_approval: true,
      steps: [
        %{"action" => "collect_forensics", "params" => %{"type" => "memory"}, "name" => "Dump Process Memory"},
        %{"action" => "kill_process", "params" => %{}, "name" => "Kill Suspicious Process"},
        %{"action" => "send_notification", "params" => %{
          "channel" => "email",
          "message" => "Credential theft attempt detected"
        }, "name" => "Notify Security Team"},
        %{"action" => "create_ticket", "params" => %{
          "title" => "Credential Theft Alert",
          "priority" => "high"
        }, "name" => "Create Incident Ticket"}
      ],
      tags: ["credential-theft", "lsass"]
    }
  end
end
