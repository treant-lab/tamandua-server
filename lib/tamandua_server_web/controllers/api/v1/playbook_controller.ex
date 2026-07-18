defmodule TamanduaServerWeb.API.V1.PlaybookController do
  @moduledoc """
  Automated Playbook API controller.

  Provides CRUD operations and execution control for automated
  response playbooks. Playbooks define sequences of actions to
  take in response to specific security events.
  """
  use TamanduaServerWeb, :controller

  plug TamanduaServerWeb.Plugs.Authorize, :playbooks_read
       when action in [:index, :show, :templates, :recent_executions, :execution_history]

  plug TamanduaServerWeb.Plugs.Authorize, :playbooks_create
       when action in [:create, :clone]

  plug TamanduaServerWeb.Plugs.Authorize, :playbooks_update when action in [:update]
  plug TamanduaServerWeb.Plugs.Authorize, :playbooks_delete when action in [:delete]
  plug TamanduaServerWeb.Plugs.Authorize, :playbooks_execute when action in [:execute]

  require Logger

  alias TamanduaServer.AuditLog
  alias TamanduaServer.Response.Playbook
  alias TamanduaServer.Response.Playbook.Templates

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  List all playbooks.

  Returns a paginated list of playbooks with summary information.

  ## Parameters
    - page: Page number
    - per_page: Items per page
    - status: Filter by status (active, disabled, draft)
    - trigger_type: Filter by trigger type
  """
  def index(conn, params) do
    scope = tenant_scope(conn)
    filters = %{}
    filters = if params["status"], do: Map.put(filters, :enabled, params["status"] == "active"), else: filters
    filters = if params["trigger_type"], do: Map.put(filters, :trigger_type, params["trigger_type"]), else: filters

    case safe_playbook_call(fn -> Playbook.list_playbooks(filters, scope) end, "Playbook.list_playbooks") do
      {:ok, playbooks} ->
        json(conn, %{
          data: Enum.map(playbooks, &serialize_playbook/1),
          meta: %{total: length(playbooks)}
        })

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  @doc """
  Get a specific playbook with full details.

  Returns the complete playbook definition including all steps,
  conditions, and configuration.
  """
  def show(conn, %{"id" => id}) do
    case Playbook.get_playbook(id, tenant_scope(conn)) do
      {:ok, playbook} ->
        json(conn, %{
          data: serialize_playbook_detail(playbook)
        })

      {:error, :not_found} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  @doc """
  Create a new playbook.

  ## Parameters
    - name: Playbook name
    - description: Description of the playbook
    - trigger: Trigger configuration (type, conditions)
    - steps: List of action steps
    - enabled: Whether the playbook is active
  """
  def create(conn, %{"playbook" => playbook_params}) do
    case Playbook.create_playbook(playbook_params, tenant_scope(conn)) do
      {:ok, playbook} ->
        user = conn.assigns[:current_user]
        AuditLog.log_config_change(user, "playbook_created", %{
          playbook_id: playbook.id,
          playbook_name: playbook.name
        }, ip_address: get_client_ip(conn), user_agent: get_user_agent(conn))

        conn
        |> put_status(:created)
        |> json(%{
          data: serialize_playbook_detail(playbook),
          message: "Playbook created successfully"
        })

      {:error, %Ecto.Changeset{} = changeset} ->
        {:error, changeset}

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  def create(conn, params) do
    create(conn, %{"playbook" => params})
  end

  @doc """
  Update an existing playbook.
  """
  def update(conn, %{"id" => id} = params) do
    scope = tenant_scope(conn)
    playbook_params = Map.get(params, "playbook", params)
      |> Map.drop(["id", :id])

    case Playbook.update_playbook(id, playbook_params, scope) do
      {:ok, updated} ->
        user = conn.assigns[:current_user]
        AuditLog.log_config_change(user, "playbook_updated", %{
          playbook_id: id,
          playbook_name: updated.name,
          changes: playbook_params
        }, ip_address: get_client_ip(conn), user_agent: get_user_agent(conn))

        json(conn, %{
          data: serialize_playbook_detail(updated),
          message: "Playbook updated successfully"
        })

      {:error, :not_found} ->
        {:error, :not_found}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:error, changeset}

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  @doc """
  Delete a playbook.
  """
  def delete(conn, %{"id" => id}) do
    case Playbook.delete_playbook(id, tenant_scope(conn)) do
      {:ok, _} ->
        user = conn.assigns[:current_user]
        AuditLog.log_config_change(user, "playbook_deleted", %{
          playbook_id: id
        }, ip_address: get_client_ip(conn), user_agent: get_user_agent(conn))

        send_resp(conn, :no_content, "")

      {:error, :not_found} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  @doc """
  Manually execute a playbook.

  Triggers a playbook execution with the provided context,
  bypassing normal trigger conditions.

  ## Parameters
    - context: Execution context (agent_id, alert_id, etc.)
    - dry_run: If true, simulate execution without taking actions
  """
  def execute(conn, %{"id" => id} = params) do
    scope = tenant_scope(conn)
    user = conn.assigns[:current_user]

    context = params
      |> Map.get("context", %{})
      |> atomize_keys()
      |> Map.put(:organization_id, elem(scope, 1))
      |> Map.put(:current_user_id, user && user.id)

    dry_run = Map.get(params, "dry_run", false)

    opts =
      if dry_run,
        do: %{skip_approval: true, dry_run: true, scope: scope},
        else: %{scope: scope}

    case Playbook.execute(id, context, opts) do
      {:ok, execution} ->
        status = if dry_run, do: :ok, else: :accepted

        # Get playbook for response and logging
        {playbook_name, playbook} = case Playbook.get_playbook(id, scope) do
          {:ok, pb} -> {pb.name, pb}
          _ -> {"Unknown", nil}
        end

        # Log playbook execution
        if playbook do
          AuditLog.log_playbook_execution(user, playbook, %{
            execution_id: execution.id,
            status: execution.status,
            dry_run: dry_run
          },
          trigger: "manual",
          ip_address: get_client_ip(conn),
          user_agent: get_user_agent(conn))
        end

        conn
        |> put_status(status)
        |> json(%{
          data: serialize_execution_detail(execution, playbook_name, dry_run),
          message: if(dry_run, do: "Dry run completed", else: "Playbook execution started")
        })

      {:error, :not_found} ->
        {:error, :not_found}

      {:error, :playbook_disabled} ->
        conn
        |> put_status(:conflict)
        |> json(%{error: "Playbook is disabled"})

      {:error, :severity_threshold_not_met} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Severity threshold not met for this playbook"})

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  @doc """
  Clone an existing playbook.

  Creates a copy of a playbook with a new name, useful for
  creating variants of existing playbooks.
  """
  def clone(conn, %{"id" => id} = params) do
    scope = tenant_scope(conn)
    new_name = Map.get(params, "name", "Copy of playbook")

    case Playbook.clone_playbook(id, new_name, scope) do
      {:ok, cloned} ->
        user = conn.assigns[:current_user]
        AuditLog.log_config_change(user, "playbook_cloned", %{
          source_playbook_id: id,
          new_playbook_id: cloned.id,
          new_playbook_name: cloned.name
        }, ip_address: get_client_ip(conn), user_agent: get_user_agent(conn))

        conn
        |> put_status(:created)
        |> json(%{
          data: serialize_playbook_detail(cloned),
          message: "Playbook cloned successfully"
        })

      {:error, :not_found} ->
        {:error, :not_found}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:error, changeset}

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  @doc """
  Get execution history for a playbook.

  Returns a paginated list of past executions with their
  status and results.
  """
  def execution_history(conn, %{"id" => id} = params) do
    scope = tenant_scope(conn)
    limit = params |> Map.get("per_page", "20") |> bounded_limit(20, 200)

    case safe_playbook_call(
           fn -> Playbook.list_executions(id, %{limit: limit, scope: scope}) end,
           "Playbook.list_executions"
         ) do
      {:ok, executions} ->
        json(conn, %{
          data: Enum.map(executions, &serialize_execution/1),
          meta: %{total: length(executions)}
        })

      {:error, :not_found} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  @doc """
  Get recent executions across all playbooks.
  """
  def recent_executions(conn, params) do
    scope = tenant_scope(conn)
    limit = params |> Map.get("limit", "50") |> bounded_limit(50, 200)

    case safe_playbook_call(
           fn -> Playbook.list_recent_executions(limit: limit, scope: scope) end,
           "Playbook.list_recent_executions"
         ) do
      {:ok, executions} ->
        json(conn, %{
          data: Enum.map(executions, &serialize_execution/1)
        })

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  @doc """
  Get available playbook templates.

  Returns a list of pre-built playbook templates that can be used
  to quickly create new playbooks.
  """
  def templates(conn, _params) do
    templates = [
      Templates.ransomware_response(),
      Templates.lateral_movement_response(),
      Templates.credential_theft_response(),
      # Additional templates
      %{
        id: "template_malware",
        name: "Malware Response",
        description: "Standard response for malware detection",
        category: "malware",
        trigger_type: "detection",
        trigger_conditions: %{
          "detection_type" => "malware"
        },
        require_approval: false,
        steps: [
          %{"action" => "kill_process", "params" => %{}},
          %{"action" => "quarantine_file", "params" => %{}},
          %{"action" => "isolate_host", "params" => %{}},
          %{"action" => "send_notification", "params" => %{"channel" => "slack"}}
        ],
        tags: ["malware", "automated"]
      },
      %{
        id: "template_phishing",
        name: "Phishing Response",
        description: "Response for phishing email detection",
        category: "phishing",
        trigger_type: "alert",
        trigger_conditions: %{
          "detection_type" => "phishing"
        },
        require_approval: true,
        steps: [
          %{"action" => "kill_process", "params" => %{"process_name" => "browser"}},
          %{"action" => "block_ip", "params" => %{}},
          %{"action" => "block_domain", "params" => %{}},
          %{"action" => "send_notification", "params" => %{"channel" => "email"}}
        ],
        tags: ["phishing", "email-security"]
      },
      %{
        id: "template_data_exfil",
        name: "Data Exfiltration Response",
        description: "Response for suspected data exfiltration",
        category: "data_exfiltration",
        trigger_type: "alert",
        trigger_conditions: %{
          "mitre_tactic" => "exfiltration"
        },
        require_approval: true,
        approval_timeout_minutes: 10,
        steps: [
          %{"action" => "isolate_host", "params" => %{}},
          %{"action" => "collect_forensics", "params" => %{"type" => "network"}},
          %{"action" => "block_ip", "params" => %{}},
          %{"action" => "create_ticket", "params" => %{"priority" => "critical"}}
        ],
        tags: ["exfiltration", "critical"]
      }
    ]

    json(conn, %{data: templates})
  end

  # Private functions

  defp serialize_playbook(playbook) do
    status = cond do
      not playbook.enabled -> "disabled"
      is_nil(playbook.execution_count) or playbook.execution_count == 0 -> "draft"
      true -> "active"
    end

    success_rate = if (playbook.execution_count || 0) > 0 do
      Float.round((playbook.success_count || 0) / playbook.execution_count * 100, 1)
    else
      0.0
    end

    %{
      id: playbook.id,
      name: playbook.name,
      description: playbook.description,
      category: (playbook.trigger_conditions || %{})["category"] || "custom",
      status: status,
      enabled: playbook.enabled,
      trigger_type: playbook.trigger_type,
      triggerConditions: Map.keys(playbook.trigger_conditions || %{}),
      trigger: %{
        type: playbook.trigger_type,
        conditions: trigger_conditions_to_list(playbook.trigger_conditions)
      },
      steps: normalize_steps(playbook.steps || []),
      executionCount: playbook.execution_count || 0,
      successRate: success_rate,
      lastExecuted: format_datetime(playbook.last_executed_at),
      createdAt: format_datetime(playbook.inserted_at),
      updatedAt: format_datetime(playbook.updated_at),
      createdBy: playbook.created_by
    }
  end

  defp serialize_playbook_detail(playbook) do
    # Use same serialization as index for consistency with frontend
    serialize_playbook(playbook)
  end

  defp serialize_execution(execution) do
    steps_completed = execution.steps_completed || []
    total_steps = length(steps_completed)
    steps_failed = Enum.count(steps_completed, fn s -> s["status"] == "failed" end)

    %{
      id: execution.id,
      playbookId: execution.playbook_id,
      triggeredBy: execution.trigger_event["trigger_source"] || "manual",
      status: execution.status,
      startedAt: format_datetime(execution.started_at),
      completedAt: format_datetime(execution.completed_at),
      stepsCompleted: length(steps_completed),
      totalSteps: total_steps,
      stepsFailed: steps_failed,
      error: execution.error_message,
      log: Enum.map(steps_completed, fn step ->
        "[#{step["completed_at"]}] Step #{step["index"]}: #{step["action"]} - #{step["status"]}"
      end),
      context: execution.execution_context
    }
  end

  defp serialize_execution_detail(execution, playbook_name, dry_run) do
    steps_completed = execution.steps_completed || []

    %{
      id: execution.id,
      playbookId: execution.playbook_id,
      playbookName: playbook_name,
      status: if(dry_run, do: "dry_run", else: execution.status),
      dryRun: dry_run,
      startedAt: format_datetime(execution.started_at),
      stepsCompleted: length(steps_completed),
      totalSteps: length(steps_completed),
      log: Enum.map(steps_completed, fn step ->
        "[#{step["completed_at"]}] Step #{step["index"]}: #{step["action"]} - #{step["status"]}"
      end)
    }
  end

  defp normalize_steps(steps) do
    Enum.with_index(steps, fn step, idx ->
      step_type = cond do
        step["action"] == "conditional" -> "condition"
        step["action"] == "wait" -> "wait"
        step["action"] == "parallel" -> "loop"
        true -> "action"
      end

      action_type = case step["action"] do
        "isolate_host" -> "isolate"
        "kill_process" -> "kill_process"
        "quarantine_file" -> "quarantine_file"
        "block_ip" -> "block_ip"
        "block_domain" -> "block_ip"
        "send_notification" -> "notify"
        "trigger_scan" -> "scan"
        _ -> "custom"
      end

      %{
        id: step["id"] || "step_#{idx}",
        name: step["name"] || step["action"] || "Step #{idx + 1}",
        stepType: step_type,
        action: step["action"],
        actionType: action_type,
        timeout: step["timeout"] || 30,
        params: step["params"] || %{},
        condition: step["condition"],
        conditionTrueBranch: step["true_step"],
        conditionFalseBranch: step["false_step"],
        waitDuration: (step["params"] || %{})["duration_seconds"]
      }
    end)
  end

  defp safe_playbook_call(fun, label) when is_function(fun, 0) do
    fun.()
  catch
    kind, reason ->
      Logger.warning("#{label} failed: #{kind} #{inspect(reason)}")
      {:ok, []}
  end

  defp trigger_conditions_to_list(nil), do: []
  defp trigger_conditions_to_list(conditions) when is_map(conditions) do
    Enum.map(conditions, fn {field, value} ->
      %{
        id: "cond_#{:erlang.phash2({field, value})}",
        field: field,
        operator: "equals",
        value: value
      }
    end)
  end

  defp atomize_keys(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_binary(k) -> {safe_existing_atom(k) || k, v}
      {k, v} -> {k, v}
    end)
  rescue
    _ -> map
  end
  defp atomize_keys(other), do: other

  defp safe_existing_atom(key) do
    String.to_existing_atom(key)
  rescue
    ArgumentError -> nil
  end

  defp to_integer(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end
  defp to_integer(val, _default) when is_integer(val), do: val
  defp to_integer(_, default), do: default

  defp bounded_limit(val, default, max_limit),
    do: val |> to_integer(default) |> max(1) |> min(max_limit)

  defp tenant_scope(conn) do
    user_organization_id =
      case conn.assigns[:current_user] do
        %{organization_id: organization_id} -> organization_id
        _ -> nil
      end

    organization_id =
      conn.assigns[:current_organization_id] ||
        conn.assigns[:organization_id] ||
        user_organization_id

    {:organization, organization_id}
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  defp get_client_ip(conn) do
    case get_req_header(conn, "x-forwarded-for") do
      [forwarded | _] ->
        forwarded
        |> String.split(",")
        |> List.first()
        |> String.trim()

      [] ->
        conn.remote_ip
        |> :inet.ntoa()
        |> to_string()
    end
  end

  defp get_user_agent(conn) do
    case get_req_header(conn, "user-agent") do
      [ua | _] -> ua
      [] -> nil
    end
  end
end
