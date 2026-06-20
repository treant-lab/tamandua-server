defmodule TamanduaServerWeb.API.V1.WorkflowController do
  @moduledoc """
  Controller for Hyperautomation Workflows API endpoints.

  Provides CRUD operations for automation workflows, execution management,
  and access to available actions and templates.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Automation.Hyperautomation

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  List all workflows with optional filtering.
  """
  def index(conn, params) do
    filters = %{
      status: Map.get(params, "status"),
      trigger_type: Map.get(params, "trigger_type"),
      category: Map.get(params, "category"),
      search: Map.get(params, "search"),
      page: Map.get(params, "page", 1),
      page_size: Map.get(params, "page_size", 20)
    }

    case Hyperautomation.list_workflows(filters) do
      {:ok, workflows} when is_list(workflows) ->
        json(conn, %{
          data: Enum.map(workflows, &serialize_workflow/1),
          meta: %{
            total_count: length(workflows),
            page: parse_int(filters.page, 1),
            page_size: parse_int(filters.page_size, 20),
            total_pages: 1
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: %{message: "Failed to list workflows", details: reason}})
    end
  end

  @doc """
  Get a specific workflow by ID.
  """
  def show(conn, %{"id" => id}) do
    case Hyperautomation.get_workflow(id) do
      {:ok, workflow} ->
        json(conn, %{
          data: %{
            id: workflow.id,
            name: workflow.name,
            description: workflow.description,
            status: workflow.status,
            trigger: workflow.trigger,
            conditions: workflow.conditions,
            actions: workflow.actions,
            execution_stats: workflow.execution_stats,
            created_at: workflow.created_at,
            updated_at: workflow.updated_at
          }
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: %{message: "Workflow not found"}})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: %{message: "Failed to get workflow", details: reason}})
    end
  end

  @doc """
  Create a new workflow.
  """
  def create(conn, params) do
    workflow_params = normalize_workflow_params(params, default_enabled: false)

    case Hyperautomation.create_workflow(workflow_params) do
      {:ok, workflow} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_workflow(workflow)})

      {:error, :invalid_trigger} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: %{message: "Invalid trigger configuration"}})

      {:error, :invalid_actions} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: %{message: "Invalid action configuration"}})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: %{message: "Validation failed", details: format_changeset_errors(changeset)}})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: %{message: "Failed to create workflow", details: reason}})
    end
  end

  @doc """
  Update an existing workflow.
  """
  def update(conn, %{"id" => id} = params) do
    update_params =
      params
      |> Map.drop(["id"])
      |> normalize_workflow_params()

    case Hyperautomation.update_workflow(id, update_params) do
      {:ok, workflow} ->
        json(conn, %{data: serialize_workflow(workflow)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: %{message: "Workflow not found"}})

      {:error, :workflow_running} ->
        conn
        |> put_status(:conflict)
        |> json(%{error: %{message: "Cannot update a running workflow"}})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: %{message: "Validation failed", details: format_changeset_errors(changeset)}})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: %{message: "Failed to update workflow", details: reason}})
    end
  end

  @doc """
  Delete a workflow.
  """
  def delete(conn, %{"id" => id}) do
    case Hyperautomation.delete_workflow(id) do
      {:ok, _} ->
        send_resp(conn, :no_content, "")

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: %{message: "Workflow not found"}})

      {:error, :workflow_running} ->
        conn
        |> put_status(:conflict)
        |> json(%{error: %{message: "Cannot delete a running workflow"}})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: %{message: "Failed to delete workflow", details: reason}})
    end
  end

  @doc """
  Execute a workflow manually.
  """
  def execute(conn, %{"id" => id} = params) do
    context = Map.get(params, "context", %{})
    execution_opts = [
      dry_run: Map.get(params, "dry_run", false),
      async: Map.get(params, "async", true)
    ]

    case Hyperautomation.execute_workflow(id, context, execution_opts) do
      {:ok, execution} ->
        is_async = Keyword.get(execution_opts, :async, true)
        status = if is_async, do: :accepted, else: :ok

        conn
        |> put_status(status)
        |> json(%{
          data: %{
            execution_id: execution.id,
            workflow_id: id,
            status: execution.status,
            started_at: execution.started_at,
            completed_at: execution.completed_at,
            result: execution.result
          }
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: %{message: "Workflow not found"}})

      {:error, :workflow_disabled} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: %{message: "Workflow is disabled"}})

      {:error, :execution_in_progress} ->
        conn
        |> put_status(:conflict)
        |> json(%{error: %{message: "Workflow execution already in progress"}})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: %{message: "Failed to execute workflow", details: reason}})
    end
  end

  @doc """
  List all available actions for workflows.
  """
  def available_actions(conn, params) do
    category_filter = Map.get(params, "category")
    search_filter = Map.get(params, "search")

    # list_actions/0 returns a map of action_name => config
    actions = Hyperautomation.list_actions()

    # Apply optional filters
    filtered_actions = actions
    |> Enum.filter(fn {_name, config} ->
      category_atom = if category_filter do
        try do
          String.to_existing_atom(category_filter)
        rescue
          ArgumentError -> nil
        end
      end
      category_match = is_nil(category_filter) || config.category == category_atom
      search_match = is_nil(search_filter) || String.contains?(config.description, search_filter)
      category_match && search_match
    end)
    |> Enum.map(fn {name, config} ->
      %{
        id: name,
        name: name,
        description: config.description,
        category: config.category,
        required_params: config.required_params,
        optional_params: config.optional_params,
        integrations: config.integrations
      }
    end)

    json(conn, %{data: filtered_actions})
  end

  @doc """
  List workflow templates.
  """
  def templates(conn, params) do
    category_filter = Map.get(params, "category")
    search_filter = Map.get(params, "search")

    case Hyperautomation.list_templates() do
      {:ok, templates} ->
        # Apply optional filters
        filtered_templates = templates
        |> Enum.filter(fn template ->
          category_match = is_nil(category_filter) || template[:category] == category_filter
          search_match = is_nil(search_filter) ||
            String.contains?(template[:name] || "", search_filter) ||
            String.contains?(template[:description] || "", search_filter)
          category_match && search_match
        end)
        |> Enum.map(fn template ->
          %{
            name: template[:name],
            description: template[:description],
            category: template[:category],
            trigger_type: template[:trigger_type],
            steps: template[:steps],
            tags: template[:tags]
          }
        end)

        json(conn, %{data: filtered_templates})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: %{message: "Failed to list templates", details: reason}})
    end
  end

  # Private functions

  defp normalize_workflow_params(params, opts \\ []) do
    trigger_type =
      (first_present(params, ["trigger_type", "triggerType"]) ||
         trigger_type_from_legacy_trigger(Map.get(params, "trigger")) ||
         "manual")
      |> normalize_trigger_type()

    trigger_config =
      first_present(params, ["trigger_config", "triggerConfig"]) ||
        trigger_config_from_legacy(params) ||
        %{}

    steps =
      first_present(params, ["steps"]) ||
        actions_to_steps(Map.get(params, "actions")) ||
        []

    %{
      name: Map.get(params, "name"),
      description: Map.get(params, "description"),
      category: Map.get(params, "category"),
      tags: Map.get(params, "tags", []),
      trigger_type: trigger_type,
      trigger_config: trigger_config,
      steps: steps,
      variables: Map.get(params, "variables", %{}),
      enabled: normalized_enabled(params, opts)
    }
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new()
  end

  defp first_present(params, keys) do
    Enum.find_value(keys, fn key ->
      case Map.fetch(params, key) do
        {:ok, value} -> value
        :error -> nil
      end
    end)
  end

  defp trigger_type_from_legacy_trigger(%{"type" => type}), do: type
  defp trigger_type_from_legacy_trigger(%{type: type}), do: type
  defp trigger_type_from_legacy_trigger(type) when is_binary(type), do: type
  defp trigger_type_from_legacy_trigger(_), do: nil

  defp trigger_config_from_legacy(params) do
    cond do
      is_map(Map.get(params, "trigger")) -> Map.get(params, "trigger")
      is_list(Map.get(params, "conditions")) -> %{"conditions" => Map.get(params, "conditions")}
      is_list(Map.get(params, "triggerConditions")) -> %{"conditions" => Map.get(params, "triggerConditions")}
      true -> nil
    end
  end

  defp normalize_trigger_type("event"), do: "event_stream"
  defp normalize_trigger_type(type) when type in ["manual", "alert", "detection", "schedule", "webhook", "api", "event_stream"], do: type
  defp normalize_trigger_type(_), do: "manual"

  defp actions_to_steps(actions) when is_list(actions) do
    actions
    |> Enum.with_index(1)
    |> Enum.map(fn
      {%{"id" => _id, "type" => _type} = step, _index} ->
        step

      {action, index} when is_map(action) ->
        %{
          "id" => Map.get(action, "id") || "step-#{index}",
          "type" => Map.get(action, "type") || "action",
          "name" => Map.get(action, "name") || Map.get(action, "action") || "Action #{index}",
          "action" => Map.get(action, "action") || Map.get(action, "name"),
          "params" => Map.get(action, "params", %{})
        }

      {action, index} when is_binary(action) ->
        %{"id" => "step-#{index}", "type" => "action", "name" => action, "action" => action, "params" => %{}}
    end)
  end

  defp actions_to_steps(_), do: nil

  defp normalized_enabled(params, opts) do
    case first_present(params, ["enabled", "isEnabled"]) do
      nil -> Keyword.get(opts, :default_enabled)
      value -> value
    end
  end

  defp serialize_workflow(workflow) do
    %{
      id: workflow.id,
      name: workflow.name,
      description: workflow.description || "",
      enabled: workflow.enabled,
      is_enabled: workflow.enabled,
      trigger_type: workflow.trigger_type,
      trigger_config: workflow.trigger_config || %{},
      steps: workflow.steps || [],
      execution_count: workflow.execution_count || 0,
      success_count: workflow.success_count || 0,
      avg_duration_seconds: workflow.avg_duration_seconds || 0,
      last_executed_at: workflow.last_executed_at,
      inserted_at: workflow.inserted_at,
      updated_at: workflow.updated_at
    }
  end

  defp parse_int(value, fallback) when is_integer(value), do: value

  defp parse_int(value, fallback) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> fallback
    end
  end

  defp parse_int(_, fallback), do: fallback

  defp format_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
