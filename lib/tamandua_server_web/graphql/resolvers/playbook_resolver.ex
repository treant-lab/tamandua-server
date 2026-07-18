defmodule TamanduaServerWeb.GraphQL.Resolvers.PlaybookResolver do
  @moduledoc """
  GraphQL resolvers for Playbook queries and mutations.
  """

  alias TamanduaServer.Response.Playbook

  # Query resolvers

  def list_playbooks(_parent, args, %{context: context}) do
    filter = Map.get(args, :filter, %{})

    with {:ok, scope} <- scope_from_context(context),
         {:ok, playbooks} <- Playbook.list_playbooks(filter, scope) do
      {:ok, playbooks}
    else
      {:error, reason} -> {:error, inspect(reason)}
    end
  end

  def get_playbook(_parent, %{id: id}, %{context: context}) do
    with {:ok, scope} <- scope_from_context(context),
         {:ok, playbook} <- Playbook.get_playbook(id, scope) do
      {:ok, playbook}
    else
      {:error, :not_found} -> {:error, "Playbook not found"}
      {:error, reason} -> {:error, inspect(reason)}
    end
  end

  def playbook_templates(_parent, _args, _resolution) do
    templates = [
      TamanduaServer.Response.Playbook.Templates.ransomware_response(),
      TamanduaServer.Response.Playbook.Templates.lateral_movement_response(),
      TamanduaServer.Response.Playbook.Templates.credential_theft_response()
    ]

    {:ok, templates}
  end

  def pending_approvals(_parent, _args, %{context: context}) do
    with {:ok, scope} <- scope_from_context(context),
         {:ok, approvals} <- Playbook.get_pending_approvals(scope) do
      {:ok, approvals}
    else
      {:error, reason} -> {:error, inspect(reason)}
    end
  end

  # Field resolvers

  def recent_executions(playbook, args, %{context: context}) do
    limit = args[:limit] || 10

    with {:ok, scope} <- scope_from_context(context),
         {:ok, executions} <- Playbook.get_execution_history(playbook.id, [limit: limit], scope) do
      {:ok, executions}
    else
      {:error, _reason} -> {:ok, []}
    end
  end

  def playbook(execution, _args, %{context: context}) do
    with {:ok, scope} <- scope_from_context(context),
         {:ok, playbook} <- Playbook.get_playbook(execution.playbook_id, scope) do
      {:ok, playbook}
    else
      {:error, _reason} -> {:ok, nil}
    end
  end

  # Mutation resolvers

  def create_playbook(_parent, %{input: input}, %{context: context}) do
    user_id = context[:current_user_id]

    attrs = input
    |> Map.put(:created_by, user_id)
    |> normalize_steps()

    with {:ok, scope} <- scope_from_context(context),
         {:ok, playbook} <- Playbook.create_playbook(attrs, scope) do
      {:ok, playbook}
    else
      {:error, changeset} when is_struct(changeset, Ecto.Changeset) ->
        {:error, format_errors(changeset)}
      {:error, reason} ->
        {:error, inspect(reason)}
    end
  end

  def update_playbook(_parent, %{id: id, input: input}, %{context: context}) do
    attrs = normalize_steps(input)

    with {:ok, scope} <- scope_from_context(context),
         {:ok, playbook} <- Playbook.update_playbook(id, attrs, scope) do
      {:ok, playbook}
    else
      {:error, :not_found} -> {:error, "Playbook not found"}
      {:error, changeset} when is_struct(changeset, Ecto.Changeset) ->
        {:error, format_errors(changeset)}
      {:error, reason} ->
        {:error, inspect(reason)}
    end
  end

  def delete_playbook(_parent, %{id: id}, %{context: context}) do
    with {:ok, scope} <- scope_from_context(context) do
      case Playbook.delete_playbook(id, scope) do
      {:ok, _playbook} ->
        {:ok, %{success: true, id: id, message: "Playbook deleted"}}
      {:error, :not_found} ->
        {:ok, %{success: false, id: id, message: "Playbook not found"}}
      {:error, reason} ->
        {:ok, %{success: false, id: id, message: inspect(reason)}}
      end
    end
  end

  def execute_playbook(_parent, %{input: input}, %{context: resolution_context}) do
    playbook_id = input.playbook_id
    context = input[:context] || %{}
    # Approval policy is enforced by the playbook itself. GraphQL callers
    # must use the separately authorized approve_execution mutation instead
    # of bypassing the pending-approval state at execution time.
    with {:ok, scope} <- scope_from_context(resolution_context) do
      authoritative_context =
        context
        |> Map.put(:organization_id, elem(scope, 1))
        |> Map.put(:current_user_id, resolution_context[:current_user_id])

      case Playbook.execute(playbook_id, authoritative_context, %{skip_approval: false, scope: scope}) do
      {:ok, execution} -> {:ok, execution}
      {:error, :not_found} -> {:error, "Playbook not found"}
      {:error, :playbook_disabled} -> {:error, "Playbook is disabled"}
      {:error, :severity_threshold_not_met} -> {:error, "Severity threshold not met"}
      {:error, reason} -> {:error, inspect(reason)}
      end
    end
  end

  def clone_playbook(_parent, %{id: id, new_name: new_name}, %{context: context}) do
    with {:ok, scope} <- scope_from_context(context),
         result <- Playbook.clone_playbook(id, new_name, scope) do
      case result do
      {:ok, playbook} -> {:ok, playbook}
      {:error, :not_found} -> {:error, "Playbook not found"}
      {:error, reason} -> {:error, inspect(reason)}
      end
    end
  end

  def approve_execution(_parent, %{execution_id: execution_id}, %{context: context}) do
    user_id = context[:current_user_id]

    with {:ok, scope} <- scope_from_context(context),
         result <- Playbook.approve_execution(execution_id, user_id, scope) do
      case result do
      {:ok, execution} -> {:ok, execution}
      {:error, :not_found} -> {:error, "Execution not found or not pending approval"}
      {:error, reason} -> {:error, inspect(reason)}
      end
    end
  end

  def cancel_execution(_parent, %{execution_id: execution_id, reason: reason}, %{context: context}) do
    with {:ok, scope} <- scope_from_context(context),
         result <- Playbook.cancel_execution(execution_id, reason || "Cancelled via GraphQL", scope) do
      case result do
      {:ok, execution} -> {:ok, execution}
      {:error, :not_found} -> {:error, "Execution not found"}
      {:error, reason} -> {:error, inspect(reason)}
      end
    end
  end

  # Private helpers

  defp normalize_steps(%{steps: steps} = input) when is_list(steps) do
    normalized_steps = Enum.map(steps, fn step ->
      %{
        "action" => step[:action] || step["action"],
        "name" => step[:name] || step["name"],
        "params" => step[:params] || step["params"] || %{},
        "timeout_seconds" => step[:timeout_seconds] || step["timeout_seconds"],
        "on_failure" => step[:on_failure] || step["on_failure"]
      }
    end)

    Map.put(input, :steps, normalized_steps)
  end

  defp normalize_steps(input), do: input

  defp scope_from_context(context) do
    case context[:organization_id] do
      organization_id when is_binary(organization_id) and organization_id != "" ->
        {:ok, {:organization, organization_id}}

      _ ->
        {:error, :tenant_required}
    end
  end

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
    |> Enum.map(fn {field, errors} -> "#{field}: #{Enum.join(errors, ", ")}" end)
    |> Enum.join("; ")
  end
end
