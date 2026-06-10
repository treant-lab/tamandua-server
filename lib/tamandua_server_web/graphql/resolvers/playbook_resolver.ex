defmodule TamanduaServerWeb.GraphQL.Resolvers.PlaybookResolver do
  @moduledoc """
  GraphQL resolvers for Playbook queries and mutations.
  """

  alias TamanduaServer.Response.Playbook
  alias TamanduaServer.Repo
  import Ecto.Query

  # Query resolvers

  def list_playbooks(_parent, args, _resolution) do
    filter = Map.get(args, :filter, %{})

    case Playbook.list_playbooks(filter) do
      {:ok, playbooks} -> {:ok, playbooks}
      {:error, reason} -> {:error, inspect(reason)}
    end
  end

  def get_playbook(_parent, %{id: id}, _resolution) do
    case Playbook.get_playbook(id) do
      {:ok, playbook} -> {:ok, playbook}
      {:error, :not_found} -> {:error, "Playbook not found"}
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

  def pending_approvals(_parent, _args, _resolution) do
    case Playbook.get_pending_approvals() do
      {:ok, approvals} -> {:ok, approvals}
      {:error, reason} -> {:error, inspect(reason)}
    end
  end

  # Field resolvers

  def recent_executions(playbook, args, _resolution) do
    limit = args[:limit] || 10

    case Playbook.get_execution_history(playbook.id, limit: limit) do
      {:ok, executions} -> {:ok, executions}
      {:error, _} -> {:ok, []}
    end
  end

  def playbook(execution, _args, _resolution) do
    case Playbook.get_playbook(execution.playbook_id) do
      {:ok, playbook} -> {:ok, playbook}
      {:error, _} -> {:ok, nil}
    end
  end

  # Mutation resolvers

  def create_playbook(_parent, %{input: input}, %{context: context}) do
    user_id = context[:current_user_id]

    attrs = input
    |> Map.put(:created_by, user_id)
    |> normalize_steps()

    case Playbook.create_playbook(attrs) do
      {:ok, playbook} -> {:ok, playbook}
      {:error, changeset} when is_struct(changeset, Ecto.Changeset) ->
        {:error, format_errors(changeset)}
      {:error, reason} ->
        {:error, inspect(reason)}
    end
  end

  def update_playbook(_parent, %{id: id, input: input}, _resolution) do
    attrs = normalize_steps(input)

    case Playbook.update_playbook(id, attrs) do
      {:ok, playbook} -> {:ok, playbook}
      {:error, :not_found} -> {:error, "Playbook not found"}
      {:error, changeset} when is_struct(changeset, Ecto.Changeset) ->
        {:error, format_errors(changeset)}
      {:error, reason} ->
        {:error, inspect(reason)}
    end
  end

  def delete_playbook(_parent, %{id: id}, _resolution) do
    case Playbook.delete_playbook(id) do
      {:ok, _playbook} ->
        {:ok, %{success: true, id: id, message: "Playbook deleted"}}
      {:error, :not_found} ->
        {:ok, %{success: false, id: id, message: "Playbook not found"}}
      {:error, reason} ->
        {:ok, %{success: false, id: id, message: inspect(reason)}}
    end
  end

  def execute_playbook(_parent, %{input: input}, %{context: _context}) do
    playbook_id = input.playbook_id
    context = input[:context] || %{}
    opts = %{skip_approval: input[:skip_approval] || false}

    case Playbook.execute(playbook_id, context, opts) do
      {:ok, execution} -> {:ok, execution}
      {:error, :not_found} -> {:error, "Playbook not found"}
      {:error, :playbook_disabled} -> {:error, "Playbook is disabled"}
      {:error, :severity_threshold_not_met} -> {:error, "Severity threshold not met"}
      {:error, reason} -> {:error, inspect(reason)}
    end
  end

  def clone_playbook(_parent, %{id: id, new_name: new_name}, _resolution) do
    case Playbook.clone_playbook(id, new_name) do
      {:ok, playbook} -> {:ok, playbook}
      {:error, :not_found} -> {:error, "Playbook not found"}
      {:error, reason} -> {:error, inspect(reason)}
    end
  end

  def approve_execution(_parent, %{execution_id: execution_id}, %{context: context}) do
    user_id = context[:current_user_id]

    case Playbook.approve_execution(execution_id, user_id) do
      {:ok, execution} -> {:ok, execution}
      {:error, :not_found} -> {:error, "Execution not found or not pending approval"}
      {:error, reason} -> {:error, inspect(reason)}
    end
  end

  def cancel_execution(_parent, %{execution_id: execution_id, reason: reason}, _resolution) do
    case Playbook.cancel_execution(execution_id, reason || "Cancelled via GraphQL") do
      {:ok, execution} -> {:ok, execution}
      {:error, :not_found} -> {:error, "Execution not found"}
      {:error, reason} -> {:error, inspect(reason)}
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
