defmodule TamanduaServer.AISecurity.ResponseActions do
  @moduledoc """
  Tenant-bound, audited response actions for discovered AI models.

  Every public mutation requires a canonical `ResponseActor`. The target model
  and its endpoint are re-resolved under that actor's organization, an intent
  audit row is persisted, and only then is the command handed to the governed
  response executor. Legacy user-id-only calls fail closed.
  """

  alias TamanduaServer.Agents
  alias TamanduaServer.AISecurity.{AIInventory, ModelBlock}
  alias TamanduaServer.Response.{Audit, Executor}

  @type actor :: %{organization_id: Ecto.UUID.t(), user_id: Ecto.UUID.t()}

  def quarantine_model(model_id, actor, opts \\ [])

  def quarantine_model(model_id, %{} = actor, opts) do
    execute(model_id, actor, "ai_model.quarantine", "quarantine_file_advanced", %{
      path_from_model: true,
      reason: Keyword.get(opts, :reason, "Quarantined by user"),
      model_id: model_id
    })
  end

  def quarantine_model(_model_id, _legacy_actor, _opts), do: {:error, :actor_scope_required}

  def block_model(model_id, actor, opts \\ [])

  def block_model(model_id, %{} = actor, opts) do
    with {:ok, context} <- prepare(model_id, actor, "ai_model.block", opts),
         {:ok, block_entry} <-
           ModelBlock.create_block(model_id, context.model[:file_hash], context.user_id,
             organization_id: context.organization_id,
             agent_id: context.agent.id,
             file_path: model_path(context.model),
             reason: Keyword.get(opts, :reason)
           ),
         result <-
           dispatch(context, "app_control_add_rule", %{
             rule_type: "block_file",
             file_hash: context.model[:file_hash],
             file_path: model_path(context.model),
             model_id: model_id
           }) do
      case result do
        {:ok, _response} ->
          {:ok, %{model_id: model_id, status: "blocked", block_entry_id: block_entry.id}}

        {:error, reason} = error ->
          ModelBlock.remove_block(model_id, context.organization_id)
          audit_failed(model_id, actor, "ai_model.block", reason)
          error
      end
    else
      {:error, %Ecto.Changeset{} = changeset} ->
        if Keyword.has_key?(changeset.errors, :model_id),
          do: {:error, :already_blocked},
          else: {:error, changeset}

      {:error, reason} = error ->
        audit_failed(model_id, actor, "ai_model.block", reason)
        error
    end
  end

  def block_model(_model_id, _legacy_actor, _opts), do: {:error, :actor_scope_required}

  def unblock_model(model_id, %{} = actor) do
    with {:ok, context} <- prepare(model_id, actor, "ai_model.unblock", []),
         true <- ModelBlock.is_blocked?(model_id, context.organization_id),
         {:ok, _response} <-
           dispatch(context, "app_control_remove_rule", %{
             rule_type: "block_file",
             file_hash: context.model[:file_hash],
             file_path: model_path(context.model),
             model_id: model_id
           }),
         {:ok, _block} <- ModelBlock.remove_block(model_id, context.organization_id) do
      {:ok, %{model_id: model_id, status: "unblocked"}}
    else
      false ->
        {:error, :not_found}

      {:error, reason} = error ->
        audit_failed(model_id, actor, "ai_model.unblock", reason)
        error
    end
  end

  def unblock_model(_model_id, _legacy_actor), do: {:error, :actor_scope_required}

  def restore_model(model_id, actor, opts \\ [])

  def restore_model(model_id, %{} = actor, opts) do
    if Keyword.get(opts, :acknowledge_risk, false) do
      execute(model_id, actor, "ai_model.restore", "quarantine_restore_file", %{
        path_from_model: true,
        model_id: model_id,
        force_restore: Keyword.get(opts, :force_restore, false),
        rescan_after: not Keyword.get(opts, :force_restore, false)
      })
    else
      {:error, :risk_acknowledgment_required}
    end
  end

  def restore_model(_model_id, _legacy_actor, _opts), do: {:error, :actor_scope_required}

  def get_model_status(organization_id, model_id) do
    with {:ok, %{component: model}} <- AIInventory.assess_risk(organization_id, model_id) do
      status =
        cond do
          ModelBlock.is_blocked?(model_id, organization_id) -> "blocked"
          model[:quarantined] -> "quarantined"
          true -> "active"
        end

      {:ok, %{model_id: model_id, status: status, model: model}}
    end
  end

  def get_model_status(_model_id), do: {:error, :organization_scope_required}

  defp execute(model_id, actor, audit_action, command_type, params) do
    with {:ok, context} <- prepare(model_id, actor, audit_action, []),
         params <- resolve_model_path(params, context.model),
         {:ok, _response} <- dispatch(context, command_type, params) do
      status = audit_action |> String.split(".") |> List.last()
      {:ok, %{model_id: model_id, status: status}}
    else
      {:error, reason} = error ->
        audit_failed(model_id, actor, audit_action, reason)
        error
    end
  end

  # Intent persistence is deliberately before every mutation or dispatch.
  defp prepare(model_id, actor, action, opts) do
    with {:ok, organization_id, user_id} <- canonical_actor(actor),
         {:ok, %{component: model}} <- AIInventory.assess_risk(organization_id, model_id),
         {:ok, agent_id} <- canonical_uuid(model[:agent_id]),
         {:ok, agent} <- Agents.get_agent_for_org(organization_id, agent_id),
         true <- model[:organization_id] == organization_id,
         {:ok, _intent} <-
           Audit.log_action(
             action <> ".intent",
             %{model_id: model_id, reason: Keyword.get(opts, :reason)},
             agent_id,
             user_id,
             organization_id
           ) do
      {:ok,
       %{
         actor: %{organization_id: organization_id, user_id: user_id},
         organization_id: organization_id,
         user_id: user_id,
         model_id: model_id,
         model: model,
         agent: agent,
         action: action
       }}
    else
      false -> {:error, :not_found}
      {:error, :not_found} -> {:error, :not_found}
      {:error, reason} -> {:error, {:intent_audit_failed, reason}}
      _ -> {:error, :not_found}
    end
  end

  # Executor repeats the authoritative agent tenant check and persists its own
  # executing/outcome record before touching the worker transport.
  defp dispatch(context, command_type, params) do
    with {:ok, %{component: current_model}} <-
           AIInventory.assess_risk(context.organization_id, context.model_id),
         true <- current_model[:agent_id] == context.agent.id,
         {:ok, current_agent} <-
           Agents.get_agent_for_org(context.organization_id, current_model[:agent_id]),
         true <- current_agent.id == context.agent.id do
      Executor.execute_action(current_agent.id, command_type, params,
        actor: context.actor,
        organization_id: context.organization_id,
        persist_action: true
      )
    else
      _ -> {:error, :not_found}
    end
  end

  defp audit_failed(model_id, actor, action, reason) do
    with {:ok, organization_id, user_id} <- canonical_actor(actor),
         {:ok, %{component: model}} <- AIInventory.assess_risk(organization_id, model_id),
         {:ok, agent_id} <- canonical_uuid(model[:agent_id]) do
      Audit.log_action(
        action <> ".outcome",
        %{model_id: model_id, success: false, error: inspect(reason)},
        agent_id,
        user_id,
        organization_id
      )
    end
  rescue
    _ -> :error
  end

  defp resolve_model_path(%{path_from_model: true} = params, model) do
    params |> Map.delete(:path_from_model) |> Map.put(:path, model_path(model))
  end

  defp resolve_model_path(params, _model), do: params
  defp model_path(model), do: model[:path] || model[:install_path]

  defp canonical_actor(%{} = actor) do
    with {:ok, organization_id} <-
           canonical_uuid(actor[:organization_id] || actor["organization_id"]),
         {:ok, user_id} <- canonical_uuid(actor[:user_id] || actor["user_id"]) do
      {:ok, organization_id, user_id}
    else
      _ -> {:error, :actor_scope_required}
    end
  end

  defp canonical_actor(_), do: {:error, :actor_scope_required}
  defp canonical_uuid(value) when is_binary(value), do: Ecto.UUID.cast(value)
  defp canonical_uuid(_), do: :error
end
