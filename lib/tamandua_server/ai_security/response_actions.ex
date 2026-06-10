defmodule TamanduaServer.AISecurity.ResponseActions do
  @moduledoc """
  Coordinates response actions for AI model threats.

  Provides quarantine, block, and restore operations with:
  - Agent command dispatch via WebSocket
  - Audit logging for all actions
  - Status tracking and error handling

  ## Response Actions

  ### Quarantine
  Moves the model file to an encrypted vault on the agent. The file cannot
  be accessed until restored. Uses AES-256-GCM encryption with per-file IV.

  ### Block
  Prevents the model from being loaded or executed without moving it.
  Creates a block entry in the database and syncs to the agent's block list.

  ### Restore
  Restores a quarantined model to its original location. Requires explicit
  risk acknowledgment. A re-scan is performed after restoration.

  ## Audit Logging

  All actions are logged to the audit system with:
  - Action type (`ai_model.quarantine`, `ai_model.block`, etc.)
  - User who performed the action
  - Timestamp and metadata (file hash, agent ID, reason)

  ## Example

      # Quarantine a malicious model
      {:ok, result} = ResponseActions.quarantine_model(model_id, user_id, reason: "Pickle RCE detected")

      # Block a suspicious model
      {:ok, result} = ResponseActions.block_model(model_id, user_id, reason: "Suspicious external data refs")

      # Restore with risk acknowledgment
      {:ok, result} = ResponseActions.restore_model(model_id, user_id, acknowledge_risk: true)
  """

  require Logger
  alias TamanduaServer.Agents
  alias TamanduaServer.Audit.ActivityLogger
  alias TamanduaServer.AISecurity.AIInventory
  alias TamanduaServer.AISecurity.ModelBlock

  @command_timeout 30_000

  @doc """
  Quarantines a model to the agent's encrypted vault.

  Sends a `quarantine_file_advanced` command to the agent, which moves the
  model file to an encrypted vault using AES-256-GCM.

  ## Options
    * `:reason` - Reason for quarantine (default: "Quarantined by user")

  ## Returns
    * `{:ok, %{model_id: string, status: "quarantined"}}` - Success
    * `{:error, :not_found}` - Model not found in inventory
    * `{:error, :agent_not_connected}` - Agent offline
    * `{:error, reason}` - Other error
  """
  def quarantine_model(model_id, user_id, opts \\ []) do
    with {:ok, model} <- get_model_with_agent(model_id),
         organization_id <- model[:organization_id],
         :ok <- send_quarantine_command(model, opts) do

      # Log successful quarantine
      log_action("ai_model.quarantine", model, user_id, organization_id, %{
        reason: Keyword.get(opts, :reason, "Quarantined by user"),
        success: true
      })

      # Broadcast status change
      broadcast_status_change(model_id, "quarantined")

      {:ok, %{model_id: model_id, status: "quarantined"}}
    else
      {:error, :not_found} = err ->
        err
      {:error, :agent_not_connected} = err ->
        # Log failed attempt
        log_action_failed("ai_model.quarantine", model_id, user_id, nil, "Agent not connected")
        err
      {:error, reason} = err ->
        log_action_failed("ai_model.quarantine", model_id, user_id, nil, inspect(reason))
        err
    end
  end

  @doc """
  Blocks a model from being loaded/executed.

  Creates a block entry in the database and sends an `app_control_add_rule`
  command to the agent. The agent enforces the block via file permissions
  and access monitoring.

  ## Options
    * `:reason` - Reason for blocking

  ## Returns
    * `{:ok, %{model_id: string, status: "blocked", block_entry_id: uuid}}` - Success
    * `{:error, :not_found}` - Model not found
    * `{:error, :already_blocked}` - Model already has an active block
    * `{:error, :agent_not_connected}` - Agent offline
    * `{:error, reason}` - Other error
  """
  def block_model(model_id, user_id, opts \\ []) do
    with {:ok, model} <- get_model_with_agent(model_id),
         organization_id <- model[:organization_id],
         file_hash <- model[:file_hash],
         {:ok, block_entry} <- ModelBlock.create_block(model_id, file_hash, user_id,
           [organization_id: organization_id,
            agent_id: model[:agent_id],
            file_path: model[:path] || model[:install_path],
            reason: Keyword.get(opts, :reason)]),
         :ok <- send_block_command(model) do

      log_action("ai_model.block", model, user_id, organization_id, %{
        reason: Keyword.get(opts, :reason, "Blocked by user"),
        block_entry_id: block_entry.id,
        success: true
      })

      broadcast_status_change(model_id, "blocked")

      {:ok, %{model_id: model_id, status: "blocked", block_entry_id: block_entry.id}}
    else
      {:error, :not_found} = err -> err
      {:error, :agent_not_connected} = err ->
        log_action_failed("ai_model.block", model_id, user_id, nil, "Agent not connected")
        err
      {:error, %Ecto.Changeset{} = changeset} ->
        # Already blocked (unique constraint)
        if Keyword.has_key?(changeset.errors, :model_id) do
          {:error, :already_blocked}
        else
          {:error, changeset}
        end
      {:error, reason} = err ->
        log_action_failed("ai_model.block", model_id, user_id, nil, inspect(reason))
        err
    end
  end

  @doc """
  Unblocks a previously blocked model.

  Removes the block entry (soft delete) and sends an `app_control_remove_rule`
  command to the agent.

  ## Returns
    * `{:ok, %{model_id: string, status: "unblocked"}}` - Success
    * `{:error, :not_found}` - Model or block entry not found
    * `{:error, :agent_not_connected}` - Agent offline
  """
  def unblock_model(model_id, user_id) do
    with {:ok, model} <- get_model_with_agent(model_id),
         organization_id <- model[:organization_id],
         {:ok, _block_entry} <- ModelBlock.remove_block(model_id, organization_id),
         :ok <- send_unblock_command(model) do

      log_action("ai_model.unblock", model, user_id, organization_id, %{success: true})
      broadcast_status_change(model_id, "unblocked")

      {:ok, %{model_id: model_id, status: "unblocked"}}
    else
      {:error, :not_found} -> {:error, :not_found}
      {:error, :agent_not_connected} = err ->
        log_action_failed("ai_model.unblock", model_id, user_id, nil, "Agent not connected")
        err
      {:error, reason} = err ->
        log_action_failed("ai_model.unblock", model_id, user_id, nil, inspect(reason))
        err
    end
  end

  @doc """
  Restores a quarantined model to its original location.

  Requires explicit risk acknowledgment via the `:acknowledge_risk` option.
  A re-scan is performed after restoration unless `:force_restore` is true.

  ## Options
    * `:acknowledge_risk` - Must be `true` to proceed (required)
    * `:force_restore` - Skip re-scan check (default: false)

  ## Returns
    * `{:ok, %{model_id: string, status: "restored"}}` - Success
    * `{:error, :risk_acknowledgment_required}` - Missing risk acknowledgment
    * `{:error, :not_found}` - Model not found
    * `{:error, :agent_not_connected}` - Agent offline
  """
  def restore_model(model_id, user_id, opts \\ []) do
    unless Keyword.get(opts, :acknowledge_risk, false) do
      {:error, :risk_acknowledgment_required}
    else
      with {:ok, model} <- get_model_with_agent(model_id),
           organization_id <- model[:organization_id],
           :ok <- send_restore_command(model, opts) do

        log_action("ai_model.restore", model, user_id, organization_id, %{
          acknowledge_risk: true,
          force_restore: Keyword.get(opts, :force_restore, false),
          success: true
        })

        broadcast_status_change(model_id, "restored")

        {:ok, %{model_id: model_id, status: "restored"}}
      else
        {:error, :not_found} = err -> err
        {:error, :agent_not_connected} = err ->
          log_action_failed("ai_model.restore", model_id, user_id, nil, "Agent not connected")
          err
        {:error, reason} = err ->
          log_action_failed("ai_model.restore", model_id, user_id, nil, inspect(reason))
          err
      end
    end
  end

  @doc """
  Gets the current response status of a model.

  Checks both the model's quarantine status and block list membership.

  ## Returns
    * `{:ok, %{model_id: string, status: string, model: map}}` - Status info
    * `{:error, :not_found}` - Model not found
  """
  def get_model_status(model_id) do
    with {:ok, model} <- get_model_with_agent(model_id) do
      organization_id = model[:organization_id]
      is_blocked = if organization_id, do: ModelBlock.is_blocked?(model_id, organization_id), else: false

      status = cond do
        is_blocked -> "blocked"
        model[:quarantined] -> "quarantined"
        true -> "active"
      end

      {:ok, %{model_id: model_id, status: status, model: model}}
    end
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp get_model_with_agent(model_id) do
    case AIInventory.assess_risk(model_id) do
      {:ok, %{component: model}} -> {:ok, model}
      {:error, :not_found} -> {:error, :not_found}
    end
  end

  defp send_quarantine_command(model, opts) do
    command = %{
      type: "quarantine_file_advanced",
      payload: %{
        path: model[:path] || model[:install_path],
        reason: Keyword.get(opts, :reason, "Quarantined by user"),
        model_id: model[:id]
      }
    }

    send_agent_command(model[:agent_id], command)
  end

  defp send_block_command(model) do
    command = %{
      type: "app_control_add_rule",
      payload: %{
        rule_type: "block_file",
        file_hash: model[:file_hash],
        file_path: model[:path] || model[:install_path],
        model_id: model[:id]
      }
    }

    send_agent_command(model[:agent_id], command)
  end

  defp send_unblock_command(model) do
    command = %{
      type: "app_control_remove_rule",
      payload: %{
        rule_type: "block_file",
        file_hash: model[:file_hash],
        file_path: model[:path] || model[:install_path],
        model_id: model[:id]
      }
    }

    send_agent_command(model[:agent_id], command)
  end

  defp send_restore_command(model, opts) do
    command = %{
      type: "quarantine_restore_file",
      payload: %{
        model_id: model[:id],
        path: model[:path] || model[:install_path],
        force_restore: Keyword.get(opts, :force_restore, false),
        rescan_after: not Keyword.get(opts, :force_restore, false)
      }
    }

    send_agent_command(model[:agent_id], command)
  end

  defp send_agent_command(agent_id, command) do
    try do
      case Agents.send_command(agent_id, command) do
        {:ok, _} -> :ok
        :ok -> :ok
        {:error, reason} -> {:error, reason}
      end
    rescue
      e ->
        Logger.error("Failed to send command to agent #{agent_id}: #{inspect(e)}")
        {:error, {:command_error, e}}
    catch
      :exit, reason ->
        Logger.error("Agent command exited: #{inspect(reason)}")
        {:error, {:exit, reason}}
    end
  end

  defp log_action(action, model, user_id, organization_id, metadata) do
    try do
      ActivityLogger.log(%{
        action: action,
        resource_type: "ai_model",
        resource_id: model[:id],
        user_id: user_id,
        organization_id: organization_id,
        metadata: Map.merge(%{
          model_path: model[:path] || model[:install_path],
          file_hash: model[:file_hash],
          agent_id: model[:agent_id]
        }, metadata),
        severity: "medium",
        category: "ai_security",
        success: true
      })
    rescue
      e ->
        Logger.warning("Failed to log action #{action}: #{inspect(e)}")
    end
  end

  defp log_action_failed(action, model_id, user_id, organization_id, reason) do
    try do
      ActivityLogger.log(%{
        action: action,
        resource_type: "ai_model",
        resource_id: model_id,
        user_id: user_id,
        organization_id: organization_id,
        metadata: %{error: reason},
        severity: "medium",
        category: "ai_security",
        success: false,
        error_message: reason
      })
    rescue
      e ->
        Logger.warning("Failed to log failed action #{action}: #{inspect(e)}")
    end
  end

  defp broadcast_status_change(model_id, status) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "ai_security:response_actions",
      {:model_status_changed, %{model_id: model_id, status: status}}
    )
  end
end
