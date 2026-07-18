defmodule TamanduaServer.AISecurity.ModelBlock do
  @moduledoc """
  Context for managing blocked AI models.

  Blocked models cannot be loaded/executed by AI runtimes.
  The block list is synchronized to agents for enforcement.

  ## Block List Sync

  When a model is blocked, the agent receives an `app_control_add_rule` command
  to add the file to its local block list. The agent enforces blocking via:
  - File permission changes (remove read/execute)
  - Real-time access monitoring

  ## Example

      # Block a malicious model
      {:ok, block} = ModelBlock.create_block(
        "model-123",
        "abc123sha256...",
        user_id,
        organization_id: org_id,
        agent_id: "agent-456",
        reason: "Detected pickle code execution vulnerability"
      )

      # Check if blocked
      true = ModelBlock.is_blocked?("model-123", org_id)

      # Unblock (soft delete)
      {:ok, _} = ModelBlock.remove_block("model-123", org_id)
  """

  import Ecto.Query
  alias TamanduaServer.Agents
  alias TamanduaServer.Repo
  alias TamanduaServer.AISecurity.ModelBlock.BlockEntry

  @doc """
  Creates a block entry for a model.

  ## Parameters
    * `model_id` - Unique identifier for the AI model
    * `file_hash` - SHA-256 hash of the model file
    * `user_id` - ID of the user creating the block
    * `opts` - Keyword list of options:
      * `:organization_id` - Required. Organization this block belongs to
      * `:agent_id` - ID of the agent hosting the model
      * `:file_path` - Full path to the model file
      * `:reason` - Justification for blocking

  ## Returns
    * `{:ok, %BlockEntry{}}` - Block entry created successfully
    * `{:error, %Ecto.Changeset{}}` - Validation failed
  """
  def create_block(model_id, file_hash, user_id, opts \\ []) do
    with {:ok, organization_id} <- canonical_uuid(Keyword.get(opts, :organization_id)),
         {:ok, agent_id} <- canonical_uuid(Keyword.get(opts, :agent_id)),
         {:ok, _agent} <- Agents.get_agent_for_org(organization_id, agent_id) do
      attrs = %{
        model_id: model_id,
        file_hash: file_hash,
        file_path: Keyword.get(opts, :file_path),
        agent_id: agent_id,
        reason: Keyword.get(opts, :reason, "Blocked by user"),
        blocked_by_id: user_id,
        organization_id: organization_id,
        status: "active"
      }

      %BlockEntry{}
      |> BlockEntry.changeset(attrs)
      |> Repo.insert()
    else
      _ -> {:error, :organization_scope_required}
    end
  end

  @doc """
  Removes a block entry (soft delete - sets status to 'removed').

  The model can be loaded again after unblocking. A corresponding
  `app_control_remove_rule` command should be sent to the agent.

  ## Returns
    * `{:ok, %BlockEntry{}}` - Block removed successfully
    * `{:error, :not_found}` - No active block found
  """
  def remove_block(model_id, organization_id) do
    with {:ok, organization_id} <- canonical_uuid(organization_id) do
      case get_block(model_id, organization_id) do
        nil ->
          {:error, :not_found}

        block ->
          block
          |> BlockEntry.changeset(%{status: "removed"})
          |> Repo.update()
      end
    else
      _ -> {:error, :organization_scope_required}
    end
  end

  @doc """
  Gets an active block entry by model_id.

  Returns `nil` if no active block exists.
  """
  def get_block(model_id, organization_id) do
    with {:ok, organization_id} <- canonical_uuid(organization_id) do
      BlockEntry
      |> where([b], b.model_id == ^model_id and b.organization_id == ^organization_id)
      |> where([b], b.status == "active")
      |> Repo.one()
    else
      _ -> nil
    end
  end

  @doc """
  Checks if a model is currently blocked.

  ## Returns
    * `true` - Model has an active block entry
    * `false` - Model is not blocked
  """
  def is_blocked?(model_id, organization_id) do
    with {:ok, organization_id} <- canonical_uuid(organization_id) do
      BlockEntry
      |> where([b], b.model_id == ^model_id and b.organization_id == ^organization_id)
      |> where([b], b.status == "active")
      |> Repo.exists?()
    else
      _ -> false
    end
  end

  @doc """
  Lists all blocked models for an organization.

  ## Options
    * `:limit` - Maximum number of results (default: 100)

  ## Returns
    List of `%BlockEntry{}` structs, ordered by most recent first.
  """
  def list_blocked(organization_id, opts \\ []) do
    with {:ok, organization_id} <- canonical_uuid(organization_id) do
      limit = Keyword.get(opts, :limit, 100)

      BlockEntry
      |> where([b], b.organization_id == ^organization_id)
      |> where([b], b.status == "active")
      |> order_by([b], desc: b.inserted_at)
      |> limit(^limit)
      |> Repo.all()
    else
      _ -> []
    end
  end

  @doc """
  Lists blocked models for a specific agent.

  Used for synchronizing the block list to an agent.
  """
  def list_blocked_for_agent(agent_id, organization_id) do
    with {:ok, organization_id} <- canonical_uuid(organization_id),
         {:ok, agent_id} <- canonical_uuid(agent_id) do
      BlockEntry
      |> where([b], b.agent_id == ^agent_id and b.organization_id == ^organization_id)
      |> where([b], b.status == "active")
      |> Repo.all()
    else
      _ -> []
    end
  end

  @doc """
  Gets blocked model hashes for sync to agent.

  Returns a list of maps with hash and path for the agent's block list.

  ## Returns
    List of `%{hash: string, path: string}`
  """
  def get_block_list_for_agent(agent_id, organization_id) do
    with {:ok, organization_id} <- canonical_uuid(organization_id),
         {:ok, agent_id} <- canonical_uuid(agent_id) do
      BlockEntry
      |> where([b], b.agent_id == ^agent_id and b.organization_id == ^organization_id)
      |> where([b], b.status == "active")
      |> select([b], %{hash: b.file_hash, path: b.file_path})
      |> Repo.all()
    else
      _ -> []
    end
  end

  @doc """
  Counts active blocks for an organization.
  """
  def count_blocked(organization_id) do
    with {:ok, organization_id} <- canonical_uuid(organization_id) do
      BlockEntry
      |> where([b], b.organization_id == ^organization_id)
      |> where([b], b.status == "active")
      |> Repo.aggregate(:count)
    else
      _ -> 0
    end
  end

  defp canonical_uuid(value) when is_binary(value), do: Ecto.UUID.cast(value)
  defp canonical_uuid(_), do: :error
end
