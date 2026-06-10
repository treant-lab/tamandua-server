defmodule TamanduaServer.Detection.AttackChainAPI do
  @moduledoc """
  Public API for managing attack chains.

  Provides CRUD operations and management functions for attack chain definitions.
  """

  import Ecto.Query
  alias TamanduaServer.{Repo, Detection}
  alias TamanduaServer.Detection.{AttackChain, AttackChainDetector, ChainLibrary}

  @doc """
  List all attack chains for an organization.
  """
  @spec list_chains(binary(), keyword()) :: [AttackChain.t()]
  def list_chains(organization_id, opts \\ []) do
    enabled_only = Keyword.get(opts, :enabled_only, false)

    query =
      from c in AttackChain,
        where: c.organization_id == ^organization_id,
        order_by: [desc: c.severity, desc: c.trigger_count]

    query =
      if enabled_only do
        from c in query, where: c.enabled == true
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Get a single attack chain by ID.
  """
  @spec get_chain(binary()) :: {:ok, AttackChain.t()} | {:error, :not_found}
  def get_chain(chain_id) do
    case Repo.get(AttackChain, chain_id) do
      nil -> {:error, :not_found}
      chain -> {:ok, chain}
    end
  end

  @doc """
  Create a new attack chain.
  """
  @spec create_chain(map()) :: {:ok, AttackChain.t()} | {:error, Ecto.Changeset.t()}
  def create_chain(attrs) do
    result =
      %AttackChain{}
      |> AttackChain.changeset(attrs)
      |> Repo.insert()

    case result do
      {:ok, chain} ->
        AttackChainDetector.reload_chains()
        {:ok, chain}

      error ->
        error
    end
  end

  @doc """
  Update an attack chain.
  """
  @spec update_chain(AttackChain.t(), map()) ::
          {:ok, AttackChain.t()} | {:error, Ecto.Changeset.t()}
  def update_chain(chain, attrs) do
    result =
      chain
      |> AttackChain.changeset(attrs)
      |> Repo.update()

    case result do
      {:ok, updated_chain} ->
        AttackChainDetector.reload_chains()
        {:ok, updated_chain}

      error ->
        error
    end
  end

  @doc """
  Delete an attack chain.
  """
  @spec delete_chain(AttackChain.t()) :: {:ok, AttackChain.t()} | {:error, Ecto.Changeset.t()}
  def delete_chain(chain) do
    result = Repo.delete(chain)

    case result do
      {:ok, deleted_chain} ->
        AttackChainDetector.reload_chains()
        {:ok, deleted_chain}

      error ->
        error
    end
  end

  @doc """
  Enable or disable a chain.
  """
  @spec toggle_chain(binary(), boolean()) :: {:ok, AttackChain.t()} | {:error, term()}
  def toggle_chain(chain_id, enabled) do
    with {:ok, chain} <- get_chain(chain_id),
         {:ok, updated} <- update_chain(chain, %{enabled: enabled}) do
      {:ok, updated}
    end
  end

  @doc """
  Install all built-in chains for an organization.
  """
  @spec install_builtin_chains(binary()) :: {:ok, map()} | {:error, term()}
  def install_builtin_chains(organization_id) do
    ChainLibrary.install_builtin_chains(organization_id)
  end

  @doc """
  Import chain from YAML content.
  """
  @spec import_yaml(String.t(), binary()) :: {:ok, AttackChain.t()} | {:error, term()}
  def import_yaml(yaml_content, organization_id) do
    with {:ok, definition} <- AttackChain.parse_yaml(yaml_content),
         attrs <- Map.put(definition, :organization_id, organization_id),
         {:ok, chain} <- create_chain(attrs) do
      {:ok, chain}
    end
  end

  @doc """
  Export chain to YAML format.
  """
  @spec export_yaml(binary()) :: {:ok, String.t()} | {:error, term()}
  def export_yaml(chain_id) do
    with {:ok, chain} <- get_chain(chain_id) do
      {:ok, AttackChain.to_yaml(chain)}
    end
  end

  @doc """
  Get chain statistics.
  """
  @spec get_chain_stats(binary()) :: map()
  def get_chain_stats(organization_id) do
    query =
      from c in AttackChain,
        where: c.organization_id == ^organization_id,
        select: %{
          total: count(c.id),
          enabled: fragment("COUNT(*) FILTER (WHERE enabled = true)"),
          critical: fragment("COUNT(*) FILTER (WHERE severity = 'critical')"),
          high: fragment("COUNT(*) FILTER (WHERE severity = 'high')"),
          triggered: fragment("SUM(trigger_count)"),
          false_positives: fragment("SUM(false_positive_count)")
        }

    stats = Repo.one(query) || %{total: 0, enabled: 0, critical: 0, high: 0, triggered: 0, false_positives: 0}

    # Add detector stats
    detector_stats = AttackChainDetector.get_stats()

    Map.merge(stats, %{
      active_chains: detector_stats.active_chains,
      events_processed: detector_stats.events_processed
    })
  end

  @doc """
  Get active chain progressions for an agent.
  """
  @spec get_active_chains_for_agent(binary()) :: [map()]
  def get_active_chains_for_agent(agent_id) do
    AttackChainDetector.get_active_chains(agent_id)
  end

  @doc """
  Test a chain in dry-run mode.
  """
  @spec test_chain(binary(), [map()]) :: {:ok, [map()]} | {:error, term()}
  def test_chain(chain_id, test_events) do
    with {:ok, chain} <- get_chain(chain_id) do
      # Temporarily enable test mode
      original_test_mode = chain.test_mode
      update_chain(chain, %{test_mode: true})

      # Process test events
      results =
        Enum.reduce(test_events, [], fn event, acc ->
          {:ok, completed} = AttackChainDetector.process_event(event)
          acc ++ completed
        end)

      # Restore original test mode
      update_chain(chain, %{test_mode: original_test_mode})

      {:ok, results}
    end
  end

  @doc """
  Record a false positive for a chain.
  """
  @spec record_false_positive(binary()) :: {:ok, AttackChain.t()} | {:error, term()}
  def record_false_positive(chain_id) do
    with {:ok, chain} <- get_chain(chain_id) do
      chain
      |> AttackChain.record_false_positive()
      |> Repo.update()
    end
  end

  @doc """
  Get chain detection history.
  """
  @spec get_detection_history(binary(), keyword()) :: [map()]
  def get_detection_history(organization_id, opts \\ []) do
    days = Keyword.get(opts, :days, 30)
    since = DateTime.utc_now() |> DateTime.add(-days * 24 * 60 * 60, :second)

    query =
      from a in Detection.Alert,
        where: a.organization_id == ^organization_id,
        where: a.inserted_at >= ^since,
        where: fragment("? IS NOT NULL", a.detection_metadata["chain_id"]),
        order_by: [desc: a.inserted_at],
        select: %{
          id: a.id,
          chain_id: fragment("?->>'chain_id'", a.detection_metadata),
          chain_name: fragment("?->>'chain_name'", a.detection_metadata),
          severity: a.severity,
          agent_id: a.agent_id,
          created_at: a.inserted_at,
          status: a.status
        }

    Repo.all(query)
  end

  @doc """
  Duplicate a chain with a new name.
  """
  @spec duplicate_chain(binary(), String.t()) :: {:ok, AttackChain.t()} | {:error, term()}
  def duplicate_chain(chain_id, new_name) do
    with {:ok, chain} <- get_chain(chain_id) do
      attrs = %{
        name: new_name,
        description: chain.description,
        severity: chain.severity,
        enabled: false,
        definition: chain.definition,
        author: chain.author,
        tags: chain.tags,
        organization_id: chain.organization_id
      }

      create_chain(attrs)
    end
  end
end
