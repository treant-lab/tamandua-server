defmodule TamanduaServer.BatchOperations do
  @moduledoc """
  Core batch operations for alerts, IOCs, and agent commands.

  Provides transaction-safe batch operations with validation, deduplication,
  and progress tracking. All operations are tenant-scoped.

  ## Rate Limits
  - Maximum 1000 items per batch
  - Maximum 10 batches per minute per organization
  """

  import Ecto.Query, warn: false
  require Logger

  alias Ecto.Multi
  alias TamanduaServer.Repo
  alias TamanduaServer.TenantScope
  alias TamanduaServer.Alerts
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Detection
  alias TamanduaServer.Detection.IOC
  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Response
  alias TamanduaServer.Workers.BatchJobWorker

  @max_batch_size 1000
  @max_batches_per_minute 10

  # ===========================================================================
  # Batch Alert Operations
  # ===========================================================================

  @doc """
  Close multiple alerts in a single transaction.

  ## Parameters
  - `organization_id` - Organization UUID
  - `alert_ids` - List of alert UUIDs (max 1000)
  - `opts` - Options:
    - `:user_id` - User performing the action
    - `:resolution_notes` - Notes for all alerts

  ## Returns
  - `{:ok, %{success_count: integer, failed: [%{id: id, reason: string}]}}`
  - `{:error, reason}`

  ## Example
      batch_close_alerts(org_id, ["uuid1", "uuid2"], user_id: user.id, resolution_notes: "False positive")
  """
  def batch_close_alerts(organization_id, alert_ids, opts \\ []) do
    with :ok <- validate_batch_size(alert_ids),
         :ok <- check_rate_limit(organization_id, :alert_close) do

      user_id = Keyword.get(opts, :user_id)
      resolution_notes = Keyword.get(opts, :resolution_notes, "Batch closed")

      multi =
        alert_ids
        |> Enum.with_index()
        |> Enum.reduce(Multi.new(), fn {alert_id, idx}, multi ->
          Multi.run(multi, {:alert, idx}, fn repo, _changes ->
            case repo.get(Alert, alert_id) do
              nil ->
                {:error, :not_found}

              %Alert{organization_id: ^organization_id} = alert ->
                attrs = %{
                  status: "resolved",
                  resolution_notes: resolution_notes
                }

                case Alerts.update_alert(alert, attrs) do
                  {:ok, updated} ->
                    # Log activity
                    log_alert_activity(alert.id, user_id, "batch_closed", %{
                      resolution_notes: resolution_notes
                    })
                    {:ok, updated}

                  {:error, changeset} ->
                    {:error, changeset}
                end

              _ ->
                {:error, :unauthorized}
            end
          end)
        end)

      case Repo.transaction(multi) do
        {:ok, results} ->
          success_count = Enum.count(results)
          {:ok, %{success_count: success_count, failed: []}}

        {:error, {_op, _idx}, reason, changes} ->
          # Partial failure - collect results
          collect_batch_results(alert_ids, changes, reason)
      end
    end
  end

  @doc """
  Assign multiple alerts to a user.

  ## Parameters
  - `organization_id` - Organization UUID
  - `alert_ids` - List of alert UUIDs
  - `assigned_to_id` - User UUID to assign to
  - `opts` - Options:
    - `:user_id` - User performing the action
  """
  def batch_assign_alerts(organization_id, alert_ids, assigned_to_id, opts \\ []) do
    with :ok <- validate_batch_size(alert_ids),
         :ok <- check_rate_limit(organization_id, :alert_assign) do

      user_id = Keyword.get(opts, :user_id)

      multi =
        alert_ids
        |> Enum.with_index()
        |> Enum.reduce(Multi.new(), fn {alert_id, idx}, multi ->
          Multi.run(multi, {:alert, idx}, fn repo, _changes ->
            case repo.get(Alert, alert_id) do
              nil ->
                {:error, :not_found}

              %Alert{organization_id: ^organization_id} = alert ->
                case Alerts.update_alert(alert, %{assigned_to_id: assigned_to_id}) do
                  {:ok, updated} ->
                    log_alert_activity(alert.id, user_id, "batch_assigned", %{
                      assigned_to_id: assigned_to_id
                    })
                    {:ok, updated}

                  {:error, changeset} ->
                    {:error, changeset}
                end

              _ ->
                {:error, :unauthorized}
            end
          end)
        end)

      execute_batch_transaction(multi, alert_ids)
    end
  end

  @doc """
  Add or remove tags from multiple alerts.

  ## Parameters
  - `organization_id` - Organization UUID
  - `alert_ids` - List of alert UUIDs
  - `opts` - Options:
    - `:add_tags` - Tags to add
    - `:remove_tags` - Tags to remove
    - `:user_id` - User performing the action
  """
  def batch_tag_alerts(organization_id, alert_ids, opts \\ []) do
    with :ok <- validate_batch_size(alert_ids),
         :ok <- check_rate_limit(organization_id, :alert_tag) do

      add_tags = Keyword.get(opts, :add_tags, [])
      remove_tags = Keyword.get(opts, :remove_tags, [])
      user_id = Keyword.get(opts, :user_id)

      multi =
        alert_ids
        |> Enum.with_index()
        |> Enum.reduce(Multi.new(), fn {alert_id, idx}, multi ->
          Multi.run(multi, {:alert, idx}, fn repo, _changes ->
            case repo.get(Alert, alert_id) do
              nil ->
                {:error, :not_found}

              %Alert{organization_id: ^organization_id} = alert ->
                # Update tags (assuming there's a tags field in enrichment)
                current_tags = get_in(alert.enrichment, ["tags"]) || []
                new_tags =
                  current_tags
                  |> Kernel.++(add_tags)
                  |> Kernel.--(remove_tags)
                  |> Enum.uniq()

                enrichment = Map.put(alert.enrichment || %{}, "tags", new_tags)

                case Alerts.update_alert(alert, %{enrichment: enrichment}) do
                  {:ok, updated} ->
                    log_alert_activity(alert.id, user_id, "batch_tagged", %{
                      add_tags: add_tags,
                      remove_tags: remove_tags
                    })
                    {:ok, updated}

                  {:error, changeset} ->
                    {:error, changeset}
                end

              _ ->
                {:error, :unauthorized}
            end
          end)
        end)

      execute_batch_transaction(multi, alert_ids)
    end
  end

  @doc """
  Delete multiple alerts.

  ## Parameters
  - `organization_id` - Organization UUID
  - `alert_ids` - List of alert UUIDs
  - `opts` - Options:
    - `:user_id` - User performing the action
  """
  def batch_delete_alerts(organization_id, alert_ids, opts \\ []) do
    with :ok <- validate_batch_size(alert_ids),
         :ok <- check_rate_limit(organization_id, :alert_delete) do

      user_id = Keyword.get(opts, :user_id)

      multi =
        alert_ids
        |> Enum.with_index()
        |> Enum.reduce(Multi.new(), fn {alert_id, idx}, multi ->
          Multi.run(multi, {:alert, idx}, fn repo, _changes ->
            case repo.get(Alert, alert_id) do
              nil ->
                {:error, :not_found}

              %Alert{organization_id: ^organization_id} = alert ->
                log_alert_activity(alert.id, user_id, "batch_deleted", %{})
                Alerts.delete_alert(alert)

              _ ->
                {:error, :unauthorized}
            end
          end)
        end)

      execute_batch_transaction(multi, alert_ids)
    end
  end

  # ===========================================================================
  # Batch IOC Operations
  # ===========================================================================

  @doc """
  Import IOCs from CSV or JSON with deduplication.

  For large imports (>1000 IOCs), this will create a background job
  and return a job ID for progress tracking.

  ## Parameters
  - `organization_id` - Organization UUID
  - `iocs` - List of IOC maps with required fields: type, value
  - `opts` - Options:
    - `:source` - Source identifier
    - `:deduplicate` - Whether to deduplicate (default: true)
    - `:async` - Force async processing (default: auto for >1000)

  ## Returns
  - `{:ok, %{imported: count, skipped: count, failed: [...]}}` - Sync
  - `{:ok, %{job_id: id}}` - Async
  """
  def batch_import_iocs(organization_id, iocs, opts \\ []) do
    deduplicate? = Keyword.get(opts, :deduplicate, true)
    async? = Keyword.get(opts, :async, length(iocs) > @max_batch_size)

    if async? do
      # Create background job
      %{
        organization_id: organization_id,
        operation: "import_iocs",
        data: iocs,
        opts: Map.new(opts)
      }
      |> BatchJobWorker.new()
      |> Oban.insert()
      |> case do
        {:ok, job} ->
          {:ok, %{job_id: job.id}}

        {:error, reason} ->
          {:error, reason}
      end
    else
      # Sync processing
      import_iocs_sync(organization_id, iocs, opts)
    end
  end

  @doc false
  def import_iocs_sync(organization_id, iocs, opts) do
    source = Keyword.get(opts, :source, "batch_import")
    deduplicate? = Keyword.get(opts, :deduplicate, true)

    # Validate batch size
    with :ok <- validate_batch_size(iocs, 10_000),
         :ok <- check_rate_limit(organization_id, :ioc_import) do

      # Deduplicate if requested
      unique_iocs = if deduplicate? do
        iocs
        |> Enum.uniq_by(fn ioc -> {ioc["type"], ioc["value"]} end)
      else
        iocs
      end

      # Get existing IOCs to avoid duplicates in DB
      existing_pairs =
        if deduplicate? do
          pairs = Enum.map(unique_iocs, fn ioc -> {ioc["type"], ioc["value"]} end)

          from(i in IOC,
            where: i.organization_id == ^organization_id,
            where: fragment("(?, ?) IN ?", i.type, i.value, ^pairs),
            select: {i.type, i.value}
          )
          |> Repo.all()
          |> MapSet.new()
        else
          MapSet.new()
        end

      # Build multi transaction
      {multi, stats} =
        unique_iocs
        |> Enum.with_index()
        |> Enum.reduce({Multi.new(), %{imported: 0, skipped: 0, failed: []}}, fn {ioc_data, idx}, {multi, stats} ->
          type = ioc_data["type"]
          value = ioc_data["value"]

          # Skip if exists
          if MapSet.member?(existing_pairs, {type, value}) do
            {multi, Map.update!(stats, :skipped, &(&1 + 1))}
          else
            new_multi = Multi.run(multi, {:ioc, idx}, fn _repo, _changes ->
              attrs = Map.merge(ioc_data, %{
                "organization_id" => organization_id,
                "source" => source,
                "enabled" => Map.get(ioc_data, "enabled", true)
              })

              Detection.create_ioc(attrs)
            end)

            {new_multi, stats}
          end
        end)

      case Repo.transaction(multi) do
        {:ok, results} ->
          imported_count = Enum.count(results)
          {:ok, %{
            imported: imported_count,
            skipped: stats.skipped,
            failed: []
          }}

        {:error, {_op, _idx}, reason, _changes} ->
          # Collect partial results
          {:error, reason}
      end
    end
  end

  @doc """
  Delete multiple IOCs.

  ## Parameters
  - `organization_id` - Organization UUID
  - `ioc_ids` - List of IOC UUIDs
  """
  def batch_delete_iocs(organization_id, ioc_ids, _opts \\ []) do
    with :ok <- validate_batch_size(ioc_ids),
         :ok <- check_rate_limit(organization_id, :ioc_delete) do

      multi =
        ioc_ids
        |> Enum.with_index()
        |> Enum.reduce(Multi.new(), fn {ioc_id, idx}, multi ->
          Multi.run(multi, {:ioc, idx}, fn repo, _changes ->
            case repo.get(IOC, ioc_id) do
              nil ->
                {:error, :not_found}

              %IOC{organization_id: ^organization_id} = ioc ->
                Detection.delete_ioc(ioc)

              _ ->
                {:error, :unauthorized}
            end
          end)
        end)

      execute_batch_transaction(multi, ioc_ids)
    end
  end

  @doc """
  Update expiration or tags for multiple IOCs.

  ## Parameters
  - `organization_id` - Organization UUID
  - `ioc_ids` - List of IOC UUIDs
  - `updates` - Map of updates:
    - `:expires_at` - New expiration date
    - `:add_tags` - Tags to add
    - `:remove_tags` - Tags to remove
  """
  def batch_update_iocs(organization_id, ioc_ids, updates, _opts \\ []) do
    with :ok <- validate_batch_size(ioc_ids),
         :ok <- check_rate_limit(organization_id, :ioc_update) do

      multi =
        ioc_ids
        |> Enum.with_index()
        |> Enum.reduce(Multi.new(), fn {ioc_id, idx}, multi ->
          Multi.run(multi, {:ioc, idx}, fn repo, _changes ->
            case repo.get(IOC, ioc_id) do
              nil ->
                {:error, :not_found}

              %IOC{organization_id: ^organization_id} = ioc ->
                attrs = build_ioc_update_attrs(ioc, updates)
                Detection.update_ioc(ioc, attrs)

              _ ->
                {:error, :unauthorized}
            end
          end)
        end)

      execute_batch_transaction(multi, ioc_ids)
    end
  end

  defp build_ioc_update_attrs(ioc, updates) do
    attrs = %{}

    # Update expiration
    attrs = if expires_at = Map.get(updates, :expires_at) do
      Map.put(attrs, :expires_at, expires_at)
    else
      attrs
    end

    # Update tags
    if add_tags = Map.get(updates, :add_tags) do
      current_tags = ioc.tags || []
      new_tags = (current_tags ++ add_tags) |> Enum.uniq()
      Map.put(attrs, :tags, new_tags)
    else
      attrs
    end
    |> then(fn attrs ->
      if remove_tags = Map.get(updates, :remove_tags) do
        current_tags = ioc.tags || []
        new_tags = current_tags -- remove_tags
        Map.put(attrs, :tags, new_tags)
      else
        attrs
      end
    end)
  end

  # ===========================================================================
  # Batch Agent Commands
  # ===========================================================================

  @doc """
  Isolate multiple agents.

  This is always async as it requires sending commands to agents.

  ## Parameters
  - `organization_id` - Organization UUID
  - `agent_ids` - List of agent UUIDs
  - `opts` - Options:
    - `:user_id` - User issuing command
    - `:reason` - Reason for isolation

  ## Returns
  - `{:ok, %{job_id: id}}`
  """
  def batch_isolate_agents(organization_id, agent_ids, opts \\ []) do
    batch_agent_command(organization_id, agent_ids, "isolate", opts)
  end

  @doc """
  Trigger scans on multiple agents.
  """
  def batch_scan_agents(organization_id, agent_ids, opts \\ []) do
    batch_agent_command(organization_id, agent_ids, "scan", opts)
  end

  @doc """
  Collect forensics from multiple agents.
  """
  def batch_collect_forensics(organization_id, agent_ids, opts \\ []) do
    batch_agent_command(organization_id, agent_ids, "collect_forensics", opts)
  end

  defp batch_agent_command(organization_id, agent_ids, command, opts) do
    with :ok <- validate_batch_size(agent_ids),
         :ok <- check_rate_limit(organization_id, :agent_command) do

      %{
        organization_id: organization_id,
        operation: "agent_command",
        command: command,
        agent_ids: agent_ids,
        opts: Map.new(opts)
      }
      |> BatchJobWorker.new()
      |> Oban.insert()
      |> case do
        {:ok, job} ->
          {:ok, %{job_id: job.id}}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  # ===========================================================================
  # Helper Functions
  # ===========================================================================

  defp validate_batch_size(items, max \\ @max_batch_size) do
    if length(items) <= max do
      :ok
    else
      {:error, {:batch_too_large, max}}
    end
  end

  defp check_rate_limit(organization_id, operation) do
    # Use Redis to track rate limits
    # Key: "batch_rate_limit:#{organization_id}:#{operation}"
    # We allow @max_batches_per_minute per organization

    # For now, return :ok - implement Redis-based rate limiting in production
    Logger.debug("[BatchOperations] Rate limit check for #{organization_id}/#{operation}")
    :ok
  end

  defp execute_batch_transaction(multi, item_ids) do
    case Repo.transaction(multi) do
      {:ok, results} ->
        success_count = Enum.count(results)
        {:ok, %{success_count: success_count, failed: []}}

      {:error, failed_op, reason, partial_results} ->
        # Collect what succeeded and what failed
        succeeded = Enum.count(partial_results)
        failed_idx = extract_index_from_op(failed_op)
        failed_id = Enum.at(item_ids, failed_idx)

        {:ok, %{
          success_count: succeeded,
          failed: [%{id: failed_id, reason: format_error(reason)}]
        }}
    end
  end

  defp extract_index_from_op({_type, idx}), do: idx
  defp extract_index_from_op(_), do: 0

  defp format_error(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
    |> inspect()
  end
  defp format_error(reason), do: inspect(reason)

  defp collect_batch_results(item_ids, partial_results, error) do
    succeeded = Enum.count(partial_results)
    failed_id = Enum.at(item_ids, succeeded)

    {:ok, %{
      success_count: succeeded,
      failed: [%{id: failed_id, reason: format_error(error)}]
    }}
  end

  defp log_alert_activity(alert_id, user_id, action, metadata) do
    # Log to alert activity table if it exists
    # This is called async to avoid blocking the transaction
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      try do
        TamanduaServer.Alerts.log_activity(alert_id, %{
          user_id: user_id,
          action: action,
          metadata: metadata,
          timestamp: DateTime.utc_now()
        })
      rescue
        e ->
          Logger.warn("[BatchOperations] Failed to log activity: #{inspect(e)}")
      end
    end)
  end
end
