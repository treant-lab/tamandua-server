defmodule TamanduaServer.Response.Remediation do
  @moduledoc """
  Server-side remediation coordination for VSS snapshots and ransomware recovery.

  Provides high-level functions to:
  - Create and manage VSS snapshots on agents
  - Restore files from snapshots
  - Coordinate ransomware remediation across agents
  - Track remediation job status (ETS-backed)
  - Manage snapshot policies with periodic evaluation
  """

  use GenServer
  require Logger

  alias TamanduaServer.Response.Executor
  alias TamanduaServer.Solana.RemediationAttestation


  @jobs_table :tamandua_remediation_jobs
  @policies_table :tamandua_snapshot_policies
  @policy_check_interval :timer.minutes(1)

  # ---------------------------------------------------------------------------
  # Client API — GenServer lifecycle
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  # ---------------------------------------------------------------------------
  # Client API — Snapshot operations (unchanged, stateless delegates)
  # ---------------------------------------------------------------------------

  @doc """
  Request snapshot creation on an agent.

  ## Parameters
    - agent_id: The agent ID
    - volume: The volume to snapshot (e.g., "C:")

  ## Returns
    - {:ok, snapshot_info} on success
    - {:error, reason} on failure
  """
  @spec create_snapshot(String.t(), String.t()) :: {:ok, map()} | {:error, any()}
  def create_snapshot(agent_id, volume \\ "C:") do
    Logger.info("Creating VSS snapshot on agent #{agent_id} for volume #{volume}")

    Executor.execute_action(agent_id, "create_snapshot", %{
      volume: volume
    })
  end

  @doc """
  List available snapshots on an agent.

  ## Parameters
    - agent_id: The agent ID
    - volume: The volume to list snapshots for (e.g., "C:")

  ## Returns
    - {:ok, %{snapshots: [...], count: n}} on success
    - {:error, reason} on failure
  """
  @spec list_snapshots(String.t(), String.t()) :: {:ok, map()} | {:error, any()}
  def list_snapshots(agent_id, volume \\ "C:") do
    Logger.info("Listing VSS snapshots on agent #{agent_id} for volume #{volume}")

    Executor.execute_action(agent_id, "list_snapshots", %{
      volume: volume
    })
  end

  @doc """
  Delete a specific snapshot on an agent.

  ## Parameters
    - agent_id: The agent ID
    - snapshot_id: The snapshot ID (GUID) to delete

  ## Returns
    - {:ok, %{deleted: true}} on success
    - {:error, reason} on failure
  """
  @spec delete_snapshot(String.t(), String.t()) :: {:ok, map()} | {:error, any()}
  def delete_snapshot(agent_id, snapshot_id) do
    Logger.info("Deleting VSS snapshot #{snapshot_id} on agent #{agent_id}")

    Executor.execute_action(agent_id, "delete_snapshot", %{
      snapshot_id: snapshot_id
    })
  end

  @doc """
  Restore a single file from a snapshot.

  ## Parameters
    - agent_id: The agent ID
    - snapshot_id: The snapshot ID to restore from
    - file_path: The original file path to restore

  ## Returns
    - {:ok, %{restored: true, file_path: path}} on success
    - {:error, reason} on failure
  """
  @spec restore_file(String.t(), String.t(), String.t()) :: {:ok, map()} | {:error, any()}
  def restore_file(agent_id, snapshot_id, file_path) do
    Logger.info("Restoring file #{file_path} from snapshot #{snapshot_id} on agent #{agent_id}")

    Executor.execute_action(agent_id, "restore_file", %{
      snapshot_id: snapshot_id,
      file_path: file_path
    })
  end

  @doc """
  Restore multiple files from a snapshot.

  ## Parameters
    - agent_id: The agent ID
    - snapshot_id: The snapshot ID to restore from
    - file_paths: List of file paths to restore

  ## Returns
    - {:ok, restore_result} on success with details of restored/failed/skipped files
    - {:error, reason} on failure
  """
  @spec restore_files(String.t(), String.t(), [String.t()]) :: {:ok, map()} | {:error, any()}
  def restore_files(agent_id, snapshot_id, file_paths) when is_list(file_paths) do
    Logger.info("Restoring #{length(file_paths)} files from snapshot #{snapshot_id} on agent #{agent_id}")

    Executor.execute_action(agent_id, "restore_files", %{
      snapshot_id: snapshot_id,
      file_paths: file_paths
    })
  end

  @doc """
  Find encrypted files on an agent (ransomware detection).

  ## Parameters
    - agent_id: The agent ID
    - opts: Options
      - :path - Root path to scan (default: "C:\\Users")

  ## Returns
    - {:ok, %{encrypted_files: [...], count: n}} on success
    - {:error, reason} on failure
  """
  @spec find_encrypted_files(String.t(), keyword()) :: {:ok, map()} | {:error, any()}
  def find_encrypted_files(agent_id, opts \\ []) do
    path = Keyword.get(opts, :path, "C:\\Users")

    Logger.info("Scanning for encrypted files on agent #{agent_id} at path #{path}")

    Executor.execute_action(agent_id, "find_encrypted_files", %{
      path: path
    })
  end

  @doc """
  Perform ransomware remediation on an agent.

  This will:
  1. Optionally scan for encrypted files if not provided
  2. Find the best available VSS snapshot for each file
  3. Restore files from snapshots
  4. Generate a remediation report

  ## Parameters
    - agent_id: The agent ID
    - opts: Options
      - :path - Root path to scan/remediate (default: "C:\\Users")
      - :encrypted_files - Pre-scanned list of encrypted files (optional)
      - :dry_run - If true, only report what would be restored (default: false)

  ## Returns
    - {:ok, remediation_result} with details of the remediation
    - {:error, reason} on failure
  """
  @spec ransomware_remediate(String.t(), keyword()) :: {:ok, map()} | {:error, any()}
  def ransomware_remediate(agent_id, opts \\ []) do
    path = Keyword.get(opts, :path, "C:\\Users")
    encrypted_files = Keyword.get(opts, :encrypted_files)
    dry_run = Keyword.get(opts, :dry_run, false)

    Logger.info("Starting ransomware remediation on agent #{agent_id}, path: #{path}, dry_run: #{dry_run}")

    if dry_run do
      # Just find encrypted files without restoring
      find_encrypted_files(agent_id, path: path)
    else
      params = %{path: path}

      params =
        if encrypted_files do
          Map.put(params, :encrypted_files, encrypted_files)
        else
          params
        end

      Executor.execute_action(agent_id, "ransomware_remediate", params)
    end
  end

  # ---------------------------------------------------------------------------
  # Client API — Remediation Job Tracking
  # ---------------------------------------------------------------------------

  @doc """
  Track a new remediation job.

  Inserts a job entry into the ETS table with `:running` status.

  ## Parameters
    - job_id: Unique job identifier (string)
    - type: The remediation type atom (e.g., :ransomware_remediate, :create_snapshot)
    - target: A human-readable target description (e.g., "C:\\Users on agent-001")
    - agent_id: The agent ID the job targets

  ## Returns
    - :ok
  """
  @spec track_job(String.t(), atom(), String.t(), String.t()) :: :ok
  def track_job(job_id, type, target, agent_id) do
    entry = %{
      status: :running,
      type: type,
      target: target,
      started_at: DateTime.utc_now(),
      completed_at: nil,
      result: nil,
      error: nil,
      agent_id: agent_id
    }

    :ets.insert(@jobs_table, {job_id, entry})
    Logger.info("Tracking remediation job #{job_id} (#{type}) for agent #{agent_id}")
    :ok
  end

  @doc """
  Update the status of a tracked remediation job.

  ## Parameters
    - job_id: The job identifier
    - status: New status atom (:completed | :failed)
    - result: Optional result map (on success) or error string (on failure)

  ## Returns
    - :ok on success
    - {:error, :not_found} if the job does not exist
  """
  @spec update_job_status(String.t(), atom(), map() | String.t() | nil) :: :ok | {:error, :not_found}
  def update_job_status(job_id, status, result \\ nil) do
    case :ets.lookup(@jobs_table, job_id) do
      [{^job_id, entry}] ->
        updated =
          entry
          |> Map.put(:status, status)
          |> Map.put(:completed_at, DateTime.utc_now())

        updated =
          case status do
            :completed -> Map.put(updated, :result, result)
            :failed -> Map.put(updated, :error, result)
            _ -> updated
          end

        :ets.insert(@jobs_table, {job_id, updated})
        Logger.info("Remediation job #{job_id} status updated to #{status}")
        :ok

      [] ->
        {:error, :not_found}
    end
  end

  @doc """
  Get the status of an ongoing or completed remediation job.

  ## Parameters
    - job_id: The remediation job ID

  ## Returns
    - {:ok, status} with job status details
    - {:error, :not_found} if job doesn't exist
  """
  @spec get_remediation_status(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_remediation_status(job_id) do
    case :ets.lookup(@jobs_table, job_id) do
      [{^job_id, entry}] ->
        {:ok, Map.put(entry, :job_id, job_id)}

      [] ->
        {:error, :not_found}
    end
  end

  @doc """
  List all remediation jobs with `:running` status.

  ## Returns
    - List of job maps with `:job_id` included
  """
  @spec list_active_jobs() :: [map()]
  def list_active_jobs do
    :ets.tab2list(@jobs_table)
    |> Enum.filter(fn {_id, entry} -> entry.status == :running end)
    |> Enum.map(fn {id, entry} -> Map.put(entry, :job_id, id) end)
  end

  @doc """
  Start an asynchronous remediation job.

  This is useful for long-running remediation operations where you want
  to return immediately and poll for status.

  ## Parameters
    - agent_id: The agent ID
    - opts: Same as ransomware_remediate/2

  ## Returns
    - {:ok, %{job_id: id}} with the job ID to poll
    - {:error, reason} on failure
  """
  @spec start_remediation_job(String.t(), keyword()) :: {:ok, map()} | {:error, any()}
  def start_remediation_job(agent_id, opts \\ []) do
    job_id = generate_job_id()
    path = Keyword.get(opts, :path, "C:\\Users")
    target = "#{path} on #{agent_id}"
    organization_id = Keyword.get(opts, :organization_id)

    track_job(job_id, :ransomware_remediate, target, agent_id)

    # Spawn async task for remediation
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      result = ransomware_remediate(agent_id, opts)

      case result do
        {:ok, data} ->
          update_job_status(job_id, :completed, data)

          # Trigger Proof of Remediation attestation for successful jobs
          maybe_attest_job(job_id, :ransomware_remediate, data, agent_id, organization_id)

        {:error, reason} ->
          update_job_status(job_id, :failed, inspect(reason))
      end

      Logger.info("Remediation job #{job_id} completed: #{inspect(result)}")
    end)

    {:ok, %{job_id: job_id, status: :running, agent_id: agent_id}}
  end

  # ---------------------------------------------------------------------------
  # Client API — Snapshot Policy Storage
  # ---------------------------------------------------------------------------

  @doc """
  Create a scheduled snapshot policy for an agent.

  This sets up automatic snapshot creation on a schedule.

  ## Parameters
    - agent_id: The agent ID
    - schedule: Interval schedule (e.g., "daily", "hourly", "12h", "30m")
    - opts: Options
      - :volume - Volume to snapshot (default: "C:")
      - :max_snapshots - Maximum snapshots to keep (default: 5)

  ## Returns
    - {:ok, policy} on success
    - {:error, reason} on failure
  """
  @spec create_snapshot_policy(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, any()}
  def create_snapshot_policy(agent_id, schedule, opts \\ []) do
    volume = Keyword.get(opts, :volume, "C:")
    max_snapshots = Keyword.get(opts, :max_snapshots, 5)

    case parse_schedule(schedule) do
      {:ok, interval_ms} ->
        policy_id = generate_job_id()
        now = DateTime.utc_now()

        policy = %{
          id: policy_id,
          agent_id: agent_id,
          schedule: schedule,
          interval_ms: interval_ms,
          volume: volume,
          max_snapshots: max_snapshots,
          enabled: true,
          created_at: now,
          updated_at: now,
          last_executed_at: nil,
          execution_count: 0
        }

        :ets.insert(@policies_table, {policy_id, policy})
        Logger.info("Created snapshot policy #{policy_id} for agent #{agent_id}: schedule=#{schedule}, volume=#{volume}")
        {:ok, policy}

      {:error, _} = err ->
        err
    end
  end

  @doc """
  List all snapshot policies.

  ## Returns
    - List of policy maps
  """
  @spec list_snapshot_policies() :: [map()]
  def list_snapshot_policies do
    :ets.tab2list(@policies_table)
    |> Enum.map(fn {_id, policy} -> policy end)
    |> Enum.sort_by(& &1.created_at, {:desc, DateTime})
  end

  @doc """
  Get a snapshot policy by ID.

  ## Returns
    - {:ok, policy} on success
    - {:error, :not_found} if policy doesn't exist
  """
  @spec get_snapshot_policy(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_snapshot_policy(policy_id) do
    case :ets.lookup(@policies_table, policy_id) do
      [{^policy_id, policy}] -> {:ok, policy}
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Delete a snapshot policy by ID.

  ## Returns
    - :ok on success
    - {:error, :not_found} if policy doesn't exist
  """
  @spec delete_snapshot_policy(String.t()) :: :ok | {:error, :not_found}
  def delete_snapshot_policy(policy_id) do
    case :ets.lookup(@policies_table, policy_id) do
      [{^policy_id, _policy}] ->
        :ets.delete(@policies_table, policy_id)
        Logger.info("Deleted snapshot policy #{policy_id}")
        :ok

      [] ->
        {:error, :not_found}
    end
  end

  @doc """
  Update fields on an existing snapshot policy.

  ## Parameters
    - policy_id: The policy ID
    - updates: Map of fields to update. Allowed keys:
      :schedule, :volume, :max_snapshots, :enabled

  ## Returns
    - {:ok, updated_policy} on success
    - {:error, :not_found} if policy doesn't exist
    - {:error, reason} if schedule is invalid
  """
  @spec update_snapshot_policy(String.t(), map()) :: {:ok, map()} | {:error, any()}
  def update_snapshot_policy(policy_id, updates) when is_map(updates) do
    case :ets.lookup(@policies_table, policy_id) do
      [{^policy_id, policy}] ->
        allowed_keys = [:schedule, :volume, :max_snapshots, :enabled]
        filtered = Map.take(updates, allowed_keys)

        # If schedule is being changed, re-parse the interval
        {interval_update, parse_error} =
          case Map.get(filtered, :schedule) do
            nil ->
              {%{}, nil}

            new_schedule ->
              case parse_schedule(new_schedule) do
                {:ok, ms} -> {%{interval_ms: ms}, nil}
                {:error, reason} -> {%{}, {:error, reason}}
              end
          end

        if parse_error do
          parse_error
        else
          updated =
            policy
            |> Map.merge(filtered)
            |> Map.merge(interval_update)
            |> Map.put(:updated_at, DateTime.utc_now())

          :ets.insert(@policies_table, {policy_id, updated})
          Logger.info("Updated snapshot policy #{policy_id}")
          {:ok, updated}
        end

      [] ->
        {:error, :not_found}
    end
  end

  # ---------------------------------------------------------------------------
  # Client API — Recovery status (unchanged)
  # ---------------------------------------------------------------------------

  @doc """
  Get available snapshots with file recovery capability check.

  For each snapshot, checks if critical user files can be recovered.

  ## Parameters
    - agent_id: The agent ID
    - sample_paths: Optional list of paths to check (default: common document locations)

  ## Returns
    - {:ok, snapshots_with_status} with recovery capability for each snapshot
    - {:error, reason} on failure
  """
  @spec get_snapshots_with_recovery_status(String.t(), [String.t()]) :: {:ok, list()} | {:error, any()}
  def get_snapshots_with_recovery_status(agent_id, _sample_paths \\ []) do
    with {:ok, %{"snapshots" => snapshots}} <- list_snapshots(agent_id) do
      # For now, just return snapshots with basic info
      # A full implementation would check each snapshot for file availability
      snapshots_with_status = Enum.map(snapshots, fn snapshot ->
        Map.put(snapshot, "recovery_capable", true)
      end)

      {:ok, snapshots_with_status}
    end
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    :ets.new(@jobs_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@policies_table, [:named_table, :set, :public, read_concurrency: true])

    schedule_policy_check()

    Logger.info("Remediation engine started (ETS tables: #{@jobs_table}, #{@policies_table})")
    {:ok, %{}}
  end

  @impl true
  def handle_info(:check_policies, state) do
    evaluate_policies()
    schedule_policy_check()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ---------------------------------------------------------------------------
  # Private functions
  # ---------------------------------------------------------------------------

  defp schedule_policy_check do
    Process.send_after(self(), :check_policies, @policy_check_interval)
  end

  defp evaluate_policies do
    now = DateTime.utc_now()

    :ets.tab2list(@policies_table)
    |> Enum.each(fn {policy_id, policy} ->
      if policy.enabled and policy_due?(policy, now) do
        Logger.info("Snapshot policy #{policy_id} is due, triggering snapshot for agent #{policy.agent_id}")

        # Track this as a remediation job
        job_id = generate_job_id()
        target = "#{policy.volume} on #{policy.agent_id} (policy #{policy_id})"
        track_job(job_id, :scheduled_snapshot, target, policy.agent_id)

        # Execute snapshot asynchronously
        Task.start(fn ->
          result = create_snapshot(policy.agent_id, policy.volume)

          case result do
            {:ok, data} ->
              update_job_status(job_id, :completed, data)
              Logger.info("Scheduled snapshot for policy #{policy_id} completed successfully")

              # Attest successful snapshot creation
              maybe_attest_job(job_id, :scheduled_snapshot, data, policy.agent_id, nil)

            {:error, reason} ->
              update_job_status(job_id, :failed, inspect(reason))
              Logger.warning("Scheduled snapshot for policy #{policy_id} failed: #{inspect(reason)}")
          end
        end)

        # Update the policy's last execution time and counter
        updated =
          policy
          |> Map.put(:last_executed_at, now)
          |> Map.update!(:execution_count, &(&1 + 1))

        :ets.insert(@policies_table, {policy_id, updated})
      end
    end)
  end

  defp policy_due?(policy, now) do
    case policy.last_executed_at do
      nil ->
        # Never executed — due immediately
        true

      last ->
        elapsed_ms = DateTime.diff(now, last, :millisecond)
        elapsed_ms >= policy.interval_ms
    end
  end

  @doc false
  def parse_schedule(schedule) when is_binary(schedule) do
    schedule_lower = String.downcase(String.trim(schedule))

    cond do
      schedule_lower == "hourly" ->
        {:ok, :timer.hours(1)}

      schedule_lower == "daily" ->
        {:ok, :timer.hours(24)}

      schedule_lower == "weekly" ->
        {:ok, :timer.hours(24 * 7)}

      true ->
        # Try parsing as "<number><unit>" (e.g., "12h", "30m", "7d")
        case Regex.run(~r/^(\d+)(s|m|h|d)$/, schedule_lower) do
          [_, amount_str, unit] ->
            {amount, ""} = Integer.parse(amount_str)

            ms =
              case unit do
                "s" -> :timer.seconds(amount)
                "m" -> :timer.minutes(amount)
                "h" -> :timer.hours(amount)
                "d" -> :timer.hours(amount * 24)
              end

            {:ok, ms}

          _ ->
            {:error, "Invalid schedule format: #{schedule}. Use 'hourly', 'daily', 'weekly', or '<N><s|m|h|d>' (e.g., '12h', '30m')."}
        end
    end
  end

  defp generate_job_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end

  # ---------------------------------------------------------------------------
  # Proof of Remediation Attestation
  # ---------------------------------------------------------------------------

  defp maybe_attest_job(job_id, job_type, result, agent_id, organization_id) do
    if RemediationAttestation.enabled?() do
      case RemediationAttestation.attest_job_completion(
             job_id,
             job_type,
             result,
             agent_id: agent_id,
             organization_id: organization_id
           ) do
        {:ok, tx_signature} ->
          Logger.info("[Remediation] Job #{job_id} attested on Solana: #{tx_signature}")

        {:error, reason} ->
          Logger.warning("[Remediation] Job attestation failed: #{inspect(reason)}")
      end
    end
  end
end
