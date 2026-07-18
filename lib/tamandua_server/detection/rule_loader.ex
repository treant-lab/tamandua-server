defmodule TamanduaServer.Detection.RuleLoader do
  @moduledoc """
  Atomic rule loading for the detection engine using double-buffering.

  This module addresses the race condition identified in the audit where
  rule reloads via `delete_all_objects` followed by inserts created a
  window where detection workers had no rules to match against.

  ## The Problem

  The original implementation:

      :ets.delete_all_objects(:detection_sigma_rules)
      for {id, rule} <- sigma_rules do
        :ets.insert(:detection_sigma_rules, {id, rule})
      end

  This created a race window where:
  1. Worker reads rules -> empty (delete happened)
  2. New rules being inserted
  3. Worker processes event with partial/no rules

  ## The Solution: Double-Buffering with Version Tracking

  We maintain two ETS tables per rule type (e.g., `:detection_sigma_rules_v0`
  and `:detection_sigma_rules_v1`). A version counter tracks which table is
  "active". During reload:

  1. Populate the inactive (backup) table
  2. Atomically swap the version counter
  3. All workers immediately see the new rules
  4. Old table becomes the next reload target

  Workers read from `get_active_table(:sigma)` which returns the current
  active table based on the version counter.

  ## Usage

      # On startup (in EngineSupervisor.init/1)
      RuleLoader.init_tables()

      # To reload rules atomically
      RuleLoader.reload_sigma_rules_atomic(rules)
      RuleLoader.reload_ioc_rules_atomic(iocs, authority_epoch)

      # Workers read from the active table
      RuleLoader.get_active_table(:sigma)  # => :detection_sigma_rules_v0 or _v1
  """

  require Logger

  alias TamanduaServer.Detection.IOCGenerationOwner

  # Version tracking table (single key-value for each rule type)
  @version_table :detection_rule_versions

  # Rule type configurations
  @rule_types %{
    sigma: %{
      base_name: :detection_sigma_rules,
      opts: [:set, :public, :named_table, {:read_concurrency, true}]
    },
    ioc: %{
      base_name: :detection_ioc_rules,
      opts: [:set, :public, :named_table, {:read_concurrency, true}]
    },
    yara: %{
      base_name: :detection_yara_rules,
      opts: [:set, :public, :named_table, {:read_concurrency, true}]
    }
  }

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Initialize all double-buffered ETS tables.

  Creates:
  - Version tracking table
  - Two tables per rule type (_v0 and _v1)
  - Sets initial version to 0 for all rule types

  Call this from EngineSupervisor.init/1 before starting workers.
  """
  @spec init_tables() :: :ok
  def init_tables do
    # Create version tracking table
    create_table_if_missing(@version_table, [:set, :public, :named_table])

    # Initialize each rule type with double-buffered tables
    for {rule_type, config} <- @rule_types, rule_type != :ioc do
      # Create both versioned tables
      create_table_if_missing(version_table_name(config.base_name, 0), config.opts)
      create_table_if_missing(version_table_name(config.base_name, 1), config.opts)

      # Initialize version to 0 if not set
      :ets.insert_new(@version_table, {rule_type, 0})
    end

    :ok = IOCGenerationOwner.ensure_started()

    if :ets.lookup(@version_table, :ioc) == [] do
      {:ok, table} = IOCGenerationOwner.create_generation()
      :ets.insert(@version_table, {:ioc, table, -1})
    end

    Logger.info("[RuleLoader] Double-buffered ETS tables initialized")
    :ok
  end

  @doc """
  Get the currently active table for a rule type.

  Workers should call this to get the table name for lookups.

  ## Examples

      active_table = RuleLoader.get_active_table(:sigma)
      :ets.tab2list(active_table)
  """
  @spec get_active_table(atom()) :: atom() | :ets.tid()
  def get_active_table(:ioc) do
    case :ets.lookup(@version_table, :ioc) do
      [{:ioc, table, _epoch, _digest, _provider}] -> table
      [{:ioc, table, _epoch}] -> table
      _ -> :unavailable
    end
  rescue
    ArgumentError -> :unavailable
  end

  def get_active_table(rule_type) do
    config = Map.fetch!(@rule_types, rule_type)
    version = get_current_version(rule_type)
    version_table_name(config.base_name, version)
  end

  @doc """
  Atomically reload Sigma rules using double-buffering.

  1. Populates the inactive table with new rules
  2. Atomically swaps the version counter
  3. Clears the old table (now inactive) for next reload

  Returns `{:ok, count}` with the number of rules loaded.
  """
  @spec reload_sigma_rules_atomic([{term(), term()}]) :: {:ok, non_neg_integer()}
  def reload_sigma_rules_atomic(rules) do
    reload_rules_atomic(:sigma, rules)
  end

  @doc """
  Publishes an IOC snapshot only when its durable database epoch is not older
  than the snapshot already visible on this node.
  """
  @spec reload_ioc_rules_atomic([{term(), term()}], non_neg_integer()) ::
          {:ok, non_neg_integer()} | {:stale, integer()} | {:error, term()}
  def reload_ioc_rules_atomic(iocs, authority_epoch)
      when is_integer(authority_epoch) and authority_epoch >= 0 do
    reload_ioc_rules_atomic(iocs, %{
      authority_epoch: authority_epoch,
      digest: ioc_rules_digest(iocs),
      provider: :legacy
    })
  end

  @spec reload_ioc_rules_atomic([{term(), term()}], map()) ::
          {:ok, non_neg_integer()} | {:stale, integer()} | {:error, term()}
  def reload_ioc_rules_atomic(iocs, %{
        authority_epoch: authority_epoch,
        digest: digest,
        provider: provider
      })
      when is_list(iocs) and is_integer(authority_epoch) and authority_epoch >= 0 and
             is_binary(digest) and byte_size(digest) == 64 and
             provider in [:legacy, :authority_v1] do
    with true <- String.match?(digest, ~r/\A[0-9a-f]{64}\z/),
         :ok <- IOCGenerationOwner.ensure_started(),
         {:ok, generation} <- IOCGenerationOwner.create_generation(),
         :ok <- populate_generation(generation, iocs) do
      publish_ioc_generation(generation, length(iocs), authority_epoch, digest, provider)
    else
      false -> {:error, :invalid_ioc_snapshot_metadata}
      error -> error
    end
  end

  def reload_ioc_rules_atomic(_iocs, _metadata), do: {:error, :invalid_ioc_snapshot_metadata}

  @doc false
  @spec ioc_rules_digest(list()) :: String.t()
  def ioc_rules_digest(iocs) when is_list(iocs) do
    :crypto.hash(:sha256, ["tamandua.ioc-runtime-rules.v1", :erlang.term_to_binary(iocs)])
    |> Base.encode16(case: :lower)
  end

  @spec published_ioc_epoch() :: integer()
  def published_ioc_epoch do
    case :ets.lookup(@version_table, :ioc) do
      [{:ioc, _version, epoch, _digest, _provider}] -> epoch
      [{:ioc, _version, epoch}] -> epoch
      [{:ioc, _version}] -> -1
      [] -> -1
    end
  rescue
    ArgumentError -> -1
  end

  @spec published_ioc_snapshot() :: map()
  def published_ioc_snapshot do
    case :ets.lookup(@version_table, :ioc) do
      [{:ioc, table, epoch, digest, provider}] ->
        %{table: table, authority_epoch: epoch, digest: digest, provider: provider}

      [{:ioc, table, epoch}] ->
        %{table: table, authority_epoch: epoch, digest: nil, provider: :legacy}

      _ ->
        %{table: :unavailable, authority_epoch: -1, digest: nil, provider: nil}
    end
  rescue
    ArgumentError -> %{table: :unavailable, authority_epoch: -1, digest: nil, provider: nil}
  end

  @doc """
  Atomically reload YARA rules using double-buffering.
  """
  @spec reload_yara_rules_atomic([{term(), term()}]) :: {:ok, non_neg_integer()}
  def reload_yara_rules_atomic(rules) do
    reload_rules_atomic(:yara, rules)
  end

  @doc """
  Get statistics about rule loading.

  Returns a map with:
  - Version numbers for each rule type
  - Rule counts per table
  - Last reload timestamps (if tracked)
  """
  @spec stats() :: map()
  def stats do
    for {rule_type, config} <- @rule_types, into: %{} do
      if rule_type == :ioc do
        active_table = get_active_table(:ioc)

        {rule_type,
         %{
           authority_epoch: published_ioc_epoch(),
           digest: published_ioc_snapshot().digest,
           provider: published_ioc_snapshot().provider,
           active_table: active_table,
           active_count: safe_table_size(active_table),
           immutable_generation: true
         }}
      else
        version = get_current_version(rule_type)
        active_table = version_table_name(config.base_name, version)
        inactive_table = version_table_name(config.base_name, 1 - version)

        {rule_type,
         %{
           active_version: version,
           active_table: active_table,
           active_count: safe_table_size(active_table),
           inactive_table: inactive_table,
           inactive_count: safe_table_size(inactive_table)
         }}
      end
    end
  end

  @doc """
  Read all rules from the active table for a rule type.

  Returns a list of `{id, rule}` tuples.
  """
  @spec read_all(atom()) :: [{term(), term()}]
  def read_all(rule_type) do
    if rule_type == :ioc do
      with_ioc_snapshot(&:ets.tab2list/1)
    else
      table = get_active_table(rule_type)
      :ets.tab2list(table)
    end
  rescue
    ArgumentError -> []
  end

  @doc "Runs a read while pinning the currently published immutable IOC generation."
  @spec with_ioc_snapshot((:ets.tid() -> result)) :: result | [] when result: term()
  def with_ioc_snapshot(fun) when is_function(fun, 1) do
    case pin_ioc_generation() do
      {:ok, table} ->
        try do
          fun.(table)
        after
          release_ioc_generation(table)
        end

      {:error, _reason} ->
        []
    end
  end

  # ============================================================================
  # Legacy Compatibility API
  # ============================================================================

  @doc """
  Get Sigma rules (legacy compatibility).

  Maps to reading from the active Sigma table.
  """
  @spec get_sigma_rules() :: [map()]
  def get_sigma_rules do
    :sigma
    |> read_all()
    |> Enum.map(fn {_id, rule} -> rule end)
  end

  @doc """
  Get IOC rules (legacy compatibility).
  """
  @spec get_iocs() :: [map()]
  def get_iocs do
    :ioc
    |> read_all()
    |> Enum.map(fn {_id, ioc} -> ioc end)
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp reload_rules_atomic(rule_type, rules) do
    lock_id = {{__MODULE__, rule_type}, self()}

    case :global.trans(lock_id, fn -> do_reload_rules_atomic(rule_type, rules) end, [node()]) do
      {:aborted, reason} -> {:error, {:reload_lock_aborted, reason}}
      result -> result
    end
  rescue
    e ->
      Logger.error("[RuleLoader] Failed to reload #{rule_type} rules: #{Exception.message(e)}")
      {:error, e}
  end

  defp do_reload_rules_atomic(rule_type, rules) do
    config = Map.fetch!(@rule_types, rule_type)
    current_version = get_current_version(rule_type)
    next_version = 1 - current_version

    # Get the inactive table (will become active)
    inactive_table = version_table_name(config.base_name, next_version)

    # Clear and populate the inactive table
    :ets.delete_all_objects(inactive_table)

    count =
      Enum.reduce(rules, 0, fn {id, rule}, acc ->
        :ets.insert(inactive_table, {id, rule})
        acc + 1
      end)

    # Atomic version swap - all workers immediately see the new table
    :ets.insert(@version_table, {rule_type, next_version})

    # Keep the old snapshot intact until the next reload clears it as the
    # inactive table. A delayed cleanup can race a second reload and erase the
    # table that has become active again.

    Logger.info(
      "[RuleLoader] Atomically reloaded #{count} #{rule_type} rules " <>
        "(v#{current_version} -> v#{next_version})"
    )

    {:ok, count}
  rescue
    e ->
      Logger.error("[RuleLoader] Failed to reload #{rule_type} rules: #{Exception.message(e)}")
      {:error, e}
  end

  defp populate_generation(table, rules) do
    Enum.each(rules, fn {id, rule} -> :ets.insert(table, {id, rule}) end)
    :ok
  rescue
    error ->
      IOCGenerationOwner.retire_generation(table)
      {:error, error}
  end

  defp publish_ioc_generation(generation, count, authority_epoch, digest, provider) do
    result =
      with_ioc_lock(fn ->
        published = published_ioc_snapshot()

        cond do
          :ets.info(generation) == :undefined ->
            {:publication_error, :generation_owner_restarted, nil}

          authority_epoch < published.authority_epoch ->
            {:stale, published.authority_epoch, generation}

          authority_epoch == published.authority_epoch and
            not is_nil(published.digest) and
              (digest != published.digest or provider != published.provider) ->
            {:publication_error, :ioc_snapshot_metadata_conflict, generation}

          # A three-field tuple was published by code that did not bind a
          # digest. At an equal epoch there is no trustworthy way to prove an
          # exact replay, even when both sides say `legacy`; require a newer
          # durable epoch instead of silently replacing it.
          authority_epoch == published.authority_epoch and is_nil(published.digest) ->
            {:publication_error, :ioc_snapshot_metadata_conflict, generation}

          true ->
            previous = get_active_table(:ioc)
            :ets.insert(@version_table, {:ioc, generation, authority_epoch, digest, provider})
            {:published, count, previous}
        end
      end)

    case result do
      {:published, ^count, retire_now} ->
        retire_outside_lock(retire_now)

        Logger.info(
          "[RuleLoader] Published #{count} immutable IOC rules at authority epoch #{authority_epoch} via #{provider}"
        )

        {:ok, count}

      {:stale, published, retire_now} ->
        retire_outside_lock(retire_now)
        {:stale, published}

      {:publication_error, reason, retire_now} ->
        retire_outside_lock(retire_now)
        {:error, reason}

      {:error, _reason} = error ->
        retire_outside_lock(generation)
        error
    end
  rescue
    error ->
      IOCGenerationOwner.retire_generation(generation)
      {:error, error}
  end

  defp pin_ioc_generation do
    with_ioc_lock(fn ->
      table = get_active_table(:ioc)

      if is_reference(table) and :ets.info(table) != :undefined do
        case IOCGenerationOwner.pin_generation(table) do
          :ok -> {:ok, table}
          {:error, reason} -> {:error, reason}
        end
      else
        {:error, :ioc_generation_unavailable}
      end
    end)
  end

  defp release_ioc_generation(table) do
    IOCGenerationOwner.release_generation(table)
  end

  defp retire_outside_lock(table) when is_reference(table),
    do: IOCGenerationOwner.retire_generation(table)

  defp retire_outside_lock(_table), do: :ok

  defp with_ioc_lock(fun) do
    lock_id = {{__MODULE__, :ioc}, self()}

    case :global.trans(lock_id, fun, [node()]) do
      {:aborted, reason} -> {:error, {:reload_lock_aborted, reason}}
      result -> result
    end
  end

  defp get_current_version(rule_type) do
    case :ets.lookup(@version_table, rule_type) do
      [{^rule_type, version, _epoch, _digest, _provider}] -> version
      [{^rule_type, version, _epoch}] -> version
      [{^rule_type, version}] -> version
      [] -> 0
    end
  rescue
    ArgumentError -> 0
  end

  defp version_table_name(base_name, version) do
    String.to_atom("#{base_name}_v#{version}")
  end

  defp create_table_if_missing(name, opts) do
    case :ets.whereis(name) do
      :undefined ->
        :ets.new(name, opts)

      _ref ->
        # Table already exists
        :ok
    end
  rescue
    ArgumentError ->
      # Table already exists
      :ok
  end

  defp safe_table_size(table) do
    :ets.info(table, :size) || 0
  rescue
    ArgumentError -> 0
  end
end
