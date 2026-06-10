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
      RuleLoader.reload_ioc_rules_atomic(iocs)

      # Workers read from the active table
      RuleLoader.get_active_table(:sigma)  # => :detection_sigma_rules_v0 or _v1
  """

  require Logger

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
    for {rule_type, config} <- @rule_types do
      # Create both versioned tables
      create_table_if_missing(version_table_name(config.base_name, 0), config.opts)
      create_table_if_missing(version_table_name(config.base_name, 1), config.opts)

      # Initialize version to 0 if not set
      :ets.insert_new(@version_table, {rule_type, 0})
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
  @spec get_active_table(atom()) :: atom()
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
  Atomically reload IOC rules using double-buffering.
  """
  @spec reload_ioc_rules_atomic([{term(), term()}]) :: {:ok, non_neg_integer()}
  def reload_ioc_rules_atomic(iocs) do
    reload_rules_atomic(:ioc, iocs)
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
      version = get_current_version(rule_type)
      active_table = version_table_name(config.base_name, version)
      inactive_table = version_table_name(config.base_name, 1 - version)

      {rule_type, %{
        active_version: version,
        active_table: active_table,
        active_count: safe_table_size(active_table),
        inactive_table: inactive_table,
        inactive_count: safe_table_size(inactive_table)
      }}
    end
  end

  @doc """
  Read all rules from the active table for a rule type.

  Returns a list of `{id, rule}` tuples.
  """
  @spec read_all(atom()) :: [{term(), term()}]
  def read_all(rule_type) do
    table = get_active_table(rule_type)
    :ets.tab2list(table)
  rescue
    ArgumentError -> []
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

    # Clear the now-inactive (old active) table to free memory
    # This is safe because no workers will read from it after the version swap
    old_table = version_table_name(config.base_name, current_version)
    spawn(fn ->
      # Small delay to ensure any in-flight reads complete
      Process.sleep(100)
      :ets.delete_all_objects(old_table)
    end)

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

  defp get_current_version(rule_type) do
    case :ets.lookup(@version_table, rule_type) do
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
