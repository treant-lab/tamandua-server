defmodule TamanduaServer.ThreatIntel.SigmaSync do
  @moduledoc """
  Enhanced SigmaHQ rule sync using local git clone.

  This module provides a comprehensive approach to syncing SigmaHQ community
  rules by cloning the entire repository locally. This complements the
  API-based `TamanduaServer.Detection.Rules.SigmaHQSync` module.

  ## Why Two Approaches?

  | Feature                    | API-based (SigmaHQSync) | Git Clone (SigmaSync) |
  |---------------------------|-------------------------|----------------------|
  | Setup complexity          | None (just HTTP)        | Requires git         |
  | Rate limiting             | GitHub API limits       | No limits            |
  | Full rule access          | One folder at a time    | All rules at once    |
  | Offline capability        | No                      | Yes (after clone)    |
  | Storage requirement       | Minimal                 | ~500MB repo          |
  | Update speed              | Slower (many requests)  | Fast (git pull)      |

  ## What This Module Provides

  Downloads and indexes community Sigma rules for:
  - Windows process creation (~800 rules)
  - File events (~200 rules)
  - Network connections (~100 rules)
  - Registry modifications (~150 rules)
  - Linux process creation (~100 rules)
  - Linux file/network events (~100 rules)
  - macOS events (~50 rules)

  Filters for EDR relevance:
  - credential access, defense evasion, execution
  - persistence, lateral movement, initial access
  - privilege escalation, command-and-control

  ## Architecture

  The sync process works as follows:

  1. **Clone/Pull** - Clone or update the SigmaHQ repository to `priv/sigmahq/`
  2. **Parse** - Walk the rule directories and parse YAML files
  3. **Filter** - Apply status, level, and category filters
  4. **Index** - Index rules by MITRE technique for fast lookup
  5. **Store** - Store parsed rules in ETS for runtime matching

  ## Rule Categories Synced

  | Category                        | Priority | Est. Rules |
  |--------------------------------|----------|------------|
  | `rules/windows/process_creation/` | High     | ~800       |
  | `rules/windows/file_event/`       | High     | ~200       |
  | `rules/windows/registry_event/`   | Medium   | ~150       |
  | `rules/linux/process_creation/`   | High     | ~100       |
  | `rules/linux/file_event/`         | Medium   | ~50        |
  | `rules/network/`                  | Medium   | ~100       |
  | `rules/macos/process_creation/`   | Medium   | ~50        |

  Total estimated: ~1,500 rules (filtered from ~3,000+ in repo)

  ## Usage

      # Initial sync (clones repo if not exists)
      SigmaSync.sync()

      # Force full resync
      SigmaSync.sync(force: true)

      # Get rules by MITRE technique
      SigmaSync.get_rules_by_technique("T1003.001")

      # Get rules matching event type
      SigmaSync.get_rules_for_event_type(:process_create)

      # Query sync status
      SigmaSync.status()

      # Import synced rules to database
      SigmaSync.import_rules_to_db(organization_id)

  ## Configuration

  Configure in `config/config.exs`:

      config :tamandua_server, TamanduaServer.ThreatIntel.SigmaSync,
        repo_url: "https://github.com/SigmaHQ/sigma.git",
        repo_path: "priv/sigmahq",
        sync_interval_hours: 24,
        min_level: "medium",
        allowed_statuses: ["stable", "test"]

  ## Integration with Detection Engine

  After sync, rules are available for:
  1. Direct query via `get_rules_by_technique/1` or `get_rules_for_event_type/1`
  2. Database import for UI management via `import_rules_to_db/2`
  3. MITRE coverage analysis via `get_technique_coverage/0`
  """

  use GenServer
  require Logger

  alias TamanduaServer.OSCommand
  alias TamanduaServer.Detection.{SigmaRule}
  alias TamanduaServer.Repo

  import Ecto.Query

  # ── Configuration ──────────────────────────────────────────────────────────

  @sigmahq_repo_url "https://github.com/SigmaHQ/sigma.git"
  @default_repo_path "priv/sigmahq"

  # Rule categories to sync with priorities
  @rule_categories [
    # High priority - most commonly used
    {"rules/windows/process_creation", :high},
    {"rules/windows/file_event", :high},
    {"rules/linux/process_creation", :high},

    # Medium priority - useful but less frequent
    {"rules/windows/registry_event", :medium},
    {"rules/windows/network_connection", :medium},
    {"rules/linux/file_event", :medium},
    {"rules/linux/network_connection", :medium},
    {"rules/network", :medium},
    {"rules/macos/process_creation", :medium},
    {"rules/macos/file_event", :medium},

    # Lower priority - specialized
    {"rules/windows/dns_query", :low},
    {"rules/windows/file_access", :low},
    {"rules/windows/image_load", :low},
    {"rules/windows/powershell", :low},
    {"rules/windows/create_remote_thread", :low}
  ]

  # Allowed rule statuses (skip experimental for production)
  @allowed_statuses ["stable", "test"]

  # Minimum rule level to include
  @level_priorities %{
    "critical" => 4,
    "high" => 3,
    "medium" => 2,
    "low" => 1,
    "informational" => 0
  }
  # medium and above
  @min_level_priority 2

  # MITRE ATT&CK tactics relevant for EDR/security
  @priority_tactics [
    "credential-access",
    "defense-evasion",
    "execution",
    "persistence",
    "lateral-movement",
    "initial-access",
    "privilege-escalation",
    "command-and-control",
    "exfiltration"
  ]

  # Web3-relevant tags for additional filtering
  @web3_relevant_tags [
    # Unsecured Credentials
    "attack.t1552",
    # Credentials from Password Stores
    "attack.t1555",
    # Steal Web Session Cookie
    "attack.t1539",
    # Adversary-in-the-Middle
    "attack.t1557",
    # Resource Hijacking (cryptomining)
    "attack.t1496",
    # Data Encrypted for Impact (ransomware)
    "attack.t1486",
    "wallet",
    "cryptocurrency",
    "browser",
    "keychain"
  ]

  # ── GenServer State ────────────────────────────────────────────────────────

  defmodule State do
    @moduledoc false
    defstruct [
      :repo_path,
      :last_sync_at,
      :last_commit,
      :rules_indexed,
      :rules_by_technique,
      :rules_by_category,
      :sync_in_progress,
      :sync_stats
    ]
  end

  # ── Public API ─────────────────────────────────────────────────────────────

  @doc """
  Start the SigmaSync GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Trigger a sync of SigmaHQ rules.

  ## Options

  - `:force` - Force full resync even if repo is up to date (default: false)
  - `:categories` - List of category paths to sync (default: all)
  - `:async` - Run sync asynchronously (default: true)

  ## Examples

      SigmaSync.sync()
      SigmaSync.sync(force: true)
      SigmaSync.sync(categories: ["rules/windows/process_creation"])
  """
  @spec sync(keyword()) :: {:ok, map()} | {:error, term()}
  def sync(opts \\ []) do
    if Keyword.get(opts, :async, true) do
      GenServer.cast(__MODULE__, {:sync, opts})
      {:ok, :sync_started}
    else
      GenServer.call(__MODULE__, {:sync, opts}, :infinity)
    end
  end

  @doc """
  Get current sync status and statistics.
  """
  @spec status() :: map()
  def status do
    GenServer.call(__MODULE__, :status)
  end

  @doc """
  Get all rules indexed by MITRE technique ID.
  """
  @spec get_rules_by_technique(String.t()) :: [map()]
  def get_rules_by_technique(technique_id) do
    GenServer.call(__MODULE__, {:get_by_technique, technique_id})
  end

  @doc """
  Get all rules for a specific logsource category.
  """
  @spec get_rules_for_category(String.t()) :: [map()]
  def get_rules_for_category(category) do
    GenServer.call(__MODULE__, {:get_by_category, category})
  end

  @doc """
  Get rules matching an event type (maps to logsource category).
  """
  @spec get_rules_for_event_type(atom()) :: [map()]
  def get_rules_for_event_type(event_type) do
    category = event_type_to_category(event_type)
    get_rules_for_category(category)
  end

  @doc """
  Search rules by title, description, or tags.
  """
  @spec search_rules(String.t()) :: [map()]
  def search_rules(query) do
    GenServer.call(__MODULE__, {:search, query})
  end

  @doc """
  Get all synced rules (filtered and indexed).
  """
  @spec list_rules() :: [map()]
  def list_rules do
    GenServer.call(__MODULE__, :list_rules)
  end

  @doc """
  Import synced rules into the database for a specific organization.
  """
  @spec import_rules_to_db(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def import_rules_to_db(organization_id, opts \\ []) do
    GenServer.call(__MODULE__, {:import_to_db, organization_id, opts}, :infinity)
  end

  @doc """
  Get MITRE technique coverage from synced rules.
  """
  @spec get_technique_coverage() :: map()
  def get_technique_coverage do
    GenServer.call(__MODULE__, :get_coverage)
  end

  # ── GenServer Callbacks ────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    repo_path = Keyword.get(opts, :repo_path, get_repo_path())

    state = %State{
      repo_path: repo_path,
      last_sync_at: nil,
      last_commit: nil,
      rules_indexed: [],
      rules_by_technique: %{},
      rules_by_category: %{},
      sync_in_progress: false,
      sync_stats: %{}
    }

    # Schedule initial sync after startup
    if Keyword.get(opts, :auto_sync, true) do
      Process.send_after(self(), :initial_sync, 5_000)
    end

    # Schedule periodic sync
    schedule_periodic_sync()

    {:ok, state}
  end

  @impl true
  def handle_call({:sync, opts}, _from, state) do
    if state.sync_in_progress do
      {:reply, {:error, :sync_in_progress}, state}
    else
      result = do_sync(state, opts)

      case result do
        {:ok, new_state} -> {:reply, {:ok, new_state.sync_stats}, new_state}
        {:error, reason} -> {:reply, {:error, reason}, state}
      end
    end
  end

  @impl true
  def handle_call(:status, _from, state) do
    status = %{
      last_sync_at: state.last_sync_at,
      last_commit: state.last_commit,
      rules_count: length(state.rules_indexed),
      techniques_covered: map_size(state.rules_by_technique),
      categories_indexed: map_size(state.rules_by_category),
      sync_in_progress: state.sync_in_progress,
      sync_stats: state.sync_stats,
      repo_path: state.repo_path,
      repo_exists: File.dir?(state.repo_path)
    }

    {:reply, status, state}
  end

  @impl true
  def handle_call({:get_by_technique, technique_id}, _from, state) do
    rules = Map.get(state.rules_by_technique, technique_id, [])
    {:reply, rules, state}
  end

  @impl true
  def handle_call({:get_by_category, category}, _from, state) do
    rules = Map.get(state.rules_by_category, category, [])
    {:reply, rules, state}
  end

  @impl true
  def handle_call({:search, query}, _from, state) do
    query_lower = String.downcase(query)

    results =
      state.rules_indexed
      |> Enum.filter(fn rule ->
        title = String.downcase(rule["title"] || "")
        desc = String.downcase(rule["description"] || "")
        tags = Enum.map(rule["tags"] || [], &String.downcase/1)

        String.contains?(title, query_lower) ||
          String.contains?(desc, query_lower) ||
          Enum.any?(tags, &String.contains?(&1, query_lower))
      end)

    {:reply, results, state}
  end

  @impl true
  def handle_call(:list_rules, _from, state) do
    {:reply, state.rules_indexed, state}
  end

  @impl true
  def handle_call({:import_to_db, organization_id, opts}, _from, state) do
    result = import_rules_to_database(state.rules_indexed, organization_id, opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_coverage, _from, state) do
    coverage = calculate_technique_coverage(state.rules_by_technique)
    {:reply, coverage, state}
  end

  @impl true
  def handle_cast({:sync, opts}, state) do
    if state.sync_in_progress do
      {:noreply, state}
    else
      state = %{state | sync_in_progress: true}

      # Run sync in a Task to avoid blocking the GenServer
      parent = self()

      Task.start(fn ->
        result = do_sync(state, opts)
        send(parent, {:sync_complete, result})
      end)

      {:noreply, state}
    end
  end

  @impl true
  def handle_info(:initial_sync, state) do
    Logger.info("[SigmaSync] Starting initial sync...")
    GenServer.cast(self(), {:sync, []})
    {:noreply, state}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    Logger.info("[SigmaSync] Starting periodic sync...")
    GenServer.cast(self(), {:sync, []})
    schedule_periodic_sync()
    {:noreply, state}
  end

  @impl true
  def handle_info({:sync_complete, result}, state) do
    case result do
      {:ok, new_state} ->
        Logger.info(
          "[SigmaSync] Sync completed: #{new_state.sync_stats.total_rules} rules indexed"
        )

        {:noreply, %{new_state | sync_in_progress: false}}

      {:error, reason} ->
        Logger.error("[SigmaSync] Sync failed: #{inspect(reason)}")
        {:noreply, %{state | sync_in_progress: false}}
    end
  end

  @impl true
  def handle_info(msg, state) do
    Logger.debug("[SigmaSync] Unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end

  # ── Private: Sync Logic ────────────────────────────────────────────────────

  defp do_sync(state, opts) do
    repo_path = state.repo_path
    force = Keyword.get(opts, :force, false)
    categories = Keyword.get(opts, :categories, nil)

    Logger.info("[SigmaSync] Starting sync to #{repo_path}")

    with :ok <- ensure_repo(repo_path, force),
         {:ok, commit} <- get_current_commit(repo_path),
         {:ok, rules} <- parse_rules(repo_path, categories),
         {:ok, filtered_rules} <- filter_rules(rules),
         {:ok, indexed} <- index_rules(filtered_rules) do
      stats = %{
        total_rules: length(filtered_rules),
        rules_parsed: length(rules),
        rules_filtered: length(rules) - length(filtered_rules),
        techniques_covered: map_size(indexed.by_technique),
        categories_indexed: map_size(indexed.by_category),
        commit: commit,
        sync_time: DateTime.utc_now()
      }

      new_state = %{
        state
        | last_sync_at: DateTime.utc_now(),
          last_commit: commit,
          rules_indexed: filtered_rules,
          rules_by_technique: indexed.by_technique,
          rules_by_category: indexed.by_category,
          sync_stats: stats
      }

      Logger.info(
        "[SigmaSync] Sync complete: #{stats.total_rules} rules, #{stats.techniques_covered} techniques"
      )

      {:ok, new_state}
    end
  end

  defp ensure_repo(repo_path, force) do
    cond do
      force && File.dir?(repo_path) ->
        Logger.info("[SigmaSync] Force sync: updating repository")
        update_repo(repo_path)

      File.dir?(repo_path) ->
        Logger.info("[SigmaSync] Repository exists, pulling updates")
        update_repo(repo_path)

      true ->
        Logger.info("[SigmaSync] Cloning SigmaHQ repository...")
        clone_repo(repo_path)
    end
  end

  defp clone_repo(repo_path) do
    # Ensure parent directory exists
    File.mkdir_p!(Path.dirname(repo_path))

    case OSCommand.run("git", ["clone", "--depth", "1", @sigmahq_repo_url, repo_path],
           stderr_to_stdout: true
         ) do
      {_output, 0} ->
        Logger.info("[SigmaSync] Repository cloned successfully")
        :ok

      # OSCommand.run/3 returns {output, exit_code} | {:error, reason};
      # {:error, reason} must precede the generic 2-tuple clause or timeouts
      # and validation failures get mislabeled as command output.
      {:error, reason} ->
        {:error, {:clone_failed, reason}}

      {output, _code} ->
        Logger.error("[SigmaSync] Failed to clone repository: #{output}")
        {:error, {:clone_failed, output}}
    end
  rescue
    e ->
      Logger.error("[SigmaSync] Git clone error: #{inspect(e)}")
      {:error, {:clone_failed, e}}
  end

  defp update_repo(repo_path) do
    case OSCommand.run("git", ["pull", "--ff-only"], cd: repo_path, stderr_to_stdout: true) do
      {_output, 0} ->
        Logger.info("[SigmaSync] Repository updated successfully")
        :ok

      # {:error, reason} must precede the generic {output, _code} clause;
      # see clone_repo/1.
      {:error, reason} ->
        {:error, {:pull_failed, reason}}

      {output, _code} ->
        # Try to recover by resetting and pulling
        Logger.warning("[SigmaSync] Pull failed, attempting reset: #{output}")
        OSCommand.run("git", ["reset", "--hard", "origin/master"], cd: repo_path)
        OSCommand.run("git", ["pull"], cd: repo_path)
        :ok
    end
  rescue
    e ->
      Logger.error("[SigmaSync] Git pull error: #{inspect(e)}")
      {:error, {:pull_failed, e}}
  end

  defp get_current_commit(repo_path) do
    case OSCommand.run("git", ["rev-parse", "HEAD"], cd: repo_path, stderr_to_stdout: true) do
      # {:error, reason} must precede the generic {output, _} clause;
      # see clone_repo/1.
      {commit, 0} -> {:ok, String.trim(commit)}
      {:error, reason} -> {:error, {:git_error, reason}}
      {output, _} -> {:error, {:git_error, output}}
    end
  rescue
    e -> {:error, {:git_error, e}}
  end

  # ── Private: Rule Parsing ──────────────────────────────────────────────────

  defp parse_rules(repo_path, categories_filter) do
    categories =
      if categories_filter do
        # Filter to only specified categories
        @rule_categories
        |> Enum.filter(fn {path, _} -> path in categories_filter end)
      else
        @rule_categories
      end

    rules =
      categories
      |> Enum.flat_map(fn {category_path, priority} ->
        full_path = Path.join(repo_path, category_path)
        parse_category_rules(full_path, category_path, priority)
      end)

    Logger.info("[SigmaSync] Parsed #{length(rules)} rules from #{length(categories)} categories")
    {:ok, rules}
  end

  defp parse_category_rules(path, category, priority) do
    if File.dir?(path) do
      path
      |> Path.join("**/*.yml")
      |> Path.wildcard()
      |> Enum.flat_map(fn file_path ->
        parse_rule_file(file_path, category, priority)
      end)
    else
      Logger.debug("[SigmaSync] Category path not found: #{path}")
      []
    end
  end

  defp parse_rule_file(file_path, category, priority) do
    case File.read(file_path) do
      {:ok, content} ->
        # Handle multi-document YAML files (separated by ---)
        content
        |> String.split(~r/^---$/m, trim: true)
        |> Enum.flat_map(fn doc ->
          case YamlElixir.read_from_string(doc) do
            {:ok, rule} when is_map(rule) ->
              enriched = enrich_rule(rule, file_path, category, priority)
              [enriched]

            _ ->
              []
          end
        end)

      {:error, reason} ->
        Logger.warning("[SigmaSync] Failed to read #{file_path}: #{inspect(reason)}")
        []
    end
  rescue
    e ->
      Logger.warning("[SigmaSync] Error parsing #{file_path}: #{inspect(e)}")
      []
  end

  defp enrich_rule(rule, file_path, category, priority) do
    # Extract MITRE techniques from tags
    tags = rule["tags"] || []
    mitre_techniques = extract_mitre_techniques(tags)
    mitre_tactics = extract_mitre_tactics(tags)

    rule
    |> Map.put("_file_path", file_path)
    |> Map.put("_category", category)
    |> Map.put("_priority", priority)
    |> Map.put("_mitre_techniques", mitre_techniques)
    |> Map.put("_mitre_tactics", mitre_tactics)
    |> Map.put("_logsource_category", get_in(rule, ["logsource", "category"]))
    |> Map.put("_logsource_product", get_in(rule, ["logsource", "product"]))
  end

  defp extract_mitre_techniques(tags) do
    tags
    |> Enum.filter(&String.starts_with?(&1, "attack.t"))
    |> Enum.map(fn tag ->
      tag
      |> String.replace_prefix("attack.", "")
      |> String.upcase()
    end)
  end

  defp extract_mitre_tactics(tags) do
    tags
    |> Enum.filter(&String.starts_with?(&1, "attack."))
    |> Enum.reject(&String.starts_with?(&1, "attack.t"))
    |> Enum.map(&String.replace_prefix(&1, "attack.", ""))
  end

  # ── Private: Rule Filtering ────────────────────────────────────────────────

  defp filter_rules(rules) do
    filtered =
      rules
      |> Enum.filter(&filter_by_status/1)
      |> Enum.filter(&filter_by_level/1)
      |> Enum.filter(&filter_by_relevance/1)
      |> Enum.filter(&has_valid_detection/1)

    Logger.info("[SigmaSync] Filtered to #{length(filtered)} rules")
    {:ok, filtered}
  end

  defp filter_by_status(rule) do
    status = rule["status"] || "experimental"
    status in @allowed_statuses
  end

  defp filter_by_level(rule) do
    level = rule["level"] || "low"
    priority = Map.get(@level_priorities, level, 0)
    priority >= @min_level_priority
  end

  defp filter_by_relevance(rule) do
    tactics = rule["_mitre_tactics"] || []
    tags = rule["tags"] || []

    # Include if any priority tactic matches
    has_priority_tactic = Enum.any?(tactics, &(&1 in @priority_tactics))

    # Include if any Web3-relevant tag matches
    has_web3_tag =
      Enum.any?(tags, fn tag ->
        tag_lower = String.downcase(tag)
        Enum.any?(@web3_relevant_tags, &String.contains?(tag_lower, String.downcase(&1)))
      end)

    # Include high-priority categories regardless of tactics
    has_high_priority = rule["_priority"] == :high

    has_priority_tactic || has_web3_tag || has_high_priority
  end

  defp has_valid_detection(rule) do
    detection = rule["detection"]
    is_map(detection) && Map.has_key?(detection, "condition")
  end

  # ── Private: Rule Indexing ─────────────────────────────────────────────────

  defp index_rules(rules) do
    by_technique =
      rules
      |> Enum.flat_map(fn rule ->
        techniques = rule["_mitre_techniques"] || []
        Enum.map(techniques, fn tech -> {tech, rule} end)
      end)
      |> Enum.group_by(fn {tech, _} -> tech end, fn {_, rule} -> rule end)

    by_category =
      rules
      |> Enum.group_by(fn rule -> rule["_logsource_category"] end)

    {:ok, %{by_technique: by_technique, by_category: by_category}}
  end

  # ── Private: Database Import ───────────────────────────────────────────────

  defp import_rules_to_database(rules, organization_id, opts) do
    conflict_resolution = Keyword.get(opts, :conflict_resolution, "skip")
    prefix = Keyword.get(opts, :prefix, "sigmahq_")

    Logger.info("[SigmaSync] Importing #{length(rules)} rules to database")

    results =
      Enum.reduce(rules, %{imported: 0, skipped: 0, failed: 0}, fn rule, acc ->
        case import_single_rule(rule, organization_id, prefix, conflict_resolution) do
          {:ok, _} -> %{acc | imported: acc.imported + 1}
          {:skipped, _} -> %{acc | skipped: acc.skipped + 1}
          {:error, _} -> %{acc | failed: acc.failed + 1}
        end
      end)

    Logger.info(
      "[SigmaSync] Import complete: #{results.imported} imported, #{results.skipped} skipped, #{results.failed} failed"
    )

    {:ok, results}
  end

  defp import_single_rule(rule, organization_id, prefix, conflict_resolution) do
    name = prefix <> (rule["id"] || rule["title"] || UUID.uuid4())

    attrs = %{
      name: name,
      title: rule["title"],
      description: rule["description"],
      author: rule["author"],
      level: rule["level"] || "medium",
      status: rule["status"] || "experimental",
      source: encode_rule_source(rule),
      detection: rule["detection"] || %{},
      logsource_category: rule["_logsource_category"],
      logsource_product: rule["_logsource_product"],
      mitre_tactics: rule["_mitre_tactics"] || [],
      mitre_techniques: rule["_mitre_techniques"] || [],
      references: rule["references"] || [],
      tags: rule["tags"] || [],
      organization_id: organization_id,
      enabled: true
    }

    # Check for existing rule
    existing =
      Repo.one(
        from(r in SigmaRule,
          where: r.name == ^name and r.organization_id == ^organization_id
        )
      )

    case {existing, conflict_resolution} do
      {nil, _} ->
        # No conflict, create new
        %SigmaRule{}
        |> SigmaRule.changeset(attrs)
        |> Repo.insert()

      {_, "skip"} ->
        {:skipped, "Rule already exists: #{name}"}

      {existing, "overwrite"} ->
        existing
        |> SigmaRule.changeset(attrs)
        |> Repo.update()

      {_, _} ->
        {:skipped, "Unknown conflict resolution"}
    end
  rescue
    e ->
      Logger.warning("[SigmaSync] Failed to import rule: #{inspect(e)}")
      {:error, e}
  end

  defp encode_rule_source(rule) do
    # Remove internal enrichment fields and store as JSON
    # (YAML encoding not available in YamlElixir, so we use JSON for storage)
    rule
    |> Map.drop([
      "_file_path",
      "_category",
      "_priority",
      "_mitre_techniques",
      "_mitre_tactics",
      "_logsource_category",
      "_logsource_product"
    ])
    |> Jason.encode!()
  rescue
    _ ->
      # Fallback: just store the title if encoding fails
      rule["title"] || "Unknown Rule"
  end

  # ── Private: Technique Coverage ────────────────────────────────────────────

  defp calculate_technique_coverage(rules_by_technique) do
    %{
      total_techniques: map_size(rules_by_technique),
      techniques:
        Enum.map(rules_by_technique, fn {technique, rules} ->
          %{
            id: technique,
            rule_count: length(rules),
            rules:
              Enum.map(rules, fn r ->
                %{
                  title: r["title"],
                  level: r["level"],
                  status: r["status"]
                }
              end)
          }
        end)
        |> Enum.sort_by(fn t -> -t.rule_count end)
    }
  end

  # ── Private: Helpers ───────────────────────────────────────────────────────

  defp get_repo_path do
    config = Application.get_env(:tamandua_server, __MODULE__, [])
    Keyword.get(config, :repo_path, @default_repo_path)
  end

  defp schedule_periodic_sync do
    config = Application.get_env(:tamandua_server, __MODULE__, [])
    hours = Keyword.get(config, :sync_interval_hours, 24)
    Process.send_after(self(), :periodic_sync, hours * 60 * 60 * 1000)
  end

  defp event_type_to_category(event_type) do
    case event_type do
      :process_create -> "process_creation"
      :process_terminate -> "process_termination"
      :process_access -> "process_access"
      :file_create -> "file_event"
      :file_modify -> "file_event"
      :file_delete -> "file_event"
      :file_rename -> "file_event"
      :network_connect -> "network_connection"
      :dns_query -> "dns_query"
      :registry_create -> "registry_event"
      :registry_modify -> "registry_event"
      :registry_delete -> "registry_event"
      _ -> to_string(event_type)
    end
  end
end
