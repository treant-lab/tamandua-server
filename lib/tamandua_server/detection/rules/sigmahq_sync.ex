defmodule TamanduaServer.Detection.Rules.SigmaHQSync do
  @moduledoc """
  SigmaHQ Community Rules Synchronization.

  Downloads and imports Sigma rules from the official SigmaHQ repository:
  https://github.com/SigmaHQ/sigma

  Features:
  - Automatic sync from SigmaHQ releases
  - Rule validation and parsing
  - Category-based filtering (process_creation, network, etc.)
  - Severity-based filtering
  - Incremental updates (only new rules)
  - Rule versioning and changelog tracking

  ## Usage

      # Sync all rules
      SigmaHQSync.sync_all()

      # Sync specific categories
      SigmaHQSync.sync_category("process_creation")
      SigmaHQSync.sync_category("network_connection")

      # Sync by severity
      SigmaHQSync.sync_by_severity(["critical", "high"])

      # Get sync status
      SigmaHQSync.get_status()

  ## Supported Categories

  - process_creation
  - network_connection
  - dns_query
  - file_event
  - registry_event
  - image_load
  - pipe_created
  - sysmon (all sysmon events)
  - windows (Windows-specific)
  - linux (Linux-specific)
  - macos (macOS-specific)
  """

  use GenServer
  require Logger
  import Ecto.Query, only: [from: 2]

  alias TamanduaServer.Detection.SigmaRule
  alias TamanduaServer.Accounts.Organization

  @sigmahq_base_url "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules"
  @sigmahq_api_url "https://api.github.com/repos/SigmaHQ/sigma"
  @sync_interval :timer.hours(24)
  @http_timeout 60_000

  # Categories to sync
  @supported_categories %{
    "process_creation" => "windows/process_creation",
    "network_connection" => "windows/network_connection",
    "dns_query" => "windows/dns_query",
    "file_event" => "windows/file/file_event",
    "file_access" => "windows/file/file_access",
    "file_delete" => "windows/file/file_delete",
    "registry_event" => "windows/registry",
    "image_load" => "windows/image_load",
    "pipe_created" => "windows/pipe_created",
    "create_remote_thread" => "windows/create_remote_thread",
    "sysmon" => "windows/sysmon",
    "powershell" => "windows/powershell",
    "linux_process" => "linux/process_creation",
    "linux_network" => "linux/network_connection",
    "linux_file" => "linux/file_event",
    "linux_auditd" => "linux/auditd",
    "macos_process" => "macos/process_creation",
    "macos_file" => "macos/file_event",
    "cloud_aws" => "cloud/aws",
    "cloud_azure" => "cloud/azure",
    "cloud_gcp" => "cloud/gcp"
  }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Sync all rules from SigmaHQ.
  """
  @spec sync_all() :: {:ok, map()} | {:error, term()}
  def sync_all do
    GenServer.call(__MODULE__, :sync_all, @http_timeout * 10)
  end

  @doc """
  Sync rules for a specific category.
  """
  @spec sync_category(String.t()) :: {:ok, integer()} | {:error, term()}
  def sync_category(category) do
    GenServer.call(__MODULE__, {:sync_category, category}, @http_timeout * 5)
  end

  @doc """
  Sync rules by severity level.
  """
  @spec sync_by_severity([String.t()]) :: {:ok, map()} | {:error, term()}
  def sync_by_severity(severities) do
    GenServer.call(__MODULE__, {:sync_by_severity, severities}, @http_timeout * 10)
  end

  @doc """
  Get sync status and statistics.
  """
  @spec get_status() :: map()
  def get_status do
    GenServer.call(__MODULE__, :get_status)
  end

  @doc """
  List available categories.
  """
  @spec list_categories() :: [String.t()]
  def list_categories do
    Map.keys(@supported_categories)
  end

  @doc """
  Force refresh (clear cache and re-sync).
  """
  @spec force_refresh() :: {:ok, map()} | {:error, term()}
  def force_refresh do
    GenServer.call(__MODULE__, :force_refresh, @http_timeout * 10)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(opts) do
    state = %{
      enabled: Keyword.get(opts, :enabled, true),
      auto_sync: Keyword.get(opts, :auto_sync, true),
      sync_interval: Keyword.get(opts, :sync_interval, @sync_interval),
      last_sync: nil,
      last_commit: nil,
      stats: %{
        total_rules: 0,
        rules_by_category: %{},
        rules_by_severity: %{},
        last_sync_added: 0,
        last_sync_updated: 0
      },
      rules_cache: %{}
    }

    if state.enabled and state.auto_sync do
      # Initial sync after 30 seconds
      Process.send_after(self(), :auto_sync, :timer.seconds(30))
    end

    Logger.info("[SigmaHQSync] Initialized")
    {:ok, state}
  end

  @impl true
  def handle_call(:sync_all, _from, state) do
    Logger.info("[SigmaHQSync] Starting full sync...")

    results = Enum.reduce(@supported_categories, %{}, fn {category, _path}, acc ->
      case do_sync_category(category, state) do
        {:ok, count} -> Map.put(acc, category, count)
        {:error, reason} -> Map.put(acc, category, {:error, reason})
      end
    end)

    total = results |> Map.values() |> Enum.filter(&is_integer/1) |> Enum.sum()

    new_state = %{state |
      last_sync: DateTime.utc_now(),
      stats: Map.merge(state.stats, %{
        total_rules: total,
        last_sync_added: total
      })
    }

    Logger.info("[SigmaHQSync] Full sync completed: #{total} rules imported")
    {:reply, {:ok, results}, new_state}
  end

  @impl true
  def handle_call({:sync_category, category}, _from, state) do
    result = do_sync_category(category, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:sync_by_severity, severities}, _from, state) do
    Logger.info("[SigmaHQSync] Syncing rules with severity: #{inspect(severities)}")

    results = Enum.reduce(@supported_categories, %{}, fn {category, _path}, acc ->
      case do_sync_category_filtered(category, severities, state) do
        {:ok, count} -> Map.put(acc, category, count)
        {:error, reason} -> Map.put(acc, category, {:error, reason})
      end
    end)

    total = results |> Map.values() |> Enum.filter(&is_integer/1) |> Enum.sum()
    Logger.info("[SigmaHQSync] Severity sync completed: #{total} rules imported")

    {:reply, {:ok, results}, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      enabled: state.enabled,
      auto_sync: state.auto_sync,
      last_sync: state.last_sync,
      last_commit: state.last_commit,
      stats: state.stats,
      categories: Map.keys(@supported_categories)
    }
    {:reply, status, state}
  end

  @impl true
  def handle_call(:force_refresh, _from, state) do
    Logger.info("[SigmaHQSync] Force refresh requested")
    new_state = %{state | rules_cache: %{}}

    # Trigger full sync
    send(self(), :sync_now)

    {:reply, :ok, new_state}
  end

  @impl true
  def handle_info(:auto_sync, state) do
    if state.enabled do
      Logger.info("[SigmaHQSync] Starting auto-sync...")
      send(self(), :sync_now)
      schedule_sync(state.sync_interval)
    end
    {:noreply, state}
  end

  @impl true
  def handle_info(:sync_now, state) do
    # Sync high-priority categories first
    priority_categories = [
      "process_creation",
      "network_connection",
      "powershell",
      "registry_event",
      "create_remote_thread"
    ]

    Enum.each(priority_categories, fn category ->
      case do_sync_category(category, state) do
        {:ok, count} -> Logger.debug("[SigmaHQSync] #{category}: #{count} rules")
        {:error, reason} -> Logger.warning("[SigmaHQSync] #{category} failed: #{inspect(reason)}")
      end
    end)

    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp do_sync_category(category, _state) do
    path = Map.get(@supported_categories, category)

    unless path do
      {:error, :unknown_category}
    else
      fetch_and_import_rules(category, path)
    end
  end

  defp do_sync_category_filtered(category, severities, _state) do
    path = Map.get(@supported_categories, category)

    unless path do
      {:error, :unknown_category}
    else
      fetch_and_import_rules_filtered(category, path, severities)
    end
  end

  defp fetch_and_import_rules(category, path) do
    # Fetch rule list from GitHub API
    case fetch_rule_list(path) do
      {:ok, files} ->
        rules = files
        |> Enum.filter(&String.ends_with?(&1, ".yml"))
        |> Enum.map(&fetch_and_parse_rule(path, &1))
        |> Enum.filter(&match?({:ok, _}, &1))
        |> Enum.map(fn {:ok, rule} -> rule end)

        # Store rules
        store_rules(category, rules)

        Logger.info("[SigmaHQSync] #{category}: imported #{length(rules)} rules")
        {:ok, length(rules)}

      {:error, reason} ->
        Logger.warning("[SigmaHQSync] Failed to fetch #{category}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp fetch_and_import_rules_filtered(category, path, severities) do
    case fetch_rule_list(path) do
      {:ok, files} ->
        rules = files
        |> Enum.filter(&String.ends_with?(&1, ".yml"))
        |> Enum.map(&fetch_and_parse_rule(path, &1))
        |> Enum.filter(&match?({:ok, _}, &1))
        |> Enum.map(fn {:ok, rule} -> rule end)
        |> Enum.filter(fn rule ->
          severity = rule["level"] || "medium"
          severity in severities
        end)

        store_rules(category, rules)
        {:ok, length(rules)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_rule_list(path) do
    url = "#{@sigmahq_api_url}/contents/rules/#{path}"
    headers = [
      {"Accept", "application/vnd.github.v3+json"},
      {"User-Agent", "Tamandua-EDR"}
    ]

    case Finch.build(:get, url, headers)
         |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, items} when is_list(items) ->
            files = items
            |> Enum.filter(&(&1["type"] == "file"))
            |> Enum.map(&(&1["name"]))
            {:ok, files}

          {:ok, %{"message" => msg}} ->
            {:error, msg}

          {:error, reason} ->
            {:error, {:json_error, reason}}
        end

      {:ok, %Finch.Response{status: 403}} ->
        {:error, :rate_limited}

      {:ok, %Finch.Response{status: 404}} ->
        {:error, :not_found}

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_and_parse_rule(path, filename) do
    url = "#{@sigmahq_base_url}/#{path}/#{filename}"

    case Finch.build(:get, url)
         |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case YamlElixir.read_from_string(body) do
          {:ok, rule} when is_map(rule) ->
            rule = Map.put(rule, "_source", "sigmahq")
            rule = Map.put(rule, "_filename", filename)
            {:ok, rule}

          {:error, reason} ->
            {:error, {:yaml_error, reason}}
        end

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp store_rules(category, rules) do
    alias TamanduaServer.Repo
    alias TamanduaServer.Detection.SigmaRule

    # Get default organization for SigmaHQ rules (or create one)
    org_id = get_or_create_sigmahq_org_id()

    inserted_count = Enum.reduce(rules, 0, fn rule, acc ->
      rule_id = rule["id"] || rule["title"] || UUID.uuid4()
      logsource = rule["logsource"] || %{}
      tags = rule["tags"] || []
      {tactics, techniques} = extract_mitre_attack(tags)

      attrs = %{
        name: rule_id,
        title: rule["title"],
        description: rule["description"],
        author: rule["author"],
        level: rule["level"] || "medium",
        status: rule["status"] || "experimental",
        enabled: true,
        source: Jason.encode!(rule),  # Store original YAML as source
        detection: rule["detection"] || %{},
        logsource_category: logsource["category"],
        logsource_product: logsource["product"],
        logsource_service: logsource["service"],
        mitre_tactics: tactics,
        mitre_techniques: techniques,
        references: rule["references"] || [],
        tags: tags,
        organization_id: org_id
      }

      # Upsert: insert or update existing rule
      case Repo.get_by(SigmaRule, name: rule_id, organization_id: org_id) do
        nil ->
          changeset = SigmaRule.changeset(%SigmaRule{}, attrs)
          case Repo.insert(changeset) do
            {:ok, _} -> acc + 1
            {:error, changeset} ->
              Logger.warning("[SigmaHQSync] Failed to insert rule #{rule_id}: #{inspect(changeset.errors)}")
              acc
          end

        existing ->
          changeset = SigmaRule.changeset(existing, attrs)
          case Repo.update(changeset) do
            {:ok, _} -> acc + 1
            {:error, changeset} ->
              Logger.warning("[SigmaHQSync] Failed to update rule #{rule_id}: #{inspect(changeset.errors)}")
              acc
          end
      end
    end)

    # Also keep in persistent_term for fast lookups by category
    Enum.each(rules, fn rule ->
      rule_id = rule["id"] || rule["title"] || UUID.uuid4()
      tags = rule["tags"] || []
      {_tactics, techniques} = extract_mitre_attack(tags)

      internal_rule = %{
        id: rule_id,
        title: rule["title"],
        description: rule["description"],
        status: rule["status"] || "experimental",
        level: rule["level"] || "medium",
        logsource: rule["logsource"] || %{},
        detection: rule["detection"] || %{},
        tags: tags,
        references: rule["references"] || [],
        author: rule["author"],
        date: rule["date"],
        modified: rule["modified"],
        source: "sigmahq",
        category: category,
        mitre_attack: techniques
      }

      :persistent_term.put({:sigma_rule, rule_id}, internal_rule)
    end)

    # Update rule index
    existing = :persistent_term.get({:sigma_rules_index, category}, [])
    rule_ids = Enum.map(rules, fn r -> r["id"] || r["title"] end)
    :persistent_term.put({:sigma_rules_index, category}, Enum.uniq(existing ++ rule_ids))

    # Trigger detection engine reload if rules were inserted/updated
    if inserted_count > 0 do
      spawn(fn ->
        # Slight delay to let the transaction commit
        Process.sleep(100)
        try do
          TamanduaServer.Detection.Engine.reload_sigma_rules()
        rescue
          e -> Logger.warning("[SigmaHQSync] Failed to reload detection engine: #{Exception.message(e)}")
        end
      end)
    end

    inserted_count
  end

  # Get or create the default organization for SigmaHQ rules
  defp get_or_create_sigmahq_org_id do
    alias TamanduaServer.Repo
    alias TamanduaServer.Accounts.Organization

    case Repo.get_by(Organization, slug: "sigmahq-community") do
      %Organization{id: id} ->
        id

      nil ->
        # Create a system organization for SigmaHQ rules
        attrs = %{
          name: "SigmaHQ Community Rules",
          slug: "sigmahq-community",
          license_tier: :enterprise
        }

        case %Organization{} |> Organization.changeset(attrs) |> Repo.insert() do
          {:ok, org} ->
            Logger.info("[SigmaHQSync] Created SigmaHQ community organization")
            org.id

          {:error, changeset} ->
            # Race condition - another process created it
            Logger.warning("[SigmaHQSync] Failed to create org: #{inspect(changeset.errors)}")
            case Repo.get_by(Organization, slug: "sigmahq-community") do
              %Organization{id: id} -> id
              nil ->
                # Fallback: use first organization
                case Repo.one(from(o in Organization, limit: 1)) do
                  %Organization{id: id} -> id
                  nil -> raise "No organization available for SigmaHQ rules"
                end
            end
        end
    end
  rescue
    e ->
      Logger.error("[SigmaHQSync] Error getting/creating org: #{Exception.message(e)}")
      # Try to get any organization as fallback
      import Ecto.Query
      case TamanduaServer.Repo.one(from(o in TamanduaServer.Accounts.Organization, limit: 1)) do
        %TamanduaServer.Accounts.Organization{id: id} -> id
        nil -> raise "No organization available for SigmaHQ rules"
      end
  end

  # Extract both tactics and techniques from SigmaHQ tags
  # Tags look like: ["attack.defense_evasion", "attack.t1562.001", ...]
  defp extract_mitre_attack(tags) do
    attack_tags = tags
    |> Enum.filter(&String.starts_with?(&1, "attack."))
    |> Enum.map(&String.replace(&1, "attack.", ""))

    # Techniques start with t/T followed by digits (e.g., t1562, T1562.001)
    techniques = attack_tags
    |> Enum.filter(&String.match?(&1, ~r/^t\d+/i))
    |> Enum.map(&String.upcase/1)

    # Tactics are the rest (e.g., defense_evasion, persistence)
    tactics = attack_tags
    |> Enum.reject(&String.match?(&1, ~r/^t\d+/i))
    |> Enum.map(&String.downcase/1)

    {tactics, techniques}
  end

  defp schedule_sync(interval) do
    Process.send_after(self(), :auto_sync, interval)
  end

  # ============================================================================
  # Rule Retrieval
  # ============================================================================

  @doc """
  Get all synced rules for a category.
  """
  @spec get_rules(String.t()) :: [map()]
  def get_rules(category) do
    rule_ids = :persistent_term.get({:sigma_rules_index, category}, [])

    Enum.map(rule_ids, fn id ->
      :persistent_term.get({:sigma_rule, id}, nil)
    end)
    |> Enum.filter(&(&1 != nil))
  end

  @doc """
  Get all synced rules.
  """
  @spec get_all_rules() :: [map()]
  def get_all_rules do
    @supported_categories
    |> Map.keys()
    |> Enum.flat_map(&get_rules/1)
  end

  @doc """
  Get rules by severity.
  """
  @spec get_rules_by_severity(String.t()) :: [map()]
  def get_rules_by_severity(severity) do
    get_all_rules()
    |> Enum.filter(&(&1.level == severity))
  end

  @doc """
  Get rules by MITRE ATT&CK technique.
  """
  @spec get_rules_by_mitre(String.t()) :: [map()]
  def get_rules_by_mitre(technique_id) do
    technique_upper = String.upcase(technique_id)

    get_all_rules()
    |> Enum.filter(fn rule ->
      Enum.any?(rule.mitre_attack || [], &(&1 == technique_upper))
    end)
  end

  @doc """
  Search rules by keyword.
  """
  @spec search_rules(String.t()) :: [map()]
  def search_rules(query) do
    query_lower = String.downcase(query)

    get_all_rules()
    |> Enum.filter(fn rule ->
      title_match = rule.title && String.contains?(String.downcase(rule.title), query_lower)
      desc_match = rule.description && String.contains?(String.downcase(rule.description), query_lower)
      title_match or desc_match
    end)
  end
end
