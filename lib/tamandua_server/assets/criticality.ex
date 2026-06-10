defmodule TamanduaServer.Assets.Criticality do
  @moduledoc """
  Asset Criticality Module

  Assigns and manages criticality scores for assets (agents/hosts).

  Factors considered:
  - Role: server, workstation, domain controller, database, etc.
  - Data sensitivity: PII, financial, healthcare, classified
  - User privilege: admin, service account, standard user
  - Business function: production, development, test
  - Network position: DMZ, internal, isolated
  - Compliance requirements: PCI, HIPAA, SOX

  Auto-discovery capabilities:
  - Domain controllers (via Active Directory patterns)
  - Database servers (via process/port detection)
  - Certificate authorities
  - Backup servers
  - Jump boxes / bastion hosts
  """

  use GenServer
  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents.Agent

  # Criticality levels
  @levels [:critical, :high, :medium, :low, :minimal]

  # Role-based criticality scores (out of 100)
  @role_scores %{
    "domain_controller" => 100,
    "certificate_authority" => 95,
    "database_server" => 90,
    "backup_server" => 85,
    "file_server" => 80,
    "mail_server" => 80,
    "web_server" => 75,
    "application_server" => 70,
    "jump_box" => 90,
    "bastion" => 90,
    "security_appliance" => 85,
    "network_device" => 80,
    "production_server" => 75,
    "staging_server" => 50,
    "development_server" => 40,
    "test_server" => 30,
    "workstation_admin" => 70,
    "workstation_privileged" => 60,
    "workstation_standard" => 40,
    "kiosk" => 20,
    "iot_device" => 30,
    "unknown" => 50
  }

  # Data sensitivity modifiers
  @sensitivity_modifiers %{
    "classified" => 1.5,
    "pii" => 1.3,
    "phi" => 1.4,  # Protected Health Information
    "pci" => 1.3,  # Payment Card Industry
    "financial" => 1.2,
    "intellectual_property" => 1.2,
    "public" => 1.0,
    "internal" => 1.05
  }

  # Compliance modifiers
  @compliance_modifiers %{
    "hipaa" => 1.3,
    "pci_dss" => 1.3,
    "sox" => 1.2,
    "gdpr" => 1.2,
    "fisma" => 1.3,
    "fedramp" => 1.4,
    "none" => 1.0
  }

  # Auto-detection patterns
  @dc_indicators [
    # Process names
    "lsass.exe",
    "ntds.dit",
    "Active Directory",
    "AD DS",
    # Hostname patterns
    ~r/^DC\d+/i,
    ~r/^PDC/i,
    ~r/^ADC/i,
    ~r/domain.*controller/i
  ]

  @db_indicators [
    # Process/service names
    "sqlservr.exe",
    "mysqld",
    "postgres",
    "oracle",
    "mongod",
    "redis-server",
    "cassandra",
    # Hostname patterns
    ~r/^DB\d+/i,
    ~r/^SQL/i,
    ~r/database/i
  ]

  @ca_indicators [
    "certsrv",
    "CertificateAuthority",
    ~r/^CA\d*/i,
    ~r/cert.*server/i
  ]

  # GenServer state
  defstruct [
    :criticality_cache,
    :auto_discovered,
    :custom_overrides,
    :last_refresh
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get the criticality assessment for an asset.

  Returns:
  - level: :critical, :high, :medium, :low, :minimal
  - score: 0-100 numeric score
  - factors: list of factors contributing to the score
  - auto_discovered: boolean indicating if role was auto-detected
  """
  @spec get_criticality(String.t()) :: map()
  def get_criticality(agent_id) do
    GenServer.call(__MODULE__, {:get_criticality, agent_id})
  end

  @doc """
  Set manual criticality override for an asset.
  """
  @spec set_criticality(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def set_criticality(agent_id, attrs) do
    GenServer.call(__MODULE__, {:set_criticality, agent_id, attrs})
  end

  @doc """
  Remove manual criticality override (revert to auto-detection).
  """
  @spec clear_criticality(String.t()) :: :ok
  def clear_criticality(agent_id) do
    GenServer.call(__MODULE__, {:clear_criticality, agent_id})
  end

  @doc """
  List all assets with their criticality levels.
  """
  @spec list_assets(keyword()) :: [map()]
  def list_assets(opts \\ []) do
    GenServer.call(__MODULE__, {:list_assets, opts})
  end

  @doc """
  Get all critical assets (criticality level = :critical or :high).
  """
  @spec get_critical_assets(String.t() | nil) :: [map()]
  def get_critical_assets(org_id \\ nil) do
    GenServer.call(__MODULE__, {:get_critical, org_id})
  end

  @doc """
  Trigger re-analysis of an asset's criticality.
  """
  @spec refresh_criticality(String.t()) :: {:ok, map()}
  def refresh_criticality(agent_id) do
    GenServer.call(__MODULE__, {:refresh, agent_id})
  end

  @doc """
  Bulk import criticality data (e.g., from CMDB).
  """
  @spec bulk_import([map()]) :: {:ok, integer()} | {:error, term()}
  def bulk_import(assets) do
    GenServer.call(__MODULE__, {:bulk_import, assets})
  end

  @doc """
  Get criticality score distribution for an organization.
  """
  @spec get_distribution(String.t()) :: map()
  def get_distribution(org_id) do
    GenServer.call(__MODULE__, {:get_distribution, org_id})
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("Starting Asset Criticality Service")

    state = %__MODULE__{
      criticality_cache: %{},
      auto_discovered: %{},
      custom_overrides: load_overrides(),
      last_refresh: nil
    }

    # Schedule periodic refresh
    schedule_refresh()

    {:ok, state}
  end

  @impl true
  def handle_call({:get_criticality, agent_id}, _from, state) do
    result = calculate_criticality(agent_id, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:set_criticality, agent_id, attrs}, _from, state) do
    # Validate and save override
    case validate_criticality_attrs(attrs) do
      :ok ->
        override = Map.merge(%{
          agent_id: agent_id,
          updated_at: DateTime.utc_now()
        }, attrs)

        save_override(agent_id, override)

        new_overrides = Map.put(state.custom_overrides, agent_id, override)
        new_state = %{state | custom_overrides: new_overrides}

        # Recalculate with override
        result = calculate_criticality(agent_id, new_state)
        {:reply, {:ok, result}, new_state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:clear_criticality, agent_id}, _from, state) do
    delete_override(agent_id)
    new_overrides = Map.delete(state.custom_overrides, agent_id)
    {:reply, :ok, %{state | custom_overrides: new_overrides}}
  end

  @impl true
  def handle_call({:list_assets, opts}, _from, state) do
    org_id = Keyword.get(opts, :organization_id)
    level = Keyword.get(opts, :level)

    agents = list_agents(org_id)

    assets = Enum.map(agents, fn agent ->
      criticality = calculate_criticality(agent.id, state)
      Map.merge(criticality, %{
        agent_id: agent.id,
        hostname: agent.hostname,
        os_type: agent.os_type,
        status: agent.status
      })
    end)

    # Filter by level if specified
    filtered = if level do
      Enum.filter(assets, fn a -> a.level == level end)
    else
      assets
    end

    {:reply, filtered, state}
  end

  @impl true
  def handle_call({:get_critical, org_id}, _from, state) do
    agents = list_agents(org_id)

    critical_assets = agents
    |> Enum.map(fn agent ->
      criticality = calculate_criticality(agent.id, state)
      Map.merge(criticality, %{
        agent_id: agent.id,
        hostname: agent.hostname,
        os_type: agent.os_type
      })
    end)
    |> Enum.filter(fn a -> a.level in [:critical, :high] end)
    |> Enum.sort_by(& &1.score, :desc)

    {:reply, critical_assets, state}
  end

  @impl true
  def handle_call({:refresh, agent_id}, _from, state) do
    # Force re-analysis
    new_cache = Map.delete(state.criticality_cache, agent_id)
    new_auto = Map.delete(state.auto_discovered, agent_id)
    new_state = %{state | criticality_cache: new_cache, auto_discovered: new_auto}

    result = calculate_criticality(agent_id, new_state)
    {:reply, {:ok, result}, new_state}
  end

  @impl true
  def handle_call({:bulk_import, assets}, _from, state) do
    count = Enum.reduce(assets, 0, fn asset, acc ->
      case validate_criticality_attrs(asset) do
        :ok ->
          agent_id = asset[:agent_id] || asset["agent_id"]
          if agent_id do
            override = Map.merge(%{
              agent_id: agent_id,
              updated_at: DateTime.utc_now()
            }, normalize_attrs(asset))
            save_override(agent_id, override)
            acc + 1
          else
            acc
          end

        _ ->
          acc
      end
    end)

    # Reload overrides
    new_overrides = load_overrides()
    {:reply, {:ok, count}, %{state | custom_overrides: new_overrides}}
  end

  @impl true
  def handle_call({:get_distribution, org_id}, _from, state) do
    agents = list_agents(org_id)

    distribution = agents
    |> Enum.map(fn agent -> calculate_criticality(agent.id, state) end)
    |> Enum.group_by(& &1.level)
    |> Enum.map(fn {level, items} -> {level, length(items)} end)
    |> Map.new()

    # Ensure all levels are present
    full_distribution = @levels
    |> Enum.map(fn level -> {level, Map.get(distribution, level, 0)} end)
    |> Map.new()

    {:reply, full_distribution, state}
  end

  @impl true
  def handle_info(:refresh_all, state) do
    Logger.debug("Refreshing all asset criticality data")

    # Clear cache to force recalculation
    new_state = %{state |
      criticality_cache: %{},
      auto_discovered: %{},
      last_refresh: DateTime.utc_now()
    }

    schedule_refresh()
    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp calculate_criticality(agent_id, state) do
    # Check for manual override first
    case Map.get(state.custom_overrides, agent_id) do
      nil ->
        # Auto-calculate
        auto_calculate_criticality(agent_id, state)

      override ->
        # Use override with auto-detected supplements
        auto = auto_calculate_criticality(agent_id, state)
        merge_override_with_auto(override, auto)
    end
  end

  defp auto_calculate_criticality(agent_id, _state) do
    # Get agent info
    agent = get_agent(agent_id)

    if agent do
      # Detect role
      {role, role_factors} = detect_role(agent)

      # Get base score from role
      base_score = Map.get(@role_scores, role, 50)

      # Apply modifiers
      {data_sensitivity, sensitivity_factor} = detect_data_sensitivity(agent)
      {compliance, compliance_factor} = detect_compliance_requirements(agent)
      user_privilege_factor = detect_user_privilege(agent)

      # Calculate final score
      modified_score = base_score * sensitivity_factor * compliance_factor * user_privilege_factor

      # Clamp to 0-100
      final_score = min(max(round(modified_score), 0), 100)

      # Determine level from score
      level = score_to_level(final_score)

      # Collect factors
      factors = role_factors ++
        [data_sensitivity, compliance] ++
        if(user_privilege_factor > 1.0, do: ["privileged_access"], else: [])

      %{
        level: level,
        score: final_score,
        role: role,
        data_sensitivity: data_sensitivity,
        compliance: compliance,
        factors: Enum.filter(factors, & &1 != nil and &1 != "none"),
        auto_discovered: true,
        override: false,
        agent: %{
          id: agent.id,
          hostname: agent.hostname,
          os_type: agent.os_type,
          tags: agent.tags || []
        }
      }
    else
      # Unknown agent - return default
      %{
        level: :medium,
        score: 50,
        role: "unknown",
        data_sensitivity: "internal",
        compliance: "none",
        factors: [],
        auto_discovered: true,
        override: false,
        agent: nil
      }
    end
  end

  defp merge_override_with_auto(override, auto) do
    # Override takes precedence, but we keep auto-detected info as supplements
    role = override[:role] || auto.role
    score = override[:score] || auto.score
    level = if override[:level], do: override[:level], else: score_to_level(score)

    %{
      level: level,
      score: score,
      role: role,
      data_sensitivity: override[:data_sensitivity] || auto.data_sensitivity,
      compliance: override[:compliance] || auto.compliance,
      factors: override[:factors] || auto.factors,
      auto_discovered: false,
      override: true,
      override_reason: override[:reason],
      overridden_at: override[:updated_at],
      agent: auto.agent
    }
  end

  defp detect_role(agent) do
    hostname = String.downcase(agent.hostname || "")
    os_type = String.downcase(agent.os_type || "")
    tags = agent.tags || []

    cond do
      # Check tags first (most explicit)
      "domain_controller" in tags or "dc" in tags ->
        {"domain_controller", ["tagged_as_dc"]}

      "database" in tags or "db" in tags ->
        {"database_server", ["tagged_as_database"]}

      # Check hostname patterns
      matches_patterns?(hostname, @dc_indicators) ->
        {"domain_controller", ["hostname_pattern_dc"]}

      matches_patterns?(hostname, @db_indicators) ->
        {"database_server", ["hostname_pattern_db"]}

      matches_patterns?(hostname, @ca_indicators) ->
        {"certificate_authority", ["hostname_pattern_ca"]}

      # Check OS type for server vs workstation
      String.contains?(os_type, "server") ->
        detect_server_role(agent)

      String.contains?(os_type, "windows") ->
        detect_workstation_role(agent)

      String.contains?(os_type, ["linux", "unix"]) ->
        detect_linux_role(agent)

      true ->
        {"unknown", []}
    end
  end

  defp matches_patterns?(value, patterns) do
    Enum.any?(patterns, fn pattern ->
      case pattern do
        %Regex{} = regex -> Regex.match?(regex, value)
        str when is_binary(str) -> String.contains?(value, String.downcase(str))
        _ -> false
      end
    end)
  end

  defp detect_server_role(agent) do
    hostname = String.downcase(agent.hostname || "")
    tags = agent.tags || []

    cond do
      String.contains?(hostname, ["web", "www", "http"]) or "web" in tags ->
        {"web_server", ["hostname_pattern_web"]}

      String.contains?(hostname, ["app", "api"]) or "application" in tags ->
        {"application_server", ["hostname_pattern_app"]}

      String.contains?(hostname, ["file", "nas", "share"]) or "file_server" in tags ->
        {"file_server", ["hostname_pattern_file"]}

      String.contains?(hostname, ["mail", "smtp", "exchange"]) or "mail" in tags ->
        {"mail_server", ["hostname_pattern_mail"]}

      String.contains?(hostname, ["backup", "veeam", "dpm"]) or "backup" in tags ->
        {"backup_server", ["hostname_pattern_backup"]}

      String.contains?(hostname, ["jump", "bastion"]) or "bastion" in tags ->
        {"jump_box", ["hostname_pattern_bastion"]}

      String.contains?(hostname, ["prod"]) or "production" in tags ->
        {"production_server", ["environment_production"]}

      String.contains?(hostname, ["stage", "staging"]) or "staging" in tags ->
        {"staging_server", ["environment_staging"]}

      String.contains?(hostname, ["dev"]) or "development" in tags ->
        {"development_server", ["environment_development"]}

      String.contains?(hostname, ["test", "qa"]) or "test" in tags ->
        {"test_server", ["environment_test"]}

      true ->
        {"production_server", ["default_server"]}
    end
  end

  defp detect_workstation_role(agent) do
    tags = agent.tags || []
    hostname = String.downcase(agent.hostname || "")

    cond do
      "admin" in tags or String.contains?(hostname, "admin") ->
        {"workstation_admin", ["tagged_admin"]}

      "privileged" in tags or "executive" in tags ->
        {"workstation_privileged", ["tagged_privileged"]}

      "kiosk" in tags ->
        {"kiosk", ["tagged_kiosk"]}

      true ->
        {"workstation_standard", ["default_workstation"]}
    end
  end

  defp detect_linux_role(agent) do
    hostname = String.downcase(agent.hostname || "")
    tags = agent.tags || []

    cond do
      String.contains?(hostname, ["docker", "k8s", "kube", "container"]) ->
        {"production_server", ["container_host"]}

      String.contains?(hostname, ["db", "mysql", "postgres", "mongo"]) ->
        {"database_server", ["hostname_pattern_db"]}

      "production" in tags ->
        {"production_server", ["tagged_production"]}

      true ->
        {"production_server", ["default_linux_server"]}
    end
  end

  defp detect_data_sensitivity(agent) do
    tags = agent.tags || []

    cond do
      Enum.any?(tags, &(&1 in ["classified", "secret", "top_secret"])) ->
        {"classified", @sensitivity_modifiers["classified"]}

      Enum.any?(tags, &(&1 in ["pii", "personal_data", "customer_data"])) ->
        {"pii", @sensitivity_modifiers["pii"]}

      Enum.any?(tags, &(&1 in ["phi", "healthcare", "medical"])) ->
        {"phi", @sensitivity_modifiers["phi"]}

      Enum.any?(tags, &(&1 in ["pci", "payment", "cardholder"])) ->
        {"pci", @sensitivity_modifiers["pci"]}

      Enum.any?(tags, &(&1 in ["financial", "banking", "trading"])) ->
        {"financial", @sensitivity_modifiers["financial"]}

      Enum.any?(tags, &(&1 in ["ip", "intellectual_property", "source_code"])) ->
        {"intellectual_property", @sensitivity_modifiers["intellectual_property"]}

      Enum.any?(tags, &(&1 in ["public", "dmz"])) ->
        {"public", @sensitivity_modifiers["public"]}

      true ->
        {"internal", @sensitivity_modifiers["internal"]}
    end
  end

  defp detect_compliance_requirements(agent) do
    tags = agent.tags || []

    cond do
      Enum.any?(tags, &String.contains?(String.downcase(&1), "fedramp")) ->
        {"fedramp", @compliance_modifiers["fedramp"]}

      Enum.any?(tags, &String.contains?(String.downcase(&1), "hipaa")) ->
        {"hipaa", @compliance_modifiers["hipaa"]}

      Enum.any?(tags, &String.contains?(String.downcase(&1), "pci")) ->
        {"pci_dss", @compliance_modifiers["pci_dss"]}

      Enum.any?(tags, &String.contains?(String.downcase(&1), "fisma")) ->
        {"fisma", @compliance_modifiers["fisma"]}

      Enum.any?(tags, &String.contains?(String.downcase(&1), "sox")) ->
        {"sox", @compliance_modifiers["sox"]}

      Enum.any?(tags, &String.contains?(String.downcase(&1), "gdpr")) ->
        {"gdpr", @compliance_modifiers["gdpr"]}

      true ->
        {"none", @compliance_modifiers["none"]}
    end
  end

  defp detect_user_privilege(agent) do
    tags = agent.tags || []

    cond do
      Enum.any?(tags, &(&1 in ["admin", "administrator", "root", "domain_admin"])) ->
        1.3

      Enum.any?(tags, &(&1 in ["privileged", "service_account", "executive"])) ->
        1.15

      true ->
        1.0
    end
  end

  defp score_to_level(score) when score >= 90, do: :critical
  defp score_to_level(score) when score >= 70, do: :high
  defp score_to_level(score) when score >= 50, do: :medium
  defp score_to_level(score) when score >= 30, do: :low
  defp score_to_level(_score), do: :minimal

  defp get_agent(agent_id) do
    try do
      Repo.get(Agent, agent_id)
    rescue
      _ -> nil
    end
  end

  defp list_agents(nil) do
    try do
      Repo.all(Agent)
    rescue
      _ -> []
    end
  end

  defp list_agents(org_id) do
    try do
      from(a in Agent, where: a.organization_id == ^org_id)
      |> Repo.all()
    rescue
      _ -> []
    end
  end

  defp validate_criticality_attrs(attrs) do
    cond do
      Map.has_key?(attrs, :level) and attrs.level not in @levels ->
        {:error, "Invalid criticality level"}

      Map.has_key?(attrs, :score) and (attrs.score < 0 or attrs.score > 100) ->
        {:error, "Score must be between 0 and 100"}

      true ->
        :ok
    end
  end

  defp normalize_attrs(attrs) do
    attrs
    |> Map.new(fn {k, v} ->
      key = if is_binary(k), do: String.to_atom(k), else: k
      {key, v}
    end)
  end

  defp load_overrides do
    try do
      query = from(c in "asset_criticality",
        select: {c.agent_id, %{
          agent_id: c.agent_id,
          level: c.level,
          score: c.score,
          role: c.role,
          data_sensitivity: c.data_sensitivity,
          compliance: c.compliance,
          factors: c.factors,
          reason: c.reason,
          updated_at: c.updated_at
        }}
      )

      Repo.all(query) |> Map.new()
    rescue
      _ -> %{}
    end
  end

  defp save_override(agent_id, override) do
    try do
      Repo.insert_all("asset_criticality", [%{
        id: Ecto.UUID.generate(),
        agent_id: agent_id,
        level: to_string(override[:level]),
        score: override[:score],
        role: override[:role],
        data_sensitivity: override[:data_sensitivity],
        compliance: override[:compliance],
        factors: override[:factors],
        reason: override[:reason],
        updated_at: override[:updated_at],
        inserted_at: DateTime.utc_now()
      }],
      on_conflict: {:replace, [:level, :score, :role, :data_sensitivity, :compliance, :factors, :reason, :updated_at]},
      conflict_target: :agent_id)
    rescue
      e -> Logger.error("Failed to save criticality override: #{inspect(e)}")
    end
  end

  defp delete_override(agent_id) do
    try do
      Repo.delete_all(from c in "asset_criticality", where: c.agent_id == ^agent_id)
    rescue
      _ -> :ok
    end
  end

  defp schedule_refresh do
    # Refresh every 6 hours
    Process.send_after(self(), :refresh_all, :timer.hours(6))
  end
end
