defmodule TamanduaServer.Detection.PreventionPolicy do
  @moduledoc """
  Prevention Policy system inspired by CrowdStrike Falcon.

  Policies define detection sensitivity and response mode per threat category.
  Each policy can be assigned to agent groups, allowing different security postures.

  ## Aggressiveness Levels
  - :disabled - No detection or blocking
  - :cautious - Only high-confidence threats (minimize false positives)
  - :moderate - Balanced detection (recommended default)
  - :aggressive - High sensitivity (more detections, some false positives)
  - :extra_aggressive - Maximum sensitivity (highest FP rate)

  ## Response Modes
  - :detect_only - Log and alert, never auto-block
  - :detect_and_prevent - Log, alert, and auto-block above threshold

  ## Threat Categories
  - :malware_ml - Machine learning malware prevention
  - :behavioral_ioa - Behavior-based Indicators of Attack
  - :exploit_prevention - Exploit mitigation (buffer overflow, ROP, etc.)
  - :ransomware - Ransomware-specific protections
  - :script_execution - Script-based execution control (PowerShell, VBS, etc.)
  - :credential_theft - Credential access prevention
  - :lateral_movement - Lateral movement prevention
  - :fileless_attack - Fileless/memory-only attack prevention
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts.Organization

  @type t :: %__MODULE__{}

  @aggressiveness_levels [:disabled, :cautious, :moderate, :aggressive, :extra_aggressive]
  @response_modes [:detect_only, :detect_and_prevent]
  @threat_categories [
    :malware_ml, :behavioral_ioa, :exploit_prevention, :ransomware,
    :script_execution, :credential_theft, :lateral_movement, :fileless_attack
  ]

  # Threshold multipliers per aggressiveness level
  # These multiply the base threat_threshold to determine when to alert/block
  @aggressiveness_thresholds %{
    disabled: %{alert: 999.0, block: 999.0},  # Never triggers
    cautious: %{alert: 0.85, block: 0.95},     # Only high-confidence
    moderate: %{alert: 0.75, block: 0.90},      # Balanced (default)
    aggressive: %{alert: 0.60, block: 0.80},    # More sensitive
    extra_aggressive: %{alert: 0.45, block: 0.70} # Maximum sensitivity
  }

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "prevention_policies" do
    field :name, :string
    field :description, :string
    field :is_default, :boolean, default: false
    field :is_enabled, :boolean, default: true

    # Per-category settings stored as JSON map
    # Example: %{"malware_ml" => %{"aggressiveness" => "aggressive", "mode" => "detect_and_prevent"}}
    field :category_settings, :map, default: %{}

    # Global overrides
    field :global_mode, :string, default: "detect_and_prevent"  # detect_only | detect_and_prevent
    field :global_aggressiveness, :string, default: "moderate"

    # Agent groups this policy applies to (list of group names/IDs)
    field :assigned_groups, {:array, :string}, default: []
    # Specific agent IDs this policy applies to
    field :assigned_agents, {:array, :string}, default: []

    # Exclusions
    field :excluded_paths, {:array, :string}, default: []
    field :excluded_processes, {:array, :string}, default: []
    field :excluded_hashes, {:array, :string}, default: []
    field :excluded_users, {:array, :string}, default: []

    # ML Response configuration
    field :auto_quarantine_threshold, :float, default: 0.90
    field :auto_kill_process, :boolean, default: false
    field :ml_response_enabled, :boolean, default: true
    field :alert_threshold, :float, default: 0.75

    # Network Containment
    field :network_containment, :map, default: %{"allow_dns" => true, "allowed_ips" => []}

    belongs_to :organization, Organization

    timestamps()
  end

  def changeset(policy, attrs) do
    attrs = normalize_attrs(attrs)

    policy
    |> cast(attrs, [
      :name, :description, :is_default, :is_enabled,
      :category_settings, :global_mode, :global_aggressiveness,
      :assigned_groups, :assigned_agents,
      :excluded_paths, :excluded_processes, :excluded_hashes, :excluded_users,
      :auto_quarantine_threshold, :auto_kill_process, :ml_response_enabled, :alert_threshold,
      :network_containment, :organization_id
    ])
    |> validate_required([:name])
    |> validate_inclusion(:global_mode, ["detect_only", "detect_and_prevent"])
    |> validate_inclusion(:global_aggressiveness, Enum.map(@aggressiveness_levels, &Atom.to_string/1))
    |> validate_number(:auto_quarantine_threshold, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> validate_number(:alert_threshold, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> unique_constraint(:name)
  end

  # ============================================================
  # PUBLIC API
  # ============================================================

  @doc "Get the effective policy for an agent. Falls back to default policy."
  def get_policy_for_agent(agent_id, opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)

    # First check for agent-specific policy
    agent_policy =
      from(p in __MODULE__,
        where: ^agent_id in p.assigned_agents and p.is_enabled == true,
        limit: 1
      )
      |> maybe_filter_by_org(organization_id)
      |> Repo.one()

    if agent_policy do
      agent_policy
    else
      # Fall back to default policy
      get_default_policy(organization_id)
    end
  end

  @doc "Get the default policy."
  def get_default_policy(organization_id \\ nil) do
    query =
      from(p in __MODULE__,
        where: p.is_default == true,
        limit: 1
      )
      |> maybe_filter_by_org(organization_id)

    case Repo.one(query) do
      nil -> build_default_policy()
      policy -> policy
    end
  end

  @doc "Create or update the default policies on startup."
  def ensure_default_policies! do
    unless Repo.exists?(from p in __MODULE__, where: p.is_default == true) do
      # Create 3 preset policies
      presets = [
        %{
          name: "Default - Moderate",
          description: "Balanced detection and prevention. Recommended for most environments.",
          is_default: true,
          global_aggressiveness: "moderate",
          global_mode: "detect_and_prevent",
          category_settings: default_category_settings("moderate", "detect_and_prevent")
        },
        %{
          name: "High Security",
          description: "Aggressive detection with maximum prevention. For high-value targets.",
          is_default: false,
          global_aggressiveness: "aggressive",
          global_mode: "detect_and_prevent",
          category_settings: default_category_settings("aggressive", "detect_and_prevent")
        },
        %{
          name: "Monitor Only",
          description: "Detect-only mode. No automatic blocking or containment.",
          is_default: false,
          global_aggressiveness: "moderate",
          global_mode: "detect_only",
          category_settings: default_category_settings("moderate", "detect_only")
        }
      ]

      Enum.each(presets, fn attrs ->
        %__MODULE__{}
        |> changeset(attrs)
        |> Repo.insert!(on_conflict: :nothing, conflict_target: :name)
      end)
    end
  end

  @doc """
  Evaluate whether an event should be alerted and/or blocked based on the policy.

  Returns:
    %{action: :ignore | :alert | :alert_and_block, severity: String.t(), reason: String.t()}
  """
  def evaluate_event(agent_id, event, threat_score, threat_category) do
    organization_id = event[:organization_id] || event["organization_id"]
    policy = get_policy_for_agent(agent_id, organization_id: organization_id)
    category_key = Atom.to_string(threat_category)

    # Get per-category settings or fall back to global
    {aggressiveness, mode} = get_category_config(policy, category_key)

    # Check exclusions first
    if excluded?(policy, event) do
      decision(policy, threat_category, aggressiveness, mode, nil, :ignore, "none", "Excluded by policy")
    else
      thresholds = Map.get(@aggressiveness_thresholds, aggressiveness, @aggressiveness_thresholds.moderate)

      cond do
        # Below alert threshold - ignore
        threat_score < thresholds.alert ->
          decision(policy, threat_category, aggressiveness, mode, thresholds, :ignore, severity_from_score(threat_score), "Below #{aggressiveness} alert threshold (#{thresholds.alert})")

        # Above block threshold AND mode is prevent
        threat_score >= thresholds.block and mode == :detect_and_prevent ->
          decision(policy, threat_category, aggressiveness, mode, thresholds, :alert_and_block, severity_from_score(threat_score), "Above #{aggressiveness} block threshold (#{thresholds.block}), auto-prevention enabled")

        # Above alert threshold but below block, or mode is detect_only
        true ->
          decision(policy, threat_category, aggressiveness, mode, thresholds, :alert, severity_from_score(threat_score), "Above #{aggressiveness} alert threshold (#{thresholds.alert}), #{mode} mode")
      end
    end
  end

  @doc "List all policies."
  def list_policies(opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)

    from(p in __MODULE__, order_by: [desc: p.is_default, asc: p.name])
    |> maybe_filter_by_org(organization_id)
    |> Repo.all()
  end

  @doc "Get a policy by ID."
  def get_policy!(id), do: Repo.get!(__MODULE__, id)

  @doc "Create a new policy."
  def create_policy(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc "Update a policy."
  def update_policy(%__MODULE__{} = policy, attrs) do
    policy
    |> changeset(attrs)
    |> Repo.update()
  end

  @doc "Delete a policy (cannot delete default)."
  def delete_policy(%__MODULE__{is_default: true}), do: {:error, "Cannot delete default policy"}
  def delete_policy(%__MODULE__{} = policy), do: Repo.delete(policy)

  @doc "Assign a policy to specific agents."
  def assign_to_agents(%__MODULE__{} = policy, agent_ids) when is_list(agent_ids) do
    current = policy.assigned_agents || []
    new_agents = Enum.uniq(current ++ agent_ids)
    update_policy(policy, %{assigned_agents: new_agents})
  end

  @doc "Remove agents from a policy."
  def unassign_agents(%__MODULE__{} = policy, agent_ids) when is_list(agent_ids) do
    current = policy.assigned_agents || []
    remaining = Enum.reject(current, &(&1 in agent_ids))
    update_policy(policy, %{assigned_agents: remaining})
  end

  @doc "Get summary of aggressiveness levels with their thresholds."
  def aggressiveness_summary do
    Enum.map(@aggressiveness_levels, fn level ->
      thresholds = Map.get(@aggressiveness_thresholds, level)
      %{
        level: level,
        label: aggressiveness_label(level),
        description: aggressiveness_description(level),
        alert_threshold: thresholds.alert,
        block_threshold: thresholds.block
      }
    end)
  end

  @doc "Get all threat categories with descriptions."
  def threat_categories do
    Enum.map(@threat_categories, fn cat ->
      %{key: cat, label: category_label(cat), description: category_description(cat)}
    end)
  end

  @doc """
  Get ML response settings for an agent.

  Returns a map with:
  - :ml_response_enabled - Whether ML response is enabled
  - :auto_quarantine_threshold - Confidence threshold for auto-quarantine
  - :auto_kill_process - Whether to auto-kill associated process
  - :alert_threshold - Confidence threshold for creating alerts
  """
  @spec get_ml_response_settings(String.t()) :: map()
  def get_ml_response_settings(agent_id) do
    policy = get_policy_for_agent(agent_id)

    %{
      ml_response_enabled: policy.ml_response_enabled,
      auto_quarantine_threshold: policy.auto_quarantine_threshold,
      auto_kill_process: policy.auto_kill_process,
      alert_threshold: policy.alert_threshold
    }
  end

  @doc """
  Alias for get_policy_for_agent/1 to match MLResponse module expectations.
  """
  @spec get_for_agent(String.t()) :: t()
  def get_for_agent(agent_id), do: get_policy_for_agent(agent_id)

  # ============================================================
  # PRIVATE HELPERS
  # ============================================================

  defp normalize_attrs(attrs) when is_map(attrs) do
    attrs = Map.new(attrs, fn {key, value} -> {to_string(key), value} end)

    attrs
    |> put_if_present("global_mode", attrs["mode"])
    |> put_if_present("global_aggressiveness", attrs["aggressiveness"])
    |> put_if_present("is_default", attrs["isDefault"])
    |> put_if_present("is_enabled", attrs["isEnabled"])
    |> put_if_present("assigned_agents", normalize_assigned_agents(attrs["assigned_agents"] || attrs["assignedAgents"]))
    |> put_if_present("assigned_groups", attrs["assigned_groups"] || attrs["assignedGroups"])
    |> put_if_present("excluded_paths", get_in(attrs, ["exclusions", "paths"]) || attrs["excludedPaths"])
    |> put_if_present("excluded_processes", get_in(attrs, ["exclusions", "processes"]) || attrs["excludedProcesses"])
    |> put_if_present("excluded_hashes", get_in(attrs, ["exclusions", "hashes"]) || attrs["excludedHashes"])
    |> put_if_present("excluded_users", get_in(attrs, ["exclusions", "users"]) || attrs["excludedUsers"])
    |> put_if_present("category_settings", normalize_category_settings(attrs["category_settings"] || attrs["categorySettings"]))
    |> put_if_present("network_containment", attrs["network_containment"] || attrs["networkContainment"])
    |> put_if_present("auto_quarantine_threshold", attrs["autoQuarantineThreshold"])
    |> put_if_present("auto_kill_process", attrs["autoKillProcess"])
    |> put_if_present("ml_response_enabled", attrs["mlResponseEnabled"])
    |> put_if_present("alert_threshold", attrs["alertThreshold"])
  end

  defp normalize_attrs(attrs), do: attrs

  defp put_if_present(attrs, _key, nil), do: attrs
  defp put_if_present(attrs, key, value), do: Map.put(attrs, key, value)

  defp normalize_assigned_agents(nil), do: nil
  defp normalize_assigned_agents(agents) when is_list(agents) do
    Enum.map(agents, fn
      %{"id" => id} -> id
      %{id: id} -> id
      id -> id
    end)
    |> Enum.reject(&is_nil/1)
  end
  defp normalize_assigned_agents(other), do: other

  defp normalize_category_settings(nil), do: nil
  defp normalize_category_settings(settings) when is_map(settings), do: settings
  defp normalize_category_settings(settings) when is_list(settings) do
    settings
    |> Enum.reduce(%{}, fn setting, acc ->
      setting = Map.new(setting, fn {key, value} -> {to_string(key), value} end)
      category = normalize_category_key(setting["category"])

      if category do
        Map.put(acc, category, %{
          "aggressiveness" => setting["aggressiveness"] || "moderate",
          "mode" => setting["mode"] || "detect_and_prevent"
        })
      else
        acc
      end
    end)
  end
  defp normalize_category_settings(other), do: other

  defp normalize_category_key("machine_learning"), do: "malware_ml"
  defp normalize_category_key(category) when is_binary(category), do: category
  defp normalize_category_key(category) when is_atom(category), do: Atom.to_string(category)
  defp normalize_category_key(_), do: nil

  defp decision(policy, threat_category, aggressiveness, mode, thresholds, action, severity, reason) do
    %{
      action: action,
      severity: severity,
      reason: reason,
      policy_id: policy.id,
      policy_name: policy.name,
      policy_mode: Atom.to_string(mode),
      policy_aggressiveness: Atom.to_string(aggressiveness),
      threat_category: Atom.to_string(threat_category),
      alert_threshold: thresholds && thresholds.alert,
      block_threshold: thresholds && thresholds.block
    }
  end

  defp get_category_config(policy, category_key) do
    category_settings = policy.category_settings || %{}

    case Map.get(category_settings, category_key) do
      %{"aggressiveness" => agg, "mode" => mode} ->
        {safe_atom(agg, :moderate), safe_atom(mode, :detect_and_prevent)}
      _ ->
        {safe_atom(policy.global_aggressiveness, :moderate), safe_atom(policy.global_mode, :detect_and_prevent)}
    end
  end

  defp excluded?(policy, event) do
    payload = event[:payload] || %{}
    path = payload[:path] || payload[:file_path] || ""
    process = payload[:process_name] || payload[:name] || ""
    hash = payload[:sha256] || payload[:hash] || ""
    user = payload[:user] || payload[:username] || ""

    path_lower = String.downcase(path)
    process_lower = String.downcase(process)

    Enum.any?(policy.excluded_paths || [], fn exc -> String.contains?(path_lower, String.downcase(exc)) end) or
    Enum.any?(policy.excluded_processes || [], fn exc -> String.downcase(exc) == process_lower end) or
    (hash != "" and hash in (policy.excluded_hashes || [])) or
    (user != "" and String.downcase(user) in Enum.map(policy.excluded_users || [], &String.downcase/1))
  end

  defp severity_from_score(score) do
    cond do
      score >= 0.9 -> "critical"
      score >= 0.75 -> "high"
      score >= 0.5 -> "medium"
      score >= 0.25 -> "low"
      true -> "info"
    end
  end

  defp safe_atom(val, default) when is_binary(val) do
    try do
      String.to_existing_atom(val)
    rescue
      _ -> default
    end
  end
  defp safe_atom(val, _default) when is_atom(val), do: val
  defp safe_atom(_, default), do: default

  defp build_default_policy do
    %__MODULE__{
      name: "Default - Moderate",
      description: "Balanced detection and prevention",
      is_default: true,
      is_enabled: true,
      global_aggressiveness: "moderate",
      global_mode: "detect_and_prevent",
      category_settings: default_category_settings("moderate", "detect_and_prevent"),
      assigned_groups: [],
      assigned_agents: [],
      excluded_paths: [],
      excluded_processes: [],
      excluded_hashes: [],
      excluded_users: [],
      # ML Response defaults
      auto_quarantine_threshold: 0.90,
      auto_kill_process: false,
      ml_response_enabled: true,
      alert_threshold: 0.75,
      network_containment: %{"allow_dns" => true, "allowed_ips" => []}
    }
  end

  defp default_category_settings(aggressiveness, mode) do
    @threat_categories
    |> Enum.map(fn cat ->
      {Atom.to_string(cat), %{"aggressiveness" => aggressiveness, "mode" => mode}}
    end)
    |> Map.new()
  end

  defp aggressiveness_label(:disabled), do: "Disabled"
  defp aggressiveness_label(:cautious), do: "Cautious"
  defp aggressiveness_label(:moderate), do: "Moderate"
  defp aggressiveness_label(:aggressive), do: "Aggressive"
  defp aggressiveness_label(:extra_aggressive), do: "Extra Aggressive"

  defp aggressiveness_description(:disabled), do: "No detection or blocking. For testing environments only."
  defp aggressiveness_description(:cautious), do: "Only high-confidence threats. Minimizes false positives."
  defp aggressiveness_description(:moderate), do: "Balanced detection. Recommended for most environments."
  defp aggressiveness_description(:aggressive), do: "High sensitivity. More detections, some false positives expected."
  defp aggressiveness_description(:extra_aggressive), do: "Maximum sensitivity. Highest detection rate with elevated false positives."

  defp category_label(:malware_ml), do: "Machine Learning"
  defp category_label(:behavioral_ioa), do: "Behavioral IOA"
  defp category_label(:exploit_prevention), do: "Exploit Prevention"
  defp category_label(:ransomware), do: "Ransomware"
  defp category_label(:script_execution), do: "Script Execution"
  defp category_label(:credential_theft), do: "Credential Theft"
  defp category_label(:lateral_movement), do: "Lateral Movement"
  defp category_label(:fileless_attack), do: "Fileless Attack"

  defp category_description(:malware_ml), do: "ML-based malware detection using binary analysis and behavioral signals."
  defp category_description(:behavioral_ioa), do: "Behavior-based Indicators of Attack using process trees and command patterns."
  defp category_description(:exploit_prevention), do: "Protection against buffer overflows, ROP chains, heap spray, and JIT spray."
  defp category_description(:ransomware), do: "Ransomware detection via canary files, rapid encryption, and shadow copy deletion."
  defp category_description(:script_execution), do: "Control over PowerShell, VBScript, JScript, and other script interpreters."
  defp category_description(:credential_theft), do: "Detection of credential dumping, Kerberoasting, DCSync, and LSASS access."
  defp category_description(:lateral_movement), do: "Detection of PsExec, WMI execution, remote service creation, and RDP abuse."
  defp category_description(:fileless_attack), do: "Detection of in-memory attacks, process injection, and reflective DLL loading."

  defp maybe_filter_by_org(query, nil), do: query
  defp maybe_filter_by_org(query, organization_id) do
    where(query, [p], p.organization_id == ^organization_id or is_nil(p.organization_id))
  end
end
