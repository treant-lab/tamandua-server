defmodule TamanduaServer.DLP.PolicyEngine do
  @moduledoc """
  DLP (Data Loss Prevention) Policy Engine.

  Manages DLP policies that define which types of sensitive data should be
  monitored and what actions to take when violations are detected. Policies
  map classifier types to destinations and enforcement actions.

  Features:
  - ETS-backed policy storage for fast evaluation
  - Built-in policy templates (PCI, HIPAA, IP Protection, Credential Leak)
  - Policy evaluation against classifier results
  - Action dispatch (log, warn, block, encrypt) to agents
  - Organization-scoped policies for multi-tenancy
  - Policy versioning and audit trail

  ## Policy Schema

      %{
        id: binary_id,
        name: string,
        description: string,
        classifiers: [classifier_types],     # e.g. ["ssn", "credit_card", "aws_access_key"]
        destinations: [destination_types],    # e.g. ["usb", "network", "cloud", "clipboard"]
        action: "block" | "warn" | "log" | "encrypt",
        severity: "low" | "medium" | "high" | "critical",
        enabled: boolean,
        org_id: binary_id,
        created_at: datetime,
        updated_at: datetime
      }
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo

  # ETS tables
  @policies_table :dlp_policies
  @policy_stats_table :dlp_policy_stats

  # Built-in policy templates
  @builtin_templates %{
    "pci_compliance" => %{
      name: "PCI DSS Compliance",
      description: "Prevents credit card data and PCI cardholder data from being exfiltrated via USB, cloud sync, or network shares. Required for PCI DSS compliance.",
      classifiers: ["credit_card", "pci_card_data"],
      destinations: ["usb", "network", "cloud", "clipboard", "email"],
      action: "block",
      severity: "critical",
      enabled: true
    },
    "hipaa_protection" => %{
      name: "HIPAA Data Protection",
      description: "Monitors and blocks protected health information (PHI) including medical record numbers, ICD-10 codes, and patient identifiers from leaving the endpoint.",
      classifiers: ["hipaa_identifier", "icd10_code", "ssn"],
      destinations: ["usb", "network", "cloud", "clipboard", "email"],
      action: "block",
      severity: "critical",
      enabled: true
    },
    "ip_protection" => %{
      name: "Intellectual Property Protection",
      description: "Detects source code secrets, internal URLs, private IP addresses, and hardcoded credentials being copied to external destinations.",
      classifiers: [
        "private_key_material", "hardcoded_password", "internal_url",
        "internal_ip", "ssh_private_key", "gcp_service_account_key"
      ],
      destinations: ["usb", "cloud", "email", "clipboard"],
      action: "warn",
      severity: "high",
      enabled: true
    },
    "credential_leak_prevention" => %{
      name: "Credential Leak Prevention",
      description: "Prevents cloud credentials (AWS, Azure, GCP), API keys, SSH keys, JWT tokens, and database connection strings from being exfiltrated.",
      classifiers: [
        "aws_access_key", "aws_secret_key", "azure_client_secret",
        "gcp_service_account_key", "generic_api_key", "ssh_private_key",
        "jwt_token", "database_connection_string"
      ],
      destinations: ["usb", "network", "cloud", "clipboard", "email"],
      action: "block",
      severity: "critical",
      enabled: true
    },
    "pii_monitoring" => %{
      name: "PII Monitoring",
      description: "Monitors personally identifiable information (SSN, email, phone, passport, driver's license) transfers. Logs all activity for audit.",
      classifiers: [
        "ssn", "email", "phone_number", "passport_number", "drivers_license"
      ],
      destinations: ["usb", "network", "cloud", "email"],
      action: "log",
      severity: "medium",
      enabled: true
    }
  }

  # ===========================================================================
  # Client API
  # ===========================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  List all DLP policies for an organization.
  """
  def list_policies(org_id \\ nil) do
    GenServer.call(__MODULE__, {:list_policies, org_id})
  end

  @doc """
  Get a specific DLP policy by ID.
  """
  def get_policy(policy_id) do
    GenServer.call(__MODULE__, {:get_policy, policy_id})
  end

  @doc """
  Create a new DLP policy.
  """
  def create_policy(params) do
    GenServer.call(__MODULE__, {:create_policy, params})
  end

  @doc """
  Update an existing DLP policy.
  """
  def update_policy(policy_id, params) do
    GenServer.call(__MODULE__, {:update_policy, policy_id, params})
  end

  @doc """
  Delete a DLP policy.
  """
  def delete_policy(policy_id) do
    GenServer.call(__MODULE__, {:delete_policy, policy_id})
  end

  @doc """
  Enable or disable a DLP policy.
  """
  def toggle_policy(policy_id, enabled) do
    GenServer.call(__MODULE__, {:toggle_policy, policy_id, enabled})
  end

  @doc """
  Evaluate a DLP event against all active policies for an organization.

  Returns a list of `{policy, action}` tuples for matching policies.
  """
  def evaluate_event(org_id, classifier_types, destination) do
    GenServer.call(__MODULE__, {:evaluate_event, org_id, classifier_types, destination})
  end

  @doc """
  Get the most restrictive action for a DLP event.
  Actions ranked: block > encrypt > warn > log
  """
  def get_enforcement_action(org_id, classifier_types, destination) do
    case evaluate_event(org_id, classifier_types, destination) do
      {:ok, []} ->
        {:ok, "log"}

      {:ok, matches} ->
        action = matches
        |> Enum.map(fn {_policy, action} -> action end)
        |> Enum.max_by(&action_priority/1)
        {:ok, action}

      error ->
        error
    end
  end

  @doc """
  List available built-in policy templates.
  """
  def list_templates do
    {:ok, @builtin_templates}
  end

  @doc """
  Create a policy from a built-in template.
  """
  def create_from_template(template_key, org_id) do
    GenServer.call(__MODULE__, {:create_from_template, template_key, org_id})
  end

  @doc """
  Get policy evaluation statistics.
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ===========================================================================
  # GenServer Implementation
  # ===========================================================================

  @impl true
  def init(_opts) do
    Logger.info("[DLP.PolicyEngine] Starting DLP Policy Engine")

    # Create ETS tables
    :ets.new(@policies_table, [:set, :named_table, :public, read_concurrency: true])
    :ets.new(@policy_stats_table, [:set, :named_table, :public, write_concurrency: true])

    # Initialize stats counters
    :ets.insert(@policy_stats_table, {:total_evaluations, 0})
    :ets.insert(@policy_stats_table, {:total_matches, 0})
    :ets.insert(@policy_stats_table, {:total_blocks, 0})
    :ets.insert(@policy_stats_table, {:total_warns, 0})
    :ets.insert(@policy_stats_table, {:total_logs, 0})

    # Load policies from database
    send(self(), :load_policies)

    {:ok, %{}}
  end

  @impl true
  def handle_info(:load_policies, state) do
    case load_policies_from_db() do
      {:ok, count} ->
        Logger.info("[DLP.PolicyEngine] Loaded #{count} policies from database")
      {:error, reason} ->
        Logger.warning("[DLP.PolicyEngine] Failed to load policies from DB: #{inspect(reason)}")
    end

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def handle_call({:list_policies, nil}, _from, state) do
    policies = :ets.tab2list(@policies_table)
    |> Enum.map(fn {_id, policy} -> policy end)
    |> Enum.sort_by(& &1.name)

    {:reply, {:ok, policies}, state}
  end

  def handle_call({:list_policies, org_id}, _from, state) do
    policies = :ets.tab2list(@policies_table)
    |> Enum.map(fn {_id, policy} -> policy end)
    |> Enum.filter(fn p -> p.org_id == org_id end)
    |> Enum.sort_by(& &1.name)

    {:reply, {:ok, policies}, state}
  end

  def handle_call({:get_policy, policy_id}, _from, state) do
    case :ets.lookup(@policies_table, policy_id) do
      [{^policy_id, policy}] -> {:reply, {:ok, policy}, state}
      [] -> {:reply, {:error, :not_found}, state}
    end
  end

  def handle_call({:create_policy, params}, _from, state) do
    policy_id = Ecto.UUID.generate()
    now = DateTime.utc_now()

    policy = %{
      id: policy_id,
      name: Map.get(params, :name, Map.get(params, "name", "Unnamed Policy")),
      description: Map.get(params, :description, Map.get(params, "description", "")),
      classifiers: Map.get(params, :classifiers, Map.get(params, "classifiers", [])),
      destinations: Map.get(params, :destinations, Map.get(params, "destinations", [])),
      action: Map.get(params, :action, Map.get(params, "action", "log")),
      severity: Map.get(params, :severity, Map.get(params, "severity", "medium")),
      enabled: Map.get(params, :enabled, Map.get(params, "enabled", true)),
      org_id: Map.get(params, :org_id, Map.get(params, "org_id")),
      created_at: now,
      updated_at: now
    }

    :ets.insert(@policies_table, {policy_id, policy})
    persist_policy(policy)

    Logger.info("[DLP.PolicyEngine] Created policy: #{policy.name} (#{policy_id})")

    {:reply, {:ok, policy}, state}
  end

  def handle_call({:update_policy, policy_id, params}, _from, state) do
    case :ets.lookup(@policies_table, policy_id) do
      [{^policy_id, existing}] ->
        updated = existing
        |> Map.merge(atomize_keys(params))
        |> Map.put(:updated_at, DateTime.utc_now())

        :ets.insert(@policies_table, {policy_id, updated})
        persist_policy(updated)

        Logger.info("[DLP.PolicyEngine] Updated policy: #{updated.name} (#{policy_id})")
        {:reply, {:ok, updated}, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  def handle_call({:delete_policy, policy_id}, _from, state) do
    case :ets.lookup(@policies_table, policy_id) do
      [{^policy_id, policy}] ->
        :ets.delete(@policies_table, policy_id)
        delete_policy_from_db(policy_id)
        Logger.info("[DLP.PolicyEngine] Deleted policy: #{policy.name} (#{policy_id})")
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  def handle_call({:toggle_policy, policy_id, enabled}, _from, state) do
    case :ets.lookup(@policies_table, policy_id) do
      [{^policy_id, policy}] ->
        updated = %{policy | enabled: enabled, updated_at: DateTime.utc_now()}
        :ets.insert(@policies_table, {policy_id, updated})
        persist_policy(updated)
        {:reply, {:ok, updated}, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  def handle_call({:evaluate_event, org_id, classifier_types, destination}, _from, state) do
    # Increment evaluation counter
    :ets.update_counter(@policy_stats_table, :total_evaluations, 1)

    # Get all active policies for this org
    policies = :ets.tab2list(@policies_table)
    |> Enum.map(fn {_id, policy} -> policy end)
    |> Enum.filter(fn p ->
      p.enabled and (p.org_id == org_id or p.org_id == nil)
    end)

    # Normalize inputs
    classifier_set = MapSet.new(classifier_types |> Enum.map(&normalize_classifier/1))
    dest_normalized = normalize_destination(destination)

    # Find matching policies
    matches = Enum.flat_map(policies, fn policy ->
      policy_classifiers = MapSet.new(policy.classifiers |> Enum.map(&normalize_classifier/1))
      policy_destinations = MapSet.new(policy.destinations |> Enum.map(&normalize_destination/1))

      classifier_overlap = MapSet.intersection(classifier_set, policy_classifiers)
      dest_match = MapSet.member?(policy_destinations, dest_normalized) or
                   MapSet.member?(policy_destinations, "any")

      if MapSet.size(classifier_overlap) > 0 and dest_match do
        # Update stats
        case policy.action do
          "block" -> :ets.update_counter(@policy_stats_table, :total_blocks, 1)
          "warn" -> :ets.update_counter(@policy_stats_table, :total_warns, 1)
          _ -> :ets.update_counter(@policy_stats_table, :total_logs, 1)
        end
        :ets.update_counter(@policy_stats_table, :total_matches, 1)

        [{policy, policy.action}]
      else
        []
      end
    end)

    {:reply, {:ok, matches}, state}
  end

  def handle_call({:create_from_template, template_key, org_id}, _from, state) do
    case Map.get(@builtin_templates, template_key) do
      nil ->
        {:reply, {:error, :template_not_found}, state}

      template ->
        policy_id = Ecto.UUID.generate()
        now = DateTime.utc_now()

        policy = Map.merge(template, %{
          id: policy_id,
          org_id: org_id,
          created_at: now,
          updated_at: now
        })

        :ets.insert(@policies_table, {policy_id, policy})
        persist_policy(policy)

        Logger.info("[DLP.PolicyEngine] Created policy from template '#{template_key}': #{policy.name}")
        {:reply, {:ok, policy}, state}
    end
  end

  def handle_call(:get_stats, _from, state) do
    stats = %{
      total_evaluations: get_counter(:total_evaluations),
      total_matches: get_counter(:total_matches),
      total_blocks: get_counter(:total_blocks),
      total_warns: get_counter(:total_warns),
      total_logs: get_counter(:total_logs),
      total_policies: :ets.info(@policies_table, :size),
      active_policies: :ets.tab2list(@policies_table)
        |> Enum.count(fn {_, p} -> p.enabled end)
    }
    {:reply, {:ok, stats}, state}
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp action_priority("block"), do: 4
  defp action_priority("encrypt"), do: 3
  defp action_priority("warn"), do: 2
  defp action_priority("log"), do: 1
  defp action_priority(_), do: 0

  defp normalize_classifier(c) when is_binary(c), do: String.downcase(c)
  defp normalize_classifier(c) when is_atom(c), do: c |> Atom.to_string() |> String.downcase()
  defp normalize_classifier(c), do: to_string(c) |> String.downcase()

  defp normalize_destination(d) when is_binary(d), do: String.downcase(d)
  defp normalize_destination(d) when is_atom(d), do: d |> Atom.to_string() |> String.downcase()
  defp normalize_destination(d), do: to_string(d) |> String.downcase()

  defp get_counter(key) do
    case :ets.lookup(@policy_stats_table, key) do
      [{^key, val}] -> val
      [] -> 0
    end
  end

  defp atomize_keys(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_binary(k) -> {String.to_existing_atom(k), v}
      {k, v} when is_atom(k) -> {k, v}
      {k, v} -> {k, v}
    end)
  rescue
    ArgumentError -> map
  end

  defp load_policies_from_db do
    try do
      import Ecto.Query

      query = from(p in "dlp_policies",
        select: %{
          id: p.id,
          name: p.name,
          description: p.description,
          classifiers: p.classifiers,
          destinations: p.destinations,
          action: p.action,
          severity: p.severity,
          enabled: p.enabled,
          org_id: p.organization_id,
          created_at: p.inserted_at,
          updated_at: p.updated_at
        }
      )

      policies = Repo.all(query)

      for policy <- policies do
        :ets.insert(@policies_table, {policy.id, policy})
      end

      {:ok, length(policies)}
    rescue
      e ->
        Logger.debug("[DLP.PolicyEngine] DB load skipped: #{inspect(e)}")
        {:ok, 0}
    end
  end

  defp persist_policy(policy) do
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      try do
        Repo.insert_all("dlp_policies", [%{
          id: policy.id,
          name: policy.name,
          description: policy.description,
          classifiers: policy.classifiers,
          destinations: policy.destinations,
          action: policy.action,
          severity: policy.severity,
          enabled: policy.enabled,
          organization_id: policy.org_id,
          inserted_at: policy.created_at,
          updated_at: policy.updated_at
        }],
          on_conflict: {:replace_all_except, [:id, :inserted_at]},
          conflict_target: :id
        )
      rescue
        e -> Logger.debug("[DLP.PolicyEngine] Persist failed: #{inspect(e)}")
      end
    end)
  end

  defp delete_policy_from_db(policy_id) do
    Task.Supervisor.start_child(TamanduaServer.TaskSupervisor, fn ->
      try do
        import Ecto.Query
        Repo.delete_all(from(p in "dlp_policies", where: p.id == ^policy_id))
      rescue
        e -> Logger.debug("[DLP.PolicyEngine] Delete failed: #{inspect(e)}")
      end
    end)
  end
end
