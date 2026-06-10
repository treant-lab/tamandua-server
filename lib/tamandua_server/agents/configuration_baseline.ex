defmodule TamanduaServer.Agents.ConfigurationBaseline do
  @moduledoc """
  Schema for agent configuration baselines.

  Stores the expected configuration state for an agent. Used to detect
  configuration drift and maintain compliance.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Agents.Agent

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "agent_configuration_baselines" do
    belongs_to :agent, Agent
    belongs_to :organization, Organization
    belongs_to :created_by, User
    belongs_to :approved_by, User

    # Configuration categories
    field :collector_settings, :map, default: %{}
    field :response_permissions, :map, default: %{}
    field :network_settings, :map, default: %{}
    field :file_paths, :map, default: %{}
    field :resource_limits, :map, default: %{}
    field :enabled_features, :map, default: %{}
    field :rule_versions, :map, default: %{}

    # Metadata
    field :baseline_hash, :string
    field :baseline_version, :integer, default: 1
    field :is_active, :boolean, default: true
    field :approved_at, :utc_datetime
    field :notes, :string

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(baseline, attrs) do
    baseline
    |> cast(attrs, [
      :agent_id,
      :organization_id,
      :collector_settings,
      :response_permissions,
      :network_settings,
      :file_paths,
      :resource_limits,
      :enabled_features,
      :rule_versions,
      :baseline_hash,
      :baseline_version,
      :is_active,
      :approved_at,
      :notes,
      :created_by_id,
      :approved_by_id
    ])
    |> validate_required([:agent_id, :organization_id])
    |> validate_number(:baseline_version, greater_than: 0)
    |> compute_baseline_hash()
    |> foreign_key_constraint(:agent_id)
    |> foreign_key_constraint(:organization_id)
    |> unique_constraint([:agent_id, :baseline_version])
  end

  @doc """
  Creates a baseline from current agent configuration.
  """
  def from_agent_config(agent, config, opts \\ []) do
    changeset(%__MODULE__{}, %{
      agent_id: agent.id,
      organization_id: agent.organization_id,
      collector_settings: extract_collector_settings(config),
      response_permissions: extract_response_permissions(config),
      network_settings: extract_network_settings(config),
      file_paths: extract_file_paths(config),
      resource_limits: extract_resource_limits(config),
      enabled_features: extract_enabled_features(config),
      rule_versions: extract_rule_versions(config),
      baseline_version: Keyword.get(opts, :version, 1),
      is_active: Keyword.get(opts, :is_active, true),
      notes: Keyword.get(opts, :notes),
      created_by_id: Keyword.get(opts, :created_by_id)
    })
  end

  @doc """
  Computes the SHA256 hash of the baseline configuration.
  """
  def compute_hash(baseline) do
    data = %{
      collector_settings: baseline.collector_settings || %{},
      response_permissions: baseline.response_permissions || %{},
      network_settings: baseline.network_settings || %{},
      file_paths: baseline.file_paths || %{},
      resource_limits: baseline.resource_limits || %{},
      enabled_features: baseline.enabled_features || %{},
      rule_versions: baseline.rule_versions || %{}
    }

    data
    |> Jason.encode!()
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  # Private functions

  defp compute_baseline_hash(changeset) do
    if changeset.valid? do
      baseline = apply_changes(changeset)
      hash = compute_hash(baseline)
      put_change(changeset, :baseline_hash, hash)
    else
      changeset
    end
  end

  defp extract_collector_settings(config) do
    %{
      process: get_in(config, ["collectors", "process"]) || %{},
      file: get_in(config, ["collectors", "file"]) || %{},
      network: get_in(config, ["collectors", "network"]) || %{},
      dns: get_in(config, ["collectors", "dns"]) || %{},
      registry: get_in(config, ["collectors", "registry"]) || %{},
      kernel_events: get_in(config, ["collectors", "kernel_events"]) || %{}
    }
  end

  defp extract_response_permissions(config) do
    %{
      allowed_actions: get_in(config, ["response", "allowed_actions"]) || [],
      auto_response_enabled: get_in(config, ["response", "auto_response_enabled"]) || false,
      max_actions_per_hour: get_in(config, ["response", "max_actions_per_hour"]) || 10,
      require_approval: get_in(config, ["response", "require_approval"]) || false
    }
  end

  defp extract_network_settings(config) do
    %{
      server_url: get_in(config, ["network", "server_url"]),
      proxy_enabled: get_in(config, ["network", "proxy_enabled"]) || false,
      proxy_url: get_in(config, ["network", "proxy_url"]),
      dns_servers: get_in(config, ["network", "dns_servers"]) || [],
      tls_verify: get_in(config, ["network", "tls_verify"]) || true,
      connection_timeout: get_in(config, ["network", "connection_timeout"]) || 30
    }
  end

  defp extract_file_paths(config) do
    %{
      quarantine_dir: get_in(config, ["paths", "quarantine_dir"]),
      log_dir: get_in(config, ["paths", "log_dir"]),
      config_dir: get_in(config, ["paths", "config_dir"]),
      cache_dir: get_in(config, ["paths", "cache_dir"]),
      yara_rules_dir: get_in(config, ["paths", "yara_rules_dir"]),
      sigma_rules_dir: get_in(config, ["paths", "sigma_rules_dir"])
    }
  end

  defp extract_resource_limits(config) do
    %{
      max_cpu_percent: get_in(config, ["resource_limits", "max_cpu_percent"]) || 20,
      max_memory_mb: get_in(config, ["resource_limits", "max_memory_mb"]) || 512,
      max_disk_mb: get_in(config, ["resource_limits", "max_disk_mb"]) || 1024,
      max_network_bps: get_in(config, ["resource_limits", "max_network_bps"])
    }
  end

  defp extract_enabled_features(config) do
    %{
      yara_enabled: get_in(config, ["detection", "yara_enabled"]) || false,
      sigma_enabled: get_in(config, ["detection", "sigma_enabled"]) || false,
      ml_enabled: get_in(config, ["detection", "ml_enabled"]) || false,
      ioc_scanning: get_in(config, ["detection", "ioc_scanning"]) || false,
      honeyfiles: get_in(config, ["detection", "honeyfiles"]) || false,
      self_defense: get_in(config, ["features", "self_defense"]) || false,
      telemetry_streaming: get_in(config, ["features", "telemetry_streaming"]) || true
    }
  end

  defp extract_rule_versions(config) do
    %{
      yara_version: get_in(config, ["rules", "yara_version"]),
      sigma_version: get_in(config, ["rules", "sigma_version"]),
      ioc_version: get_in(config, ["rules", "ioc_version"]),
      last_updated: get_in(config, ["rules", "last_updated"])
    }
  end
end
