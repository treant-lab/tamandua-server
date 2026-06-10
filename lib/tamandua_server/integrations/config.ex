defmodule TamanduaServer.Integrations.Config do
  @moduledoc """
  Integration Configuration Management

  Provides centralized configuration storage for all integrations:
  - Database-backed configuration storage
  - Encrypted credential storage
  - Per-organization integration configs
  - Configuration validation and migration

  ## Schema

  Integrations are stored with:
  - `type` - Integration type (splunk, sentinel, elastic, webhook, etc.)
  - `name` - User-friendly name
  - `config` - JSON configuration (encrypted sensitive fields)
  - `enabled` - Whether the integration is active
  - `organization_id` - Multi-tenant support
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  # Integration types
  @integration_types ~w(
    splunk sentinel elastic webhook
    xsoar swimlane tines
    servicenow jira pagerduty
  )a

  schema "integrations" do
    field :type, Ecto.Enum, values: @integration_types
    field :name, :string
    field :description, :string
    field :config, :map, default: %{}
    field :encrypted_config, :binary  # Encrypted sensitive data
    field :enabled, :boolean, default: true
    field :last_sync_at, :utc_datetime
    field :last_error, :string
    field :stats, :map, default: %{}

    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps()
  end

  @required_fields [:type, :name]
  @optional_fields [:description, :config, :enabled, :last_sync_at, :last_error, :stats, :organization_id]

  # ============================================================================
  # Changeset Functions
  # ============================================================================

  def changeset(integration, attrs) do
    integration
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:type, @integration_types)
    |> validate_config()
    |> encrypt_sensitive_config()
    |> unique_constraint([:type, :name, :organization_id])
  end

  defp validate_config(changeset) do
    type = get_field(changeset, :type)
    config = get_field(changeset, :config) || %{}

    case validate_config_for_type(type, config) do
      :ok -> changeset
      {:error, message} -> add_error(changeset, :config, message)
    end
  end

  defp validate_config_for_type(:splunk, config) do
    if config["hec_url"] || config[:hec_url] do
      :ok
    else
      {:error, "Splunk HEC URL is required"}
    end
  end

  defp validate_config_for_type(:sentinel, config) do
    if (config["workspace_id"] || config[:workspace_id]) &&
       (config["shared_key"] || config[:shared_key]) do
      :ok
    else
      {:error, "Workspace ID and shared key are required"}
    end
  end

  defp validate_config_for_type(:elastic, config) do
    if config["url"] || config[:url] do
      :ok
    else
      {:error, "Elasticsearch URL is required"}
    end
  end

  defp validate_config_for_type(:webhook, config) do
    if config["url"] || config[:url] do
      :ok
    else
      {:error, "Webhook URL is required"}
    end
  end

  defp validate_config_for_type(:xsoar, config) do
    if (config["url"] || config[:url]) && (config["api_key"] || config[:api_key]) do
      :ok
    else
      {:error, "XSOAR URL and API key are required"}
    end
  end

  defp validate_config_for_type(:swimlane, config) do
    if config["url"] || config[:url] do
      :ok
    else
      {:error, "Swimlane URL is required"}
    end
  end

  defp validate_config_for_type(:tines, _config) do
    :ok  # Tines uses webhook URLs per-story
  end

  defp validate_config_for_type(:servicenow, config) do
    if config["instance"] || config[:instance] do
      :ok
    else
      {:error, "ServiceNow instance is required"}
    end
  end

  defp validate_config_for_type(:jira, config) do
    if (config["url"] || config[:url]) && (config["project_key"] || config[:project_key]) do
      :ok
    else
      {:error, "Jira URL and project key are required"}
    end
  end

  defp validate_config_for_type(:pagerduty, config) do
    if config["routing_key"] || config[:routing_key] do
      :ok
    else
      {:error, "PagerDuty routing key is required"}
    end
  end

  defp validate_config_for_type(_, _), do: :ok

  defp encrypt_sensitive_config(changeset) do
    config = get_field(changeset, :config) || %{}
    sensitive_keys = get_sensitive_keys(get_field(changeset, :type))

    if Enum.any?(sensitive_keys, &Map.has_key?(config, &1)) do
      # Extract and encrypt sensitive values
      {sensitive, public} = Map.split(config, sensitive_keys)

      encrypted = encrypt_map(sensitive)

      changeset
      |> put_change(:config, public)
      |> put_change(:encrypted_config, encrypted)
    else
      changeset
    end
  end

  defp get_sensitive_keys(:splunk), do: ["hec_token", "soar_token", "rest_password", :hec_token, :soar_token, :rest_password]
  defp get_sensitive_keys(:sentinel), do: ["shared_key", "client_secret", :shared_key, :client_secret]
  defp get_sensitive_keys(:elastic), do: ["password", "api_key", :password, :api_key]
  defp get_sensitive_keys(:webhook), do: ["secret", :secret]
  defp get_sensitive_keys(:xsoar), do: ["api_key", :api_key]
  defp get_sensitive_keys(:swimlane), do: ["password", "token", :password, :token]
  defp get_sensitive_keys(:tines), do: ["api_token", "token", :api_token, :token]
  defp get_sensitive_keys(:servicenow), do: ["password", "client_secret", :password, :client_secret]
  defp get_sensitive_keys(:jira), do: ["api_token", :api_token]
  defp get_sensitive_keys(:pagerduty), do: ["routing_key", "api_token", :routing_key, :api_token]
  defp get_sensitive_keys(_), do: []

  defp encrypt_map(map) when map_size(map) == 0, do: nil
  defp encrypt_map(map) do
    secret = get_encryption_key()
    data = Jason.encode!(map)

    # Use AES-GCM encryption
    iv = :crypto.strong_rand_bytes(16)
    {ciphertext, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, secret, iv, data, "", true)

    # Combine IV + tag + ciphertext
    iv <> tag <> ciphertext
  end

  defp get_encryption_key do
    key = Application.get_env(:tamandua_server, :integration_encryption_key)

    if key do
      # Ensure key is 32 bytes for AES-256
      :crypto.hash(:sha256, key)
    else
      # Fallback to a derived key from secret_key_base
      secret_base = Application.get_env(:tamandua_server, TamanduaServerWeb.Endpoint)[:secret_key_base]
      :crypto.hash(:sha256, secret_base <> "integration_config")
    end
  end

  # ============================================================================
  # Query Functions
  # ============================================================================

  @doc """
  List all integrations, optionally filtered by organization.
  """
  def list_integrations(opts \\ []) do
    query = from(i in __MODULE__, order_by: [asc: i.type, asc: i.name])

    query = case opts[:organization_id] do
      nil -> query
      org_id -> from(i in query, where: i.organization_id == ^org_id)
    end

    query = case opts[:type] do
      nil -> query
      type -> from(i in query, where: i.type == ^type)
    end

    query = case opts[:enabled] do
      nil -> query
      enabled -> from(i in query, where: i.enabled == ^enabled)
    end

    Repo.all(query)
    |> Enum.map(&decrypt_config/1)
  end

  @doc """
  Get an integration by ID.
  """
  def get_integration(id) do
    case Repo.get(__MODULE__, id) do
      nil -> {:error, :not_found}
      integration -> {:ok, decrypt_config(integration)}
    end
  end

  @doc """
  Get an integration by type and name.
  """
  def get_integration_by_type(type, name, org_id \\ nil) do
    query = from(i in __MODULE__,
      where: i.type == ^type and i.name == ^name
    )

    query = if org_id do
      from(i in query, where: i.organization_id == ^org_id)
    else
      query
    end

    case Repo.one(query) do
      nil -> {:error, :not_found}
      integration -> {:ok, decrypt_config(integration)}
    end
  end

  @doc """
  Create a new integration.
  """
  def create_integration(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, integration} -> {:ok, decrypt_config(integration)}
      error -> error
    end
  end

  @doc """
  Update an integration.
  """
  def update_integration(id, attrs) when is_binary(id) do
    case Repo.get(__MODULE__, id) do
      nil -> {:error, :not_found}
      integration -> update_integration(integration, attrs)
    end
  end

  def update_integration(%__MODULE__{} = integration, attrs) do
    integration
    |> changeset(attrs)
    |> Repo.update()
    |> case do
      {:ok, updated} -> {:ok, decrypt_config(updated)}
      error -> error
    end
  end

  @doc """
  Delete an integration.
  """
  def delete_integration(id) when is_binary(id) do
    case Repo.get(__MODULE__, id) do
      nil -> {:error, :not_found}
      integration -> Repo.delete(integration)
    end
  end

  @doc """
  Enable an integration.
  """
  def enable_integration(id) do
    update_integration(id, %{enabled: true})
  end

  @doc """
  Disable an integration.
  """
  def disable_integration(id) do
    update_integration(id, %{enabled: false})
  end

  @doc """
  Update integration stats.
  """
  def update_stats(id, stats) do
    from(i in __MODULE__, where: i.id == ^id)
    |> Repo.update_all(set: [stats: stats, last_sync_at: DateTime.utc_now()])
  end

  @doc """
  Record an integration error.
  """
  def record_error(id, error_message) do
    from(i in __MODULE__, where: i.id == ^id)
    |> Repo.update_all(set: [last_error: error_message])
  end

  @doc """
  Clear integration error.
  """
  def clear_error(id) do
    from(i in __MODULE__, where: i.id == ^id)
    |> Repo.update_all(set: [last_error: nil])
  end

  # ============================================================================
  # Decryption
  # ============================================================================

  defp decrypt_config(%__MODULE__{encrypted_config: nil} = integration) do
    integration
  end

  defp decrypt_config(%__MODULE__{encrypted_config: encrypted} = integration) do
    case decrypt_map(encrypted) do
      {:ok, sensitive} ->
        merged_config = Map.merge(integration.config || %{}, sensitive)
        %{integration | config: merged_config, encrypted_config: nil}

      {:error, _} ->
        integration
    end
  end

  defp decrypt_map(nil), do: {:ok, %{}}
  defp decrypt_map(data) when byte_size(data) < 32, do: {:error, :invalid_data}
  defp decrypt_map(data) do
    secret = get_encryption_key()

    # Extract IV (16 bytes) + tag (16 bytes) + ciphertext
    <<iv::binary-16, tag::binary-16, ciphertext::binary>> = data

    case :crypto.crypto_one_time_aead(:aes_256_gcm, secret, iv, ciphertext, "", tag, false) do
      :error ->
        {:error, :decryption_failed}

      plaintext ->
        {:ok, Jason.decode!(plaintext)}
    end
  rescue
    _ -> {:error, :decryption_failed}
  end

  # ============================================================================
  # Runtime Configuration
  # ============================================================================

  @doc """
  Get runtime configuration for an integration.
  Returns merged config suitable for starting the integration module.
  """
  def get_runtime_config(id) do
    case get_integration(id) do
      {:ok, integration} ->
        config = integration.config || %{}

        # Convert string keys to atoms for module configuration
        config = config
        |> Enum.map(fn {k, v} -> {String.to_atom(to_string(k)), v} end)
        |> Map.new()

        {:ok, config}

      error ->
        error
    end
  end

  @doc """
  Get all enabled integrations of a specific type.
  """
  def get_enabled_integrations(type, org_id \\ nil) do
    query = from(i in __MODULE__,
      where: i.type == ^type and i.enabled == true
    )

    query = if org_id do
      from(i in query, where: i.organization_id == ^org_id)
    else
      query
    end

    Repo.all(query)
    |> Enum.map(&decrypt_config/1)
  end

  @doc """
  Test an integration configuration without saving.
  """
  def test_integration_config(type, config) do
    module = get_module_for_type(type)

    if module && function_exported?(module, :test_connection, 0) do
      # Start a temporary process with the config
      case GenServer.start(module, config) do
        {:ok, pid} ->
          result = GenServer.call(pid, :test_connection, 30_000)
          GenServer.stop(pid)
          result

        {:error, reason} ->
          {:error, reason}
      end
    else
      {:error, :test_not_supported}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp get_module_for_type(:splunk), do: TamanduaServer.Integrations.Splunk
  defp get_module_for_type(:sentinel), do: TamanduaServer.Integrations.Sentinel
  defp get_module_for_type(:elastic), do: TamanduaServer.Integrations.Elastic
  defp get_module_for_type(:webhook), do: TamanduaServer.Integrations.Webhook
  defp get_module_for_type(:xsoar), do: TamanduaServer.Integrations.SOAR.XSOAR
  defp get_module_for_type(:swimlane), do: TamanduaServer.Integrations.SOAR.Swimlane
  defp get_module_for_type(:tines), do: TamanduaServer.Integrations.SOAR.Tines
  defp get_module_for_type(:servicenow), do: TamanduaServer.Integrations.Ticketing.ServiceNow
  defp get_module_for_type(:jira), do: TamanduaServer.Integrations.Ticketing.Jira
  defp get_module_for_type(:pagerduty), do: TamanduaServer.Integrations.Ticketing.PagerDuty
  defp get_module_for_type(_), do: nil

  @doc """
  Get available integration types with metadata.
  """
  def available_types do
    [
      %{
        type: :splunk,
        name: "Splunk",
        category: :siem,
        description: "Forward events and alerts to Splunk via HEC",
        required_fields: ["hec_url", "hec_token"],
        optional_fields: ["index", "sourcetype", "soar_url", "soar_token"]
      },
      %{
        type: :sentinel,
        name: "Microsoft Sentinel",
        category: :siem,
        description: "Send events to Azure Log Analytics and create Sentinel incidents",
        required_fields: ["workspace_id", "shared_key"],
        optional_fields: ["tenant_id", "client_id", "client_secret", "log_type"]
      },
      %{
        type: :elastic,
        name: "Elasticsearch",
        category: :siem,
        description: "Index events in Elasticsearch/OpenSearch",
        required_fields: ["url"],
        optional_fields: ["username", "password", "api_key", "index_prefix"]
      },
      %{
        type: :webhook,
        name: "Webhook",
        category: :generic,
        description: "Send alerts to any HTTP endpoint",
        required_fields: ["url"],
        optional_fields: ["method", "headers", "secret", "template"]
      },
      %{
        type: :xsoar,
        name: "Palo Alto XSOAR",
        category: :soar,
        description: "Create incidents and trigger playbooks in XSOAR",
        required_fields: ["url", "api_key"],
        optional_fields: []
      },
      %{
        type: :swimlane,
        name: "Swimlane",
        category: :soar,
        description: "Create records and trigger workflows in Swimlane",
        required_fields: ["url"],
        optional_fields: ["username", "password", "token", "application_id"]
      },
      %{
        type: :tines,
        name: "Tines",
        category: :soar,
        description: "Trigger Tines stories via webhooks",
        required_fields: [],
        optional_fields: ["tenant", "api_token", "webhook_urls"]
      },
      %{
        type: :servicenow,
        name: "ServiceNow",
        category: :ticketing,
        description: "Create security incidents in ServiceNow",
        required_fields: ["instance"],
        optional_fields: ["username", "password", "client_id", "client_secret", "table"]
      },
      %{
        type: :jira,
        name: "Jira",
        category: :ticketing,
        description: "Create issues in Jira",
        required_fields: ["url", "project_key"],
        optional_fields: ["email", "api_token", "issue_type"]
      },
      %{
        type: :pagerduty,
        name: "PagerDuty",
        category: :ticketing,
        description: "Trigger PagerDuty incidents",
        required_fields: ["routing_key"],
        optional_fields: ["api_token", "default_service_id", "escalation_policy_id"]
      }
    ]
  end
end
