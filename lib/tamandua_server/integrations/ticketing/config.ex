defmodule TamanduaServer.Integrations.Ticketing.Config do
  @moduledoc """
  Ticketing integration configuration schema.

  Stores per-organization configurations for Jira and ServiceNow integrations
  with encrypted credentials using AES-256-GCM.

  ## Configuration Structure

  ### Jira Config
  ```
  %{
    "base_url" => "https://company.atlassian.net",
    "email" => "integration@company.com",
    "api_token" => "secret-api-token",
    "project_key" => "SEC",
    "issue_type" => "Security Incident"
  }
  ```

  ### ServiceNow Config
  ```
  %{
    "instance_url" => "https://company.service-now.com",
    "username" => "tamandua_integration",
    "password" => "secret-password",
    "client_id" => "oauth-client-id",        # Optional, for OAuth
    "client_secret" => "oauth-client-secret", # Optional, for OAuth
    "table" => "sn_si_incident"              # Security Incident table
  }
  ```
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  require Logger

  alias TamanduaServer.Repo
  alias __MODULE__

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @valid_types ["jira", "servicenow"]
  @valid_severities ["critical", "high", "medium", "low", "info"]
  @valid_health_statuses ["unknown", "healthy", "degraded", "unhealthy"]

  # Encryption settings
  @aes_key_size 32
  @iv_size 12
  @tag_size 16

  @type t :: %__MODULE__{
    id: binary() | nil,
    organization_id: binary() | nil,
    type: String.t() | nil,
    enabled: boolean(),
    config: binary() | nil,
    min_severity: String.t(),
    auto_create: boolean(),
    dedupe_enabled: boolean(),
    dedupe_window_hours: integer(),
    last_sync_at: DateTime.t() | nil,
    health_status: String.t(),
    inserted_at: DateTime.t() | nil,
    updated_at: DateTime.t() | nil
  }

  schema "ticketing_configs" do
    field :type, :string
    field :enabled, :boolean, default: false
    field :config, :binary
    field :min_severity, :string, default: "high"
    field :auto_create, :boolean, default: true
    field :dedupe_enabled, :boolean, default: true
    field :dedupe_window_hours, :integer, default: 24
    field :last_sync_at, :utc_datetime_usec
    field :health_status, :string, default: "unknown"

    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime_usec)
  end

  @doc """
  Creates a changeset for ticketing configuration.
  """
  @spec changeset(t(), map()) :: Ecto.Changeset.t()
  def changeset(%Config{} = config, attrs) do
    config
    |> cast(attrs, [
      :organization_id,
      :type,
      :enabled,
      :config,
      :min_severity,
      :auto_create,
      :dedupe_enabled,
      :dedupe_window_hours,
      :last_sync_at,
      :health_status
    ])
    |> validate_required([:organization_id, :type])
    |> validate_inclusion(:type, @valid_types)
    |> validate_inclusion(:min_severity, @valid_severities)
    |> validate_inclusion(:health_status, @valid_health_statuses)
    |> validate_number(:dedupe_window_hours, greater_than: 0, less_than_or_equal_to: 168)
    |> unique_constraint([:organization_id, :type])
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Returns the list of valid ticketing types.
  """
  @spec valid_types() :: [String.t()]
  def valid_types, do: @valid_types

  @doc """
  Encrypts a configuration map using AES-256-GCM.

  ## Parameters
  - `config_map` - Configuration map to encrypt

  ## Returns
  - `{:ok, encrypted_binary}` - Success with encrypted data
  - `{:error, reason}` - Encryption failure
  """
  @spec encrypt_config(map()) :: {:ok, binary()} | {:error, term()}
  def encrypt_config(config_map) when is_map(config_map) do
    try do
      key = get_encryption_key()
      iv = :crypto.strong_rand_bytes(@iv_size)
      plaintext = Jason.encode!(config_map)

      {ciphertext, tag} =
        :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, "", @tag_size, true)

      # Format: IV (12 bytes) || Tag (16 bytes) || Ciphertext
      encrypted = <<iv::binary-size(@iv_size), tag::binary-size(@tag_size), ciphertext::binary>>
      {:ok, encrypted}
    rescue
      e ->
        Logger.error("[Ticketing.Config] Encryption failed: #{inspect(e)}")
        {:error, {:encryption_failed, e}}
    end
  end

  @doc """
  Decrypts a configuration binary using AES-256-GCM.

  ## Parameters
  - `encrypted_binary` - Encrypted configuration data

  ## Returns
  - `{:ok, config_map}` - Success with decrypted configuration map
  - `{:error, reason}` - Decryption failure
  """
  @spec decrypt_config(binary()) :: {:ok, map()} | {:error, term()}
  def decrypt_config(encrypted) when is_binary(encrypted) do
    try do
      min_size = @iv_size + @tag_size + 1
      if byte_size(encrypted) < min_size do
        {:error, :invalid_encrypted_data}
      else
        key = get_encryption_key()

        <<iv::binary-size(@iv_size), tag::binary-size(@tag_size), ciphertext::binary>> = encrypted

        case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, "", tag, false) do
          plaintext when is_binary(plaintext) ->
            {:ok, Jason.decode!(plaintext)}

          :error ->
            {:error, :decryption_authentication_failed}
        end
      end
    rescue
      e ->
        Logger.error("[Ticketing.Config] Decryption failed: #{inspect(e)}")
        {:error, {:decryption_failed, e}}
    end
  end

  def decrypt_config(nil), do: {:ok, %{}}

  @doc """
  Gets a ticketing configuration by organization ID and type.

  Returns the config with decrypted credentials.

  ## Parameters
  - `org_id` - Organization ID
  - `type` - Ticketing type ("jira" or "servicenow")

  ## Returns
  - `{:ok, config_with_decrypted}` - Success with config and decrypted credentials
  - `{:error, :not_found}` - Config not found
  - `{:error, reason}` - Decryption failure
  """
  @spec get_config(binary(), String.t()) :: {:ok, map()} | {:error, term()}
  def get_config(org_id, type) when type in @valid_types do
    query = from(c in Config,
      where: c.organization_id == ^org_id and c.type == ^type
    )

    case Repo.one(query) do
      nil ->
        {:error, :not_found}

      config ->
        case decrypt_config(config.config) do
          {:ok, decrypted} ->
            {:ok, Map.put(config, :decrypted_config, decrypted)}

          error ->
            error
        end
    end
  end

  @doc """
  Lists all enabled ticketing configurations for an organization.

  Returns configs with decrypted credentials.

  ## Parameters
  - `org_id` - Organization ID

  ## Returns
  - List of configs with decrypted credentials
  """
  @spec list_enabled(binary()) :: [map()]
  def list_enabled(org_id) do
    query = from(c in Config,
      where: c.organization_id == ^org_id and c.enabled == true
    )

    Repo.all(query)
    |> Enum.map(fn config ->
      case decrypt_config(config.config) do
        {:ok, decrypted} ->
          Map.put(config, :decrypted_config, decrypted)

        {:error, _reason} ->
          Logger.error("[Ticketing.Config] Failed to decrypt config #{config.id}")
          nil
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  @doc """
  Lists all enabled ticketing configurations across all organizations.

  Used by the TicketingRouter to get all active integrations.

  ## Returns
  - List of configs with decrypted credentials
  """
  @spec list_all_enabled() :: [map()]
  def list_all_enabled do
    query = from(c in Config,
      where: c.enabled == true
    )

    Repo.all(query)
    |> Enum.map(fn config ->
      case decrypt_config(config.config) do
        {:ok, decrypted} ->
          Map.put(config, :decrypted_config, decrypted)

        {:error, _reason} ->
          Logger.error("[Ticketing.Config] Failed to decrypt config #{config.id}")
          nil
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  @doc """
  Creates a new ticketing configuration with encrypted credentials.

  ## Parameters
  - `attrs` - Configuration attributes including:
    - `:organization_id` - Required
    - `:type` - Required ("jira" or "servicenow")
    - `:credentials` - Map of credentials to encrypt
    - Other optional fields

  ## Returns
  - `{:ok, config}` - Success
  - `{:error, changeset}` - Validation failure
  """
  @spec create_config(map()) :: {:ok, t()} | {:error, Ecto.Changeset.t() | term()}
  def create_config(attrs) do
    with {:ok, encrypted} <- maybe_encrypt_credentials(attrs) do
      attrs = Map.put(attrs, :config, encrypted)

      %Config{}
      |> changeset(attrs)
      |> Repo.insert()
    end
  end

  @doc """
  Updates an existing ticketing configuration.

  Re-encrypts credentials if provided.

  ## Parameters
  - `config` - Existing config struct
  - `attrs` - Attributes to update

  ## Returns
  - `{:ok, config}` - Success
  - `{:error, changeset}` - Validation failure
  """
  @spec update_config(t(), map()) :: {:ok, t()} | {:error, Ecto.Changeset.t() | term()}
  def update_config(%Config{} = config, attrs) do
    with {:ok, encrypted} <- maybe_encrypt_credentials(attrs) do
      attrs = if encrypted, do: Map.put(attrs, :config, encrypted), else: attrs

      config
      |> changeset(attrs)
      |> Repo.update()
    end
  end

  @doc """
  Updates the health status and last sync time for a config.

  ## Parameters
  - `config` - Config struct
  - `status` - New health status
  """
  @spec update_health(t(), String.t()) :: {:ok, t()} | {:error, term()}
  def update_health(%Config{} = config, status) when status in @valid_health_statuses do
    config
    |> changeset(%{health_status: status, last_sync_at: DateTime.utc_now()})
    |> Repo.update()
  end

  @doc """
  Deletes a ticketing configuration.

  ## Parameters
  - `config` - Config struct to delete

  ## Returns
  - `{:ok, config}` - Success
  - `{:error, changeset}` - Failure
  """
  @spec delete_config(t()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def delete_config(%Config{} = config) do
    Repo.delete(config)
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp maybe_encrypt_credentials(%{credentials: credentials}) when is_map(credentials) do
    encrypt_config(credentials)
  end

  defp maybe_encrypt_credentials(%{"credentials" => credentials}) when is_map(credentials) do
    encrypt_config(credentials)
  end

  defp maybe_encrypt_credentials(_attrs), do: {:ok, nil}

  defp get_encryption_key do
    # Get encryption key from application config or environment
    key_base64 =
      Application.get_env(:tamandua_server, :ticketing_encryption_key) ||
        System.get_env("TAMANDUA_TICKETING_ENCRYPTION_KEY") ||
        raise "Ticketing encryption key not configured. Set :ticketing_encryption_key in config or TAMANDUA_TICKETING_ENCRYPTION_KEY env var."

    case Base.decode64(key_base64) do
      {:ok, key} when byte_size(key) == @aes_key_size ->
        key

      {:ok, key} ->
        raise "Invalid ticketing encryption key size: #{byte_size(key)} bytes, expected #{@aes_key_size}"

      :error ->
        raise "Invalid ticketing encryption key: not valid Base64"
    end
  end
end
