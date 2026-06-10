defmodule TamanduaServer.Integrations.Chat.TeamsConfig do
  @moduledoc """
  Microsoft Teams configuration schema.

  Stores per-organization Teams configurations with encrypted app passwords.
  Each team can have separate alert and escalation channels with configurable
  notification rules and conversation references for proactive messaging.

  ## Example

      TeamsConfig.create_config(%{
        organization_id: "org-123",
        team_id: "19:abc123...",
        team_name: "Security Operations",
        tenant_id: "tenant-uuid",
        app_id: "app-uuid",
        app_password: "secret-password",
        alert_channel_id: "19:channel123...",
        escalation_channel_id: "19:channel456...",
        min_severity: "high"
      })
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  require Logger

  alias TamanduaServer.Repo
  alias __MODULE__

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @valid_severities ["critical", "high", "medium", "low", "info"]

  # Encryption settings (same as ticketing)
  @aes_key_size 32
  @iv_size 12
  @tag_size 16

  @type t :: %__MODULE__{
    id: binary() | nil,
    organization_id: binary() | nil,
    team_id: String.t() | nil,
    team_name: String.t() | nil,
    tenant_id: String.t() | nil,
    app_id: String.t() | nil,
    app_password: binary() | nil,
    alert_channel_id: String.t() | nil,
    escalation_channel_id: String.t() | nil,
    webhook_url: String.t() | nil,
    min_severity: String.t(),
    enabled: boolean(),
    notification_rules: map(),
    digest_schedule: map(),
    conversation_reference: map() | nil,
    inserted_at: DateTime.t() | nil,
    updated_at: DateTime.t() | nil
  }

  schema "teams_configs" do
    field :team_id, :string
    field :team_name, :string
    field :tenant_id, :string
    field :app_id, :string
    field :app_password, :binary
    field :alert_channel_id, :string
    field :escalation_channel_id, :string
    field :webhook_url, :string
    field :min_severity, :string, default: "high"
    field :enabled, :boolean, default: true
    field :notification_rules, :map, default: %{}
    field :digest_schedule, :map, default: %{}
    field :conversation_reference, :map

    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime_usec)
  end

  @doc """
  Creates a changeset for Teams configuration.
  """
  @spec changeset(t(), map()) :: Ecto.Changeset.t()
  def changeset(%TeamsConfig{} = config, attrs) do
    config
    |> cast(attrs, [
      :organization_id,
      :team_id,
      :team_name,
      :tenant_id,
      :app_id,
      :app_password,
      :alert_channel_id,
      :escalation_channel_id,
      :webhook_url,
      :min_severity,
      :enabled,
      :notification_rules,
      :digest_schedule,
      :conversation_reference
    ])
    |> validate_required([:organization_id, :team_id])
    |> validate_inclusion(:min_severity, @valid_severities)
    |> unique_constraint(:team_id)
    |> foreign_key_constraint(:organization_id)
    |> encrypt_secrets()
  end

  @doc """
  Creates a new Teams configuration with encrypted credentials.

  ## Parameters

  - `attrs` - Configuration attributes including:
    - `:organization_id` - Required
    - `:team_id` - Required (Teams team ID)
    - `:app_password` - Plain text password (will be encrypted)
    - Other optional fields

  ## Returns

  - `{:ok, config}` - Success
  - `{:error, changeset}` - Validation failure
  """
  @spec create_config(map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def create_config(attrs) do
    %TeamsConfig{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Gets a Teams configuration by team_id.

  ## Parameters

  - `team_id` - Teams team ID

  ## Returns

  - Config struct or nil if not found
  """
  @spec get_for_team_id(String.t()) :: t() | nil
  def get_for_team_id(team_id) when is_binary(team_id) do
    Repo.get_by(TeamsConfig, team_id: team_id)
  end

  @doc """
  Gets Teams configurations for an organization.

  ## Parameters

  - `org_id` - Organization ID

  ## Returns

  - List of config structs
  """
  @spec get_for_organization(binary()) :: [t()]
  def get_for_organization(org_id) do
    query = from(c in TeamsConfig,
      where: c.organization_id == ^org_id and c.enabled == true
    )

    Repo.all(query)
  end

  @doc """
  Lists all enabled Teams configurations.

  ## Returns

  - List of config structs
  """
  @spec list_enabled() :: [t()]
  def list_enabled do
    query = from(c in TeamsConfig, where: c.enabled == true)
    Repo.all(query)
  end

  @doc """
  Updates a Teams configuration.

  Re-encrypts secrets if provided.

  ## Parameters

  - `config` - Existing config struct
  - `attrs` - Attributes to update

  ## Returns

  - `{:ok, config}` - Success
  - `{:error, changeset}` - Validation failure
  """
  @spec update_config(t(), map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def update_config(%TeamsConfig{} = config, attrs) do
    config
    |> changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Decrypts the app password for use in API calls.

  ## Parameters

  - `config` - Config struct with encrypted app_password

  ## Returns

  - `{:ok, plain_password}` - Decrypted password
  - `{:error, reason}` - Decryption failure
  """
  @spec decrypt_app_password(t()) :: {:ok, String.t()} | {:error, term()}
  def decrypt_app_password(%TeamsConfig{app_password: nil}), do: {:error, :no_password}
  def decrypt_app_password(%TeamsConfig{app_password: encrypted}) do
    decrypt_value(encrypted)
  end

  @doc """
  Updates the conversation reference for proactive messaging.

  Called when the bot is added to a conversation/channel.

  ## Parameters

  - `config` - Config struct
  - `conv_ref` - Conversation reference map from Bot Framework

  ## Returns

  - `{:ok, config}` - Success
  - `{:error, changeset}` - Failure
  """
  @spec update_conversation_reference(t(), map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def update_conversation_reference(%TeamsConfig{} = config, conv_ref) do
    update_config(config, %{conversation_reference: conv_ref})
  end

  @doc """
  Deletes a Teams configuration.

  ## Parameters

  - `config` - Config struct to delete

  ## Returns

  - `{:ok, config}` - Success
  - `{:error, changeset}` - Failure
  """
  @spec delete_config(t()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def delete_config(%TeamsConfig{} = config) do
    Repo.delete(config)
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp encrypt_secrets(changeset) do
    maybe_encrypt_field(changeset, :app_password)
  end

  defp maybe_encrypt_field(changeset, field) do
    case get_change(changeset, field) do
      nil -> changeset
      value when is_binary(value) and byte_size(value) > 0 ->
        case encrypt_value(value) do
          {:ok, encrypted} -> put_change(changeset, field, encrypted)
          {:error, _} -> add_error(changeset, field, "encryption failed")
        end
      _other -> changeset
    end
  end

  defp encrypt_value(plaintext) when is_binary(plaintext) do
    try do
      key = get_encryption_key()
      iv = :crypto.strong_rand_bytes(@iv_size)

      {ciphertext, tag} =
        :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, "", @tag_size, true)

      # Format: IV (12 bytes) || Tag (16 bytes) || Ciphertext
      encrypted = <<iv::binary-size(@iv_size), tag::binary-size(@tag_size), ciphertext::binary>>
      {:ok, encrypted}
    rescue
      e ->
        Logger.error("[TeamsConfig] Encryption failed: #{inspect(e)}")
        {:error, {:encryption_failed, e}}
    end
  end

  defp decrypt_value(encrypted) when is_binary(encrypted) do
    try do
      min_size = @iv_size + @tag_size + 1
      if byte_size(encrypted) < min_size do
        {:error, :invalid_encrypted_data}
      else
        key = get_encryption_key()

        <<iv::binary-size(@iv_size), tag::binary-size(@tag_size), ciphertext::binary>> = encrypted

        case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, "", tag, false) do
          plaintext when is_binary(plaintext) -> {:ok, plaintext}
          :error -> {:error, :decryption_authentication_failed}
        end
      end
    rescue
      e ->
        Logger.error("[TeamsConfig] Decryption failed: #{inspect(e)}")
        {:error, {:decryption_failed, e}}
    end
  end

  defp get_encryption_key do
    key_base64 =
      Application.get_env(:tamandua_server, :chat_encryption_key) ||
        Application.get_env(:tamandua_server, :ticketing_encryption_key) ||
        System.get_env("TAMANDUA_CHAT_ENCRYPTION_KEY") ||
        System.get_env("TAMANDUA_TICKETING_ENCRYPTION_KEY") ||
        raise "Chat encryption key not configured"

    case Base.decode64(key_base64) do
      {:ok, key} when byte_size(key) == @aes_key_size -> key
      {:ok, key} -> raise "Invalid encryption key size: #{byte_size(key)} bytes"
      :error -> raise "Invalid encryption key: not valid Base64"
    end
  end
end
