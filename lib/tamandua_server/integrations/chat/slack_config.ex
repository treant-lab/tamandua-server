defmodule TamanduaServer.Integrations.Chat.SlackConfig do
  @moduledoc """
  Slack workspace configuration schema.

  Stores per-organization Slack workspace configurations with encrypted bot tokens.
  Each workspace can have separate alert and escalation channels with configurable
  notification rules.

  ## Example

      SlackConfig.create_config(%{
        organization_id: "org-123",
        team_id: "T1234ABCD",
        team_name: "ACME Corp",
        alert_channel: "C1234ABCD",
        escalation_channel: "C5678EFGH",
        min_severity: "high",
        bot_token: "xoxb-...",
        signing_secret: "..."
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
    bot_token: binary() | nil,
    signing_secret: binary() | nil,
    alert_channel: String.t() | nil,
    escalation_channel: String.t() | nil,
    min_severity: String.t(),
    enabled: boolean(),
    notification_rules: map(),
    digest_schedule: map(),
    inserted_at: DateTime.t() | nil,
    updated_at: DateTime.t() | nil
  }

  schema "slack_workspace_configs" do
    field :team_id, :string
    field :team_name, :string
    field :bot_token, :binary
    field :signing_secret, :binary
    field :alert_channel, :string
    field :escalation_channel, :string
    field :min_severity, :string, default: "high"
    field :enabled, :boolean, default: true
    field :notification_rules, :map, default: %{}
    field :digest_schedule, :map, default: %{}

    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime_usec)
  end

  @doc """
  Creates a changeset for Slack workspace configuration.
  """
  @spec changeset(t(), map()) :: Ecto.Changeset.t()
  def changeset(%SlackConfig{} = config, attrs) do
    config
    |> cast(attrs, [
      :organization_id,
      :team_id,
      :team_name,
      :bot_token,
      :signing_secret,
      :alert_channel,
      :escalation_channel,
      :min_severity,
      :enabled,
      :notification_rules,
      :digest_schedule
    ])
    |> validate_required([:organization_id, :team_id])
    |> validate_inclusion(:min_severity, @valid_severities)
    |> unique_constraint(:team_id)
    |> foreign_key_constraint(:organization_id)
    |> encrypt_secrets()
  end

  @doc """
  Creates a new Slack workspace configuration with encrypted tokens.

  ## Parameters

  - `attrs` - Configuration attributes including:
    - `:organization_id` - Required
    - `:team_id` - Required (Slack workspace ID)
    - `:bot_token` - Plain text bot token (will be encrypted)
    - `:signing_secret` - Plain text signing secret (will be encrypted)
    - Other optional fields

  ## Returns

  - `{:ok, config}` - Success
  - `{:error, changeset}` - Validation failure
  """
  @spec create_config(map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def create_config(attrs) do
    %SlackConfig{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Gets a Slack workspace configuration by team_id.

  ## Parameters

  - `team_id` - Slack workspace team ID (e.g., "T1234ABCD")

  ## Returns

  - Config struct or nil if not found
  """
  @spec get_for_team_id(String.t()) :: t() | nil
  def get_for_team_id(team_id) when is_binary(team_id) do
    Repo.get_by(SlackConfig, team_id: team_id)
  end

  @doc """
  Gets Slack workspace configurations for an organization.

  ## Parameters

  - `org_id` - Organization ID

  ## Returns

  - List of config structs
  """
  @spec get_for_organization(binary()) :: [t()]
  def get_for_organization(org_id) do
    query = from(c in SlackConfig,
      where: c.organization_id == ^org_id and c.enabled == true
    )

    Repo.all(query)
  end

  @doc """
  Lists all enabled Slack workspace configurations.

  ## Returns

  - List of config structs
  """
  @spec list_enabled() :: [t()]
  def list_enabled do
    query = from(c in SlackConfig, where: c.enabled == true)
    Repo.all(query)
  end

  @doc """
  Updates a Slack workspace configuration.

  Re-encrypts secrets if provided.

  ## Parameters

  - `config` - Existing config struct
  - `attrs` - Attributes to update

  ## Returns

  - `{:ok, config}` - Success
  - `{:error, changeset}` - Validation failure
  """
  @spec update_config(t(), map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def update_config(%SlackConfig{} = config, attrs) do
    config
    |> changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Decrypts the bot token for use in API calls.

  ## Parameters

  - `config` - Config struct with encrypted bot_token

  ## Returns

  - `{:ok, plain_token}` - Decrypted token
  - `{:error, reason}` - Decryption failure
  """
  @spec decrypt_bot_token(t()) :: {:ok, String.t()} | {:error, term()}
  def decrypt_bot_token(%SlackConfig{bot_token: nil}), do: {:error, :no_token}
  def decrypt_bot_token(%SlackConfig{bot_token: encrypted}) do
    decrypt_value(encrypted)
  end

  @doc """
  Decrypts the signing secret for request verification.

  ## Parameters

  - `config` - Config struct with encrypted signing_secret

  ## Returns

  - `{:ok, plain_secret}` - Decrypted secret
  - `{:error, reason}` - Decryption failure
  """
  @spec decrypt_signing_secret(t()) :: {:ok, String.t()} | {:error, term()}
  def decrypt_signing_secret(%SlackConfig{signing_secret: nil}), do: {:error, :no_secret}
  def decrypt_signing_secret(%SlackConfig{signing_secret: encrypted}) do
    decrypt_value(encrypted)
  end

  @doc """
  Deletes a Slack workspace configuration.

  ## Parameters

  - `config` - Config struct to delete

  ## Returns

  - `{:ok, config}` - Success
  - `{:error, changeset}` - Failure
  """
  @spec delete_config(t()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def delete_config(%SlackConfig{} = config) do
    Repo.delete(config)
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp encrypt_secrets(changeset) do
    changeset
    |> maybe_encrypt_field(:bot_token)
    |> maybe_encrypt_field(:signing_secret)
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
        Logger.error("[SlackConfig] Encryption failed: #{inspect(e)}")
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
        Logger.error("[SlackConfig] Decryption failed: #{inspect(e)}")
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
