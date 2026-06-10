defmodule TamanduaServer.Backup.VaultClient do
  @moduledoc """
  HashiCorp Vault client for secure key management.

  Manages master encryption keys (KEK) and supports key rotation.

  ## Configuration
      config :tamandua_server, TamanduaServer.Backup.VaultClient,
        vault_url: "https://vault.example.com:8200",
        vault_token: System.get_env("VAULT_TOKEN"),
        vault_path: "secret/data/tamandua/backup",
        key_name: "master_encryption_key",
        fallback_key: System.get_env("BACKUP_MASTER_KEY")  # For development only

  ## Key Rotation
  Keys should be rotated yearly. During rotation:
  1. New key is created in Vault
  2. Old key remains accessible for decryption
  3. All new backups use new key
  4. Old backups can be re-encrypted with new key
  """

  require Logger
  use GenServer

  @key_cache_ttl :timer.hours(1)
  @vault_timeout :timer.seconds(10)

  defstruct [:vault_url, :vault_token, :vault_path, :key_name, :fallback_key, :cache]

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Retrieves the current master encryption key (KEK).

  Returns cached key if available and not expired, otherwise fetches from Vault.

  ## Returns
  - `{:ok, key}` - 32-byte encryption key
  - `{:error, reason}` - Fetch failure
  """
  @spec get_master_key() :: {:ok, binary()} | {:error, term()}
  def get_master_key do
    GenServer.call(__MODULE__, :get_master_key, @vault_timeout)
  end

  @doc """
  Rotates the master encryption key.

  Creates a new key version in Vault. Old keys remain accessible for decryption.

  ## Returns
  - `{:ok, new_key_version}` - Success
  - `{:error, reason}` - Rotation failure
  """
  @spec rotate_master_key() :: {:ok, integer()} | {:error, term()}
  def rotate_master_key do
    GenServer.call(__MODULE__, :rotate_master_key, @vault_timeout)
  end

  @doc """
  Retrieves a specific key version from Vault.

  Used for decrypting old backups after key rotation.

  ## Parameters
  - `version` - Key version number

  ## Returns
  - `{:ok, key}` - Retrieved key
  - `{:error, reason}` - Fetch failure
  """
  @spec get_key_version(integer()) :: {:ok, binary()} | {:error, term()}
  def get_key_version(version) do
    GenServer.call(__MODULE__, {:get_key_version, version}, @vault_timeout)
  end

  @doc """
  Invalidates the cached master key.

  Forces next `get_master_key/0` call to fetch from Vault.
  """
  @spec invalidate_cache() :: :ok
  def invalidate_cache do
    GenServer.cast(__MODULE__, :invalidate_cache)
  end

  # Server Callbacks

  @impl true
  def init(opts) do
    config = Application.get_env(:tamandua_server, __MODULE__, [])
    merged_config = Keyword.merge(config, opts)

    state = %__MODULE__{
      vault_url: Keyword.fetch!(merged_config, :vault_url),
      vault_token: Keyword.fetch!(merged_config, :vault_token),
      vault_path: Keyword.get(merged_config, :vault_path, "secret/data/tamandua/backup"),
      key_name: Keyword.get(merged_config, :key_name, "master_encryption_key"),
      fallback_key: Keyword.get(merged_config, :fallback_key),
      cache: nil
    }

    Logger.info("VaultClient initialized", vault_url: state.vault_url)
    {:ok, state}
  end

  @impl true
  def handle_call(:get_master_key, _from, state) do
    case get_cached_key(state) do
      {:ok, key} ->
        {:reply, {:ok, key}, state}

      :cache_miss ->
        case fetch_key_from_vault(state) do
          {:ok, key} ->
            new_state = cache_key(state, key)
            {:reply, {:ok, key}, new_state}

          {:error, _reason} = error ->
            # Fallback to environment variable for development
            case fallback_key(state) do
              {:ok, key} ->
                Logger.warning("Using fallback master key (development only)")
                {:reply, {:ok, key}, state}

              :no_fallback ->
                {:reply, error, state}
            end
        end
    end
  end

  @impl true
  def handle_call(:rotate_master_key, _from, state) do
    case rotate_key_in_vault(state) do
      {:ok, new_version} = result ->
        new_state = invalidate_cache_internal(state)
        Logger.info("Master key rotated", version: new_version)
        {:reply, result, new_state}

      {:error, _reason} = error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:get_key_version, version}, _from, state) do
    result = fetch_key_version_from_vault(state, version)
    {:reply, result, state}
  end

  @impl true
  def handle_cast(:invalidate_cache, state) do
    new_state = invalidate_cache_internal(state)
    {:noreply, new_state}
  end

  # Private Functions

  defp get_cached_key(%{cache: nil}), do: :cache_miss

  defp get_cached_key(%{cache: {key, expires_at}}) do
    if DateTime.compare(DateTime.utc_now(), expires_at) == :lt do
      {:ok, key}
    else
      :cache_miss
    end
  end

  defp cache_key(state, key) do
    expires_at = DateTime.add(DateTime.utc_now(), @key_cache_ttl, :millisecond)
    %{state | cache: {key, expires_at}}
  end

  defp invalidate_cache_internal(state) do
    %{state | cache: nil}
  end

  defp fetch_key_from_vault(state) do
    url = "#{state.vault_url}/v1/#{state.vault_path}"
    headers = [{"X-Vault-Token", state.vault_token}]

    case Req.get(url, headers: headers, receive_timeout: @vault_timeout) do
      {:ok, %{status: 200, body: body}} ->
        extract_key_from_response(body, state.key_name)

      {:ok, %{status: status}} ->
        Logger.error("Vault returned non-200 status", status: status)
        {:error, {:vault_error, status}}

      {:error, reason} ->
        Logger.error("Failed to fetch key from Vault", reason: inspect(reason))
        {:error, {:vault_connection_error, reason}}
    end
  end

  defp extract_key_from_response(body, key_name) do
    with {:ok, data} <- Map.fetch(body, "data"),
         {:ok, data_inner} <- Map.fetch(data, "data"),
         {:ok, key_b64} <- Map.fetch(data_inner, key_name),
         {:ok, key} <- Base.decode64(key_b64) do
      if byte_size(key) == 32 do
        {:ok, key}
      else
        {:error, :invalid_key_size}
      end
    else
      :error -> {:error, :key_not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  defp rotate_key_in_vault(state) do
    # Generate new master key
    new_key = :crypto.strong_rand_bytes(32)
    new_key_b64 = Base.encode64(new_key)

    url = "#{state.vault_url}/v1/#{state.vault_path}"
    headers = [
      {"X-Vault-Token", state.vault_token},
      {"Content-Type", "application/json"}
    ]

    body = Jason.encode!(%{data: %{state.key_name => new_key_b64}})

    case Req.post(url, headers: headers, body: body, receive_timeout: @vault_timeout) do
      {:ok, %{status: status, body: response}} when status in 200..299 ->
        version = get_in(response, ["data", "metadata", "version"]) || 1
        {:ok, version}

      {:ok, %{status: status}} ->
        Logger.error("Vault key rotation failed", status: status)
        {:error, {:vault_error, status}}

      {:error, reason} ->
        Logger.error("Failed to rotate key in Vault", reason: inspect(reason))
        {:error, {:vault_connection_error, reason}}
    end
  end

  defp fetch_key_version_from_vault(state, version) do
    url = "#{state.vault_url}/v1/#{state.vault_path}?version=#{version}"
    headers = [{"X-Vault-Token", state.vault_token}]

    case Req.get(url, headers: headers, receive_timeout: @vault_timeout) do
      {:ok, %{status: 200, body: body}} ->
        extract_key_from_response(body, state.key_name)

      {:ok, %{status: status}} ->
        Logger.error("Vault returned non-200 status for version", status: status, version: version)
        {:error, {:vault_error, status}}

      {:error, reason} ->
        Logger.error("Failed to fetch key version from Vault", reason: inspect(reason))
        {:error, {:vault_connection_error, reason}}
    end
  end

  defp fallback_key(%{fallback_key: nil}), do: :no_fallback

  defp fallback_key(%{fallback_key: key_b64}) when is_binary(key_b64) do
    case Base.decode64(key_b64) do
      {:ok, key} when byte_size(key) == 32 -> {:ok, key}
      {:ok, _} -> {:error, :invalid_fallback_key_size}
      :error -> {:error, :invalid_fallback_key_encoding}
    end
  end
end
