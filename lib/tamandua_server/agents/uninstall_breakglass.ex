defmodule TamanduaServer.Agents.UninstallBreakglass do
  @moduledoc """
  Emits bounded, offline uninstall authorities signed by a dedicated Ed25519 key.

  The key domain is intentionally independent from agent update, configuration,
  enrollment, JWT and audit-signing keys. An envelope is returned only after its
  issuance has been inserted into a dedicated, tenant-bound append-only store.
  That record proves issuance only; offline consumption belongs to the endpoint
  replay ledger and is never inferred by this server module.
  """

  import Ecto.Query

  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Agents.{Agent, AgentUninstallBreakglassIssuance}
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant

  @config_env "TAMANDUA_UNINSTALL_BREAKGLASS_ED25519_PRIVATE_KEYS_JSON"
  @domain "tamandua.uninstall-breakglass.ed25519/v1"
  @domain_prefix @domain <> <<0>>
  @schema_version "tamandua.uninstall-breakglass/v1"
  @action "agent_uninstall"
  @authorization_mode "offline_breakglass"
  @default_ttl_seconds 3_600
  @maximum_ttl_seconds 86_400
  @maximum_config_bytes 16_384
  @maximum_keys 16
  @maximum_payload_bytes 4_096
  @maximum_envelope_bytes 16_384
  @platforms ~w(windows linux macos)
  @consumers ~w(native_cli windows_msi)
  @payload_keys ~w(action agent_id authorization_mode consumer expires_at intent_id issued_at issued_by_user_id key_domain key_id nonce not_before organization_id platform reason schema_version)

  @type envelope :: %{payload: String.t(), signature: String.t()}

  @spec issue(String.t(), String.t(), String.t(), map(), keyword()) ::
          {:ok, envelope()} | {:error, atom()}
  def issue(organization_id, agent_id, issued_by_user_id, attrs, opts \\ [])

  def issue(organization_id, agent_id, issued_by_user_id, attrs, opts)
      when is_map(attrs) and is_list(opts) do
    with {:ok, organization_id} <- canonical_uuid(organization_id, :tenant_context_required),
         {:ok, agent_id} <- canonical_uuid(agent_id, :agent_not_found),
         {:ok, issued_by_user_id} <- canonical_uuid(issued_by_user_id, :issuer_invalid),
         {:ok, reason} <- reason(value(attrs, :reason)),
         {:ok, platform} <- allowlisted(value(attrs, :platform), @platforms),
         {:ok, consumer} <- allowlisted(value(attrs, :consumer), @consumers),
         :ok <- validate_consumer_platform(platform, consumer),
         {:ok, ttl_seconds} <- ttl_seconds(value(attrs, :ttl_seconds)),
         :ok <- authorize_target(organization_id, agent_id, issued_by_user_id, opts),
         {:ok, %{key_id: key_id, private_key: private_key}} <- load_active_key(opts),
         {:ok, issued_at} <- issued_at(opts),
         {:ok, intent_id} <- generated_uuid(opts, :intent_id),
         {:ok, nonce_bytes} <- generated_nonce(opts),
         {:ok, payload_bytes, payload} <-
           build_payload(%{
             organization_id: organization_id,
             agent_id: agent_id,
             issued_by_user_id: issued_by_user_id,
             reason: reason,
             platform: platform,
             consumer: consumer,
             ttl_seconds: ttl_seconds,
             issued_at: issued_at,
             intent_id: intent_id,
             key_id: key_id,
             nonce_bytes: nonce_bytes
           }),
         {:ok, signature_bytes} <- sign(payload_bytes, private_key),
         :ok <- record_issuance(payload, payload_bytes, signature_bytes, opts) do
      {:ok,
       %{
         payload: Base.url_encode64(payload_bytes, padding: false),
         signature: Base.url_encode64(signature_bytes, padding: false)
       }}
    end
  end

  def issue(_organization_id, _agent_id, _issued_by_user_id, _attrs, _opts),
    do: {:error, :request_invalid}

  @doc false
  def canonical_payload(payload) when is_map(payload) do
    "{" <>
      Enum.map_join(@payload_keys, ",", fn key ->
        Jason.encode!(key) <> ":" <> Jason.encode!(Map.fetch!(payload, key))
      end) <> "}"
  end

  @doc false
  def domain_prefix, do: @domain_prefix

  @doc false
  def encode_envelope(%{payload: payload, signature: signature})
      when is_binary(payload) and is_binary(signature) do
    body =
      "{" <>
        Jason.encode!("payload") <>
        ":" <>
        Jason.encode!(payload) <>
        "," <>
        Jason.encode!("signature") <>
        ":" <>
        Jason.encode!(signature) <>
        "}"

    if byte_size(body) <= @maximum_envelope_bytes,
      do: {:ok, body},
      else: {:error, :request_invalid}
  end

  def encode_envelope(_envelope), do: {:error, :request_invalid}

  @doc false
  def load_active_key(opts \\ []) do
    with {:ok, encoded} <- configured_keyring(opts),
         true <- byte_size(encoded) in 1..@maximum_config_bytes,
         {:ok, decoded} <- decode_unique_json(encoded),
         :ok <- exact_keys(decoded, ~w(active_key_id keys)),
         {:ok, active_key_id} <- key_id(decoded["active_key_id"]),
         {:ok, entries} <- key_entries(decoded["keys"]),
         {:ok, private_key} <- active_private_key(entries, active_key_id) do
      {:ok, %{key_id: active_key_id, private_key: private_key}}
    else
      _ -> {:error, :signer_unavailable}
    end
  end

  defp configured_keyring(opts) do
    case Keyword.fetch(opts, :private_keys_json) do
      {:ok, value} when is_binary(value) -> {:ok, value}
      {:ok, _value} -> {:error, :signer_unavailable}
      :error ->
        case System.get_env(@config_env) do
          value when is_binary(value) and value != "" -> {:ok, value}
          _ -> {:error, :signer_unavailable}
        end
    end
  end

  defp decode_unique_json(encoded) do
    with {:ok, ordered} <- Jason.decode(encoded, objects: :ordered_objects),
         {:ok, decoded} <- ordered_to_plain(ordered) do
      {:ok, decoded}
    else
      _ -> {:error, :signer_unavailable}
    end
  end

  defp ordered_to_plain(%Jason.OrderedObject{values: pairs}) when is_list(pairs) do
    keys = Enum.map(pairs, &elem(&1, 0))

    if length(keys) == MapSet.size(MapSet.new(keys)) do
      Enum.reduce_while(pairs, {:ok, %{}}, fn {key, value}, {:ok, acc} ->
        case ordered_to_plain(value) do
          {:ok, plain} -> {:cont, {:ok, Map.put(acc, key, plain)}}
          error -> {:halt, error}
        end
      end)
    else
      {:error, :signer_unavailable}
    end
  end

  defp ordered_to_plain(values) when is_list(values) do
    Enum.reduce_while(values, {:ok, []}, fn value, {:ok, acc} ->
      case ordered_to_plain(value) do
        {:ok, plain} -> {:cont, {:ok, [plain | acc]}}
        error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
      error -> error
    end
  end

  defp ordered_to_plain(value), do: {:ok, value}

  defp key_entries(entries) when is_list(entries) and length(entries) in 1..@maximum_keys do
    Enum.reduce_while(entries, {:ok, %{}, MapSet.new()}, fn entry, {:ok, keys, material} ->
      with :ok <- exact_keys(entry, ~w(key_id private_key)),
           {:ok, id} <- key_id(entry["key_id"]),
           false <- Map.has_key?(keys, id),
           {:ok, private_key} <- canonical_private_key(entry["private_key"]),
           false <- MapSet.member?(material, private_key) do
        {:cont, {:ok, Map.put(keys, id, private_key), MapSet.put(material, private_key)}}
      else
        _ -> {:halt, {:error, :signer_unavailable}}
      end
    end)
    |> case do
      {:ok, keys, _material} -> {:ok, keys}
      error -> error
    end
  end

  defp key_entries(_entries), do: {:error, :signer_unavailable}

  defp active_private_key(entries, active_key_id) do
    case Map.fetch(entries, active_key_id) do
      {:ok, private_key} -> {:ok, private_key}
      :error -> {:error, :signer_unavailable}
    end
  end

  defp canonical_private_key(value) when is_binary(value) do
    with {:ok, decoded} <- Base.url_decode64(value, padding: false),
         true <- byte_size(decoded) == 32,
         true <- Base.url_encode64(decoded, padding: false) == value,
         false <- placeholder_key?(decoded),
         {:ok, public_key} <- derive_public_key(decoded),
         true <- valid_seed?(decoded, public_key) do
      {:ok, decoded}
    else
      _ -> {:error, :signer_unavailable}
    end
  end

  defp canonical_private_key(_value), do: {:error, :signer_unavailable}

  defp derive_public_key(seed) do
    case :crypto.generate_key(:eddsa, :ed25519, seed) do
      {public_key, _derived_private} when is_binary(public_key) and byte_size(public_key) == 32 ->
        {:ok, public_key}

      _ ->
        {:error, :signer_unavailable}
    end
  rescue
    _ -> {:error, :signer_unavailable}
  end

  defp valid_seed?(seed, public_key) do
    probe = @domain_prefix <> "key-validation"
    signature = :crypto.sign(:eddsa, :none, probe, [seed, :ed25519])

    is_binary(signature) and byte_size(signature) == 64 and
      :crypto.verify(:eddsa, :none, probe, signature, [public_key, :ed25519])
  rescue
    _ -> false
  end

  defp placeholder_key?(key) do
    key == :binary.copy(<<0>>, 32) or
      key == :binary.copy(<<1>>, 32) or
      MapSet.size(MapSet.new(:binary.bin_to_list(key))) == 1
  end

  defp key_id(value) when is_binary(value) and byte_size(value) in 1..64 do
    if Regex.match?(~r/^[a-z0-9][a-z0-9._-]*$/, value) and
         value not in ~w(default placeholder changeme change-me test example unknown) do
      {:ok, value}
    else
      {:error, :signer_unavailable}
    end
  end

  defp key_id(_value), do: {:error, :signer_unavailable}

  defp build_payload(attrs) do
    expires_at = DateTime.add(attrs.issued_at, attrs.ttl_seconds, :second)
    timestamp = &DateTime.to_iso8601/1

    payload = %{
      "action" => @action,
      "agent_id" => attrs.agent_id,
      "authorization_mode" => @authorization_mode,
      "consumer" => attrs.consumer,
      "expires_at" => timestamp.(expires_at),
      "intent_id" => attrs.intent_id,
      "issued_at" => timestamp.(attrs.issued_at),
      "issued_by_user_id" => attrs.issued_by_user_id,
      "key_domain" => @domain,
      "key_id" => attrs.key_id,
      "nonce" => Base.url_encode64(attrs.nonce_bytes, padding: false),
      "not_before" => timestamp.(attrs.issued_at),
      "organization_id" => attrs.organization_id,
      "platform" => attrs.platform,
      "reason" => attrs.reason,
      "schema_version" => @schema_version
    }

    encoded = canonical_payload(payload)

    if byte_size(encoded) <= @maximum_payload_bytes,
      do: {:ok, encoded, payload},
      else: {:error, :request_invalid}
  rescue
    _ -> {:error, :request_invalid}
  end

  defp sign(payload_bytes, private_key) do
    signature =
      :crypto.sign(:eddsa, :none, @domain_prefix <> payload_bytes, [private_key, :ed25519])

    if is_binary(signature) and byte_size(signature) == 64,
      do: {:ok, signature},
      else: {:error, :signer_unavailable}
  rescue
    _ -> {:error, :signer_unavailable}
  end

  defp record_issuance(payload, payload_bytes, _signature_bytes, opts) do
    {:ok, nonce_bytes} = Base.url_decode64(payload["nonce"], padding: false)

    issuance = %{
      intent_id: payload["intent_id"],
      organization_id: payload["organization_id"],
      agent_id: payload["agent_id"],
      issued_by_user_id: payload["issued_by_user_id"],
      reason: payload["reason"],
      platform: payload["platform"],
      consumer: payload["consumer"],
      key_id: payload["key_id"],
      issued_at: parse_timestamp!(payload["issued_at"]),
      not_before: parse_timestamp!(payload["not_before"]),
      expires_at: parse_timestamp!(payload["expires_at"]),
      payload_sha256: :crypto.hash(:sha256, payload_bytes),
      nonce_sha256: :crypto.hash(:sha256, nonce_bytes)
    }

    recorder = Keyword.get(opts, :recorder, &record_authoritative_issuance/1)

    case recorder.(issuance) do
      :ok -> :ok
      {:ok, _record} -> :ok
      _ -> {:error, :store_unavailable}
    end
  rescue
    _ -> {:error, :store_unavailable}
  end

  defp record_authoritative_issuance(issuance) do
    MultiTenant.with_organization(issuance.organization_id, fn ->
      %AgentUninstallBreakglassIssuance{}
      |> AgentUninstallBreakglassIssuance.issuance_changeset(issuance)
      |> Repo.insert()
    end)
  rescue
    _ -> {:error, :store_unavailable}
  end

  defp parse_timestamp!(value) do
    {:ok, timestamp, 0} = DateTime.from_iso8601(value)
    DateTime.truncate(timestamp, :microsecond)
  end

  defp authorize_target(organization_id, agent_id, issued_by_user_id, opts) do
    authorizer = Keyword.get(opts, :authorizer, &authorize_target_in_store/3)

    case authorizer.(organization_id, agent_id, issued_by_user_id) do
      :ok -> :ok
      {:error, reason} when reason in [:agent_not_found, :issuer_invalid, :store_unavailable] ->
        {:error, reason}

      _ ->
        {:error, :store_unavailable}
    end
  rescue
    _ -> {:error, :store_unavailable}
  end

  defp authorize_target_in_store(organization_id, agent_id, issued_by_user_id) do
    MultiTenant.with_organization(organization_id, fn ->
      agent_exists? =
        Repo.exists?(
          from(a in Agent,
            where: a.id == ^agent_id and a.organization_id == ^organization_id
          )
        )

      issuer_exists? =
        Repo.exists?(
          from(u in User,
            where: u.id == ^issued_by_user_id and u.organization_id == ^organization_id
          )
        )

      cond do
        not agent_exists? -> {:error, :agent_not_found}
        not issuer_exists? -> {:error, :issuer_invalid}
        true -> :ok
      end
    end)
  rescue
    _ -> {:error, :store_unavailable}
  end

  defp issued_at(opts) do
    now = Keyword.get_lazy(opts, :now, fn -> DateTime.utc_now() end)

    if match?(%DateTime{}, now),
      do: {:ok, now |> DateTime.to_unix(:second) |> DateTime.from_unix!(:second)},
      else: {:error, :request_invalid}
  end

  defp generated_uuid(opts, name) do
    value = Keyword.get_lazy(opts, name, &Ecto.UUID.generate/0)
    canonical_uuid(value, :signer_unavailable)
  end

  defp generated_nonce(opts) do
    nonce = Keyword.get_lazy(opts, :nonce_bytes, fn -> :crypto.strong_rand_bytes(32) end)
    if is_binary(nonce) and byte_size(nonce) == 32, do: {:ok, nonce}, else: {:error, :signer_unavailable}
  rescue
    _ -> {:error, :signer_unavailable}
  end

  defp ttl_seconds(nil), do: {:ok, @default_ttl_seconds}

  defp ttl_seconds(value) when is_integer(value) and value in 1..@maximum_ttl_seconds,
    do: {:ok, value}

  defp ttl_seconds(_value), do: {:error, :request_invalid}

  defp reason(value) when is_binary(value) and byte_size(value) in 8..512 do
    if String.valid?(value) and value == String.trim(value) and
         not Regex.match?(~r/[\x{0000}-\x{001F}\x{007F}-\x{009F}]/u, value) do
      {:ok, value}
    else
      {:error, :request_invalid}
    end
  end

  defp reason(_value), do: {:error, :request_invalid}

  defp value(attrs, key), do: Map.get(attrs, key) || Map.get(attrs, Atom.to_string(key))

  defp exact_keys(value, keys) when is_map(value) do
    if Enum.sort(Map.keys(value)) == Enum.sort(keys), do: :ok, else: {:error, :signer_unavailable}
  end

  defp exact_keys(_value, _keys), do: {:error, :signer_unavailable}

  defp allowlisted(value, allowlist) when is_binary(value) do
    if value in allowlist, do: {:ok, value}, else: {:error, :request_invalid}
  end

  defp allowlisted(_value, _allowlist), do: {:error, :request_invalid}

  defp validate_consumer_platform("windows", "windows_msi"), do: :ok
  defp validate_consumer_platform(_platform, "windows_msi"), do: {:error, :request_invalid}
  defp validate_consumer_platform(_platform, "native_cli"), do: :ok

  defp canonical_uuid(value, error) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> {:error, error}
    end
  end

  defp canonical_uuid(_value, error), do: {:error, error}
end
