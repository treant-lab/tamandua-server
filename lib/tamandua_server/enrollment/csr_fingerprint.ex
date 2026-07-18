defmodule TamanduaServer.Enrollment.CSRFingerprint do
  @moduledoc """
  Versioned HMAC fingerprints for CSR enrollment intents.

  The input contract accepts only the installation-token digest. Callers must
  never pass or persist the clear installation token here.
  """

  @domain "tamandua.enrollment.csr-intent.fingerprint.v1"
  @idempotency_domain "tamandua.enrollment.csr-intent.idempotency.v1"
  @fields [:organization_id, :installation_token_digest, :csr_sha256, :agent_info_canonical]
  @token_digest_regex ~r/\A[0-9a-f]{64}\z/

  def derive(material, idempotency_key, opts \\ [])
      when is_map(material) and is_binary(idempotency_key) do
    with :ok <- validate_idempotency_key(idempotency_key),
         {:ok, version, key} <- fetch_key(opts),
         {:ok, encoded} <- encode_material(material) do
      {:ok,
       %{
         fingerprint_key_version: version,
         request_fingerprint: hmac(key, frame(@domain) <> encoded),
         idempotency_key_hash: hmac(key, frame(@idempotency_domain) <> frame(idempotency_key))
       }}
    end
  end

  def derive(_material, _idempotency_key, _opts), do: {:error, :invalid_fingerprint_material}

  def secure_compare(left, right)
      when is_binary(left) and is_binary(right) and byte_size(left) == 32 and
             byte_size(right) == 32,
      do: Plug.Crypto.secure_compare(left, right)

  def secure_compare(_left, _right), do: false

  defp fetch_key(opts) do
    keyring = Keyword.get_lazy(opts, :keyring, &configured_keyring/0)
    version = Keyword.get(opts, :version, keyring[:current_version])
    keys = keyring[:keys] || %{}

    case {version, Map.get(keys, version)} do
      {version, key}
      when is_integer(version) and version in 1..32_767 and is_binary(key) and
             byte_size(key) >= 32 ->
        {:ok, version, key}

      _ ->
        {:error, :fingerprint_key_unavailable}
    end
  end

  defp configured_keyring do
    Application.get_env(:tamandua_server, :enrollment_csr_fingerprint_keyring, [])
  end

  defp encode_material(material) do
    with true <- MapSet.new(Map.keys(material)) == MapSet.new(@fields),
         {:ok, organization_id} <- Map.fetch(material, :organization_id),
         {:ok, ^organization_id} <- Ecto.UUID.cast(organization_id),
         {:ok, token_digest} <- Map.fetch(material, :installation_token_digest),
         true <- is_binary(token_digest) and Regex.match?(@token_digest_regex, token_digest),
         {:ok, csr_sha256} when is_binary(csr_sha256) and byte_size(csr_sha256) == 32 <-
           Map.fetch(material, :csr_sha256),
         {:ok, agent_info} when is_binary(agent_info) and byte_size(agent_info) in 2..16_384 <-
           Map.fetch(material, :agent_info_canonical) do
      encoded =
        Enum.map_join(@fields, fn field ->
          value = Map.fetch!(material, field)
          frame(Atom.to_string(field)) <> frame(value)
        end)

      {:ok, encoded}
    else
      _ -> {:error, :invalid_fingerprint_material}
    end
  end

  defp validate_idempotency_key(value) when byte_size(value) in 16..256, do: :ok
  defp validate_idempotency_key(_value), do: {:error, :invalid_idempotency_key}

  defp frame(value), do: <<byte_size(value)::unsigned-big-32, value::binary>>
  defp hmac(key, value), do: :crypto.mac(:hmac, :sha256, key, value)
end
