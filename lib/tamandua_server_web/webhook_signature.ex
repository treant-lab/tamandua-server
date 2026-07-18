defmodule TamanduaServerWeb.WebhookSignature do
  @moduledoc """
  Fail-closed authentication for public webhooks.

  Secrets are configured in `:public_webhook_secrets`, grouped by family and
  provider, or as `TAMANDUA_WEBHOOK_<FAMILY>_<PROVIDER>_SECRET`.
  """

  import Plug.Conn, only: [get_req_header: 2]

  @signature_headers [
    "x-tamandua-signature",
    "x-webhook-signature",
    "x-hub-signature-256",
    "x-signature"
  ]

  @type failure :: :no_signing_secret | :invalid_signature

  @spec verify(Plug.Conn.t(), atom() | String.t(), String.t()) :: :ok | {:error, failure()}
  def verify(conn, family, provider) when is_binary(provider) do
    with {:ok, secret} <- fetch_secret(family, provider),
         {:ok, raw_body} <- fetch_raw_body(conn),
         :ok <- verify_signature(conn, family, provider, raw_body, secret) do
      :ok
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp verify_signature(conn, :registries, "huggingface", _body, secret) do
    with {:ok, supplied} <- fetch_header(conn, ["x-webhook-secret"]),
         true <- secure_compare(supplied, secret),
         do: :ok,
         else: (_ -> {:error, :invalid_signature})
  end

  defp verify_signature(conn, :registries, "wandb", body, secret) do
    with {:ok, supplied} <- fetch_header(conn, ["x-wandb-signature"]),
         true <- valid_hex_hmac?(body, supplied, secret),
         do: :ok,
         else: (_ -> {:error, :invalid_signature})
  end

  defp verify_signature(conn, :registries, "mlflow", body, secret) do
    with {:ok, supplied} <- fetch_header(conn, ["x-mlflow-signature"]),
         {:ok, delivery_id} <- fetch_header(conn, ["x-mlflow-delivery-id"]),
         {:ok, timestamp} <- fetch_header(conn, ["x-mlflow-timestamp"]),
         :ok <- verify_fresh_timestamp(timestamp),
         true <- valid_mlflow_hmac?(body, supplied, delivery_id, timestamp, secret),
         do: :ok,
         else: (_ -> {:error, :invalid_signature})
  end

  defp verify_signature(conn, _family, _provider, body, secret) do
    with {:ok, supplied} <- fetch_header(conn, @signature_headers),
         true <- valid_hex_hmac?(body, supplied, secret),
         do: :ok,
         else: (_ -> {:error, :invalid_signature})
  end

  defp fetch_secret(family, provider) do
    configured = Application.get_env(:tamandua_server, :public_webhook_secrets, %{})

    secret =
      configured
      |> config_value(family)
      |> config_value(provider)
      |> Kernel.||(System.get_env(secret_env_name(family, provider)))

    if is_binary(secret) and byte_size(secret) > 0,
      do: {:ok, secret},
      else: {:error, :no_signing_secret}
  end

  defp config_value(config, key) when is_map(config) do
    Map.get(config, key) || Map.get(config, to_string(key)) || existing_atom_value(config, key)
  end

  defp config_value(config, key) when is_list(config) do
    case existing_atom(key) do
      nil -> nil
      atom -> Keyword.get(config, atom)
    end
  end

  defp config_value(_, _), do: nil

  defp existing_atom_value(config, key) do
    case existing_atom(key) do
      nil -> nil
      atom -> Map.get(config, atom)
    end
  end

  defp existing_atom(key) when is_atom(key), do: key

  defp existing_atom(key) do
    String.to_existing_atom(key)
  rescue
    ArgumentError -> nil
  end

  defp secret_env_name(family, provider) do
    suffix =
      [family, provider]
      |> Enum.map(&to_string/1)
      |> Enum.map(&String.upcase/1)
      |> Enum.map(&String.replace(&1, ~r/[^A-Z0-9]+/, "_"))
      |> Enum.join("_")

    "TAMANDUA_WEBHOOK_#{suffix}_SECRET"
  end

  defp fetch_raw_body(conn) do
    case conn.assigns[:raw_body] || conn.private[:raw_body] do
      body when is_binary(body) and byte_size(body) > 0 ->
        {:ok, body}

      chunks when is_list(chunks) and chunks != [] ->
        {:ok, chunks |> Enum.reverse() |> IO.iodata_to_binary()}

      _ ->
        {:error, :invalid_signature}
    end
  end

  defp fetch_header(conn, headers) do
    value =
      Enum.find_value(headers, fn header ->
        case get_req_header(conn, header) do
          [value | _] when is_binary(value) and byte_size(value) > 0 -> value
          _ -> nil
        end
      end)

    if value, do: {:ok, value}, else: {:error, :invalid_signature}
  end

  defp valid_hex_hmac?(body, signature, secret) do
    supplied = String.replace_prefix(signature, "sha256=", "") |> String.downcase()
    expected = :crypto.mac(:hmac, :sha256, secret, body) |> Base.encode16(case: :lower)
    secure_compare(supplied, expected)
  end

  defp valid_mlflow_hmac?(body, "v1," <> supplied, delivery_id, timestamp, secret) do
    expected =
      :crypto.mac(:hmac, :sha256, secret, Enum.join([delivery_id, timestamp, body], "."))
      |> Base.encode64()

    secure_compare(supplied, expected)
  end

  defp valid_mlflow_hmac?(_, _, _, _, _), do: false

  defp verify_fresh_timestamp(timestamp) do
    with {seconds, ""} <- Integer.parse(timestamp),
         true <- abs(System.system_time(:second) - seconds) <= 300,
         do: :ok,
         else: (_ -> {:error, :invalid_signature})
  end

  defp secure_compare(left, right) do
    byte_size(left) == byte_size(right) and Plug.Crypto.secure_compare(left, right)
  end
end
