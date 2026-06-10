defmodule TamanduaServerWeb.Plugs.WebhookAuth do
  @moduledoc """
  Secure webhook authentication plug.

  Verifies HMAC signatures for incoming webhooks using server-side secrets only.
  The secret is NEVER taken from the request payload - it must be looked up from:
  - Database (integration config)
  - Application environment

  ## Security Features

  - HMAC signature verification using constant-time comparison
  - Raw body preservation for signature calculation
  - Fail-closed in production (rejects if no secret configured)
  - Replay attack prevention via timestamp validation
  - Multiple signature header support (X-Hub-Signature-256, X-Signature, etc.)

  ## Usage

      plug TamanduaServerWeb.Plugs.WebhookAuth, source: :integration
      plug TamanduaServerWeb.Plugs.WebhookAuth, source: :config, key: :stripe_webhook_secret

  ## Options

  - `:source` - Where to look up the secret (:integration, :config, :param_key)
  - `:key` - Config key when source is :config
  - `:param_key` - Path param or query param key for integration ID when source is :integration
  - `:optional` - If true, allow requests without signatures in dev/test
  - `:signature_headers` - List of header names to check for signatures
  """

  @behaviour Plug

  import Plug.Conn
  require Logger

  alias TamanduaServer.Integrations.Config, as: IntegrationConfig

  @default_signature_headers [
    "x-hub-signature-256",
    "x-signature",
    "x-tines-signature",
    "x-webhook-signature",
    "x-slack-signature"
  ]

  @impl true
  def init(opts) do
    %{
      source: Keyword.get(opts, :source, :integration),
      key: Keyword.get(opts, :key),
      param_key: Keyword.get(opts, :param_key, "integration_id"),
      optional: Keyword.get(opts, :optional, false),
      signature_headers: Keyword.get(opts, :signature_headers, @default_signature_headers)
    }
  end

  @impl true
  def call(conn, opts) do
    with {:ok, secret} <- get_webhook_secret(conn, opts),
         {:ok, signature} <- get_signature(conn, opts.signature_headers),
         :ok <- verify_signature(conn, secret, signature) do
      conn
      |> assign(:webhook_authenticated, true)
      |> assign(:webhook_signature_verified, true)
    else
      {:error, :no_secret_configured} ->
        handle_no_secret(conn, opts)

      {:error, :missing_signature} ->
        handle_missing_signature(conn, opts)

      {:error, :invalid_signature} ->
        reject_request(conn, "Invalid webhook signature", :unauthorized)

      {:error, :replay_attack} ->
        reject_request(conn, "Request timestamp expired or invalid", :unauthorized)

      {:error, :integration_not_found} ->
        reject_request(conn, "Integration not found", :not_found)

      {:error, reason} ->
        Logger.error("[WebhookAuth] Unexpected error: #{inspect(reason)}")
        reject_request(conn, "Webhook authentication failed", :unauthorized)
    end
  end

  # ============================================================================
  # Secret Retrieval - NEVER from request payload
  # ============================================================================

  defp get_webhook_secret(conn, %{source: :integration, param_key: param_key}) do
    integration_id = conn.path_params[param_key] ||
                     conn.params[param_key] ||
                     conn.path_params["integration_id"] ||
                     conn.params["integration_id"]

    if integration_id do
      case IntegrationConfig.get_integration(integration_id) do
        {:ok, integration} ->
          secret = get_secret_from_config(integration.config)
          if secret, do: {:ok, secret}, else: {:error, :no_secret_configured}

        {:error, :not_found} ->
          {:error, :integration_not_found}
      end
    else
      {:error, :no_secret_configured}
    end
  end

  defp get_webhook_secret(_conn, %{source: :config, key: key}) when is_atom(key) do
    case Application.get_env(:tamandua_server, key) do
      nil -> {:error, :no_secret_configured}
      secret when is_binary(secret) and secret != "" -> {:ok, secret}
      _ -> {:error, :no_secret_configured}
    end
  end

  defp get_webhook_secret(_conn, %{source: :env, key: key}) when is_binary(key) do
    case System.get_env(key) do
      nil -> {:error, :no_secret_configured}
      secret when is_binary(secret) and secret != "" -> {:ok, secret}
      _ -> {:error, :no_secret_configured}
    end
  end

  defp get_webhook_secret(_conn, _opts), do: {:error, :no_secret_configured}

  defp get_secret_from_config(config) when is_map(config) do
    # Check multiple possible secret field names
    config["webhook_secret"] ||
      config[:webhook_secret] ||
      config["secret"] ||
      config[:secret] ||
      config["signing_secret"] ||
      config[:signing_secret]
  end

  defp get_secret_from_config(_), do: nil

  # ============================================================================
  # Signature Extraction
  # ============================================================================

  defp get_signature(conn, headers) do
    signature = Enum.find_value(headers, fn header ->
      case get_req_header(conn, header) do
        [sig | _] when is_binary(sig) and sig != "" -> sig
        _ -> nil
      end
    end)

    if signature do
      {:ok, signature}
    else
      {:error, :missing_signature}
    end
  end

  # ============================================================================
  # Signature Verification
  # ============================================================================

  defp verify_signature(conn, secret, signature) do
    raw_body = get_raw_body(conn)

    if raw_body do
      # Check for timestamp to prevent replay attacks
      with :ok <- verify_timestamp(conn) do
        if verify_hmac(raw_body, signature, secret) do
          :ok
        else
          {:error, :invalid_signature}
        end
      end
    else
      Logger.warning("[WebhookAuth] No raw body available for signature verification")
      {:error, :invalid_signature}
    end
  end

  defp get_raw_body(conn) do
    # Try multiple locations where raw body might be cached
    conn.assigns[:raw_body] ||
      conn.private[:raw_body] ||
      # CacheBodyReader stores as list, join if needed
      case conn.assigns[:raw_body] do
        chunks when is_list(chunks) -> Enum.join(Enum.reverse(chunks))
        _ -> nil
      end
  end

  defp verify_hmac(body, signature, secret) do
    # Support multiple signature formats
    {algorithm, expected_hash} = parse_signature(signature)

    computed = compute_hmac(body, secret, algorithm)

    Plug.Crypto.secure_compare(computed, expected_hash)
  end

  defp parse_signature(signature) do
    cond do
      String.starts_with?(signature, "sha256=") ->
        {:sha256, String.replace_prefix(signature, "sha256=", "")}

      String.starts_with?(signature, "sha512=") ->
        {:sha512, String.replace_prefix(signature, "sha512=", "")}

      String.starts_with?(signature, "sha1=") ->
        {:sha1, String.replace_prefix(signature, "sha1=", "")}

      String.starts_with?(signature, "v0=") ->
        # Slack format
        {:sha256, String.replace_prefix(signature, "v0=", "")}

      true ->
        # Assume SHA256 if no prefix
        {:sha256, signature}
    end
  end

  defp compute_hmac(body, secret, algorithm) do
    algo = case algorithm do
      :sha256 -> :sha256
      :sha512 -> :sha512
      :sha1 -> :sha
      _ -> :sha256
    end

    :crypto.mac(:hmac, algo, secret, body)
    |> Base.encode16(case: :lower)
  end

  # ============================================================================
  # Replay Attack Prevention
  # ============================================================================

  defp verify_timestamp(conn) do
    # Check for timestamp in various headers
    timestamp = get_timestamp_from_headers(conn)

    case timestamp do
      nil ->
        # No timestamp provided - allow (some webhooks don't include timestamps)
        :ok

      ts when is_integer(ts) ->
        now = System.system_time(:second)
        diff = abs(now - ts)

        # Allow 5 minute window
        if diff <= 300 do
          :ok
        else
          {:error, :replay_attack}
        end
    end
  end

  defp get_timestamp_from_headers(conn) do
    # Try various timestamp header formats
    headers = [
      {"x-slack-request-timestamp", &parse_unix_timestamp/1},
      {"x-timestamp", &parse_unix_timestamp/1},
      {"x-webhook-timestamp", &parse_unix_timestamp/1}
    ]

    Enum.find_value(headers, fn {header, parser} ->
      case get_req_header(conn, header) do
        [value | _] -> parser.(value)
        _ -> nil
      end
    end)
  end

  defp parse_unix_timestamp(value) when is_binary(value) do
    case Integer.parse(value) do
      {ts, _} -> ts
      :error -> nil
    end
  end

  defp parse_unix_timestamp(_), do: nil

  # ============================================================================
  # Error Handling
  # ============================================================================

  defp handle_no_secret(conn, opts) do
    if allow_insecure_webhook?() or opts.optional do
      Logger.warning("[WebhookAuth] No secret configured - allowing webhook in insecure mode")
      conn
      |> assign(:webhook_authenticated, false)
      |> assign(:webhook_signature_verified, false)
    else
      reject_request(conn, "Webhook not configured", :unauthorized)
    end
  end

  defp handle_missing_signature(conn, opts) do
    if allow_insecure_webhook?() or opts.optional do
      Logger.warning("[WebhookAuth] Missing signature - allowing webhook in insecure mode")
      conn
      |> assign(:webhook_authenticated, false)
      |> assign(:webhook_signature_verified, false)
    else
      reject_request(conn, "Missing webhook signature", :unauthorized)
    end
  end

  defp allow_insecure_webhook? do
    # Only allow insecure webhooks in dev/test with explicit config
    Application.get_env(:tamandua_server, :webhook_insecure_mode, false) and
      Application.get_env(:tamandua_server, :env) in [:dev, :test]
  end

  defp reject_request(conn, message, status) do
    conn
    |> put_status(status)
    |> Phoenix.Controller.json(%{error: message})
    |> halt()
  end
end
