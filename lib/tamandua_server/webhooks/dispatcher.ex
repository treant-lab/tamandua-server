defmodule TamanduaServer.Webhooks.Dispatcher do
  @moduledoc """
  Core webhook dispatch logic.

  Handles:
  - Finding relevant webhooks for an event
  - Enqueuing webhook delivery jobs
  - Building payloads
  - Computing HMAC signatures
  """

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Webhooks.{Webhook, OAuthClient, TemplateEngine}
  alias TamanduaServer.Workers.WebhookWorker

  @doc """
  Dispatches a webhook event to all matching webhooks.

  ## Examples

      iex> dispatch_event("alert.created", alert_id, %{alert: alert_data})
      {:ok, 3}  # 3 webhooks enqueued

  """
  def dispatch_event(event_type, event_id, payload, opts \\ []) do
    organization_id = Keyword.get(opts, :organization_id)

    webhooks = find_matching_webhooks(event_type, organization_id)

    Enum.each(webhooks, fn webhook ->
      enqueue_webhook_job(webhook, event_type, event_id, payload)
    end)

    {:ok, length(webhooks)}
  end

  @doc """
  Finds all webhooks that should receive this event.
  """
  def find_matching_webhooks(event_type, organization_id) do
    import Ecto.Query

    query =
      from w in Webhook,
        where: w.enabled == true,
        where: ^event_type in w.events

    query =
      if organization_id do
        where(query, [w], w.organization_id == ^organization_id)
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Enqueues a webhook delivery job using Oban.

  Supports priority-based queue assignment:
  - critical: priority 0 (highest)
  - high: priority 1
  - normal: priority 2
  - low: priority 3
  """
  def enqueue_webhook_job(webhook, event_type, event_id, payload) do
    priority = priority_to_number(webhook.priority)

    %{
      webhook_id: webhook.id,
      event_type: event_type,
      event_id: event_id,
      payload: payload
    }
    |> WebhookWorker.new(queue: :webhooks, priority: priority)
    |> Oban.insert()
  end

  defp priority_to_number("critical"), do: 0
  defp priority_to_number("high"), do: 1
  defp priority_to_number("normal"), do: 2
  defp priority_to_number("low"), do: 3
  defp priority_to_number(_), do: 2

  @doc """
  Builds the webhook payload with event data and metadata.

  If webhook has a template enabled, renders the template.
  Otherwise, returns standard JSON payload.
  """
  def build_payload(webhook, event_type, event_id, data) do
    standard_payload = %{
      event: event_type,
      event_id: event_id,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      data: data
    }

    if webhook.use_template && webhook.template do
      case TemplateEngine.render(webhook.template, standard_payload) do
        {:ok, rendered} -> rendered
        {:error, _} -> standard_payload
      end
    else
      standard_payload
    end
  end

  # Backwards compatibility
  def build_payload(event_type, event_id, data) do
    %{
      event: event_type,
      event_id: event_id,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      data: data
    }
  end

  @doc """
  Computes HMAC-SHA256 signature for webhook payload.

  Used for webhook authentication when auth_type is "hmac".
  """
  def compute_hmac_signature(payload, secret) when is_map(payload) do
    payload
    |> Jason.encode!()
    |> compute_hmac_signature(secret)
  end

  def compute_hmac_signature(payload_string, secret) when is_binary(payload_string) do
    :crypto.mac(:hmac, :sha256, secret, payload_string)
    |> Base.encode16(case: :lower)
  end

  @doc """
  Sends a test event to a webhook.
  """
  def send_test_event(webhook) do
    test_payload = %{
      message: "This is a test webhook from Tamandua EDR",
      webhook_id: webhook.id,
      webhook_name: webhook.name,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    enqueue_webhook_job(webhook, "system.test", webhook.id, test_payload)
  end

  @doc """
  Delivers a webhook synchronously (used by WebhookWorker).

  Returns {:ok, response_data} or {:error, error_data}.

  Supports:
  - Multiple HTTP methods (POST, PUT, PATCH)
  - JSON and XML payloads
  - OAuth 2.0 authentication
  - mTLS (client certificates)
  - Custom templates
  """
  def deliver_webhook(webhook, event_type, payload) do
    start_time = System.monotonic_time(:millisecond)

    with {:ok, headers} <- build_headers(webhook, payload),
         {:ok, body} <- encode_body(webhook, payload) do
      Logger.info(
        "[Webhook] Delivering #{event_type} to #{webhook.name} (#{webhook.url})"
      )

      http_method = String.downcase(webhook.http_method) |> String.to_atom()
      req_opts = build_request_options(webhook, headers, body)

      result = apply(Req, http_method, [webhook.url, req_opts])
      duration_ms = System.monotonic_time(:millisecond) - start_time

      case result do
        {:ok, %Req.Response{status: status, headers: headers, body: body}}
        when status in 200..299 ->
          {:ok,
           %{
             status: status,
             headers: headers_to_map(headers),
             body: body,
             duration_ms: duration_ms
           }}

        {:ok, %Req.Response{status: status, headers: headers, body: body}} ->
          {:error,
           %{
             status: status,
             headers: headers_to_map(headers),
             body: body,
             duration_ms: duration_ms,
             message: "HTTP #{status}"
           }}

        {:error, exception} ->
          {:error,
           %{
             status: nil,
             headers: %{},
             body: nil,
             duration_ms: duration_ms,
             message: Exception.message(exception)
           }}
      end
    else
      {:error, reason} ->
        duration_ms = System.monotonic_time(:millisecond) - start_time

        {:error,
         %{
           status: nil,
           headers: %{},
           body: nil,
           duration_ms: duration_ms,
           message: "Failed to prepare request: #{inspect(reason)}"
         }}
    end
  end

  defp build_request_options(webhook, headers, body) do
    opts = [
      headers: headers,
      body: body,
      receive_timeout: webhook.timeout_seconds * 1000,
      retry: false
    ]

    # Add mTLS configuration if enabled
    if webhook.mtls_enabled && webhook.mtls_client_cert do
      cert = decode_pem(webhook.mtls_client_cert)
      key = decode_pem(webhook.mtls_client_key)
      ca_cert = if webhook.mtls_ca_cert, do: decode_pem(webhook.mtls_ca_cert), else: nil

      ssl_opts = [
        cert: cert,
        key: key
      ]

      ssl_opts = if ca_cert, do: Keyword.put(ssl_opts, :cacerts, [ca_cert]), else: ssl_opts

      Keyword.put(opts, :connect_options, ssl: ssl_opts)
    else
      opts
    end
  end

  defp decode_pem(pem_string) do
    # In production, properly decode PEM certificates
    # For now, return the string
    pem_string
  end

  defp encode_body(webhook, payload) do
    case webhook.payload_format do
      "json" ->
        {:ok, Jason.encode!(payload)}

      "xml" ->
        # Simple XML encoding - in production you'd use a proper XML library
        xml = map_to_xml(payload)
        {:ok, xml}

      _ ->
        {:ok, Jason.encode!(payload)}
    end
  end

  defp map_to_xml(map) when is_map(map) do
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<webhook>\n" <>
      Enum.map_join(map, "\n", fn {k, v} -> "  <#{k}>#{escape_xml(v)}</#{k}>" end) <>
      "\n</webhook>"
  end

  defp escape_xml(value) when is_binary(value) do
    value
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
    |> String.replace("'", "&apos;")
  end

  defp escape_xml(value), do: inspect(value)

  defp build_headers(webhook, payload) do
    content_type = webhook.content_type || "application/json"

    base_headers = [
      {"content-type", content_type},
      {"user-agent", "TamanduaEDR-Webhook/1.0"}
    ]

    case build_auth_headers(webhook, payload) do
      {:ok, auth_headers} ->
        {:ok, base_headers ++ auth_headers}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp build_auth_headers(webhook, payload) do
    case webhook.auth_type do
      "basic" ->
        credentials = Base.encode64("#{webhook.auth_username}:#{webhook.auth_password}")
        {:ok, [{"authorization", "Basic #{credentials}"}]}

      "bearer" ->
        {:ok, [{"authorization", "Bearer #{webhook.auth_token}"}]}

      "hmac" ->
        signature = compute_hmac_signature(payload, webhook.secret)
        {:ok, [{"x-tamandua-signature", signature}]}

      "custom_headers" ->
        headers = Enum.map(webhook.custom_headers, fn {k, v} -> {String.downcase(k), v} end)
        {:ok, headers}

      "oauth2" ->
        case OAuthClient.get_access_token(webhook) do
          {:ok, access_token} ->
            {:ok, [{"authorization", "Bearer #{access_token}"}]}

          {:error, reason} ->
            {:error, "OAuth2 token fetch failed: #{inspect(reason)}"}
        end

      "mtls" ->
        # mTLS uses SSL/TLS layer, no additional headers needed
        {:ok, []}

      _ ->
        {:ok, []}
    end
  end

  defp headers_to_map(headers) when is_list(headers) do
    Enum.into(headers, %{})
  end

  defp headers_to_map(headers) when is_map(headers), do: headers
end
