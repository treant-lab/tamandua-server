defmodule TamanduaServerWeb.WebhookController do
  use TamanduaServerWeb, :controller

  require Logger

  alias TamanduaServer.Integrations
  alias TamanduaServerWeb.WebhookSignature
  alias TamanduaServer.Registries.{DownloadHook, MLflow, WandB, HuggingFace}

  @doc """
  Handle incoming threat intelligence feeds from various providers.
  """
  def threat_intel(conn, %{"provider" => provider} = params) do
    with :ok <- WebhookSignature.verify(conn, :threat_intel, provider) do
      Logger.info("Received authenticated threat intel from #{provider}")

      case process_threat_intel(provider, params) do
        {:ok, result} ->
          json(conn, %{status: "accepted", result: result})

        {:error, reason} ->
          conn
          |> put_status(400)
          |> json(%{error: reason})
      end
    else
      {:error, reason} -> reject_unsigned_webhook(conn, reason)
    end
  end

  @doc """
  Handle alert integration webhooks (Slack, PagerDuty, etc.).
  """
  def alert_integration(conn, %{"integration" => integration} = params) do
    with :ok <- WebhookSignature.verify(conn, :alerts, integration) do
      Logger.info("Received authenticated webhook for integration: #{integration}")

      case process_integration_webhook(integration, params) do
        :ok ->
          json(conn, %{status: "accepted"})

        {:error, reason} ->
          conn
          |> put_status(400)
          |> json(%{error: reason})
      end
    else
      {:error, reason} -> reject_unsigned_webhook(conn, reason)
    end
  end

  @doc """
  Handle SOAR platform webhook callbacks for async playbook execution results.

  SOAR platforms (Tines, XSOAR, Swimlane, etc.) call this endpoint to report
  the result of a playbook execution that was triggered by Tamandua.

  The callback payload should include:
  - `execution_id` - The Tamandua execution ID (returned when the playbook was triggered)
  - `status` - Execution status ("completed", "failed", "running")
  - `result` - Optional result data
  - `error` - Optional error message

  For Tines, the `x-tines-signature` header is verified against the configured
  webhook signing secret.
  """
  def soar_callback(conn, %{"platform" => platform} = params) do
    Logger.info("Received SOAR callback from platform: #{platform}")

    # Verify webhook signature for platforms that support it
    case verify_soar_signature(conn, platform) do
      :ok ->
        execution_id = params["execution_id"] || params["tamandua_execution_id"]

        if execution_id do
          # Parse the callback payload based on platform
          callback_data = parse_soar_callback(platform, params)

          case TamanduaServer.Integrations.SOAR.Executor.handle_webhook_callback(
                 execution_id,
                 callback_data
               ) do
            :ok ->
              json(conn, %{status: "accepted", execution_id: execution_id})

            {:error, :not_found} ->
              conn
              |> put_status(404)
              |> json(%{error: "Execution not found", execution_id: execution_id})
          end
        else
          conn
          |> put_status(400)
          |> json(%{error: "Missing execution_id in callback payload"})
        end

      {:error, reason} when reason in [:invalid_signature, :no_signing_secret] ->
        Logger.warning(
          "[WebhookController] SOAR callback from #{platform} rejected: #{inspect(reason)}"
        )

        conn
        |> put_status(401)
        |> json(%{error: "Webhook authentication failed"})
    end
  end

  defp reject_unsigned_webhook(conn, reason) do
    Logger.warning("[WebhookController] Public webhook rejected: #{inspect(reason)}")

    conn
    |> put_status(401)
    |> json(%{error: "Webhook authentication failed"})
  end

  defp verify_soar_signature(conn, "tines") do
    case Plug.Conn.get_req_header(conn, "x-tines-signature") do
      [signature | _] ->
        # Read cached raw body (requires CacheBodyReader plug or similar)
        case webhook_raw_body(conn) do
          {:ok, raw_body} ->
            TamanduaServer.Integrations.SOAR.Tines.verify_webhook_signature(raw_body, signature)

          {:error, reason} ->
            {:error, reason}
        end

      [] ->
        {:error, :invalid_signature}
    end
  end

  defp verify_soar_signature(conn, platform), do: WebhookSignature.verify(conn, :soar, platform)

  defp webhook_raw_body(conn) do
    case conn.assigns[:raw_body] || conn.private[:raw_body] do
      body when is_binary(body) and byte_size(body) > 0 ->
        {:ok, body}

      chunks when is_list(chunks) and chunks != [] ->
        {:ok, chunks |> Enum.reverse() |> IO.iodata_to_binary()}

      _ ->
        {:error, :invalid_signature}
    end
  end

  defp parse_soar_callback("tines", params) do
    TamanduaServer.Integrations.SOAR.Tines.parse_webhook_callback(params)
  end

  defp parse_soar_callback(_platform, params) do
    %{
      "status" => params["status"] || "completed",
      "result" => params["result"] || params["data"],
      "error" => params["error"] || params["error_message"]
    }
  end

  @doc """
  Bulk import IOCs from various formats.
  """
  def bulk_import(conn, %{"format" => format, "data" => data}) do
    Logger.info("Bulk import request: format=#{format}")

    case process_bulk_import(format, data) do
      {:ok, result} ->
        json(conn, %{status: "accepted", result: result})

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{error: reason})
    end
  end

  defp process_threat_intel(provider, params) do
    case provider do
      "misp" -> Integrations.process_misp_feed(params)
      "otx" -> Integrations.process_otx_feed(params)
      "virustotal" -> Integrations.process_virustotal_feed(params)
      _ -> {:error, "Unknown provider: #{provider}"}
    end
  end

  defp process_integration_webhook(integration, params) do
    case integration do
      "slack" -> Integrations.process_slack_action(params)
      "pagerduty" -> Integrations.process_pagerduty_webhook(params)
      "teams" -> Integrations.process_teams_webhook(params)
      _ -> {:error, "Unknown integration: #{integration}"}
    end
  end

  defp process_bulk_import(format, data) do
    case format do
      "stix" -> import_stix(data)
      "csv" -> import_csv(data)
      "txt" -> import_txt(data)
      _ -> {:error, "Unknown format: #{format}"}
    end
  end

  # Import STIX 2.x format (simplified)
  defp import_stix(data) do
    objects = data["objects"] || []

    results =
      Enum.map(objects, fn obj ->
        case obj["type"] do
          "indicator" ->
            import_stix_indicator(obj)

          _ ->
            {:skipped, obj["type"]}
        end
      end)

    created =
      Enum.count(results, fn
        {:ok, _} -> true
        _ -> false
      end)

    {:ok, %{created: created, total: length(objects)}}
  end

  defp import_stix_indicator(indicator) do
    pattern = indicator["pattern"] || ""

    # Parse STIX pattern like [file:hashes.MD5 = 'abc123']
    cond do
      String.contains?(pattern, "file:hashes.MD5") ->
        value = extract_pattern_value(pattern)
        create_ioc("hash_md5", value, indicator)

      String.contains?(pattern, "file:hashes.SHA-256") ->
        value = extract_pattern_value(pattern)
        create_ioc("hash_sha256", value, indicator)

      String.contains?(pattern, "ipv4-addr:value") ->
        value = extract_pattern_value(pattern)
        create_ioc("ip", value, indicator)

      String.contains?(pattern, "domain-name:value") ->
        value = extract_pattern_value(pattern)
        create_ioc("domain", value, indicator)

      String.contains?(pattern, "url:value") ->
        value = extract_pattern_value(pattern)
        create_ioc("url", value, indicator)

      true ->
        {:skipped, :unknown_pattern}
    end
  end

  defp extract_pattern_value(pattern) do
    case Regex.run(~r/'([^']+)'/, pattern) do
      [_, value] -> value
      _ -> ""
    end
  end

  defp create_ioc(type, value, indicator) do
    attrs = %{
      type: type,
      value: value,
      description: indicator["description"] || indicator["name"],
      source: "stix_import",
      severity: "medium",
      enabled: true
    }

    create_global_ioc(attrs)
  end

  # Import CSV format
  defp import_csv(data) when is_binary(data) do
    lines = String.split(data, "\n", trim: true)

    results =
      Enum.map(lines, fn line ->
        parts = String.split(line, ",", parts: 3)

        case parts do
          [type, value] ->
            create_ioc_from_csv(type, value, "")

          [type, value, description] ->
            create_ioc_from_csv(type, value, description)

          _ ->
            {:skipped, :invalid_format}
        end
      end)

    created =
      Enum.count(results, fn
        {:ok, _} -> true
        _ -> false
      end)

    {:ok, %{created: created, total: length(lines)}}
  end

  defp import_csv(_), do: {:error, "CSV data must be a string"}

  defp create_ioc_from_csv(type, value, description) do
    attrs = %{
      type: String.trim(type),
      value: String.trim(value),
      description: String.trim(description),
      source: "csv_import",
      severity: "medium",
      enabled: true
    }

    create_global_ioc(attrs)
  end

  # Import plain text (one IOC per line, auto-detect type)
  defp import_txt(data) when is_binary(data) do
    lines =
      String.split(data, "\n", trim: true)
      |> Enum.map(&String.trim/1)
      |> Enum.filter(&(&1 != ""))

    results =
      Enum.map(lines, fn line ->
        type = detect_ioc_type(line)
        create_ioc_from_txt(type, line)
      end)

    created =
      Enum.count(results, fn
        {:ok, _} -> true
        _ -> false
      end)

    {:ok, %{created: created, total: length(lines)}}
  end

  defp import_txt(_), do: {:error, "TXT data must be a string"}

  defp detect_ioc_type(value) do
    cond do
      # MD5 hash (32 hex chars)
      Regex.match?(~r/^[a-fA-F0-9]{32}$/, value) -> "hash_md5"
      # SHA1 hash (40 hex chars)
      Regex.match?(~r/^[a-fA-F0-9]{40}$/, value) -> "hash_sha1"
      # SHA256 hash (64 hex chars)
      Regex.match?(~r/^[a-fA-F0-9]{64}$/, value) -> "hash_sha256"
      # IPv4 address
      Regex.match?(~r/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/, value) -> "ip"
      # URL
      String.starts_with?(value, "http://") or String.starts_with?(value, "https://") -> "url"
      # Email
      Regex.match?(~r/^[^\s@]+@[^\s@]+\.[^\s@]+$/, value) -> "email"
      # Domain (default fallback for non-IP strings with dots)
      Regex.match?(~r/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, value) -> "domain"
      # Unknown
      true -> "unknown"
    end
  end

  defp create_ioc_from_txt(type, value) do
    attrs = %{
      type: type,
      value: value,
      description: "Imported from text file",
      source: "txt_import",
      severity: "medium",
      enabled: true
    }

    create_global_ioc(attrs)
  end

  # ============================================================================
  # Model Registry Webhook Endpoints
  # ============================================================================

  @doc """
  Handle incoming MLflow model registry webhook events.

  MLflow sends webhooks for model lifecycle events:
  - MODEL_VERSION_TRANSITION_REQUEST_CREATED: Model promotion requested
  - MODEL_VERSION_TRANSITIONED_STAGE: Model moved to new stage
  - REGISTERED_MODEL_CREATED: New model registered

  URL: POST /api/webhooks/registries/mlflow

  ## Example Payload

      {
        "event": "MODEL_VERSION_TRANSITION_REQUEST_CREATED",
        "model_name": "fraud-detection",
        "version": "3",
        "stage": "Production",
        "timestamp": 1642334400000
      }
  """
  def mlflow(conn, params) do
    with :ok <- WebhookSignature.verify(conn, :registries, "mlflow") do
      process_mlflow_webhook(conn, params)
    else
      {:error, reason} -> reject_unsigned_webhook(conn, reason)
    end
  end

  defp process_mlflow_webhook(conn, params) do
    Logger.info("[WebhookController] MLflow webhook received: #{inspect(params)}")

    case validate_mlflow_event(params) do
      {:ok, %{model_id: model_id, event: event}} ->
        Logger.info("[WebhookController] MLflow event #{event} for model #{model_id}")

        # Extract org_id from request if authenticated, otherwise use default
        org_id = get_org_id_from_conn(conn)

        case DownloadHook.handle_download(model_id, MLflow, %{organization_id: org_id}) do
          {:ok, provenance_id} ->
            Logger.info(
              "[WebhookController] MLflow scan triggered: provenance_id=#{provenance_id}"
            )

            json(conn, %{
              status: "accepted",
              provenance_id: provenance_id,
              model_id: model_id,
              event: event
            })

          {:error, reason} ->
            Logger.error("[WebhookController] MLflow scan failed: #{inspect(reason)}")
            # Return 200 to prevent webhook retries - log the error
            json(conn, %{
              status: "error",
              reason: "scan_failed",
              model_id: model_id
            })
        end

      {:error, :invalid_event_type} ->
        # Unknown event type - acknowledge but don't process
        Logger.debug("[WebhookController] MLflow webhook ignored: unknown event type")
        json(conn, %{status: "ignored", reason: "unknown_event_type"})

      {:error, :missing_fields} ->
        Logger.warning("[WebhookController] MLflow webhook missing required fields")

        conn
        |> put_status(400)
        |> json(%{error: "missing_required_fields", required: ["event", "model_name", "version"]})
    end
  end

  @doc """
  Handle incoming HuggingFace Hub webhook events.

  HuggingFace sends webhooks for repository events:
  - model.update: Model files updated
  - model.create: New model created

  URL: POST /api/webhooks/registries/huggingface

  ## Example Payload

      {
        "event": "model.update",
        "repo": {
          "type": "model",
          "name": "org/model-name"
        },
        "timestamp": "2024-01-15T10:30:00Z"
      }
  """
  def huggingface(conn, params) do
    with :ok <- WebhookSignature.verify(conn, :registries, "huggingface") do
      process_huggingface_webhook(conn, params)
    else
      {:error, reason} -> reject_unsigned_webhook(conn, reason)
    end
  end

  defp process_huggingface_webhook(conn, params) do
    Logger.info("[WebhookController] HuggingFace webhook received: #{inspect(params)}")

    case validate_huggingface_event(params) do
      {:ok, %{model_id: model_id, event: event}} ->
        Logger.info("[WebhookController] HuggingFace event #{event} for model #{model_id}")

        org_id = get_org_id_from_conn(conn)

        case DownloadHook.handle_download(model_id, HuggingFace, %{organization_id: org_id}) do
          {:ok, provenance_id} ->
            Logger.info(
              "[WebhookController] HuggingFace scan triggered: provenance_id=#{provenance_id}"
            )

            json(conn, %{
              status: "accepted",
              provenance_id: provenance_id,
              model_id: model_id,
              event: event
            })

          {:error, reason} ->
            Logger.error("[WebhookController] HuggingFace scan failed: #{inspect(reason)}")
            json(conn, %{status: "error", reason: "scan_failed", model_id: model_id})
        end

      {:error, :invalid_event_type} ->
        Logger.debug("[WebhookController] HuggingFace webhook ignored: unknown event type")
        json(conn, %{status: "ignored", reason: "unknown_event_type"})

      {:error, :missing_fields} ->
        Logger.warning("[WebhookController] HuggingFace webhook missing required fields")

        conn
        |> put_status(400)
        |> json(%{error: "missing_required_fields", required: ["event", "repo"]})
    end
  end

  @doc """
  Handle incoming Weights & Biases webhook events.

  W&B sends webhooks for artifact lifecycle events:
  - artifact_created: New artifact version logged

  URL: POST /api/webhooks/registries/wandb

  ## Example Payload

      {
        "event_type": "artifact_created",
        "artifact_version": {
          "id": "QXJ0aWZhY3Q6MTIzNDU2",
          "entity": "my-org",
          "project": "fraud-detection",
          "artifact_sequence_name": "model-v1",
          "version": "v2",
          "created_at": "2024-01-15T10:30:00Z"
        }
      }
  """
  def wandb(conn, params) do
    with :ok <- WebhookSignature.verify(conn, :registries, "wandb") do
      process_wandb_webhook(conn, params)
    else
      {:error, reason} -> reject_unsigned_webhook(conn, reason)
    end
  end

  defp process_wandb_webhook(conn, params) do
    Logger.info("[WebhookController] W&B webhook received: #{inspect(params)}")

    case validate_wandb_event(params) do
      {:ok, %{model_id: model_id, event: event}} ->
        Logger.info("[WebhookController] W&B event #{event} for artifact #{model_id}")

        org_id = get_org_id_from_conn(conn)

        case DownloadHook.handle_download(model_id, WandB, %{organization_id: org_id}) do
          {:ok, provenance_id} ->
            Logger.info("[WebhookController] W&B scan triggered: provenance_id=#{provenance_id}")

            json(conn, %{
              status: "accepted",
              provenance_id: provenance_id,
              model_id: model_id,
              event: event
            })

          {:error, reason} ->
            Logger.error("[WebhookController] W&B scan failed: #{inspect(reason)}")
            json(conn, %{status: "error", reason: "scan_failed", model_id: model_id})
        end

      {:error, :invalid_event_type} ->
        Logger.debug("[WebhookController] W&B webhook ignored: unknown event type")
        json(conn, %{status: "ignored", reason: "unknown_event_type"})

      {:error, :missing_fields} ->
        Logger.warning("[WebhookController] W&B webhook missing required fields")

        conn
        |> put_status(400)
        |> json(%{error: "missing_required_fields", required: ["event_type", "artifact_version"]})
    end
  end

  # MLflow event validation
  defp validate_mlflow_event(params) do
    event = params["event"]
    model_name = params["model_name"]
    version = params["version"]

    cond do
      is_nil(event) or is_nil(model_name) or is_nil(version) ->
        {:error, :missing_fields}

      event in [
        "MODEL_VERSION_TRANSITION_REQUEST_CREATED",
        "MODEL_VERSION_TRANSITIONED_STAGE",
        "REGISTERED_MODEL_CREATED",
        "MODEL_VERSION_CREATED"
      ] ->
        model_id = "#{model_name}:#{version}"
        {:ok, %{model_id: model_id, event: event}}

      true ->
        {:error, :invalid_event_type}
    end
  end

  # HuggingFace event validation
  defp validate_huggingface_event(params) do
    event = params["event"]
    repo = params["repo"]

    cond do
      is_nil(event) or is_nil(repo) ->
        {:error, :missing_fields}

      event in ["model.update", "model.create", "repo.content.changed"] and
          repo["type"] == "model" ->
        model_id = repo["name"]
        {:ok, %{model_id: model_id, event: event}}

      true ->
        {:error, :invalid_event_type}
    end
  end

  # W&B event validation
  defp validate_wandb_event(params) do
    event_type = params["event_type"]
    artifact_version = params["artifact_version"]

    cond do
      is_nil(event_type) or is_nil(artifact_version) ->
        {:error, :missing_fields}

      event_type in ["artifact_created", "artifact_updated", "artifact_aliased"] ->
        entity = artifact_version["entity"]
        project = artifact_version["project"]
        artifact_name = artifact_version["artifact_sequence_name"]
        version = artifact_version["version"]

        if entity && project && artifact_name && version do
          model_id = "#{entity}/#{project}/#{artifact_name}:#{version}"
          {:ok, %{model_id: model_id, event: event_type}}
        else
          {:error, :missing_fields}
        end

      true ->
        {:error, :invalid_event_type}
    end
  end

  # Extract organization ID from connection (if authenticated)
  defp get_org_id_from_conn(conn) do
    # Try to get org_id from various sources
    conn.assigns[:current_organization_id] ||
      conn.assigns[:organization_id] ||
      get_in(conn.assigns, [:current_user, :organization_id]) ||
      nil
  end

  # ============================================================================
  # Bidirectional Sync Webhook Endpoints
  # ============================================================================

  @doc """
  Receive and process an incoming webhook from an external integration.

  URL: POST /api/webhooks/:integration_type/:integration_id

  Examples:
  - POST /api/webhooks/jira/550e8400-e29b-41d4-a716-446655440000
  - POST /api/webhooks/splunk/550e8400-e29b-41d4-a716-446655440000
  """
  def receive_webhook(
        conn,
        %{"integration_type" => integration_type, "integration_id" => integration_id} = _params
      ) do
    # Read raw body for signature verification
    {:ok, raw_body, conn} = Plug.Conn.read_body(conn)

    # Parse JSON payload
    payload =
      case Jason.decode(raw_body) do
        {:ok, decoded} ->
          decoded

        {:error, _} ->
          # If JSON decode fails, try to use the already-parsed body params
          conn.body_params || %{}
      end

    # Extract headers
    headers = extract_headers(conn)

    # Get remote IP for rate limiting
    remote_ip = get_remote_ip(conn)

    # Process webhook
    opts = [
      headers: headers,
      raw_body: raw_body,
      remote_ip: remote_ip
    ]

    # Convert integration_type to atom
    integration_type_atom =
      try do
        String.to_existing_atom(integration_type)
      rescue
        ArgumentError -> :generic
      end

    case TamanduaServer.Integrations.WebhookReceiver.process_webhook(
           integration_type_atom,
           integration_id,
           payload,
           opts
         ) do
      {:ok, result} ->
        Logger.info(
          "[WebhookController] Successfully processed #{integration_type} webhook for integration #{integration_id}"
        )

        conn
        |> put_status(:ok)
        |> json(%{
          status: "success",
          message: "Webhook processed successfully",
          action: result[:action] || :processed
        })

      {:error, :duplicate_webhook} ->
        Logger.debug(
          "[WebhookController] Duplicate webhook rejected for integration #{integration_id}"
        )

        conn
        |> put_status(:ok)
        |> json(%{
          status: "success",
          message: "Webhook already processed (duplicate)"
        })

      {:error, :rate_limited} ->
        Logger.warning(
          "[WebhookController] Rate limit exceeded for integration #{integration_id}"
        )

        conn
        |> put_status(:too_many_requests)
        |> json(%{
          status: "error",
          message: "Rate limit exceeded",
          error: "rate_limited"
        })

      {:error, :invalid_signature} ->
        Logger.warning("[WebhookController] Invalid signature for integration #{integration_id}")

        conn
        |> put_status(:unauthorized)
        |> json(%{
          status: "error",
          message: "Invalid webhook signature",
          error: "invalid_signature"
        })

      {:error, :not_found} ->
        Logger.warning("[WebhookController] Integration not found: #{integration_id}")

        conn
        |> put_status(:not_found)
        |> json(%{
          status: "error",
          message: "Integration not found",
          error: "not_found"
        })

      {:error, reason} ->
        Logger.error("[WebhookController] Failed to process webhook: #{inspect(reason)}")

        conn
        |> put_status(:unprocessable_entity)
        |> json(%{
          status: "error",
          message: "Failed to process webhook",
          error: inspect(reason)
        })
    end
  end

  @doc """
  Get webhook delivery history for an integration.

  URL: GET /api/webhooks/:integration_id/history
  """
  def webhook_history(conn, %{"integration_id" => integration_id} = params) do
    opts = [
      limit: bounded_limit(params["limit"], 50, 500),
      offset: bounded_offset(params["offset"]),
      status: params["status"]
    ]

    case TamanduaServer.Integrations.WebhookReceiver.get_webhook_history(integration_id, opts) do
      {:ok, deliveries, total} ->
        conn
        |> put_status(:ok)
        |> json(%{
          status: "success",
          data: deliveries,
          meta: %{
            total: total,
            limit: opts[:limit],
            offset: opts[:offset]
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{
          status: "error",
          message: "Failed to retrieve webhook history",
          error: inspect(reason)
        })
    end
  end

  @doc """
  Verify webhook endpoint (for some integrations that ping before use).

  URL: GET /api/webhooks/:integration_type/:integration_id
  """
  def verify_webhook(conn, %{
        "integration_type" => integration_type,
        "integration_id" => integration_id
      }) do
    Logger.info(
      "[WebhookController] Webhook verification request for #{integration_type}/#{integration_id}"
    )

    # Some services (like Slack) send a challenge parameter for verification
    challenge = conn.params["challenge"]

    if challenge do
      conn
      |> put_status(:ok)
      |> json(%{challenge: challenge})
    else
      conn
      |> put_status(:ok)
      |> json(%{
        status: "success",
        message: "Webhook endpoint verified",
        integration_type: integration_type,
        integration_id: integration_id
      })
    end
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp create_global_ioc(attrs) do
    case TamanduaServer.Detection.IOCs.add_global(attrs) do
      {:ok, _ioc} = success ->
        TamanduaServer.Detection.IOCReload.schedule()
        success

      error ->
        error
    end
  end

  defp bounded_limit(value, default, max_limit),
    do: value |> parse_int(default) |> max(1) |> min(max_limit)

  defp bounded_offset(value), do: value |> parse_int(0) |> max(0)

  defp parse_int(nil, default), do: default
  defp parse_int(value, _default) when is_integer(value), do: value

  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(_, default), do: default

  defp extract_headers(conn) do
    conn.req_headers
    |> Enum.into(%{})
  end

  defp get_remote_ip(conn) do
    # Check X-Forwarded-For header first (if behind proxy)
    case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
      [forwarded | _] ->
        forwarded
        |> String.split(",")
        |> List.first()
        |> String.trim()

      [] ->
        # Fall back to remote_ip from conn
        case conn.remote_ip do
          {a, b, c, d} -> "#{a}.#{b}.#{c}.#{d}"
          ip -> to_string(ip)
        end
    end
  end
end
