defmodule TamanduaServer.Telemetry.Ingestor do
  @moduledoc """
  Broadway pipeline for ingesting and processing telemetry data from agents.

  Handles:
  - High-volume event ingestion
  - Batch processing
  - Database persistence
  - Detection engine integration
  """

  use Broadway
  require Logger

  alias Broadway.Message
  alias TamanduaServer.Detection.Engine
  alias TamanduaServer.Telemetry.ClickHouse
  alias TamanduaServer.Telemetry.ClickHouseWriter
  alias TamanduaServer.Telemetry.CorrelationEvidence
  alias TamanduaServer.Telemetry.EventContract
  alias TamanduaServer.Telemetry.IngestorProducer
  alias TamanduaServer.Agents.OrgLookup
  alias TamanduaServer.Telemetry.Enrichment
  alias TamanduaServer.AISecurity.{AIGateway, AIInventory, AttackSurface, EndpointUsage}

  alias TamanduaServer.NDR.{
    EncryptedTraffic,
    EventNormalizer,
    FlowAnalyzer,
    LateralDetector,
    ProtocolAnalyzer
  }

  alias TamanduaServer.Telemetry.PackageInstallCorrelator
  alias TamanduaServer.Detection.TyposquattingAnalyzer
  alias TamanduaServer.Detection.EtwTamperingHandler
  alias TamanduaServer.Alerts.SupplyChainEnricher
  alias TamanduaServer.Alerts

  @batch_size 100
  @batch_timeout 1_000
  @ai_usage_domain_indicators [
    "api.openai.com",
    "chat.openai.com",
    "chatgpt.com",
    "platform.openai.com",
    "api.anthropic.com",
    "claude.ai",
    "generativelanguage.googleapis.com",
    "ai.google.dev",
    "gemini.google.com",
    "bard.google.com",
    "copilot.microsoft.com",
    "openai.azure.com",
    "api.cognitive.microsoft.com",
    "huggingface.co",
    "api-inference.huggingface.co",
    "api.cohere.ai",
    "cohere.com",
    "api.replicate.com",
    "replicate.com",
    "api.mistral.ai",
    "api.groq.com",
    "console.groq.com",
    "openrouter.ai",
    "api.openrouter.ai",
    "api.perplexity.ai",
    "perplexity.ai",
    "bedrock-runtime.",
    "localhost:11434",
    "127.0.0.1:11434",
    "ollama",
    "localai",
    "gpt4all",
    "llamacpp",
    "text-generation-webui"
  ]

  def start_link(opts) do
    Broadway.start_link(__MODULE__,
      name: __MODULE__,
      producer: [
        module: {IngestorProducer, []},
        transformer: {__MODULE__, :transform, []},
        concurrency: 1
      ],
      processors: [
        default: [
          concurrency: System.schedulers_online() * 2,
          max_demand: 10
        ]
      ],
      batchers: [
        default: [
          batch_size: @batch_size,
          batch_timeout: @batch_timeout,
          concurrency: 4
        ],
        ml: [
          batch_size: 10,
          batch_timeout: 5_000,
          concurrency: 2
        ]
      ],
      context: opts
    )
  end

  @doc """
  Push a batch of telemetry events for processing.
  """
  @spec push_batch(map()) :: :ok
  def push_batch(telemetry_batch) do
    events = telemetry_batch[:events] || []
    agent_id = telemetry_batch[:agent_id]

    messages =
      Enum.map(events, fn event ->
        Map.put(event, :agent_id, agent_id)
      end)

    IngestorProducer.push_messages(messages)
    Logger.debug("Pushed batch of #{length(messages)} events")
    :ok
  end

  @doc """
  Push a single event for processing.
  """
  @spec push_event(map()) :: :ok
  def push_event(event) do
    IngestorProducer.push_messages([event])
    Logger.debug("Pushed event #{event[:event_id]}")
    :ok
  end

  @doc """
  Push a binary sample for ML analysis.
  """
  @spec push_binary_sample(map()) :: :ok
  def push_binary_sample(sample) do
    IngestorProducer.push_messages([{:binary_sample, sample}])
    :ok
  end

  # Broadway callbacks

  @impl true
  def handle_message(_processor, %Message{data: {:binary_sample, _sample}} = message, _context) do
    # Route to ML batcher
    message
    |> Message.put_batcher(:ml)
  end

  @impl true
  def handle_message(_processor, %Message{data: event} = message, _context) do
    # Intercept system_health events and route them to the health metrics store
    # instead of persisting every health snapshot to the database.
    event_type = event["event_type"] || event[:event_type]

    cond do
      offline_verdict_sync_event?(event_type, event) ->
        handle_offline_verdict_sync_event(event)

        message
        |> Message.update_data(fn _ -> Map.put(event, :_skip_persist, true) end)
        |> Message.put_batcher(:default)

      event_type in ["system_health", :system_health] ->
        handle_health_event(event)

        # Acknowledge without persisting to events table
        message
        |> Message.update_data(fn _ -> Map.put(event, :_skip_persist, true) end)
        |> Message.put_batcher(:default)

      event_type in ["network_discovery", :network_discovery] ->
        # Route network discovery events to the DeviceInventory GenServer
        # instead of persisting raw events to the events table.
        handle_network_discovery_event(event)

        message
        |> Message.update_data(fn _ -> Map.put(event, :_skip_persist, true) end)
        |> Message.put_batcher(:default)

      event_type in ["package_install", :package_install] ->
        # Route package install events to supply chain detection
        handle_package_install_event(event)

        message
        |> Message.update_data(fn _ ->
          Map.put(event, :processed_at, System.system_time(:millisecond))
        end)
        |> Message.put_batcher(:default)

      event_type in [
        "inference_request",
        :inference_request,
        "inference_response",
        :inference_response
      ] ->
        # Route inference events directly to the detection engine for InferenceTracker
        # These events are high-priority for real-time prompt injection detection
        try do
          Engine.analyze_event_async(event)
        rescue
          _ -> :ok
        catch
          _, _ -> :ok
        end

        message
        |> Message.update_data(fn _ ->
          Map.put(event, :processed_at, System.system_time(:millisecond))
        end)
        |> Message.put_batcher(:default)

      EtwTamperingHandler.etw_tampering_event?(event_type) ->
        # Route ETW tampering events to specialized handler for high-priority alerting
        # These are critical defense evasion events (MITRE T1562.006)
        handle_etw_tampering_event(event)

        # Also send to detection engine for additional analysis
        try do
          Engine.analyze_event_async(event)
        rescue
          _ -> :ok
        catch
          _, _ -> :ok
        end

        message
        |> Message.update_data(fn _ ->
          Map.put(event, :processed_at, System.system_time(:millisecond))
        end)
        |> Message.put_batcher(:default)

      true ->
        # Quick enrichment (resilient — never crash the pipeline)
        enriched_event =
          try do
            enrich_event(event)
          rescue
            e ->
              Logger.error("Event enrichment failed: #{Exception.message(e)}")
              event
          catch
            :exit, reason ->
              Logger.warning("Event enrichment unavailable: #{inspect(reason)}")
              event

            kind, reason ->
              Logger.warning("Event enrichment failed: #{inspect({kind, reason})}")
              event
          end
          |> ensure_event_identity()
          |> add_server_side_process_detections()

        # Run through detection engine asynchronously.
        #
        # Engine.analyze_event_async/1 uses GenServer.cast to route the event to
        # one of 16 sharded workers.  Alerts are created inside the worker.
        # This prevents Broadway processors from blocking on a synchronous
        # GenServer.call (15 s timeout) which caused channel crashes when agents
        # reconnect and flush thousands of persisted events at once.
        if Process.whereis(Engine) do
          try do
            Engine.analyze_event_async(enriched_event)
          rescue
            _ -> :ok
          catch
            _, _ -> :ok
          end
        end

        maybe_feed_ndr_direct(enriched_event)
        maybe_feed_ai_security_direct(enriched_event)

        # Feed to package install correlator for session tracking
        try do
          PackageInstallCorrelator.process_event(enriched_event)
        rescue
          _ -> :ok
        catch
          _, _ -> :ok
        end

        final_event =
          enriched_event
          |> Map.put(:processed_at, System.system_time(:millisecond))
          |> normalize_event_for_timeline()

        safely_create_agent_detection_alert(final_event)

        message
        |> Message.update_data(fn _ -> final_event end)
        |> Message.put_batcher(:default)
    end
  end

  defp handle_health_event(event) do
    agent_id = event["agent_id"] || event[:agent_id]
    payload = event["payload"] || event[:payload] || %{}

    if agent_id do
      TamanduaServer.Agents.Registry.update_health(agent_id, payload)

      driver_status = Map.get(payload, "driver_status") || Map.get(payload, :driver_status)

      if driver_status && agent_id == "9390f816-2a0f-47c3-aa4b-2b244fa2d737" do
        Logger.info(
          "[DriverLab] health agent=#{agent_id} driver_status=#{inspect(driver_status)}"
        )
      end

      # Broadcast health update to the dashboard so the frontend can update
      # CPU/memory gauges in real time without page refresh.
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agents:#{agent_id}",
        {:health_update, agent_id, payload}
      )

      Logger.debug("Health metrics updated for agent #{agent_id}")
    end
  end

  defp offline_verdict_sync_event?(event_type, event) do
    payload = event["payload"] || event[:payload] || %{}
    payload_type = payload["type"] || payload[:type]

    event_type in ["system_health", :system_health] and payload_type == "offline_verdict_sync"
  end

  defp handle_offline_verdict_sync_event(event) do
    payload = event["payload"] || event[:payload] || %{}
    verdicts = payload["verdicts"] || payload[:verdicts] || []

    verdicts
    |> Enum.take(500)
    |> Enum.each(fn verdict ->
      verdict
      |> offline_verdict_to_detection_event(event)
      |> safely_create_agent_detection_alert()
    end)
  rescue
    e ->
      Logger.warning("[Ingestor] Offline verdict sync handling failed: #{Exception.message(e)}")
      :ok
  end

  defp offline_verdict_to_detection_event(verdict, parent_event) when is_map(verdict) do
    agent_id = parent_event["agent_id"] || parent_event[:agent_id]
    org_id = parent_event["organization_id"] || parent_event[:organization_id] || OrgLookup.get_org_id(agent_id)
    file_path = verdict["file_path"] || verdict[:file_path]
    file_hash = verdict["file_hash"] || verdict[:file_hash]
    combined_verdict = verdict["combined_verdict"] || verdict[:combined_verdict] || "unknown"
    ml_score = verdict["ml_score"] || verdict[:ml_score]
    ml_verdict = verdict["ml_verdict"] || verdict[:ml_verdict]
    yara_matches = verdict["yara_matches"] || verdict[:yara_matches] || []

    detections =
      []
      |> maybe_add_offline_ml_detection(verdict, ml_score, ml_verdict, file_path)
      |> add_offline_yara_detections(yara_matches, file_path)

    %{
      "event_id" => parent_event["event_id"] || parent_event[:event_id],
      "event_type" => "ml_detection",
      "agent_id" => agent_id,
      "organization_id" => org_id,
      "timestamp" => verdict["timestamp"] || verdict[:timestamp] || parent_event["timestamp"] || parent_event[:timestamp],
      "severity" => offline_verdict_severity(combined_verdict, ml_score),
      "payload" => %{
        "path" => file_path,
        "file_hash" => file_hash,
        "file_size" => verdict["file_size"] || verdict[:file_size],
        "combined_verdict" => combined_verdict,
        "ml_score" => ml_score,
        "ml_verdict" => ml_verdict,
        "model_version" => verdict["model_version"] || verdict[:model_version],
        "rules_version" => verdict["rules_version"] || verdict[:rules_version],
        "source" => "agent_offline_sync"
      },
      "metadata" => %{
        "source" => "agent_offline_ml",
        "offline_sync" => "true"
      },
      "detections" => detections
    }
  end

  defp offline_verdict_to_detection_event(_verdict, parent_event), do: parent_event

  defp maybe_add_offline_ml_detection(detections, _verdict, nil, _ml_verdict, _file_path), do: detections

  defp maybe_add_offline_ml_detection(detections, verdict, ml_score, ml_verdict, file_path) do
    combined_verdict = verdict["combined_verdict"] || verdict[:combined_verdict] || "unknown"

    if combined_verdict in ["malicious", :malicious, "suspicious", :suspicious] do
      [
        %{
          "detection_type" => "ml",
          "rule_name" => "OFFLINE_ML_#{ml_verdict || combined_verdict}",
          "confidence" => ml_score,
          "description" => "Offline ML classified #{file_path || "file"} as #{ml_verdict || combined_verdict}",
          "mitre_tactics" => ["Execution"],
          "mitre_techniques" => []
        }
        | detections
      ]
    else
      detections
    end
  end

  defp add_offline_yara_detections(detections, yara_matches, file_path) when is_list(yara_matches) do
    yara_detections =
      Enum.map(yara_matches, fn rule ->
        %{
          "detection_type" => "yara",
          "rule_name" => "OFFLINE_YARA_#{rule}",
          "confidence" => 0.85,
          "description" => "Offline YARA rule matched #{rule} on #{file_path || "file"}",
          "mitre_tactics" => ["Execution"],
          "mitre_techniques" => []
        }
      end)

    detections ++ yara_detections
  end

  defp add_offline_yara_detections(detections, _yara_matches, _file_path), do: detections

  defp offline_verdict_severity(verdict, score) do
    cond do
      verdict in ["malicious", :malicious] and is_number(score) and score >= 0.9 -> "critical"
      verdict in ["malicious", :malicious] -> "high"
      verdict in ["suspicious", :suspicious] -> "medium"
      true -> "info"
    end
  end

  defp handle_network_discovery_event(event) do
    agent_id = event["agent_id"] || event[:agent_id]
    payload = event["payload"] || event[:payload] || %{}

    if agent_id do
      # Route to DeviceInventory for device merging and classification
      TamanduaServer.NetworkDiscovery.DeviceInventory.ingest_discovery(agent_id, payload)

      # Also report agent's subnets for scan coordination
      subnet = Map.get(payload, "subnet") || Map.get(payload, :subnet)

      if subnet do
        TamanduaServer.NetworkDiscovery.ScanPolicy.register_agent(agent_id, [subnet])
      end

      Logger.debug("Network discovery event processed for agent #{agent_id}")
    end
  end

  defp maybe_feed_ai_security_direct(event) when is_map(event) do
    maybe_ingest_ai_inventory(event)
    maybe_ingest_ai_gateway_usage(event)
    maybe_analyze_ai_usage(event)
  rescue
    e ->
      Logger.debug("[Ingestor] AI security routing skipped: #{Exception.message(e)}")
  catch
    _, _ -> :ok
  end

  defp maybe_feed_ai_security_direct(_), do: :ok

  defp maybe_ingest_ai_inventory(event) do
    payload = event["payload"] || event[:payload] || %{}
    event_type = event["event_type"] || event[:event_type]
    ai_discovery = payload["ai_discovery"] || payload[:ai_discovery]

    if ai_discovery_payload?(ai_discovery) or event_type in ["ai_discovery", :ai_discovery] do
      agent_id = event["agent_id"] || event[:agent_id]

      if agent_id && Process.whereis(AIInventory) do
        AIInventory.ingest_discovery(agent_id, event)
      end
    end
  end

  defp maybe_ingest_ai_gateway_usage(event) do
    if Process.whereis(AIGateway) do
      EndpointUsage.ingest_telemetry_event(event)
    else
      :ignore
    end
  end

  defp maybe_analyze_ai_usage(event) do
    event_type = event["event_type"] || event[:event_type]

    if event_type in [
         "dns_query",
         :dns_query,
         "network_connect",
         :network_connect,
         "network_close",
         :network_close
       ] do
      payload = event["payload"] || event[:payload] || %{}
      metadata = event["metadata"] || event[:metadata] || %{}
      domain = ai_usage_domain(event, payload)

      if (truthy?(metadata["ai_usage"] || metadata[:ai_usage]) or
            (domain && ai_usage_domain?(domain))) and Process.whereis(AttackSurface) do
        AttackSurface.analyze_network_event(%{
          agent_id: event["agent_id"] || event[:agent_id],
          remote_domain: domain,
          remote_ip: payload["remote_ip"] || payload[:remote_ip],
          bytes_sent:
            payload["bytes_sent"] || payload[:bytes_sent] || payload["bytes_out"] ||
              payload[:bytes_out] || 0,
          bytes_received:
            payload["bytes_received"] || payload[:bytes_received] || payload["bytes_in"] ||
              payload[:bytes_in] || 0,
          process_name: payload["process_name"] || payload[:process_name],
          process_path: payload["process_path"] || payload[:process_path],
          source_event_type: event_type,
          telemetry_source: "endpoint_dns_network"
        })
      end
    end
  end

  defp ai_usage_domain(event, payload) do
    event["remote_domain"] || event[:remote_domain] ||
      payload["remote_domain"] || payload[:remote_domain] ||
      payload["domain"] || payload[:domain] ||
      payload["query"] || payload[:query] ||
      payload["host"] || payload[:host] ||
      payload["sni"] || payload[:sni] ||
      payload["tls_sni"] || payload[:tls_sni] ||
      first_domain_candidate(payload["domain_candidates"] || payload[:domain_candidates])
  end

  defp first_domain_candidate([first | _]) when is_binary(first), do: first
  defp first_domain_candidate(_), do: nil

  defp ai_usage_domain?(domain) when is_binary(domain) do
    domain_lower = String.downcase(domain)
    Enum.any?(@ai_usage_domain_indicators, &String.contains?(domain_lower, &1))
  end

  defp ai_usage_domain?(_), do: false

  defp ai_discovery_payload?(value) when is_map(value), do: map_size(value) > 0
  defp ai_discovery_payload?(value) when is_list(value), do: value != []
  defp ai_discovery_payload?(value), do: truthy?(value)

  defp truthy?(value), do: value in [true, "true", 1, "1"]

  defp handle_package_install_event(event) do
    agent_id = event["agent_id"] || event[:agent_id]
    payload = event["payload"] || event[:payload] || %{}
    ecosystem = payload["ecosystem"] || payload[:ecosystem]
    package_name = payload["package_name"] || payload[:package_name]

    if agent_id && ecosystem && package_name do
      # Check for typosquatting
      case TyposquattingAnalyzer.check_typosquatting(to_string(ecosystem), package_name) do
        {:typosquatting, info} ->
          # Create typosquatting alert
          alert =
            SupplyChainEnricher.create_supply_chain_alert(agent_id, %{
              ecosystem: String.to_existing_atom(ecosystem),
              package_name: package_name,
              version: payload["version"] || payload[:version] || "unknown",
              risk_type: :typosquatting,
              extra: %{
                "similar_to" => info.similar_to,
                "detection_method" => info.detection_method
              }
            })

          case Alerts.create_alert(Map.from_struct(alert)) do
            {:ok, created_alert} ->
              enriched = SupplyChainEnricher.enrich(created_alert)
              SupplyChainEnricher.broadcast_alert(enriched)

              Logger.info(
                "[Ingestor] Typosquatting alert created for #{ecosystem}:#{package_name}"
              )

            {:error, reason} ->
              Logger.error("[Ingestor] Failed to create typosquatting alert: #{inspect(reason)}")
          end

        :ok ->
          :ok
      end

      Logger.debug("[Ingestor] Processed package install: #{ecosystem}:#{package_name}")
    end
  rescue
    e ->
      Logger.warning("[Ingestor] Package install processing failed: #{Exception.message(e)}")
  end

  defp handle_etw_tampering_event(event) do
    agent_id = event["agent_id"] || event[:agent_id]

    if agent_id do
      case EtwTamperingHandler.process_event(event) do
        {:ok, alert} ->
          Logger.info(
            "[Ingestor] ETW tampering alert created for agent #{agent_id}: #{alert.title}"
          )

        {:error, reason} ->
          Logger.error("[Ingestor] Failed to create ETW tampering alert: #{inspect(reason)}")
      end
    end
  rescue
    e ->
      Logger.warning("[Ingestor] ETW tampering processing failed: #{Exception.message(e)}")
  end

  @impl true
  def handle_batch(:default, messages, _batch_info, _context) do
    events =
      messages
      |> Enum.map(fn %Message{data: event} -> event end)
      |> Enum.filter(&is_map/1)
      |> Enum.reject(fn event -> event[:_skip_persist] == true end)

    if Enum.empty?(events) do
      messages
    else
      # Always broadcast for real-time feeds, regardless of DB persistence
      broadcast_events(Enum.map(events, &add_organization_id/1))

      # Dual-write: send ALL events to ClickHouse for high-volume storage.
      # This is fire-and-forget — ClickHouse buffers internally and flushes
      # asynchronously, so it never blocks the Broadway pipeline.
      persist_to_clickhouse(events)

      case persist_events(events) do
        {:ok, count} ->
          Logger.debug("Persisted #{count} events to database")
          maybe_log_lab_persist_summary(events, count)
          messages

        {:error, reason} ->
          Logger.error("Failed to persist events: #{inspect(reason)}")
          Enum.map(messages, fn msg -> Message.failed(msg, reason) end)
      end
    end
  end

  @impl true
  def handle_batch(:ml, messages, _batch_info, _context) do
    samples =
      messages
      |> Enum.flat_map(fn
        %Message{data: {:binary_sample, sample}} -> [sample]
        _ -> []
      end)

    if length(samples) > 0 do
      # Send to ML service for analysis
      case Engine.analyze_binary(samples) do
        {:ok, _results} ->
          Logger.info("ML analysis completed for #{length(samples)} samples")

        {:error, reason} ->
          Logger.error("ML analysis failed: #{inspect(reason)}")
      end
    end

    messages
  end

  @impl true
  def handle_failed(messages, _context) do
    Logger.error("Broadway: #{length(messages)} events failed processing")

    Enum.each(messages, fn
      %Message{data: event, status: {:failed, reason}} when is_map(event) ->
        event_type = event[:event_type] || event["event_type"] || "unknown"
        agent_id = event[:agent_id] || event["agent_id"] || "unknown"
        Logger.error("Failed event [#{event_type}] from agent #{agent_id}: #{inspect(reason)}")

      %Message{status: {:failed, reason}} ->
        Logger.error("Failed message: #{inspect(reason)}")

      _ ->
        :ok
    end)

    messages
  end

  # Transformer callback
  def transform(event, _opts) do
    %Message{
      data: event,
      acknowledger: {Broadway.NoopAcknowledger, nil, nil}
    }
  end

  # Private functions

  defp enrich_event(event) do
    event
    |> add_timestamp()
    |> normalize_ndr_event()
    |> normalize_process_payload_aliases()
    |> add_organization_id()
    |> add_os_type()
    |> enrich_with_fast_lookups()
    |> sanitize_null_bytes()
  end

  defp normalize_process_payload_aliases(event) when is_map(event) do
    event_type = event_value(event, :event_type) |> to_string()

    if event_type in ["process_create", "process_terminate", "process_exec"] do
      payload =
        event
        |> event_value(:payload)
        |> ensure_ingestor_map()
        |> normalize_process_alias("process_name", [:name, :image, :exe])
        |> normalize_process_alias("command_line", [:cmdline, :commandline])
        |> normalize_process_alias("executable_path", [:path, :image_path])
        |> normalize_process_alias("username", [:user, :user_name])
        |> normalize_process_alias("parent_process_name", [:parent_name])
        |> normalize_process_alias("parent_executable_path", [:parent_path])

      put_event_value(event, :payload, payload)
    else
      event
    end
  end

  defp normalize_process_payload_aliases(event), do: event

  defp normalize_process_alias(payload, canonical_key, aliases) when is_map(payload) do
    aliases
    |> Enum.find_value(&map_value(payload, &1))
    |> then(&put_when_blank(payload, canonical_key, &1))
  end

  defp normalize_ndr_event(event) do
    EventNormalizer.normalize_event(event)
  rescue
    _ -> event
  catch
    _, _ -> event
  end

  # Fast synchronous enrichment that doesn't block the pipeline.
  # Expensive enrichment is done asynchronously via AsyncWorker.
  defp enrich_with_fast_lookups(event) do
    cond do
      lightweight_profile?() and lab_threat_intel_enrichment?() ->
        enrich_with_local_threat_intel(event)

      lightweight_profile?() or is_nil(Process.whereis(Enrichment.Cache)) ->
        event

      true ->
        event
        |> Enrichment.ThreatIntel.enrich_event()
        |> Enrichment.Geo.enrich_event()
        |> Enrichment.Asset.enrich_event()
    end
  end

  defp enrich_with_local_threat_intel(event) do
    Enrichment.ThreatIntel.enrich_event(event)
  rescue
    e ->
      Logger.debug("[Ingestor] Local threat-intel enrichment skipped: #{Exception.message(e)}")
      event
  catch
    :exit, reason ->
      Logger.debug("[Ingestor] Local threat-intel enrichment unavailable: #{inspect(reason)}")
      event

    kind, reason ->
      Logger.debug("[Ingestor] Local threat-intel enrichment failed: #{inspect({kind, reason})}")
      event
  end

  # PostgreSQL jsonb does not support \u0000 (NULL bytes).  Windows APIs
  # sometimes include null terminators in process names and command lines.
  # Recursively strip them from all string values before DB insertion.
  #
  # Optimized version: only processes string values, skips numbers/booleans/nil
  # for better performance on high-volume telemetry.
  defp sanitize_null_bytes(data) when is_map(data) do
    Map.new(data, fn
      {k, v} when is_binary(k) ->
        # Only sanitize the key if it contains a null byte (rare)
        sanitized_key = if String.contains?(k, <<0>>), do: String.replace(k, <<0>>, ""), else: k
        {sanitized_key, sanitize_null_bytes(v)}

      {k, v} ->
        {k, sanitize_null_bytes(v)}
    end)
  end

  defp sanitize_null_bytes(data) when is_list(data) do
    Enum.map(data, &sanitize_null_bytes/1)
  end

  defp sanitize_null_bytes(data) when is_binary(data) do
    # Fast path: only replace if null byte is present
    if String.contains?(data, <<0>>) do
      String.replace(data, <<0>>, "")
    else
      data
    end
  end

  # Skip sanitization for non-string values (numbers, booleans, nil)
  defp sanitize_null_bytes(data), do: data

  defp add_timestamp(event) do
    if event[:timestamp] do
      event
    else
      Map.put(event, :timestamp, System.system_time(:millisecond))
    end
  end

  defp add_organization_id(event) do
    if event[:organization_id] || event["organization_id"] do
      event
    else
      agent_id = event[:agent_id] || event["agent_id"]

      case OrgLookup.get_org_id(agent_id) do
        nil -> event
        org_id -> Map.put(event, :organization_id, org_id)
      end
    end
  end

  # Stamp the event with the originating agent's os_type so Sigma logsource
  # filtering can discriminate Windows/Linux/macOS rules. Uses the cached
  # OrgLookup so we avoid a DB hit per event; leaves the event untouched when
  # the os_type is unknown (the filter stays permissive on nil).
  defp add_os_type(event) do
    if event[:os_type] || event["os_type"] do
      event
    else
      agent_id = event[:agent_id] || event["agent_id"]

      case OrgLookup.get_os_type(agent_id) do
        nil -> event
        os_type -> Map.put(event, :os_type, os_type)
      end
    end
  end

  defp maybe_create_agent_detection_alert(event) do
    detections = event["detections"] || event[:detections] || []

    cond do
      detections == [] ->
        :ok

      not agent_detection_alerts_enabled?() ->
        :ok

      true ->
        normalized_detections =
          detections
          |> Enum.map(&normalize_detection/1)
          |> Enum.filter(&alertable_agent_detection?(&1, event))
          |> Enum.sort_by(&agent_detection_priority/1, :desc)

        if normalized_detections == [] do
          :ok
        else
          first_detection = List.first(normalized_detections, %{})

          severity =
            normalize_alert_severity(
              event["severity"] || event[:severity] || first_detection[:severity] || "medium"
            )

          event_type = event["event_type"] || event[:event_type] || "unknown"

          attrs = %{
            severity: severity,
            status: "new",
            title: detection_alert_title(event_type, first_detection),
            description: detection_alert_description(event_type, first_detection),
            agent_id: event["agent_id"] || event[:agent_id],
            organization_id: event["organization_id"] || event[:organization_id],
            mitre_tactics: detection_values(normalized_detections, :mitre_tactics),
            mitre_techniques: detection_values(normalized_detections, :mitre_techniques),
            threat_score: detection_threat_score(severity, normalized_detections),
            event: event,
            detections: normalized_detections,
            detection_metadata: agent_detection_metadata(event, normalized_detections),
            rule_author_pubkey: detection_rule_author_pubkey(event, first_detection)
          }

          case Alerts.create_alert(attrs) do
            {:ok, alert} ->
              Logger.info(
                "[Ingestor] Alert created from agent detection event=#{event["event_id"] || event[:event_id]} alert=#{alert.id}"
              )

            {:error, reason} ->
              Logger.warning(
                "[Ingestor] Failed to create alert from agent detection: #{inspect(reason)}"
              )
          end
        end
    end
  rescue
    e ->
      Logger.warning("[Ingestor] Agent detection alert creation failed: #{Exception.message(e)}")
  end

  defp add_server_side_process_detections(event) when is_map(event) do
    event_type = event["event_type"] || event[:event_type]

    if process_event_type?(event_type) do
      payload = (event["payload"] || event[:payload] || %{}) |> ensure_ingestor_map()
      existing = normalize_event_detections(event["detections"] || event[:detections] || [])
      generated = process_behavior_detections(event, payload)
      merged = merge_detections(existing, generated)

      if merged == existing do
        event
      else
        event
        |> Map.put("detections", merged)
        |> Map.put(:detections, merged)
        |> put_event_value(:severity, strongest_detection_severity(merged, event["severity"] || event[:severity]))
      end
    else
      event
    end
  rescue
    e ->
      Logger.warning("[Ingestor] Server-side process detection failed: #{Exception.message(e)}")
      event
  end

  defp add_server_side_process_detections(event), do: event

  defp process_event_type?(event_type) do
    event_type
    |> to_string()
    |> String.downcase()
    |> case do
      value ->
        value in [
          "process_create",
          "process_start",
          "process_execution",
          "process_spawn",
          "live_response_command"
        ]
    end
  end

  defp process_behavior_detections(event, payload) do
    [
      powershell_encoded_command_detection(event, payload),
      regsvr32_proxy_execution_detection(event, payload),
      relocated_windows_binary_detection(event, payload)
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp powershell_encoded_command_detection(event, payload) do
    process = process_basename(payload)
    path = process_path(payload)
    cmdline = process_command_line(payload)
    decoded = process_decoded_command_line(payload)

    if process in ["powershell.exe", "pwsh.exe"] and command_line_has_encoded_flag?(cmdline) do
      detection(
        "powershell_encoded_command",
        "powershell_encoded_command",
        "PowerShell was launched with an EncodedCommand argument. This is a common execution and obfuscation pattern and should be reviewed with the decoded payload.",
        ["execution", "defense_evasion"],
        ["T1059.001", "T1027"],
        "medium",
        0.9,
        %{
          "process_name" => process,
          "process_path" => path,
          "command_line" => cmdline,
          "decoded_command_line" => decoded,
          "basis" => ["process_name", "encoded_command_flag", "command_line"]
        },
        event
      )
    end
  end

  defp regsvr32_proxy_execution_detection(event, payload) do
    process = process_basename(payload)
    path = process_path(payload)
    cmdline = process_command_line(payload)
    decoded = process_decoded_command_line(payload)
    command_evidence = join_command_evidence(cmdline, decoded)
    normalized_cmdline = normalize_ingestor_text(command_evidence)

    proxy_indicators =
      String.contains?(normalized_cmdline, "scrobj.dll") or
        String.contains?(normalized_cmdline, "/i:") or
        String.contains?(normalized_cmdline, "http://") or
        String.contains?(normalized_cmdline, "https://")

    if (process == "regsvr32.exe" or String.contains?(normalized_cmdline, "regsvr32.exe")) and
         proxy_indicators do
      detection(
        "regsvr32_proxy_execution",
        "signed_binary_proxy_execution",
        "Regsvr32 was launched with scriptlet/proxy execution indicators. This maps to signed binary proxy execution and requires command-line review.",
        ["defense_evasion"],
        ["T1218.010"],
        "medium",
        0.86,
        %{
          "process_name" => process,
          "process_path" => path,
          "command_line" => cmdline,
          "decoded_command_line" => decoded,
          "basis" => ["process_or_decoded_script", "scriptlet_or_proxy_argument"]
        },
        event
      )
    end
  end

  defp relocated_windows_binary_detection(event, payload) do
    process = process_basename(payload)
    path = process_path(payload)
    normalized_path = normalize_ingestor_path(path)
    cmdline = process_command_line(payload)
    decoded = process_decoded_command_line(payload)
    command_evidence = join_command_evidence(cmdline, decoded)
    normalized_command_evidence = normalize_ingestor_text(command_evidence)

    suspicious_location =
      String.contains?(normalized_path, "\\temp\\") or
        String.contains?(normalized_path, "\\users\\") or
        String.contains?(normalized_path, "\\programdata\\") or
        String.contains?(normalized_command_evidence, "$env:temp") or
        String.contains?(normalized_command_evidence, "%temp%") or
        String.contains?(normalized_command_evidence, "\\temp\\") or
        String.contains?(normalized_command_evidence, "\\users\\") or
        String.contains?(normalized_command_evidence, "\\programdata\\")

    command_references_untrusted_executable =
      (String.contains?(normalized_command_evidence, "$env:temp") or
         String.contains?(normalized_command_evidence, "%temp%") or
         String.contains?(normalized_command_evidence, "\\temp\\") or
         String.contains?(normalized_command_evidence, "\\users\\") or
         String.contains?(normalized_command_evidence, "\\programdata\\")) and
        String.contains?(normalized_command_evidence, ".exe")

    masquerade_name =
      String.contains?(process, "tamandua-response") or
        String.contains?(normalized_command_evidence, "tamandua-response") or
        String.contains?(process, "svchost") or
        String.contains?(normalized_command_evidence, "svchost.exe") or
        String.contains?(process, "spoolsv") or
        String.contains?(normalized_command_evidence, "spoolsv.exe") or
        String.contains?(process, "lsass") or
        String.contains?(normalized_command_evidence, "lsass.exe") or
        String.contains?(process, "csrss") or
        String.contains?(normalized_command_evidence, "csrss.exe") or
        String.contains?(process, "host") or
        String.contains?(process, "update") or
        String.contains?(process, "service") or
        String.contains?(process, "security")

    if suspicious_location and
         (not trusted_windows_binary_path?(normalized_path) or command_references_untrusted_executable) and
         (String.ends_with?(process, ".exe") or String.contains?(normalized_command_evidence, ".exe")) and
         masquerade_name do
      detection(
        "process_masquerade_outside_system32",
        "process_masquerade",
        "Executable name and location suggest a relocated or masqueraded Windows binary outside trusted system directories.",
        ["defense_evasion"],
        ["T1036"],
        "medium",
        0.82,
        %{
          "process_name" => process,
          "process_path" => path,
          "command_line" => cmdline,
          "decoded_command_line" => decoded,
          "basis" => ["executable_path_or_decoded_script", "untrusted_location", "masquerade_name"]
        },
        event
      )
    end
  end

  defp detection(rule_name, detection_type, description, tactics, techniques, severity, confidence, evidence, event) do
    %{
      "rule_name" => rule_name,
      "name" => rule_name,
      "detection_type" => detection_type,
      "type" => detection_type,
      "description" => description,
      "mitre_tactics" => tactics,
      "mitre_techniques" => techniques,
      "severity" => severity,
      "confidence" => confidence,
      "source" => "server_process_behavior",
      "source_event_id" => event["event_id"] || event[:event_id] || event["id"] || event[:id],
      "evidence" => evidence
    }
  end

  defp merge_detections(existing, generated) do
    (existing ++ generated)
    |> Enum.filter(&is_map/1)
    |> Enum.uniq_by(fn detection ->
      {Map.get(detection, "rule_name") || Map.get(detection, :rule_name) || Map.get(detection, "name"),
       Map.get(detection, "detection_type") || Map.get(detection, :detection_type) || Map.get(detection, "type")}
    end)
  end

  defp strongest_detection_severity(detections, current) do
    severities =
      [current | Enum.map(detections, &(Map.get(&1, "severity") || Map.get(&1, :severity)))]
      |> Enum.map(&normalize_event_severity_text/1)

    cond do
      "critical" in severities -> "critical"
      "high" in severities -> "high"
      "medium" in severities -> "medium"
      "low" in severities -> "low"
      true -> "info"
    end
  end

  defp process_basename(payload), do: payload |> process_path_or_name() |> basename_text()

  defp process_path_or_name(payload) do
    first_text_value(payload, [
      :exe_path,
      :executable_path,
      :process_path,
      :image_path,
      :path,
      :process_name,
      :name,
      :image
    ]) || ""
  end

  defp process_path(payload) do
    first_text_value(payload, [:exe_path, :executable_path, :process_path, :image_path, :path]) || ""
  end

  defp process_command_line(payload) do
    first_text_value(payload, [:command_line, :cmdline, :command, :process_command_line]) || ""
  end

  defp process_decoded_command_line(payload) do
    first_text_value(payload, [:decoded_command_line, :decoded_script, :script_text]) || ""
  end

  defp join_command_evidence(left, ""), do: left || ""
  defp join_command_evidence("", right), do: right || ""
  defp join_command_evidence(left, right), do: "#{left}\n#{right}"

  defp command_line_has_encoded_flag?(cmdline) when is_binary(cmdline) do
    Regex.match?(~r/(^|\s|\/|-)(enc|encodedcommand)\b/i, cmdline)
  end

  defp command_line_has_encoded_flag?(_), do: false

  defp trusted_windows_binary_path?(path) when is_binary(path) do
    String.contains?(path, "\\windows\\system32\\") or
      String.contains?(path, "\\windows\\syswow64\\") or
      String.contains?(path, "\\windows\\winsxs\\")
  end

  defp trusted_windows_binary_path?(_), do: false

  defp safely_create_agent_detection_alert(event) do
    maybe_create_agent_detection_alert(event)
  rescue
    e ->
      Logger.warning("[Ingestor] Agent detection alert creation failed: #{Exception.message(e)}")
      :ok
  catch
    :exit, reason ->
      Logger.warning("[Ingestor] Agent detection alert creation exited: #{inspect(reason)}")
      :ok
  end

  defp agent_detection_alerts_enabled? do
    System.get_env("TAMANDUA_AGENT_DETECTION_ALERTS", "true") == "true"
  end

  defp alertable_agent_detection?(detection, event) when is_map(detection) do
    confidence = detection_confidence(detection)
    min_confidence = agent_detection_alert_min_confidence()

    severity =
      normalize_alert_severity(
        event["severity"] || event[:severity] || detection[:severity] || detection["severity"] || "medium"
      )

    confidence >= min_confidence or severity in ["high", "critical"]
  end

  defp alertable_agent_detection?(_, _), do: false

  defp agent_detection_priority(detection) when is_map(detection) do
    rule =
      detection[:name] || detection[:rule_name] || detection["name"] || detection["rule_name"] ||
        detection[:type] || detection["type"] || ""

    case normalize_ingestor_text(rule) do
      "regsvr32_proxy_execution" -> 90
      "process_masquerade_outside_system32" -> 80
      "powershell_encoded_command" -> 60
      value when value != "" -> 50
      _ -> 0
    end
  end

  defp agent_detection_priority(_), do: 0

  defp agent_detection_alert_min_confidence do
    case Float.parse(System.get_env("TAMANDUA_AGENT_DETECTION_ALERT_MIN_CONFIDENCE", "0.7")) do
      {value, _} when value >= 0.0 and value <= 1.0 -> value
      _ -> 0.7
    end
  end

  defp detection_confidence(detection) when is_map(detection) do
    case detection[:confidence] || detection["confidence"] do
      value when is_float(value) -> value
      value when is_integer(value) -> value / 1.0

      value when is_binary(value) ->
        case Float.parse(value) do
          {parsed, _} -> parsed
          _ -> 0.0
        end

      _ ->
        0.0
    end
  end

  defp normalize_detection(detection) when is_map(detection) do
    detection
    |> Enum.reduce(%{}, fn {key, value}, acc ->
      Map.put(acc, normalize_detection_key(key), value)
    end)
  end

  defp normalize_detection(_), do: %{}

  defp normalize_detection_key(key) when is_atom(key), do: key
  defp normalize_detection_key("detection_type"), do: :type
  defp normalize_detection_key("rule_name"), do: :name
  defp normalize_detection_key("confidence"), do: :confidence
  defp normalize_detection_key("description"), do: :description
  defp normalize_detection_key("mitre_tactics"), do: :mitre_tactics
  defp normalize_detection_key("mitre_techniques"), do: :mitre_techniques
  defp normalize_detection_key("severity"), do: :severity
  defp normalize_detection_key("rule_author_pubkey"), do: :rule_author_pubkey
  defp normalize_detection_key(key) when is_binary(key), do: key
  defp normalize_detection_key(key), do: key

  defp normalize_alert_severity(severity) when is_atom(severity),
    do: normalize_alert_severity(Atom.to_string(severity))

  defp normalize_alert_severity(severity) when is_binary(severity) do
    case String.downcase(severity) do
      value when value in ["critical", "high", "medium", "low", "info"] -> value
      _ -> "medium"
    end
  end

  defp normalize_alert_severity(_), do: "medium"

  defp detection_alert_title(event_type, detection) do
    rule = detection[:name] || detection[:rule_name] || detection[:description]
    event_label = event_type |> to_string() |> String.replace("_", " ")

    cond do
      ml_agent_detection?(detection) -> "ML Detection: #{rule || event_label}"
      rule -> "Agent detection: #{rule}"
      true -> "Agent detection: #{event_label}"
    end
  end

  defp detection_alert_description(event_type, detection) do
    detection[:description] ||
      "Agent local analysis produced a detection for event type #{event_type}."
  end

  defp detection_values(detections, key) do
    detections
    |> Enum.flat_map(fn detection -> List.wrap(detection[key] || []) end)
    |> Enum.map(&to_string/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  defp detection_threat_score("critical", _), do: 0.95
  defp detection_threat_score("high", _), do: 0.85

  defp detection_threat_score("medium", detections),
    do: max(0.60, max_detection_confidence(detections))

  defp detection_threat_score("low", detections),
    do: max(0.35, max_detection_confidence(detections))

  defp detection_threat_score(_, detections), do: max_detection_confidence(detections)

  defp max_detection_confidence(detections) do
    detections
    |> Enum.map(fn detection -> detection[:confidence] end)
    |> Enum.filter(&is_number/1)
    |> Enum.max(fn -> 0.5 end)
  end

  defp detection_rule_author_pubkey(event, detection) do
    detection[:rule_author_pubkey] ||
      get_in(event, ["metadata", "rule_author_pubkey"]) ||
      get_in(event, [:metadata, :rule_author_pubkey])
  end

  defp agent_detection_metadata(event, detections) do
    first_detection = List.first(detections, %{})
    payload = event["payload"] || event[:payload] || %{}

    %{
      "source" => if(Enum.any?(detections, &ml_agent_detection?/1), do: "ml", else: "agent"),
      "detection_source" => if(Enum.any?(detections, &ml_agent_detection?/1), do: "ml", else: "agent"),
      "detection_type" => if(Enum.any?(detections, &ml_agent_detection?/1), do: "ml", else: to_string(first_detection[:type] || "agent")),
      "rule_name" => first_detection[:name] || first_detection[:rule_name],
      "confidence" => max_detection_confidence(detections),
      "prediction" => payload["ml_verdict"] || payload[:ml_verdict],
      "malware_family" => payload["ml_verdict"] || payload[:ml_verdict],
      "model_version" => payload["model_version"] || payload[:model_version],
      "event_type" => event["event_type"] || event[:event_type]
    }
  end

  defp ml_agent_detection?(detection) when is_map(detection) do
    type = detection[:type] || detection["type"] || detection[:detection_type] || detection["detection_type"]
    name = detection[:name] || detection["name"] || detection[:rule_name] || detection["rule_name"] || ""

    normalize_ingestor_text(type) == "ml" or
      String.starts_with?(to_string(name), "OFFLINE_ML")
  end

  defp ml_agent_detection?(_), do: false

  defp persist_events(events) do
    now = NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)

    event_maps =
      events
      |> Enum.reject(&drop_ingested_event?/1)
      |> Enum.map(fn event ->
        # Handle both atom and string keys (JSON parsing produces string keys)
        event_id = event["event_id"] || event[:event_id] || event["id"] || event[:id]
        agent_id = event["agent_id"] || event[:agent_id]
        event_type = event["event_type"] || event[:event_type] || "unknown"
        event_type = to_string(event_type)
        timestamp = event["timestamp"] || event[:timestamp]
        payload =
          (event["payload"] || event[:payload] || %{})
          |> canonicalize_payload(event_type)
        severity = event["severity"] || event[:severity] || "info"
        severity = normalize_ingested_event_severity(event_type, payload, severity)
        payload = normalize_ingested_event_payload(event_type, payload)
        detections = normalize_event_detections(event["detections"] || event[:detections] || [])
        analysis = event["analysis"] || event[:analysis]

        organization_id =
          event["organization_id"] ||
            event[:organization_id] ||
            OrgLookup.get_org_id(agent_id)

        # Convert timestamp to DateTime (handles nil, integer, and string formats).
        # The Ecto schema declares :utc_datetime_usec which requires the
        # microsecond tuple precision to be exactly 6.  DateTime.truncate/2
        # only truncates the VALUE but preserves the original precision
        # metadata (e.g. 3 for millisecond-resolution timestamps from the
        # agent), so we explicitly promote to precision 6 via ensure_usec/1.
        event_timestamp =
          case timestamp do
            ts when is_integer(ts) and ts > 0 ->
              case DateTime.from_unix(ts, :millisecond) do
                {:ok, dt} -> ensure_usec(dt)
                {:error, _} -> ensure_usec(DateTime.utc_now())
              end

            ts when is_binary(ts) ->
              case DateTime.from_iso8601(ts) do
                {:ok, dt, _} -> ensure_usec(dt)
                {:error, _} -> ensure_usec(DateTime.utc_now())
              end

            %DateTime{} = dt ->
              ensure_usec(dt)

            _ ->
              ensure_usec(DateTime.utc_now())
          end
          |> clamp_future_timestamp()

        # Get enrichment data (already added by enrich_event) and preserve
        # source provenance before calculating the event contract.
        enrichment = event["enrichment"] || event[:enrichment] || %{}
        metadata = event["metadata"] || event[:metadata] || %{}
        derived_source = derive_event_source(event, payload, metadata, enrichment)
        metadata = put_when_blank(metadata, "source", derived_source)

        enrichment =
          enrichment
          |> Map.put_new(:analysis, analysis)
          |> put_when_blank("metadata", metadata)
          |> put_when_blank("source", derived_source)
          |> put_when_blank("origin", event_origin(derived_source))
          |> put_enrichment_metadata_source(derived_source)

        # Remove geo_info from payload if it was added there (legacy)
        # and ensure it's in enrichment instead
        legacy_geo = get_in(payload, ["geo_info"]) || get_in(payload, [:geo_info])

        enrichment =
          if legacy_geo && !enrichment[:geo] do
            Map.put(enrichment, :geo, %{"_legacy" => legacy_geo})
          else
            enrichment
          end

        evidence_event = %{
          id: event_id,
          agent_id: agent_id,
          event_type: event_type,
          timestamp: event_timestamp,
          severity: severity,
          payload: payload,
          enrichment: enrichment,
          detections: detections
        }

        enrichment =
          enrichment
          |> Map.put_new(
            "correlation_entities",
            CorrelationEvidence.extract_entities(evidence_event)
          )
          |> Map.put_new(
            "telemetry_quality",
            CorrelationEvidence.telemetry_quality(evidence_event)
          )
          |> Map.put_new("event_contract", EventContract.summarize(evidence_event))

        %{
          id: dump_uuid(event_id || Ecto.UUID.generate()),
          agent_id: dump_uuid(agent_id),
          event_type: event_type,
          timestamp: event_timestamp,
          severity: severity,
          payload: payload,
          enrichment: enrichment,
          detections: detections,
          sha256: get_in(payload, ["sha256"]) || get_in(payload, [:sha256]),
          organization_id: dump_uuid(organization_id),
          created_at: now
        }
      end)

    # Filter out events with nil agent_id (FK constraint requires it)
    event_maps = Enum.filter(event_maps, fn em -> is_binary(em[:agent_id]) end)

    if Enum.empty?(event_maps) do
      {:ok, 0}
    else
      # Ensure agent exists in database before inserting events (FK constraint)
      ensure_agents_exist(event_maps)

      insert_event_maps(event_maps, 2)
    end
  rescue
    e ->
      Logger.error("Database error persisting #{length(events)} events: #{Exception.message(e)}")
      {:error, e}
  end

  defp insert_event_maps([], _attempts_left), do: {:ok, 0}

  defp canonicalize_payload(payload, event_type) when is_map(payload) do
    category = EventContract.category(event_type)

    payload
    |> canonicalize_common_payload_fields()
    |> maybe_canonicalize_process_payload(category)
    |> maybe_canonicalize_network_payload(category)
    |> maybe_canonicalize_file_payload(category)
  end

  defp canonicalize_payload(payload, _event_type), do: payload

  defp canonicalize_common_payload_fields(payload) do
    payload
    |> put_alias_if_present("hostname", ["host", "computer_name", "device_name"])
    |> put_alias_if_present("user", ["username", "user_name", "account"])
  end

  defp maybe_canonicalize_process_payload(payload, category)
       when category in ["process", "script", "module", "driver"] do
    payload
    |> put_alias_if_present("process_name", ["name", "image", "image_name"])
    |> put_alias_if_present("command_line", ["cmdline", "command", "process_command_line"])
    |> put_alias_if_present("parent_process_name", ["parent_name", "parent_image"])
    |> put_alias_if_present("process_id", ["pid"])
    |> put_alias_if_present("parent_process_id", ["ppid", "parent_pid"])
    |> put_alias_if_present("exe_path", ["path", "image_path", "process_path"])
  end

  defp maybe_canonicalize_process_payload(payload, _category), do: payload

  defp maybe_canonicalize_network_payload(payload, category)
       when category in ["network", "dns", "ai_usage"] do
    payload
    |> put_alias_if_present("remote_ip", [
      "dst_ip",
      "dest_ip",
      "destination_ip",
      "remote_addr",
      "remote_address",
      "ip"
    ])
    |> put_alias_if_present("remote_port", ["dst_port", "destination_port", "port"])
    |> put_alias_if_present("domain", ["query", "dns_query", "host", "hostname"])
    |> put_alias_if_present("protocol", ["proto", "transport"])
  end

  defp maybe_canonicalize_network_payload(payload, _category), do: payload

  defp maybe_canonicalize_file_payload(payload, category)
       when category in ["file", "module", "driver"] do
    payload
    |> put_alias_if_present("file_path", ["path", "target_path", "module_path", "image_path"])
    |> put_alias_if_present("sha256", ["hash_sha256"])
  end

  defp maybe_canonicalize_file_payload(payload, _category), do: payload

  defp put_alias_if_present(payload, canonical_key, aliases) do
    if canonical_present?(Map.get(payload, canonical_key) || Map.get(payload, String.to_atom(canonical_key))) do
      payload
    else
      value =
        Enum.find_value(aliases, fn alias_key ->
          Map.get(payload, alias_key) || Map.get(payload, String.to_atom(alias_key))
        end)

      if canonical_present?(value), do: Map.put(payload, canonical_key, value), else: payload
    end
  end

  defp canonical_present?(value) when is_binary(value), do: String.trim(value) != ""
  defp canonical_present?(nil), do: false
  defp canonical_present?([]), do: false
  defp canonical_present?(_), do: true

  defp maybe_log_lab_persist_summary(events, count) do
    debug_agent_id = System.get_env("TAMANDUA_DEBUG_AGENT_ID", "9390f816-2a0f-47c3-aa4b-2b244fa2d737")

    lab_events =
      Enum.filter(events, fn event ->
        to_string(event["agent_id"] || event[:agent_id]) == debug_agent_id
      end)

    if lab_events != [] do
      type_counts =
        lab_events
        |> Enum.map(fn event -> event["event_type"] || event[:event_type] || "unknown" end)
        |> Enum.frequencies()

      Logger.info(
        "[Ingestor] Persist summary agent=#{debug_agent_id} lab_events=#{length(lab_events)} batch_inserted=#{count} types=#{inspect(type_counts)}"
      )
    end
  end

  defp insert_event_maps(event_maps, attempts_left) do
    case TamanduaServer.Repo.insert_all("events", event_maps,
           on_conflict: :nothing,
           returning: false
         ) do
      {count, _} ->
        {:ok, count}

      error ->
        {:error, error}
    end
  rescue
    e in Postgrex.Error ->
      if transient_db_error?(e) and attempts_left > 0 do
        Logger.warning(
          "[Ingestor] Transient event insert failure for #{length(event_maps)} events, retrying: #{inspect(e.postgres[:code])}"
        )

        Process.sleep(50)
        insert_event_maps(event_maps, attempts_left - 1)
      else
        split_or_return_insert_error(event_maps, e)
      end

    e ->
      split_or_return_insert_error(event_maps, e)
  end

  defp normalize_ingested_event_severity("response_action", payload, severity) do
    severity = to_string(severity)

    if agent_canary_file_missing_event?(payload) do
      "medium"
    else
      severity
    end
  end

  defp normalize_ingested_event_severity(_event_type, _payload, severity), do: to_string(severity)

  defp normalize_ingested_event_payload("response_action", payload) when is_map(payload) do
    if agent_canary_file_missing_event?(payload) do
      payload
      |> Map.put_new("source", "agent_protection")
      |> Map.put_new("provider", "tamandua_agent")
      |> Map.put_new("noise_context", "agent_self_canary_missing")
    else
      payload
    end
  end

  defp normalize_ingested_event_payload(_event_type, payload), do: payload

  defp drop_ingested_event?(event) when is_map(event) do
    event_type = event["event_type"] || event[:event_type] || "unknown"
    payload = event["payload"] || event[:payload] || %{}

    to_string(event_type) == "response_action" and
      agent_canary_file_missing_event?(payload) and
      is_nil(Map.get(payload, "source_pid") || Map.get(payload, :source_pid)) and
      is_nil(Map.get(payload, "source_process") || Map.get(payload, :source_process))
  end

  defp drop_ingested_event?(_), do: false

  defp agent_canary_file_missing_event?(payload) when is_map(payload) do
    tamper_type = Map.get(payload, "tamper_type") || Map.get(payload, :tamper_type)
    description = Map.get(payload, "description") || Map.get(payload, :description) || ""

    tamper_type == "CanaryFileAccess" and
      String.contains?(to_string(description), "Canary file deleted") and
      String.contains?(to_string(description), "\\.canary\\")
  end

  defp agent_canary_file_missing_event?(_), do: false

  defp split_or_return_insert_error(event_maps, error) when length(event_maps) > 1 do
    Logger.warning(
      "[Ingestor] Event batch insert failed for #{length(event_maps)} events, splitting batch: #{Exception.message(error)}"
    )

    event_maps
    |> Enum.chunk_every(max(div(length(event_maps), 2), 1))
    |> Enum.reduce_while({:ok, 0}, fn chunk, {:ok, total} ->
      case insert_event_maps(chunk, 1) do
        {:ok, count} -> {:cont, {:ok, total + count}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp split_or_return_insert_error(_event_maps, error), do: {:error, error}

  defp put_when_blank(map, _key, nil), do: map
  defp put_when_blank(map, _key, ""), do: map

  defp put_when_blank(map, key, value) when is_map(map) do
    current = Map.get(map, key) || Map.get(map, to_atom_key(key))

    if is_nil(current) or current == "" or current == %{} do
      Map.put(map, key, value)
    else
      map
    end
  end

  defp put_when_blank(map, _key, _value), do: map

  defp put_enrichment_metadata_source(enrichment, nil), do: enrichment

  defp put_enrichment_metadata_source(enrichment, source) when is_map(enrichment) do
    metadata =
      enrichment
      |> Map.get("metadata", Map.get(enrichment, :metadata, %{}))
      |> case do
        metadata when is_map(metadata) -> metadata
        _ -> %{}
      end
      |> put_when_blank("source", source)

    Map.put(enrichment, "metadata", metadata)
  end

  defp put_enrichment_metadata_source(enrichment, _source), do: enrichment

  defp derive_event_source(event, payload, metadata, enrichment) do
    [
      get_any(event, "source"),
      get_any(metadata, "source"),
      get_any(payload, "source"),
      get_any(enrichment, "source"),
      get_any(get_any(enrichment, "metadata") || %{}, "source")
    ]
    |> Enum.find(&present?/1)
  end

  defp event_origin(nil), do: "agent"
  defp event_origin(source), do: "agent:#{source}"

  defp get_any(map, key) when is_map(map), do: Map.get(map, key) || Map.get(map, to_atom_key(key))
  defp get_any(_map, _key), do: nil

  defp present?(value), do: not is_nil(value) and value != ""

  defp to_atom_key(key) when is_binary(key) do
    try do
      String.to_existing_atom(key)
    rescue
      ArgumentError -> key
    end
  end

  defp to_atom_key(key), do: key

  defp transient_db_error?(%Postgrex.Error{postgres: %{code: code}}) do
    code in [:deadlock_detected, :serialization_failure]
  end

  defp transient_db_error?(_), do: false

  defp dump_uuid(nil), do: nil
  defp dump_uuid(<<_::128>> = uuid), do: uuid

  defp dump_uuid(uuid) when is_binary(uuid) do
    case Ecto.UUID.dump(uuid) do
      {:ok, dumped} -> dumped
      :error -> Ecto.UUID.bingenerate()
    end
  end

  defp dump_uuid(value), do: value

  defp ensure_event_identity(event) when is_map(event) do
    event_id = event["event_id"] || event[:event_id] || event["id"] || event[:id] || Ecto.UUID.generate()

    event
    |> Map.put("event_id", event_id)
    |> Map.put(:event_id, event_id)
    |> Map.put("id", event_id)
    |> Map.put(:id, event_id)
  end

  defp ensure_event_identity(event), do: event

  defp normalize_event_for_timeline(event) when is_map(event) do
    severity = event_value(event, :severity) |> normalize_event_severity_text()
    detections = event_value(event, :detections) |> normalize_event_detections()
    event = ensure_timeline_source(event)

    cond do
      severity in ["critical", "high"] and benign_edge_update_ntdll_event?(event, detections) ->
        event
        |> put_event_value(:severity, "medium")
        |> put_timeline_adjustment(severity, "medium", "edge_update_ntdll_fresh_mapping_without_actionable_context")

      severity in ["critical", "high"] and benign_edge_update_etw_event?(event, detections) ->
        event
        |> put_event_value(:severity, "medium")
        |> put_timeline_adjustment(severity, "medium", "edge_update_etw_patch_without_actionable_context")

      severity in ["critical", "high"] and contextless_etw_tamper_event?(event, detections) ->
        event
        |> put_event_value(:severity, "medium")
        |> put_timeline_adjustment(severity, "medium", "etw_tamper_missing_actionable_context")

      severity in ["critical", "high"] and ntdll_self_write_no_permission_transition_event?(event, detections) ->
        event
        |> put_event_value(:severity, "medium")
        |> put_timeline_adjustment(severity, "medium", "ntdll_self_write_no_permission_transition")

      severity in ["critical", "high"] and contextless_ntdll_write_event?(event, detections) ->
        event
        |> put_event_value(:severity, "medium")
        |> put_timeline_adjustment(severity, "medium", "ntdll_write_missing_target_context")

      severity in ["critical", "high"] and contextless_service_registry_event?(event, detections) ->
        event
        |> put_event_value(:severity, "medium")
        |> put_timeline_adjustment(severity, "medium", "service_registry_change_missing_process_context")

      true ->
        maybe_normalize_contextless_timeline_event(event, severity, detections)
    end
  end

  defp normalize_event_for_timeline(event), do: event

  defp ensure_timeline_source(event) do
    enrichment = event |> event_value(:enrichment) |> ensure_ingestor_map()

    if blank_ingestor?(map_value(enrichment, :source)) do
      metadata = event |> event_value(:metadata) |> ensure_ingestor_map()
      payload = event |> event_value(:payload) |> ensure_ingestor_map()

      explicit_source =
        first_text_value(metadata, [:source, :provider]) ||
          first_text_value(payload, [:source, :provider])

      source =
        case event_value(event, :event_type) |> normalize_ingestor_text() do
          _ when not is_nil(explicit_source) -> explicit_source
          "defense_evasion" -> "endpoint_behavior_inferred"
          "etw_tamper" -> "endpoint_behavior_inferred"
          "ntdll_write" -> "endpoint_behavior_inferred"
          "persistence_install" -> "endpoint_behavior_inferred"
          _ -> nil
        end

      if source do
        put_event_value(event, :enrichment, Map.put(enrichment, "source", source))
      else
        event
      end
    else
      event
    end
  end

  defp maybe_normalize_contextless_timeline_event(event, severity, detections) do
    if severity in ["critical", "high"] and detections == [] do
      case timeline_severity_adjustment(event, severity) do
        {^severity, nil} ->
          event

        {new_severity, reason} ->
          event
          |> put_event_value(:severity, new_severity)
          |> put_timeline_adjustment(severity, new_severity, reason)
      end
    else
      event
    end
  end

  defp normalize_event_detections(detections) when is_list(detections) do
    detections
    |> Enum.filter(&is_map/1)
    |> Enum.map(fn detection ->
      Enum.into(detection, %{}, fn {key, value} -> {to_string(key), value} end)
    end)
  end

  defp normalize_event_detections(_), do: []

  defp timeline_severity_adjustment(event, severity) do
    event_type = event_value(event, :event_type) |> to_string()

    cond do
      String.starts_with?(event_type, "file_") ->
        path = event_payload_path(event)

        case benign_file_churn_reason(path) do
          {:low, reason} -> {"low", reason}
          {:info, reason} -> {"info", reason}
          nil -> {severity, nil}
        end

      benign_ntdll_event?(event) ->
        {"info", "benign_ntdll_self_write_without_detection"}

      true ->
        {severity, nil}
    end
  end

  defp benign_edge_update_etw_event?(event, detections) do
    payload = event_value(event, :payload) |> ensure_ingestor_map()
    process = payload |> first_text_value([:name, :process_name, :image, :exe_path]) |> basename_text()
    parent = payload |> first_text_value([:parent_name, :parent_process_name]) |> basename_text()
    path = payload |> first_text_value([:path, :exe_path, :executable_path, :image_path]) |> normalize_ingestor_path()
    cmdline = payload |> first_text_value([:cmdline, :command_line]) |> normalize_ingestor_text()

    etw_t1562? =
      Enum.any?(detections, fn detection ->
        rule =
          detection
          |> Map.get("rule_name", Map.get(detection, :rule_name) || Map.get(detection, "name") || Map.get(detection, :name))
          |> normalize_ingestor_text()

        techniques =
          [
            Map.get(detection, "mitre_technique"),
            Map.get(detection, :mitre_technique),
            Map.get(detection, "mitre_techniques"),
            Map.get(detection, :mitre_techniques)
          ]
          |> Enum.map(&inspect/1)
          |> Enum.join(" ")
          |> normalize_ingestor_text()

        String.starts_with?(rule, "etw_") and String.contains?(techniques, "t1562.006")
      end)

    etw_t1562? and
      process == "microsoftedgeupdate.exe" and
      parent in ["svchost.exe", "microsoftedgeupdate.exe"] and
      String.contains?(path, "\\program files (x86)\\microsoft\\edgeupdate\\microsoftedgeupdate.exe") and
      benign_edge_update_commandline?(cmdline)
  end

  defp benign_edge_update_ntdll_event?(event, detections) do
    payload = event_value(event, :payload) |> ensure_ingestor_map()
    enrichment = event_value(event, :enrichment) |> ensure_ingestor_map()
    metadata = map_value(enrichment, :metadata) |> ensure_ingestor_map()
    process = payload |> first_text_value([:name, :process_name, :image, :exe_path]) |> basename_text()
    path = payload |> first_text_value([:path, :process_path, :exe_path, :executable_path, :image_path]) |> normalize_ingestor_path()
    operation = metadata |> first_text_value([:operation]) |> normalize_ingestor_text()
    mem_type = payload |> first_text_value([:mem_type_str]) |> normalize_ingestor_text()
    protection = payload |> first_text_value([:new_protection_str]) |> normalize_ingestor_text()
    source_pid = metadata |> map_value(:source_pid) |> normalize_ingestor_text()
    target_pid = metadata |> map_value(:target_pid) |> normalize_ingestor_text()

    ntdll_mapping? =
      Enum.any?(detections, fn detection ->
        rule =
          detection
          |> Map.get("rule_name", Map.get(detection, :rule_name) || Map.get(detection, "name") || Map.get(detection, :name))
          |> normalize_ingestor_text()

        rule == "ntdll_write_ntmapviewofsection"
      end)

    ntdll_mapping? and
      process == "microsoftedgeupdate.exe" and
      String.contains?(path, "\\program files (x86)\\microsoft\\edgeupdate\\microsoftedgeupdate.exe") and
      operation == "ntmapviewofsection" and
      mem_type == "mem_image" and
      protection == "page_execute_read" and
      source_pid != "" and
      source_pid == target_pid
  end

  defp benign_edge_update_commandline?(cmdline) do
    String.ends_with?(String.trim(cmdline), "microsoftedgeupdate.exe /c") or
      (String.contains?(cmdline, "microsoftedgeupdate.exe") and
         String.contains?(cmdline, " /ua ") and
         String.contains?(cmdline, "/installsource scheduler"))
  end

  defp contextless_etw_tamper_event?(event, detections) do
    payload = event_value(event, :payload) |> ensure_ingestor_map()
    metadata = event_value(event, :metadata) |> ensure_ingestor_map()
    enrichment = event_value(event, :enrichment) |> ensure_ingestor_map()

    etw_t1562? =
      Enum.any?(detections, fn detection ->
        rule =
          detection
          |> Map.get("rule_name", Map.get(detection, :rule_name) || Map.get(detection, "name") || Map.get(detection, :name))
          |> normalize_ingestor_text()

        techniques =
          [
            Map.get(detection, "mitre_technique"),
            Map.get(detection, :mitre_technique),
            Map.get(detection, "mitre_techniques"),
            Map.get(detection, :mitre_techniques)
          ]
          |> Enum.map(&inspect/1)
          |> Enum.join(" ")
          |> normalize_ingestor_text()

        String.starts_with?(rule, "etw_") and String.contains?(techniques, "t1562.006")
      end)

    context_values = [
      map_value(payload, :name),
      map_value(payload, :process_name),
      map_value(payload, :image),
      map_value(payload, :path),
      map_value(payload, :image_path),
      map_value(payload, :exe_path),
      map_value(payload, :cmdline),
      map_value(payload, :command_line),
      map_value(payload, :provider_name),
      map_value(payload, :session_name),
      map_value(payload, :operation),
      map_value(payload, :target_provider),
      map_value(payload, :target_session),
      map_value(metadata, :process_name),
      map_value(metadata, :image_path),
      map_value(metadata, :command_line),
      map_value(metadata, :provider_name),
      map_value(metadata, :session_name),
      map_value(metadata, :operation),
      map_value(metadata, :target_provider),
      map_value(metadata, :target_session),
      map_value(enrichment, :provider_name),
      map_value(enrichment, :session_name),
      map_value(enrichment, :operation),
      map_value(enrichment, :target_provider),
      map_value(enrichment, :target_session)
    ]

    etw_t1562? and Enum.all?(context_values, &blank_ingestor?/1)
  end

  defp contextless_ntdll_write_event?(event, detections) do
    payload = event_value(event, :payload) |> ensure_ingestor_map()
    metadata = event_value(event, :metadata) |> ensure_ingestor_map()
    enrichment = event_value(event, :enrichment) |> ensure_ingestor_map()

    ntdll_write? =
      Enum.any?(detections, fn detection ->
        rule =
          detection
          |> Map.get("rule_name", Map.get(detection, :rule_name) || Map.get(detection, "name") || Map.get(detection, :name))
          |> normalize_ingestor_text()

        rule in [
          "ntdll_write_writeprocessmemory",
          "ntdll_write_ntwritevirtualmemory",
          "ntdll_write_ntmapviewofsection"
        ]
      end)

    target_values =
      [
        map_value(payload, :target_pid),
        map_value(payload, :target_process),
        map_value(payload, :target_process_name),
        map_value(payload, :target_image),
        map_value(payload, :target_module),
        map_value(payload, :target_address),
        map_value(payload, :write_size),
        map_value(payload, :bytes_written),
        map_value(payload, :call_stack),
        map_value(metadata, :target_pid),
        map_value(metadata, :target_process),
        map_value(metadata, :target_process_name),
        map_value(metadata, :target_image),
        map_value(metadata, :target_module),
        map_value(metadata, :target_address),
        map_value(metadata, :write_size),
        map_value(metadata, :bytes_written),
        map_value(metadata, :call_stack),
        map_value(enrichment, :target_pid),
        map_value(enrichment, :target_process),
        map_value(enrichment, :target_process_name),
        map_value(enrichment, :target_image),
        map_value(enrichment, :target_module),
        map_value(enrichment, :target_address),
        map_value(enrichment, :write_size),
        map_value(enrichment, :bytes_written),
        map_value(enrichment, :call_stack)
      ]

    ntdll_write? and Enum.all?(target_values, &blank_ingestor?/1)
  end

  defp ntdll_self_write_no_permission_transition_event?(event, detections) do
    ntdll_write_detection?(detections) and
      ntdll_same_process_target?(event) and
      ntdll_image_text_target?(event) and
      ntdll_no_permission_transition?(event) and
      not ntdll_thread_execution_context?(event) and
      not ntdll_credential_target?(event)
  end

  defp ntdll_write_detection?(detections) do
    Enum.any?(detections, fn detection ->
      rule =
        detection
        |> Map.get("rule_name", Map.get(detection, :rule_name) || Map.get(detection, "name") || Map.get(detection, :name))
        |> normalize_ingestor_text()

      rule in [
        "ntdll_write_writeprocessmemory",
        "ntdll_write_ntwritevirtualmemory",
        "ntdll_write_ntmapviewofsection"
      ]
    end)
  end

  defp ntdll_same_process_target?(event) do
    source_pid =
      first_nested_event_value(event, [
        [:payload, :source_pid],
        [:metadata, :source_pid],
        [:enrichment, :source_pid],
        [:enrichment, :metadata, :source_pid],
        [:payload, :pid],
        [:metadata, :pid]
      ])

    target_pid =
      first_nested_event_value(event, [
        [:payload, :target_pid],
        [:metadata, :target_pid],
        [:enrichment, :target_pid],
        [:enrichment, :metadata, :target_pid]
      ])

    not blank_ingestor?(source_pid) and to_string(source_pid) == to_string(target_pid)
  end

  defp ntdll_image_text_target?(event) do
    mem_type =
      first_nested_event_value(event, [
        [:payload, :mem_type_str],
        [:metadata, :mem_type_str],
        [:enrichment, :mem_type_str],
        [:enrichment, :metadata, :mem_type_str],
        [:payload, :memory_type],
        [:enrichment, :metadata, :memory_type]
      ])
      |> normalize_ingestor_text()

    target_function =
      first_nested_event_value(event, [
        [:payload, :target_function],
        [:metadata, :target_function],
        [:enrichment, :target_function],
        [:enrichment, :metadata, :target_function],
        [:payload, :target_module],
        [:enrichment, :metadata, :target_module]
      ])
      |> normalize_ingestor_text()

    mem_type in ["mem_image", "image", "0x1000000"] and
      (target_function == "" or String.contains?(target_function, "ntdll.dll!.text"))
  end

  defp ntdll_no_permission_transition?(event) do
    old_protection =
      first_nested_event_value(event, [
        [:payload, :old_protection_str],
        [:metadata, :old_protection_str],
        [:enrichment, :old_protection_str],
        [:enrichment, :metadata, :old_protection_str],
        [:payload, :old_protection],
        [:enrichment, :metadata, :old_protection]
      ])
      |> normalize_memory_protection()

    new_protection =
      first_nested_event_value(event, [
        [:payload, :new_protection_str],
        [:metadata, :new_protection_str],
        [:enrichment, :new_protection_str],
        [:enrichment, :metadata, :new_protection_str],
        [:payload, :new_protection],
        [:enrichment, :metadata, :new_protection]
      ])
      |> normalize_memory_protection()

    old_protection in ["page_execute_read", "0x20"] and
      new_protection in ["page_execute_read", "0x20"] and
      old_protection == new_protection
  end

  defp ntdll_thread_execution_context?(event) do
    thread_from_unbacked =
      first_nested_event_value(event, [
        [:payload, :thread_from_unbacked],
        [:metadata, :thread_from_unbacked],
        [:enrichment, :thread_from_unbacked],
        [:enrichment, :metadata, :thread_from_unbacked]
      ])

    thread_start =
      first_nested_event_value(event, [
        [:payload, :thread_start_address],
        [:metadata, :thread_start_address],
        [:enrichment, :thread_start_address],
        [:enrichment, :metadata, :thread_start_address]
      ])

    thread_from_unbacked in [true, "true", "1", 1] or not blank_ingestor?(thread_start)
  end

  defp ntdll_credential_target?(event) do
    target =
      first_nested_event_value(event, [
        [:payload, :target_process],
        [:payload, :target_process_name],
        [:metadata, :target_process],
        [:metadata, :target_process_name],
        [:enrichment, :target_process],
        [:enrichment, :target_process_name],
        [:enrichment, :metadata, :target_process],
        [:enrichment, :metadata, :target_process_name]
      ])
      |> normalize_ingestor_text()

    String.contains?(target, "lsass") or String.contains?(target, "sam")
  end

  defp first_nested_event_value(event, paths) do
    Enum.find_value(paths, fn path ->
      value = nested_event_value(event, path)
      if blank_ingestor?(value), do: nil, else: value
    end)
  end

  defp nested_event_value(value, []), do: value

  defp nested_event_value(value, [key | rest]) when is_map(value) do
    value
    |> map_value(key)
    |> nested_event_value(rest)
  end

  defp nested_event_value(_, _), do: nil

  defp normalize_memory_protection(value) do
    value
    |> normalize_ingestor_text()
    |> String.replace(" ", "_")
  end

  defp contextless_service_registry_event?(event, detections) do
    payload = event_value(event, :payload) |> ensure_ingestor_map()
    event_type = event_value(event, :event_type) |> normalize_ingestor_text()
    key_path = payload |> first_text_value([:key_path, :registry_key, :target_object, :target_name]) |> normalize_ingestor_path()
    operation = payload |> first_text_value([:operation]) |> normalize_ingestor_text()
    process = payload |> first_text_value([:process_name, :name, :image, :exe_path]) |> basename_text()
    pid = payload |> map_value(:pid) |> normalize_ingestor_text()

    service_rule? =
      Enum.any?(detections, fn detection ->
        rule =
          detection
          |> Map.get("rule_name", Map.get(detection, :rule_name) || Map.get(detection, "name") || Map.get(detection, :name))
          |> normalize_ingestor_text()

        rule == "registry_t1543_003"
      end)

    event_type in ["registry_delete", "registry_modify", "registry_set_value"] and
      service_rule? and
      (String.contains?(key_path, "\\system\\currentcontrolset\\services") or
         String.contains?(key_path, "hklm\\system\\currentcontrolset\\services")) and
      operation in ["", "key_delete", "value_delete", "value_set", "set_value"] and
      process in ["", "unknown"] and
      pid in ["", "0"]
  end

  defp put_timeline_adjustment(event, original_severity, new_severity, reason) do
    enrichment =
      event
      |> event_value(:enrichment)
      |> ensure_ingestor_map()
      |> Map.put("timeline_severity_adjusted", true)
      |> Map.put("original_severity", original_severity)
      |> Map.put("adjusted_severity", new_severity)
      |> Map.put("timeline_adjustment_reason", reason)
      |> Map.put("timeline_adjustment_basis", "structured_event_context")

    put_event_value(event, :enrichment, enrichment)
  end

  defp event_payload_path(event) do
    payload = event_value(event, :payload) |> ensure_ingestor_map()

    first_text_value(payload, [
      :path,
      :file_path,
      :target_path,
      :source_path,
      :destination_path,
      :new_path,
      :old_path
    ])
  end

  defp benign_file_churn_reason(path) when is_binary(path) do
    normalized = path |> String.replace("\\", "/") |> String.downcase()

    cond do
      browser_profile_churn_path?(normalized) ->
        {:low, "browser_profile_or_cache_churn"}

      macos_user_churn_path?(normalized) ->
        {:info, "macos_user_app_or_index_churn"}

      log_churn_path?(normalized) ->
        {:info, "application_log_churn"}

      true ->
        nil
    end
  end

  defp benign_file_churn_reason(_), do: nil

  defp browser_profile_churn_path?(path) do
    browser_root? =
      String.contains?(path, "/library/application support/google/chrome/") or
        String.contains?(path, "/library/application support/brave software/") or
        String.contains?(path, "/library/application support/microsoft edge/") or
        String.contains?(path, "/library/application support/firefox/") or
        String.contains?(path, "/appdata/local/google/chrome/user data/") or
        String.contains?(path, "/appdata/local/bravesoftware/brave-browser/user data/") or
        String.contains?(path, "/appdata/local/microsoft/edge/user data/") or
        String.contains?(path, "/appdata/roaming/mozilla/firefox/profiles/")

    profile_churn? =
      Enum.any?(
        [
          "/cache/",
          "/code cache/",
          "/gpu cache/",
          "/service worker/cache",
          "/shadercache/",
          "/grshadercache/",
          "/dawncache/",
          "/cookies-journal",
          "/network persistent state",
          "/secure preferences",
          "/preferences",
          "/reporting and nel-journal",
          "/history-journal",
          "/favicons-journal",
          "/top sites-journal",
          "/visited links",
          "/session storage/",
          "/local storage/",
          "/indexeddb/",
          "/shared_proto_db/",
          "/transportsecurity"
        ],
        &String.contains?(path, &1)
      )

    browser_root? and profile_churn?
  end

  defp macos_user_churn_path?(path) do
    String.contains?(path, "/library/caches/") or
      String.contains?(path, "/library/application support/com.apple.spotlight/") or
      String.contains?(path, "/library/application support/addressbook/") or
      String.contains?(path, "/library/containers/com.apple.") or
      String.contains?(path, "/library/group containers/group.com.apple.") or
      String.contains?(path, "/library/application support/knowledge/") or
      String.contains?(path, "/library/application support/com.apple.sharedfilelist/")
  end

  defp log_churn_path?(path) do
    String.contains?(path, "/library/logs/") or
      String.contains?(path, "/logs/synergy/") or
      String.ends_with?(path, ".log") or
      String.ends_with?(path, ".log.tmp")
  end

  defp benign_ntdll_event?(event) do
    payload = event_value(event, :payload) |> ensure_ingestor_map()
    event_type = event_value(event, :event_type) |> to_string() |> String.downcase()
    transition = first_text_value(payload, [:transition_type, :type, :operation, :operation_type])

    ntdll? =
      event_type in ["defense_evasion", "memory_operation", "ntdll_write"] or
        text_contains?(transition, "ntdll")

    same_process? =
      same_value?(payload, :source_pid, :target_pid) or
        same_value?(payload, :pid, :target_pid) or
        same_value?(payload, :process_id, :target_pid)

    common_process? =
      payload
      |> first_text_value([:process_name, :source_process_name, :image, :exe])
      |> common_userland_process?()

    suspicious_operation? =
      payload
      |> first_text_value([:operation, :operation_type, :transition_type, :protection])
      |> text_contains_any?(["directsyscall", "manualsyscall", "rwx", "remote", "cross_process"])

    ntdll? and same_process? and common_process? and not suspicious_operation?
  end

  defp common_userland_process?(value) when is_binary(value) do
    process = value |> String.replace("\\", "/") |> Path.basename() |> String.downcase()

    process in [
      "chrome.exe",
      "brave.exe",
      "msedge.exe",
      "firefox.exe",
      "backgroundtaskhost.exe",
      "docker.exe",
      "conhost.exe",
      "node.exe",
      "asysupdate.exe",
      "asusupdate.exe"
    ]
  end

  defp common_userland_process?(_), do: false

  defp same_value?(map, left, right) do
    left_value = map_value(map, left)
    right_value = map_value(map, right)
    not is_nil(left_value) and to_string(left_value) == to_string(right_value)
  end

  defp first_text_value(map, keys) do
    keys
    |> Enum.find_value(fn key ->
      value = map_value(map, key)
      if is_binary(value) and value != "", do: value, else: nil
    end)
  end

  defp map_value(map, key) when is_map(map), do: Map.get(map, key) || Map.get(map, to_string(key))
  defp map_value(_, _), do: nil

  defp event_value(map, key) when is_map(map),
    do: Map.get(map, key) || Map.get(map, to_string(key))

  defp event_value(_, _), do: nil

  defp put_event_value(event, key, value) do
    event
    |> Map.put(key, value)
    |> Map.put(to_string(key), value)
  end

  defp ensure_ingestor_map(map) when is_map(map), do: map
  defp ensure_ingestor_map(_), do: %{}

  defp normalize_event_severity_text(severity) when is_atom(severity),
    do: normalize_event_severity_text(Atom.to_string(severity))

  defp normalize_event_severity_text(severity) when is_binary(severity) do
    severity |> String.downcase() |> String.trim()
  end

  defp normalize_event_severity_text(_), do: "info"

  defp normalize_ingestor_text(value) when is_binary(value),
    do: value |> String.downcase() |> String.trim()

  defp normalize_ingestor_text(value), do: value |> to_string() |> String.downcase() |> String.trim()

  defp normalize_ingestor_path(value) do
    value
    |> normalize_ingestor_text()
    |> String.replace("/", "\\")
  end

  defp basename_text(nil), do: ""

  defp basename_text(value) do
    value
    |> to_string()
    |> String.replace("\\", "/")
    |> Path.basename()
    |> String.downcase()
  end

  defp blank_ingestor?(value), do: value in [nil, "", []]

  defp text_contains?(value, needle) when is_binary(value),
    do: value |> String.downcase() |> String.contains?(needle)

  defp text_contains?(_, _), do: false

  defp text_contains_any?(value, needles) when is_binary(value) do
    normalized = String.downcase(value)
    Enum.any?(needles, &String.contains?(normalized, &1))
  end

  defp text_contains_any?(_, _), do: false

  defp ensure_agents_exist(event_maps) do
    agent_ids =
      event_maps
      |> Enum.map(& &1[:agent_id])
      |> Enum.map(&load_uuid/1)
      |> Enum.reject(&is_nil/1)
      |> Enum.filter(&is_binary/1)
      |> Enum.uniq()

    now = NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)

    Enum.each(agent_ids, fn agent_id ->
      # Quick check: skip if agent already known in ETS registry
      case TamanduaServer.Agents.Registry.get(agent_id) do
        {:ok, _} ->
          :ok

        {:error, :not_found} ->
          # Agent not in registry, ensure it exists in the database
          machine_id =
            try do
              :crypto.hash(:sha256, agent_id)
            rescue
              _ -> <<0::256>>
            end

          attrs = %{
            id: agent_id,
            hostname: "unknown",
            os_type: "unknown",
            status: "online",
            last_seen_at: now,
            config: %{},
            machine_id: machine_id,
            inserted_at: now,
            updated_at: now
          }

          TamanduaServer.Repo.insert_all(
            TamanduaServer.Agents.Agent,
            [attrs],
            on_conflict: :nothing,
            conflict_target: :id
          )
      end
    end)
  rescue
    e ->
      Logger.warning("Could not ensure agents exist: #{Exception.message(e)}")
      :ok
  end

  defp load_uuid(<<_::128>> = uuid) do
    case Ecto.UUID.load(uuid) do
      {:ok, loaded} -> loaded
      :error -> uuid
    end
  end

  defp load_uuid(value), do: value

  defp broadcast_events(events) do
    # Group by agent for efficient broadcasting
    events
    |> Enum.group_by(& &1[:agent_id])
    |> Enum.each(fn {agent_id, agent_events} ->
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agent:#{agent_id}:events",
        {:new_events, agent_events}
      )
    end)

    # Broadcast to dashboard, org-scoped to prevent cross-tenant leakage.
    # Each connected dashboard subscribes only to "dashboard:events:<its org>",
    # so events never reach a socket belonging to a different organization.
    events
    |> Enum.group_by(&(&1[:organization_id] || &1["organization_id"]))
    |> Enum.each(fn {org_id, org_events} ->
      if org_id do
        Phoenix.PubSub.broadcast(
          TamanduaServer.PubSub,
          "dashboard:events:#{org_id}",
          {:new_events, org_events}
        )
      end
    end)

    # Broadcast to external streaming consumers
    Enum.each(events, fn event ->
      try do
        TamanduaServer.Streaming.StreamManager.broadcast_event(event)
      rescue
        _ -> :ok
      catch
        _, _ -> :ok
      end
    end)
  end

  # ── ClickHouse Dual-Write ───────────────────────────────────────────
  #
  # Sends events to the ClickHouseWriter for batched, fault-tolerant storage.
  # This call is non-blocking (cast) and fully fault-tolerant:
  #   - If ClickHouse is disabled via config, it's a no-op.
  #   - If the ClickHouseWriter GenServer is down, the error is caught and logged.
  #   - Events are buffered and flushed asynchronously with retry + circuit breaker.
  #   - The circuit breaker prevents cascading failures when ClickHouse is down.
  # The Broadway pipeline is NEVER blocked or crashed by ClickHouse issues.

  # Promote a DateTime to microsecond precision (precision = 6) so that
  # Ecto's :utc_datetime_usec type accepts it.  Timestamps originating from
  # the agent arrive with millisecond precision (precision = 3), and
  # DateTime.truncate/2 does not promote the precision field.
  defp ensure_usec(%DateTime{microsecond: {val, prec}} = dt) when prec < 6 do
    %{dt | microsecond: {val, 6}}
  end

  defp ensure_usec(%DateTime{} = dt), do: dt
  defp ensure_usec(_), do: %{DateTime.utc_now() | microsecond: {0, 6}}

  defp clamp_future_timestamp(%DateTime{} = timestamp) do
    now = ensure_usec(DateTime.utc_now())
    max_future = DateTime.add(now, 5 * 60, :second)

    if DateTime.compare(timestamp, max_future) == :gt do
      now
    else
      timestamp
    end
  end

  defp persist_to_clickhouse(events) do
    # Primary path: use the new ClickHouseWriter with circuit breaker
    ClickHouseWriter.write(events)

    # Also send to the legacy ClickHouse GenServer for backward compatibility
    # (it maintains the same buffer/flush mechanism but without circuit breaker)
    ClickHouse.insert_events(events)
  rescue
    e ->
      Logger.warning("[Ingestor] ClickHouse write failed (non-fatal): #{Exception.message(e)}")
  catch
    :exit, reason ->
      Logger.warning("[Ingestor] ClickHouse process unavailable (non-fatal): #{inspect(reason)}")
  end

  defp maybe_feed_ndr_direct(event) do
    if ndr_direct_feed?() and EventNormalizer.network_event?(event) do
      ndr_event = EventNormalizer.normalize_event(event)

      FlowAnalyzer.process_event(ndr_event)

      _detections =
        ProtocolAnalyzer.analyze_event(ndr_event) ++
          LateralDetector.analyze_event(ndr_event) ++
          EncryptedTraffic.analyze_event(ndr_event)
    end

    :ok
  rescue
    e ->
      Logger.debug("[Ingestor] Direct NDR feed unavailable: #{Exception.message(e)}")
      :ok
  catch
    :exit, reason ->
      Logger.debug("[Ingestor] Direct NDR feed process unavailable: #{inspect(reason)}")
      :ok
  end

  defp ndr_direct_feed? do
    lightweight_profile?() and is_nil(Process.whereis(Engine))
  end

  defp lightweight_profile? do
    System.get_env("TAMANDUA_LAB_LIGHT", "false") == "true" or
      System.get_env("TAMANDUA_BOOT_PROFILE") in ["core", "demo"]
  end

  defp lab_threat_intel_enrichment? do
    System.get_env("TAMANDUA_ENABLE_THREAT_INTEL_ENRICHMENT", "true") != "false"
  end
end
