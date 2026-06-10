defmodule TamanduaServer.Connectors.MISP do
  @moduledoc """
  MISP (Malware Information Sharing Platform) connector.

  Bidirectional sync with MISP threat intelligence platform:
  - Pull IOCs from MISP events
  - Push Tamandua alerts/IOCs to MISP
  - Support for MISP taxonomies and galaxy clusters
  """

  use TamanduaServer.Connectors.Behaviour
  require Logger

  alias TamanduaServer.Connectors.Helpers.{Auth, Retry, Transform, RateLimiter}

  defmodule State do
    @moduledoc false
    defstruct [:url, :api_key, :verify_ssl, :poll_interval, :last_sync, :org_id, :token_info]
  end

  @impl true
  def metadata do
    %{
      name: "MISP Connector",
      version: "1.0.0",
      type: :ioc_source,
      description: "Bidirectional sync with MISP threat intelligence platform",
      author: "Tamandua Team",
      config_schema: %{
        required: [:url, :api_key],
        properties: %{
          url: %{type: :string, format: :url},
          api_key: %{type: :string, min_length: 40},
          verify_ssl: %{type: :boolean, default: true},
          poll_interval: %{type: :integer, default: 300},
          org_id: %{type: :string}
        }
      }
    }
  end

  @impl true
  def init(config) do
    state = %State{
      url: config.url,
      api_key: config.api_key,
      verify_ssl: Map.get(config, :verify_ssl, true),
      poll_interval: Map.get(config, :poll_interval, 300),
      org_id: Map.get(config, :org_id),
      last_sync: nil
    }

    # Test connection
    case test_connection(state) do
      :ok ->
        Logger.info("[MISP Connector] Initialized successfully")
        {:ok, state}

      {:error, reason} ->
        Logger.error("[MISP Connector] Connection test failed: #{inspect(reason)}")
        {:error, {:connection_failed, reason}}
    end
  end

  @impl true
  def start(state) do
    # Start polling loop
    schedule_poll(state.poll_interval)
    Logger.info("[MISP Connector] Started polling (interval: #{state.poll_interval}s)")
    :ok
  end

  @impl true
  def stop(_state) do
    Logger.info("[MISP Connector] Stopped")
    :ok
  end

  @impl true
  def health(state) do
    case test_connection(state) do
      :ok ->
        {:ok, %{
          status: :healthy,
          last_sync: state.last_sync,
          poll_interval: state.poll_interval
        }}

      {:error, reason} ->
        {:error, {:unhealthy, reason}}
    end
  end

  @impl true
  def handle_inbound(event, state) do
    # Pull IOCs from MISP event
    case fetch_event(event["event_id"], state) do
      {:ok, misp_event} ->
        iocs = extract_iocs(misp_event)
        {:ok, %{event: misp_event, iocs: iocs}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl true
  def handle_outbound(event, state) do
    # Push alert/IOC to MISP
    case event.type do
      "alert" -> create_misp_event_from_alert(event, state)
      "ioc" -> create_misp_attribute(event, state)
      _ -> {:error, :unsupported_event_type}
    end
  end

  @impl true
  def transform_inbound(event) do
    # Transform MISP event to Tamandua format
    %{
      type: "ioc_batch",
      source: "misp",
      event_id: event["Event"]["uuid"],
      timestamp: parse_timestamp(event["Event"]["timestamp"]),
      data: event
    }
  end

  @impl true
  def transform_outbound(event) do
    # Transform Tamandua alert to MISP event format
    alert = Transform.alert_to_generic(event)

    %{
      "Event" => %{
        "info" => alert.title,
        "threat_level_id" => severity_to_threat_level(alert.severity),
        "analysis" => 2, # Completed
        "distribution" => 1, # This community only
        "Attribute" => build_misp_attributes(alert)
      }
    }
  end

  # Private Functions

  defp test_connection(state) do
    url = "#{state.url}/servers/getPyMISPVersion.json"
    headers = [Auth.build_api_key_header(state.api_key, prefix: "")]

    Retry.with_backoff(fn ->
      case Req.get(url, headers: headers, connect_options: [verify: state.verify_ssl]) do
        {:ok, %{status: 200}} -> {:ok, :connected}
        {:ok, %{status: status}} -> {:error, {:http_error, status}}
        {:error, reason} -> {:error, reason}
      end
    end, max_attempts: 3)
  end

  defp fetch_event(event_id, state) do
    url = "#{state.url}/events/view/#{event_id}.json"
    headers = [Auth.build_api_key_header(state.api_key, prefix: "")]

    # Rate limit: 100 requests per minute
    case RateLimiter.check_rate("misp:api", limit: 100, window: 60) do
      :ok ->
        Retry.with_backoff(fn ->
          case Req.get(url, headers: headers, connect_options: [verify: state.verify_ssl]) do
            {:ok, %{status: 200, body: body}} -> {:ok, body}
            {:ok, %{status: 404}} -> {:error, :event_not_found}
            {:ok, %{status: status}} -> {:error, {:http_error, status}}
            {:error, reason} -> {:error, reason}
          end
        end)

      {:error, {:rate_limited, wait_time}} ->
        {:error, {:rate_limited, wait_time}}
    end
  end

  defp extract_iocs(misp_event) do
    event = misp_event["Event"]
    attributes = event["Attribute"] || []

    Enum.filter(attributes, fn attr ->
      attr["to_ids"] == true
    end)
    |> Enum.map(fn attr ->
      %{
        type: misp_type_to_tamandua(attr["type"]),
        value: attr["value"],
        description: attr["comment"] || event["info"],
        severity: threat_level_to_severity(event["threat_level_id"]),
        source: "misp",
        tags: extract_tags(event),
        metadata: %{
          misp_event_id: event["uuid"],
          misp_attribute_id: attr["uuid"],
          category: attr["category"]
        }
      }
    end)
  end

  defp create_misp_event_from_alert(alert, state) do
    url = "#{state.url}/events/add"
    headers = [
      Auth.build_api_key_header(state.api_key, prefix: ""),
      {"Content-Type", "application/json"}
    ]

    payload = transform_outbound(alert)

    case RateLimiter.check_rate("misp:api", limit: 100, window: 60) do
      :ok ->
        Retry.with_backoff(fn ->
          case Req.post(url, json: payload, headers: headers, connect_options: [verify: state.verify_ssl]) do
            {:ok, %{status: 200, body: body}} ->
              {:ok, %{event_id: body["Event"]["uuid"]}}

            {:ok, %{status: status, body: body}} ->
              {:error, {:http_error, status, body}}

            {:error, reason} ->
              {:error, reason}
          end
        end)

      {:error, {:rate_limited, wait_time}} ->
        {:error, {:rate_limited, wait_time}}
    end
  end

  defp create_misp_attribute(ioc, state) do
    url = "#{state.url}/attributes/add"
    headers = [
      Auth.build_api_key_header(state.api_key, prefix: ""),
      {"Content-Type", "application/json"}
    ]

    payload = %{
      "Attribute" => %{
        "type" => tamandua_type_to_misp(ioc.type),
        "value" => ioc.value,
        "comment" => ioc.description,
        "to_ids" => true
      }
    }

    Retry.with_backoff(fn ->
      case Req.post(url, json: payload, headers: headers, connect_options: [verify: state.verify_ssl]) do
        {:ok, %{status: 200, body: body}} ->
          {:ok, %{attribute_id: body["Attribute"]["uuid"]}}

        {:ok, %{status: status}} ->
          {:error, {:http_error, status}}

        {:error, reason} ->
          {:error, reason}
      end
    end)
  end

  defp build_misp_attributes(alert) do
    attributes = []

    # Add IOCs from alert metadata if present
    if alert.metadata[:iocs] do
      Enum.map(alert.metadata.iocs, fn ioc ->
        %{
          "type" => tamandua_type_to_misp(ioc.type),
          "value" => ioc.value,
          "to_ids" => true
        }
      end)
    else
      attributes
    end
  end

  defp misp_type_to_tamandua(type) do
    case type do
      "ip-src" -> "ip"
      "ip-dst" -> "ip"
      "domain" -> "domain"
      "hostname" -> "domain"
      "url" -> "url"
      "md5" -> "hash_md5"
      "sha1" -> "hash_sha1"
      "sha256" -> "hash_sha256"
      other -> other
    end
  end

  defp tamandua_type_to_misp(type) do
    case type do
      "ip" -> "ip-src"
      "domain" -> "domain"
      "url" -> "url"
      "hash_md5" -> "md5"
      "hash_sha1" -> "sha1"
      "hash_sha256" -> "sha256"
      other -> other
    end
  end

  defp severity_to_threat_level(severity) do
    case severity do
      "critical" -> 1
      "high" -> 2
      "medium" -> 3
      "low" -> 4
      _ -> 3
    end
  end

  defp threat_level_to_severity(level) do
    case level do
      1 -> "critical"
      2 -> "high"
      3 -> "medium"
      4 -> "low"
      _ -> "medium"
    end
  end

  defp extract_tags(event) do
    tags = event["Tag"] || []
    Enum.map(tags, fn tag -> tag["name"] end)
  end

  defp parse_timestamp(ts) when is_binary(ts) do
    case Integer.parse(ts) do
      {unix_ts, _} -> DateTime.from_unix!(unix_ts)
      :error -> DateTime.utc_now()
    end
  end
  defp parse_timestamp(ts) when is_integer(ts), do: DateTime.from_unix!(ts)
  defp parse_timestamp(_), do: DateTime.utc_now()

  defp schedule_poll(interval) do
    Process.send_after(self(), :poll, interval * 1000)
  end
end
