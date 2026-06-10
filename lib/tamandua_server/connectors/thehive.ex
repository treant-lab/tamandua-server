defmodule TamanduaServer.Connectors.TheHive do
  @moduledoc """
  TheHive connector for case management integration.

  Capabilities:
  - Create cases from Tamandua alerts
  - Update case status based on alert resolution
  - Sync observables (IOCs) between systems
  - Support for custom fields and tags
  """

  use TamanduaServer.Connectors.Behaviour
  require Logger

  alias TamanduaServer.Connectors.Helpers.{Auth, Retry, Transform, RateLimiter}

  defmodule State do
    @moduledoc false
    defstruct [:url, :api_key, :verify_ssl, :default_case_template, :auto_create_cases]
  end

  @impl true
  def metadata do
    %{
      name: "TheHive Connector",
      version: "1.0.0",
      type: :alert_sink,
      description: "Case management integration with TheHive",
      author: "Tamandua Team",
      config_schema: %{
        required: [:url, :api_key],
        properties: %{
          url: %{type: :string, format: :url},
          api_key: %{type: :string, min_length: 20},
          verify_ssl: %{type: :boolean, default: true},
          default_case_template: %{type: :string},
          auto_create_cases: %{type: :boolean, default: true}
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
      default_case_template: Map.get(config, :default_case_template),
      auto_create_cases: Map.get(config, :auto_create_cases, true)
    }

    case test_connection(state) do
      :ok ->
        Logger.info("[TheHive Connector] Initialized successfully")
        {:ok, state}

      {:error, reason} ->
        {:error, {:connection_failed, reason}}
    end
  end

  @impl true
  def start(_state) do
    Logger.info("[TheHive Connector] Started")
    :ok
  end

  @impl true
  def stop(_state) do
    Logger.info("[TheHive Connector] Stopped")
    :ok
  end

  @impl true
  def health(state) do
    case test_connection(state) do
      :ok ->
        {:ok, %{status: :healthy}}

      {:error, reason} ->
        {:error, {:unhealthy, reason}}
    end
  end

  @impl true
  def handle_outbound(event, state) do
    case event.type do
      "alert" -> create_case_from_alert(event, state)
      "ioc" -> create_observable(event, state)
      _ -> {:error, :unsupported_event_type}
    end
  end

  @impl true
  def transform_outbound(event) do
    alert = Transform.alert_to_generic(event)

    %{
      title: alert.title,
      description: alert.description || "No description",
      severity: severity_to_hive_severity(alert.severity),
      tlp: 2, # TLP:AMBER
      pap: 2, # PAP:AMBER
      tags: build_tags(alert),
      customFields: %{
        "tamandua_alert_id" => alert.id,
        "agent_id" => alert.agent_id,
        "mitre_tactics" => Enum.join(alert.mitre_tactics || [], ", "),
        "mitre_techniques" => Enum.join(alert.mitre_techniques || [], ", ")
      },
      observables: build_observables(alert)
    }
  end

  # Private Functions

  defp test_connection(state) do
    url = "#{state.url}/api/v1/status"
    headers = [Auth.build_api_key_header(state.api_key)]

    Retry.with_backoff(fn ->
      case Req.get(url, headers: headers, connect_options: [verify: state.verify_ssl]) do
        {:ok, %{status: 200}} -> {:ok, :connected}
        {:ok, %{status: status}} -> {:error, {:http_error, status}}
        {:error, reason} -> {:error, reason}
      end
    end, max_attempts: 3)
  end

  defp create_case_from_alert(alert, state) do
    url = "#{state.url}/api/v1/case"
    headers = [
      Auth.build_api_key_header(state.api_key),
      {"Content-Type", "application/json"}
    ]

    payload = transform_outbound(alert)

    case RateLimiter.check_rate("thehive:api", limit: 50, window: 60) do
      :ok ->
        Retry.with_backoff(fn ->
          case Req.post(url, json: payload, headers: headers, connect_options: [verify: state.verify_ssl]) do
            {:ok, %{status: 201, body: body}} ->
              Logger.info("[TheHive] Created case #{body["id"]} for alert #{alert.id}")
              {:ok, %{case_id: body["id"], case_number: body["caseId"]}}

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

  defp create_observable(ioc, state) do
    url = "#{state.url}/api/v1/case/#{ioc.case_id}/artifact"
    headers = [
      Auth.build_api_key_header(state.api_key),
      {"Content-Type", "application/json"}
    ]

    payload = %{
      dataType: ioc_type_to_observable_type(ioc.type),
      data: ioc.value,
      message: ioc.description,
      tlp: 2,
      ioc: true,
      sighted: false,
      tags: ioc.tags || []
    }

    Retry.with_backoff(fn ->
      case Req.post(url, json: payload, headers: headers, connect_options: [verify: state.verify_ssl]) do
        {:ok, %{status: 201, body: body}} ->
          {:ok, %{observable_id: body["id"]}}

        {:ok, %{status: status}} ->
          {:error, {:http_error, status}}

        {:error, reason} ->
          {:error, reason}
      end
    end)
  end

  defp severity_to_hive_severity(severity) do
    case severity do
      "critical" -> 3 # Critical
      "high" -> 2     # High
      "medium" -> 1   # Medium
      "low" -> 1      # Low
      _ -> 1
    end
  end

  defp ioc_type_to_observable_type(type) do
    case type do
      "ip" -> "ip"
      "domain" -> "domain"
      "url" -> "url"
      "hash_md5" -> "hash"
      "hash_sha1" -> "hash"
      "hash_sha256" -> "hash"
      "email" -> "mail"
      "filename" -> "filename"
      _ -> "other"
    end
  end

  defp build_tags(alert) do
    base_tags = ["tamandua", "edr", "severity:#{alert.severity}"]
    mitre_tags = Enum.map(alert.mitre_tactics || [], fn t -> "mitre:#{t}" end)
    base_tags ++ mitre_tags
  end

  defp build_observables(alert) do
    # Extract IOCs from alert metadata
    case alert.metadata[:iocs] do
      nil -> []
      iocs ->
        Enum.map(iocs, fn ioc ->
          %{
            dataType: ioc_type_to_observable_type(ioc.type),
            data: ioc.value,
            message: ioc.description,
            tlp: 2,
            ioc: true,
            sighted: false
          }
        end)
    end
  end
end
