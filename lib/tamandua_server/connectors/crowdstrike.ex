defmodule TamanduaServer.Connectors.CrowdStrike do
  @moduledoc """
  CrowdStrike Falcon connector.

  Capabilities:
  - Pull threat intelligence from CrowdStrike Intel API
  - Execute response actions via RTR (Real-Time Response)
  - Query detections and incidents
  - Sync IOCs and indicators
  """

  use TamanduaServer.Connectors.Behaviour
  require Logger

  alias TamanduaServer.Connectors.Helpers.{Auth, Retry, Transform, RateLimiter}

  defmodule State do
    @moduledoc false
    defstruct [:client_id, :client_secret, :base_url, :token_info, :verify_ssl]
  end

  @impl true
  def metadata do
    %{
      name: "CrowdStrike Falcon Connector",
      version: "1.0.0",
      type: :response_action,
      description: "Integration with CrowdStrike Falcon for threat intel and response actions",
      author: "Tamandua Team",
      config_schema: %{
        required: [:client_id, :client_secret],
        properties: %{
          client_id: %{type: :string, min_length: 20},
          client_secret: %{type: :string, min_length: 20},
          base_url: %{type: :string, format: :url, default: "https://api.crowdstrike.com"},
          verify_ssl: %{type: :boolean, default: true}
        }
      }
    }
  end

  @impl true
  def init(config) do
    state = %State{
      client_id: config.client_id,
      client_secret: config.client_secret,
      base_url: Map.get(config, :base_url, "https://api.crowdstrike.com"),
      verify_ssl: Map.get(config, :verify_ssl, true),
      token_info: nil
    }

    # Obtain OAuth token
    case get_access_token(state) do
      {:ok, token_info} ->
        updated_state = %{state | token_info: token_info}
        Logger.info("[CrowdStrike Connector] Initialized successfully")
        {:ok, updated_state}

      {:error, reason} ->
        {:error, {:auth_failed, reason}}
    end
  end

  @impl true
  def start(_state) do
    Logger.info("[CrowdStrike Connector] Started")
    :ok
  end

  @impl true
  def stop(_state) do
    Logger.info("[CrowdStrike Connector] Stopped")
    :ok
  end

  @impl true
  def health(state) do
    # Check token validity
    if Auth.token_expired?(state.token_info) do
      {:error, {:unhealthy, :token_expired}}
    else
      {:ok, %{
        status: :healthy,
        token_expires_at: state.token_info[:expires_at]
      }}
    end
  end

  @impl true
  def handle_inbound(_event, state) do
    # Pull threat intel indicators
    case fetch_indicators(state) do
      {:ok, indicators} ->
        iocs = transform_indicators(indicators)
        {:ok, %{iocs: iocs, count: length(iocs)}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl true
  def handle_outbound(event, state) do
    # Execute response action
    case event.action do
      "contain_host" -> contain_host(event.agent_id, state)
      "lift_containment" -> lift_containment(event.agent_id, state)
      "run_command" -> run_rtr_command(event.agent_id, event.command, state)
      _ -> {:error, :unsupported_action}
    end
  end

  @impl true
  def transform_inbound(event) do
    %{
      type: "ioc_batch",
      source: "crowdstrike",
      timestamp: DateTime.utc_now(),
      data: event
    }
  end

  # Private Functions

  defp get_access_token(state) do
    url = "#{state.base_url}/oauth2/token"

    Auth.oauth_client_credentials(
      url,
      state.client_id,
      state.client_secret
    )
  end

  defp ensure_token(state) do
    Auth.ensure_valid_token(state.token_info, fn ->
      get_access_token(state)
    end)
  end

  defp fetch_indicators(state) do
    case ensure_token(state) do
      {:ok, token_info} ->
        url = "#{state.base_url}/intel/combined/indicators/v1"
        headers = [
          {"Authorization", "Bearer #{token_info.access_token}"},
          {"Content-Type", "application/json"}
        ]

        case RateLimiter.check_rate("crowdstrike:api", limit: 6000, window: 60) do
          :ok ->
            Retry.with_backoff(fn ->
              case Req.get(url, headers: headers, connect_options: [verify: state.verify_ssl]) do
                {:ok, %{status: 200, body: body}} ->
                  {:ok, body["resources"] || []}

                {:ok, %{status: status}} ->
                  {:error, {:http_error, status}}

                {:error, reason} ->
                  {:error, reason}
              end
            end)

          {:error, {:rate_limited, wait_time}} ->
            {:error, {:rate_limited, wait_time}}
        end

      {:error, reason} ->
        {:error, {:token_refresh_failed, reason}}
    end
  end

  defp contain_host(agent_id, state) do
    case ensure_token(state) do
      {:ok, token_info} ->
        url = "#{state.base_url}/devices/entities/devices-actions/v2?action_name=contain"
        headers = [
          {"Authorization", "Bearer #{token_info.access_token}"},
          {"Content-Type", "application/json"}
        ]

        payload = %{
          ids: [agent_id]
        }

        Retry.with_backoff(fn ->
          case Req.post(url, json: payload, headers: headers, connect_options: [verify: state.verify_ssl]) do
            {:ok, %{status: 202, body: body}} ->
              Logger.info("[CrowdStrike] Contained host #{agent_id}")
              {:ok, %{action_id: body["resources"] |> List.first()}}

            {:ok, %{status: status}} ->
              {:error, {:http_error, status}}

            {:error, reason} ->
              {:error, reason}
          end
        end)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp lift_containment(agent_id, state) do
    case ensure_token(state) do
      {:ok, token_info} ->
        url = "#{state.base_url}/devices/entities/devices-actions/v2?action_name=lift_containment"
        headers = [
          {"Authorization", "Bearer #{token_info.access_token}"},
          {"Content-Type", "application/json"}
        ]

        payload = %{
          ids: [agent_id]
        }

        Retry.with_backoff(fn ->
          case Req.post(url, json: payload, headers: headers, connect_options: [verify: state.verify_ssl]) do
            {:ok, %{status: 202, body: body}} ->
              Logger.info("[CrowdStrike] Lifted containment for host #{agent_id}")
              {:ok, %{action_id: body["resources"] |> List.first()}}

            {:ok, %{status: status}} ->
              {:error, {:http_error, status}}

            {:error, reason} ->
              {:error, reason}
          end
        end)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp run_rtr_command(agent_id, command, state) do
    case ensure_token(state) do
      {:ok, token_info} ->
        # Simplified RTR command execution
        url = "#{state.base_url}/real-time-response/entities/admin-command/v1"
        headers = [
          {"Authorization", "Bearer #{token_info.access_token}"},
          {"Content-Type", "application/json"}
        ]

        payload = %{
          base_command: "runscript",
          command_string: command,
          device_id: agent_id
        }

        Retry.with_backoff(fn ->
          case Req.post(url, json: payload, headers: headers, connect_options: [verify: state.verify_ssl]) do
            {:ok, %{status: 201, body: body}} ->
              {:ok, %{command_id: body["session_id"]}}

            {:ok, %{status: status}} ->
              {:error, {:http_error, status}}

            {:error, reason} ->
              {:error, reason}
          end
        end)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp transform_indicators(indicators) do
    Enum.map(indicators, fn indicator ->
      %{
        type: indicator_type_to_tamandua(indicator["type"]),
        value: indicator["indicator"],
        description: indicator["labels"] |> Enum.join(", "),
        severity: malicious_confidence_to_severity(indicator["malicious_confidence"]),
        source: "crowdstrike",
        tags: indicator["labels"] || [],
        metadata: %{
          actor: indicator["actors"],
          malware_families: indicator["malware_families"]
        }
      }
    end)
  end

  defp indicator_type_to_tamandua(type) do
    case type do
      "ip_address" -> "ip"
      "domain" -> "domain"
      "url" -> "url"
      "md5" -> "hash_md5"
      "sha1" -> "hash_sha1"
      "sha256" -> "hash_sha256"
      _ -> "unknown"
    end
  end

  defp malicious_confidence_to_severity(confidence) do
    case confidence do
      c when c >= 80 -> "critical"
      c when c >= 60 -> "high"
      c when c >= 40 -> "medium"
      _ -> "low"
    end
  end
end
