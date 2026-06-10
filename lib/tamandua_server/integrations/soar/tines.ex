defmodule TamanduaServer.Integrations.SOAR.Tines do
  @moduledoc """
  Tines SOAR Integration

  Provides integration with Tines no-code automation platform:
  - Story (workflow) triggering via webhook actions
  - Event submission
  - Story status monitoring
  - Team/tenant management

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.SOAR.Tines,
        tenant: "your-tenant",
        api_token: "your-api-token",
        # or email/token auth:
        email: "your-email",
        token: "your-user-token",
        verify_ssl: true

  """

  use GenServer
  require Logger

  @behaviour TamanduaServer.Integrations.SOAR.Behaviour

  @base_url "https://app.tines.com/api/v1"
  @default_timeout_ms 30_000

  defstruct [
    :config,
    :url,
    :auth_header,
    :tenant,
    :stats,
    :webhook_urls
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl TamanduaServer.Integrations.SOAR.Behaviour
  def trigger_playbook(playbook_name, params \\ %{}) do
    GenServer.call(__MODULE__, {:trigger_playbook, playbook_name, params}, 60_000)
  end

  @impl TamanduaServer.Integrations.SOAR.Behaviour
  def get_playbook_status(run_id) do
    GenServer.call(__MODULE__, {:get_playbook_status, run_id}, 30_000)
  end

  @impl TamanduaServer.Integrations.SOAR.Behaviour
  def create_incident(incident_data) do
    GenServer.call(__MODULE__, {:create_incident, incident_data}, 30_000)
  end

  @impl TamanduaServer.Integrations.SOAR.Behaviour
  def update_incident(incident_id, updates) do
    GenServer.call(__MODULE__, {:update_incident, incident_id, updates}, 30_000)
  end

  @impl TamanduaServer.Integrations.SOAR.Behaviour
  def get_incident(incident_id) do
    GenServer.call(__MODULE__, {:get_incident, incident_id}, 30_000)
  end

  @impl TamanduaServer.Integrations.SOAR.Behaviour
  def add_artifact(incident_id, artifact) do
    GenServer.call(__MODULE__, {:add_artifact, incident_id, artifact}, 30_000)
  end

  @impl TamanduaServer.Integrations.SOAR.Behaviour
  def list_playbooks(opts \\ []) do
    GenServer.call(__MODULE__, {:list_playbooks, opts}, 30_000)
  end

  @impl TamanduaServer.Integrations.SOAR.Behaviour
  def test_connection do
    GenServer.call(__MODULE__, :test_connection, 30_000)
  end

  @impl TamanduaServer.Integrations.SOAR.Behaviour
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Send an event to a Tines webhook.
  """
  @spec send_event(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def send_event(webhook_url, event) do
    GenServer.call(__MODULE__, {:send_event, webhook_url, event}, 30_000)
  end

  @doc """
  List stories (workflows).
  """
  @spec list_stories(keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_stories(opts \\ []) do
    GenServer.call(__MODULE__, {:list_stories, opts}, 30_000)
  end

  @doc """
  Get story details.
  """
  @spec get_story(String.t()) :: {:ok, map()} | {:error, term()}
  def get_story(story_id) do
    GenServer.call(__MODULE__, {:get_story, story_id}, 30_000)
  end

  @doc """
  Register a webhook URL for a story.
  """
  @spec register_webhook(String.t(), String.t()) :: :ok
  def register_webhook(story_name, webhook_url) do
    GenServer.cast(__MODULE__, {:register_webhook, story_name, webhook_url})
  end

  @doc """
  List agents in the team.
  """
  @spec list_agents(keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_agents(opts \\ []) do
    GenServer.call(__MODULE__, {:list_agents, opts}, 30_000)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting Tines Integration")

    config = load_config(opts)
    auth_header = build_auth_header(config)

    state = %__MODULE__{
      config: config,
      url: config.url || @base_url,
      auth_header: auth_header,
      tenant: config.tenant,
      stats: %{
        stories_triggered: 0,
        events_sent: 0,
        last_activity: nil
      },
      webhook_urls: config.webhook_urls || %{}
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:trigger_playbook, playbook_name, params}, _from, state) do
    # In Tines, we trigger stories via webhook actions
    webhook_url = Map.get(state.webhook_urls, playbook_name) || params[:webhook_url]

    if webhook_url do
      payload = build_trigger_payload(params)

      case send_webhook(webhook_url, payload, state.config) do
        {:ok, response} ->
          new_stats = update_stat(state.stats, :stories_triggered)
          run_id = response["event_id"] || :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
          {:reply, {:ok, run_id}, %{state | stats: new_stats}}

        error ->
          {:reply, error, state}
      end
    else
      {:reply, {:error, "No webhook URL configured for story: #{playbook_name}"}, state}
    end
  end

  @impl true
  def handle_call({:get_playbook_status, run_id}, _from, state) do
    # Tines doesn't have direct run status - would need to track via story logs
    case get_request(state, "/stories/runs/#{run_id}") do
      {:ok, response} ->
        status = %{
          id: run_id,
          status: response["status"] || "unknown",
          started_at: response["created_at"],
          completed_at: response["finished_at"]
        }
        {:reply, {:ok, status}, state}

      {:error, _} ->
        # Return pending as default if we can't get status
        {:reply, {:ok, %{id: run_id, status: "pending"}}, state}
    end
  end

  @impl true
  def handle_call({:create_incident, incident_data}, _from, state) do
    # Tines creates cases via stories - trigger the incident story
    webhook_url = Map.get(state.webhook_urls, "incident") || incident_data[:webhook_url]

    if webhook_url do
      payload = format_incident(incident_data)

      case send_webhook(webhook_url, payload, state.config) do
        {:ok, response} ->
          incident_id = response["event_id"] || incident_data[:id] || generate_id()
          {:reply, {:ok, incident_id}, state}

        error ->
          {:reply, error, state}
      end
    else
      {:reply, {:error, :no_incident_webhook_configured}, state}
    end
  end

  @impl true
  def handle_call({:update_incident, incident_id, updates}, _from, state) do
    # Send update to update incident story
    webhook_url = Map.get(state.webhook_urls, "update_incident")

    if webhook_url do
      payload = Map.merge(updates, %{incident_id: incident_id, action: "update"})

      case send_webhook(webhook_url, payload, state.config) do
        {:ok, _} -> {:reply, :ok, state}
        error -> {:reply, error, state}
      end
    else
      {:reply, {:error, :no_update_webhook_configured}, state}
    end
  end

  @impl true
  def handle_call({:get_incident, incident_id}, _from, state) do
    # Tines uses stories/events as incident proxies. Query the audit log
    # or event store for the incident by searching events with matching incident_id.
    case get_request(state, "/events?incident_id=#{URI.encode(to_string(incident_id))}") do
      {:ok, %{"events" => [event | _]}} ->
        incident = %{
          id: incident_id,
          status: event["status"] || "open",
          title: event["title"] || event["name"],
          description: event["description"],
          created_at: event["created_at"],
          updated_at: event["updated_at"],
          raw_event: event
        }
        {:reply, {:ok, incident}, state}

      {:ok, %{"events" => []}} ->
        # Fallback: try searching stories for an execution with this ID
        case get_request(state, "/stories?search=#{URI.encode(to_string(incident_id))}") do
          {:ok, %{"stories" => [story | _]}} ->
            {:reply, {:ok, %{
              id: incident_id,
              status: if(story["disabled"], do: "closed", else: "open"),
              title: story["name"],
              description: story["description"],
              story_id: story["id"]
            }}, state}

          _ ->
            {:reply, {:error, :not_found}, state}
        end

      {:ok, events} when is_list(events) ->
        case events do
          [event | _] ->
            {:reply, {:ok, %{
              id: incident_id,
              status: event["status"] || "open",
              title: event["title"] || event["name"],
              raw_event: event
            }}, state}

          [] ->
            {:reply, {:error, :not_found}, state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:add_artifact, incident_id, artifact}, _from, state) do
    webhook_url = Map.get(state.webhook_urls, "add_artifact")

    if webhook_url do
      payload = %{
        incident_id: incident_id,
        artifact: artifact,
        action: "add_artifact"
      }

      case send_webhook(webhook_url, payload, state.config) do
        {:ok, _} ->
          artifact_id = generate_id()
          {:reply, {:ok, artifact_id}, state}

        error ->
          {:reply, error, state}
      end
    else
      {:reply, {:error, :no_artifact_webhook_configured}, state}
    end
  end

  @impl true
  def handle_call({:list_playbooks, _opts}, _from, state) do
    case get_request(state, "/stories") do
      {:ok, %{"stories" => stories}} ->
        formatted = Enum.map(stories, fn story ->
          %{
            id: story["id"],
            name: story["name"],
            description: story["description"],
            enabled: story["disabled"] != true,
            team_id: story["team_id"]
          }
        end)
        {:reply, {:ok, formatted}, state}

      {:ok, stories} when is_list(stories) ->
        formatted = Enum.map(stories, fn story ->
          %{
            id: story["id"],
            name: story["name"],
            description: story["description"],
            enabled: story["disabled"] != true
          }
        end)
        {:reply, {:ok, formatted}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call(:test_connection, _from, state) do
    case get_request(state, "/team") do
      {:ok, _} ->
        {:reply, {:ok, "Connected to Tines"}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_call({:send_event, webhook_url, event}, _from, state) do
    case send_webhook(webhook_url, event, state.config) do
      {:ok, response} ->
        new_stats = update_stat(state.stats, :events_sent)
        {:reply, {:ok, response}, %{state | stats: new_stats}}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:list_stories, opts}, _from, state) do
    page = opts[:page] || 1
    per_page = opts[:per_page] || 50

    case get_request(state, "/stories?page=#{page}&per_page=#{per_page}") do
      {:ok, %{"stories" => stories}} ->
        {:reply, {:ok, stories}, state}

      {:ok, response} when is_list(response) ->
        {:reply, {:ok, response}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:get_story, story_id}, _from, state) do
    case get_request(state, "/stories/#{story_id}") do
      {:ok, story} ->
        {:reply, {:ok, story}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:list_agents, _opts}, _from, state) do
    case get_request(state, "/agents") do
      {:ok, %{"agents" => agents}} ->
        {:reply, {:ok, agents}, state}

      {:ok, agents} when is_list(agents) ->
        {:reply, {:ok, agents}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_cast({:register_webhook, story_name, webhook_url}, state) do
    new_webhooks = Map.put(state.webhook_urls, story_name, webhook_url)
    {:noreply, %{state | webhook_urls: new_webhooks}}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp load_config(opts) do
    app_config = Application.get_env(:tamandua_server, __MODULE__, [])

    %{
      url: opts[:url] || app_config[:url] || @base_url,
      tenant: opts[:tenant] || app_config[:tenant],
      api_token: opts[:api_token] || app_config[:api_token],
      email: opts[:email] || app_config[:email],
      token: opts[:token] || app_config[:token],
      webhook_signing_secret: opts[:webhook_signing_secret] || app_config[:webhook_signing_secret],
      webhook_urls: opts[:webhook_urls] || app_config[:webhook_urls] || %{},
      timeout_ms: opts[:timeout_ms] || app_config[:timeout_ms] || @default_timeout_ms,
      verify_ssl: opts[:verify_ssl] != false && app_config[:verify_ssl] != false
    }
  end

  defp build_auth_header(config) do
    cond do
      config.api_token ->
        "Bearer #{config.api_token}"

      config.email && config.token ->
        "Token #{config.email}:#{config.token}"

      true ->
        nil
    end
  end

  defp build_trigger_payload(params) do
    base = %{
      source: "tamandua-edr",
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    alert = params[:alert] || params["alert"]

    if alert do
      Map.merge(base, %{
        alert_id: alert[:id] || alert["id"],
        title: alert[:title] || alert["title"],
        description: alert[:description] || alert["description"],
        severity: alert[:severity] || alert["severity"],
        hostname: alert[:hostname] || alert["hostname"],
        agent_id: alert[:agent_id] || alert["agent_id"],
        mitre_tactics: alert[:mitre_tactics] || alert["mitre_tactics"] || [],
        mitre_techniques: alert[:mitre_techniques] || alert["mitre_techniques"] || [],
        evidence: alert[:evidence] || alert["evidence"] || %{}
      })
    else
      Map.merge(base, Map.drop(params, [:webhook_url]))
    end
  end

  defp format_incident(incident_data) do
    %{
      type: "incident",
      source: "tamandua-edr",
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      alert_id: incident_data[:id] || incident_data["id"],
      title: incident_data[:title] || incident_data["title"],
      description: incident_data[:description] || incident_data["description"],
      severity: incident_data[:severity] || incident_data["severity"],
      hostname: incident_data[:hostname] || incident_data["hostname"],
      agent_id: incident_data[:agent_id] || incident_data["agent_id"],
      mitre_tactics: incident_data[:mitre_tactics] || incident_data["mitre_tactics"] || [],
      mitre_techniques: incident_data[:mitre_techniques] || incident_data["mitre_techniques"] || [],
      threat_score: incident_data[:threat_score] || incident_data["threat_score"],
      evidence: incident_data[:evidence] || incident_data["evidence"] || %{}
    }
  end

  defp send_webhook(webhook_url, payload, config) do
    alias TamanduaServer.Integrations.IntegrationLog

    body = Jason.encode!(payload)

    headers = [
      {"content-type", "application/json"}
    ]

    request = Finch.build(:post, webhook_url, headers, body)

    IntegrationLog.log_api_call("tines", "send_webhook", payload, fn ->
      case Finch.request(request, TamanduaServer.Finch, receive_timeout: config.timeout_ms) do
        {:ok, %Finch.Response{status: code, body: resp_body}} when code in 200..299 ->
          response = if resp_body != "" do
            case Jason.decode(resp_body) do
              {:ok, data} -> data
              _ -> %{"status" => "accepted"}
            end
          else
            %{"status" => "accepted"}
          end
          {:ok, response}

        {:ok, %Finch.Response{status: code, body: resp_body}} ->
          Logger.error("Tines webhook error: HTTP #{code} - #{resp_body}")
          {:error, "HTTP #{code}: #{resp_body}"}

        {:error, %Mint.TransportError{reason: reason}} ->
          Logger.error("Tines connection error: #{inspect(reason)}")
          {:error, inspect(reason)}

        {:error, reason} ->
          Logger.error("Tines connection error: #{inspect(reason)}")
          {:error, inspect(reason)}
      end
    end)
  rescue
    e ->
      Logger.error("Tines exception: #{inspect(e)}")
      {:error, Exception.message(e)}
  end

  defp get_request(state, endpoint) do
    alias TamanduaServer.Integrations.IntegrationLog

    url = "#{state.url}#{endpoint}"

    headers = [
      {"content-type", "application/json"},
      {"accept", "application/json"}
    ]

    headers = if state.auth_header do
      [{"authorization", state.auth_header} | headers]
    else
      headers
    end

    headers = if state.tenant do
      [{"x-tenant-id", state.tenant} | headers]
    else
      headers
    end

    request = Finch.build(:get, url, headers)

    IntegrationLog.log_api_call("tines", "get:#{endpoint}", nil, fn ->
      case Finch.request(request, TamanduaServer.Finch, receive_timeout: state.config.timeout_ms) do
        {:ok, %Finch.Response{status: code, body: resp_body}} when code in 200..299 ->
          {:ok, Jason.decode!(resp_body)}

        {:ok, %Finch.Response{status: code, body: resp_body}} ->
          {:error, "HTTP #{code}: #{resp_body}"}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, inspect(reason)}

        {:error, reason} ->
          {:error, inspect(reason)}
      end
    end)
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp update_stat(stats, key) do
    stats
    |> Map.update(key, 1, &(&1 + 1))
    |> Map.put(:last_activity, DateTime.utc_now())
  end

  defp generate_id do
    :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
  end

  # ============================================================================
  # Webhook Callback Verification & Parsing
  # ============================================================================

  @doc """
  Verify the HMAC signature on an inbound Tines webhook callback.

  Tines signs webhook payloads using the configured signing secret with HMAC-SHA256.
  The signature is sent in the `x-tines-signature` header.

  Returns `:ok` if the signature is valid, `{:error, :invalid_signature}` otherwise.
  """
  @spec verify_webhook_signature(String.t(), String.t()) :: :ok | {:error, :invalid_signature | :no_signing_secret}
  def verify_webhook_signature(raw_body, signature_header) do
    config = load_config([])
    secret = config.webhook_signing_secret

    if secret do
      expected = :crypto.mac(:hmac, :sha256, secret, raw_body)
                 |> Base.encode16(case: :lower)

      # Tines may send signature as "sha256=<hex>" or just "<hex>"
      actual = signature_header
               |> String.replace_prefix("sha256=", "")
               |> String.downcase()

      if Plug.Crypto.secure_compare(expected, actual) do
        :ok
      else
        {:error, :invalid_signature}
      end
    else
      {:error, :no_signing_secret}
    end
  end

  @doc """
  Parse a Tines webhook callback payload into a normalized structure.

  Returns a map with:
  - `execution_id` - The SOAR execution ID (if included in the original trigger payload)
  - `status` - Normalized status ("completed", "failed", "running")
  - `result` - The result data from Tines
  - `story_id` - The Tines story ID
  - `raw` - The raw payload
  """
  @spec parse_webhook_callback(map()) :: map()
  def parse_webhook_callback(payload) do
    %{
      execution_id: payload["execution_id"] || payload["tamandua_execution_id"],
      status: normalize_tines_status(payload["status"] || payload["event_status"]),
      result: payload["result"] || payload["data"] || payload["output"],
      story_id: payload["story_id"] || payload["story"],
      story_name: payload["story_name"],
      event_id: payload["event_id"] || payload["id"],
      agent_name: payload["agent_name"],
      error: payload["error"] || payload["error_message"],
      timestamp: payload["created_at"] || payload["timestamp"],
      raw: payload
    }
  end

  defp normalize_tines_status("completed"), do: "completed"
  defp normalize_tines_status("succeeded"), do: "completed"
  defp normalize_tines_status("success"), do: "completed"
  defp normalize_tines_status("done"), do: "completed"
  defp normalize_tines_status("failed"), do: "failed"
  defp normalize_tines_status("errored"), do: "failed"
  defp normalize_tines_status("error"), do: "failed"
  defp normalize_tines_status("running"), do: "running"
  defp normalize_tines_status("in_progress"), do: "running"
  defp normalize_tines_status("pending"), do: "pending"
  defp normalize_tines_status(_), do: "completed"
end
