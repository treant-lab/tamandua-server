defmodule TamanduaServer.Integrations.Ticketing.PagerDuty do
  @moduledoc """
  PagerDuty Integration

  Provides integration with PagerDuty for incident alerting:
  - Trigger incidents via Events API v2
  - Acknowledge and resolve incidents
  - Change event submission
  - Incident management via REST API

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.Ticketing.PagerDuty,
        routing_key: "your-integration-key",  # Events API v2 integration key
        api_token: "your-api-token",          # REST API token
        default_service_id: nil,       # PagerDuty service ID (e.g., "PABC123")
        escalation_policy_id: nil,     # PagerDuty escalation policy ID
        verify_ssl: true

  """

  use GenServer
  require Logger

  @events_api_url "https://events.pagerduty.com/v2/enqueue"
  @change_events_url "https://events.pagerduty.com/v2/change/enqueue"
  @rest_api_url "https://api.pagerduty.com"

  @default_timeout_ms 30_000

  # Pattern matching placeholder IDs that should never be sent to PagerDuty
  @placeholder_pattern ~r/^P[X]{3,}$/

  defstruct [
    :config,
    :routing_key,
    :api_token,
    :configured,
    :stats
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Trigger a PagerDuty incident.
  """
  @spec trigger_incident(map()) :: {:ok, String.t()} | {:error, term()}
  def trigger_incident(incident_data) do
    GenServer.call(__MODULE__, {:trigger_incident, incident_data}, 30_000)
  end

  @doc """
  Acknowledge an incident.
  """
  @spec acknowledge_incident(String.t()) :: :ok | {:error, term()}
  def acknowledge_incident(dedup_key) do
    GenServer.call(__MODULE__, {:acknowledge_incident, dedup_key}, 30_000)
  end

  @doc """
  Resolve an incident.
  """
  @spec resolve_incident(String.t()) :: :ok | {:error, term()}
  def resolve_incident(dedup_key) do
    GenServer.call(__MODULE__, {:resolve_incident, dedup_key}, 30_000)
  end

  @doc """
  Send a change event.
  """
  @spec send_change_event(map()) :: {:ok, String.t()} | {:error, term()}
  def send_change_event(change_data) do
    GenServer.call(__MODULE__, {:send_change_event, change_data}, 30_000)
  end

  @doc """
  List incidents via REST API.
  """
  @spec list_incidents(keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_incidents(opts \\ []) do
    GenServer.call(__MODULE__, {:list_incidents, opts}, 30_000)
  end

  @doc """
  Get incident details via REST API.
  """
  @spec get_incident(String.t()) :: {:ok, map()} | {:error, term()}
  def get_incident(incident_id) do
    GenServer.call(__MODULE__, {:get_incident, incident_id}, 30_000)
  end

  @doc """
  Add a note to an incident.
  """
  @spec add_note(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def add_note(incident_id, note) do
    GenServer.call(__MODULE__, {:add_note, incident_id, note}, 30_000)
  end

  @doc """
  Update incident status via REST API.
  """
  @spec update_incident(String.t(), map()) :: :ok | {:error, term()}
  def update_incident(incident_id, updates) do
    GenServer.call(__MODULE__, {:update_incident, incident_id, updates}, 30_000)
  end

  @doc """
  Test connection to PagerDuty.
  """
  @spec test_connection() :: {:ok, String.t()} | {:error, term()}
  def test_connection do
    GenServer.call(__MODULE__, :test_connection, 30_000)
  end

  @doc """
  Get integration statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting PagerDuty Integration")

    config = load_config(opts)
    configured = validate_config(config)

    state = %__MODULE__{
      config: config,
      routing_key: config.routing_key,
      api_token: config.api_token,
      configured: configured,
      stats: %{
        incidents_triggered: 0,
        incidents_acknowledged: 0,
        incidents_resolved: 0,
        change_events_sent: 0,
        last_activity: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:trigger_incident, _incident_data}, _from, %{configured: false} = state) do
    {:reply, not_configured_error(), state}
  end

  def handle_call({:trigger_incident, incident_data}, _from, state) do
    event = format_trigger_event(incident_data, state.config)

    case send_event(event, state.config) do
      {:ok, response} ->
        dedup_key = response["dedup_key"]
        new_stats = update_stat(state.stats, :incidents_triggered)
        Logger.info("Triggered PagerDuty incident: #{dedup_key}")
        {:reply, {:ok, dedup_key}, %{state | stats: new_stats}}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:acknowledge_incident, _dedup_key}, _from, %{configured: false} = state) do
    {:reply, not_configured_error(), state}
  end

  def handle_call({:acknowledge_incident, dedup_key}, _from, state) do
    event = %{
      routing_key: state.routing_key,
      dedup_key: dedup_key,
      event_action: "acknowledge"
    }

    case send_event(event, state.config) do
      {:ok, _} ->
        new_stats = update_stat(state.stats, :incidents_acknowledged)
        {:reply, :ok, %{state | stats: new_stats}}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:resolve_incident, _dedup_key}, _from, %{configured: false} = state) do
    {:reply, not_configured_error(), state}
  end

  def handle_call({:resolve_incident, dedup_key}, _from, state) do
    event = %{
      routing_key: state.routing_key,
      dedup_key: dedup_key,
      event_action: "resolve"
    }

    case send_event(event, state.config) do
      {:ok, _} ->
        new_stats = update_stat(state.stats, :incidents_resolved)
        {:reply, :ok, %{state | stats: new_stats}}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:send_change_event, _change_data}, _from, %{configured: false} = state) do
    {:reply, not_configured_error(), state}
  end

  def handle_call({:send_change_event, change_data}, _from, state) do
    event = format_change_event(change_data, state.config)

    case send_change(event, state.config) do
      {:ok, response} ->
        new_stats = update_stat(state.stats, :change_events_sent)
        {:reply, {:ok, response["id"]}, %{state | stats: new_stats}}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:list_incidents, _opts}, _from, %{configured: false} = state) do
    {:reply, not_configured_error(), state}
  end

  def handle_call({:list_incidents, opts}, _from, state) do
    params = build_list_params(opts)

    case rest_get(state, "/incidents#{params}") do
      {:ok, response} ->
        {:reply, {:ok, response["incidents"] || []}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:get_incident, _incident_id}, _from, %{configured: false} = state) do
    {:reply, not_configured_error(), state}
  end

  def handle_call({:get_incident, incident_id}, _from, state) do
    case rest_get(state, "/incidents/#{incident_id}") do
      {:ok, response} ->
        {:reply, {:ok, response["incident"]}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:add_note, _incident_id, _note}, _from, %{configured: false} = state) do
    {:reply, not_configured_error(), state}
  end

  def handle_call({:add_note, incident_id, note}, _from, state) do
    body = %{
      note: %{
        content: note
      }
    }

    case rest_post(state, "/incidents/#{incident_id}/notes", body) do
      {:ok, response} ->
        {:reply, {:ok, response["note"]}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:update_incident, _incident_id, _updates}, _from, %{configured: false} = state) do
    {:reply, not_configured_error(), state}
  end

  def handle_call({:update_incident, incident_id, updates}, _from, state) do
    body = %{
      incident: format_incident_update(updates)
    }

    case rest_put(state, "/incidents/#{incident_id}", body) do
      {:ok, _} -> {:reply, :ok, state}
      error -> {:reply, error, state}
    end
  end

  @impl true
  def handle_call(:test_connection, _from, %{configured: false} = state) do
    {:reply, not_configured_error(), state}
  end

  def handle_call(:test_connection, _from, state) do
    # Test via Events API with a trigger/resolve cycle
    test_key = "tamandua-test-#{:rand.uniform(1_000_000)}"

    test_event = %{
      routing_key: state.routing_key,
      dedup_key: test_key,
      event_action: "trigger",
      payload: %{
        summary: "Tamandua EDR test connection",
        source: "tamandua-test",
        severity: "info"
      }
    }

    case send_event(test_event, state.config) do
      {:ok, _} ->
        # Immediately resolve the test incident
        resolve_event = %{
          routing_key: state.routing_key,
          dedup_key: test_key,
          event_action: "resolve"
        }
        send_event(resolve_event, state.config)
        {:reply, {:ok, "Connection successful"}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp load_config(opts) do
    app_config = Application.get_env(:tamandua_server, __MODULE__, [])

    %{
      routing_key: opts[:routing_key] || app_config[:routing_key],
      api_token: opts[:api_token] || app_config[:api_token],
      default_service_id: sanitize_placeholder(opts[:default_service_id] || app_config[:default_service_id]),
      escalation_policy_id: sanitize_placeholder(opts[:escalation_policy_id] || app_config[:escalation_policy_id]),
      from_email: opts[:from_email] || app_config[:from_email],
      timeout_ms: opts[:timeout_ms] || app_config[:timeout_ms] || @default_timeout_ms,
      verify_ssl: opts[:verify_ssl] != false && app_config[:verify_ssl] != false
    }
  end

  defp validate_config(config) do
    issues = []

    issues = if is_nil(config.routing_key) || config.routing_key == "" do
      ["routing_key is not configured" | issues]
    else
      issues
    end

    issues = if is_placeholder?(config.default_service_id) do
      ["default_service_id contains a placeholder value" | issues]
    else
      issues
    end

    issues = if is_placeholder?(config.escalation_policy_id) do
      ["escalation_policy_id contains a placeholder value" | issues]
    else
      issues
    end

    if issues == [] do
      true
    else
      Logger.warning(
        "PagerDuty integration is not fully configured. " <>
        "Issues: #{Enum.join(issues, "; ")}. " <>
        "API calls will return {:error, :not_configured} until valid credentials are provided."
      )
      false
    end
  end

  defp is_placeholder?(nil), do: false
  defp is_placeholder?(value) when is_binary(value) do
    Regex.match?(@placeholder_pattern, value)
  end
  defp is_placeholder?(_), do: false

  defp sanitize_placeholder(nil), do: nil
  defp sanitize_placeholder(value) when is_binary(value) do
    if Regex.match?(@placeholder_pattern, value), do: nil, else: value
  end
  defp sanitize_placeholder(value), do: value

  defp not_configured_error do
    {:error, {:not_configured, "PagerDuty integration is not configured. " <>
      "Please set routing_key, default_service_id, and escalation_policy_id " <>
      "in the application config or environment."}}
  end

  defp format_trigger_event(data, config) do
    # Use alert ID as dedup key if available
    dedup_key = data[:dedup_key] || data[:id] || data["id"] || generate_dedup_key()

    severity = map_severity(data[:severity] || data["severity"])

    %{
      routing_key: data[:routing_key] || config.routing_key,
      dedup_key: dedup_key,
      event_action: "trigger",
      payload: %{
        summary: data[:title] || data["title"] || "Tamandua Alert",
        source: data[:hostname] || data["hostname"] || "tamandua-edr",
        severity: severity,
        timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
        component: "tamandua-edr",
        group: data[:agent_id] || data["agent_id"],
        class: data[:alert_type] || data["alert_type"] || "security",
        custom_details: build_custom_details(data)
      },
      links: build_links(data),
      images: []
    }
  end

  defp format_change_event(data, config) do
    %{
      routing_key: data[:routing_key] || config.routing_key,
      payload: %{
        summary: data[:summary] || data["summary"] || "Tamandua Change",
        source: data[:source] || data["source"] || "tamandua-edr",
        timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
        custom_details: data[:details] || data["details"] || %{}
      },
      links: data[:links] || []
    }
  end

  defp format_incident_update(updates) do
    update = %{}

    update = if status = updates[:status] || updates["status"] do
      Map.put(update, :status, status)
    else
      update
    end

    update = if title = updates[:title] || updates["title"] do
      Map.put(update, :title, title)
    else
      update
    end

    update = if urgency = updates[:urgency] || updates["urgency"] do
      Map.put(update, :urgency, urgency)
    else
      update
    end

    update = if resolution = updates[:resolution] || updates["resolution"] do
      Map.put(update, :resolution, resolution)
    else
      update
    end

    update
  end

  defp build_custom_details(data) do
    details = %{
      alert_id: data[:id] || data["id"],
      agent_id: data[:agent_id] || data["agent_id"],
      hostname: data[:hostname] || data["hostname"],
      description: data[:description] || data["description"],
      threat_score: data[:threat_score] || data["threat_score"]
    }

    mitre_tactics = data[:mitre_tactics] || data["mitre_tactics"] || []
    details = if length(mitre_tactics) > 0 do
      Map.put(details, :mitre_tactics, Enum.join(mitre_tactics, ", "))
    else
      details
    end

    mitre_techniques = data[:mitre_techniques] || data["mitre_techniques"] || []
    details = if length(mitre_techniques) > 0 do
      Map.put(details, :mitre_techniques, Enum.join(mitre_techniques, ", "))
    else
      details
    end

    evidence = data[:evidence] || data["evidence"]
    if evidence && is_map(evidence) && map_size(evidence) > 0 do
      Map.put(details, :evidence, Jason.encode!(evidence))
    else
      details
    end
  end

  defp build_links(data) do
    links = []

    # Add link to Tamandua console if base URL is configured
    base_url = Application.get_env(:tamandua_server, :console_url)
    alert_id = data[:id] || data["id"]

    if base_url && alert_id do
      [%{href: "#{base_url}/app/alerts/#{alert_id}", text: "View in Tamandua"} | links]
    else
      links
    end
  end

  defp map_severity(severity) do
    case severity do
      "critical" -> "critical"
      "high" -> "error"
      "medium" -> "warning"
      "low" -> "info"
      "info" -> "info"
      _ -> "warning"
    end
  end

  defp build_list_params(opts) do
    params = []

    params = if status = opts[:status] do
      ["statuses[]=#{status}" | params]
    else
      params
    end

    params = if urgency = opts[:urgency] do
      ["urgencies[]=#{urgency}" | params]
    else
      params
    end

    params = if service_id = opts[:service_id] do
      ["service_ids[]=#{service_id}" | params]
    else
      params
    end

    params = if since = opts[:since] do
      ["since=#{since}" | params]
    else
      params
    end

    params = if until_time = opts[:until] do
      ["until=#{until_time}" | params]
    else
      params
    end

    params = ["limit=#{opts[:limit] || 25}" | params]
    params = ["offset=#{opts[:offset] || 0}" | params]

    if length(params) > 0, do: "?" <> Enum.join(params, "&"), else: ""
  end

  defp send_event(event, config) do
    headers = [{"Content-Type", "application/json"}]
    options = http_options(config)

    case Finch.build(:post, @events_api_url, headers, Jason.encode!(event)) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: code, body: resp_body}} when code in 200..299 ->
        {:ok, Jason.decode!(resp_body)}

      {:ok, %{status_code: 202, body: resp_body}} ->
        {:ok, Jason.decode!(resp_body)}

      {:ok, %{status_code: code, body: resp_body}} ->
        Logger.error("PagerDuty Events API error: HTTP #{code} - #{resp_body}")
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        Logger.error("PagerDuty connection error: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("PagerDuty exception: #{inspect(e)}")
      {:error, Exception.message(e)}
  end

  defp send_change(event, config) do
    headers = [{"Content-Type", "application/json"}]
    options = http_options(config)

    case Finch.build(:post, @change_events_url, headers, Jason.encode!(event)) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: code, body: resp_body}} when code in 200..299 ->
        {:ok, Jason.decode!(resp_body)}

      {:ok, %{status_code: 202, body: resp_body}} ->
        {:ok, Jason.decode!(resp_body)}

      {:ok, %{status_code: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp rest_get(state, endpoint) do
    url = "#{@rest_api_url}#{endpoint}"

    headers = [
      {"Authorization", "Token token=#{state.api_token}"},
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    options = http_options(state.config)

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: 200, body: resp_body}} ->
        {:ok, Jason.decode!(resp_body)}

      {:ok, %{status_code: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp rest_post(state, endpoint, body) do
    url = "#{@rest_api_url}#{endpoint}"

    headers = [
      {"Authorization", "Token token=#{state.api_token}"},
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    if state.config.from_email do
      [{"From", state.config.from_email} | headers]
    else
      headers
    end

    options = http_options(state.config)

    case Finch.build(:post, url, headers, Jason.encode!(body)) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: code, body: resp_body}} when code in 200..299 ->
        {:ok, Jason.decode!(resp_body)}

      {:ok, %{status_code: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp rest_put(state, endpoint, body) do
    url = "#{@rest_api_url}#{endpoint}"

    headers = [
      {"Authorization", "Token token=#{state.api_token}"},
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    headers = if state.config.from_email do
      [{"From", state.config.from_email} | headers]
    else
      headers
    end

    options = http_options(state.config)

    case Finch.build(:put, url, headers, Jason.encode!(body)) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: code, body: resp_body}} when code in 200..299 ->
        {:ok, Jason.decode!(resp_body)}

      {:ok, %{status_code: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp http_options(config) do
    opts = [
      timeout: config.timeout_ms,
      recv_timeout: config.timeout_ms
    ]

    if config.verify_ssl do
      opts
    else
      Keyword.put(opts, :ssl, verify: :verify_none)
    end
  end

  defp generate_dedup_key do
    "tamandua-#{:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)}"
  end

  defp update_stat(stats, key) do
    stats
    |> Map.update(key, 1, &(&1 + 1))
    |> Map.put(:last_activity, DateTime.utc_now())
  end
end
