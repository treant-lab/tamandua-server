defmodule TamanduaServer.Integrations.Sentinel do
  @moduledoc """
  Microsoft Sentinel Integration Module

  Provides integration with Microsoft Sentinel (Azure Sentinel):
  - Log Analytics Data Collector API for event ingestion
  - Forward alerts as SecurityAlert records
  - Forward events as custom log tables
  - Support for Sentinel playbook (Logic Apps) triggers
  - Incident management via Azure REST API

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.Sentinel,
        workspace_id: "your-workspace-id",
        shared_key: "your-shared-key",
        log_type: "TamanduaEDR",
        tenant_id: "your-azure-tenant-id",
        client_id: "your-azure-client-id",
        client_secret: "your-azure-client-secret",
        subscription_id: "your-subscription-id",
        resource_group: "your-resource-group"

  """

  use GenServer
  require Logger

  @behaviour TamanduaServer.Integrations.SIEMBehaviour

  # Azure endpoints
  @log_analytics_api_version "2016-04-01"
  @sentinel_api_version "2022-11-01"
  @azure_login_url "https://login.microsoftonline.com"
  @management_url "https://management.azure.com"

  # Default configuration
  @default_batch_size 100
  @default_batch_interval_ms 5000
  @default_timeout_ms 30_000

  defstruct [
    :config,
    :workspace_id,
    :shared_key,
    :access_token,
    :token_expires_at,
    :event_buffer,
    :stats
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Send a single event to Log Analytics.
  """
  @spec send_event(map()) :: :ok | {:error, term()}
  def send_event(event) do
    GenServer.call(__MODULE__, {:send_event, event})
  end

  @doc """
  Send a batch of events to Log Analytics.
  """
  @spec send_batch([map()]) :: :ok | {:error, term()}
  def send_batch(events) when is_list(events) do
    GenServer.call(__MODULE__, {:send_batch, events}, 60_000)
  end

  @doc """
  Forward an alert to Sentinel as a SecurityAlert.
  """
  @spec forward_alert(map()) :: :ok | {:error, term()}
  def forward_alert(alert) do
    GenServer.call(__MODULE__, {:forward_alert, alert})
  end

  @doc """
  Create a Sentinel incident.
  """
  @spec create_incident(map()) :: {:ok, String.t()} | {:error, term()}
  def create_incident(incident_data) do
    GenServer.call(__MODULE__, {:create_incident, incident_data}, 30_000)
  end

  @doc """
  Update a Sentinel incident.
  """
  @spec update_incident(String.t(), map()) :: :ok | {:error, term()}
  def update_incident(incident_id, updates) do
    GenServer.call(__MODULE__, {:update_incident, incident_id, updates}, 30_000)
  end

  @doc """
  Trigger a Sentinel playbook (Logic App).
  """
  @spec trigger_playbook(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def trigger_playbook(playbook_url, payload) do
    GenServer.call(__MODULE__, {:trigger_playbook, playbook_url, payload}, 60_000)
  end

  @doc """
  List Sentinel incidents.
  """
  @spec list_incidents(keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_incidents(opts \\ []) do
    GenServer.call(__MODULE__, {:list_incidents, opts}, 30_000)
  end

  @doc """
  Get Sentinel incident by ID.
  """
  @spec get_incident(String.t()) :: {:ok, map()} | {:error, term()}
  def get_incident(incident_id) do
    GenServer.call(__MODULE__, {:get_incident, incident_id}, 30_000)
  end

  @doc """
  Test connection to Sentinel.
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
  # Behaviour Callbacks
  # ============================================================================

  @impl TamanduaServer.Integrations.SIEMBehaviour
  def send_events(events), do: send_batch(events)

  @impl TamanduaServer.Integrations.SIEMBehaviour
  def send_alerts(alerts) do
    Enum.each(alerts, &forward_alert/1)
    :ok
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting Microsoft Sentinel Integration")

    config = load_config(opts)

    # Schedule batch flush
    if config.batch_interval_ms > 0 do
      schedule_batch_flush(config.batch_interval_ms)
    end

    state = %__MODULE__{
      config: config,
      workspace_id: config.workspace_id,
      shared_key: config.shared_key,
      access_token: nil,
      token_expires_at: nil,
      event_buffer: [],
      stats: %{
        events_sent: 0,
        events_failed: 0,
        alerts_sent: 0,
        incidents_created: 0,
        playbooks_triggered: 0,
        last_send: nil,
        last_error: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:send_event, event}, _from, state) do
    formatted = format_log_analytics_event(event, state.config)
    new_buffer = [formatted | state.event_buffer]

    if length(new_buffer) >= state.config.batch_size do
      case flush_events(new_buffer, state) do
        :ok ->
          new_stats = update_stats(state.stats, :events_sent, length(new_buffer))
          {:reply, :ok, %{state | event_buffer: [], stats: new_stats}}

        {:error, reason} = error ->
          new_stats = update_stats(state.stats, :events_failed, length(new_buffer))
          new_stats = Map.put(new_stats, :last_error, reason)
          {:reply, error, %{state | stats: new_stats}}
      end
    else
      {:reply, :ok, %{state | event_buffer: new_buffer}}
    end
  end

  @impl true
  def handle_call({:send_batch, events}, _from, state) do
    formatted = Enum.map(events, &format_log_analytics_event(&1, state.config))

    case flush_events(formatted, state) do
      :ok ->
        new_stats = update_stats(state.stats, :events_sent, length(events))
        {:reply, :ok, %{state | stats: new_stats}}

      {:error, reason} = error ->
        new_stats = update_stats(state.stats, :events_failed, length(events))
        new_stats = Map.put(new_stats, :last_error, reason)
        {:reply, error, %{state | stats: new_stats}}
    end
  end

  @impl true
  def handle_call({:forward_alert, alert}, _from, state) do
    # Send alert to both Log Analytics (as SecurityAlert) and create incident if high severity
    alert_event = format_security_alert(alert, state.config)

    case send_to_log_analytics(state, [alert_event], "SecurityAlert") do
      :ok ->
        new_stats = update_stats(state.stats, :alerts_sent, 1)

        # Auto-create incident for high/critical severity
        severity = alert[:severity] || alert["severity"]
        if severity in ["critical", "high"] do
          spawn(fn -> create_incident_from_alert(alert, state) end)
        end

        {:reply, :ok, %{state | stats: new_stats}}

      {:error, _reason} = error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:create_incident, incident_data}, _from, state) do
    case ensure_access_token(state) do
      {:ok, new_state} ->
        result = create_sentinel_incident(incident_data, new_state)
        case result do
          {:ok, incident_id} ->
            new_stats = update_stats(new_state.stats, :incidents_created, 1)
            {:reply, result, %{new_state | stats: new_stats}}
          error ->
            {:reply, error, new_state}
        end

      {:error, _reason} = error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:update_incident, incident_id, updates}, _from, state) do
    case ensure_access_token(state) do
      {:ok, new_state} ->
        result = update_sentinel_incident(incident_id, updates, new_state)
        {:reply, result, new_state}

      {:error, _reason} = error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:trigger_playbook, playbook_url, payload}, _from, state) do
    result = trigger_logic_app(playbook_url, payload, state.config)

    case result do
      {:ok, _} ->
        new_stats = update_stats(state.stats, :playbooks_triggered, 1)
        {:reply, result, %{state | stats: new_stats}}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:list_incidents, opts}, _from, state) do
    case ensure_access_token(state) do
      {:ok, new_state} ->
        result = fetch_sentinel_incidents(opts, new_state)
        {:reply, result, new_state}

      {:error, _reason} = error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:get_incident, incident_id}, _from, state) do
    case ensure_access_token(state) do
      {:ok, new_state} ->
        result = fetch_sentinel_incident(incident_id, new_state)
        {:reply, result, new_state}

      {:error, _reason} = error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call(:test_connection, _from, state) do
    test_event = %{
      TimeGenerated: DateTime.utc_now() |> DateTime.to_iso8601(),
      Message: "Tamandua EDR test connection",
      Source: "tamandua:test"
    }

    case send_to_log_analytics(state, [test_event], "TamanduaTest") do
      :ok -> {:reply, {:ok, "Connection successful"}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_info(:flush_batch, state) do
    if length(state.event_buffer) > 0 do
      case flush_events(state.event_buffer, state) do
        :ok ->
          new_stats = update_stats(state.stats, :events_sent, length(state.event_buffer))
          schedule_batch_flush(state.config.batch_interval_ms)
          {:noreply, %{state | event_buffer: [], stats: new_stats}}

        {:error, reason} ->
          new_stats = update_stats(state.stats, :events_failed, length(state.event_buffer))
          new_stats = Map.put(new_stats, :last_error, reason)
          schedule_batch_flush(state.config.batch_interval_ms)
          {:noreply, %{state | stats: new_stats}}
      end
    else
      schedule_batch_flush(state.config.batch_interval_ms)
      {:noreply, state}
    end
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp load_config(opts) do
    app_config = Application.get_env(:tamandua_server, __MODULE__, [])

    %{
      workspace_id: opts[:workspace_id] || app_config[:workspace_id],
      shared_key: opts[:shared_key] || app_config[:shared_key],
      log_type: opts[:log_type] || app_config[:log_type] || "TamanduaEDR",
      tenant_id: opts[:tenant_id] || app_config[:tenant_id],
      client_id: opts[:client_id] || app_config[:client_id],
      client_secret: opts[:client_secret] || app_config[:client_secret],
      subscription_id: opts[:subscription_id] || app_config[:subscription_id],
      resource_group: opts[:resource_group] || app_config[:resource_group],
      workspace_name: opts[:workspace_name] || app_config[:workspace_name],
      batch_size: opts[:batch_size] || app_config[:batch_size] || @default_batch_size,
      batch_interval_ms: opts[:batch_interval_ms] || app_config[:batch_interval_ms] || @default_batch_interval_ms,
      timeout_ms: opts[:timeout_ms] || app_config[:timeout_ms] || @default_timeout_ms,
      verify_ssl: opts[:verify_ssl] != false && app_config[:verify_ssl] != false
    }
  end

  defp schedule_batch_flush(interval) do
    Process.send_after(self(), :flush_batch, interval)
  end

  defp format_log_analytics_event(event, _config) do
    timestamp = get_event_time(event)

    %{
      TimeGenerated: timestamp,
      EventType: event[:event_type] || event["event_type"] || event[:type] || event["type"],
      Severity: event[:severity] || event["severity"],
      AgentId: event[:agent_id] || event["agent_id"],
      Hostname: event[:hostname] || event["hostname"] || get_in(event, [:payload, :hostname]),
      ProcessName: get_in(event, [:payload, :name]) || get_in(event, ["payload", "name"]),
      ProcessPath: get_in(event, [:payload, :path]) || get_in(event, ["payload", "path"]),
      ProcessId: get_in(event, [:payload, :pid]) || get_in(event, ["payload", "pid"]),
      User: get_in(event, [:payload, :user]) || get_in(event, ["payload", "user"]),
      CommandLine: get_in(event, [:payload, :cmdline]) || get_in(event, ["payload", "cmdline"]),
      RemoteIP: get_in(event, [:payload, :remote_ip]) || get_in(event, ["payload", "remote_ip"]),
      RemotePort: get_in(event, [:payload, :remote_port]) || get_in(event, ["payload", "remote_port"]),
      SHA256: get_in(event, [:payload, :sha256]) || get_in(event, ["payload", "sha256"]),
      RawData: Jason.encode!(event[:payload] || event["payload"] || event)
    }
  end

  defp format_security_alert(alert, _config) do
    timestamp = get_alert_time(alert)

    %{
      TimeGenerated: timestamp,
      AlertName: alert[:title] || alert["title"],
      Description: alert[:description] || alert["description"],
      Severity: map_severity_to_sentinel(alert[:severity] || alert["severity"]),
      Status: "New",
      VendorName: "Tamandua",
      ProductName: "Tamandua EDR",
      AlertType: "tamandua_edr_alert",
      ConfidenceLevel: "High",
      CompromisedEntity: alert[:hostname] || alert["hostname"],
      RemediationSteps: "Review in Tamandua EDR console",
      Tactics: Enum.join(alert[:mitre_tactics] || alert["mitre_tactics"] || [], ","),
      Techniques: Enum.join(alert[:mitre_techniques] || alert["mitre_techniques"] || [], ","),
      ExtendedProperties: Jason.encode!(%{
        alert_id: alert[:id] || alert["id"],
        agent_id: alert[:agent_id] || alert["agent_id"],
        threat_score: alert[:threat_score] || alert["threat_score"],
        evidence: alert[:evidence] || alert["evidence"] || %{}
      })
    }
  end

  defp get_event_time(event) do
    timestamp = event[:timestamp] || event["timestamp"] || event[:inserted_at] || event["inserted_at"]

    case timestamp do
      %DateTime{} = dt -> DateTime.to_iso8601(dt)
      %NaiveDateTime{} = ndt -> NaiveDateTime.to_iso8601(ndt) <> "Z"
      ts when is_binary(ts) -> ts
      ts when is_integer(ts) -> DateTime.from_unix!(ts) |> DateTime.to_iso8601()
      _ -> DateTime.utc_now() |> DateTime.to_iso8601()
    end
  end

  defp get_alert_time(alert) do
    timestamp = alert[:created_at] || alert["created_at"] || alert[:inserted_at] || alert["inserted_at"]
    get_event_time(%{timestamp: timestamp})
  end

  defp map_severity_to_sentinel(severity) do
    case severity do
      "critical" -> "High"
      "high" -> "High"
      "medium" -> "Medium"
      "low" -> "Low"
      "info" -> "Informational"
      _ -> "Medium"
    end
  end

  defp flush_events(events, state) do
    send_to_log_analytics(state, events, state.config.log_type)
  end

  defp send_to_log_analytics(state, events, log_type) do
    body = Jason.encode!(events)
    date = format_rfc1123_date()
    content_length = byte_size(body)

    # Build signature
    string_to_sign = "POST\n#{content_length}\napplication/json\nx-ms-date:#{date}\n/api/logs"
    signature = build_signature(state.shared_key, string_to_sign)

    url = "https://#{state.workspace_id}.ods.opinsights.azure.com/api/logs?api-version=#{@log_analytics_api_version}"

    headers = [
      {"Authorization", "SharedKey #{state.workspace_id}:#{signature}"},
      {"Content-Type", "application/json"},
      {"Log-Type", log_type},
      {"x-ms-date", date},
      {"time-generated-field", "TimeGenerated"}
    ]

    options = http_options(state.config)

    case Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %Finch.Response{status: code}} when code in 200..299 ->
        :ok

      {:ok, %Finch.Response{status: code, body: resp_body}} ->
        Logger.error("Log Analytics error: HTTP #{code} - #{resp_body}")
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, reason} ->
        Logger.error("Log Analytics connection error: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("Log Analytics exception: #{inspect(e)}")
      {:error, Exception.message(e)}
  end

  defp build_signature(shared_key, string_to_sign) do
    decoded_key = Base.decode64!(shared_key)
    signature = :crypto.mac(:hmac, :sha256, decoded_key, string_to_sign)
    Base.encode64(signature)
  end

  defp format_rfc1123_date do
    Calendar.strftime(DateTime.utc_now(), "%a, %d %b %Y %H:%M:%S GMT")
  end

  # ============================================================================
  # Azure Management API Functions
  # ============================================================================

  defp ensure_access_token(state) do
    now = DateTime.utc_now()

    if state.access_token && state.token_expires_at &&
       DateTime.compare(state.token_expires_at, now) == :gt do
      {:ok, state}
    else
      case get_azure_access_token(state.config) do
        {:ok, token, expires_at} ->
          {:ok, %{state | access_token: token, token_expires_at: expires_at}}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp get_azure_access_token(config) do
    if config.tenant_id && config.client_id && config.client_secret do
      url = "#{@azure_login_url}/#{config.tenant_id}/oauth2/v2.0/token"

      body = URI.encode_query(%{
        "client_id" => config.client_id,
        "client_secret" => config.client_secret,
        "scope" => "https://management.azure.com/.default",
        "grant_type" => "client_credentials"
      })

      headers = [{"Content-Type", "application/x-www-form-urlencoded"}]
      options = http_options(config)

      case Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
        {:ok, %{status_code: 200, body: resp_body}} ->
          response = Jason.decode!(resp_body)
          token = response["access_token"]
          expires_in = response["expires_in"] || 3600
          expires_at = DateTime.add(DateTime.utc_now(), expires_in - 60, :second)
          {:ok, token, expires_at}

        {:ok, %{status_code: code, body: resp_body}} ->
          {:error, "Failed to get token: HTTP #{code} - #{resp_body}"}

        {:error, %{reason: reason}} ->
          {:error, reason}
      end
    else
      {:error, :azure_credentials_not_configured}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp create_sentinel_incident(incident_data, state) do
    config = state.config
    incident_id = UUID.uuid4()

    url = "#{@management_url}/subscriptions/#{config.subscription_id}" <>
          "/resourceGroups/#{config.resource_group}" <>
          "/providers/Microsoft.OperationalInsights/workspaces/#{config.workspace_name}" <>
          "/providers/Microsoft.SecurityInsights/incidents/#{incident_id}" <>
          "?api-version=#{@sentinel_api_version}"

    body = %{
      properties: %{
        title: incident_data[:title] || incident_data["title"] || "Tamandua Alert",
        description: incident_data[:description] || incident_data["description"],
        severity: map_severity_to_sentinel(incident_data[:severity] || incident_data["severity"]),
        status: "New",
        classification: nil,
        classificationComment: nil,
        classificationReason: nil,
        labels: [%{labelName: "Tamandua", labelType: "User"}],
        owner: nil
      }
    }

    headers = [
      {"Authorization", "Bearer #{state.access_token}"},
      {"Content-Type", "application/json"}
    ]

    options = http_options(config)

    case Finch.build(:put, url, headers, Jason.encode!(body)) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: code}} when code in [200, 201] ->
        {:ok, incident_id}

      {:ok, %{status_code: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp update_sentinel_incident(incident_id, updates, state) do
    config = state.config

    url = "#{@management_url}/subscriptions/#{config.subscription_id}" <>
          "/resourceGroups/#{config.resource_group}" <>
          "/providers/Microsoft.OperationalInsights/workspaces/#{config.workspace_name}" <>
          "/providers/Microsoft.SecurityInsights/incidents/#{incident_id}" <>
          "?api-version=#{@sentinel_api_version}"

    body = %{
      properties: updates
    }

    headers = [
      {"Authorization", "Bearer #{state.access_token}"},
      {"Content-Type", "application/json"}
    ]

    options = http_options(config)

    case Finch.build(:patch, url, headers, Jason.encode!(body)) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: 200}} ->
        :ok

      {:ok, %{status_code: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp fetch_sentinel_incidents(opts, state) do
    config = state.config

    filter = build_incident_filter(opts)

    url = "#{@management_url}/subscriptions/#{config.subscription_id}" <>
          "/resourceGroups/#{config.resource_group}" <>
          "/providers/Microsoft.OperationalInsights/workspaces/#{config.workspace_name}" <>
          "/providers/Microsoft.SecurityInsights/incidents" <>
          "?api-version=#{@sentinel_api_version}#{filter}"

    headers = [
      {"Authorization", "Bearer #{state.access_token}"}
    ]

    options = http_options(config)

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %Finch.Response{status: 200, body: resp_body}} ->
        response = Jason.decode!(resp_body)
        {:ok, response["value"] || []}

      {:ok, %Finch.Response{status: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp fetch_sentinel_incident(incident_id, state) do
    config = state.config

    url = "#{@management_url}/subscriptions/#{config.subscription_id}" <>
          "/resourceGroups/#{config.resource_group}" <>
          "/providers/Microsoft.OperationalInsights/workspaces/#{config.workspace_name}" <>
          "/providers/Microsoft.SecurityInsights/incidents/#{incident_id}" <>
          "?api-version=#{@sentinel_api_version}"

    headers = [
      {"Authorization", "Bearer #{state.access_token}"}
    ]

    options = http_options(config)

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %Finch.Response{status: 200, body: resp_body}} ->
        {:ok, Jason.decode!(resp_body)}

      {:ok, %Finch.Response{status: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp build_incident_filter(opts) do
    filters = []

    filters = if status = opts[:status] do
      ["properties/status eq '#{status}'" | filters]
    else
      filters
    end

    filters = if severity = opts[:severity] do
      ["properties/severity eq '#{severity}'" | filters]
    else
      filters
    end

    if length(filters) > 0 do
      "&$filter=" <> Enum.join(filters, " and ")
    else
      ""
    end
  end

  # ============================================================================
  # Logic Apps (Playbook) Functions
  # ============================================================================

  defp trigger_logic_app(playbook_url, payload, config) do
    headers = [{"Content-Type", "application/json"}]
    options = http_options(config)

    case Finch.build(:post, playbook_url, headers, Jason.encode!(payload)) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: code, body: resp_body}} when code in 200..299 ->
        response = if resp_body != "" do
          case Jason.decode(resp_body) do
            {:ok, data} -> data
            _ -> %{status: "triggered"}
          end
        else
          %{status: "triggered"}
        end
        {:ok, response}

      {:ok, %{status_code: 202}} ->
        {:ok, %{status: "accepted"}}

      {:ok, %{status_code: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp create_incident_from_alert(alert, state) do
    incident_data = %{
      title: alert[:title] || alert["title"],
      description: alert[:description] || alert["description"],
      severity: alert[:severity] || alert["severity"]
    }

    case ensure_access_token(state) do
      {:ok, new_state} ->
        create_sentinel_incident(incident_data, new_state)

      {:error, reason} ->
        Logger.warning("Failed to create Sentinel incident: #{inspect(reason)}")
    end
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

  defp update_stats(stats, key, increment) do
    stats
    |> Map.update(key, increment, &(&1 + increment))
    |> Map.put(:last_send, DateTime.utc_now())
  end
end
