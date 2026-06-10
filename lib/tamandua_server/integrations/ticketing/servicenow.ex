defmodule TamanduaServer.Integrations.Ticketing.ServiceNow do
  @moduledoc """
  ServiceNow Integration

  Provides integration with ServiceNow ITSM:
  - Security incident creation and management
  - Change request creation
  - CMDB integration for asset correlation
  - Knowledge base article creation

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.Ticketing.ServiceNow,
        instance: "your-instance",  # or full URL
        username: "your-username",
        password: "your-password",
        # or OAuth:
        client_id: "your-client-id",
        client_secret: "your-client-secret",
        table: "sn_si_incident",  # Security Incident table
        verify_ssl: true

  """

  use GenServer
  require Logger

  @default_timeout_ms 30_000

  # ServiceNow tables
  @security_incident_table "sn_si_incident"
  @incident_table "incident"
  @change_request_table "change_request"
  @cmdb_ci_table "cmdb_ci"
  @kb_article_table "kb_knowledge"

  defstruct [
    :config,
    :base_url,
    :auth_header,
    :access_token,
    :token_expires_at,
    :stats
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Create a security incident.
  """
  @spec create_incident(map()) :: {:ok, String.t()} | {:error, term()}
  def create_incident(incident_data) do
    GenServer.call(__MODULE__, {:create_incident, incident_data}, 30_000)
  end

  @doc """
  Update an existing incident.
  """
  @spec update_incident(String.t(), map()) :: :ok | {:error, term()}
  def update_incident(incident_id, updates) do
    GenServer.call(__MODULE__, {:update_incident, incident_id, updates}, 30_000)
  end

  @doc """
  Get incident details.
  """
  @spec get_incident(String.t()) :: {:ok, map()} | {:error, term()}
  def get_incident(incident_id) do
    GenServer.call(__MODULE__, {:get_incident, incident_id}, 30_000)
  end

  @doc """
  Add a work note to an incident.
  """
  @spec add_work_note(String.t(), String.t()) :: :ok | {:error, term()}
  def add_work_note(incident_id, note) do
    GenServer.call(__MODULE__, {:add_work_note, incident_id, note}, 30_000)
  end

  @doc """
  Close an incident.
  """
  @spec close_incident(String.t(), map()) :: :ok | {:error, term()}
  def close_incident(incident_id, resolution) do
    GenServer.call(__MODULE__, {:close_incident, incident_id, resolution}, 30_000)
  end

  @doc """
  Search for incidents.
  """
  @spec search_incidents(map()) :: {:ok, [map()]} | {:error, term()}
  def search_incidents(query) do
    GenServer.call(__MODULE__, {:search_incidents, query}, 30_000)
  end

  @doc """
  Create a change request.
  """
  @spec create_change_request(map()) :: {:ok, String.t()} | {:error, term()}
  def create_change_request(change_data) do
    GenServer.call(__MODULE__, {:create_change_request, change_data}, 30_000)
  end

  @doc """
  Lookup CI (Configuration Item) in CMDB.
  """
  @spec lookup_ci(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_ci(hostname_or_ip) do
    GenServer.call(__MODULE__, {:lookup_ci, hostname_or_ip}, 30_000)
  end

  @doc """
  Test connection to ServiceNow.
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
    Logger.info("Starting ServiceNow Integration")

    config = load_config(opts)
    auth_header = build_auth_header(config)

    state = %__MODULE__{
      config: config,
      base_url: build_base_url(config),
      auth_header: auth_header,
      access_token: nil,
      token_expires_at: nil,
      stats: %{
        incidents_created: 0,
        incidents_updated: 0,
        change_requests_created: 0,
        last_activity: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:create_incident, incident_data}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        table = incident_data[:table] || state.config.table || @security_incident_table
        record = format_incident(incident_data)

        case post_request(new_state, "/api/now/table/#{table}", record) do
          {:ok, response} ->
            incident_id = response["result"]["sys_id"]
            number = response["result"]["number"]
            new_stats = update_stat(new_state.stats, :incidents_created)
            Logger.info("Created ServiceNow incident: #{number}")
            {:reply, {:ok, incident_id}, %{new_state | stats: new_stats}}

          error ->
            {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:update_incident, incident_id, updates}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        table = updates[:table] || state.config.table || @security_incident_table

        case patch_request(new_state, "/api/now/table/#{table}/#{incident_id}", updates) do
          {:ok, _} ->
            new_stats = update_stat(new_state.stats, :incidents_updated)
            {:reply, :ok, %{new_state | stats: new_stats}}

          error ->
            {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_incident, incident_id}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        table = state.config.table || @security_incident_table

        case get_request(new_state, "/api/now/table/#{table}/#{incident_id}") do
          {:ok, response} ->
            {:reply, {:ok, response["result"]}, new_state}

          error ->
            {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:add_work_note, incident_id, note}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        table = state.config.table || @security_incident_table
        updates = %{work_notes: note}

        case patch_request(new_state, "/api/now/table/#{table}/#{incident_id}", updates) do
          {:ok, _} -> {:reply, :ok, new_state}
          error -> {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:close_incident, incident_id, resolution}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        table = state.config.table || @security_incident_table
        updates = %{
          state: 6,  # Resolved
          close_code: resolution[:close_code] || "Solved (Work Around)",
          close_notes: resolution[:close_notes] || resolution[:notes] || "Resolved via Tamandua EDR"
        }

        case patch_request(new_state, "/api/now/table/#{table}/#{incident_id}", updates) do
          {:ok, _} -> {:reply, :ok, new_state}
          error -> {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:search_incidents, query}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        table = query[:table] || state.config.table || @security_incident_table
        params = build_query_params(query)

        case get_request(new_state, "/api/now/table/#{table}#{params}") do
          {:ok, response} ->
            {:reply, {:ok, response["result"] || []}, new_state}

          error ->
            {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:create_change_request, change_data}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        record = format_change_request(change_data)

        case post_request(new_state, "/api/now/table/#{@change_request_table}", record) do
          {:ok, response} ->
            change_id = response["result"]["sys_id"]
            new_stats = update_stat(new_state.stats, :change_requests_created)
            {:reply, {:ok, change_id}, %{new_state | stats: new_stats}}

          error ->
            {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:lookup_ci, hostname_or_ip}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        query = "sysparm_query=name=#{URI.encode(hostname_or_ip)}^ORip_address=#{URI.encode(hostname_or_ip)}"

        case get_request(new_state, "/api/now/table/#{@cmdb_ci_table}?#{query}") do
          {:ok, %{"result" => [ci | _]}} ->
            {:reply, {:ok, ci}, new_state}

          {:ok, %{"result" => []}} ->
            {:reply, {:error, :not_found}, new_state}

          error ->
            {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:test_connection, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        case get_request(new_state, "/api/now/table/sys_user?sysparm_limit=1") do
          {:ok, _} ->
            {:reply, {:ok, "Connected to ServiceNow"}, new_state}

          {:error, reason} ->
            {:reply, {:error, reason}, new_state}
        end

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
      instance: opts[:instance] || app_config[:instance],
      username: opts[:username] || app_config[:username],
      password: opts[:password] || app_config[:password],
      client_id: opts[:client_id] || app_config[:client_id],
      client_secret: opts[:client_secret] || app_config[:client_secret],
      table: opts[:table] || app_config[:table] || @security_incident_table,
      assignment_group: opts[:assignment_group] || app_config[:assignment_group],
      caller_id: opts[:caller_id] || app_config[:caller_id],
      timeout_ms: opts[:timeout_ms] || app_config[:timeout_ms] || @default_timeout_ms,
      verify_ssl: opts[:verify_ssl] != false && app_config[:verify_ssl] != false
    }
  end

  defp build_base_url(config) do
    instance = config.instance

    if String.starts_with?(instance || "", "http") do
      instance
    else
      "https://#{instance}.service-now.com"
    end
  end

  defp build_auth_header(config) do
    if config.username && config.password do
      auth = Base.encode64("#{config.username}:#{config.password}")
      "Basic #{auth}"
    else
      nil
    end
  end

  defp ensure_auth(state) do
    cond do
      # Basic auth is always valid
      state.auth_header ->
        {:ok, state}

      # OAuth token still valid
      state.access_token && state.token_expires_at &&
          DateTime.compare(state.token_expires_at, DateTime.utc_now()) == :gt ->
        {:ok, state}

      # Need to get OAuth token
      state.config.client_id && state.config.client_secret ->
        get_oauth_token(state)

      true ->
        {:error, :no_auth_configured}
    end
  end

  defp get_oauth_token(state) do
    url = "#{state.base_url}/oauth_token.do"

    body = URI.encode_query(%{
      "grant_type" => "client_credentials",
      "client_id" => state.config.client_id,
      "client_secret" => state.config.client_secret
    })

    headers = [{"content-type", "application/x-www-form-urlencoded"}]

    request = Finch.build(:post, url, headers, body)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: state.config.timeout_ms) do
      {:ok, %Finch.Response{status: 200, body: resp_body}} ->
        response = Jason.decode!(resp_body)
        token = response["access_token"]
        expires_in = response["expires_in"] || 3600
        expires_at = DateTime.add(DateTime.utc_now(), expires_in - 60, :second)
        {:ok, %{state | access_token: token, token_expires_at: expires_at}}

      {:ok, %Finch.Response{status: code, body: resp_body}} ->
        {:error, "OAuth failed: HTTP #{code} - #{resp_body}"}

      {:error, reason} ->
        {:error, inspect(reason)}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp format_incident(data) do
    record = %{
      short_description: data[:title] || data["title"],
      description: data[:description] || data["description"],
      impact: map_severity_to_impact(data[:severity] || data["severity"]),
      urgency: map_severity_to_urgency(data[:severity] || data["severity"]),
      category: "Security",
      subcategory: data[:subcategory] || "Malware",
      caller_id: data[:caller_id]
    }

    # Add Tamandua-specific fields
    record = Map.merge(record, %{
      u_tamandua_alert_id: data[:id] || data["id"],
      u_hostname: data[:hostname] || data["hostname"],
      u_agent_id: data[:agent_id] || data["agent_id"],
      u_mitre_tactics: Enum.join(data[:mitre_tactics] || data["mitre_tactics"] || [], ", "),
      u_mitre_techniques: Enum.join(data[:mitre_techniques] || data["mitre_techniques"] || [], ", "),
      u_threat_score: data[:threat_score] || data["threat_score"]
    })

    # Remove nil values
    record
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp format_change_request(data) do
    %{
      short_description: data[:title] || data["title"],
      description: data[:description] || data["description"],
      type: data[:type] || "Standard",
      category: data[:category] || "Security",
      risk: data[:risk] || "Low",
      impact: data[:impact] || "Low",
      reason: data[:reason] || "Security response action from Tamandua EDR",
      u_tamandua_alert_id: data[:alert_id] || data["alert_id"]
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp map_severity_to_impact(severity) do
    case severity do
      "critical" -> 1
      "high" -> 2
      "medium" -> 2
      "low" -> 3
      _ -> 2
    end
  end

  defp map_severity_to_urgency(severity) do
    case severity do
      "critical" -> 1
      "high" -> 2
      "medium" -> 2
      "low" -> 3
      _ -> 2
    end
  end

  defp build_query_params(query) do
    params = []

    params = if query[:sysparm_query] || query["sysparm_query"] do
      ["sysparm_query=#{URI.encode(query[:sysparm_query] || query["sysparm_query"])}" | params]
    else
      params
    end

    params = if limit = query[:limit] || query["limit"] do
      ["sysparm_limit=#{limit}" | params]
    else
      params
    end

    params = if offset = query[:offset] || query["offset"] do
      ["sysparm_offset=#{offset}" | params]
    else
      params
    end

    params = if fields = query[:fields] || query["fields"] do
      ["sysparm_fields=#{Enum.join(fields, ",")}" | params]
    else
      params
    end

    if length(params) > 0, do: "?" <> Enum.join(params, "&"), else: ""
  end

  defp get_request(state, endpoint) do
    make_request(:get, state, endpoint, nil)
  end

  defp post_request(state, endpoint, body) do
    make_request(:post, state, endpoint, body)
  end

  defp patch_request(state, endpoint, body) do
    make_request(:patch, state, endpoint, body)
  end

  defp make_request(method, state, endpoint, body) do
    alias TamanduaServer.Integrations.IntegrationLog

    url = "#{state.base_url}#{endpoint}"

    headers = [
      {"content-type", "application/json"},
      {"accept", "application/json"}
    ]

    headers = cond do
      state.access_token ->
        [{"authorization", "Bearer #{state.access_token}"} | headers]

      state.auth_header ->
        [{"authorization", state.auth_header} | headers]

      true ->
        headers
    end

    encoded_body = if body, do: Jason.encode!(body), else: nil

    request = case method do
      :get -> Finch.build(:get, url, headers)
      :post -> Finch.build(:post, url, headers, encoded_body)
      :patch -> Finch.build(:patch, url, headers, encoded_body)
      :put -> Finch.build(:put, url, headers, encoded_body)
    end

    action = "#{method}:#{endpoint}"

    IntegrationLog.log_api_call("servicenow", action, body, fn ->
      case Finch.request(request, TamanduaServer.Finch, receive_timeout: state.config.timeout_ms) do
        {:ok, %Finch.Response{status: code, body: resp_body}} when code in 200..299 ->
          if resp_body == "" do
            {:ok, %{}}
          else
            {:ok, Jason.decode!(resp_body)}
          end

        {:ok, %Finch.Response{status: code, body: resp_body}} ->
          Logger.error("ServiceNow API error: HTTP #{code} - #{resp_body}")
          {:error, "HTTP #{code}: #{resp_body}"}

        {:error, %Mint.TransportError{reason: reason}} ->
          Logger.error("ServiceNow connection error: #{inspect(reason)}")
          {:error, inspect(reason)}

        {:error, reason} ->
          Logger.error("ServiceNow connection error: #{inspect(reason)}")
          {:error, inspect(reason)}
      end
    end)
  rescue
    e ->
      Logger.error("ServiceNow exception: #{inspect(e)}")
      {:error, Exception.message(e)}
  end

  defp update_stat(stats, key) do
    stats
    |> Map.update(key, 1, &(&1 + 1))
    |> Map.put(:last_activity, DateTime.utc_now())
  end

  # ============================================================================
  # Alert Integration Functions
  # ============================================================================

  @doc """
  Create a ServiceNow security incident from a Tamandua alert.

  Maps alert fields to ServiceNow incident fields:
  - title -> short_description
  - description -> description
  - severity -> impact/urgency (critical->1/1, high->2/2, medium->2/2, low->3/3)
  - hostname -> u_hostname (and cmdb_ci if CI lookup succeeds)
  - mitre_tactics/techniques -> u_mitre_tactics, u_mitre_techniques

  ## Parameters

  - `alert` - Alert map with id, title, severity, etc.
  - `config` - Configuration map with table, etc.

  ## Returns

  `{:ok, sys_id}` on success, `{:error, reason}` on failure.
  """
  @spec create_incident_from_alert(map(), map()) :: {:ok, String.t()} | {:error, term()}
  def create_incident_from_alert(alert, config) do
    hostname = alert[:hostname] || alert["hostname"]

    # Attempt CMDB lookup for asset correlation
    ci_sys_id = case lookup_ci(hostname) do
      {:ok, %{"sys_id" => sys_id}} -> sys_id
      _ -> nil
    end

    incident_data = %{
      title: "[Tamandua] #{alert[:title] || alert["title"] || "Alert"}",
      description: alert[:description] || alert["description"],
      severity: alert[:severity] || alert["severity"],
      hostname: hostname,
      agent_id: alert[:agent_id] || alert["agent_id"],
      mitre_tactics: alert[:mitre_tactics] || alert["mitre_tactics"] || [],
      mitre_techniques: alert[:mitre_techniques] || alert["mitre_techniques"] || [],
      threat_score: alert[:threat_score] || alert["threat_score"],
      id: alert[:id] || alert["id"],
      # ServiceNow-specific
      table: config[:table] || config["table"] || @security_incident_table,
      cmdb_ci: ci_sys_id
    }

    create_incident(incident_data)
  end

  @doc """
  Search for existing ServiceNow incident for an alert (deduplication).

  Uses sysparm_query to find incidents with matching u_tamandua_alert_id.

  ## Parameters

  - `alert_id` - The alert ID to search for
  - `config` - Configuration map with table

  ## Returns

  - `{:ok, sys_id}` if found
  - `{:ok, nil}` if not found
  - `{:error, reason}` on failure
  """
  @spec find_existing_incident(String.t(), map()) :: {:ok, String.t() | nil} | {:error, term()}
  def find_existing_incident(alert_id, config) do
    table = config[:table] || config["table"] || @security_incident_table
    query = %{
      table: table,
      sysparm_query: "u_tamandua_alert_id=#{alert_id}",
      limit: 1,
      fields: ["sys_id", "number"]
    }

    case search_incidents(query) do
      {:ok, [%{"sys_id" => sys_id} | _]} -> {:ok, sys_id}
      {:ok, []} -> {:ok, nil}
      error -> error
    end
  end

  @doc """
  Sync Tamandua alert status changes to ServiceNow incident.

  Maps Tamandua statuses to ServiceNow incident states:
  - resolved -> 6 (Resolved)
  - closed -> 7 (Closed)
  - in_progress -> 2 (In Progress)
  - other -> 1 (New)

  ## Parameters

  - `incident_id` - ServiceNow incident sys_id
  - `updates` - Map with :status and optional fields

  ## Returns

  `:ok` on success, `{:error, reason}` on failure.
  """
  @spec sync_alert_status(String.t(), map()) :: :ok | {:error, term()}
  def sync_alert_status(incident_id, %{status: status} = _updates) do
    snow_state = case status do
      "resolved" -> 6  # Resolved
      "closed" -> 7    # Closed
      "in_progress" -> 2  # In Progress
      "acknowledged" -> 2  # In Progress
      _ -> 1  # New
    end

    update_incident(incident_id, %{
      state: snow_state,
      work_notes: "Status updated from Tamandua EDR: #{status}"
    })
  end

  def sync_alert_status(incident_id, updates) when is_map(updates) do
    # If no status key, just update with provided fields
    update_incident(incident_id, updates)
  end
end
