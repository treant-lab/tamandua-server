defmodule TamanduaServer.Integrations.CaseManagement.ServiceNowSecOps do
  @moduledoc """
  ServiceNow Security Operations Integration

  Provides integration with ServiceNow Security Operations (SecOps):
  - Security Incident Response (SIR) cases
  - Threat Intelligence integration
  - Vulnerability Response
  - Configuration Compliance
  - Security Incident automation

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.CaseManagement.ServiceNowSecOps,
        instance: "your-instance",
        username: "your-username",
        password: "your-password",
        verify_ssl: true

  """

  use GenServer
  require Logger

  @default_timeout_ms 30_000

  # ServiceNow SecOps tables
  @sir_table "sn_si_incident"
  @task_table "sn_si_task"
  @observable_table "sn_ti_observable"
  @threat_intel_table "sn_ti_indicator"

  defstruct [:config, :base_url, :auth_header, :stats]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Create a Security Incident Response case.
  """
  @spec create_security_incident(map()) :: {:ok, String.t()} | {:error, term()}
  def create_security_incident(incident_data) do
    GenServer.call(__MODULE__, {:create_security_incident, incident_data}, 30_000)
  end

  @doc """
  Update a security incident.
  """
  @spec update_security_incident(String.t(), map()) :: :ok | {:error, term()}
  def update_security_incident(incident_id, updates) do
    GenServer.call(__MODULE__, {:update_security_incident, incident_id, updates}, 30_000)
  end

  @doc """
  Get security incident details.
  """
  @spec get_security_incident(String.t()) :: {:ok, map()} | {:error, term()}
  def get_security_incident(incident_id) do
    GenServer.call(__MODULE__, {:get_security_incident, incident_id}, 30_000)
  end

  @doc """
  Create a task for a security incident.
  """
  @spec create_task(String.t(), map()) :: {:ok, String.t()} | {:error, term()}
  def create_task(incident_id, task_data) do
    GenServer.call(__MODULE__, {:create_task, incident_id, task_data}, 30_000)
  end

  @doc """
  Add an observable to a security incident.
  """
  @spec add_observable(String.t(), map()) :: {:ok, String.t()} | {:error, term()}
  def add_observable(incident_id, observable) do
    GenServer.call(__MODULE__, {:add_observable, incident_id, observable}, 30_000)
  end

  @doc """
  Create a threat intelligence indicator.
  """
  @spec create_indicator(map()) :: {:ok, String.t()} | {:error, term()}
  def create_indicator(indicator_data) do
    GenServer.call(__MODULE__, {:create_indicator, indicator_data}, 30_000)
  end

  @doc """
  Search security incidents.
  """
  @spec search_incidents(map()) :: {:ok, [map()]} | {:error, term()}
  def search_incidents(query) do
    GenServer.call(__MODULE__, {:search_incidents, query}, 30_000)
  end

  @doc """
  Close a security incident.
  """
  @spec close_incident(String.t(), map()) :: :ok | {:error, term()}
  def close_incident(incident_id, resolution) do
    GenServer.call(__MODULE__, {:close_incident, incident_id, resolution}, 30_000)
  end

  @doc """
  Escalate to major incident.
  """
  @spec escalate_to_major(String.t()) :: :ok | {:error, term()}
  def escalate_to_major(incident_id) do
    GenServer.call(__MODULE__, {:escalate_to_major, incident_id}, 30_000)
  end

  @spec test_connection() :: {:ok, String.t()} | {:error, term()}
  def test_connection do
    GenServer.call(__MODULE__, :test_connection, 30_000)
  end

  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting ServiceNow SecOps Integration")
    config = load_config(opts)

    state = %__MODULE__{
      config: config,
      base_url: build_base_url(config),
      auth_header: build_auth_header(config),
      stats: %{
        incidents_created: 0,
        tasks_created: 0,
        observables_added: 0,
        indicators_created: 0,
        errors: 0,
        last_activity: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:create_security_incident, incident_data}, _from, state) do
    body = format_security_incident(incident_data)

    case post_request(state, "/api/now/table/#{@sir_table}", body) do
      {:ok, response} ->
        incident_id = response["result"]["sys_id"]
        new_stats = update_stat(state.stats, :incidents_created)
        Logger.info("Created ServiceNow Security Incident: #{incident_id}")
        {:reply, {:ok, incident_id}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:update_security_incident, incident_id, updates}, _from, state) do
    body = format_incident_update(updates)

    case patch_request(state, "/api/now/table/#{@sir_table}/#{incident_id}", body) do
      {:ok, _} -> {:reply, :ok, state}
      error -> {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:get_security_incident, incident_id}, _from, state) do
    case get_request(state, "/api/now/table/#{@sir_table}/#{incident_id}") do
      {:ok, response} ->
        {:reply, {:ok, format_incident_response(response["result"])}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:create_task, incident_id, task_data}, _from, state) do
    body = format_task(incident_id, task_data)

    case post_request(state, "/api/now/table/#{@task_table}", body) do
      {:ok, response} ->
        task_id = response["result"]["sys_id"]
        new_stats = update_stat(state.stats, :tasks_created)
        {:reply, {:ok, task_id}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:add_observable, incident_id, observable}, _from, state) do
    body = format_observable(incident_id, observable)

    case post_request(state, "/api/now/table/#{@observable_table}", body) do
      {:ok, response} ->
        obs_id = response["result"]["sys_id"]
        new_stats = update_stat(state.stats, :observables_added)
        {:reply, {:ok, obs_id}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:create_indicator, indicator_data}, _from, state) do
    body = format_indicator(indicator_data)

    case post_request(state, "/api/now/table/#{@threat_intel_table}", body) do
      {:ok, response} ->
        indicator_id = response["result"]["sys_id"]
        new_stats = update_stat(state.stats, :indicators_created)
        {:reply, {:ok, indicator_id}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:search_incidents, query}, _from, state) do
    params = build_query_params(query)

    case get_request(state, "/api/now/table/#{@sir_table}#{params}") do
      {:ok, response} ->
        incidents = Enum.map(response["result"] || [], &format_incident_response/1)
        {:reply, {:ok, incidents}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:close_incident, incident_id, resolution}, _from, state) do
    body = %{
      state: "3",  # Closed
      close_code: map_close_code(resolution[:code] || resolution["code"]),
      close_notes: resolution[:notes] || resolution["notes"]
    }

    case patch_request(state, "/api/now/table/#{@sir_table}/#{incident_id}", body) do
      {:ok, _} -> {:reply, :ok, state}
      error -> {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:escalate_to_major, incident_id}, _from, state) do
    body = %{
      major_security_incident: "true",
      priority: "1"
    }

    case patch_request(state, "/api/now/table/#{@sir_table}/#{incident_id}", body) do
      {:ok, _} -> {:reply, :ok, state}
      error -> {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call(:test_connection, _from, state) do
    case get_request(state, "/api/now/table/sys_user?sysparm_limit=1") do
      {:ok, _} -> {:reply, {:ok, "Connected to ServiceNow SecOps"}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
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

  defp format_security_incident(data) do
    %{
      short_description: data[:title] || data["title"],
      description: data[:description] || data["description"],
      priority: map_priority(data[:severity] || data["severity"]),
      category: data[:category] || "Malware",
      subcategory: data[:subcategory] || "Other",
      contact_type: "Self-service",
      state: "1",  # New
      u_tamandua_alert_id: data[:id] || data["id"],
      u_source_ip: data[:source_ip] || data["source_ip"],
      u_destination_ip: data[:destination_ip] || data["destination_ip"],
      u_affected_ci: data[:hostname] || data["hostname"],
      u_attack_vector: Enum.join(data[:mitre_techniques] || data["mitre_techniques"] || [], ", ")
    }
  end

  defp format_incident_update(updates) do
    result = %{}

    result = if state = updates[:state] || updates["state"] do
      Map.put(result, :state, map_state(state))
    else
      result
    end

    result = if priority = updates[:priority] || updates["priority"] do
      Map.put(result, :priority, map_priority(priority))
    else
      result
    end

    result = if assignee = updates[:assignee] || updates["assignee"] do
      Map.put(result, :assigned_to, assignee)
    else
      result
    end

    result
  end

  defp format_incident_response(result) do
    %{
      id: result["sys_id"],
      number: result["number"],
      title: result["short_description"],
      description: result["description"],
      state: result["state"],
      priority: result["priority"],
      category: result["category"],
      assigned_to: result["assigned_to"],
      created_at: result["sys_created_on"],
      updated_at: result["sys_updated_on"],
      affected_ci: result["u_affected_ci"]
    }
  end

  defp format_task(incident_id, data) do
    %{
      security_incident: incident_id,
      short_description: data[:title] || data["title"],
      description: data[:description] || data["description"],
      state: "1",  # Open
      assigned_to: data[:assignee] || data["assignee"],
      due_date: data[:due_date] || data["due_date"]
    }
  end

  defp format_observable(incident_id, observable) do
    %{
      security_incident: incident_id,
      type: map_observable_type(observable[:type] || observable["type"]),
      value: observable[:value] || observable["value"],
      source: "Tamandua EDR",
      notes: observable[:description] || observable["description"]
    }
  end

  defp format_indicator(data) do
    %{
      type: map_indicator_type(data[:type] || data["type"]),
      value: data[:value] || data["value"],
      source: "Tamandua EDR",
      threat_score: data[:threat_score] || data["threat_score"] || 50,
      status: "Active",
      notes: data[:description] || data["description"]
    }
  end

  defp map_priority(severity) do
    case severity do
      "critical" -> "1"
      "high" -> "2"
      "medium" -> "3"
      "low" -> "4"
      _ -> "3"
    end
  end

  defp map_state(state) do
    case state do
      "new" -> "1"
      "in_progress" -> "2"
      "closed" -> "3"
      "resolved" -> "3"
      _ -> "1"
    end
  end

  defp map_close_code(code) do
    case code do
      "resolved" -> "Resolved"
      "false_positive" -> "False Positive"
      "duplicate" -> "Duplicate"
      "no_action" -> "No Action Required"
      _ -> "Resolved"
    end
  end

  defp map_observable_type(type) do
    case type do
      t when t in ["ip", :ip] -> "IP Address"
      t when t in ["domain", :domain] -> "Domain"
      t when t in ["url", :url] -> "URL"
      t when t in ["hash", :hash] -> "File Hash"
      t when t in ["email", :email] -> "Email"
      _ -> "Other"
    end
  end

  defp map_indicator_type(type) do
    case type do
      t when t in ["ip", :ip] -> "ip_address"
      t when t in ["domain", :domain] -> "domain"
      t when t in ["url", :url] -> "url"
      t when t in ["hash", :hash] -> "file_hash"
      t when t in ["email", :email] -> "email"
      _ -> "other"
    end
  end

  defp build_query_params(query) do
    params = []

    params = if status = query[:status] || query["status"] do
      ["sysparm_query=state=#{map_state(status)}" | params]
    else
      params
    end

    params = if limit = query[:limit] || query["limit"] do
      ["sysparm_limit=#{limit}" | params]
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
    url = "#{state.base_url}#{endpoint}"

    headers = [
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    headers = if state.auth_header do
      [{"Authorization", state.auth_header} | headers]
    else
      headers
    end

    options = [
      timeout: state.config.timeout_ms,
      recv_timeout: state.config.timeout_ms
    ]

    options = if state.config.verify_ssl do
      options
    else
      Keyword.put(options, :ssl, verify: :verify_none)
    end

    timeout = Keyword.get(options, :recv_timeout, 30_000)

    result = case method do
      :get -> Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: timeout)
      :post -> Finch.build(:post, url, headers, Jason.encode!(body)) |> Finch.request(TamanduaServer.Finch, receive_timeout: timeout)
      :patch -> Finch.build(:patch, url, headers, Jason.encode!(body)) |> Finch.request(TamanduaServer.Finch, receive_timeout: timeout)
    end

    case result do
      {:ok, %{status_code: code, body: resp_body}} when code in 200..299 ->
        {:ok, Jason.decode!(resp_body)}

      {:ok, %{status_code: code, body: resp_body}} ->
        Logger.error("ServiceNow SecOps API error: HTTP #{code} - #{resp_body}")
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        Logger.error("ServiceNow SecOps connection error: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("ServiceNow SecOps exception: #{inspect(e)}")
      {:error, Exception.message(e)}
  end

  defp update_stat(stats, key) do
    stats |> Map.update(key, 1, &(&1 + 1)) |> Map.put(:last_activity, DateTime.utc_now())
  end

  defp update_error_stat(state) do
    new_stats = Map.update(state.stats, :errors, 1, &(&1 + 1))
    %{state | stats: new_stats}
  end
end
