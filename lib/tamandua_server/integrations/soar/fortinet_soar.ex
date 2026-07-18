defmodule TamanduaServer.Integrations.SOAR.FortiSOAR do
  @moduledoc """
  FortiSOAR Integration

  Provides bi-directional integration with Fortinet FortiSOAR platform:
  - Push alerts to FortiSOAR as alerts/incidents
  - Pull actions from FortiSOAR (playbook actions)
  - Sync investigation status
  - Artifact/indicator sharing
  - Playbook triggering and monitoring
  - Module record management

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.SOAR.FortiSOAR,
        url: "https://fortisoar.example.com",
        username: "your-username",
        password: "your-password",
        # or API token:
        api_token: "your-api-token",
        verify_ssl: true,
        poll_interval_ms: 30_000

  ## Bi-directional Sync

  The integration supports:
  1. Push: Alerts -> FortiSOAR Alerts/Incidents
  2. Pull: FortiSOAR Actions -> Tamandua Response Commands
  3. Status Sync: Investigation state synchronization
  4. Artifacts: Share IOCs, indicators, and evidence

  """

  use GenServer
  require Logger

  @behaviour TamanduaServer.Integrations.SOAR.Behaviour

  @default_timeout_ms 30_000
  @default_poll_interval_ms 30_000

  # FortiSOAR API endpoints
  @alerts_endpoint "/api/3/alerts"
  @incidents_endpoint "/api/3/incidents"
  @indicators_endpoint "/api/3/indicators"
  @playbooks_endpoint "/api/3/playbooks"
  @execute_endpoint "/api/3/manual_trigger"

  defstruct [
    :config,
    :url,
    :auth_header,
    :access_token,
    :token_expires_at,
    :stats,
    :poll_timer
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

  # Bi-directional sync specific functions

  @doc """
  Push an alert to FortiSOAR.
  """
  @spec push_alert(map()) :: {:ok, String.t()} | {:error, term()}
  def push_alert(alert) do
    GenServer.call(__MODULE__, {:push_alert, alert}, 30_000)
  end

  @doc """
  Create an alert in FortiSOAR.
  """
  @spec create_alert(map()) :: {:ok, String.t()} | {:error, term()}
  def create_alert(alert_data) do
    GenServer.call(__MODULE__, {:create_alert, alert_data}, 30_000)
  end

  @doc """
  Pull pending actions from FortiSOAR.
  """
  @spec pull_actions() :: {:ok, [map()]} | {:error, term()}
  def pull_actions do
    GenServer.call(__MODULE__, :pull_actions, 30_000)
  end

  @doc """
  Sync investigation status with FortiSOAR.
  """
  @spec sync_investigation(String.t(), map()) :: :ok | {:error, term()}
  def sync_investigation(record_id, status) do
    GenServer.call(__MODULE__, {:sync_investigation, record_id, status}, 30_000)
  end

  @doc """
  Add an indicator to FortiSOAR.
  """
  @spec add_indicator(map()) :: {:ok, String.t()} | {:error, term()}
  def add_indicator(indicator) do
    GenServer.call(__MODULE__, {:add_indicator, indicator}, 30_000)
  end

  @doc """
  Share indicators with FortiSOAR.
  """
  @spec share_indicators([map()]) :: {:ok, [String.t()]} | {:error, term()}
  def share_indicators(indicators) do
    GenServer.call(__MODULE__, {:share_indicators, indicators}, 30_000)
  end

  @doc """
  Get alert details.
  """
  @spec get_alert(String.t()) :: {:ok, map()} | {:error, term()}
  def get_alert(alert_id) do
    GenServer.call(__MODULE__, {:get_alert, alert_id}, 30_000)
  end

  @doc """
  Link alert to incident.
  """
  @spec link_alert_to_incident(String.t(), String.t()) :: :ok | {:error, term()}
  def link_alert_to_incident(alert_id, incident_id) do
    GenServer.call(__MODULE__, {:link_alert_to_incident, alert_id, incident_id}, 30_000)
  end

  @doc """
  Execute a manual action.
  """
  @spec execute_action(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def execute_action(action_name, params) do
    GenServer.call(__MODULE__, {:execute_action, action_name, params}, 60_000)
  end

  @doc """
  Search records in a module.
  """
  @spec search_records(String.t(), map()) :: {:ok, [map()]} | {:error, term()}
  def search_records(module_name, query) do
    GenServer.call(__MODULE__, {:search_records, module_name, query}, 30_000)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting FortiSOAR Integration")

    config = load_config(opts)

    state = %__MODULE__{
      config: config,
      url: config.url,
      auth_header: nil,
      access_token: nil,
      token_expires_at: nil,
      stats: %{
        alerts_created: 0,
        incidents_created: 0,
        indicators_added: 0,
        playbooks_triggered: 0,
        sync_operations: 0,
        last_activity: nil,
        errors: 0
      },
      poll_timer: nil
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:trigger_playbook, playbook_name, params}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        # Find playbook by name first
        case find_playbook(new_state, playbook_name) do
          {:ok, playbook} ->
            body = %{
              playbook: playbook["@id"],
              records: params[:records] || params["records"] || [],
              manual_input: params[:inputs] || params["inputs"] || %{}
            }

            case post_request(new_state, @execute_endpoint, body) do
              {:ok, response} ->
                new_stats = update_stat(new_state.stats, :playbooks_triggered)
                run_id = response["@id"] || response["id"] || generate_id()
                {:reply, {:ok, run_id}, %{new_state | stats: new_stats}}

              error ->
                {:reply, error, update_error_stat(new_state)}
            end

          error ->
            {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_playbook_status, run_id}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        case get_request(new_state, "/api/3/workflow_instances/#{run_id}") do
          {:ok, response} ->
            status = %{
              id: response["@id"] || response["id"],
              playbook_id: response["playbook"],
              status: response["status"],
              started_at: response["createDate"],
              completed_at: response["modifyDate"],
              result: response["result"]
            }
            {:reply, {:ok, status}, new_state}

          error ->
            {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:create_incident, incident_data}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        incident = format_incident(incident_data)

        case post_request(new_state, @incidents_endpoint, incident) do
          {:ok, response} ->
            incident_id = response["@id"] || response["id"] || response["uuid"]
            new_stats = update_stat(new_state.stats, :incidents_created)
            Logger.info("Created FortiSOAR incident: #{incident_id}")
            {:reply, {:ok, incident_id}, %{new_state | stats: new_stats}}

          error ->
            {:reply, error, update_error_stat(new_state)}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:update_incident, incident_id, updates}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        body = format_incident_update(updates)

        case put_request(new_state, "#{@incidents_endpoint}/#{incident_id}", body) do
          {:ok, _} ->
            new_stats = update_stat(new_state.stats, :sync_operations)
            {:reply, :ok, %{new_state | stats: new_stats}}

          error ->
            {:reply, error, update_error_stat(new_state)}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_incident, incident_id}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        case get_request(new_state, "#{@incidents_endpoint}/#{incident_id}") do
          {:ok, response} -> {:reply, {:ok, response}, new_state}
          error -> {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:add_artifact, incident_id, artifact}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        # In FortiSOAR, artifacts are indicators linked to incidents
        indicator = format_indicator(artifact)

        case post_request(new_state, @indicators_endpoint, indicator) do
          {:ok, response} ->
            indicator_id = response["@id"] || response["id"]
            new_stats = update_stat(new_state.stats, :indicators_added)

            # Link indicator to incident
            link_indicator_to_incident(new_state, indicator_id, incident_id)

            {:reply, {:ok, indicator_id}, %{new_state | stats: new_stats}}

          error ->
            {:reply, error, update_error_stat(new_state)}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:list_playbooks, opts}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        params = build_list_params(opts)

        case get_request(new_state, "#{@playbooks_endpoint}#{params}") do
          {:ok, response} ->
            playbooks = response["hydra:member"] || response["data"] || []
            formatted = Enum.map(playbooks, fn pb ->
              %{
                id: pb["@id"] || pb["id"] || pb["uuid"],
                name: pb["name"],
                description: pb["description"],
                enabled: pb["isActive"] == true,
                tags: pb["tags"] || [],
                collection: pb["collection"]
              }
            end)
            {:reply, {:ok, formatted}, new_state}

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
        case get_request(new_state, "/api/3/system_configuration") do
          {:ok, _} -> {:reply, {:ok, "Connected to FortiSOAR"}, new_state}
          {:error, reason} -> {:reply, {:error, reason}, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_call({:push_alert, alert}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        alert_data = format_alert(alert)

        case post_request(new_state, @alerts_endpoint, alert_data) do
          {:ok, response} ->
            alert_id = response["@id"] || response["id"]
            new_stats = update_stat(new_state.stats, :alerts_created)

            # Add indicators if present
            new_state = add_alert_indicators(alert, alert_id, new_state)

            {:reply, {:ok, alert_id}, %{new_state | stats: new_stats}}

          error ->
            {:reply, error, update_error_stat(new_state)}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:create_alert, alert_data}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        alert = format_alert(alert_data)

        case post_request(new_state, @alerts_endpoint, alert) do
          {:ok, response} ->
            alert_id = response["@id"] || response["id"]
            new_stats = update_stat(new_state.stats, :alerts_created)
            {:reply, {:ok, alert_id}, %{new_state | stats: new_stats}}

          error ->
            {:reply, error, update_error_stat(new_state)}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:pull_actions, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        # Query for pending manual tasks
        query = %{
          filters: [
            %{field: "status", operator: "eq", value: "/api/3/picklists/pending"}
          ],
          logic: "AND"
        }

        case post_request(new_state, "/api/query/tasks", query) do
          {:ok, response} ->
            actions = response["hydra:member"] || response["data"] || []
            formatted = Enum.map(actions, &format_action_response/1)
            {:reply, {:ok, formatted}, new_state}

          error ->
            {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:sync_investigation, record_id, status}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        body = format_status_sync(status)

        # Determine if it's an alert or incident based on ID format
        endpoint = if String.contains?(record_id, "alerts") do
          "#{@alerts_endpoint}/#{record_id}"
        else
          "#{@incidents_endpoint}/#{record_id}"
        end

        case put_request(new_state, endpoint, body) do
          {:ok, _} ->
            new_stats = update_stat(new_state.stats, :sync_operations)
            {:reply, :ok, %{new_state | stats: new_stats}}

          error ->
            {:reply, error, update_error_stat(new_state)}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:add_indicator, indicator}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        indicator_data = format_indicator(indicator)

        case post_request(new_state, @indicators_endpoint, indicator_data) do
          {:ok, response} ->
            indicator_id = response["@id"] || response["id"]
            new_stats = update_stat(new_state.stats, :indicators_added)
            {:reply, {:ok, indicator_id}, %{new_state | stats: new_stats}}

          error ->
            {:reply, error, update_error_stat(new_state)}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:share_indicators, indicators}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        results = Enum.map(indicators, fn indicator ->
          indicator_data = format_indicator(indicator)

          case post_request(new_state, @indicators_endpoint, indicator_data) do
            {:ok, response} -> {:ok, response["@id"] || response["id"]}
            error -> error
          end
        end)

        successful = Enum.filter(results, fn
          {:ok, _} -> true
          _ -> false
        end)

        indicator_ids = Enum.map(successful, fn {:ok, id} -> id end)
        new_stats = Map.update(new_state.stats, :indicators_added, length(indicator_ids), &(&1 + length(indicator_ids)))

        {:reply, {:ok, indicator_ids}, %{new_state | stats: new_stats}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_alert, alert_id}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        case get_request(new_state, "#{@alerts_endpoint}/#{alert_id}") do
          {:ok, response} -> {:reply, {:ok, response}, new_state}
          error -> {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:link_alert_to_incident, alert_id, incident_id}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        body = %{
          incidents: [incident_id]
        }

        case put_request(new_state, "#{@alerts_endpoint}/#{alert_id}", body) do
          {:ok, _} -> {:reply, :ok, new_state}
          error -> {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:execute_action, action_name, params}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        body = %{
          action: action_name,
          parameters: params
        }

        case post_request(new_state, "/api/3/execute", body) do
          {:ok, response} -> {:reply, {:ok, response}, new_state}
          error -> {:reply, error, update_error_stat(new_state)}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:search_records, module_name, query}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        endpoint = "/api/query/#{module_name}"

        case post_request(new_state, endpoint, query) do
          {:ok, response} ->
            records = response["hydra:member"] || response["data"] || []
            {:reply, {:ok, records}, new_state}

          error ->
            {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp load_config(opts) do
    app_config = Application.get_env(:tamandua_server, __MODULE__, [])

    %{
      url: opts[:url] || app_config[:url],
      username: opts[:username] || app_config[:username],
      password: opts[:password] || app_config[:password],
      api_token: opts[:api_token] || app_config[:api_token],
      poll_interval_ms: opts[:poll_interval_ms] || app_config[:poll_interval_ms] || @default_poll_interval_ms,
      timeout_ms: opts[:timeout_ms] || app_config[:timeout_ms] || @default_timeout_ms,
      verify_ssl: opts[:verify_ssl] != false && app_config[:verify_ssl] != false
    }
  end

  defp ensure_auth(state) do
    cond do
      # API token auth
      state.config.api_token ->
        {:ok, %{state | auth_header: "Bearer #{state.config.api_token}"}}

      # Token still valid
      state.access_token && state.token_expires_at &&
          DateTime.compare(state.token_expires_at, DateTime.utc_now()) == :gt ->
        {:ok, state}

      # Need to authenticate
      state.config.username && state.config.password ->
        authenticate(state)

      true ->
        {:error, :no_auth_configured}
    end
  end

  defp authenticate(state) do
    url = "#{state.url}/api/3/auth/login"

    body = Jason.encode!(%{
      credentials: %{
        loginid: state.config.username,
        password: state.config.password
      }
    })

    headers = [
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    options = http_options(state.config)

    case Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: 200, body: resp_body}} ->
        response = Jason.decode!(resp_body)
        token = response["token"]
        # FortiSOAR tokens typically expire in 24 hours
        expires_at = DateTime.add(DateTime.utc_now(), 23 * 60 * 60, :second)
        {:ok, %{state | access_token: token, token_expires_at: expires_at, auth_header: "Bearer #{token}"}}

      {:ok, %{status_code: code, body: resp_body}} ->
        {:error, "Auth failed: HTTP #{code} - #{resp_body}"}

      {:error, %{reason: reason}} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp find_playbook(state, playbook_name) do
    query = %{
      filters: [
        %{field: "name", operator: "eq", value: playbook_name}
      ]
    }

    case post_request(state, "/api/query/playbooks", query) do
      {:ok, response} ->
        playbooks = response["hydra:member"] || response["data"] || []
        case List.first(playbooks) do
          nil -> {:error, :playbook_not_found}
          playbook -> {:ok, playbook}
        end

      error ->
        error
    end
  end

  defp format_alert(data) do
    %{
      name: data[:title] || data["title"] || "Tamandua Alert",
      description: data[:description] || data["description"],
      severity: format_picklist_ref("severity", map_severity(data[:severity] || data["severity"])),
      status: format_picklist_ref("alertStatus", "Open"),
      source: "Tamandua EDR",
      sourceId: data[:id] || data["id"],
      sourceData: %{
        tamandua_alert_id: data[:id] || data["id"],
        hostname: data[:hostname] || data["hostname"],
        agent_id: data[:agent_id] || data["agent_id"],
        mitre_tactics: data[:mitre_tactics] || data["mitre_tactics"] || [],
        mitre_techniques: data[:mitre_techniques] || data["mitre_techniques"] || [],
        threat_score: data[:threat_score] || data["threat_score"]
      },
      type: format_picklist_ref("alertType", data[:type] || "Malware"),
      computerName: data[:hostname] || data["hostname"]
    }
  end

  defp format_incident(data) do
    %{
      name: data[:title] || data["title"] || "Tamandua Incident",
      description: data[:description] || data["description"],
      severity: format_picklist_ref("severity", map_severity(data[:severity] || data["severity"])),
      status: format_picklist_ref("incidentStatus", "Open"),
      category: format_picklist_ref("category", data[:category] || "Malware"),
      source: "Tamandua EDR",
      sourceId: data[:id] || data["id"],
      sourceData: %{
        tamandua_alert_id: data[:id] || data["id"],
        hostname: data[:hostname] || data["hostname"],
        agent_id: data[:agent_id] || data["agent_id"],
        mitre_tactics: data[:mitre_tactics] || data["mitre_tactics"] || [],
        mitre_techniques: data[:mitre_techniques] || data["mitre_techniques"] || [],
        threat_score: data[:threat_score] || data["threat_score"]
      }
    }
  end

  defp format_incident_update(updates) do
    result = %{}

    result = if status = updates[:status] || updates["status"] do
      Map.put(result, :status, format_picklist_ref("incidentStatus", map_incident_status(status)))
    else
      result
    end

    result = if severity = updates[:severity] || updates["severity"] do
      Map.put(result, :severity, format_picklist_ref("severity", map_severity(severity)))
    else
      result
    end

    result = if notes = updates[:notes] || updates["notes"] do
      Map.put(result, :closureNotes, notes)
    else
      result
    end

    result
  end

  defp format_status_sync(status) do
    result = %{}

    result = if s = status[:status] || status["status"] do
      Map.put(result, :status, format_picklist_ref("alertStatus", map_incident_status(s)))
    else
      result
    end

    result = if resolution = status[:resolution] || status["resolution"] do
      Map.put(result, :resolution, format_picklist_ref("resolution", resolution))
    else
      result
    end

    result
  end

  defp format_indicator(artifact) do
    type = artifact[:type] || artifact["type"]
    value = artifact[:value] || artifact["value"]

    %{
      value: value,
      typeofindicator: format_picklist_ref("indicatorType", map_indicator_type(type)),
      reputation: format_picklist_ref("indicatorReputation", artifact[:reputation] || "Suspicious"),
      tlp: format_picklist_ref("tlp", "Amber"),
      description: artifact[:description] || artifact["description"],
      source: "Tamandua EDR",
      sourceData: artifact[:source_data] || artifact["source_data"] || %{}
    }
  end

  defp format_action_response(action) do
    %{
      id: action["@id"] || action["id"],
      name: action["name"],
      status: action["status"],
      description: action["description"],
      assignee: action["assignee"],
      due_date: action["dueDate"],
      created_at: action["createDate"],
      parameters: action["parameters"] || %{}
    }
  end

  defp format_picklist_ref(type, value) do
    # FortiSOAR uses IRI references for picklist values
    "/api/3/picklists/#{type}/#{URI.encode(to_string(value))}"
  end

  defp map_severity(severity) do
    case severity do
      "critical" -> "Critical"
      "high" -> "High"
      "medium" -> "Medium"
      "low" -> "Low"
      "info" -> "Minimal"
      _ -> "Medium"
    end
  end

  defp map_incident_status(status) do
    case status do
      "open" -> "Open"
      "in_progress" -> "In Progress"
      "resolved" -> "Resolved"
      "closed" -> "Closed"
      _ -> "Open"
    end
  end

  defp map_indicator_type(type) do
    case type do
      "ip" -> "IP Address"
      :ip -> "IP Address"
      "domain" -> "Domain"
      :domain -> "Domain"
      "url" -> "URL"
      :url -> "URL"
      "email" -> "Email Address"
      :email -> "Email Address"
      "hash" -> "FileHash-MD5"
      :hash -> "FileHash-MD5"
      "md5" -> "FileHash-MD5"
      :md5 -> "FileHash-MD5"
      "sha1" -> "FileHash-SHA1"
      :sha1 -> "FileHash-SHA1"
      "sha256" -> "FileHash-SHA256"
      :sha256 -> "FileHash-SHA256"
      "file" -> "File"
      :file -> "File"
      "process" -> "Process"
      :process -> "Process"
      _ -> "Other"
    end
  end

  defp build_list_params(opts) do
    params = []

    params = if limit = opts[:limit] do
      ["$limit=#{limit}" | params]
    else
      params
    end

    params = if offset = opts[:offset] do
      ["$skip=#{offset}" | params]
    else
      params
    end

    if length(params) > 0, do: "?" <> Enum.join(params, "&"), else: ""
  end

  defp add_alert_indicators(alert, alert_id, state) do
    artifacts = alert[:artifacts] || alert["artifacts"] || []
    iocs = alert[:iocs] || alert["iocs"] || []

    all_indicators = artifacts ++ Enum.map(iocs, fn ioc ->
      %{type: ioc[:type] || ioc["type"], value: ioc[:value] || ioc["value"]}
    end)

    if length(all_indicators) > 0 do
      Enum.each(all_indicators, fn indicator ->
        indicator_data = format_indicator(indicator)

        case post_request(state, @indicators_endpoint, indicator_data) do
          {:ok, response} ->
            indicator_id = response["@id"] || response["id"]
            link_indicator_to_alert(state, indicator_id, alert_id)

          _ ->
            :ok
        end
      end)

      new_stats = Map.update(state.stats, :indicators_added, length(all_indicators), &(&1 + length(all_indicators)))
      %{state | stats: new_stats}
    else
      state
    end
  end

  defp link_indicator_to_alert(state, indicator_id, alert_id) do
    body = %{
      alerts: [alert_id]
    }

    put_request(state, "#{@indicators_endpoint}/#{indicator_id}", body)
  end

  defp link_indicator_to_incident(state, indicator_id, incident_id) do
    body = %{
      incidents: [incident_id]
    }

    put_request(state, "#{@indicators_endpoint}/#{indicator_id}", body)
  end

  defp get_request(state, endpoint) do
    make_request(:get, state, endpoint, nil)
  end

  defp post_request(state, endpoint, body) do
    make_request(:post, state, endpoint, body)
  end

  defp put_request(state, endpoint, body) do
    make_request(:put, state, endpoint, body)
  end

  defp make_request(method, state, endpoint, body) do
    url = "#{state.url}#{endpoint}"

    headers = [
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    headers = if state.auth_header do
      [{"Authorization", state.auth_header} | headers]
    else
      headers
    end

    options = http_options(state.config)

    timeout = Keyword.get(options, :recv_timeout, 30_000)

    result = case method do
      :get -> Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: timeout)
      :post -> Finch.build(:post, url, headers, Jason.encode!(body)) |> Finch.request(TamanduaServer.Finch, receive_timeout: timeout)
      :put -> Finch.build(:put, url, headers, Jason.encode!(body)) |> Finch.request(TamanduaServer.Finch, receive_timeout: timeout)
      :patch -> Finch.build(:patch, url, headers, Jason.encode!(body)) |> Finch.request(TamanduaServer.Finch, receive_timeout: timeout)
      :delete -> Finch.build(:delete, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: timeout)
    end

    case result do
      {:ok, %{status_code: code, body: resp_body}} when code in 200..299 ->
        if resp_body == "" do
          {:ok, %{}}
        else
          case Jason.decode(resp_body) do
            {:ok, data} -> {:ok, data}
            _ -> {:ok, %{raw: resp_body}}
          end
        end

      {:ok, %{status_code: code, body: resp_body}} ->
        Logger.error("FortiSOAR API error: HTTP #{code} - #{resp_body}")
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        Logger.error("FortiSOAR connection error: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("FortiSOAR exception: #{inspect(e)}")
      {:error, Exception.message(e)}
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

  defp update_stat(stats, key) do
    stats
    |> Map.update(key, 1, &(&1 + 1))
    |> Map.put(:last_activity, DateTime.utc_now())
  end

  defp update_error_stat(state) do
    new_stats = Map.update(state.stats, :errors, 1, &(&1 + 1))
    %{state | stats: new_stats}
  end

  defp generate_id do
    :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
  end
end
