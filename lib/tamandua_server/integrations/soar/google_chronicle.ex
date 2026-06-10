defmodule TamanduaServer.Integrations.SOAR.GoogleChronicle do
  @moduledoc """
  Google Chronicle SOAR Integration (Siemplify)

  Provides bi-directional integration with Google Chronicle SOAR platform:
  - Push alerts to Chronicle SOAR as cases/alerts
  - Pull actions from Chronicle SOAR (playbook actions)
  - Sync investigation status
  - Entity/artifact sharing
  - Playbook triggering and monitoring
  - Integration with Chronicle SIEM

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.SOAR.GoogleChronicle,
        url: "https://your-instance.backstory.chronicle.security",
        api_key: "your-api-key",
        # or service account:
        service_account_json: "/path/to/service-account.json",
        project_id: "your-project-id",
        region: "us",  # or "europe", "asia"
        verify_ssl: true,
        poll_interval_ms: 30_000

  ## Bi-directional Sync

  The integration supports:
  1. Push: Alerts -> Chronicle SOAR Cases/Alerts
  2. Pull: Chronicle SOAR Actions -> Tamandua Response Commands
  3. Status Sync: Investigation state synchronization
  4. Entities: Share IOCs, entities, and enrichment data

  """

  use GenServer
  require Logger

  @behaviour TamanduaServer.Integrations.SOAR.Behaviour

  @default_timeout_ms 30_000
  @default_poll_interval_ms 30_000

  # Chronicle SOAR API endpoints
  @cases_endpoint "/api/external/v1/cases"
  @alerts_endpoint "/api/external/v1/alerts"
  @entities_endpoint "/api/external/v1/entities"
  @playbooks_endpoint "/api/external/v1/playbooks"
  @actions_endpoint "/api/external/v1/actions"
  @workflows_endpoint "/api/external/v1/workflows"

  defstruct [
    :config,
    :url,
    :auth_header,
    :access_token,
    :token_expires_at,
    :stats,
    :poll_timer,
    :environment
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
  Push an alert to Chronicle SOAR.
  """
  @spec push_alert(map()) :: {:ok, String.t()} | {:error, term()}
  def push_alert(alert) do
    GenServer.call(__MODULE__, {:push_alert, alert}, 30_000)
  end

  @doc """
  Create a case in Chronicle SOAR.
  """
  @spec create_case(map()) :: {:ok, String.t()} | {:error, term()}
  def create_case(case_data) do
    GenServer.call(__MODULE__, {:create_case, case_data}, 30_000)
  end

  @doc """
  Pull pending actions from Chronicle SOAR.
  """
  @spec pull_actions() :: {:ok, [map()]} | {:error, term()}
  def pull_actions do
    GenServer.call(__MODULE__, :pull_actions, 30_000)
  end

  @doc """
  Sync investigation status with Chronicle SOAR.
  """
  @spec sync_investigation(String.t(), map()) :: :ok | {:error, term()}
  def sync_investigation(case_id, status) do
    GenServer.call(__MODULE__, {:sync_investigation, case_id, status}, 30_000)
  end

  @doc """
  Add an entity to a case.
  """
  @spec add_entity(String.t(), map()) :: {:ok, String.t()} | {:error, term()}
  def add_entity(case_id, entity) do
    GenServer.call(__MODULE__, {:add_entity, case_id, entity}, 30_000)
  end

  @doc """
  Share entities with Chronicle SOAR case.
  """
  @spec share_entities(String.t(), [map()]) :: {:ok, [String.t()]} | {:error, term()}
  def share_entities(case_id, entities) do
    GenServer.call(__MODULE__, {:share_entities, case_id, entities}, 30_000)
  end

  @doc """
  Get case details.
  """
  @spec get_case(String.t()) :: {:ok, map()} | {:error, term()}
  def get_case(case_id) do
    GenServer.call(__MODULE__, {:get_case, case_id}, 30_000)
  end

  @doc """
  Close a case.
  """
  @spec close_case(String.t(), map()) :: :ok | {:error, term()}
  def close_case(case_id, resolution) do
    GenServer.call(__MODULE__, {:close_case, case_id, resolution}, 30_000)
  end

  @doc """
  Execute a workflow action.
  """
  @spec execute_action(String.t(), String.t(), map()) :: {:ok, map()} | {:error, term()}
  def execute_action(case_id, action_name, params) do
    GenServer.call(__MODULE__, {:execute_action, case_id, action_name, params}, 60_000)
  end

  @doc """
  Search cases.
  """
  @spec search_cases(map()) :: {:ok, [map()]} | {:error, term()}
  def search_cases(query) do
    GenServer.call(__MODULE__, {:search_cases, query}, 30_000)
  end

  @doc """
  Get case alerts.
  """
  @spec get_case_alerts(String.t()) :: {:ok, [map()]} | {:error, term()}
  def get_case_alerts(case_id) do
    GenServer.call(__MODULE__, {:get_case_alerts, case_id}, 30_000)
  end

  @doc """
  Ingest events to Chronicle SIEM.
  """
  @spec ingest_events([map()]) :: {:ok, map()} | {:error, term()}
  def ingest_events(events) do
    GenServer.call(__MODULE__, {:ingest_events, events}, 60_000)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting Google Chronicle SOAR Integration")

    config = load_config(opts)

    state = %__MODULE__{
      config: config,
      url: config.url,
      auth_header: nil,
      access_token: nil,
      token_expires_at: nil,
      stats: %{
        cases_created: 0,
        alerts_pushed: 0,
        entities_added: 0,
        playbooks_triggered: 0,
        sync_operations: 0,
        events_ingested: 0,
        last_activity: nil,
        errors: 0
      },
      poll_timer: nil,
      environment: config.environment || "Default Environment"
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:trigger_playbook, playbook_name, params}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        case_id = params[:case_id] || params["case_id"]
        alert_id = params[:alert_id] || params["alert_id"]

        body = %{
          playbook_identifier: playbook_name,
          case_id: case_id,
          alert_identifier: alert_id,
          scope: params[:scope] || "CurrentCase",
          environment: state.environment
        }

        case post_request(new_state, "#{@playbooks_endpoint}/run", body) do
          {:ok, response} ->
            new_stats = update_stat(new_state.stats, :playbooks_triggered)
            run_id = response["workflow_id"] || response["id"] || generate_id()
            {:reply, {:ok, run_id}, %{new_state | stats: new_stats}}

          error ->
            {:reply, error, update_error_stat(new_state)}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_playbook_status, run_id}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        case get_request(new_state, "#{@workflows_endpoint}/#{run_id}") do
          {:ok, response} ->
            status = %{
              id: response["id"],
              playbook_name: response["playbook_name"],
              case_id: response["case_id"],
              status: response["status"],
              started_at: response["start_time"],
              completed_at: response["end_time"],
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
        # Chronicle SOAR uses cases, not incidents
        case_data = format_case(incident_data)

        case post_request(new_state, @cases_endpoint, case_data) do
          {:ok, response} ->
            case_id = response["id"] || response["case_id"]
            new_stats = update_stat(new_state.stats, :cases_created)
            Logger.info("Created Chronicle SOAR case: #{case_id}")
            {:reply, {:ok, case_id}, %{new_state | stats: new_stats}}

          error ->
            {:reply, error, update_error_stat(new_state)}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:update_incident, case_id, updates}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        body = format_case_update(updates)

        case put_request(new_state, "#{@cases_endpoint}/#{case_id}", body) do
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
  def handle_call({:get_incident, case_id}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        case get_request(new_state, "#{@cases_endpoint}/#{case_id}") do
          {:ok, response} -> {:reply, {:ok, response}, new_state}
          error -> {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:add_artifact, case_id, artifact}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        entity = format_entity(artifact)

        case post_request(new_state, "#{@cases_endpoint}/#{case_id}/entities", entity) do
          {:ok, response} ->
            entity_id = response["id"] || response["identifier"]
            new_stats = update_stat(new_state.stats, :entities_added)
            {:reply, {:ok, entity_id}, %{new_state | stats: new_stats}}

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
            playbooks = response["playbooks"] || response["data"] || []
            formatted = Enum.map(playbooks, fn pb ->
              %{
                id: pb["id"] || pb["identifier"],
                name: pb["name"],
                display_name: pb["display_name"],
                description: pb["description"],
                enabled: pb["is_enabled"] == true,
                tags: pb["tags"] || [],
                trigger_type: pb["trigger_type"]
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
        case get_request(new_state, "/api/external/v1/ping") do
          {:ok, _} -> {:reply, {:ok, "Connected to Google Chronicle SOAR"}, new_state}
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
            alert_id = response["id"] || response["alert_id"]
            new_stats = update_stat(new_state.stats, :alerts_pushed)

            # Add entities if present
            new_state = add_alert_entities(alert, alert_id, new_state)

            {:reply, {:ok, alert_id}, %{new_state | stats: new_stats}}

          error ->
            {:reply, error, update_error_stat(new_state)}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:create_case, case_data}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        case_record = format_case(case_data)

        case post_request(new_state, @cases_endpoint, case_record) do
          {:ok, response} ->
            case_id = response["id"] || response["case_id"]
            new_stats = update_stat(new_state.stats, :cases_created)
            {:reply, {:ok, case_id}, %{new_state | stats: new_stats}}

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
        query = %{
          status: "pending",
          environment: state.environment
        }

        case post_request(new_state, "#{@actions_endpoint}/pending", query) do
          {:ok, response} ->
            actions = response["actions"] || response["data"] || []
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
  def handle_call({:sync_investigation, case_id, status}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        body = format_status_sync(status)

        case put_request(new_state, "#{@cases_endpoint}/#{case_id}", body) do
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
  def handle_call({:add_entity, case_id, entity}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        entity_data = format_entity(entity)

        case post_request(new_state, "#{@cases_endpoint}/#{case_id}/entities", entity_data) do
          {:ok, response} ->
            entity_id = response["id"] || response["identifier"]
            new_stats = update_stat(new_state.stats, :entities_added)
            {:reply, {:ok, entity_id}, %{new_state | stats: new_stats}}

          error ->
            {:reply, error, update_error_stat(new_state)}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:share_entities, case_id, entities}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        results = Enum.map(entities, fn entity ->
          entity_data = format_entity(entity)

          case post_request(new_state, "#{@cases_endpoint}/#{case_id}/entities", entity_data) do
            {:ok, response} -> {:ok, response["id"] || response["identifier"]}
            error -> error
          end
        end)

        successful = Enum.filter(results, fn
          {:ok, _} -> true
          _ -> false
        end)

        entity_ids = Enum.map(successful, fn {:ok, id} -> id end)
        new_stats = Map.update(new_state.stats, :entities_added, length(entity_ids), &(&1 + length(entity_ids)))

        {:reply, {:ok, entity_ids}, %{new_state | stats: new_stats}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_case, case_id}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        case get_request(new_state, "#{@cases_endpoint}/#{case_id}") do
          {:ok, response} -> {:reply, {:ok, response}, new_state}
          error -> {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:close_case, case_id, resolution}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        body = %{
          status: "Closed",
          root_cause: resolution[:root_cause] || resolution["root_cause"],
          close_reason: resolution[:reason] || resolution["reason"] || "Resolved",
          close_comment: resolution[:comment] || resolution["comment"]
        }

        case put_request(new_state, "#{@cases_endpoint}/#{case_id}/close", body) do
          {:ok, _} -> {:reply, :ok, new_state}
          error -> {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:execute_action, case_id, action_name, params}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        body = %{
          case_id: case_id,
          action_identifier: action_name,
          parameters: params,
          environment: state.environment
        }

        case post_request(new_state, "#{@actions_endpoint}/execute", body) do
          {:ok, response} -> {:reply, {:ok, response}, new_state}
          error -> {:reply, error, update_error_stat(new_state)}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:search_cases, query}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        search_query = build_search_query(query)

        case post_request(new_state, "#{@cases_endpoint}/search", search_query) do
          {:ok, response} ->
            cases = response["cases"] || response["data"] || []
            {:reply, {:ok, cases}, new_state}

          error ->
            {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_case_alerts, case_id}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        case get_request(new_state, "#{@cases_endpoint}/#{case_id}/alerts") do
          {:ok, response} ->
            alerts = response["alerts"] || response["data"] || []
            {:reply, {:ok, alerts}, new_state}

          error ->
            {:reply, error, new_state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:ingest_events, events}, _from, state) do
    case ensure_auth(state) do
      {:ok, new_state} ->
        # Chronicle SIEM ingestion endpoint
        formatted_events = Enum.map(events, &format_udm_event/1)

        body = %{
          customer_id: state.config.project_id,
          events: formatted_events
        }

        case post_request(new_state, "/v1/events:batchCreate", body) do
          {:ok, response} ->
            new_stats = Map.update(new_state.stats, :events_ingested, length(events), &(&1 + length(events)))
            {:reply, {:ok, response}, %{new_state | stats: new_stats}}

          error ->
            {:reply, error, update_error_stat(new_state)}
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
      api_key: opts[:api_key] || app_config[:api_key],
      service_account_json: opts[:service_account_json] || app_config[:service_account_json],
      project_id: opts[:project_id] || app_config[:project_id],
      region: opts[:region] || app_config[:region] || "us",
      environment: opts[:environment] || app_config[:environment] || "Default Environment",
      poll_interval_ms: opts[:poll_interval_ms] || app_config[:poll_interval_ms] || @default_poll_interval_ms,
      timeout_ms: opts[:timeout_ms] || app_config[:timeout_ms] || @default_timeout_ms,
      verify_ssl: opts[:verify_ssl] != false && app_config[:verify_ssl] != false
    }
  end

  defp ensure_auth(state) do
    cond do
      # API key auth
      state.config.api_key ->
        {:ok, %{state | auth_header: "Bearer #{state.config.api_key}"}}

      # Token still valid
      state.access_token && state.token_expires_at &&
          DateTime.compare(state.token_expires_at, DateTime.utc_now()) == :gt ->
        {:ok, state}

      # Service account auth
      state.config.service_account_json ->
        authenticate_service_account(state)

      true ->
        {:error, :no_auth_configured}
    end
  end

  defp authenticate_service_account(state) do
    # Load service account JSON
    case File.read(state.config.service_account_json) do
      {:ok, content} ->
        case Jason.decode(content) do
          {:ok, sa_config} ->
            # Generate JWT and exchange for access token
            generate_oauth_token(state, sa_config)

          _ ->
            {:error, :invalid_service_account_json}
        end

      _ ->
        {:error, :service_account_file_not_found}
    end
  end

  defp generate_oauth_token(state, sa_config) do
    token_url = "https://oauth2.googleapis.com/token"

    case build_jwt(sa_config) do
      {:ok, jwt} ->
        body = URI.encode_query(%{
          "grant_type" => "urn:ietf:params:oauth:grant-type:jwt-bearer",
          "assertion" => jwt
        })

        headers = [{"Content-Type", "application/x-www-form-urlencoded"}]
        options = http_options(state.config)
        timeout = Keyword.get(options, :recv_timeout, 30_000)

        case Finch.build(:post, token_url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: timeout) do
          {:ok, %Finch.Response{status: 200, body: resp_body}} ->
            response = Jason.decode!(resp_body)
            token = response["access_token"]
            expires_in = response["expires_in"] || 3600
            expires_at = DateTime.add(DateTime.utc_now(), expires_in - 60, :second)
            {:ok, %{state | access_token: token, token_expires_at: expires_at, auth_header: "Bearer #{token}"}}

          {:ok, %Finch.Response{status: code, body: resp_body}} ->
            {:error, "OAuth failed: HTTP #{code} - #{resp_body}"}

          {:error, reason} ->
            {:error, {:http_error, reason}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp build_jwt(sa_config) do
    private_key_pem = sa_config["private_key"]

    if is_nil(private_key_pem) or private_key_pem == "" do
      {:error, :credentials_not_configured}
    else
      now = System.system_time(:second)

      header = %{"alg" => "RS256", "typ" => "JWT"}
      claims = %{
        "iss" => sa_config["client_email"],
        "sub" => sa_config["client_email"],
        "aud" => "https://oauth2.googleapis.com/token",
        "scope" => "https://www.googleapis.com/auth/chronicle-backstory",
        "iat" => now,
        "exp" => now + 3600
      }

      header_b64 = Base.url_encode64(Jason.encode!(header), padding: false)
      claims_b64 = Base.url_encode64(Jason.encode!(claims), padding: false)
      signing_input = "#{header_b64}.#{claims_b64}"

      case sign_jwt_rsa256(signing_input, private_key_pem) do
        {:ok, signature} ->
          {:ok, "#{signing_input}.#{signature}"}

        {:error, reason} ->
          {:error, {:jwt_signing_failed, reason}}
      end
    end
  end

  defp sign_jwt_rsa256(data, private_key_pem) do
    try do
      [entry | _] = :public_key.pem_decode(private_key_pem)
      private_key = :public_key.pem_entry_decode(entry)
      signature = :public_key.sign(data, :sha256, private_key)
      {:ok, Base.url_encode64(signature, padding: false)}
    rescue
      e -> {:error, Exception.message(e)}
    end
  end

  defp format_case(data) do
    %{
      name: data[:title] || data["title"] || "Tamandua Alert",
      description: data[:description] || data["description"],
      priority: map_priority(data[:severity] || data["severity"]),
      status: "Open",
      environment: data[:environment] || "Default Environment",
      stage: "Initial",
      alert_count: 1,
      tags: build_tags(data),
      custom_fields: %{
        tamandua_alert_id: data[:id] || data["id"],
        hostname: data[:hostname] || data["hostname"],
        agent_id: data[:agent_id] || data["agent_id"],
        mitre_tactics: Enum.join(data[:mitre_tactics] || data["mitre_tactics"] || [], ", "),
        mitre_techniques: Enum.join(data[:mitre_techniques] || data["mitre_techniques"] || [], ", "),
        threat_score: data[:threat_score] || data["threat_score"]
      }
    }
  end

  defp format_alert(data) do
    %{
      name: data[:title] || data["title"] || "Tamandua Alert",
      description: data[:description] || data["description"],
      ticket_id: data[:id] || data["id"],
      device_product: "Tamandua EDR",
      device_vendor: "Tamandua",
      severity: map_severity_number(data[:severity] || data["severity"]),
      start_time: DateTime.utc_now() |> DateTime.to_unix(:millisecond),
      end_time: DateTime.utc_now() |> DateTime.to_unix(:millisecond),
      environment: "Default Environment",
      events: [
        %{
          name: data[:title] || data["title"],
          device_product: "Tamandua EDR",
          _raw_log: Jason.encode!(data[:evidence] || data["evidence"] || %{})
        }
      ],
      source_system_name: "Tamandua",
      tags: build_tags(data)
    }
  end

  defp format_case_update(updates) do
    result = %{}

    result = if status = updates[:status] || updates["status"] do
      Map.put(result, :status, map_case_status(status))
    else
      result
    end

    result = if priority = updates[:priority] || updates["priority"] do
      Map.put(result, :priority, map_priority(priority))
    else
      result
    end

    result = if stage = updates[:stage] || updates["stage"] do
      Map.put(result, :stage, stage)
    else
      result
    end

    result
  end

  defp format_status_sync(status) do
    result = %{}

    result = if s = status[:status] || status["status"] do
      Map.put(result, :status, map_case_status(s))
    else
      result
    end

    result = if stage = status[:stage] || status["stage"] do
      Map.put(result, :stage, stage)
    else
      result
    end

    result
  end

  defp format_entity(artifact) do
    type = artifact[:type] || artifact["type"]
    value = artifact[:value] || artifact["value"]

    %{
      identifier: value,
      entity_type: map_entity_type(type),
      is_suspicious: artifact[:suspicious] || artifact["suspicious"] || false,
      is_internal_asset: artifact[:internal] || artifact["internal"] || false,
      properties: artifact[:properties] || artifact["properties"] || %{}
    }
  end

  defp format_action_response(action) do
    %{
      id: action["id"],
      name: action["action_name"],
      case_id: action["case_id"],
      alert_id: action["alert_id"],
      status: action["status"],
      parameters: action["parameters"] || %{},
      created_at: action["creation_time"]
    }
  end

  defp format_udm_event(event) do
    # Format as Chronicle UDM (Unified Data Model) event
    %{
      metadata: %{
        event_timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
        event_type: event[:event_type] || event["event_type"] || "GENERIC_EVENT",
        product_name: "Tamandua EDR",
        vendor_name: "Tamandua"
      },
      principal: %{
        hostname: event[:hostname] || event["hostname"],
        asset_id: event[:agent_id] || event["agent_id"]
      },
      target: build_target(event),
      security_result: [
        %{
          action: "BLOCK",
          severity: map_udm_severity(event[:severity] || event["severity"]),
          category: event[:category] || event["category"] || "UNKNOWN"
        }
      ]
    }
  end

  defp build_target(event) do
    target = %{}

    target = if process = event[:process] || event["process"] do
      Map.put(target, :process, %{
        file: %{full_path: process[:path] || process["path"]},
        command_line: process[:command_line] || process["command_line"]
      })
    else
      target
    end

    target = if file = event[:file] || event["file"] do
      Map.put(target, :file, %{
        full_path: file[:path] || file["path"],
        sha256: file[:sha256] || file["sha256"]
      })
    else
      target
    end

    target
  end

  defp map_priority(severity) do
    case severity do
      "critical" -> 100
      "high" -> 80
      "medium" -> 60
      "low" -> 40
      "info" -> 20
      _ -> 60
    end
  end

  defp map_severity_number(severity) do
    case severity do
      "critical" -> 5
      "high" -> 4
      "medium" -> 3
      "low" -> 2
      "info" -> 1
      _ -> 3
    end
  end

  defp map_udm_severity(severity) do
    case severity do
      "critical" -> "CRITICAL"
      "high" -> "HIGH"
      "medium" -> "MEDIUM"
      "low" -> "LOW"
      "info" -> "INFORMATIONAL"
      _ -> "MEDIUM"
    end
  end

  defp map_case_status(status) do
    case status do
      "open" -> "Open"
      "in_progress" -> "In Progress"
      "resolved" -> "Resolved"
      "closed" -> "Closed"
      _ -> "Open"
    end
  end

  defp map_entity_type(type) do
    case type do
      "ip" -> "ADDRESS"
      :ip -> "ADDRESS"
      "domain" -> "HOSTNAME"
      :domain -> "HOSTNAME"
      "url" -> "URL"
      :url -> "URL"
      "email" -> "EMAILADDRESS"
      :email -> "EMAILADDRESS"
      "hash" -> "FILEHASH"
      :hash -> "FILEHASH"
      "file" -> "FILENAME"
      :file -> "FILENAME"
      "process" -> "PROCESS"
      :process -> "PROCESS"
      "user" -> "USER"
      :user -> "USER"
      _ -> "GENERIC"
    end
  end

  defp build_tags(data) do
    tags = ["tamandua-edr"]

    tags = if hostname = data[:hostname] || data["hostname"] do
      ["host:#{hostname}" | tags]
    else
      tags
    end

    tactics = data[:mitre_tactics] || data["mitre_tactics"] || []
    tags = Enum.reduce(tactics, tags, fn tactic, acc ->
      ["mitre:#{tactic}" | acc]
    end)

    techniques = data[:mitre_techniques] || data["mitre_techniques"] || []
    Enum.reduce(techniques, tags, fn technique, acc ->
      ["mitre:#{technique}" | acc]
    end)
  end

  defp build_list_params(opts) do
    params = []

    params = if limit = opts[:limit] do
      ["pageSize=#{limit}" | params]
    else
      params
    end

    params = if token = opts[:page_token] do
      ["pageToken=#{token}" | params]
    else
      params
    end

    if length(params) > 0, do: "?" <> Enum.join(params, "&"), else: ""
  end

  defp build_search_query(query) do
    %{
      filters: [
        if(status = query[:status] || query["status"], do: %{field: "status", value: map_case_status(status)}),
        if(priority = query[:priority] || query["priority"], do: %{field: "priority", operator: "gte", value: map_priority(priority)})
      ] |> Enum.reject(&is_nil/1),
      sort_by: query[:sort_by] || "creation_time",
      sort_order: query[:sort_order] || "desc",
      page_size: query[:limit] || 50
    }
  end

  defp add_alert_entities(alert, alert_id, state) do
    artifacts = alert[:artifacts] || alert["artifacts"] || []
    iocs = alert[:iocs] || alert["iocs"] || []

    all_entities = artifacts ++ Enum.map(iocs, fn ioc ->
      %{type: ioc[:type] || ioc["type"], value: ioc[:value] || ioc["value"]}
    end)

    if length(all_entities) > 0 do
      Enum.each(all_entities, fn entity ->
        entity_data = format_entity(entity)
        post_request(state, "#{@alerts_endpoint}/#{alert_id}/entities", entity_data)
      end)

      new_stats = Map.update(state.stats, :entities_added, length(all_entities), &(&1 + length(all_entities)))
      %{state | stats: new_stats}
    else
      state
    end
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
        Logger.error("Chronicle SOAR API error: HTTP #{code} - #{resp_body}")
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        Logger.error("Chronicle SOAR connection error: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("Chronicle SOAR exception: #{inspect(e)}")
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
