defmodule TamanduaServer.Integrations.SOAR.SplunkSOAR do
  @moduledoc """
  Splunk SOAR (formerly Phantom) Integration

  Provides bi-directional integration with Splunk SOAR platform:
  - Push alerts to SOAR as events/containers
  - Pull actions from SOAR (action requests)
  - Sync investigation status
  - Artifact sharing
  - Playbook triggering and monitoring
  - Asset management integration

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.SOAR.SplunkSOAR,
        url: "https://phantom.example.com",
        api_token: "your-api-token",
        # or username/password:
        username: "your-username",
        password: "your-password",
        verify_ssl: true,
        poll_interval_ms: 30_000,  # Poll for actions every 30 seconds
        default_label: "tamandua",
        default_severity: "medium"

  ## Bi-directional Sync

  The integration supports:
  1. Push: Alerts -> SOAR Containers/Events
  2. Pull: SOAR Actions -> Tamandua Response Commands
  3. Status Sync: Investigation state synchronization
  4. Artifacts: Share IOCs, evidence files, and enrichment data

  """

  use GenServer
  require Logger

  @behaviour TamanduaServer.Integrations.SOAR.Behaviour

  @default_timeout_ms 30_000
  @default_poll_interval_ms 30_000

  # Splunk SOAR API endpoints
  @container_endpoint "/rest/container"
  @artifact_endpoint "/rest/artifact"
  @action_run_endpoint "/rest/action_run"
  @playbook_endpoint "/rest/playbook"
  @playbook_run_endpoint "/rest/playbook_run"
  @asset_endpoint "/rest/asset"
  @app_run_endpoint "/rest/app_run"

  defstruct [
    :config,
    :url,
    :auth_header,
    :stats,
    :poll_timer,
    :pending_actions
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
  Push an alert to Splunk SOAR as a container.
  """
  @spec push_alert(map()) :: {:ok, String.t()} | {:error, term()}
  def push_alert(alert) do
    GenServer.call(__MODULE__, {:push_alert, alert}, 30_000)
  end

  @doc """
  Pull pending actions from Splunk SOAR.
  """
  @spec pull_actions() :: {:ok, [map()]} | {:error, term()}
  def pull_actions do
    GenServer.call(__MODULE__, :pull_actions, 30_000)
  end

  @doc """
  Sync investigation status with SOAR.
  """
  @spec sync_investigation(String.t(), map()) :: :ok | {:error, term()}
  def sync_investigation(container_id, status) do
    GenServer.call(__MODULE__, {:sync_investigation, container_id, status}, 30_000)
  end

  @doc """
  Share artifacts with SOAR container.
  """
  @spec share_artifacts(String.t(), [map()]) :: {:ok, [String.t()]} | {:error, term()}
  def share_artifacts(container_id, artifacts) do
    GenServer.call(__MODULE__, {:share_artifacts, container_id, artifacts}, 30_000)
  end

  @doc """
  Get container (incident) artifacts.
  """
  @spec get_artifacts(String.t()) :: {:ok, [map()]} | {:error, term()}
  def get_artifacts(container_id) do
    GenServer.call(__MODULE__, {:get_artifacts, container_id}, 30_000)
  end

  @doc """
  Run an action on an asset.
  """
  @spec run_action(String.t(), String.t(), map()) :: {:ok, String.t()} | {:error, term()}
  def run_action(action_name, asset_name, params) do
    GenServer.call(__MODULE__, {:run_action, action_name, asset_name, params}, 60_000)
  end

  @doc """
  Register a callback handler for SOAR actions.
  """
  @spec register_action_handler(pid()) :: :ok
  def register_action_handler(handler_pid) do
    GenServer.cast(__MODULE__, {:register_action_handler, handler_pid})
  end

  @doc """
  Get action run status.
  """
  @spec get_action_status(String.t()) :: {:ok, map()} | {:error, term()}
  def get_action_status(action_run_id) do
    GenServer.call(__MODULE__, {:get_action_status, action_run_id}, 30_000)
  end

  @doc """
  List available assets.
  """
  @spec list_assets() :: {:ok, [map()]} | {:error, term()}
  def list_assets do
    GenServer.call(__MODULE__, :list_assets, 30_000)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting Splunk SOAR Integration")

    config = load_config(opts)
    auth_header = build_auth_header(config)

    state = %__MODULE__{
      config: config,
      url: config.url,
      auth_header: auth_header,
      stats: %{
        containers_created: 0,
        artifacts_added: 0,
        playbooks_triggered: 0,
        actions_received: 0,
        actions_executed: 0,
        sync_operations: 0,
        last_activity: nil,
        last_poll: nil,
        errors: 0
      },
      poll_timer: nil,
      pending_actions: []
    }

    # Start polling for actions if configured
    state = if config.poll_interval_ms > 0 do
      timer = Process.send_after(self(), :poll_actions, config.poll_interval_ms)
      %{state | poll_timer: timer}
    else
      state
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:trigger_playbook, playbook_name, params}, _from, state) do
    container_id = params[:container_id] || params["container_id"]

    body = %{
      playbook_id: playbook_name,
      container_id: container_id,
      scope: params[:scope] || "new",
      run: true
    }

    case post_request(state, @playbook_run_endpoint, body) do
      {:ok, response} ->
        new_stats = update_stat(state.stats, :playbooks_triggered)
        run_id = to_string(response["playbook_run_id"] || response["id"])
        {:reply, {:ok, run_id}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:get_playbook_status, run_id}, _from, state) do
    case get_request(state, "#{@playbook_run_endpoint}/#{run_id}") do
      {:ok, response} ->
        status = %{
          id: to_string(response["id"]),
          playbook_id: response["playbook"],
          container_id: response["container"],
          status: response["status"],
          message: response["message"],
          started_at: response["start_time"],
          completed_at: response["end_time"],
          owner: response["owner"]
        }
        {:reply, {:ok, status}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:create_incident, incident_data}, _from, state) do
    container = format_container(incident_data, state.config)

    case post_request(state, @container_endpoint, container) do
      {:ok, response} ->
        container_id = to_string(response["id"])
        new_stats = update_stat(state.stats, :containers_created)
        Logger.info("Created Splunk SOAR container: #{container_id}")
        {:reply, {:ok, container_id}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:update_incident, incident_id, updates}, _from, state) do
    body = format_container_update(updates)

    case post_request(state, "#{@container_endpoint}/#{incident_id}", body) do
      {:ok, _} ->
        new_stats = update_stat(state.stats, :sync_operations)
        {:reply, :ok, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:get_incident, incident_id}, _from, state) do
    case get_request(state, "#{@container_endpoint}/#{incident_id}") do
      {:ok, response} ->
        {:reply, {:ok, response}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:add_artifact, incident_id, artifact}, _from, state) do
    artifact_data = format_artifact(artifact, incident_id)

    case post_request(state, @artifact_endpoint, artifact_data) do
      {:ok, response} ->
        artifact_id = to_string(response["id"])
        new_stats = update_stat(state.stats, :artifacts_added)
        {:reply, {:ok, artifact_id}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:list_playbooks, opts}, _from, state) do
    page_size = opts[:page_size] || 100
    page = opts[:page] || 0

    case get_request(state, "#{@playbook_endpoint}?page_size=#{page_size}&page=#{page}") do
      {:ok, %{"data" => playbooks}} ->
        formatted = Enum.map(playbooks, fn pb ->
          %{
            id: to_string(pb["id"]),
            name: pb["name"],
            description: pb["description"],
            enabled: pb["active"] == true,
            version: pb["version"],
            playbook_type: pb["playbook_type"]
          }
        end)
        {:reply, {:ok, formatted}, state}

      {:ok, response} when is_list(response) ->
        {:reply, {:ok, response}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call(:test_connection, _from, state) do
    case get_request(state, "/rest/version") do
      {:ok, response} ->
        version = response["version"] || "unknown"
        {:reply, {:ok, "Connected to Splunk SOAR (version: #{version})"}, state}

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
    container = format_container(alert, state.config)

    case post_request(state, @container_endpoint, container) do
      {:ok, response} ->
        container_id = to_string(response["id"])
        new_stats = update_stat(state.stats, :containers_created)

        # Also add artifacts if present in alert
        state = add_alert_artifacts(alert, container_id, state)

        {:reply, {:ok, container_id}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call(:pull_actions, _from, state) do
    # Query for pending action runs targeting our assets
    params = "?_filter_status__in=[\"pending\",\"running\"]&_filter_asset__name__startswith=\"tamandua\"&page_size=100"

    case get_request(state, "#{@app_run_endpoint}#{params}") do
      {:ok, %{"data" => actions}} ->
        new_stats = Map.put(state.stats, :last_poll, DateTime.utc_now())
        formatted_actions = Enum.map(actions, &format_action_request/1)
        {:reply, {:ok, formatted_actions}, %{state | stats: new_stats, pending_actions: formatted_actions}}

      {:ok, response} when is_list(response) ->
        {:reply, {:ok, response}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:sync_investigation, container_id, status}, _from, state) do
    body = %{
      status: map_investigation_status(status[:status] || status["status"]),
      owner_name: status[:owner] || status["owner"],
      close_time: status[:closed_at] || status["closed_at"],
      custom_fields: %{
        tamandua_investigation_id: status[:investigation_id] || status["investigation_id"],
        tamandua_resolution: status[:resolution] || status["resolution"]
      }
    }

    case post_request(state, "#{@container_endpoint}/#{container_id}", body) do
      {:ok, _} ->
        new_stats = update_stat(state.stats, :sync_operations)
        {:reply, :ok, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:share_artifacts, container_id, artifacts}, _from, state) do
    results = Enum.map(artifacts, fn artifact ->
      artifact_data = format_artifact(artifact, container_id)

      case post_request(state, @artifact_endpoint, artifact_data) do
        {:ok, response} -> {:ok, to_string(response["id"])}
        error -> error
      end
    end)

    successful = Enum.filter(results, fn
      {:ok, _} -> true
      _ -> false
    end)

    artifact_ids = Enum.map(successful, fn {:ok, id} -> id end)
    new_stats = Map.update(state.stats, :artifacts_added, length(artifact_ids), &(&1 + length(artifact_ids)))

    {:reply, {:ok, artifact_ids}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:get_artifacts, container_id}, _from, state) do
    case get_request(state, "#{@artifact_endpoint}?_filter_container=#{container_id}&page_size=1000") do
      {:ok, %{"data" => artifacts}} ->
        formatted = Enum.map(artifacts, fn a ->
          %{
            id: to_string(a["id"]),
            name: a["name"],
            type: a["type"],
            label: a["label"],
            cef: a["cef"],
            cef_types: a["cef_types"],
            source_data_identifier: a["source_data_identifier"],
            tags: a["tags"]
          }
        end)
        {:reply, {:ok, formatted}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:run_action, action_name, asset_name, params}, _from, state) do
    body = %{
      action: action_name,
      name: "Tamandua: #{action_name}",
      targets: [
        %{
          assets: [asset_name],
          parameters: [params]
        }
      ],
      type: "investigate"
    }

    case post_request(state, @action_run_endpoint, body) do
      {:ok, response} ->
        action_run_id = to_string(response["action_run_id"] || response["id"])
        new_stats = update_stat(state.stats, :actions_executed)
        {:reply, {:ok, action_run_id}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:get_action_status, action_run_id}, _from, state) do
    case get_request(state, "#{@action_run_endpoint}/#{action_run_id}") do
      {:ok, response} ->
        status = %{
          id: to_string(response["id"]),
          action: response["action"],
          status: response["status"],
          message: response["message"],
          result_summary: response["result_summary"],
          started_at: response["create_time"],
          completed_at: response["close_time"]
        }
        {:reply, {:ok, status}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call(:list_assets, _from, state) do
    case get_request(state, "#{@asset_endpoint}?page_size=1000") do
      {:ok, %{"data" => assets}} ->
        formatted = Enum.map(assets, fn a ->
          %{
            id: to_string(a["id"]),
            name: a["name"],
            description: a["description"],
            product_name: a["product_name"],
            product_vendor: a["product_vendor"],
            configuration: a["configuration"],
            tags: a["tags"]
          }
        end)
        {:reply, {:ok, formatted}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_cast({:register_action_handler, handler_pid}, state) do
    {:noreply, Map.put(state, :action_handler, handler_pid)}
  end

  @impl true
  def handle_info(:poll_actions, state) do
    # Poll for actions
    new_state = case do_pull_actions(state) do
      {:ok, actions} when length(actions) > 0 ->
        new_stats = Map.update(state.stats, :actions_received, length(actions), &(&1 + length(actions)))

        # Notify handler if registered
        if handler = Map.get(state, :action_handler) do
          send(handler, {:soar_actions, actions})
        end

        %{state | stats: new_stats, pending_actions: actions}

      _ ->
        state
    end

    # Schedule next poll
    timer = Process.send_after(self(), :poll_actions, state.config.poll_interval_ms)
    {:noreply, %{new_state | poll_timer: timer, stats: Map.put(new_state.stats, :last_poll, DateTime.utc_now())}}
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
      url: opts[:url] || app_config[:url],
      api_token: opts[:api_token] || app_config[:api_token],
      username: opts[:username] || app_config[:username],
      password: opts[:password] || app_config[:password],
      default_label: opts[:default_label] || app_config[:default_label] || "tamandua",
      default_severity: opts[:default_severity] || app_config[:default_severity] || "medium",
      poll_interval_ms: opts[:poll_interval_ms] || app_config[:poll_interval_ms] || @default_poll_interval_ms,
      timeout_ms: opts[:timeout_ms] || app_config[:timeout_ms] || @default_timeout_ms,
      verify_ssl: opts[:verify_ssl] != false && app_config[:verify_ssl] != false
    }
  end

  defp build_auth_header(config) do
    cond do
      config.api_token ->
        "ph-auth-token=#{config.api_token}"

      config.username && config.password ->
        auth = Base.encode64("#{config.username}:#{config.password}")
        "Basic #{auth}"

      true ->
        nil
    end
  end

  defp format_container(data, config) do
    %{
      name: data[:title] || data["title"] || "Tamandua Alert",
      description: data[:description] || data["description"],
      label: config.default_label,
      severity: map_severity(data[:severity] || data["severity"] || config.default_severity),
      status: "new",
      sensitivity: "amber",
      owner_id: data[:owner_id] || data["owner_id"],
      container_type: "default",
      source_data_identifier: data[:id] || data["id"],
      custom_fields: %{
        tamandua_alert_id: data[:id] || data["id"],
        hostname: data[:hostname] || data["hostname"],
        agent_id: data[:agent_id] || data["agent_id"],
        mitre_tactics: data[:mitre_tactics] || data["mitre_tactics"] || [],
        mitre_techniques: data[:mitre_techniques] || data["mitre_techniques"] || [],
        threat_score: data[:threat_score] || data["threat_score"]
      },
      tags: build_tags(data),
      data: %{
        raw: data[:evidence] || data["evidence"] || %{}
      }
    }
  end

  defp format_container_update(updates) do
    base = %{}

    base = if status = updates[:status] || updates["status"] do
      Map.put(base, :status, map_investigation_status(status))
    else
      base
    end

    base = if severity = updates[:severity] || updates["severity"] do
      Map.put(base, :severity, map_severity(severity))
    else
      base
    end

    base = if owner = updates[:owner_id] || updates["owner_id"] do
      Map.put(base, :owner_id, owner)
    else
      base
    end

    base
  end

  defp format_artifact(artifact, container_id) do
    type = artifact[:type] || artifact["type"] || infer_artifact_type(artifact)
    value = artifact[:value] || artifact["value"]

    %{
      container_id: container_id,
      name: artifact[:name] || artifact["name"] || value,
      label: artifact[:label] || artifact["label"] || "artifact",
      type: type,
      source_data_identifier: artifact[:source_id] || artifact["source_id"],
      cef: build_cef(type, value, artifact),
      cef_types: build_cef_types(type),
      tags: artifact[:tags] || artifact["tags"] || [],
      severity: map_severity(artifact[:severity] || artifact["severity"] || "medium")
    }
  end

  defp format_action_request(action) do
    %{
      id: to_string(action["id"]),
      action: action["action"],
      app: action["app"],
      asset: action["asset"],
      status: action["status"],
      parameters: action["parameters"] || %{},
      container_id: action["container"],
      created_at: action["create_time"],
      message: action["message"]
    }
  end

  defp map_severity(severity) do
    case severity do
      "critical" -> "high"
      "high" -> "high"
      "medium" -> "medium"
      "low" -> "low"
      "info" -> "low"
      _ -> "medium"
    end
  end

  defp map_investigation_status(status) do
    case status do
      "open" -> "open"
      "in_progress" -> "open"
      "resolved" -> "closed"
      "closed" -> "closed"
      "new" -> "new"
      _ -> "open"
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

  defp infer_artifact_type(artifact) do
    value = to_string(artifact[:value] || artifact["value"] || "")

    cond do
      String.match?(value, ~r/^[a-fA-F0-9]{64}$/) -> "hash"
      String.match?(value, ~r/^[a-fA-F0-9]{40}$/) -> "hash"
      String.match?(value, ~r/^[a-fA-F0-9]{32}$/) -> "hash"
      String.match?(value, ~r/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) -> "ip"
      String.contains?(value, "@") -> "email"
      String.starts_with?(value, "http") -> "url"
      true -> "domain"
    end
  end

  defp build_cef(type, value, artifact) do
    base = case type do
      "hash" -> %{fileHash: value}
      "ip" -> %{sourceAddress: value}
      "domain" -> %{destinationDnsDomain: value}
      "url" -> %{requestURL: value}
      "email" -> %{emailAddress: value}
      "file" -> %{fileName: value, filePath: artifact[:path] || artifact["path"]}
      "process" -> %{processName: value, processPath: artifact[:path] || artifact["path"]}
      _ -> %{value: value}
    end

    # Add description if present
    if desc = artifact[:description] || artifact["description"] do
      Map.put(base, :message, desc)
    else
      base
    end
  end

  defp build_cef_types(type) do
    case type do
      "hash" -> %{fileHash: ["sha256", "sha1", "md5"]}
      "ip" -> %{sourceAddress: ["ip"]}
      "domain" -> %{destinationDnsDomain: ["domain"]}
      "url" -> %{requestURL: ["url"]}
      "email" -> %{emailAddress: ["email"]}
      _ -> %{}
    end
  end

  defp add_alert_artifacts(alert, container_id, state) do
    artifacts = alert[:artifacts] || alert["artifacts"] || []
    iocs = alert[:iocs] || alert["iocs"] || []

    all_artifacts = artifacts ++ Enum.map(iocs, fn ioc ->
      %{type: ioc[:type] || ioc["type"], value: ioc[:value] || ioc["value"]}
    end)

    if length(all_artifacts) > 0 do
      Enum.each(all_artifacts, fn artifact ->
        artifact_data = format_artifact(artifact, container_id)
        post_request(state, @artifact_endpoint, artifact_data)
      end)

      new_stats = Map.update(state.stats, :artifacts_added, length(all_artifacts), &(&1 + length(all_artifacts)))
      %{state | stats: new_stats}
    else
      state
    end
  end

  defp do_pull_actions(state) do
    params = "?_filter_status__in=[\"pending\",\"running\"]&page_size=100"

    case get_request(state, "#{@app_run_endpoint}#{params}") do
      {:ok, %{"data" => actions}} ->
        {:ok, Enum.map(actions, &format_action_request/1)}

      {:ok, response} when is_list(response) ->
        {:ok, response}

      error ->
        error
    end
  end

  defp post_request(state, endpoint, body) do
    make_request(:post, state, endpoint, body)
  end

  defp get_request(state, endpoint) do
    make_request(:get, state, endpoint, nil)
  end

  defp make_request(method, state, endpoint, body) do
    url = "#{state.url}#{endpoint}"

    headers = [
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    headers = if state.auth_header do
      if String.starts_with?(state.auth_header, "ph-auth-token") do
        [{state.auth_header, ""} | headers]
      else
        [{"Authorization", state.auth_header} | headers]
      end
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
      :put -> Finch.build(:put, url, headers, Jason.encode!(body)) |> Finch.request(TamanduaServer.Finch, receive_timeout: timeout)
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
        Logger.error("Splunk SOAR API error: HTTP #{code} - #{resp_body}")
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        Logger.error("Splunk SOAR connection error: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("Splunk SOAR exception: #{inspect(e)}")
      {:error, Exception.message(e)}
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
end
