defmodule TamanduaServer.Integrations.SOAR.IBMSOAR do
  @moduledoc """
  IBM Security QRadar SOAR (formerly Resilient) Integration

  Provides bi-directional integration with IBM Security SOAR:
  - Push alerts to SOAR as incidents
  - Pull actions from SOAR (tasks and action invocations)
  - Sync investigation status
  - Artifact sharing
  - Playbook triggering and monitoring
  - Workflow management

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.SOAR.IBMSOAR,
        url: "https://resilient.example.com",
        api_key_id: "your-api-key-id",
        api_key_secret: "your-api-key-secret",
        org_name: "your-org-name",
        verify_ssl: true,
        poll_interval_ms: 30_000

  ## Bi-directional Sync

  The integration supports:
  1. Push: Alerts -> SOAR Incidents
  2. Pull: SOAR Tasks/Actions -> Tamandua Response Commands
  3. Status Sync: Investigation state synchronization
  4. Artifacts: Share IOCs, evidence files, and enrichment data

  """

  use GenServer
  require Logger

  @behaviour TamanduaServer.Integrations.SOAR.Behaviour

  @default_timeout_ms 30_000
  @default_poll_interval_ms 30_000

  # IBM SOAR API endpoints

  defstruct [
    :config,
    :url,
    :api_key_id,
    :api_key_secret,
    :org_id,
    :stats,
    :poll_timer,
    :csrf_token
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
  Push an alert to IBM SOAR as an incident.
  """
  @spec push_alert(map()) :: {:ok, String.t()} | {:error, term()}
  def push_alert(alert) do
    GenServer.call(__MODULE__, {:push_alert, alert}, 30_000)
  end

  @doc """
  Pull pending tasks from IBM SOAR.
  """
  @spec pull_tasks(String.t()) :: {:ok, [map()]} | {:error, term()}
  def pull_tasks(incident_id) do
    GenServer.call(__MODULE__, {:pull_tasks, incident_id}, 30_000)
  end

  @doc """
  Sync investigation status with SOAR.
  """
  @spec sync_investigation(String.t(), map()) :: :ok | {:error, term()}
  def sync_investigation(incident_id, status) do
    GenServer.call(__MODULE__, {:sync_investigation, incident_id, status}, 30_000)
  end

  @doc """
  Share artifacts with SOAR incident.
  """
  @spec share_artifacts(String.t(), [map()]) :: {:ok, [String.t()]} | {:error, term()}
  def share_artifacts(incident_id, artifacts) do
    GenServer.call(__MODULE__, {:share_artifacts, incident_id, artifacts}, 30_000)
  end

  @doc """
  Get incident artifacts.
  """
  @spec get_artifacts(String.t()) :: {:ok, [map()]} | {:error, term()}
  def get_artifacts(incident_id) do
    GenServer.call(__MODULE__, {:get_artifacts, incident_id}, 30_000)
  end

  @doc """
  Create a task for an incident.
  """
  @spec create_task(String.t(), map()) :: {:ok, String.t()} | {:error, term()}
  def create_task(incident_id, task_data) do
    GenServer.call(__MODULE__, {:create_task, incident_id, task_data}, 30_000)
  end

  @doc """
  Update a task status.
  """
  @spec update_task(String.t(), String.t(), map()) :: :ok | {:error, term()}
  def update_task(incident_id, task_id, updates) do
    GenServer.call(__MODULE__, {:update_task, incident_id, task_id, updates}, 30_000)
  end

  @doc """
  Invoke an action/function.
  """
  @spec invoke_action(String.t(), map()) :: {:ok, String.t()} | {:error, term()}
  def invoke_action(action_name, params) do
    GenServer.call(__MODULE__, {:invoke_action, action_name, params}, 60_000)
  end

  @doc """
  List available workflows.
  """
  @spec list_workflows() :: {:ok, [map()]} | {:error, term()}
  def list_workflows do
    GenServer.call(__MODULE__, :list_workflows, 30_000)
  end

  @doc """
  Search incidents.
  """
  @spec search_incidents(map()) :: {:ok, [map()]} | {:error, term()}
  def search_incidents(query) do
    GenServer.call(__MODULE__, {:search_incidents, query}, 30_000)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting IBM Security SOAR Integration")

    config = load_config(opts)

    state = %__MODULE__{
      config: config,
      url: config.url,
      api_key_id: config.api_key_id,
      api_key_secret: config.api_key_secret,
      org_id: nil,  # Will be resolved on first request
      stats: %{
        incidents_created: 0,
        incidents_updated: 0,
        artifacts_added: 0,
        tasks_created: 0,
        playbooks_triggered: 0,
        sync_operations: 0,
        last_activity: nil,
        errors: 0
      },
      poll_timer: nil,
      csrf_token: nil
    }

    # Resolve org ID on startup
    state = resolve_org_id(state)

    {:ok, state}
  end

  @impl true
  def handle_call({:trigger_playbook, playbook_name, params}, _from, state) do
    incident_id = params[:incident_id] || params["incident_id"]

    body = %{
      playbook_id: playbook_name,
      incident_id: incident_id
    }

    endpoint = "/rest/orgs/#{state.org_id}/playbook_instances"

    case post_request(state, endpoint, body) do
      {:ok, response} ->
        new_stats = update_stat(state.stats, :playbooks_triggered)
        run_id = to_string(response["id"])
        {:reply, {:ok, run_id}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:get_playbook_status, run_id}, _from, state) do
    endpoint = "/rest/orgs/#{state.org_id}/playbook_instances/#{run_id}"

    case get_request(state, endpoint) do
      {:ok, response} ->
        status = %{
          id: to_string(response["id"]),
          playbook_id: response["playbook_id"],
          incident_id: response["incident_id"],
          status: response["status"],
          started_at: format_timestamp(response["start_date"]),
          completed_at: format_timestamp(response["end_date"]),
          result: response["result"]
        }
        {:reply, {:ok, status}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:create_incident, incident_data}, _from, state) do
    incident = format_incident(incident_data)
    endpoint = "/rest/orgs/#{state.org_id}/incidents"

    case post_request(state, endpoint, incident) do
      {:ok, response} ->
        incident_id = to_string(response["id"])
        new_stats = update_stat(state.stats, :incidents_created)
        Logger.info("Created IBM SOAR incident: #{incident_id}")
        {:reply, {:ok, incident_id}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:update_incident, incident_id, updates}, _from, state) do
    # IBM SOAR requires patch with handle_format
    body = format_incident_update(updates)
    endpoint = "/rest/orgs/#{state.org_id}/incidents/#{incident_id}"

    case patch_request(state, endpoint, body) do
      {:ok, _} ->
        new_stats = update_stat(state.stats, :incidents_updated)
        {:reply, :ok, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:get_incident, incident_id}, _from, state) do
    endpoint = "/rest/orgs/#{state.org_id}/incidents/#{incident_id}"

    case get_request(state, endpoint) do
      {:ok, response} ->
        {:reply, {:ok, response}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:add_artifact, incident_id, artifact}, _from, state) do
    artifact_data = format_artifact(artifact)
    endpoint = "/rest/orgs/#{state.org_id}/incidents/#{incident_id}/artifacts"

    case post_request(state, endpoint, artifact_data) do
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
    query_params = build_list_params(opts)
    endpoint = "/rest/orgs/#{state.org_id}/playbooks#{query_params}"

    case get_request(state, endpoint) do
      {:ok, %{"entities" => playbooks}} ->
        formatted = Enum.map(playbooks, fn pb ->
          %{
            id: to_string(pb["id"]),
            name: pb["name"],
            display_name: pb["display_name"],
            description: pb["description"],
            enabled: pb["status"] == "enabled",
            version: pb["version"]
          }
        end)
        {:reply, {:ok, formatted}, state}

      {:ok, playbooks} when is_list(playbooks) ->
        {:reply, {:ok, playbooks}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call(:test_connection, _from, state) do
    case get_request(state, "/rest/const") do
      {:ok, _} ->
        {:reply, {:ok, "Connected to IBM Security SOAR"}, state}

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
    incident = format_incident(alert)
    endpoint = "/rest/orgs/#{state.org_id}/incidents"

    case post_request(state, endpoint, incident) do
      {:ok, response} ->
        incident_id = to_string(response["id"])
        new_stats = update_stat(state.stats, :incidents_created)

        # Add artifacts if present
        state = add_alert_artifacts(alert, incident_id, state)

        {:reply, {:ok, incident_id}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:pull_tasks, incident_id}, _from, state) do
    endpoint = "/rest/orgs/#{state.org_id}/incidents/#{incident_id}/tasks"

    case get_request(state, endpoint) do
      {:ok, tasks} when is_list(tasks) ->
        formatted = Enum.map(tasks, &format_task_response/1)
        {:reply, {:ok, formatted}, state}

      {:ok, %{"entities" => tasks}} ->
        formatted = Enum.map(tasks, &format_task_response/1)
        {:reply, {:ok, formatted}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:sync_investigation, incident_id, status}, _from, state) do
    body = format_investigation_sync(status)
    endpoint = "/rest/orgs/#{state.org_id}/incidents/#{incident_id}"

    case patch_request(state, endpoint, body) do
      {:ok, _} ->
        new_stats = update_stat(state.stats, :sync_operations)
        {:reply, :ok, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:share_artifacts, incident_id, artifacts}, _from, state) do
    endpoint = "/rest/orgs/#{state.org_id}/incidents/#{incident_id}/artifacts"

    results = Enum.map(artifacts, fn artifact ->
      artifact_data = format_artifact(artifact)

      case post_request(state, endpoint, artifact_data) do
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
  def handle_call({:get_artifacts, incident_id}, _from, state) do
    endpoint = "/rest/orgs/#{state.org_id}/incidents/#{incident_id}/artifacts"

    case get_request(state, endpoint) do
      {:ok, artifacts} when is_list(artifacts) ->
        formatted = Enum.map(artifacts, &format_artifact_response/1)
        {:reply, {:ok, formatted}, state}

      {:ok, %{"entities" => artifacts}} ->
        formatted = Enum.map(artifacts, &format_artifact_response/1)
        {:reply, {:ok, formatted}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:create_task, incident_id, task_data}, _from, state) do
    task = format_task(task_data)
    endpoint = "/rest/orgs/#{state.org_id}/incidents/#{incident_id}/tasks"

    case post_request(state, endpoint, task) do
      {:ok, response} ->
        task_id = to_string(response["id"])
        new_stats = update_stat(state.stats, :tasks_created)
        {:reply, {:ok, task_id}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:update_task, incident_id, task_id, updates}, _from, state) do
    body = format_task_update(updates)
    endpoint = "/rest/orgs/#{state.org_id}/incidents/#{incident_id}/tasks/#{task_id}"

    case patch_request(state, endpoint, body) do
      {:ok, _} -> {:reply, :ok, state}
      error -> {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:invoke_action, action_name, params}, _from, state) do
    body = %{
      function: action_name,
      inputs: params
    }
    endpoint = "/rest/orgs/#{state.org_id}/functions/#{action_name}"

    case post_request(state, endpoint, body) do
      {:ok, response} ->
        action_id = to_string(response["id"] || response["action_id"])
        {:reply, {:ok, action_id}, state}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call(:list_workflows, _from, state) do
    endpoint = "/rest/orgs/#{state.org_id}/workflows"

    case get_request(state, endpoint) do
      {:ok, %{"entities" => workflows}} ->
        formatted = Enum.map(workflows, fn wf ->
          %{
            id: to_string(wf["id"]),
            name: wf["name"],
            description: wf["description"],
            enabled: wf["status"] == "enabled"
          }
        end)
        {:reply, {:ok, formatted}, state}

      {:ok, workflows} when is_list(workflows) ->
        {:reply, {:ok, workflows}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:search_incidents, query}, _from, state) do
    body = build_search_query(query)
    endpoint = "/rest/orgs/#{state.org_id}/incidents/query?return_level=full"

    case post_request(state, endpoint, body) do
      {:ok, %{"data" => incidents}} ->
        {:reply, {:ok, incidents}, state}

      {:ok, incidents} when is_list(incidents) ->
        {:reply, {:ok, incidents}, state}

      error ->
        {:reply, error, state}
    end
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp load_config(opts) do
    app_config = Application.get_env(:tamandua_server, __MODULE__, [])

    %{
      url: opts[:url] || app_config[:url],
      api_key_id: opts[:api_key_id] || app_config[:api_key_id],
      api_key_secret: opts[:api_key_secret] || app_config[:api_key_secret],
      org_name: opts[:org_name] || app_config[:org_name],
      poll_interval_ms: opts[:poll_interval_ms] || app_config[:poll_interval_ms] || @default_poll_interval_ms,
      timeout_ms: opts[:timeout_ms] || app_config[:timeout_ms] || @default_timeout_ms,
      verify_ssl: opts[:verify_ssl] != false && app_config[:verify_ssl] != false
    }
  end

  defp resolve_org_id(state) do
    case get_request(state, "/rest/orgs") do
      {:ok, orgs} when is_list(orgs) ->
        org = if state.config.org_name do
          Enum.find(orgs, fn o -> o["name"] == state.config.org_name end)
        else
          List.first(orgs)
        end

        if org do
          %{state | org_id: org["id"]}
        else
          Logger.error("Could not resolve IBM SOAR organization ID")
          state
        end

      {:ok, %{"entities" => orgs}} ->
        org = if state.config.org_name do
          Enum.find(orgs, fn o -> o["name"] == state.config.org_name end)
        else
          List.first(orgs)
        end

        if org do
          %{state | org_id: org["id"]}
        else
          state
        end

      _ ->
        Logger.error("Could not resolve IBM SOAR organization ID")
        state
    end
  end

  defp format_incident(data) do
    %{
      name: data[:title] || data["title"] || "Tamandua Alert",
      description: %{
        format: "text",
        content: data[:description] || data["description"] || ""
      },
      severity_code: %{
        name: map_severity(data[:severity] || data["severity"])
      },
      incident_type_ids: [data[:incident_type] || 17],  # 17 = Malware
      discovered_date: DateTime.utc_now() |> DateTime.to_unix(:millisecond),
      properties: %{
        tamandua_alert_id: data[:id] || data["id"],
        hostname: data[:hostname] || data["hostname"],
        agent_id: data[:agent_id] || data["agent_id"],
        mitre_tactics: Enum.join(data[:mitre_tactics] || data["mitre_tactics"] || [], ", "),
        mitre_techniques: Enum.join(data[:mitre_techniques] || data["mitre_techniques"] || [], ", "),
        threat_score: data[:threat_score] || data["threat_score"]
      }
    }
  end

  defp format_incident_update(updates) do
    changes = %{}

    changes = if status = updates[:status] || updates["status"] do
      Map.put(changes, :plan_status, map_incident_status(status))
    else
      changes
    end

    changes = if resolution = updates[:resolution] || updates["resolution"] do
      Map.merge(changes, %{
        resolution_id: map_resolution(resolution),
        resolution_summary: %{format: "text", content: updates[:resolution_notes] || updates["resolution_notes"] || ""}
      })
    else
      changes
    end

    changes = if severity = updates[:severity] || updates["severity"] do
      Map.put(changes, :severity_code, %{name: map_severity(severity)})
    else
      changes
    end

    %{changes: changes}
  end

  defp format_investigation_sync(status) do
    changes = %{}

    changes = if plan_status = status[:status] || status["status"] do
      Map.put(changes, :plan_status, map_incident_status(plan_status))
    else
      changes
    end

    changes = if owner = status[:owner] || status["owner"] do
      Map.put(changes, :owner_id, owner)
    else
      changes
    end

    if resolution = status[:resolution] || status["resolution"] do
      Map.merge(changes, %{
        resolution_id: map_resolution(resolution),
        resolution_summary: %{format: "text", content: status[:resolution_notes] || status["resolution_notes"] || ""}
      })
    else
      changes
    end

    %{changes: changes}
  end

  defp format_artifact(artifact) do
    type_id = map_artifact_type(artifact[:type] || artifact["type"])
    value = artifact[:value] || artifact["value"]

    %{
      type: type_id,
      value: value,
      description: %{
        format: "text",
        content: artifact[:description] || artifact["description"] || ""
      },
      properties: artifact[:properties] || artifact["properties"] || %{}
    }
  end

  defp format_artifact_response(artifact) do
    %{
      id: to_string(artifact["id"]),
      type: artifact["type"],
      value: artifact["value"],
      description: get_text_content(artifact["description"]),
      created_date: format_timestamp(artifact["created"]),
      properties: artifact["properties"]
    }
  end

  defp format_task(task_data) do
    %{
      name: task_data[:name] || task_data["name"],
      phase_id: task_data[:phase_id] || task_data["phase_id"] || 1000,  # Default phase
      instructions: %{
        format: "text",
        content: task_data[:instructions] || task_data["instructions"] || task_data[:description] || task_data["description"] || ""
      },
      due_date: task_data[:due_date] || task_data["due_date"],
      owner_id: task_data[:owner_id] || task_data["owner_id"]
    }
  end

  defp format_task_update(updates) do
    changes = %{}

    changes = if status = updates[:status] || updates["status"] do
      Map.put(changes, :status, map_task_status(status))
    else
      changes
    end

    changes = if notes = updates[:notes] || updates["notes"] do
      Map.put(changes, :notes, %{format: "text", content: notes})
    else
      changes
    end

    %{changes: changes}
  end

  defp format_task_response(task) do
    %{
      id: to_string(task["id"]),
      name: task["name"],
      status: task["status"],
      phase_id: task["phase_id"],
      instructions: get_text_content(task["instructions"]),
      due_date: format_timestamp(task["due_date"]),
      owner_id: task["owner_id"],
      created_date: format_timestamp(task["created"])
    }
  end

  defp map_severity(severity) do
    case severity do
      "critical" -> "High"
      "high" -> "High"
      "medium" -> "Medium"
      "low" -> "Low"
      "info" -> "Low"
      _ -> "Medium"
    end
  end

  defp map_incident_status(status) do
    case status do
      "open" -> "A"  # Active
      "in_progress" -> "A"
      "resolved" -> "C"  # Closed
      "closed" -> "C"
      _ -> "A"
    end
  end

  defp map_resolution(resolution) do
    case resolution do
      "resolved" -> 1  # Resolved
      "duplicate" -> 2  # Duplicate
      "not_an_issue" -> 3  # Not an Issue
      "no_action" -> 4  # No Action Needed
      _ -> 1
    end
  end

  defp map_task_status(status) do
    case status do
      "pending" -> "O"  # Open
      "in_progress" -> "O"
      "completed" -> "C"  # Complete
      _ -> "O"
    end
  end

  defp map_artifact_type(type) do
    case type do
      "ip" -> 1  # IP Address
      :ip -> 1
      "domain" -> 2  # DNS Name
      :domain -> 2
      "url" -> 3  # URL
      :url -> 3
      "email" -> 4  # Email Address
      :email -> 4
      "hash" -> 5  # Malware MD5 Hash
      :hash -> 5
      "sha256" -> 13  # Malware SHA-256 Hash
      :sha256 -> 13
      "file" -> 6  # File Name
      :file -> 6
      "process" -> 7  # Process Name
      :process -> 7
      "user" -> 8  # User Account
      :user -> 8
      _ -> 0  # String
    end
  end

  defp build_list_params(opts) do
    params = []

    params = if limit = opts[:limit] do
      ["length=#{limit}" | params]
    else
      params
    end

    params = if offset = opts[:offset] do
      ["start=#{offset}" | params]
    else
      params
    end

    if length(params) > 0, do: "?" <> Enum.join(params, "&"), else: ""
  end

  defp build_search_query(query) do
    filters = []

    filters = if status = query[:status] || query["status"] do
      [%{conditions: [%{field_name: "plan_status", method: "equals", value: map_incident_status(status)}]} | filters]
    else
      filters
    end

    filters = if severity = query[:severity] || query["severity"] do
      [%{conditions: [%{field_name: "severity_code", method: "equals", value: map_severity(severity)}]} | filters]
    else
      filters
    end

    %{
      filters: filters,
      sorts: [%{field_name: "create_date", type: "desc"}]
    }
  end

  defp get_text_content(nil), do: nil
  defp get_text_content(text) when is_binary(text), do: text
  defp get_text_content(%{"content" => content}), do: content
  defp get_text_content(_), do: nil

  defp format_timestamp(nil), do: nil
  defp format_timestamp(ts) when is_integer(ts) do
    DateTime.from_unix!(div(ts, 1000)) |> DateTime.to_iso8601()
  end
  defp format_timestamp(ts), do: ts

  defp add_alert_artifacts(alert, incident_id, state) do
    artifacts = alert[:artifacts] || alert["artifacts"] || []
    iocs = alert[:iocs] || alert["iocs"] || []

    all_artifacts = artifacts ++ Enum.map(iocs, fn ioc ->
      %{type: ioc[:type] || ioc["type"], value: ioc[:value] || ioc["value"]}
    end)

    endpoint = "/rest/orgs/#{state.org_id}/incidents/#{incident_id}/artifacts"

    if length(all_artifacts) > 0 do
      Enum.each(all_artifacts, fn artifact ->
        artifact_data = format_artifact(artifact)
        post_request(state, endpoint, artifact_data)
      end)

      new_stats = Map.update(state.stats, :artifacts_added, length(all_artifacts), &(&1 + length(all_artifacts)))
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

  defp patch_request(state, endpoint, body) do
    make_request(:patch, state, endpoint, body)
  end

  defp make_request(method, state, endpoint, body) do
    url = "#{state.url}#{endpoint}"

    headers = [
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    # IBM SOAR uses API key authentication
    headers = if state.api_key_id && state.api_key_secret do
      [{"Authorization", "Basic #{Base.encode64("#{state.api_key_id}:#{state.api_key_secret}")}"} | headers]
    else
      headers
    end

    # Add CSRF token if available
    headers = if state.csrf_token do
      [{"X-sess-id", state.csrf_token} | headers]
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
        Logger.error("IBM SOAR API error: HTTP #{code} - #{resp_body}")
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        Logger.error("IBM SOAR connection error: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("IBM SOAR exception: #{inspect(e)}")
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
