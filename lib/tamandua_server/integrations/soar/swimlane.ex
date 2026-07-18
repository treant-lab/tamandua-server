defmodule TamanduaServer.Integrations.SOAR.Swimlane do
  @moduledoc """
  Swimlane SOAR Integration

  Provides integration with Swimlane platform:
  - Record creation and management
  - Workflow/playbook triggering
  - Application management
  - Task management

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.SOAR.Swimlane,
        url: "https://swimlane.example.com/api",
        username: "api-user",
        password: "api-password",
        # or personal access token:
        token: "your-pat",
        application_id: "your-app-id",
        verify_ssl: true

  """

  use GenServer
  require Logger

  @behaviour TamanduaServer.Integrations.SOAR.Behaviour

  @default_timeout_ms 30_000

  defstruct [
    :config,
    :url,
    :auth_header,
    :application_id,
    :stats
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
  Search records in an application.
  """
  @spec search_records(String.t(), map()) :: {:ok, [map()]} | {:error, term()}
  def search_records(app_id, query) do
    GenServer.call(__MODULE__, {:search_records, app_id, query}, 30_000)
  end

  @doc """
  List available applications.
  """
  @spec list_applications() :: {:ok, [map()]} | {:error, term()}
  def list_applications do
    GenServer.call(__MODULE__, :list_applications, 30_000)
  end

  @doc """
  Create a task for a record.
  """
  @spec create_task(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def create_task(record_id, task_data) do
    GenServer.call(__MODULE__, {:create_task, record_id, task_data}, 30_000)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting Swimlane Integration")

    config = load_config(opts)
    auth_header = build_auth_header(config)

    state = %__MODULE__{
      config: config,
      url: config.url,
      auth_header: auth_header,
      application_id: config.application_id,
      stats: %{
        records_created: 0,
        workflows_triggered: 0,
        tasks_created: 0,
        last_activity: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:trigger_playbook, playbook_name, params}, _from, state) do
    # In Swimlane, playbooks are workflows
    _app_id = params[:application_id] || state.application_id
    record_id = params[:record_id]

    body = %{
      workflowName: playbook_name,
      recordId: record_id,
      inputs: params[:inputs] || %{}
    }

    case post_request(state, "/workflow/run", body) do
      {:ok, response} ->
        new_stats = update_stat(state.stats, :workflows_triggered)
        {:reply, {:ok, response["id"] || response["runId"]}, %{state | stats: new_stats}}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:get_playbook_status, run_id}, _from, state) do
    case get_request(state, "/workflow/run/#{run_id}") do
      {:ok, response} ->
        status = %{
          id: response["id"],
          status: response["status"],
          workflow_name: response["workflowName"],
          started_at: response["startTime"],
          completed_at: response["endTime"],
          result: response["result"]
        }
        {:reply, {:ok, status}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:create_incident, incident_data}, _from, state) do
    app_id = incident_data[:application_id] || state.application_id

    record = format_record(incident_data)

    case post_request(state, "/app/#{app_id}/record", record) do
      {:ok, response} ->
        new_stats = update_stat(state.stats, :records_created)
        {:reply, {:ok, response["id"]}, %{state | stats: new_stats}}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:update_incident, incident_id, updates}, _from, state) do
    app_id = updates[:application_id] || state.application_id

    case patch_request(state, "/app/#{app_id}/record/#{incident_id}", updates) do
      {:ok, _} -> {:reply, :ok, state}
      error -> {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:get_incident, incident_id}, _from, state) do
    app_id = state.application_id

    case get_request(state, "/app/#{app_id}/record/#{incident_id}") do
      {:ok, record} ->
        {:reply, {:ok, record}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:add_artifact, incident_id, artifact}, _from, state) do
    app_id = state.application_id

    # Get current record
    case get_request(state, "/app/#{app_id}/record/#{incident_id}") do
      {:ok, record} ->
        # Add artifact to artifacts field
        artifacts = record["artifacts"] || []
        new_artifact = format_artifact(artifact)
        updated_artifacts = [new_artifact | artifacts]

        case patch_request(state, "/app/#{app_id}/record/#{incident_id}", %{artifacts: updated_artifacts}) do
          {:ok, _} ->
            artifact_id = :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
            {:reply, {:ok, artifact_id}, state}

          error ->
            {:reply, error, state}
        end

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:list_playbooks, opts}, _from, state) do
    app_id = opts[:application_id] || state.application_id

    case get_request(state, "/app/#{app_id}/workflow") do
      {:ok, workflows} when is_list(workflows) ->
        formatted = Enum.map(workflows, fn wf ->
          %{
            id: wf["id"],
            name: wf["name"],
            description: wf["description"],
            enabled: wf["enabled"]
          }
        end)
        {:reply, {:ok, formatted}, state}

      {:ok, response} ->
        {:reply, {:ok, response["workflows"] || []}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call(:test_connection, _from, state) do
    case get_request(state, "/user") do
      {:ok, _} ->
        {:reply, {:ok, "Connected to Swimlane"}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_call({:search_records, app_id, query}, _from, state) do
    body = %{
      filters: query[:filters] || [],
      sorts: query[:sorts] || [],
      limit: query[:limit] || 100,
      offset: query[:offset] || 0
    }

    case post_request(state, "/app/#{app_id}/search", body) do
      {:ok, %{"results" => records}} ->
        {:reply, {:ok, records}, state}

      {:ok, response} when is_list(response) ->
        {:reply, {:ok, response}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call(:list_applications, _from, state) do
    case get_request(state, "/app") do
      {:ok, apps} when is_list(apps) ->
        formatted = Enum.map(apps, fn app ->
          %{
            id: app["id"],
            name: app["name"],
            description: app["description"],
            acronym: app["acronym"]
          }
        end)
        {:reply, {:ok, formatted}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:create_task, record_id, task_data}, _from, state) do
    app_id = state.application_id

    task = %{
      recordId: record_id,
      name: task_data[:name] || task_data["name"],
      description: task_data[:description] || task_data["description"],
      status: task_data[:status] || task_data["status"] || "pending",
      assignee: task_data[:assignee] || task_data["assignee"],
      dueDate: task_data[:due_date] || task_data["due_date"]
    }

    case post_request(state, "/app/#{app_id}/record/#{record_id}/task", task) do
      {:ok, response} ->
        new_stats = update_stat(state.stats, :tasks_created)
        {:reply, {:ok, response}, %{state | stats: new_stats}}

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
      username: opts[:username] || app_config[:username],
      password: opts[:password] || app_config[:password],
      token: opts[:token] || app_config[:token],
      application_id: opts[:application_id] || app_config[:application_id],
      timeout_ms: opts[:timeout_ms] || app_config[:timeout_ms] || @default_timeout_ms,
      verify_ssl: opts[:verify_ssl] != false && app_config[:verify_ssl] != false
    }
  end

  defp build_auth_header(config) do
    cond do
      config.token ->
        "Bearer #{config.token}"

      config.username && config.password ->
        auth = Base.encode64("#{config.username}:#{config.password}")
        "Basic #{auth}"

      true ->
        nil
    end
  end

  defp format_record(data) do
    %{
      "Title" => data[:title] || data["title"],
      "Description" => data[:description] || data["description"],
      "Severity" => map_severity(data[:severity] || data["severity"]),
      "Status" => "New",
      "Source" => "Tamandua EDR",
      "Tamandua Alert ID" => data[:id] || data["id"],
      "Hostname" => data[:hostname] || data["hostname"],
      "Agent ID" => data[:agent_id] || data["agent_id"],
      "MITRE Tactics" => Enum.join(data[:mitre_tactics] || data["mitre_tactics"] || [], ", "),
      "MITRE Techniques" => Enum.join(data[:mitre_techniques] || data["mitre_techniques"] || [], ", "),
      "Threat Score" => data[:threat_score] || data["threat_score"]
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp format_artifact(artifact) do
    %{
      type: artifact[:type] || artifact["type"],
      value: artifact[:value] || artifact["value"],
      source: artifact[:source] || artifact["source"] || "Tamandua EDR",
      description: artifact[:description] || artifact["description"]
    }
  end

  defp map_severity(severity) do
    case severity do
      "critical" -> "Critical"
      "high" -> "High"
      "medium" -> "Medium"
      "low" -> "Low"
      "info" -> "Informational"
      _ -> "Medium"
    end
  end

  defp post_request(state, endpoint, body) do
    make_request(:post, state, endpoint, body)
  end

  defp patch_request(state, endpoint, body) do
    make_request(:patch, state, endpoint, body)
  end

  defp get_request(state, endpoint) do
    make_request(:get, state, endpoint, nil)
  end

  defp make_request(method, state, endpoint, body) do
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

    encoded_body = if body, do: Jason.encode!(body), else: nil

    request = case method do
      :get -> Finch.build(:get, url, headers)
      :post -> Finch.build(:post, url, headers, encoded_body)
      :patch -> Finch.build(:patch, url, headers, encoded_body)
      :put -> Finch.build(:put, url, headers, encoded_body)
    end

    action = "#{method}:#{endpoint}"

    IntegrationLog.log_api_call("swimlane", action, body, fn ->
      case Finch.request(request, TamanduaServer.Finch, receive_timeout: state.config.timeout_ms) do
        {:ok, %Finch.Response{status: code, body: resp_body}} when code in 200..299 ->
          if resp_body == "" do
            {:ok, %{}}
          else
            {:ok, Jason.decode!(resp_body)}
          end

        {:ok, %Finch.Response{status: code, body: resp_body}} ->
          Logger.error("Swimlane API error: HTTP #{code} - #{resp_body}")
          {:error, "HTTP #{code}: #{resp_body}"}

        {:error, %Mint.TransportError{reason: reason}} ->
          Logger.error("Swimlane connection error: #{inspect(reason)}")
          {:error, inspect(reason)}

        {:error, reason} ->
          Logger.error("Swimlane connection error: #{inspect(reason)}")
          {:error, inspect(reason)}
      end
    end)
  rescue
    e ->
      Logger.error("Swimlane exception: #{inspect(e)}")
      {:error, Exception.message(e)}
  end

  defp update_stat(stats, key) do
    stats
    |> Map.update(key, 1, &(&1 + 1))
    |> Map.put(:last_activity, DateTime.utc_now())
  end
end
