defmodule TamanduaServer.Integrations.CaseManagement.TheHive do
  @moduledoc """
  TheHive Integration for Case Management

  Provides integration with TheHive Security Incident Response Platform:
  - Case creation and management
  - Task assignment and tracking
  - Observable (IOC) management
  - Alert ingestion
  - Cortex analyzer integration

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.CaseManagement.TheHive,
        url: "https://thehive.example.com",
        api_key: "your-api-key",
        organisation: "your-org",
        verify_ssl: true

  """

  use GenServer
  require Logger

  @default_timeout_ms 30_000

  defstruct [:config, :url, :api_key, :organisation, :stats]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Create a new case.
  """
  @spec create_case(map()) :: {:ok, String.t()} | {:error, term()}
  def create_case(case_data) do
    GenServer.call(__MODULE__, {:create_case, case_data}, 30_000)
  end

  @doc """
  Update an existing case.
  """
  @spec update_case(String.t(), map()) :: :ok | {:error, term()}
  def update_case(case_id, updates) do
    GenServer.call(__MODULE__, {:update_case, case_id, updates}, 30_000)
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
  Create a task for a case.
  """
  @spec create_task(String.t(), map()) :: {:ok, String.t()} | {:error, term()}
  def create_task(case_id, task_data) do
    GenServer.call(__MODULE__, {:create_task, case_id, task_data}, 30_000)
  end

  @doc """
  Update a task.
  """
  @spec update_task(String.t(), map()) :: :ok | {:error, term()}
  def update_task(task_id, updates) do
    GenServer.call(__MODULE__, {:update_task, task_id, updates}, 30_000)
  end

  @doc """
  Add an observable (IOC) to a case.
  """
  @spec add_observable(String.t(), map()) :: {:ok, String.t()} | {:error, term()}
  def add_observable(case_id, observable) do
    GenServer.call(__MODULE__, {:add_observable, case_id, observable}, 30_000)
  end

  @doc """
  Create an alert.
  """
  @spec create_alert(map()) :: {:ok, String.t()} | {:error, term()}
  def create_alert(alert_data) do
    GenServer.call(__MODULE__, {:create_alert, alert_data}, 30_000)
  end

  @doc """
  Promote an alert to a case.
  """
  @spec promote_alert(String.t()) :: {:ok, String.t()} | {:error, term()}
  def promote_alert(alert_id) do
    GenServer.call(__MODULE__, {:promote_alert, alert_id}, 30_000)
  end

  @doc """
  Run a Cortex analyzer on an observable.
  """
  @spec run_analyzer(String.t(), String.t()) :: {:ok, String.t()} | {:error, term()}
  def run_analyzer(observable_id, analyzer_name) do
    GenServer.call(__MODULE__, {:run_analyzer, observable_id, analyzer_name}, 60_000)
  end

  @doc """
  Search cases.
  """
  @spec search_cases(map()) :: {:ok, [map()]} | {:error, term()}
  def search_cases(query) do
    GenServer.call(__MODULE__, {:search_cases, query}, 30_000)
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
    Logger.info("Starting TheHive Case Management Integration")
    config = load_config(opts)

    state = %__MODULE__{
      config: config,
      url: config.url,
      api_key: config.api_key,
      organisation: config.organisation,
      stats: %{
        cases_created: 0,
        tasks_created: 0,
        observables_added: 0,
        alerts_created: 0,
        errors: 0,
        last_activity: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:create_case, case_data}, _from, state) do
    body = format_case(case_data)

    case post_request(state, "/api/case", body) do
      {:ok, response} ->
        case_id = response["_id"] || response["id"]
        new_stats = update_stat(state.stats, :cases_created)
        Logger.info("Created TheHive case: #{case_id}")
        {:reply, {:ok, case_id}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:update_case, case_id, updates}, _from, state) do
    body = format_case_update(updates)

    case patch_request(state, "/api/case/#{case_id}", body) do
      {:ok, _} -> {:reply, :ok, state}
      error -> {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:get_case, case_id}, _from, state) do
    case get_request(state, "/api/case/#{case_id}") do
      {:ok, response} -> {:reply, {:ok, format_case_response(response)}, state}
      error -> {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:close_case, case_id, resolution}, _from, state) do
    body = %{
      status: "Resolved",
      resolutionStatus: map_resolution(resolution[:status] || resolution["status"]),
      summary: resolution[:summary] || resolution["summary"],
      impactStatus: resolution[:impact] || resolution["impact"]
    }

    case patch_request(state, "/api/case/#{case_id}", body) do
      {:ok, _} -> {:reply, :ok, state}
      error -> {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:create_task, case_id, task_data}, _from, state) do
    body = format_task(task_data)

    case post_request(state, "/api/case/#{case_id}/task", body) do
      {:ok, response} ->
        task_id = response["_id"] || response["id"]
        new_stats = update_stat(state.stats, :tasks_created)
        {:reply, {:ok, task_id}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:update_task, task_id, updates}, _from, state) do
    body = format_task_update(updates)

    case patch_request(state, "/api/case/task/#{task_id}", body) do
      {:ok, _} -> {:reply, :ok, state}
      error -> {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:add_observable, case_id, observable}, _from, state) do
    body = format_observable(observable)

    case post_request(state, "/api/case/#{case_id}/artifact", body) do
      {:ok, response} ->
        obs_id = response["_id"] || response["id"]
        new_stats = update_stat(state.stats, :observables_added)
        {:reply, {:ok, obs_id}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:create_alert, alert_data}, _from, state) do
    body = format_alert(alert_data)

    case post_request(state, "/api/alert", body) do
      {:ok, response} ->
        alert_id = response["_id"] || response["id"]
        new_stats = update_stat(state.stats, :alerts_created)
        {:reply, {:ok, alert_id}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:promote_alert, alert_id}, _from, state) do
    case post_request(state, "/api/alert/#{alert_id}/createCase", %{}) do
      {:ok, response} ->
        case_id = response["_id"] || response["id"]
        {:reply, {:ok, case_id}, state}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:run_analyzer, observable_id, analyzer_name}, _from, state) do
    body = %{
      analyzerId: analyzer_name,
      artifactId: observable_id
    }

    case post_request(state, "/api/connector/cortex/job", body) do
      {:ok, response} ->
        job_id = response["_id"] || response["id"]
        {:reply, {:ok, job_id}, state}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:search_cases, query}, _from, state) do
    body = %{query: build_thehive_query(query)}

    case post_request(state, "/api/case/_search", body) do
      {:ok, response} when is_list(response) ->
        cases = Enum.map(response, &format_case_response/1)
        {:reply, {:ok, cases}, state}

      {:ok, response} ->
        {:reply, {:ok, response}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call(:test_connection, _from, state) do
    case get_request(state, "/api/status") do
      {:ok, _} -> {:reply, {:ok, "Connected to TheHive"}, state}
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
      url: opts[:url] || app_config[:url],
      api_key: opts[:api_key] || app_config[:api_key],
      organisation: opts[:organisation] || app_config[:organisation],
      timeout_ms: opts[:timeout_ms] || app_config[:timeout_ms] || @default_timeout_ms,
      verify_ssl: opts[:verify_ssl] != false && app_config[:verify_ssl] != false
    }
  end

  defp format_case(data) do
    %{
      title: data[:title] || data["title"],
      description: data[:description] || data["description"],
      severity: map_severity(data[:severity] || data["severity"]),
      tlp: data[:tlp] || data["tlp"] || 2,
      pap: data[:pap] || data["pap"] || 2,
      flag: data[:flag] || false,
      tags: build_tags(data),
      customFields: %{
        "tamandua_alert_id" => %{string: data[:id] || data["id"]},
        "hostname" => %{string: data[:hostname] || data["hostname"]},
        "agent_id" => %{string: data[:agent_id] || data["agent_id"]},
        "threat_score" => %{integer: data[:threat_score] || data["threat_score"]}
      }
    }
  end

  defp format_case_update(updates) do
    result = %{}

    result = if title = updates[:title] || updates["title"] do
      Map.put(result, :title, title)
    else
      result
    end

    result = if status = updates[:status] || updates["status"] do
      Map.put(result, :status, map_case_status(status))
    else
      result
    end

    result = if severity = updates[:severity] || updates["severity"] do
      Map.put(result, :severity, map_severity(severity))
    else
      result
    end

    result
  end

  defp format_case_response(response) do
    %{
      id: response["_id"] || response["id"],
      title: response["title"],
      description: response["description"],
      severity: response["severity"],
      status: response["status"],
      tlp: response["tlp"],
      pap: response["pap"],
      owner: response["owner"],
      tags: response["tags"] || [],
      created_at: response["createdAt"],
      updated_at: response["updatedAt"],
      custom_fields: response["customFields"]
    }
  end

  defp format_task(data) do
    %{
      title: data[:title] || data["title"],
      description: data[:description] || data["description"],
      status: "Waiting",
      flag: data[:flag] || false,
      group: data[:group] || data["group"],
      owner: data[:assignee] || data["assignee"]
    }
  end

  defp format_task_update(updates) do
    result = %{}

    result = if status = updates[:status] || updates["status"] do
      Map.put(result, :status, map_task_status(status))
    else
      result
    end

    result = if owner = updates[:owner] || updates["owner"] do
      Map.put(result, :owner, owner)
    else
      result
    end

    result
  end

  defp format_observable(observable) do
    %{
      dataType: map_observable_type(observable[:type] || observable["type"]),
      data: observable[:value] || observable["value"],
      message: observable[:description] || observable["description"],
      tlp: observable[:tlp] || 2,
      ioc: observable[:ioc] || true,
      sighted: observable[:sighted] || false,
      tags: observable[:tags] || []
    }
  end

  defp format_alert(data) do
    %{
      title: data[:title] || data["title"],
      description: data[:description] || data["description"],
      type: "tamandua",
      source: "Tamandua EDR",
      sourceRef: data[:id] || data["id"],
      severity: map_severity(data[:severity] || data["severity"]),
      tlp: data[:tlp] || 2,
      pap: data[:pap] || 2,
      tags: build_tags(data),
      artifacts: Enum.map(data[:artifacts] || data["artifacts"] || [], fn a ->
        format_observable(a)
      end),
      customFields: %{
        "hostname" => %{string: data[:hostname] || data["hostname"]},
        "agent_id" => %{string: data[:agent_id] || data["agent_id"]},
        "threat_score" => %{integer: data[:threat_score] || data["threat_score"]}
      }
    }
  end

  defp map_severity(severity) do
    case severity do
      "critical" -> 4
      "high" -> 3
      "medium" -> 2
      "low" -> 1
      _ -> 2
    end
  end

  defp map_case_status(status) do
    case status do
      "open" -> "Open"
      "in_progress" -> "InProgress"
      "resolved" -> "Resolved"
      "closed" -> "Deleted"
      _ -> "Open"
    end
  end

  defp map_task_status(status) do
    case status do
      "pending" -> "Waiting"
      "in_progress" -> "InProgress"
      "completed" -> "Completed"
      "cancelled" -> "Cancel"
      _ -> "Waiting"
    end
  end

  defp map_resolution(resolution) do
    case resolution do
      "true_positive" -> "TruePositive"
      "false_positive" -> "FalsePositive"
      "indeterminate" -> "Indeterminate"
      "duplicate" -> "Duplicate"
      _ -> "TruePositive"
    end
  end

  defp map_observable_type(type) do
    case type do
      t when t in ["ip", :ip] -> "ip"
      t when t in ["domain", :domain] -> "domain"
      t when t in ["url", :url] -> "url"
      t when t in ["email", :email] -> "mail"
      t when t in ["hash", "md5", "sha1", "sha256", :hash, :md5, :sha1, :sha256] -> "hash"
      t when t in ["file", :file] -> "filename"
      t when t in ["user", :user] -> "user-agent"
      _ -> "other"
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

  defp build_thehive_query(query) do
    conditions = []

    conditions = if status = query[:status] || query["status"] do
      [%{"_field" => "status", "_value" => map_case_status(status)} | conditions]
    else
      conditions
    end

    conditions = if severity = query[:severity] || query["severity"] do
      [%{"_field" => "severity", "_value" => map_severity(severity)} | conditions]
    else
      conditions
    end

    if length(conditions) > 0 do
      %{"_and" => conditions}
    else
      %{}
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
      {"Authorization", "Bearer #{state.api_key}"},
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    headers = if state.organisation do
      [{"X-Organisation", state.organisation} | headers]
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
        if resp_body == "" do
          {:ok, %{}}
        else
          {:ok, Jason.decode!(resp_body)}
        end

      {:ok, %{status_code: code, body: resp_body}} ->
        Logger.error("TheHive API error: HTTP #{code} - #{resp_body}")
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        Logger.error("TheHive connection error: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("TheHive exception: #{inspect(e)}")
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
