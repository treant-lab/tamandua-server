defmodule TamanduaServer.Integrations.SOAR.XSOAR do
  @moduledoc """
  Palo Alto XSOAR (Cortex XSOAR / Demisto) Integration

  Provides integration with Palo Alto XSOAR platform:
  - Incident creation and management
  - Playbook triggering and monitoring
  - Indicator/artifact submission
  - War room entry creation
  - Integration instance management

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.SOAR.XSOAR,
        url: "https://xsoar.example.com",
        api_key: "your-api-key",
        verify_ssl: true

  """

  use GenServer
  require Logger

  @behaviour TamanduaServer.Integrations.SOAR.Behaviour

  # XSOAR API endpoints
  @incidents_endpoint "/incidents"
  @playbooks_endpoint "/playbook"
  @indicators_endpoint "/indicators"
  @entry_endpoint "/entry"
  @investigation_endpoint "/investigation"

  @default_timeout_ms 30_000

  defstruct [
    :config,
    :url,
    :api_key,
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
  Create a war room entry for an incident.
  """
  @spec create_entry(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def create_entry(incident_id, content, opts \\ []) do
    GenServer.call(__MODULE__, {:create_entry, incident_id, content, opts}, 30_000)
  end

  @doc """
  Search for incidents.
  """
  @spec search_incidents(map()) :: {:ok, [map()]} | {:error, term()}
  def search_incidents(query) do
    GenServer.call(__MODULE__, {:search_incidents, query}, 30_000)
  end

  @doc """
  Submit indicators.
  """
  @spec submit_indicators([map()]) :: {:ok, map()} | {:error, term()}
  def submit_indicators(indicators) do
    GenServer.call(__MODULE__, {:submit_indicators, indicators}, 30_000)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting XSOAR Integration")

    config = load_config(opts)

    state = %__MODULE__{
      config: config,
      url: config.url,
      api_key: config.api_key,
      stats: %{
        incidents_created: 0,
        playbooks_triggered: 0,
        indicators_submitted: 0,
        last_activity: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:trigger_playbook, playbook_name, params}, _from, state) do
    body = %{
      name: playbook_name,
      investigationId: params[:incident_id] || params["incident_id"],
      inputs: params[:inputs] || params["inputs"] || %{}
    }

    case post_request(state, "#{@playbooks_endpoint}/run", body) do
      {:ok, response} ->
        new_stats = update_stat(state.stats, :playbooks_triggered)
        {:reply, {:ok, response["id"] || response["investigationId"]}, %{state | stats: new_stats}}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:get_playbook_status, run_id}, _from, state) do
    case get_request(state, "#{@investigation_endpoint}/#{run_id}") do
      {:ok, response} ->
        status = %{
          id: response["id"],
          status: response["status"],
          playbook_id: response["playbookId"],
          started_at: response["created"],
          completed_at: response["closed"],
          result: response["result"]
        }
        {:reply, {:ok, status}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:create_incident, incident_data}, _from, state) do
    xsoar_incident = format_incident(incident_data)

    case post_request(state, @incidents_endpoint, xsoar_incident) do
      {:ok, response} ->
        new_stats = update_stat(state.stats, :incidents_created)
        {:reply, {:ok, response["id"]}, %{state | stats: new_stats}}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:update_incident, incident_id, updates}, _from, state) do
    body = Map.merge(updates, %{id: incident_id})

    case post_request(state, "#{@incidents_endpoint}/update", body) do
      {:ok, _} -> {:reply, :ok, state}
      error -> {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:get_incident, incident_id}, _from, state) do
    body = %{
      filter: %{
        query: "id:#{incident_id}"
      },
      size: 1
    }

    case post_request(state, "#{@incidents_endpoint}/search", body) do
      {:ok, %{"data" => [incident | _]}} ->
        {:reply, {:ok, incident}, state}

      {:ok, %{"data" => []}} ->
        {:reply, {:error, :not_found}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:add_artifact, incident_id, artifact}, _from, state) do
    indicator = format_indicator(artifact)
    indicator = Map.put(indicator, "investigationIds", [incident_id])

    case post_request(state, @indicators_endpoint, indicator) do
      {:ok, response} ->
        {:reply, {:ok, response["id"]}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:list_playbooks, opts}, _from, state) do
    query = opts[:query] || ""
    size = opts[:size] || 50

    body = %{
      query: query,
      size: size
    }

    case post_request(state, "#{@playbooks_endpoint}/search", body) do
      {:ok, %{"playbooks" => playbooks}} ->
        formatted = Enum.map(playbooks, fn pb ->
          %{
            id: pb["id"],
            name: pb["name"],
            description: pb["description"],
            version: pb["version"],
            enabled: pb["hidden"] != true
          }
        end)
        {:reply, {:ok, formatted}, state}

      {:ok, response} ->
        {:reply, {:ok, response["playbooks"] || []}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call(:test_connection, _from, state) do
    case get_request(state, "/system/config") do
      {:ok, _} ->
        {:reply, {:ok, "Connected to XSOAR"}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_call({:create_entry, incident_id, content, opts}, _from, state) do
    entry = %{
      investigationId: incident_id,
      data: content,
      type: opts[:type] || 1,  # 1 = note
      category: opts[:category] || "notes"
    }

    case post_request(state, @entry_endpoint, entry) do
      {:ok, response} ->
        {:reply, {:ok, response}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:search_incidents, query}, _from, state) do
    body = %{
      filter: query,
      size: query[:size] || 100
    }

    case post_request(state, "#{@incidents_endpoint}/search", body) do
      {:ok, %{"data" => incidents}} ->
        {:reply, {:ok, incidents}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:submit_indicators, indicators}, _from, state) do
    formatted = Enum.map(indicators, &format_indicator/1)

    case post_request(state, "#{@indicators_endpoint}/batch", formatted) do
      {:ok, response} ->
        count = length(indicators)
        new_stats = Map.update(state.stats, :indicators_submitted, count, &(&1 + count))
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
      api_key: opts[:api_key] || app_config[:api_key],
      timeout_ms: opts[:timeout_ms] || app_config[:timeout_ms] || @default_timeout_ms,
      verify_ssl: opts[:verify_ssl] != false && app_config[:verify_ssl] != false
    }
  end

  defp format_incident(data) do
    %{
      name: data[:title] || data["title"],
      type: data[:type] || data["type"] || "Tamandua Alert",
      severity: map_severity(data[:severity] || data["severity"]),
      details: data[:description] || data["description"],
      occurred: data[:timestamp] || DateTime.utc_now() |> DateTime.to_iso8601(),
      labels: build_labels(data),
      customFields: %{
        tamanduaalertid: data[:id] || data["id"],
        hostname: data[:hostname] || data["hostname"],
        agentid: data[:agent_id] || data["agent_id"],
        mitretactics: Enum.join(data[:mitre_tactics] || data["mitre_tactics"] || [], ", "),
        mitretechniques: Enum.join(data[:mitre_techniques] || data["mitre_techniques"] || [], ", "),
        threatscore: data[:threat_score] || data["threat_score"]
      }
    }
  end

  defp map_severity(severity) do
    case severity do
      "critical" -> 4
      "high" -> 3
      "medium" -> 2
      "low" -> 1
      "info" -> 0
      _ -> 2
    end
  end

  defp build_labels(data) do
    labels = [
      %{type: "source", value: "tamandua-edr"}
    ]

    labels = if hostname = data[:hostname] || data["hostname"] do
      [%{type: "hostname", value: hostname} | labels]
    else
      labels
    end

    labels = if agent_id = data[:agent_id] || data["agent_id"] do
      [%{type: "agent_id", value: agent_id} | labels]
    else
      labels
    end

    tactics = data[:mitre_tactics] || data["mitre_tactics"] || []
    labels = Enum.reduce(tactics, labels, fn tactic, acc ->
      [%{type: "mitre_tactic", value: tactic} | acc]
    end)

    techniques = data[:mitre_techniques] || data["mitre_techniques"] || []
    Enum.reduce(techniques, labels, fn technique, acc ->
      [%{type: "mitre_technique", value: technique} | acc]
    end)
  end

  defp format_indicator(artifact) do
    type = artifact[:type] || artifact["type"] || infer_indicator_type(artifact)
    value = artifact[:value] || artifact["value"]

    %{
      indicator_type: map_indicator_type(type),
      value: value,
      source: artifact[:source] || artifact["source"] || "Tamandua EDR",
      score: artifact[:score] || artifact["score"] || 0,
      comment: artifact[:description] || artifact["description"],
      customFields: artifact[:custom_fields] || artifact["custom_fields"] || %{}
    }
  end

  defp infer_indicator_type(artifact) do
    value = artifact[:value] || artifact["value"] || ""

    cond do
      String.match?(value, ~r/^[a-fA-F0-9]{64}$/) -> :sha256
      String.match?(value, ~r/^[a-fA-F0-9]{40}$/) -> :sha1
      String.match?(value, ~r/^[a-fA-F0-9]{32}$/) -> :md5
      String.match?(value, ~r/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) -> :ip
      String.contains?(value, "@") -> :email
      String.starts_with?(value, "http") -> :url
      true -> :domain
    end
  end

  defp map_indicator_type(type) do
    case type do
      :sha256 -> "File SHA256"
      :sha1 -> "File SHA-1"
      :md5 -> "File MD5"
      :ip -> "IP"
      :domain -> "Domain"
      :url -> "URL"
      :email -> "Email"
      :cve -> "CVE"
      t when is_binary(t) -> t
      _ -> "Domain"
    end
  end

  defp post_request(state, endpoint, body) do
    alias TamanduaServer.Integrations.IntegrationLog

    url = "#{state.url}#{endpoint}"

    headers = [
      {"authorization", state.api_key},
      {"content-type", "application/json"},
      {"accept", "application/json"}
    ]

    encoded_body = Jason.encode!(body)
    request = Finch.build(:post, url, headers, encoded_body)

    IntegrationLog.log_api_call("xsoar", "post:#{endpoint}", body, fn ->
      case Finch.request(request, TamanduaServer.Finch, receive_timeout: state.config.timeout_ms) do
        {:ok, %Finch.Response{status: code, body: resp_body}} when code in 200..299 ->
          {:ok, Jason.decode!(resp_body)}

        {:ok, %Finch.Response{status: code, body: resp_body}} ->
          Logger.error("XSOAR API error: HTTP #{code} - #{resp_body}")
          {:error, "HTTP #{code}: #{resp_body}"}

        {:error, %Mint.TransportError{reason: reason}} ->
          Logger.error("XSOAR connection error: #{inspect(reason)}")
          {:error, inspect(reason)}

        {:error, reason} ->
          Logger.error("XSOAR connection error: #{inspect(reason)}")
          {:error, inspect(reason)}
      end
    end)
  rescue
    e ->
      Logger.error("XSOAR exception: #{inspect(e)}")
      {:error, Exception.message(e)}
  end

  defp get_request(state, endpoint) do
    alias TamanduaServer.Integrations.IntegrationLog

    url = "#{state.url}#{endpoint}"

    headers = [
      {"authorization", state.api_key},
      {"accept", "application/json"}
    ]

    request = Finch.build(:get, url, headers)

    IntegrationLog.log_api_call("xsoar", "get:#{endpoint}", nil, fn ->
      case Finch.request(request, TamanduaServer.Finch, receive_timeout: state.config.timeout_ms) do
        {:ok, %Finch.Response{status: code, body: resp_body}} when code in 200..299 ->
          {:ok, Jason.decode!(resp_body)}

        {:ok, %Finch.Response{status: code, body: resp_body}} ->
          {:error, "HTTP #{code}: #{resp_body}"}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, inspect(reason)}

        {:error, reason} ->
          {:error, inspect(reason)}
      end
    end)
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp update_stat(stats, key) do
    stats
    |> Map.update(key, 1, &(&1 + 1))
    |> Map.put(:last_activity, DateTime.utc_now())
  end
end
