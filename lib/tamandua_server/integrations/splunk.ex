defmodule TamanduaServer.Integrations.Splunk do
  @moduledoc """
  Splunk Integration Module

  Provides integration with Splunk platform:
  - HTTP Event Collector (HEC) for event/alert forwarding
  - Splunk SOAR (Phantom) webhook integration for automated response
  - Support for Splunk saved search triggers via REST API
  - Index and sourcetype management

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.Splunk,
        hec_url: "https://splunk.example.com:8088",
        hec_token: "your-hec-token",
        index: "tamandua",
        sourcetype: "tamandua:edr",
        verify_ssl: true,
        soar_url: "https://phantom.example.com",
        soar_token: "your-phantom-token"

  """

  use GenServer
  require Logger


  @behaviour TamanduaServer.Integrations.SIEMBehaviour

  # HEC endpoints
  @hec_event_endpoint "/services/collector/event"
  @hec_health_endpoint "/services/collector/health"

  # Splunk REST API endpoints
  @saved_searches_endpoint "/servicesNS/-/-/saved/searches"

  # SOAR endpoints
  @phantom_container_endpoint "/rest/container"
  @phantom_artifact_endpoint "/rest/artifact"
  @phantom_playbook_endpoint "/rest/playbook_run"

  # Default configuration
  @default_batch_size 100
  @default_batch_interval_ms 5000
  @default_timeout_ms 30_000

  defstruct [
    :config,
    :hec_url,
    :hec_token,
    :soar_url,
    :soar_token,
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
  Send a single event to Splunk HEC.
  """
  @spec send_event(map()) :: :ok | {:error, term()}
  def send_event(event) do
    GenServer.call(__MODULE__, {:send_event, event})
  end

  @doc """
  Send a batch of events to Splunk HEC.
  """
  @spec send_batch([map()]) :: :ok | {:error, term()}
  def send_batch(events) when is_list(events) do
    GenServer.call(__MODULE__, {:send_batch, events}, 60_000)
  end

  @doc """
  Forward an alert to Splunk.
  """
  @spec forward_alert(map()) :: :ok | {:error, term()}
  def forward_alert(alert) do
    GenServer.call(__MODULE__, {:forward_alert, alert})
  end

  @doc """
  Forward an alert to Splunk SOAR (Phantom).
  Creates a container and associated artifacts.
  """
  @spec forward_to_soar(map()) :: {:ok, String.t()} | {:error, term()}
  def forward_to_soar(alert) do
    GenServer.call(__MODULE__, {:forward_to_soar, alert}, 60_000)
  end

  @doc """
  Trigger a Splunk SOAR playbook.
  """
  @spec trigger_playbook(String.t(), map()) :: {:ok, String.t()} | {:error, term()}
  def trigger_playbook(playbook_name, params \\ %{}) do
    GenServer.call(__MODULE__, {:trigger_playbook, playbook_name, params}, 60_000)
  end

  @doc """
  List available Splunk saved searches.
  """
  @spec list_saved_searches() :: {:ok, [map()]} | {:error, term()}
  def list_saved_searches do
    GenServer.call(__MODULE__, :list_saved_searches, 30_000)
  end

  @doc """
  Run a Splunk saved search.
  """
  @spec run_saved_search(String.t()) :: {:ok, map()} | {:error, term()}
  def run_saved_search(search_name) do
    GenServer.call(__MODULE__, {:run_saved_search, search_name}, 120_000)
  end

  @doc """
  Get Splunk HEC health status.
  """
  @spec health_check() :: {:ok, map()} | {:error, term()}
  def health_check do
    GenServer.call(__MODULE__, :health_check)
  end

  @doc """
  Test connection to Splunk.
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

  @doc """
  Update configuration dynamically.
  """
  @spec update_config(map()) :: :ok
  def update_config(new_config) do
    GenServer.cast(__MODULE__, {:update_config, new_config})
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
    Logger.info("Starting Splunk Integration")

    config = load_config(opts)

    # Schedule batch flush
    if config.batch_interval_ms > 0 do
      schedule_batch_flush(config.batch_interval_ms)
    end

    state = %__MODULE__{
      config: config,
      hec_url: config.hec_url,
      hec_token: config.hec_token,
      soar_url: config.soar_url,
      soar_token: config.soar_token,
      event_buffer: [],
      stats: %{
        events_sent: 0,
        events_failed: 0,
        alerts_sent: 0,
        soar_containers_created: 0,
        playbooks_triggered: 0,
        last_send: nil,
        last_error: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:send_event, event}, _from, state) do
    formatted = format_hec_event(event, state.config)
    new_buffer = [formatted | state.event_buffer]

    if length(new_buffer) >= state.config.batch_size do
      # Flush immediately
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
    formatted = Enum.map(events, &format_hec_event(&1, state.config))

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
    event = format_alert_event(alert, state.config)

    case send_hec_event(state, event) do
      :ok ->
        new_stats = update_stats(state.stats, :alerts_sent, 1)
        {:reply, :ok, %{state | stats: new_stats}}

      {:error, _reason} = error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:forward_to_soar, alert}, _from, state) do
    if state.soar_url && state.soar_token do
      case create_phantom_container(alert, state) do
        {:ok, container_id} ->
          # Create artifacts for the container
          create_phantom_artifacts(container_id, alert, state)

          new_stats = update_stats(state.stats, :soar_containers_created, 1)
          {:reply, {:ok, container_id}, %{state | stats: new_stats}}

        {:error, _reason} = error ->
          {:reply, error, state}
      end
    else
      {:reply, {:error, :soar_not_configured}, state}
    end
  end

  @impl true
  def handle_call({:trigger_playbook, playbook_name, params}, _from, state) do
    if state.soar_url && state.soar_token do
      case run_phantom_playbook(playbook_name, params, state) do
        {:ok, run_id} ->
          new_stats = update_stats(state.stats, :playbooks_triggered, 1)
          {:reply, {:ok, run_id}, %{state | stats: new_stats}}

        {:error, _reason} = error ->
          {:reply, error, state}
      end
    else
      {:reply, {:error, :soar_not_configured}, state}
    end
  end

  @impl true
  def handle_call(:list_saved_searches, _from, state) do
    result = fetch_saved_searches(state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:run_saved_search, search_name}, _from, state) do
    result = execute_saved_search(search_name, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:health_check, _from, state) do
    result = check_hec_health(state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:test_connection, _from, state) do
    test_event = %{
      event: "Tamandua EDR test connection",
      source: "tamandua:test",
      sourcetype: "tamandua:test",
      time: System.os_time(:second)
    }

    case send_hec_event(state, test_event) do
      :ok -> {:reply, {:ok, "Connection successful"}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_cast({:update_config, new_config}, state) do
    updated_config = Map.merge(state.config, new_config)
    {:noreply, %{state | config: updated_config}}
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
      hec_url: opts[:hec_url] || app_config[:hec_url],
      hec_token: opts[:hec_token] || app_config[:hec_token],
      index: opts[:index] || app_config[:index] || "tamandua",
      sourcetype: opts[:sourcetype] || app_config[:sourcetype] || "tamandua:edr",
      source: opts[:source] || app_config[:source] || "tamandua",
      host: opts[:host] || app_config[:host],
      verify_ssl: opts[:verify_ssl] != false && app_config[:verify_ssl] != false,
      batch_size: opts[:batch_size] || app_config[:batch_size] || @default_batch_size,
      batch_interval_ms: opts[:batch_interval_ms] || app_config[:batch_interval_ms] || @default_batch_interval_ms,
      timeout_ms: opts[:timeout_ms] || app_config[:timeout_ms] || @default_timeout_ms,
      soar_url: opts[:soar_url] || app_config[:soar_url],
      soar_token: opts[:soar_token] || app_config[:soar_token],
      rest_url: opts[:rest_url] || app_config[:rest_url],
      rest_username: opts[:rest_username] || app_config[:rest_username],
      rest_password: opts[:rest_password] || app_config[:rest_password]
    }
  end

  defp schedule_batch_flush(interval) do
    Process.send_after(self(), :flush_batch, interval)
  end

  defp format_hec_event(event, config) do
    base = %{
      time: get_event_time(event),
      source: config.source,
      sourcetype: config.sourcetype,
      index: config.index,
      event: event
    }

    # Add host if configured
    if config.host do
      Map.put(base, :host, config.host)
    else
      case event do
        %{hostname: hostname} when is_binary(hostname) -> Map.put(base, :host, hostname)
        %{"hostname" => hostname} when is_binary(hostname) -> Map.put(base, :host, hostname)
        _ -> base
      end
    end
  end

  defp format_alert_event(alert, config) do
    %{
      time: get_alert_time(alert),
      source: config.source,
      sourcetype: "tamandua:alert",
      index: config.index,
      host: alert[:hostname] || alert["hostname"],
      event: %{
        alert_id: alert[:id] || alert["id"],
        title: alert[:title] || alert["title"],
        description: alert[:description] || alert["description"],
        severity: alert[:severity] || alert["severity"],
        status: alert[:status] || alert["status"],
        agent_id: alert[:agent_id] || alert["agent_id"],
        hostname: alert[:hostname] || alert["hostname"],
        mitre_tactics: alert[:mitre_tactics] || alert["mitre_tactics"] || [],
        mitre_techniques: alert[:mitre_techniques] || alert["mitre_techniques"] || [],
        threat_score: alert[:threat_score] || alert["threat_score"],
        evidence: alert[:evidence] || alert["evidence"] || %{},
        event_ids: alert[:event_ids] || alert["event_ids"] || []
      }
    }
  end

  defp get_event_time(event) do
    timestamp = event[:timestamp] || event["timestamp"] || event[:inserted_at] || event["inserted_at"]

    case timestamp do
      %DateTime{} = dt -> DateTime.to_unix(dt, :second)
      %NaiveDateTime{} = ndt -> NaiveDateTime.to_gregorian_seconds(ndt) - 62_167_219_200
      ts when is_integer(ts) -> ts
      ts when is_binary(ts) ->
        case DateTime.from_iso8601(ts) do
          {:ok, dt, _} -> DateTime.to_unix(dt, :second)
          _ -> System.os_time(:second)
        end
      _ -> System.os_time(:second)
    end
  end

  defp get_alert_time(alert) do
    timestamp = alert[:created_at] || alert["created_at"] || alert[:inserted_at] || alert["inserted_at"]
    get_event_time(%{timestamp: timestamp})
  end

  defp flush_events(events, state) do
    body = events
    |> Enum.map(&Jason.encode!/1)
    |> Enum.join("")

    send_to_hec(state, body)
  end

  defp send_hec_event(state, event) do
    body = Jason.encode!(event)
    send_to_hec(state, body)
  end

  defp send_to_hec(state, body) do
    url = "#{state.hec_url}#{@hec_event_endpoint}"

    headers = [
      {"Authorization", "Splunk #{state.hec_token}"},
      {"Content-Type", "application/json"}
    ]

    options = http_options(state.config)

    case Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %Finch.Response{status: code}} when code in 200..299 ->
        :ok

      {:ok, %Finch.Response{status: code, body: resp_body}} ->
        Logger.error("Splunk HEC error: HTTP #{code} - #{resp_body}")
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, reason} ->
        Logger.error("Splunk HEC connection error: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("Splunk HEC exception: #{inspect(e)}")
      {:error, Exception.message(e)}
  end

  defp check_hec_health(state) do
    url = "#{state.hec_url}#{@hec_health_endpoint}"

    headers = [
      {"Authorization", "Splunk #{state.hec_token}"}
    ]

    options = http_options(state.config)

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        {:ok, Jason.decode!(body)}

      {:ok, %Finch.Response{status: code, body: body}} ->
        {:error, "HTTP #{code}: #{body}"}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  # ============================================================================
  # Splunk SOAR (Phantom) Functions
  # ============================================================================

  defp create_phantom_container(alert, state) do
    url = "#{state.soar_url}#{@phantom_container_endpoint}"

    container = %{
      name: alert[:title] || alert["title"] || "Tamandua Alert",
      description: alert[:description] || alert["description"],
      label: "events",
      severity: map_severity_to_phantom(alert[:severity] || alert["severity"]),
      status: "new",
      source_data_identifier: alert[:id] || alert["id"],
      custom_fields: %{
        tamandua_alert_id: alert[:id] || alert["id"],
        agent_id: alert[:agent_id] || alert["agent_id"],
        hostname: alert[:hostname] || alert["hostname"],
        mitre_tactics: Enum.join(alert[:mitre_tactics] || alert["mitre_tactics"] || [], ", "),
        mitre_techniques: Enum.join(alert[:mitre_techniques] || alert["mitre_techniques"] || [], ", ")
      }
    }

    headers = [
      {"ph-auth-token", state.soar_token},
      {"Content-Type", "application/json"}
    ]

    options = http_options(state.config)

    case Finch.build(:post, url, headers, Jason.encode!(container)) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        response = Jason.decode!(body)
        {:ok, to_string(response["id"])}

      {:ok, %Finch.Response{status: code, body: body}} ->
        {:error, "HTTP #{code}: #{body}"}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp create_phantom_artifacts(container_id, alert, state) do
    artifacts = build_artifacts(alert)

    Enum.each(artifacts, fn artifact ->
      artifact_with_container = Map.put(artifact, :container_id, container_id)
      post_phantom_artifact(artifact_with_container, state)
    end)
  end

  defp build_artifacts(alert) do
    artifacts = []

    # Process artifact
    process = get_in(alert, [:evidence, :process]) || get_in(alert, ["evidence", "process"])

    artifacts =
      if process do
        [%{
          name: "Process",
          cef: %{
            fileName: process[:name] || process["name"],
            filePath: process[:path] || process["path"],
            processId: process[:pid] || process["pid"],
            commandLine: process[:cmdline] || process["cmdline"],
            fileHash: process[:sha256] || process["sha256"]
          },
          label: "process",
          severity: alert[:severity] || alert["severity"]
        } | artifacts]
      else
        artifacts
      end

    # Network artifacts
    network = get_in(alert, [:evidence, :network]) || get_in(alert, ["evidence", "network"])

    artifacts =
      if network do
        Enum.reduce(List.wrap(network), artifacts, fn conn, acc ->
          [%{
            name: "Network Connection",
            cef: %{
              destinationAddress: conn[:remote_ip] || conn["remote_ip"],
              destinationPort: conn[:remote_port] || conn["remote_port"],
              sourceAddress: conn[:local_ip] || conn["local_ip"],
              sourcePort: conn[:local_port] || conn["local_port"]
            },
            label: "network",
            severity: alert[:severity] || alert["severity"]
          } | acc]
        end)
      else
        artifacts
      end

    # File hash artifacts
    hashes = get_in(alert, [:evidence, :file_hashes]) || get_in(alert, ["evidence", "file_hashes"])

    artifacts =
      if hashes do
        Enum.reduce(List.wrap(hashes), artifacts, fn hash, acc ->
          [%{
            name: "File Hash",
            cef: %{
              fileHash: hash[:sha256] || hash["sha256"] || hash,
              fileName: hash[:name] || hash["name"]
            },
            label: "hash",
            severity: alert[:severity] || alert["severity"]
          } | acc]
        end)
      else
        artifacts
      end

    artifacts
  end

  defp post_phantom_artifact(artifact, state) do
    url = "#{state.soar_url}#{@phantom_artifact_endpoint}"

    headers = [
      {"ph-auth-token", state.soar_token},
      {"Content-Type", "application/json"}
    ]

    options = http_options(state.config)

    Finch.build(:post, url, headers, Jason.encode!(artifact)) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000))
  end

  defp run_phantom_playbook(playbook_name, params, state) do
    url = "#{state.soar_url}#{@phantom_playbook_endpoint}"

    body = %{
      playbook: playbook_name,
      container_id: params[:container_id],
      scope: params[:scope] || "new",
      run: true
    }

    headers = [
      {"ph-auth-token", state.soar_token},
      {"Content-Type", "application/json"}
    ]

    options = http_options(state.config)

    case Finch.build(:post, url, headers, Jason.encode!(body)) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %Finch.Response{status: 200, body: resp_body}} ->
        response = Jason.decode!(resp_body)
        {:ok, to_string(response["playbook_run_id"])}

      {:ok, %Finch.Response{status: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp map_severity_to_phantom(severity) do
    case severity do
      "critical" -> "high"
      "high" -> "high"
      "medium" -> "medium"
      "low" -> "low"
      "info" -> "low"
      _ -> "medium"
    end
  end

  # ============================================================================
  # Splunk REST API Functions (Saved Searches)
  # ============================================================================

  defp fetch_saved_searches(state) do
    if state.config.rest_url && state.config.rest_username do
      url = "#{state.config.rest_url}#{@saved_searches_endpoint}?output_mode=json"

      headers = basic_auth_headers(state.config)
      options = http_options(state.config)

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
        {:ok, %{status_code: 200, body: body}} ->
          response = Jason.decode!(body)
          searches = response["entry"] || []
          {:ok, Enum.map(searches, fn s ->
            %{
              name: s["name"],
              search: get_in(s, ["content", "search"]),
              description: get_in(s, ["content", "description"]),
              cron_schedule: get_in(s, ["content", "cron_schedule"]),
              is_scheduled: get_in(s, ["content", "is_scheduled"]),
              alert_type: get_in(s, ["content", "alert_type"])
            }
          end)}

        {:ok, %{status_code: code, body: body}} ->
          {:error, "HTTP #{code}: #{body}"}

        {:error, %{reason: reason}} ->
          {:error, reason}
      end
    else
      {:error, :rest_not_configured}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp execute_saved_search(search_name, state) do
    if state.config.rest_url && state.config.rest_username do
      # Dispatch the search
      dispatch_url = "#{state.config.rest_url}#{@saved_searches_endpoint}/#{URI.encode(search_name)}/dispatch?output_mode=json"

      headers = basic_auth_headers(state.config)
      options = http_options(state.config)

      case Finch.build(:post, dispatch_url, headers, "") |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
        {:ok, %{status_code: 201, body: body}} ->
          response = Jason.decode!(body)
          sid = response["sid"]
          wait_for_search_results(sid, state)

        {:ok, %{status_code: code, body: body}} ->
          {:error, "HTTP #{code}: #{body}"}

        {:error, %{reason: reason}} ->
          {:error, reason}
      end
    else
      {:error, :rest_not_configured}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp wait_for_search_results(sid, state, attempts \\ 0) do
    if attempts > 60 do
      {:error, :search_timeout}
    else
      results_url = "#{state.config.rest_url}/services/search/jobs/#{sid}/results?output_mode=json"

      headers = basic_auth_headers(state.config)
      options = http_options(state.config)

      case Finch.build(:get, results_url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
        {:ok, %{status_code: 200, body: body}} ->
          response = Jason.decode!(body)
          {:ok, %{
            sid: sid,
            results: response["results"] || [],
            result_count: length(response["results"] || [])
          }}

        {:ok, %{status_code: 204}} ->
          # Search still running
          Process.sleep(1000)
          wait_for_search_results(sid, state, attempts + 1)

        {:ok, %{status_code: code, body: body}} ->
          {:error, "HTTP #{code}: #{body}"}

        {:error, %{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp basic_auth_headers(config) do
    auth = Base.encode64("#{config.rest_username}:#{config.rest_password}")
    [{"Authorization", "Basic #{auth}"}]
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
