defmodule TamanduaServer.Integrations.Elastic do
  @moduledoc """
  Elasticsearch/OpenSearch Integration Module

  Provides integration with Elasticsearch and OpenSearch:
  - Bulk API for efficient event ingestion
  - Index templates for Tamandua event structure
  - Support for Elastic SIEM detection rules
  - Index lifecycle management (ILM)
  - Data streams support

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.Elastic,
        url: "https://elasticsearch.example.com:9200",
        username: "elastic",
        password: "your-password",
        # or API key:
        api_key: "your-api-key",
        index_prefix: "tamandua",
        verify_ssl: true,
        enable_ilm: true,
        hot_days: 7,
        warm_days: 30,
        delete_days: 90

  """

  use GenServer
  require Logger

  @behaviour TamanduaServer.Integrations.SIEMBehaviour

  # Default configuration
  @default_batch_size 500
  @default_batch_interval_ms 5000
  @default_timeout_ms 30_000

  # Index template settings
  @template_name "tamandua-edr"
  @data_stream_prefix "tamandua-edr"

  defstruct [
    :config,
    :url,
    :auth_header,
    :event_buffer,
    :stats,
    :cluster_info
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Send a single event to Elasticsearch.
  """
  @spec send_event(map()) :: :ok | {:error, term()}
  def send_event(event) do
    GenServer.call(__MODULE__, {:send_event, event})
  end

  @doc """
  Send a batch of events to Elasticsearch using the Bulk API.
  """
  @spec send_batch([map()]) :: :ok | {:error, term()}
  def send_batch(events) when is_list(events) do
    GenServer.call(__MODULE__, {:send_batch, events}, 60_000)
  end

  @doc """
  Forward an alert to Elasticsearch.
  """
  @spec forward_alert(map()) :: :ok | {:error, term()}
  def forward_alert(alert) do
    GenServer.call(__MODULE__, {:forward_alert, alert})
  end

  @doc """
  Search events in Elasticsearch.
  """
  @spec search(map(), keyword()) :: {:ok, map()} | {:error, term()}
  def search(query, opts \\ []) do
    GenServer.call(__MODULE__, {:search, query, opts}, 60_000)
  end

  @doc """
  Get cluster health.
  """
  @spec cluster_health() :: {:ok, map()} | {:error, term()}
  def cluster_health do
    GenServer.call(__MODULE__, :cluster_health)
  end

  @doc """
  Initialize index templates.
  """
  @spec setup_templates() :: :ok | {:error, term()}
  def setup_templates do
    GenServer.call(__MODULE__, :setup_templates, 30_000)
  end

  @doc """
  Create or update ILM policy.
  """
  @spec setup_ilm_policy() :: :ok | {:error, term()}
  def setup_ilm_policy do
    GenServer.call(__MODULE__, :setup_ilm_policy, 30_000)
  end

  @doc """
  Test connection to Elasticsearch.
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
  Get index statistics.
  """
  @spec index_stats() :: {:ok, map()} | {:error, term()}
  def index_stats do
    GenServer.call(__MODULE__, :index_stats, 30_000)
  end

  @doc """
  Create a detection rule (Elastic SIEM format).
  """
  @spec create_detection_rule(map()) :: {:ok, map()} | {:error, term()}
  def create_detection_rule(rule) do
    GenServer.call(__MODULE__, {:create_detection_rule, rule}, 30_000)
  end

  @doc """
  List detection rules.
  """
  @spec list_detection_rules(keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_detection_rules(opts \\ []) do
    GenServer.call(__MODULE__, {:list_detection_rules, opts}, 30_000)
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
    Logger.info("Starting Elasticsearch Integration")

    config = load_config(opts)

    # Schedule batch flush
    if config.batch_interval_ms > 0 do
      schedule_batch_flush(config.batch_interval_ms)
    end

    # Build auth header
    auth_header = build_auth_header(config)

    state = %__MODULE__{
      config: config,
      url: config.url,
      auth_header: auth_header,
      event_buffer: [],
      stats: %{
        events_sent: 0,
        events_failed: 0,
        alerts_sent: 0,
        bulk_requests: 0,
        last_send: nil,
        last_error: nil
      },
      cluster_info: nil
    }

    # Async setup
    if config.auto_setup do
      spawn(fn -> setup_on_start(state) end)
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:send_event, event}, _from, state) do
    formatted = format_event(event, state.config)
    new_buffer = [formatted | state.event_buffer]

    if length(new_buffer) >= state.config.batch_size do
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
    formatted = Enum.map(events, &format_event(&1, state.config))

    case flush_events(formatted, state) do
      :ok ->
        new_stats = update_stats(state.stats, :events_sent, length(events))
        new_stats = Map.update(new_stats, :bulk_requests, 1, &(&1 + 1))
        {:reply, :ok, %{state | stats: new_stats}}

      {:error, reason} = error ->
        new_stats = update_stats(state.stats, :events_failed, length(events))
        new_stats = Map.put(new_stats, :last_error, reason)
        {:reply, error, %{state | stats: new_stats}}
    end
  end

  @impl true
  def handle_call({:forward_alert, alert}, _from, state) do
    formatted = format_alert(alert, state.config)

    case index_document("#{state.config.index_prefix}-alerts", formatted, state) do
      :ok ->
        new_stats = update_stats(state.stats, :alerts_sent, 1)
        {:reply, :ok, %{state | stats: new_stats}}

      {:error, _reason} = error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:search, query, opts}, _from, state) do
    index = opts[:index] || "#{state.config.index_prefix}-*"
    result = execute_search(index, query, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:cluster_health, _from, state) do
    result = get_cluster_health(state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:setup_templates, _from, state) do
    result = create_index_template(state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:setup_ilm_policy, _from, state) do
    result = create_ilm_policy(state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:test_connection, _from, state) do
    case get_cluster_info(state) do
      {:ok, info} ->
        version = get_in(info, ["version", "number"]) || "unknown"
        cluster_name = info["cluster_name"] || "unknown"
        {:reply, {:ok, "Connected to #{cluster_name} (version #{version})"}, %{state | cluster_info: info}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  @impl true
  def handle_call(:index_stats, _from, state) do
    result = get_index_stats(state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:create_detection_rule, rule}, _from, state) do
    result = create_siem_rule(rule, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:list_detection_rules, opts}, _from, state) do
    result = fetch_siem_rules(opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_info(:flush_batch, state) do
    if length(state.event_buffer) > 0 do
      case flush_events(state.event_buffer, state) do
        :ok ->
          new_stats = update_stats(state.stats, :events_sent, length(state.event_buffer))
          new_stats = Map.update(new_stats, :bulk_requests, 1, &(&1 + 1))
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
      url: opts[:url] || app_config[:url] || "http://localhost:9200",
      username: opts[:username] || app_config[:username],
      password: opts[:password] || app_config[:password],
      api_key: opts[:api_key] || app_config[:api_key],
      index_prefix: opts[:index_prefix] || app_config[:index_prefix] || "tamandua",
      use_data_streams: opts[:use_data_streams] != false && app_config[:use_data_streams] != false,
      verify_ssl: opts[:verify_ssl] != false && app_config[:verify_ssl] != false,
      batch_size: opts[:batch_size] || app_config[:batch_size] || @default_batch_size,
      batch_interval_ms: opts[:batch_interval_ms] || app_config[:batch_interval_ms] || @default_batch_interval_ms,
      timeout_ms: opts[:timeout_ms] || app_config[:timeout_ms] || @default_timeout_ms,
      auto_setup: opts[:auto_setup] != false && app_config[:auto_setup] != false,
      enable_ilm: opts[:enable_ilm] != false && app_config[:enable_ilm] != false,
      hot_days: opts[:hot_days] || app_config[:hot_days] || 7,
      warm_days: opts[:warm_days] || app_config[:warm_days] || 30,
      delete_days: opts[:delete_days] || app_config[:delete_days] || 90
    }
  end

  defp build_auth_header(config) do
    cond do
      config.api_key ->
        "ApiKey #{config.api_key}"

      config.username && config.password ->
        auth = Base.encode64("#{config.username}:#{config.password}")
        "Basic #{auth}"

      true ->
        nil
    end
  end

  defp schedule_batch_flush(interval) do
    Process.send_after(self(), :flush_batch, interval)
  end

  defp setup_on_start(state) do
    # Wait a bit for the GenServer to fully start
    Process.sleep(1000)

    case create_index_template(state) do
      :ok -> Logger.info("Elasticsearch index template created")
      {:error, reason} -> Logger.warning("Failed to create index template: #{inspect(reason)}")
    end

    if state.config.enable_ilm do
      case create_ilm_policy(state) do
        :ok -> Logger.info("Elasticsearch ILM policy created")
        {:error, reason} -> Logger.warning("Failed to create ILM policy: #{inspect(reason)}")
      end
    end
  end

  defp format_event(event, config) do
    timestamp = get_event_time(event)

    %{
      "@timestamp" => timestamp,
      "event.category" => "host",
      "event.kind" => "event",
      "event.type" => event[:event_type] || event["event_type"] || event[:type] || event["type"],
      "event.severity" => severity_to_number(event[:severity] || event["severity"]),
      "agent.id" => event[:agent_id] || event["agent_id"],
      "host.name" => event[:hostname] || event["hostname"] || get_in(event, [:payload, :hostname]),
      "process.name" => get_in(event, [:payload, :name]) || get_in(event, ["payload", "name"]),
      "process.executable" => get_in(event, [:payload, :path]) || get_in(event, ["payload", "path"]),
      "process.pid" => get_in(event, [:payload, :pid]) || get_in(event, ["payload", "pid"]),
      "process.parent.pid" => get_in(event, [:payload, :ppid]) || get_in(event, ["payload", "ppid"]),
      "process.command_line" => get_in(event, [:payload, :cmdline]) || get_in(event, ["payload", "cmdline"]),
      "user.name" => get_in(event, [:payload, :user]) || get_in(event, ["payload", "user"]),
      "source.ip" => get_in(event, [:payload, :local_ip]) || get_in(event, ["payload", "local_ip"]),
      "destination.ip" => get_in(event, [:payload, :remote_ip]) || get_in(event, ["payload", "remote_ip"]),
      "destination.port" => get_in(event, [:payload, :remote_port]) || get_in(event, ["payload", "remote_port"]),
      "file.hash.sha256" => get_in(event, [:payload, :sha256]) || get_in(event, ["payload", "sha256"]),
      "file.hash.md5" => get_in(event, [:payload, :md5]) || get_in(event, ["payload", "md5"]),
      "tamandua.raw" => event[:payload] || event["payload"],
      "data_stream.namespace" => config.index_prefix
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp format_alert(alert, config) do
    timestamp = get_alert_time(alert)

    %{
      "@timestamp" => timestamp,
      "event.category" => "intrusion_detection",
      "event.kind" => "alert",
      "event.severity" => severity_to_number(alert[:severity] || alert["severity"]),
      "rule.name" => alert[:title] || alert["title"],
      "rule.description" => alert[:description] || alert["description"],
      "agent.id" => alert[:agent_id] || alert["agent_id"],
      "host.name" => alert[:hostname] || alert["hostname"],
      "threat.indicator.confidence" => alert[:threat_score] || alert["threat_score"],
      "threat.tactic.name" => alert[:mitre_tactics] || alert["mitre_tactics"] || [],
      "threat.technique.id" => alert[:mitre_techniques] || alert["mitre_techniques"] || [],
      "tamandua.alert_id" => alert[:id] || alert["id"],
      "tamandua.status" => alert[:status] || alert["status"],
      "tamandua.evidence" => alert[:evidence] || alert["evidence"] || %{},
      "tamandua.event_ids" => alert[:event_ids] || alert["event_ids"] || [],
      "data_stream.namespace" => config.index_prefix
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp get_event_time(event) do
    timestamp = event[:timestamp] || event["timestamp"] || event[:inserted_at] || event["inserted_at"]

    case timestamp do
      %DateTime{} = dt -> DateTime.to_iso8601(dt)
      %NaiveDateTime{} = ndt -> NaiveDateTime.to_iso8601(ndt) <> "Z"
      ts when is_binary(ts) -> ts
      ts when is_integer(ts) -> DateTime.from_unix!(ts) |> DateTime.to_iso8601()
      _ -> DateTime.utc_now() |> DateTime.to_iso8601()
    end
  end

  defp get_alert_time(alert) do
    timestamp = alert[:created_at] || alert["created_at"] || alert[:inserted_at] || alert["inserted_at"]
    get_event_time(%{timestamp: timestamp})
  end

  defp severity_to_number(severity) do
    case severity do
      "critical" -> 1
      "high" -> 2
      "medium" -> 3
      "low" -> 4
      "info" -> 5
      _ -> 3
    end
  end

  defp flush_events(events, state) do
    if state.config.use_data_streams do
      bulk_to_data_stream(events, state)
    else
      index_name = build_index_name(state.config)
      bulk_index(events, index_name, state)
    end
  end

  defp bulk_to_data_stream(events, state) do
    # Build bulk request body for data streams
    body = events
    |> Enum.flat_map(fn event ->
      action = Jason.encode!(%{"create" => %{}})
      doc = Jason.encode!(event)
      [action, doc]
    end)
    |> Enum.join("\n")
    |> Kernel.<>("\n")

    url = "#{state.url}/#{@data_stream_prefix}-events/_bulk"
    execute_bulk(url, body, state)
  end

  defp bulk_index(events, index, state) do
    # Build bulk request body
    body = events
    |> Enum.flat_map(fn event ->
      doc_id = :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
      action = Jason.encode!(%{"index" => %{"_index" => index, "_id" => doc_id}})
      doc = Jason.encode!(event)
      [action, doc]
    end)
    |> Enum.join("\n")
    |> Kernel.<>("\n")

    url = "#{state.url}/_bulk"
    execute_bulk(url, body, state)
  end

  defp execute_bulk(url, body, state) do
    headers = [{"Content-Type", "application/x-ndjson"}]
    headers = add_auth_header(headers, state.auth_header)
    _options = http_options(state.config)

    case Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: state.config.timeout_ms) do
      {:ok, %Finch.Response{status: code, body: resp_body}} when code in 200..299 ->
        response = Jason.decode!(resp_body)

        if response["errors"] do
          error_items = response["items"]
          |> Enum.filter(fn item ->
            action = item["index"] || item["create"]
            action && action["error"]
          end)

          if length(error_items) > 0 do
            Logger.warning("Elasticsearch bulk had #{length(error_items)} errors")
          end
        end

        :ok

      {:ok, %Finch.Response{status: code, body: resp_body}} ->
        Logger.error("Elasticsearch bulk error: HTTP #{code} - #{resp_body}")
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %Mint.TransportError{reason: reason}} ->
        Logger.error("Elasticsearch connection error: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("Elasticsearch exception: #{inspect(e)}")
      {:error, Exception.message(e)}
  end

  defp index_document(index, document, state) do
    doc_id = :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
    url = "#{state.url}/#{index}/_doc/#{doc_id}"

    headers = [{"Content-Type", "application/json"}]
    headers = add_auth_header(headers, state.auth_header)
    _options = http_options(state.config)

    case Finch.build(:post, url, headers, Jason.encode!(document)) |> Finch.request(TamanduaServer.Finch, receive_timeout: state.config.timeout_ms) do
      {:ok, %Finch.Response{status: code}} when code in 200..299 ->
        :ok

      {:ok, %Finch.Response{status: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp execute_search(index, query, state) do
    url = "#{state.url}/#{index}/_search"

    headers = [{"Content-Type", "application/json"}]
    headers = add_auth_header(headers, state.auth_header)
    _options = http_options(state.config)

    case Finch.build(:post, url, headers, Jason.encode!(query)) |> Finch.request(TamanduaServer.Finch, receive_timeout: state.config.timeout_ms) do
      {:ok, %Finch.Response{status: 200, body: resp_body}} ->
        {:ok, Jason.decode!(resp_body)}

      {:ok, %Finch.Response{status: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp get_cluster_info(state) do
    url = "#{state.url}/"

    headers = add_auth_header([], state.auth_header)

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: state.config.timeout_ms) do
      {:ok, %Finch.Response{status: 200, body: resp_body}} ->
        {:ok, Jason.decode!(resp_body)}

      {:ok, %Finch.Response{status: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp get_cluster_health(state) do
    url = "#{state.url}/_cluster/health"

    headers = add_auth_header([], state.auth_header)

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: state.config.timeout_ms) do
      {:ok, %Finch.Response{status: 200, body: resp_body}} ->
        {:ok, Jason.decode!(resp_body)}

      {:ok, %Finch.Response{status: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp get_index_stats(state) do
    url = "#{state.url}/#{state.config.index_prefix}-*/_stats"

    headers = add_auth_header([], state.auth_header)

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: state.config.timeout_ms) do
      {:ok, %Finch.Response{status: 200, body: resp_body}} ->
        response = Jason.decode!(resp_body)
        stats = %{
          total_docs: get_in(response, ["_all", "primaries", "docs", "count"]) || 0,
          total_size_bytes: get_in(response, ["_all", "primaries", "store", "size_in_bytes"]) || 0,
          index_count: map_size(response["indices"] || %{})
        }
        {:ok, stats}

      {:ok, %Finch.Response{status: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  # ============================================================================
  # Index Template Functions
  # ============================================================================

  defp create_index_template(state) do
    template = build_index_template(state.config)

    url = "#{state.url}/_index_template/#{@template_name}"

    headers = [{"Content-Type", "application/json"}]
    headers = add_auth_header(headers, state.auth_header)
    _options = http_options(state.config)

    case Finch.build(:put, url, headers, Jason.encode!(template)) |> Finch.request(TamanduaServer.Finch, receive_timeout: state.config.timeout_ms) do
      {:ok, %Finch.Response{status: 200}} -> :ok
      {:ok, %Finch.Response{status: code, body: resp_body}} -> {:error, "HTTP #{code}: #{resp_body}"}
      {:error, %Mint.TransportError{reason: reason}} -> {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp build_index_template(config) do
    template = %{
      "index_patterns" => ["#{config.index_prefix}-*", "#{@data_stream_prefix}-*"],
      "data_stream" => %{},
      "priority" => 500,
      "template" => %{
        "settings" => %{
          "number_of_shards" => 1,
          "number_of_replicas" => 1,
          "index.lifecycle.name" => "tamandua-ilm-policy"
        },
        "mappings" => %{
          "properties" => %{
            "@timestamp" => %{"type" => "date"},
            "event.category" => %{"type" => "keyword"},
            "event.kind" => %{"type" => "keyword"},
            "event.type" => %{"type" => "keyword"},
            "event.severity" => %{"type" => "integer"},
            "agent.id" => %{"type" => "keyword"},
            "host.name" => %{"type" => "keyword"},
            "process.name" => %{"type" => "keyword"},
            "process.executable" => %{"type" => "keyword"},
            "process.pid" => %{"type" => "long"},
            "process.parent.pid" => %{"type" => "long"},
            "process.command_line" => %{"type" => "text", "fields" => %{"keyword" => %{"type" => "keyword", "ignore_above" => 2048}}},
            "user.name" => %{"type" => "keyword"},
            "source.ip" => %{"type" => "ip"},
            "destination.ip" => %{"type" => "ip"},
            "destination.port" => %{"type" => "integer"},
            "file.hash.sha256" => %{"type" => "keyword"},
            "file.hash.md5" => %{"type" => "keyword"},
            "rule.name" => %{"type" => "keyword"},
            "rule.description" => %{"type" => "text"},
            "threat.indicator.confidence" => %{"type" => "float"},
            "threat.tactic.name" => %{"type" => "keyword"},
            "threat.technique.id" => %{"type" => "keyword"},
            "tamandua.alert_id" => %{"type" => "keyword"},
            "tamandua.status" => %{"type" => "keyword"},
            "tamandua.evidence" => %{"type" => "object", "enabled" => false},
            "tamandua.event_ids" => %{"type" => "keyword"},
            "tamandua.raw" => %{"type" => "object", "enabled" => false},
            "data_stream.namespace" => %{"type" => "keyword"}
          }
        }
      }
    }

    if config.enable_ilm do
      put_in(template, ["template", "settings", "index.lifecycle.name"], "tamandua-ilm-policy")
    else
      template
    end
  end

  defp create_ilm_policy(state) do
    config = state.config

    policy = %{
      "policy" => %{
        "phases" => %{
          "hot" => %{
            "min_age" => "0ms",
            "actions" => %{
              "rollover" => %{
                "max_primary_shard_size" => "50gb",
                "max_age" => "#{config.hot_days}d"
              }
            }
          },
          "warm" => %{
            "min_age" => "#{config.hot_days}d",
            "actions" => %{
              "shrink" => %{"number_of_shards" => 1},
              "forcemerge" => %{"max_num_segments" => 1}
            }
          },
          "delete" => %{
            "min_age" => "#{config.delete_days}d",
            "actions" => %{
              "delete" => %{}
            }
          }
        }
      }
    }

    url = "#{state.url}/_ilm/policy/tamandua-ilm-policy"

    headers = [{"Content-Type", "application/json"}]
    headers = add_auth_header(headers, state.auth_header)
    _options = http_options(state.config)

    case Finch.build(:put, url, headers, Jason.encode!(policy)) |> Finch.request(TamanduaServer.Finch, receive_timeout: state.config.timeout_ms) do
      {:ok, %Finch.Response{status: 200}} -> :ok
      {:ok, %Finch.Response{status: code, body: resp_body}} -> {:error, "HTTP #{code}: #{resp_body}"}
      {:error, %Mint.TransportError{reason: reason}} -> {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  # ============================================================================
  # Elastic SIEM Detection Rules
  # ============================================================================

  defp create_siem_rule(rule, state) do
    # Elastic Security detection rule format
    siem_rule = %{
      "name" => rule[:name] || rule["name"],
      "description" => rule[:description] || rule["description"],
      "risk_score" => rule[:risk_score] || rule["risk_score"] || 50,
      "severity" => rule[:severity] || rule["severity"] || "medium",
      "type" => rule[:type] || rule["type"] || "query",
      "query" => rule[:query] || rule["query"],
      "index" => ["#{state.config.index_prefix}-*"],
      "enabled" => rule[:enabled] != false,
      "tags" => rule[:tags] || rule["tags"] || ["tamandua"],
      "threat" => build_threat_mapping(rule)
    }

    url = "#{state.url}/api/detection_engine/rules"

    headers = [
      {"Content-Type", "application/json"},
      {"kbn-xsrf", "true"}
    ]
    headers = add_auth_header(headers, state.auth_header)
    _options = http_options(state.config)

    case Finch.build(:post, url, headers, Jason.encode!(siem_rule)) |> Finch.request(TamanduaServer.Finch, receive_timeout: state.config.timeout_ms) do
      {:ok, %Finch.Response{status: 200, body: resp_body}} ->
        {:ok, Jason.decode!(resp_body)}

      {:ok, %Finch.Response{status: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp fetch_siem_rules(_opts, state) do
    url = "#{state.url}/api/detection_engine/rules/_find?per_page=100"

    headers = [{"kbn-xsrf", "true"}]
    headers = add_auth_header(headers, state.auth_header)
    options = http_options(state.config)

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: 200, body: resp_body}} ->
        response = Jason.decode!(resp_body)
        {:ok, response["data"] || []}

      {:ok, %{status_code: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp build_threat_mapping(rule) do
    tactics = rule[:mitre_tactics] || rule["mitre_tactics"] || []
    techniques = rule[:mitre_techniques] || rule["mitre_techniques"] || []

    if length(tactics) > 0 || length(techniques) > 0 do
      [%{
        "framework" => "MITRE ATT&CK",
        "tactic" => Enum.map(tactics, fn t -> %{"id" => t, "name" => t} end),
        "technique" => Enum.map(techniques, fn t -> %{"id" => t, "name" => t} end)
      }]
    else
      []
    end
  end

  defp build_index_name(config) do
    date = Date.utc_today() |> Date.to_iso8601() |> String.replace("-", ".")
    "#{config.index_prefix}-events-#{date}"
  end

  defp add_auth_header(headers, nil), do: headers
  defp add_auth_header(headers, auth_header) do
    [{"Authorization", auth_header} | headers]
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
