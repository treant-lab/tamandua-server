defmodule TamanduaServer.Integrations.SIEM do
  @moduledoc """
  SIEM Integration Module

  ENTERPRISE FEATURE: Integration with major SIEM platforms:
  - Splunk HEC (HTTP Event Collector)
  - Elastic/OpenSearch (via Bulk API)
  - Azure Sentinel (Log Analytics API)
  - IBM QRadar (LEEF format)
  - Generic Syslog (RFC 5424)
  - Generic Webhook (JSON)

  Supports:
  - Real-time event forwarding
  - Batch forwarding (configurable)
  - Retry with exponential backoff
  - Circuit breaker for failed destinations
  - Format transformation (CEF, LEEF, JSON)
  - Filtering by severity/type
  """

  use GenServer
  require Logger

  alias TamanduaServer.{Alerts, Events}

  @batch_size 100
  @batch_interval_ms 5000
  @max_retries 3
  @retry_base_delay_ms 1000

  # Integration configuration
  defmodule IntegrationConfig do
    @moduledoc "SIEM integration configuration"
    defstruct [
      :id,
      :name,
      :type,            # :splunk, :elastic, :sentinel, :qradar, :syslog, :webhook
      :enabled,
      :url,
      :token,           # API token/key
      :username,
      :password,
      :index,           # For Elastic/Splunk
      :source_type,
      :format,          # :json, :cef, :leef
      :batch_size,
      :batch_interval_ms,
      :min_severity,    # Filter: minimum severity to forward
      :event_types,     # Filter: specific event types to forward
      :include_raw,     # Include raw event data
      :tls_verify,
      :custom_headers,
      :field_mapping,   # Custom field mapping
      :circuit_breaker  # Circuit breaker state
    ]
  end

  # Event batch
  defmodule Batch do
    @moduledoc "Event batch for forwarding"
    defstruct [
      :integration_id,
      :events,
      :created_at,
      :retry_count
    ]
  end

  # Circuit breaker
  defmodule CircuitBreaker do
    @moduledoc "Circuit breaker for failed integrations"
    defstruct [
      :state,           # :closed, :open, :half_open
      :failure_count,
      :last_failure,
      :reset_timeout_ms
    ]
  end

  # State
  defstruct [
    :integrations,    # %{id => IntegrationConfig}
    :batches,         # %{id => Batch}
    :stats            # Forwarding statistics
  ]

  ## Client API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Add a SIEM integration
  """
  def add_integration(config) do
    GenServer.call(__MODULE__, {:add_integration, config})
  end

  @doc """
  Remove a SIEM integration
  """
  def remove_integration(id) do
    GenServer.call(__MODULE__, {:remove_integration, id})
  end

  @doc """
  List all integrations
  """
  def list_integrations do
    GenServer.call(__MODULE__, :list_integrations)
  end

  @doc """
  Forward an event to all configured SIEMs
  """
  def forward_event(event) do
    GenServer.cast(__MODULE__, {:forward_event, event})
  end

  @doc """
  Forward an alert to all configured SIEMs
  """
  def forward_alert(alert) do
    GenServer.cast(__MODULE__, {:forward_alert, alert})
  end

  @doc """
  Get forwarding statistics
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Test integration connectivity
  """
  def test_integration(id) do
    GenServer.call(__MODULE__, {:test_integration, id}, 30_000)
  end

  ## Server Callbacks

  @impl true
  def init(_opts) do
    Logger.info("Starting SIEM Integration Manager")

    # Schedule batch flush
    schedule_batch_flush()

    state = %__MODULE__{
      integrations: load_integrations(),
      batches: %{},
      stats: %{
        events_forwarded: 0,
        events_failed: 0,
        batches_sent: 0,
        last_forward: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:add_integration, config}, _from, state) do
    integration = %IntegrationConfig{
      id: config[:id] || generate_id(),
      name: config[:name],
      type: config[:type],
      enabled: config[:enabled] != false,
      url: config[:url],
      token: config[:token],
      username: config[:username],
      password: config[:password],
      index: config[:index],
      source_type: config[:source_type] || "tamandua:edr",
      format: config[:format] || :json,
      batch_size: config[:batch_size] || @batch_size,
      batch_interval_ms: config[:batch_interval_ms] || @batch_interval_ms,
      min_severity: config[:min_severity],
      event_types: config[:event_types],
      include_raw: config[:include_raw] != false,
      tls_verify: config[:tls_verify] != false,
      custom_headers: config[:custom_headers] || %{},
      field_mapping: config[:field_mapping] || %{},
      circuit_breaker: %CircuitBreaker{
        state: :closed,
        failure_count: 0,
        last_failure: nil,
        reset_timeout_ms: 60_000
      }
    }

    new_integrations = Map.put(state.integrations, integration.id, integration)
    save_integrations(new_integrations)

    {:reply, {:ok, integration}, %{state | integrations: new_integrations}}
  end

  @impl true
  def handle_call({:remove_integration, id}, _from, state) do
    new_integrations = Map.delete(state.integrations, id)
    new_batches = Map.delete(state.batches, id)
    save_integrations(new_integrations)

    {:reply, :ok, %{state | integrations: new_integrations, batches: new_batches}}
  end

  @impl true
  def handle_call(:list_integrations, _from, state) do
    integrations = Map.values(state.integrations)
    {:reply, {:ok, integrations}, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, {:ok, state.stats}, state}
  end

  @impl true
  def handle_call({:test_integration, id}, _from, state) do
    case Map.get(state.integrations, id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      integration ->
        result = test_connection(integration)
        {:reply, result, state}
    end
  end

  @impl true
  def handle_cast({:forward_event, event}, state) do
    new_batches = state.integrations
      |> Enum.filter(fn {_id, config} ->
        config.enabled and should_forward?(config, event)
      end)
      |> Enum.reduce(state.batches, fn {id, config}, batches ->
        batch = Map.get(batches, id, %Batch{
          integration_id: id,
          events: [],
          created_at: DateTime.utc_now(),
          retry_count: 0
        })

        updated_batch = %{batch | events: [event | batch.events]}

        # Check if batch is full
        if length(updated_batch.events) >= config.batch_size do
          send(self(), {:flush_batch, id})
        end

        Map.put(batches, id, updated_batch)
      end)

    {:noreply, %{state | batches: new_batches}}
  end

  @impl true
  def handle_cast({:forward_alert, alert}, state) do
    # Convert alert to event format and forward
    event = %{
      type: :alert,
      timestamp: alert.created_at,
      severity: alert.severity,
      data: %{
        alert_id: alert.id,
        title: alert.title,
        description: alert.description,
        agent_id: alert.agent_id,
        hostname: alert.hostname,
        detection_type: alert.detection_type,
        mitre_tactics: alert.mitre_tactics,
        mitre_techniques: alert.mitre_techniques
      }
    }

    handle_cast({:forward_event, event}, state)
  end

  @impl true
  def handle_info(:flush_all_batches, state) do
    # Flush all non-empty batches
    Enum.each(state.batches, fn {id, batch} ->
      if length(batch.events) > 0 do
        send(self(), {:flush_batch, id})
      end
    end)

    schedule_batch_flush()
    {:noreply, state}
  end

  @impl true
  def handle_info({:flush_batch, integration_id}, state) do
    case {Map.get(state.integrations, integration_id), Map.get(state.batches, integration_id)} do
      {nil, _} ->
        {:noreply, state}

      {_, nil} ->
        {:noreply, state}

      {_, %{events: []}} ->
        {:noreply, state}

      {integration, batch} ->
        # Check circuit breaker
        if circuit_open?(integration.circuit_breaker) do
          Logger.warning("Circuit breaker open for integration #{integration.name}")
          {:noreply, state}
        else
          # Forward batch
          case send_batch(integration, batch) do
            :ok ->
              # Success - clear batch and update stats
              new_batches = Map.put(state.batches, integration_id, %Batch{
                integration_id: integration_id,
                events: [],
                created_at: DateTime.utc_now(),
                retry_count: 0
              })

              new_stats = %{state.stats |
                events_forwarded: state.stats.events_forwarded + length(batch.events),
                batches_sent: state.stats.batches_sent + 1,
                last_forward: DateTime.utc_now()
              }

              # Reset circuit breaker
              new_integrations = Map.update!(state.integrations, integration_id, fn config ->
                %{config | circuit_breaker: %{config.circuit_breaker | failure_count: 0, state: :closed}}
              end)

              {:noreply, %{state | batches: new_batches, stats: new_stats, integrations: new_integrations}}

            {:error, reason} ->
              Logger.error("Failed to forward batch to #{integration.name}: #{inspect(reason)}")

              # Update circuit breaker
              new_integrations = Map.update!(state.integrations, integration_id, fn config ->
                update_circuit_breaker(config, :failure)
              end)

              # Retry logic
              if batch.retry_count < @max_retries do
                delay = @retry_base_delay_ms * :math.pow(2, batch.retry_count) |> round()
                Process.send_after(self(), {:flush_batch, integration_id}, delay)

                new_batches = Map.update!(state.batches, integration_id, fn b ->
                  %{b | retry_count: b.retry_count + 1}
                end)

                {:noreply, %{state | batches: new_batches, integrations: new_integrations}}
              else
                # Max retries exceeded - drop batch
                new_stats = %{state.stats |
                  events_failed: state.stats.events_failed + length(batch.events)
                }

                new_batches = Map.put(state.batches, integration_id, %Batch{
                  integration_id: integration_id,
                  events: [],
                  created_at: DateTime.utc_now(),
                  retry_count: 0
                })

                {:noreply, %{state | batches: new_batches, stats: new_stats, integrations: new_integrations}}
              end
          end
        end
    end
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  ## Private Functions

  defp load_integrations do
    # Load from database/config
    # For now, return empty map
    %{}
  end

  defp save_integrations(_integrations) do
    # Save to database/config
    :ok
  end

  defp generate_id do
    :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
  end

  defp should_forward?(config, event) do
    # Check severity filter
    severity_ok = if config.min_severity do
      severity_value(event[:severity]) >= severity_value(config.min_severity)
    else
      true
    end

    # Check event type filter
    type_ok = if config.event_types do
      event[:type] in config.event_types
    else
      true
    end

    severity_ok and type_ok
  end

  defp severity_value(nil), do: 0
  defp severity_value(:info), do: 1
  defp severity_value(:low), do: 2
  defp severity_value(:medium), do: 3
  defp severity_value(:high), do: 4
  defp severity_value(:critical), do: 5
  defp severity_value(s) when is_binary(s), do: severity_value(String.to_atom(s))
  defp severity_value(_), do: 0

  defp send_batch(integration, batch) do
    formatted_events = Enum.map(batch.events, fn event ->
      format_event(integration, event)
    end)

    case integration.type do
      :splunk -> send_to_splunk(integration, formatted_events)
      :elastic -> send_to_elastic(integration, formatted_events)
      :sentinel -> send_to_sentinel(integration, formatted_events)
      :qradar -> send_to_qradar(integration, formatted_events)
      :syslog -> send_to_syslog(integration, formatted_events)
      :webhook -> send_to_webhook(integration, formatted_events)
      _ -> {:error, :unknown_type}
    end
  end

  defp format_event(integration, event) do
    base_event = %{
      timestamp: format_timestamp(event[:timestamp]),
      source: "tamandua-edr",
      source_type: integration.source_type,
      host: event[:hostname] || event[:data][:hostname],
      severity: event[:severity],
      event_type: event[:type],
      data: event[:data]
    }

    # Apply field mapping
    mapped = apply_field_mapping(base_event, integration.field_mapping)

    case integration.format do
      :json -> Jason.encode!(mapped)
      :cef -> to_cef(mapped)
      :leef -> to_leef(mapped)
      _ -> Jason.encode!(mapped)
    end
  end

  defp format_timestamp(nil), do: DateTime.utc_now() |> DateTime.to_iso8601()
  defp format_timestamp(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_timestamp(ts), do: to_string(ts)

  defp apply_field_mapping(event, mapping) when map_size(mapping) == 0, do: event
  defp apply_field_mapping(event, mapping) do
    Enum.reduce(mapping, event, fn {source, target}, acc ->
      value = get_in(acc, String.split(source, "."))
      if value do
        put_in(acc, String.split(target, "."), value)
      else
        acc
      end
    end)
  end

  # Splunk HEC
  defp send_to_splunk(integration, events) do
    url = "#{integration.url}/services/collector/event"

    body = events
      |> Enum.map(fn event -> %{"event" => event, "sourcetype" => integration.source_type} end)
      |> Enum.map(&Jason.encode!/1)
      |> Enum.join("")

    headers = [
      {"Authorization", "Splunk #{integration.token}"},
      {"Content-Type", "application/json"}
    ]

    http_post(url, body, headers, integration.tls_verify)
  end

  # Elasticsearch
  defp send_to_elastic(integration, events) do
    url = "#{integration.url}/#{integration.index}/_bulk"

    body = events
      |> Enum.flat_map(fn event ->
        [
          Jason.encode!(%{"index" => %{"_index" => integration.index}}),
          event
        ]
      end)
      |> Enum.join("\n")
      |> Kernel.<>("\n")

    headers = [
      {"Content-Type", "application/x-ndjson"}
    ]

    headers = if integration.token do
      [{"Authorization", "ApiKey #{integration.token}"} | headers]
    else
      if integration.username && integration.password do
        auth = Base.encode64("#{integration.username}:#{integration.password}")
        [{"Authorization", "Basic #{auth}"} | headers]
      else
        headers
      end
    end

    http_post(url, body, headers, integration.tls_verify)
  end

  # Azure Sentinel
  defp send_to_sentinel(integration, events) do
    # Workspace ID and shared key based auth
    url = "#{integration.url}/api/logs?api-version=2016-04-01"

    body = Jason.encode!(events)

    # Generate signature
    date = Calendar.strftime(DateTime.utc_now(), "%a, %d %b %Y %H:%M:%S GMT")
    string_to_sign = "POST\n#{byte_size(body)}\napplication/json\nx-ms-date:#{date}\n/api/logs"
    signature = :crypto.mac(:hmac, :sha256, Base.decode64!(integration.token), string_to_sign)
      |> Base.encode64()

    headers = [
      {"Authorization", "SharedKey #{integration.username}:#{signature}"},
      {"Content-Type", "application/json"},
      {"Log-Type", integration.index || "TamanduaEDR"},
      {"x-ms-date", date}
    ]

    http_post(url, body, headers, integration.tls_verify)
  end

  # QRadar (LEEF format)
  defp send_to_qradar(integration, events) do
    # QRadar uses syslog with LEEF format
    formatted = Enum.map(events, &to_leef/1)
    send_syslog_messages(integration, formatted)
  end

  # Syslog
  defp send_to_syslog(integration, events) do
    formatted = Enum.map(events, fn event ->
      "<134>1 #{format_timestamp(nil)} tamandua-edr - - - #{event}"
    end)

    send_syslog_messages(integration, formatted)
  end

  defp send_syslog_messages(integration, messages) do
    uri = URI.parse(integration.url)
    host = uri.host || "localhost"
    port = uri.port || 514

    case :gen_udp.open(0) do
      {:ok, socket} ->
        Enum.each(messages, fn msg ->
          :gen_udp.send(socket, String.to_charlist(host), port, String.to_charlist(msg))
        end)
        :gen_udp.close(socket)
        :ok

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Generic Webhook
  defp send_to_webhook(integration, events) do
    body = Jason.encode!(%{
      source: "tamandua-edr",
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      event_count: length(events),
      events: events
    })

    headers = [
      {"Content-Type", "application/json"}
    ]

    headers = if integration.token do
      [{"Authorization", "Bearer #{integration.token}"} | headers]
    else
      headers
    end

    headers = Map.to_list(integration.custom_headers) ++ headers

    http_post(integration.url, body, headers, integration.tls_verify)
  end

  # CEF format
  defp to_cef(event) do
    # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    severity_map = %{info: 0, low: 3, medium: 5, high: 7, critical: 10}
    sev = severity_map[event[:severity]] || 0

    extensions = [
      "rt=#{event[:timestamp]}",
      "src=#{event[:host]}",
      "cat=#{event[:event_type]}"
    ] |> Enum.join(" ")

    "CEF:0|Tamandua|EDR|1.0|#{event[:event_type]}|#{event[:event_type]}|#{sev}|#{extensions}"
  end

  # LEEF format
  defp to_leef(event) do
    # LEEF:Version|Vendor|Product|Version|EventID|
    attrs = [
      "devTime=#{event[:timestamp]}",
      "src=#{event[:host]}",
      "cat=#{event[:event_type]}",
      "sev=#{event[:severity]}"
    ] |> Enum.join("\t")

    "LEEF:2.0|Tamandua|EDR|1.0|#{event[:event_type]}|#{attrs}"
  end

  defp http_post(url, body, headers, verify_ssl) do
    options = if verify_ssl do
      []
    else
      [ssl: [verify: :verify_none]]
    end

    case Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: code}} when code in 200..299 ->
        :ok

      {:ok, %{status_code: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        {:error, reason}
    end
  rescue
    e -> {:error, inspect(e)}
  end

  defp test_connection(integration) do
    test_event = %{
      type: :test,
      timestamp: DateTime.utc_now(),
      severity: :info,
      hostname: "tamandua-test",
      data: %{message: "Test connection from Tamandua EDR"}
    }

    case send_batch(integration, %Batch{events: [test_event], retry_count: 0}) do
      :ok -> {:ok, "Connection successful"}
      {:error, reason} -> {:error, reason}
    end
  end

  defp circuit_open?(cb) do
    case cb.state do
      :open ->
        # Check if reset timeout has passed
        if cb.last_failure && DateTime.diff(DateTime.utc_now(), cb.last_failure, :millisecond) > cb.reset_timeout_ms do
          false  # Half-open, allow one request
        else
          true
        end
      _ ->
        false
    end
  end

  defp update_circuit_breaker(config, :failure) do
    cb = config.circuit_breaker
    new_count = cb.failure_count + 1

    new_state = if new_count >= 5 do
      :open
    else
      cb.state
    end

    %{config | circuit_breaker: %{cb |
      state: new_state,
      failure_count: new_count,
      last_failure: DateTime.utc_now()
    }}
  end

  defp schedule_batch_flush do
    Process.send_after(self(), :flush_all_batches, @batch_interval_ms)
  end
end
