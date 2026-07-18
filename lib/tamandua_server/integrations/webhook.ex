defmodule TamanduaServer.Integrations.Webhook do
  @moduledoc """
  Generic Webhook Integration Module

  Provides a flexible webhook output for integrating with any HTTP endpoint:
  - Configurable webhook destinations
  - Custom payload templates with variable substitution
  - Retry logic with exponential backoff
  - HMAC signature verification for security
  - Request/response logging
  - Rate limiting per destination

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.Webhook,
        destinations: [
          %{
            id: "slack-alerts",
            url: "https://hooks.slack.com/services/...",
            method: :post,
            headers: %{"Content-Type" => "application/json"},
            secret: "webhook-secret-for-hmac",
            template: "slack_alert",
            enabled: true,
            retry_attempts: 3,
            timeout_ms: 10000
          }
        ]

  ## Template Variables

  Templates support variable substitution using `{{variable}}` syntax:
  - `{{alert.title}}` - Alert title
  - `{{alert.severity}}` - Alert severity
  - `{{alert.hostname}}` - Affected hostname
  - `{{timestamp}}` - ISO8601 timestamp
  - `{{json}}` - Full JSON payload

  """

  use GenServer
  require Logger

  # Default configuration
  @default_timeout_ms 30_000
  @default_retry_attempts 3
  @default_retry_base_delay_ms 1000
  @default_rate_limit_per_minute 60

  defstruct [
    :destinations,
    :templates,
    :stats,
    :rate_limits
  ]

  defmodule Destination do
    @moduledoc "Webhook destination configuration"
    defstruct [
      :id,
      :name,
      :url,
      :method,
      :headers,
      :secret,
      :signature_header,
      :signature_algorithm,
      :template,
      :enabled,
      :retry_attempts,
      :timeout_ms,
      :rate_limit_per_minute,
      :filters,
      :transform
    ]
  end

  defmodule Template do
    @moduledoc "Webhook payload template"
    defstruct [
      :id,
      :name,
      :content_type,
      :body,
      :description
    ]
  end

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Send an alert to all matching webhook destinations.
  """
  @spec send_alert(map()) :: :ok | {:error, term()}
  def send_alert(alert) do
    GenServer.call(__MODULE__, {:send_alert, alert}, 60_000)
  end

  @doc """
  Send an event to all matching webhook destinations.
  """
  @spec send_event(map()) :: :ok | {:error, term()}
  def send_event(event) do
    GenServer.call(__MODULE__, {:send_event, event}, 60_000)
  end

  @doc """
  Send a custom payload to a specific destination.
  """
  @spec send_to_destination(String.t(), map()) :: :ok | {:error, term()}
  def send_to_destination(destination_id, payload) do
    GenServer.call(__MODULE__, {:send_to_destination, destination_id, payload}, 60_000)
  end

  @doc """
  Add a webhook destination.
  """
  @spec add_destination(map()) :: {:ok, Destination.t()} | {:error, term()}
  def add_destination(config) do
    GenServer.call(__MODULE__, {:add_destination, config})
  end

  @doc """
  Update a webhook destination.
  """
  @spec update_destination(String.t(), map()) :: {:ok, Destination.t()} | {:error, term()}
  def update_destination(destination_id, updates) do
    GenServer.call(__MODULE__, {:update_destination, destination_id, updates})
  end

  @doc """
  Remove a webhook destination.
  """
  @spec remove_destination(String.t()) :: :ok | {:error, term()}
  def remove_destination(destination_id) do
    GenServer.call(__MODULE__, {:remove_destination, destination_id})
  end

  @doc """
  List all webhook destinations.
  """
  @spec list_destinations() :: {:ok, [Destination.t()]}
  def list_destinations do
    GenServer.call(__MODULE__, :list_destinations)
  end

  @doc """
  Test a webhook destination.
  """
  @spec test_destination(String.t()) :: {:ok, map()} | {:error, term()}
  def test_destination(destination_id) do
    GenServer.call(__MODULE__, {:test_destination, destination_id}, 30_000)
  end

  @doc """
  Add a payload template.
  """
  @spec add_template(map()) :: {:ok, Template.t()} | {:error, term()}
  def add_template(template) do
    GenServer.call(__MODULE__, {:add_template, template})
  end

  @doc """
  List available templates.
  """
  @spec list_templates() :: {:ok, [Template.t()]}
  def list_templates do
    GenServer.call(__MODULE__, :list_templates)
  end

  @doc """
  Get integration statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Verify an incoming webhook signature.
  """
  @spec verify_signature(String.t(), String.t(), String.t(), atom()) :: boolean()
  def verify_signature(payload, signature, secret, algorithm \\ :sha256) do
    expected = compute_signature(payload, secret, algorithm)
    Plug.Crypto.secure_compare(expected, signature)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting Webhook Integration")

    destinations = load_destinations(opts)
    templates = load_default_templates()

    state = %__MODULE__{
      destinations: destinations,
      templates: templates,
      stats: %{
        requests_sent: 0,
        requests_failed: 0,
        retries: 0,
        last_send: nil,
        by_destination: %{}
      },
      rate_limits: %{}
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:send_alert, alert}, _from, state) do
    results = state.destinations
    |> Map.values()
    |> Enum.filter(&(&1.enabled && matches_filters?(&1, alert, :alert)))
    |> Enum.map(fn dest ->
      if check_rate_limit(dest.id, state) do
        send_webhook(dest, :alert, alert, state)
      else
        {:error, :rate_limited}
      end
    end)

    new_state = update_stats_for_results(state, results)
    {:reply, summarize_results(results), new_state}
  end

  @impl true
  def handle_call({:send_event, event}, _from, state) do
    results = state.destinations
    |> Map.values()
    |> Enum.filter(&(&1.enabled && matches_filters?(&1, event, :event)))
    |> Enum.map(fn dest ->
      if check_rate_limit(dest.id, state) do
        send_webhook(dest, :event, event, state)
      else
        {:error, :rate_limited}
      end
    end)

    new_state = update_stats_for_results(state, results)
    {:reply, summarize_results(results), new_state}
  end

  @impl true
  def handle_call({:send_to_destination, destination_id, payload}, _from, state) do
    case Map.get(state.destinations, destination_id) do
      nil ->
        {:reply, {:error, :destination_not_found}, state}

      dest ->
        if check_rate_limit(dest.id, state) do
          result = send_webhook(dest, :custom, payload, state)
          new_state = update_stats_for_results(state, [result])
          {:reply, result, new_state}
        else
          {:reply, {:error, :rate_limited}, state}
        end
    end
  end

  @impl true
  def handle_call({:add_destination, config}, _from, state) do
    destination = build_destination(config)
    new_destinations = Map.put(state.destinations, destination.id, destination)
    {:reply, {:ok, destination}, %{state | destinations: new_destinations}}
  end

  @impl true
  def handle_call({:update_destination, destination_id, updates}, _from, state) do
    case Map.get(state.destinations, destination_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      existing ->
        updated = merge_destination(existing, updates)
        new_destinations = Map.put(state.destinations, destination_id, updated)
        {:reply, {:ok, updated}, %{state | destinations: new_destinations}}
    end
  end

  @impl true
  def handle_call({:remove_destination, destination_id}, _from, state) do
    new_destinations = Map.delete(state.destinations, destination_id)
    {:reply, :ok, %{state | destinations: new_destinations}}
  end

  @impl true
  def handle_call(:list_destinations, _from, state) do
    {:reply, {:ok, Map.values(state.destinations)}, state}
  end

  @impl true
  def handle_call({:test_destination, destination_id}, _from, state) do
    case Map.get(state.destinations, destination_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      dest ->
        test_payload = %{
          type: "test",
          message: "Tamandua webhook test",
          timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
          destination_id: destination_id
        }

        result = send_webhook(dest, :test, test_payload, state)
        {:reply, result, state}
    end
  end

  @impl true
  def handle_call({:add_template, template_config}, _from, state) do
    template = %Template{
      id: template_config[:id] || generate_id(),
      name: template_config[:name],
      content_type: template_config[:content_type] || "application/json",
      body: template_config[:body],
      description: template_config[:description]
    }

    new_templates = Map.put(state.templates, template.id, template)
    {:reply, {:ok, template}, %{state | templates: new_templates}}
  end

  @impl true
  def handle_call(:list_templates, _from, state) do
    {:reply, {:ok, Map.values(state.templates)}, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp load_destinations(opts) do
    app_config = Application.get_env(:tamandua_server, __MODULE__, [])
    destinations_config = opts[:destinations] || app_config[:destinations] || []

    destinations_config
    |> Enum.map(&build_destination/1)
    |> Enum.into(%{}, fn d -> {d.id, d} end)
  end

  defp build_destination(config) do
    %Destination{
      id: config[:id] || config["id"] || generate_id(),
      name: config[:name] || config["name"] || "Webhook",
      url: config[:url] || config["url"],
      method: (config[:method] || config["method"] || :post) |> normalize_method(),
      headers: config[:headers] || config["headers"] || %{},
      secret: config[:secret] || config["secret"],
      signature_header: config[:signature_header] || config["signature_header"] || "X-Signature",
      signature_algorithm: config[:signature_algorithm] || config["signature_algorithm"] || :sha256,
      template: config[:template] || config["template"],
      enabled: config[:enabled] != false && config["enabled"] != false,
      retry_attempts: config[:retry_attempts] || config["retry_attempts"] || @default_retry_attempts,
      timeout_ms: config[:timeout_ms] || config["timeout_ms"] || @default_timeout_ms,
      rate_limit_per_minute: config[:rate_limit_per_minute] || config["rate_limit_per_minute"] || @default_rate_limit_per_minute,
      filters: config[:filters] || config["filters"] || %{},
      transform: config[:transform] || config["transform"]
    }
  end

  defp merge_destination(existing, updates) do
    updates_map = Enum.into(updates, %{})

    %{existing |
      name: updates_map[:name] || updates_map["name"] || existing.name,
      url: updates_map[:url] || updates_map["url"] || existing.url,
      method: normalize_method(updates_map[:method] || updates_map["method"] || existing.method),
      headers: updates_map[:headers] || updates_map["headers"] || existing.headers,
      secret: updates_map[:secret] || updates_map["secret"] || existing.secret,
      template: updates_map[:template] || updates_map["template"] || existing.template,
      enabled: if(Map.has_key?(updates_map, :enabled), do: updates_map[:enabled], else: existing.enabled),
      retry_attempts: updates_map[:retry_attempts] || updates_map["retry_attempts"] || existing.retry_attempts,
      timeout_ms: updates_map[:timeout_ms] || updates_map["timeout_ms"] || existing.timeout_ms,
      filters: updates_map[:filters] || updates_map["filters"] || existing.filters
    }
  end

  defp normalize_method(method) when is_atom(method), do: method
  defp normalize_method("post"), do: :post
  defp normalize_method("POST"), do: :post
  defp normalize_method("put"), do: :put
  defp normalize_method("PUT"), do: :put
  defp normalize_method("patch"), do: :patch
  defp normalize_method("PATCH"), do: :patch
  defp normalize_method(_), do: :post

  defp load_default_templates do
    %{
      "json" => %Template{
        id: "json",
        name: "JSON",
        content_type: "application/json",
        body: "{{json}}",
        description: "Full JSON payload"
      },
      "slack_alert" => %Template{
        id: "slack_alert",
        name: "Slack Alert",
        content_type: "application/json",
        body: """
        {
          "blocks": [
            {
              "type": "header",
              "text": {"type": "plain_text", "text": "{{alert.severity|upper}} Alert: {{alert.title}}"}
            },
            {
              "type": "section",
              "text": {"type": "mrkdwn", "text": "{{alert.description}}"}
            },
            {
              "type": "section",
              "fields": [
                {"type": "mrkdwn", "text": "*Host:* {{alert.hostname}}"},
                {"type": "mrkdwn", "text": "*Agent:* {{alert.agent_id}}"},
                {"type": "mrkdwn", "text": "*Time:* {{timestamp}}"},
                {"type": "mrkdwn", "text": "*MITRE:* {{alert.mitre_techniques|join:', '}}"}
              ]
            }
          ]
        }
        """,
        description: "Slack Block Kit formatted alert"
      },
      "teams_alert" => %Template{
        id: "teams_alert",
        name: "Microsoft Teams Alert",
        content_type: "application/json",
        body: """
        {
          "@type": "MessageCard",
          "@context": "http://schema.org/extensions",
          "themeColor": "{{alert.severity|color}}",
          "summary": "{{alert.title}}",
          "sections": [{
            "activityTitle": "{{alert.severity|upper}} Alert",
            "facts": [
              {"name": "Title", "value": "{{alert.title}}"},
              {"name": "Host", "value": "{{alert.hostname}}"},
              {"name": "Description", "value": "{{alert.description}}"},
              {"name": "Time", "value": "{{timestamp}}"}
            ],
            "markdown": true
          }]
        }
        """,
        description: "Microsoft Teams card formatted alert"
      },
      "pagerduty_alert" => %Template{
        id: "pagerduty_alert",
        name: "PagerDuty Alert",
        content_type: "application/json",
        body: """
        {
          "routing_key": "{{config.routing_key}}",
          "event_action": "trigger",
          "dedup_key": "{{alert.id}}",
          "payload": {
            "summary": "{{alert.title}}",
            "severity": "{{alert.severity|pagerduty_severity}}",
            "source": "{{alert.hostname}}",
            "component": "tamandua-edr",
            "custom_details": {
              "description": "{{alert.description}}",
              "mitre_tactics": "{{alert.mitre_tactics|join:', '}}",
              "mitre_techniques": "{{alert.mitre_techniques|join:', '}}",
              "threat_score": "{{alert.threat_score}}"
            }
          }
        }
        """,
        description: "PagerDuty Events API v2 format"
      },
      "syslog_cef" => %Template{
        id: "syslog_cef",
        name: "CEF Syslog",
        content_type: "text/plain",
        body: "CEF:0|Tamandua|EDR|1.0|{{alert.id}}|{{alert.title}}|{{alert.severity|cef_severity}}|src={{alert.hostname}} msg={{alert.description}}",
        description: "Common Event Format for syslog"
      }
    }
  end

  defp matches_filters?(destination, data, type) do
    filters = destination.filters

    # Check type filter
    type_ok = case filters[:types] || filters["types"] do
      nil -> true
      types -> type in types
    end

    # Check severity filter
    severity_ok = case filters[:min_severity] || filters["min_severity"] do
      nil -> true
      min_sev ->
        data_sev = data[:severity] || data["severity"]
        severity_value(data_sev) >= severity_value(min_sev)
    end

    # Check agent filter
    agent_ok = case filters[:agent_ids] || filters["agent_ids"] do
      nil -> true
      agent_ids ->
        data_agent = data[:agent_id] || data["agent_id"]
        data_agent in agent_ids
    end

    type_ok && severity_ok && agent_ok
  end

  defp severity_value(nil), do: 0
  defp severity_value("info"), do: 1
  defp severity_value("low"), do: 2
  defp severity_value("medium"), do: 3
  defp severity_value("high"), do: 4
  defp severity_value("critical"), do: 5
  defp severity_value(s) when is_atom(s), do: severity_value(to_string(s))
  defp severity_value(_), do: 0

  defp check_rate_limit(destination_id, state) do
    now = System.system_time(:second)
    minute_key = div(now, 60)

    rate_limit = get_in(state.rate_limits, [destination_id, minute_key]) || 0
    dest = Map.get(state.destinations, destination_id)
    limit = if dest, do: dest.rate_limit_per_minute, else: @default_rate_limit_per_minute

    rate_limit < limit
  end

  defp send_webhook(destination, type, data, state) do
    payload = build_payload(destination, type, data, state)
    body = encode_payload(payload, destination, state)

    headers = build_headers(destination, body)
    options = http_options(destination)

    send_with_retry(destination, body, headers, options, 0)
  end

  defp build_payload(_destination, type, data, _state) do
    base_payload = %{
      type: type,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      source: "tamandua-edr"
    }

    case type do
      :alert ->
        Map.merge(base_payload, %{
          alert: normalize_alert_data(data)
        })

      :event ->
        Map.merge(base_payload, %{
          event: data
        })

      :test ->
        Map.merge(base_payload, data)

      :custom ->
        Map.merge(base_payload, data)
    end
  end

  defp normalize_alert_data(alert) do
    %{
      id: alert[:id] || alert["id"],
      title: alert[:title] || alert["title"],
      description: alert[:description] || alert["description"],
      severity: alert[:severity] || alert["severity"],
      status: alert[:status] || alert["status"],
      hostname: alert[:hostname] || alert["hostname"],
      agent_id: alert[:agent_id] || alert["agent_id"],
      mitre_tactics: alert[:mitre_tactics] || alert["mitre_tactics"] || [],
      mitre_techniques: alert[:mitre_techniques] || alert["mitre_techniques"] || [],
      threat_score: alert[:threat_score] || alert["threat_score"],
      evidence: alert[:evidence] || alert["evidence"] || %{}
    }
  end

  defp encode_payload(payload, destination, state) do
    template = get_template(destination.template, state)

    if template && template.body != "{{json}}" do
      render_template(template.body, payload)
    else
      Jason.encode!(payload)
    end
  end

  defp get_template(nil, _state), do: nil
  defp get_template(template_id, state) do
    Map.get(state.templates, template_id)
  end

  defp render_template(template, payload) do
    # Simple template variable substitution
    Regex.replace(~r/\{\{([^}]+)\}\}/, template, fn _, var ->
      render_variable(String.trim(var), payload)
    end)
  end

  defp render_variable(var, payload) do
    case String.split(var, "|") do
      [path] ->
        get_nested_value(payload, String.split(path, "."))

      [path | filters] ->
        value = get_nested_value(payload, String.split(path, "."))
        apply_filters(value, filters)
    end
  end

  defp get_nested_value(data, []), do: to_string_safe(data)
  defp get_nested_value(data, [key | rest]) when is_map(data) do
    value = data[String.to_atom(key)] || data[key]
    get_nested_value(value, rest)
  end
  defp get_nested_value(data, _), do: to_string_safe(data)

  defp to_string_safe(nil), do: ""
  defp to_string_safe(value) when is_binary(value), do: value
  defp to_string_safe(value) when is_list(value), do: Jason.encode!(value)
  defp to_string_safe(value) when is_map(value), do: Jason.encode!(value)
  defp to_string_safe(value), do: to_string(value)

  defp apply_filters(value, []), do: value
  defp apply_filters(value, [filter | rest]) do
    filtered = apply_filter(value, String.trim(filter))
    apply_filters(filtered, rest)
  end

  defp apply_filter(value, "upper"), do: String.upcase(to_string(value))
  defp apply_filter(value, "lower"), do: String.downcase(to_string(value))
  defp apply_filter(value, "json"), do: Jason.encode!(value)

  defp apply_filter(value, "join:" <> separator) do
    case value do
      list when is_list(list) -> Enum.join(list, separator)
      _ -> to_string(value)
    end
  end

  defp apply_filter(value, "color") do
    case value do
      "critical" -> "FF0000"
      "high" -> "FFA500"
      "medium" -> "FFFF00"
      "low" -> "00FF00"
      _ -> "808080"
    end
  end

  defp apply_filter(value, "pagerduty_severity") do
    case value do
      "critical" -> "critical"
      "high" -> "error"
      "medium" -> "warning"
      "low" -> "info"
      _ -> "info"
    end
  end

  defp apply_filter(value, "cef_severity") do
    case value do
      "critical" -> "10"
      "high" -> "7"
      "medium" -> "5"
      "low" -> "3"
      _ -> "0"
    end
  end

  defp apply_filter(value, _), do: value

  defp build_headers(destination, body) do
    base_headers = destination.headers
    |> Enum.map(fn {k, v} -> {to_string(k), v} end)

    # Add content type if not present
    headers = if Enum.any?(base_headers, fn {k, _} -> String.downcase(k) == "content-type" end) do
      base_headers
    else
      [{"Content-Type", "application/json"} | base_headers]
    end

    # Add signature if secret is configured
    if destination.secret do
      signature = compute_signature(body, destination.secret, destination.signature_algorithm)
      [{destination.signature_header, signature} | headers]
    else
      headers
    end
  end

  defp compute_signature(payload, secret, algorithm) do
    algo = case algorithm do
      :sha256 -> :sha256
      :sha512 -> :sha512
      :sha1 -> :sha
      "sha256" -> :sha256
      "sha512" -> :sha512
      "sha1" -> :sha
      _ -> :sha256
    end

    :crypto.mac(:hmac, algo, secret, payload)
    |> Base.encode16(case: :lower)
    |> then(&"sha256=#{&1}")
  end

  defp http_options(destination) do
    [
      timeout: destination.timeout_ms,
      recv_timeout: destination.timeout_ms
    ]
  end

  defp send_with_retry(destination, body, headers, options, attempt) do
    result = execute_request(destination.method, destination.url, body, headers, options)

    case result do
      {:ok, response} ->
        {:ok, response}

      {:error, reason} when attempt < destination.retry_attempts ->
        delay = @default_retry_base_delay_ms * round(:math.pow(2, attempt))
        Logger.warning("Webhook to #{destination.url} failed, retrying in #{delay}ms: #{inspect(reason)}")
        Process.sleep(delay)
        send_with_retry(destination, body, headers, options, attempt + 1)

      {:error, reason} ->
        Logger.error("Webhook to #{destination.url} failed after #{attempt + 1} attempts: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp execute_request(method, url, body, headers, options) do
    timeout = Keyword.get(options, :recv_timeout, 30_000)

    case method do
      :post -> Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: timeout)
      :put -> Finch.build(:put, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: timeout)
      :patch -> Finch.build(:patch, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: timeout)
      _ -> Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: timeout)
    end
    |> case do
      {:ok, %{status_code: code, body: resp_body}} when code in 200..299 ->
        {:ok, %{status_code: code, body: resp_body}}

      {:ok, %{status_code: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{String.slice(resp_body, 0, 200)}"}

      {:error, %{reason: reason}} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp update_stats_for_results(state, results) do
    {successes, failures} = Enum.split_with(results, fn
      {:ok, _} -> true
      :ok -> true
      _ -> false
    end)

    new_stats = state.stats
    |> Map.update(:requests_sent, length(successes), &(&1 + length(successes)))
    |> Map.update(:requests_failed, length(failures), &(&1 + length(failures)))
    |> Map.put(:last_send, DateTime.utc_now())

    %{state | stats: new_stats}
  end

  defp summarize_results(results) do
    failures = Enum.filter(results, fn
      {:error, _} -> true
      _ -> false
    end)

    if length(failures) == 0 do
      :ok
    else
      {:error, "#{length(failures)} webhook(s) failed"}
    end
  end

  defp generate_id do
    :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
  end
end
