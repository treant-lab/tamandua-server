defmodule TamanduaServer.Integrations.SIEM.QRadar do
  @moduledoc """
  IBM QRadar SIEM connector for bidirectional integration.

  Provides:
  - `send_syslog/3` - Forward events via syslog (RFC 5424 format)
  - `send_reference_data/3` - Update QRadar reference sets via REST API
  - `search_aql/3` - Execute AQL (Ariel Query Language) searches
  - `test_connection/1` - Validate API token and connectivity

  Configurable: host, port, token, TLS.
  """

  require Logger

  alias TamanduaServer.Integrations.IntegrationLog

  @default_syslog_port 514
  @default_api_port 443
  @default_timeout_ms 30_000
  @aql_poll_max_attempts 60

  @type config :: %{
          optional(:host) => String.t(),
          optional(:port) => non_neg_integer(),
          optional(:api_port) => non_neg_integer(),
          optional(:token) => String.t(),
          optional(:tls) => boolean(),
          optional(:timeout_ms) => non_neg_integer(),
          optional(:verify_ssl) => boolean()
        }

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Forward events to QRadar via syslog (RFC 5424) using LEEF format.

  ## Parameters

  - `events` - List of event maps
  - `config` - QRadar configuration map with `:host`, `:port`
  - `opts` - Optional: `:protocol` (`:udp` | `:tcp`, default `:udp`)

  ## Returns

  `:ok` on success, `{:error, reason}` on failure.
  """
  @spec send_syslog(list(map()), config(), keyword()) :: :ok | {:error, term()}
  def send_syslog(events, config, opts \\ []) when is_list(events) do
    host = to_charlist(config[:host] || "localhost")
    port = config[:port] || @default_syslog_port
    protocol = opts[:protocol] || :udp

    messages = Enum.map(events, &format_syslog_leef/1)

    IntegrationLog.log_api_call("qradar", "send_syslog", "#{length(events)} events", fn ->
      case protocol do
        :udp -> send_udp_syslog(host, port, messages)
        :tcp -> send_tcp_syslog(host, port, messages, config)
      end
    end)
  end

  @doc """
  Update a QRadar reference set via the REST API.

  Reference sets are used to store IOCs, IP addresses, hashes, etc.
  that QRadar rules can match against.

  ## Parameters

  - `set_name` - Name of the reference set
  - `values` - List of values to add to the set
  - `config` - QRadar configuration map with `:host`, `:token`

  ## Returns

  `:ok` on success, `{:error, reason}` on failure.
  """
  @spec send_reference_data(String.t(), list(String.t()), config()) :: :ok | {:error, term()}
  def send_reference_data(set_name, values, config) when is_list(values) do
    base_url = api_base_url(config)
    timeout = config[:timeout_ms] || @default_timeout_ms

    headers = [
      {"SEC", config[:token]},
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    IntegrationLog.log_api_call("qradar", "send_reference_data", "#{set_name}: #{length(values)} values", fn ->
      results =
        Enum.map(values, fn value ->
          encoded_name = URI.encode(set_name)
          encoded_value = URI.encode(value)
          url = "#{base_url}/api/reference_data/sets/#{encoded_name}?value=#{encoded_value}"

          case do_http(:post, url, headers, nil, timeout) do
            {:ok, %{status: status}} when status in 200..299 -> :ok
            {:ok, %{status: status, body: body}} -> {:error, "HTTP #{status}: #{truncate(body)}"}
            {:error, reason} -> {:error, reason}
          end
        end)

      errors = Enum.filter(results, &match?({:error, _}, &1))

      if errors == [] do
        :ok
      else
        {:error, "#{length(errors)}/#{length(values)} reference data updates failed"}
      end
    end)
  end

  @doc """
  Execute an AQL (Ariel Query Language) search via the QRadar REST API.

  ## Parameters

  - `aql_query` - AQL query string
  - `config` - QRadar configuration map with `:host`, `:token`
  - `opts` - Optional: `:range` (e.g., "items=0-49")

  ## Returns

  `{:ok, results}` on success, `{:error, reason}` on failure.
  """
  @spec search_aql(String.t(), config(), keyword()) :: {:ok, map()} | {:error, term()}
  def search_aql(aql_query, config, opts \\ []) do
    base_url = api_base_url(config)
    timeout = config[:timeout_ms] || @default_timeout_ms

    headers = [
      {"SEC", config[:token]},
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    headers = if range = opts[:range] do
      [{"Range", range} | headers]
    else
      headers
    end

    # Dispatch the search
    search_url = "#{base_url}/api/ariel/searches"
    body = URI.encode_query(%{"query_expression" => aql_query})

    IntegrationLog.log_api_call("qradar", "search_aql", aql_query, fn ->
      with {:ok, search_id} <- dispatch_aql_search(search_url, headers, body, timeout),
           {:ok, results} <- poll_aql_results(base_url, search_id, headers, timeout) do
        {:ok, results}
      end
    end)
  end

  @doc """
  Validate QRadar API token and endpoint connectivity.

  ## Parameters

  - `config` - QRadar configuration map

  ## Returns

  `{:ok, %{version: ...}}` on success, `{:error, reason}` on failure.
  """
  @spec test_connection(config()) :: {:ok, map()} | {:error, term()}
  def test_connection(config) do
    base_url = api_base_url(config)
    url = "#{base_url}/api/system/about"
    timeout = config[:timeout_ms] || @default_timeout_ms

    headers = [
      {"SEC", config[:token]},
      {"Accept", "application/json"}
    ]

    case do_http(:get, url, headers, nil, timeout) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, Jason.decode!(body)}

      {:ok, %{status: status, body: body}} ->
        {:error, "QRadar API check failed: HTTP #{status} - #{truncate(body)}"}

      {:error, reason} ->
        {:error, "Connection failed: #{inspect(reason)}"}
    end
  rescue
    e -> {:error, "Connection test error: #{Exception.message(e)}"}
  end

  # ============================================================================
  # Private: Syslog Transport
  # ============================================================================

  defp send_udp_syslog(host, port, messages) do
    case :gen_udp.open(0) do
      {:ok, socket} ->
        Enum.each(messages, fn msg ->
          :gen_udp.send(socket, host, port, String.to_charlist(msg))
        end)

        :gen_udp.close(socket)
        :ok

      {:error, reason} ->
        {:error, {:udp_error, reason}}
    end
  end

  defp send_tcp_syslog(host, port, messages, config) do
    tcp_opts = [:binary, active: false, packet: 0]

    tcp_opts =
      if config[:tls] do
        ssl_opts = [verify: if(config[:verify_ssl] != false, do: :verify_peer, else: :verify_none)]
        Keyword.put(tcp_opts, :ssl, ssl_opts)
      else
        tcp_opts
      end

    case :gen_tcp.connect(host, port, tcp_opts, 10_000) do
      {:ok, socket} ->
        result =
          Enum.reduce_while(messages, :ok, fn msg, _acc ->
            # RFC 5425: length-prefixed syslog over TCP
            framed = "#{byte_size(msg)} #{msg}"

            case :gen_tcp.send(socket, framed) do
              :ok -> {:cont, :ok}
              {:error, reason} -> {:halt, {:error, {:tcp_send_error, reason}}}
            end
          end)

        :gen_tcp.close(socket)
        result

      {:error, reason} ->
        {:error, {:tcp_connect_error, reason}}
    end
  end

  # ============================================================================
  # Private: LEEF Event Formatting
  # ============================================================================

  defp format_syslog_leef(event) do
    timestamp = extract_iso_timestamp(event)
    hostname = alert_field(event, :hostname) || "tamandua-edr"
    severity = syslog_severity(alert_field(event, :severity))
    facility = 10
    priority = facility * 8 + severity

    # LEEF 2.0 header: LEEF:Version|Vendor|Product|Version|EventID|
    event_type = alert_field(event, :type) || alert_field(event, :event_type) || "generic"

    attrs =
      [
        "devTime=#{timestamp}",
        "src=#{hostname}",
        "cat=#{event_type}",
        "sev=#{alert_field(event, :severity) || "info"}"
      ]
      |> add_leef_attr("usrName", alert_field(event, :user))
      |> add_leef_attr("dstIP", alert_field(event, :remote_ip))
      |> add_leef_attr("dstPort", alert_field(event, :remote_port))
      |> add_leef_attr("fileHash", alert_field(event, :sha256))
      |> Enum.join("\t")

    leef_payload = "LEEF:2.0|Tamandua|EDR|1.0|#{event_type}|#{attrs}"

    # RFC 5424 syslog header
    "<#{priority}>1 #{timestamp} #{hostname} tamandua-edr - - - #{leef_payload}"
  end

  defp add_leef_attr(attrs, _key, nil), do: attrs
  defp add_leef_attr(attrs, _key, ""), do: attrs
  defp add_leef_attr(attrs, key, value), do: attrs ++ ["#{key}=#{value}"]

  defp syslog_severity("critical"), do: 2
  defp syslog_severity("high"), do: 3
  defp syslog_severity("medium"), do: 4
  defp syslog_severity("low"), do: 5
  defp syslog_severity("info"), do: 6
  defp syslog_severity(_), do: 6

  # ============================================================================
  # Private: AQL Search
  # ============================================================================

  defp dispatch_aql_search(url, headers, body, timeout) do
    case do_http(:post, url, headers ++ [{"Content-Type", "application/x-www-form-urlencoded"}], body, timeout) do
      {:ok, %{status: 201, body: resp_body}} ->
        response = Jason.decode!(resp_body)
        {:ok, response["search_id"]}

      {:ok, %{status: status, body: resp_body}} ->
        {:error, "AQL dispatch failed: HTTP #{status} - #{truncate(resp_body)}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp poll_aql_results(base_url, search_id, headers, timeout, attempts \\ 0) do
    if attempts > @aql_poll_max_attempts do
      {:error, :search_timeout}
    else
      url = "#{base_url}/api/ariel/searches/#{search_id}"

      case do_http(:get, url, headers, nil, timeout) do
        {:ok, %{status: 200, body: body}} ->
          response = Jason.decode!(body)

          if response["status"] == "COMPLETED" do
            # Fetch results
            results_url = "#{base_url}/api/ariel/searches/#{search_id}/results"

            case do_http(:get, results_url, headers, nil, timeout) do
              {:ok, %{status: 200, body: results_body}} ->
                {:ok, Jason.decode!(results_body)}

              {:ok, %{status: status, body: results_body}} ->
                {:error, "AQL results failed: HTTP #{status} - #{truncate(results_body)}"}

              {:error, reason} ->
                {:error, reason}
            end
          else
            Process.sleep(1_000)
            poll_aql_results(base_url, search_id, headers, timeout, attempts + 1)
          end

        {:ok, %{status: status, body: body}} ->
          {:error, "AQL poll failed: HTTP #{status} - #{truncate(body)}"}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  # ============================================================================
  # Private: HTTP
  # ============================================================================

  defp do_http(method, url, headers, body, timeout) do
    request = Finch.build(method, url, headers, body)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: timeout) do
      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        {:ok, %{status: status, body: resp_body}}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  # ============================================================================
  # Private: Helpers
  # ============================================================================

  defp api_base_url(config) do
    protocol = if config[:tls] != false, do: "https", else: "http"
    port = config[:api_port] || @default_api_port
    "#{protocol}://#{config[:host]}:#{port}"
  end

  defp extract_iso_timestamp(data) do
    ts = alert_field(data, :timestamp) || alert_field(data, :created_at)

    case ts do
      %DateTime{} = dt -> DateTime.to_iso8601(dt)
      s when is_binary(s) -> s
      _ -> DateTime.utc_now() |> DateTime.to_iso8601()
    end
  end

  defp alert_field(data, key) when is_atom(key) do
    Map.get(data, key) || Map.get(data, to_string(key))
  end

  defp truncate(str) when is_binary(str) and byte_size(str) > 500 do
    String.slice(str, 0, 500) <> "..."
  end

  defp truncate(str) when is_binary(str), do: str
  defp truncate(other), do: inspect(other)
end
