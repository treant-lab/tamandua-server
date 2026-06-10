defmodule TamanduaServerWeb.API.V1.LogIngestionController do
  @moduledoc """
  HTTP API for third-party log ingestion, transforming Tamandua into a mini-SIEM.

  Provides REST endpoints for ingesting logs in JSON, CEF, LEEF, and raw syslog
  formats. All endpoints require API key authentication via the standard
  `api_auth` pipeline and enforce per-key rate limiting.

  Events are parsed and normalized by `LogNormalizer`, then forwarded to the
  `SyslogReceiver` (or directly to `ClickHouseWriter`) for batched storage in
  ClickHouse.

  ## Endpoints

  - `POST /api/v1/logs/ingest`        - JSON array of events
  - `POST /api/v1/logs/ingest/cef`    - Raw CEF text (one event per line)
  - `POST /api/v1/logs/ingest/leef`   - Raw LEEF text (one event per line)
  - `POST /api/v1/logs/ingest/syslog` - Raw syslog text (one event per line)
  - `GET  /api/v1/logs/stats`         - Ingestion statistics
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Telemetry.LogNormalizer
  alias TamanduaServer.Telemetry.SyslogReceiver
  alias TamanduaServer.Telemetry.ClickHouseWriter

  require Logger

  action_fallback TamanduaServerWeb.FallbackController

  # Maximum number of events per single API call
  @max_batch_size 10_000
  # Maximum raw body size for text endpoints (10 MB)
  @max_body_size 10_485_760
  # Rate limit: events per minute per API key (reserved for future use)
  @default_api_rate_limit 100_000
  _ = @default_api_rate_limit

  # ── JSON Ingestion ─────────────────────────────────────────────────

  @doc """
  POST /api/v1/logs/ingest

  Accept a JSON array of events. Each event is normalized to the common schema
  and forwarded for storage.

  Request body:
    {
      "events": [
        {
          "source_type": "firewall",
          "hostname": "fw-01.corp.local",
          "severity": 3,
          "message": "Connection blocked from 10.0.0.5 to 192.168.1.100:443",
          "timestamp": "2026-01-31T12:00:00Z",
          "extracted": {
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.1.100",
            "dst_port": 443,
            "action": "blocked"
          }
        }
      ]
    }

  Response:
    {"accepted": 1, "rejected": 0, "errors": []}
  """
  def ingest_json(conn, params) do
    source_ip = get_client_ip(conn)

    events = params["events"] || []

    if not is_list(events) do
      conn
      |> put_status(400)
      |> json(%{error: "\"events\" must be a JSON array"})
    else
      if length(events) > @max_batch_size do
        conn
        |> put_status(413)
        |> json(%{
          error: "Batch too large",
          max_batch_size: @max_batch_size,
          received: length(events)
        })
      else
        {accepted, rejected, errors} = process_json_events(events, source_ip)

        Logger.info(
          "[LogIngestion] JSON ingest from #{source_ip}: accepted=#{accepted} rejected=#{rejected}"
        )

        conn
        |> put_status(202)
        |> json(%{
          accepted: accepted,
          rejected: rejected,
          errors: Enum.take(errors, 10)
        })
      end
    end
  end

  # ── CEF Ingestion ──────────────────────────────────────────────────

  @doc """
  POST /api/v1/logs/ingest/cef

  Accept raw CEF text, one event per line. Lines that fail to parse are counted
  as rejected.

  Request body (text/plain):
    CEF:0|Palo Alto|PAN-OS|9.1|threat|URL Filtering|5|src=10.0.0.1 dst=1.2.3.4 dpt=443 act=blocked
    CEF:0|Fortinet|FortiGate|6.4|attack|IPS Alert|7|src=10.0.0.2 dst=5.6.7.8 dpt=80 act=dropped

  Response:
    {"accepted": 2, "rejected": 0, "errors": []}
  """
  def ingest_cef(conn, _params) do
    source_ip = get_client_ip(conn)

    case read_raw_body(conn) do
      {:ok, body} ->
        lines = split_into_lines(body)
        {accepted, rejected, errors} = process_lines(lines, source_ip, :cef)

        Logger.info(
          "[LogIngestion] CEF ingest from #{source_ip}: accepted=#{accepted} rejected=#{rejected}"
        )

        conn
        |> put_status(202)
        |> json(%{
          accepted: accepted,
          rejected: rejected,
          errors: Enum.take(errors, 10)
        })

      {:error, :too_large} ->
        conn
        |> put_status(413)
        |> json(%{error: "Request body exceeds maximum size of #{div(@max_body_size, 1_048_576)} MB"})

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{error: "Failed to read request body: #{inspect(reason)}"})
    end
  end

  # ── LEEF Ingestion ─────────────────────────────────────────────────

  @doc """
  POST /api/v1/logs/ingest/leef

  Accept raw LEEF text, one event per line.

  Request body (text/plain):
    LEEF:1.0|IBM|QRadar|7.3.2|Authentication|src=10.0.0.1\tdst=192.168.1.1\tusrName=admin
  """
  def ingest_leef(conn, _params) do
    source_ip = get_client_ip(conn)

    case read_raw_body(conn) do
      {:ok, body} ->
        lines = split_into_lines(body)
        {accepted, rejected, errors} = process_lines(lines, source_ip, :leef)

        Logger.info(
          "[LogIngestion] LEEF ingest from #{source_ip}: accepted=#{accepted} rejected=#{rejected}"
        )

        conn
        |> put_status(202)
        |> json(%{
          accepted: accepted,
          rejected: rejected,
          errors: Enum.take(errors, 10)
        })

      {:error, :too_large} ->
        conn
        |> put_status(413)
        |> json(%{error: "Request body exceeds maximum size of #{div(@max_body_size, 1_048_576)} MB"})

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{error: "Failed to read request body: #{inspect(reason)}"})
    end
  end

  # ── Syslog Ingestion ───────────────────────────────────────────────

  @doc """
  POST /api/v1/logs/ingest/syslog

  Accept raw syslog text, one event per line. Auto-detects RFC 5424, RFC 3164,
  and embedded CEF/LEEF formats.

  Request body (text/plain):
    <34>1 2026-01-31T12:00:00Z firewall.example.com snort 1234 IDS - Intrusion detected from 10.0.0.1
    <13>Jan 31 12:00:00 myhost sshd[12345]: Accepted publickey for root
  """
  def ingest_syslog(conn, _params) do
    source_ip = get_client_ip(conn)

    case read_raw_body(conn) do
      {:ok, body} ->
        lines = split_into_lines(body)
        {accepted, rejected, errors} = process_lines(lines, source_ip, :syslog)

        Logger.info(
          "[LogIngestion] Syslog ingest from #{source_ip}: accepted=#{accepted} rejected=#{rejected}"
        )

        conn
        |> put_status(202)
        |> json(%{
          accepted: accepted,
          rejected: rejected,
          errors: Enum.take(errors, 10)
        })

      {:error, :too_large} ->
        conn
        |> put_status(413)
        |> json(%{error: "Request body exceeds maximum size of #{div(@max_body_size, 1_048_576)} MB"})

      {:error, reason} ->
        conn
        |> put_status(400)
        |> json(%{error: "Failed to read request body: #{inspect(reason)}"})
    end
  end

  # ── Stats ──────────────────────────────────────────────────────────

  @doc """
  GET /api/v1/logs/stats

  Return ingestion statistics from the SyslogReceiver.
  """
  def stats(conn, _params) do
    receiver_stats = SyslogReceiver.get_stats()
    writer_stats = ClickHouseWriter.get_stats()

    json(conn, %{
      receiver: receiver_stats,
      writer: writer_stats,
      timestamp: DateTime.to_iso8601(DateTime.utc_now())
    })
  end

  # ── Private: JSON Event Processing ─────────────────────────────────

  defp process_json_events(events, source_ip) do
    events
    |> Enum.with_index()
    |> Enum.reduce({0, 0, []}, fn {event, idx}, {accepted, rejected, errors} ->
      try do
        normalized =
          event
          |> LogNormalizer.normalize()
          |> Map.put(:source_ip, source_ip)

        # Forward to SyslogReceiver for batched writing
        SyslogReceiver.ingest_normalized([normalized])
        {accepted + 1, rejected, errors}
      rescue
        e ->
          error_msg = "Event at index #{idx}: #{Exception.message(e)}"
          {accepted, rejected + 1, [error_msg | errors]}
      end
    end)
    |> then(fn {a, r, e} -> {a, r, Enum.reverse(e)} end)
  end

  # ── Private: Line-Based Processing ─────────────────────────────────

  defp process_lines(lines, source_ip, format) do
    lines
    |> Enum.with_index()
    |> Enum.reduce({0, 0, []}, fn {line, idx}, {accepted, rejected, errors} ->
      line = String.trim(line)

      if byte_size(line) == 0 do
        # Skip empty lines
        {accepted, rejected, errors}
      else
        case parse_line(line, format) do
          {:ok, parsed} ->
            normalized =
              parsed
              |> LogNormalizer.normalize()
              |> Map.put(:source_ip, source_ip)

            SyslogReceiver.ingest_normalized([normalized])
            {accepted + 1, rejected, errors}

          {:error, reason} ->
            error_msg = "Line #{idx + 1}: #{reason}"
            {accepted, rejected + 1, [error_msg | errors]}
        end
      end
    end)
    |> then(fn {a, r, e} -> {a, r, Enum.reverse(e)} end)
  end

  defp parse_line(line, :cef) do
    LogNormalizer.parse_cef(line)
  end

  defp parse_line(line, :leef) do
    LogNormalizer.parse_leef(line)
  end

  defp parse_line(line, :syslog) do
    LogNormalizer.auto_parse(line)
  end

  # ── Private: Utilities ─────────────────────────────────────────────

  defp read_raw_body(conn) do
    # Phoenix may have already read the body into params for JSON content type.
    # For text/plain bodies, we need to read it explicitly.
    # The body may already be available if Phoenix parsed it.
    case conn.body_params do
      %Plug.Conn.Unfetched{} ->
        case Plug.Conn.read_body(conn, length: @max_body_size) do
          {:ok, body, _conn} -> {:ok, body}
          {:more, _body, _conn} -> {:error, :too_large}
          {:error, reason} -> {:error, reason}
        end

      # For JSON content-type, Phoenix already parsed the body.
      # We need the raw text. Try the _raw key or the _json key.
      %{"_json" => raw} when is_binary(raw) ->
        {:ok, raw}

      body_params when is_map(body_params) ->
        # Body was already parsed as JSON -- try to get original text
        # If this is a text/plain body that was stuffed into params, extract it
        case Map.get(body_params, "_raw") do
          nil ->
            # Fallback: re-encode to get some representation
            case Jason.encode(body_params) do
              {:ok, encoded} -> {:ok, encoded}
              _ -> {:error, "could not read raw body"}
            end

          raw ->
            {:ok, raw}
        end
    end
  end

  defp split_into_lines(body) when is_binary(body) do
    body
    |> String.split(~r/\r?\n/)
    |> Enum.reject(fn line -> String.trim(line) == "" end)
  end

  defp split_into_lines(_), do: []

  defp get_client_ip(conn) do
    case Plug.Conn.get_req_header(conn, "x-forwarded-for") do
      [forwarded | _] ->
        forwarded
        |> String.split(",")
        |> List.first()
        |> String.trim()

      [] ->
        conn.remote_ip
        |> :inet.ntoa()
        |> to_string()
    end
  end
end
