defmodule TamanduaServer.XDR.Parser do
  @moduledoc """
  Unified parser module for XDR log formats.

  Provides a common interface to all format-specific parsers:
  - CEF (Common Event Format)
  - LEEF (Log Event Extended Format)
  - JSON (including cloud audit logs)
  - Syslog (RFC 5424 and RFC 3164)
  - Generic (heuristic-based)
  """

  alias TamanduaServer.XDR.Parser.{CEF, LEEF, JSON, Syslog, Generic}

  @doc """
  Auto-detect format and parse a log event.

  Returns {:ok, map} on success, {:error, reason} on failure.
  """
  @spec parse(binary() | map()) :: {:ok, map()} | {:error, term()}
  def parse(data) when is_map(data) do
    JSON.parse(data)
  end

  def parse(data) when is_binary(data) do
    format = detect_format(data)
    parse(data, format)
  end

  def parse(_), do: {:error, :invalid_input}

  @doc """
  Parse a log event with a specific format.
  """
  @spec parse(binary() | map(), atom() | String.t()) :: {:ok, map()} | {:error, term()}
  def parse(data, format) when is_binary(format) do
    parse(data, String.to_existing_atom(format))
  rescue
    ArgumentError -> parse(data, :generic)
  end

  def parse(data, :cef), do: CEF.parse(data)
  def parse(data, :leef), do: LEEF.parse(data)
  def parse(data, :json), do: JSON.parse(data)
  def parse(data, :syslog), do: Syslog.parse(data)
  def parse(data, :generic), do: Generic.parse(data)
  def parse(data, _), do: Generic.parse(data)

  @doc """
  Detect the format of a log line.
  """
  @spec detect_format(binary() | map()) :: atom()
  def detect_format(data) when is_map(data), do: :json

  def detect_format(data) when is_binary(data) do
    data = String.trim(data)

    cond do
      # CEF format
      String.contains?(data, "CEF:") -> :cef

      # LEEF format
      String.contains?(data, "LEEF:") -> :leef

      # JSON (starts with { or [)
      String.starts_with?(data, "{") or String.starts_with?(data, "[") -> :json

      # Syslog (starts with <priority>)
      String.starts_with?(data, "<") and Regex.match?(~r/^<\d+>/, data) -> :syslog

      # Default to generic parsing
      true -> :generic
    end
  end

  def detect_format(_), do: :generic

  @doc """
  Batch parse multiple log lines.
  Returns a list of {result, original} tuples.
  """
  @spec parse_batch([binary() | map()]) :: [{({:ok, map()} | {:error, term()}), term()}]
  def parse_batch(lines) do
    Enum.map(lines, fn line ->
      {parse(line), line}
    end)
  end

  @doc """
  Batch parse multiple log lines, filtering out failures.
  Returns only successfully parsed events.
  """
  @spec parse_batch_ok([binary() | map()]) :: [map()]
  def parse_batch_ok(lines) do
    lines
    |> parse_batch()
    |> Enum.filter(fn {{status, _}, _} -> status == :ok end)
    |> Enum.map(fn {{:ok, event}, _} -> event end)
  end
end
