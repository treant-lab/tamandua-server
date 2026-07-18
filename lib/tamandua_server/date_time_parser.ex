defmodule TamanduaServer.DateTimeParser do
  @moduledoc """
  Small UTC datetime parser for the timestamp formats accepted by server integrations.

  This intentionally covers the formats used in telemetry, HTTP cache headers, and
  certificate parsing without depending on Timex/tzdata.
  """

  @months %{
    "jan" => 1,
    "feb" => 2,
    "mar" => 3,
    "apr" => 4,
    "may" => 5,
    "jun" => 6,
    "jul" => 7,
    "aug" => 8,
    "sep" => 9,
    "oct" => 10,
    "nov" => 11,
    "dec" => 12
  }

  @doc """
  Parses a timestamp as UTC.

  Returns `{:ok, %DateTime{}}` or `{:error, :invalid_date}`.
  """
  def parse_utc(value) when is_binary(value) do
    value = String.trim(value)

    parsers = [
      &parse_iso8601/1,
      &parse_ymd_datetime/1,
      &parse_http_rfc1123/1,
      &parse_http_rfc850/1,
      &parse_ansi_c/1,
      &parse_checkpoint_native/1
    ]

    Enum.find_value(parsers, {:error, :invalid_date}, fn parser ->
      case parser.(value) do
        {:ok, %DateTime{} = datetime} -> {:ok, datetime}
        _ -> nil
      end
    end)
  end

  def parse_utc(%DateTime{} = datetime), do: {:ok, datetime}
  def parse_utc(_), do: {:error, :invalid_date}

  def parse_utc!(value, fallback \\ DateTime.utc_now()) do
    case parse_utc(value) do
      {:ok, datetime} -> datetime
      {:error, _} -> fallback
    end
  end

  def parse_syslog(value, year \\ DateTime.utc_now().year) when is_binary(value) do
    case Regex.run(~r/^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})$/, String.trim(value)) do
      [_, mon, day, hour, min, sec] ->
        build_datetime(year, month_number(mon), day, hour, min, sec)

      _ ->
        {:error, :invalid_date}
    end
  end

  defp parse_iso8601(value) do
    normalized =
      if String.contains?(value, " ") and String.match?(value, ~r/^\d{4}-\d{2}-\d{2}\s/) do
        String.replace(value, " ", "T", parts: 2)
      else
        value
      end

    case DateTime.from_iso8601(normalized) do
      {:ok, datetime, _offset} -> {:ok, DateTime.shift_zone!(datetime, "Etc/UTC")}
      _ -> parse_naive_iso8601(normalized)
    end
  end

  defp parse_naive_iso8601(value) do
    case NaiveDateTime.from_iso8601(value) do
      {:ok, naive} -> {:ok, DateTime.from_naive!(naive, "Etc/UTC")}
      _ -> {:error, :invalid_date}
    end
  end

  defp parse_ymd_datetime(value) do
    case Regex.run(~r/^(\d{4})[\/-](\d{1,2})[\/-](\d{1,2})[ T](\d{1,2}):(\d{2}):(\d{2})$/, value) do
      [_, year, month, day, hour, min, sec] -> build_datetime(year, month, day, hour, min, sec)
      _ -> {:error, :invalid_date}
    end
  end

  defp parse_http_rfc1123(value) do
    case Regex.run(~r/^[A-Za-z]{3},\s+(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\s+GMT$/, value) do
      [_, day, mon, year, hour, min, sec] -> build_datetime(year, month_number(mon), day, hour, min, sec)
      _ -> {:error, :invalid_date}
    end
  end

  defp parse_http_rfc850(value) do
    case Regex.run(~r/^[A-Za-z]+,\s+(\d{1,2})-([A-Za-z]{3})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})\s+GMT$/, value) do
      [_, day, mon, yy, hour, min, sec] ->
        year = if String.to_integer(yy) >= 70, do: "19#{yy}", else: "20#{yy}"
        build_datetime(year, month_number(mon), day, hour, min, sec)

      _ ->
        {:error, :invalid_date}
    end
  end

  defp parse_ansi_c(value) do
    case Regex.run(~r/^[A-Za-z]{3}\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})(?:\s+GMT)?$/, value) do
      [_, mon, day, hour, min, sec, year] -> build_datetime(year, month_number(mon), day, hour, min, sec)
      _ -> {:error, :invalid_date}
    end
  end

  defp parse_checkpoint_native(value) do
    case Regex.run(~r/^(\d{1,2})([A-Za-z]{3})(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})$/, value) do
      [_, day, mon, year, hour, min, sec] -> build_datetime(year, month_number(mon), day, hour, min, sec)
      _ -> {:error, :invalid_date}
    end
  end

  defp month_number(nil), do: nil
  defp month_number(month), do: Map.get(@months, String.downcase(to_string(month)))

  defp build_datetime(_year, nil, _day, _hour, _min, _sec), do: {:error, :invalid_date}

  defp build_datetime(year, month, day, hour, min, sec) do
    with {year, ""} <- Integer.parse(to_string(year)),
         {month, ""} <- Integer.parse(to_string(month)),
         {day, ""} <- Integer.parse(to_string(day)),
         {hour, ""} <- Integer.parse(to_string(hour)),
         {min, ""} <- Integer.parse(to_string(min)),
         {sec, ""} <- Integer.parse(to_string(sec)),
         {:ok, date} <- Date.new(year, month, day),
         {:ok, time} <- Time.new(hour, min, sec),
         {:ok, naive} <- NaiveDateTime.new(date, time) do
      {:ok, DateTime.from_naive!(naive, "Etc/UTC")}
    else
      _ -> {:error, :invalid_date}
    end
  end
end
