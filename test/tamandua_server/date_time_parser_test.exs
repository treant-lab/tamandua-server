defmodule TamanduaServer.DateTimeParserTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.DateTimeParser

  test "parses HTTP date variants as UTC datetimes" do
    assert {:ok, ~U[2024-01-01 12:00:00Z]} =
             DateTimeParser.parse_utc("Mon, 01 Jan 2024 12:00:00 GMT")

    assert {:ok, ~U[2024-01-01 12:00:00Z]} =
             DateTimeParser.parse_utc("Monday, 01-Jan-24 12:00:00 GMT")

    assert {:ok, ~U[2024-01-01 12:00:00Z]} =
             DateTimeParser.parse_utc("Mon Jan 1 12:00:00 2024")
  end

  test "parses integration timestamp variants" do
    assert {:ok, ~U[2024-05-03 01:02:03Z]} =
             DateTimeParser.parse_utc("2024/05/03 01:02:03")

    assert {:ok, ~U[2024-05-03 01:02:03Z]} =
             DateTimeParser.parse_utc("2024-05-03T01:02:03")

    assert {:ok, ~U[2024-05-03 01:02:03Z]} =
             DateTimeParser.parse_utc("3May2024 01:02:03")
  end

  test "parses syslog and OpenSSL certificate timestamps" do
    assert {:ok, ~U[2026-03-01 12:00:00Z]} =
             DateTimeParser.parse_syslog("Mar  1 12:00:00", 2026)

    assert {:ok, ~U[2026-03-01 12:00:00Z]} =
             DateTimeParser.parse_utc("Mar  1 12:00:00 2026 GMT")
  end

  test "returns an error for invalid input" do
    assert {:error, :invalid_date} = DateTimeParser.parse_utc("not a date")
  end
end
