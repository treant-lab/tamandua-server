defmodule TamanduaServer.Alerts.Timestamp do
  @moduledoc false

  @last_sort_key 9_223_372_036_854_775_807

  def normalize(%DateTime{} = dt), do: dt

  def normalize(%NaiveDateTime{} = ndt) do
    DateTime.from_naive!(ndt, "Etc/UTC")
  end

  def normalize(value) when is_binary(value) do
    trimmed = String.trim(value)

    case DateTime.from_iso8601(trimmed) do
      {:ok, dt, _offset} ->
        dt

      _ ->
        case NaiveDateTime.from_iso8601(String.trim_trailing(trimmed, "Z")) do
          {:ok, ndt} -> DateTime.from_naive!(ndt, "Etc/UTC")
          _ -> nil
        end
    end
  end

  def normalize(value) when is_integer(value) do
    unit = if abs(value) > 10_000_000_000, do: :millisecond, else: :second

    case DateTime.from_unix(value, unit) do
      {:ok, dt} -> dt
      _ -> nil
    end
  end

  def normalize(_), do: nil

  def sort_key(value, missing \\ :last) do
    case normalize(value) do
      %DateTime{} = dt -> DateTime.to_unix(dt, :microsecond)
      nil when missing == :first -> -@last_sort_key
      nil -> @last_sort_key
    end
  end

  def compare(left, right) do
    with %DateTime{} = left_dt <- normalize(left),
         %DateTime{} = right_dt <- normalize(right) do
      DateTime.compare(left_dt, right_dt)
    else
      _ -> nil
    end
  end

  def diff(left, right, unit \\ :second) do
    with %DateTime{} = left_dt <- normalize(left),
         %DateTime{} = right_dt <- normalize(right) do
      DateTime.diff(left_dt, right_dt, unit)
    else
      _ -> nil
    end
  end

  def iso8601(value) do
    case normalize(value) do
      %DateTime{} = dt -> DateTime.to_iso8601(dt)
      nil -> nil
    end
  end
end
