defmodule TamanduaServer.IocSnapshotDigest do
  @moduledoc """
  Canonical digest for a complete IOC authority snapshot.

  Every scalar is length-prefixed and nullable values have an explicit tag.
  UUIDs are encoded as their canonical 16-byte representation. Callers must
  provide rows in strict ascending `id` order.
  """

  @fields [:id, :organization_id, :type, :value, :severity, :description, :source]

  @spec sha256(non_neg_integer(), non_neg_integer(), non_neg_integer(), [map()]) ::
          {:ok, String.t()} | {:error, atom()}
  def sha256(epoch, count, byte_count, rows)
      when is_integer(epoch) and epoch >= 0 and is_integer(count) and count >= 0 and
             is_integer(byte_count) and byte_count >= 0 and is_list(rows) and
             count == length(rows) do
    with :ok <- ordered_unique_ids(rows),
         {:ok, encoded_rows} <- encode_rows(rows) do
      payload = [
        "tamandua.ioc-snapshot.v1",
        uint64(epoch),
        uint64(count),
        uint64(byte_count),
        encoded_rows
      ]

      {:ok, :crypto.hash(:sha256, payload) |> Base.encode16(case: :lower)}
    end
  end

  def sha256(_epoch, _count, _byte_count, _rows), do: {:error, :invalid_snapshot}

  defp encode_rows(rows) do
    Enum.reduce_while(rows, {:ok, []}, fn row, {:ok, encoded} ->
      case encode_row(row) do
        {:ok, value} -> {:cont, {:ok, [encoded, value]}}
        error -> {:halt, error}
      end
    end)
  end

  defp encode_row(row) when is_map(row) do
    Enum.reduce_while(@fields, {:ok, []}, fn field, {:ok, encoded} ->
      case encode_field(field, Map.get(row, field)) do
        {:ok, value} -> {:cont, {:ok, [encoded, value]}}
        error -> {:halt, error}
      end
    end)
  end

  defp encode_row(_row), do: {:error, :invalid_row}

  defp encode_field(field, nil) when field in [:organization_id, :description, :source],
    do: {:ok, <<0>>}

  defp encode_field(field, value) when field in [:id, :organization_id] and is_binary(value) do
    case Ecto.UUID.dump(value) do
      {:ok, binary} -> {:ok, [<<1>>, uint64(byte_size(binary)), binary]}
      :error -> {:error, :invalid_uuid}
    end
  end

  defp encode_field(field, value)
       when field in [:type, :value, :severity, :description, :source] and is_binary(value) do
    {:ok, [<<1>>, uint64(byte_size(value)), value]}
  end

  defp encode_field(_field, _value), do: {:error, :invalid_field}

  defp ordered_unique_ids(rows) do
    rows
    |> Enum.reduce_while({:ok, nil}, fn row, {:ok, previous} ->
      with id when is_binary(id) <- Map.get(row, :id),
           {:ok, binary} <- Ecto.UUID.dump(id),
           true <- is_nil(previous) or binary > previous do
        {:cont, {:ok, binary}}
      else
        _ -> {:halt, {:error, :unordered_or_duplicate_id}}
      end
    end)
    |> case do
      {:ok, _last} -> :ok
      error -> error
    end
  end

  defp uint64(value), do: <<value::unsigned-big-integer-size(64)>>
end
