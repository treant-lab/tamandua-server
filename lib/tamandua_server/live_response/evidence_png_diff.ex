defmodule TamanduaServer.LiveResponse.EvidencePngDiff do
  @moduledoc "Bounded, deterministic PNG pixel diff. No shell process, native decoder, or LLM is used."

  @signature <<137, 80, 78, 71, 13, 10, 26, 10>>
  @max_pixels 524_288
  @max_bytes 8_388_608
  @delta_threshold 8

  def compare(left, right) when is_binary(left) and is_binary(right) do
    with {:ok, a} <- decode(left),
         {:ok, b} <- decode(right),
         :ok <- compatible(a, b) do
      {:ok, metrics(a, b)}
    end
  end

  def compare(_, _), do: {:error, :invalid_png}

  defp decode(binary) when byte_size(binary) <= @max_bytes do
    with <<@signature, chunks::binary>> <- binary,
         {:ok, ihdr, idat} <- chunks(chunks, nil, []),
         {:ok, meta} <- header(ihdr),
         {:ok, raw} <- inflate(idat, meta),
         {:ok, pixels} <- unfilter(raw, meta) do
      {:ok, Map.put(meta, :pixels, pixels)}
    else
      _ -> {:error, :invalid_png}
    end
  rescue
    _ -> {:error, :invalid_png}
  end

  defp decode(_), do: {:error, :image_too_large}

  defp chunks(<<>>, _ihdr, _idat), do: {:error, :invalid_png}

  defp chunks(<<length::32, type::binary-size(4), rest::binary>>, ihdr, idat)
       when length <= @max_bytes and byte_size(rest) >= length + 4 do
    <<data::binary-size(length), crc::32, tail::binary>> = rest

    if :erlang.crc32(type <> data) != crc do
      {:error, :invalid_png}
    else
      case type do
        "IHDR" when is_nil(ihdr) ->
          chunks(tail, data, idat)

        "IDAT" when not is_nil(ihdr) ->
          chunks(tail, ihdr, [data | idat])

        "IEND" when not is_nil(ihdr) ->
          {:ok, ihdr, idat |> Enum.reverse() |> IO.iodata_to_binary()}

        <<first, _::binary>> when first in ?a..?z ->
          chunks(tail, ihdr, idat)

        _ ->
          {:error, :unsupported_png}
      end
    end
  end

  defp chunks(_, _, _), do: {:error, :invalid_png}

  defp header(<<width::32, height::32, 8, color, 0, 0, 0>>)
       when width > 0 and height > 0 and width * height <= @max_pixels and color in [2, 6] do
    bpp = if color == 2, do: 3, else: 4
    {:ok, %{width: width, height: height, bpp: bpp, stride: width * bpp}}
  end

  defp header(_), do: {:error, :unsupported_png}

  defp inflate(idat, %{height: height, stride: stride}) do
    expected = height * (stride + 1)

    if expected <= @max_pixels * 4 + 4_096 do
      z = :zlib.open()

      try do
        :ok = :zlib.inflateInit(z)

        case safe_inflate(z, idat, expected, [], 0) do
          {:ok, raw} when byte_size(raw) == expected -> {:ok, raw}
          {:error, reason} -> {:error, reason}
          _ -> {:error, :invalid_png}
        end
      after
        :zlib.close(z)
      end
    else
      {:error, :image_too_large}
    end
  end

  defp safe_inflate(z, input, cap, acc, size) do
    case :zlib.safeInflate(z, input) do
      {:continue, output} ->
        append_inflate(z, output, cap, acc, size)

      {:finished, output} ->
        with {:ok, acc, size} <- append_output(output, cap, acc, size) do
          _ = size
          {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary()}
        end
    end
  end

  defp append_inflate(z, output, cap, acc, size) do
    with {:ok, acc, size} <- append_output(output, cap, acc, size) do
      safe_inflate(z, <<>>, cap, acc, size)
    end
  end

  defp append_output(output, cap, acc, size) do
    binary = IO.iodata_to_binary(output)
    next = size + byte_size(binary)

    if next <= cap,
      do: {:ok, [binary | acc], next},
      else: {:error, :decompressed_image_too_large}
  end

  defp unfilter(raw, %{height: height, stride: stride, bpp: bpp}) do
    do_unfilter(raw, height, stride, bpp, :binary.copy(<<0>>, stride), [])
  end

  defp do_unfilter(<<>>, 0, _stride, _bpp, _previous, rows),
    do: {:ok, rows |> Enum.reverse() |> IO.iodata_to_binary()}

  defp do_unfilter(<<filter, rest::binary>>, rows_left, stride, bpp, previous, rows)
       when rows_left > 0 and filter in 0..4 and byte_size(rest) >= stride do
    <<encoded::binary-size(stride), remaining::binary>> = rest

    row =
      reconstruct(
        :binary.bin_to_list(encoded),
        :binary.bin_to_list(previous),
        filter,
        bpp,
        [],
        [],
        0
      )

    row_binary = :erlang.list_to_binary(row)
    do_unfilter(remaining, rows_left - 1, stride, bpp, row_binary, [row_binary | rows])
  end

  defp do_unfilter(_, _, _, _, _, _), do: {:error, :invalid_png}

  defp reconstruct([], [], _filter, _bpp, acc, _up_acc, _index), do: Enum.reverse(acc)

  defp reconstruct([value | rest], [up | ups], filter, bpp, acc, up_acc, index) do
    left = if index < bpp, do: 0, else: Enum.at(acc, bpp - 1)
    upper_left = if index < bpp, do: 0, else: Enum.at(up_acc, bpp - 1)

    predictor =
      case filter do
        0 -> 0
        1 -> left
        2 -> up
        3 -> div(left + up, 2)
        4 -> paeth(left, up, upper_left)
      end

    reconstructed = rem(value + predictor, 256)
    reconstruct(rest, ups, filter, bpp, [reconstructed | acc], [up | up_acc], index + 1)
  end

  defp paeth(a, b, c) do
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)

    cond do
      pa <= pb and pa <= pc -> a
      pb <= pc -> b
      true -> c
    end
  end

  defp compatible(a, b) do
    if a.width == b.width and a.height == b.height and a.bpp == b.bpp,
      do: :ok,
      else: {:error, :incompatible_images}
  end

  defp metrics(a, b) do
    initial = %{changed: 0, delta: 0, min_x: nil, min_y: nil, max_x: nil, max_y: nil}
    result = compare_pixels(a.pixels, b.pixels, a.bpp, a.width, 0, initial)
    total = a.width * a.height

    %{
      schema_version: "tamandua.evidence_png_diff/v1",
      width: a.width,
      height: a.height,
      compared_pixels: total,
      changed_pixels: result.changed,
      changed_ratio: result.changed / total,
      mean_absolute_channel_delta: result.delta / (total * a.bpp),
      threshold: @delta_threshold,
      bounding_region: bounding(result)
    }
  end

  defp compare_pixels(<<>>, <<>>, _bpp, _width, _index, acc), do: acc

  defp compare_pixels(left, right, bpp, width, index, acc) do
    <<a::binary-size(bpp), rest_a::binary>> = left
    <<b::binary-size(bpp), rest_b::binary>> = right

    deltas =
      Enum.zip(:binary.bin_to_list(a), :binary.bin_to_list(b))
      |> Enum.map(fn {x, y} -> abs(x - y) end)

    acc = %{acc | delta: acc.delta + Enum.sum(deltas)}

    acc =
      if Enum.max(deltas) > @delta_threshold do
        x = rem(index, width)
        y = div(index, width)

        %{
          acc
          | changed: acc.changed + 1,
            min_x: minimum(acc.min_x, x),
            min_y: minimum(acc.min_y, y),
            max_x: maximum(acc.max_x, x),
            max_y: maximum(acc.max_y, y)
        }
      else
        acc
      end

    compare_pixels(rest_a, rest_b, bpp, width, index + 1, acc)
  end

  defp minimum(nil, value), do: value
  defp minimum(a, b), do: min(a, b)
  defp maximum(nil, value), do: value
  defp maximum(a, b), do: max(a, b)
  defp bounding(%{changed: 0}), do: nil

  defp bounding(r),
    do: %{x: r.min_x, y: r.min_y, width: r.max_x - r.min_x + 1, height: r.max_y - r.min_y + 1}
end
