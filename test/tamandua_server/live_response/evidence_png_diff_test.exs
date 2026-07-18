defmodule TamanduaServer.LiveResponse.EvidencePngDiffTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.LiveResponse.EvidencePngDiff

  test "returns deterministic pixel metrics and a bounded region" do
    left = png(2, 1, <<0, 0, 0, 0, 0, 0, 0>>)
    right = png(2, 1, <<0, 0, 0, 0, 255, 0, 0>>)

    assert {:ok, metrics} = EvidencePngDiff.compare(left, right)
    assert metrics.compared_pixels == 2
    assert metrics.changed_pixels == 1
    assert metrics.changed_ratio == 0.5
    assert metrics.bounding_region == %{x: 1, y: 0, width: 1, height: 1}
    refute Map.has_key?(metrics, :heatmap)
  end

  test "rejects truncated chunks and interlaced PNGs" do
    valid = png(1, 1, <<0, 0, 0, 0>>)

    assert {:error, :invalid_png} =
             EvidencePngDiff.compare(binary_part(valid, 0, byte_size(valid) - 3), valid)

    interlaced = png(1, 1, <<0, 0, 0, 0>>, interlace: 1)
    assert {:error, :invalid_png} = EvidencePngDiff.compare(interlaced, interlaced)
  end

  test "stops inflated output above the exact image bound" do
    bomb = png(1, 1, :binary.copy(<<0>>, 1_000_000))
    valid = png(1, 1, <<0, 0, 0, 0>>)

    assert {:error, :invalid_png} = EvidencePngDiff.compare(bomb, valid)
  end

  test "rejects images above the pixel cap before inflate" do
    oversized = png(2_000, 2_000, <<0>>)
    assert {:error, :invalid_png} = EvidencePngDiff.compare(oversized, oversized)
  end

  defp png(width, height, raw, opts \\ []) do
    ihdr = <<width::32, height::32, 8, 2, 0, 0, Keyword.get(opts, :interlace, 0)>>

    <<137, 80, 78, 71, 13, 10, 26, 10>> <>
      chunk("IHDR", ihdr) <>
      chunk("IDAT", :zlib.compress(raw)) <>
      chunk("IEND", <<>>)
  end

  defp chunk(type, data) do
    <<byte_size(data)::32, type::binary, data::binary, :erlang.crc32(type <> data)::32>>
  end
end
