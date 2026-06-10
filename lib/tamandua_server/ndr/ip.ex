defmodule TamanduaServer.NDR.IP do
  @moduledoc """
  IP classification helpers for NDR.

  Supports IPv4 and IPv6 address strings, including bracketed IPv6 literals and
  scoped link-local addresses such as `fe80::1%eth0`.
  """

  import Bitwise

  @doc "Returns true for internal/local address space used by NDR topology and lateral detection."
  def internal?(ip) do
    classification(ip) in [:private, :loopback, :link_local, :unique_local, :unspecified]
  end

  @doc "Classifies an address as internal/local/public/invalid."
  def classification(ip) when is_binary(ip) do
    ip
    |> normalize_literal()
    |> parse()
    |> classify_tuple()
  end

  def classification(_), do: :invalid

  @doc "Returns a canonical address string when parsing succeeds, otherwise the original trimmed value."
  def canonical(value) when is_binary(value) do
    normalized = normalize_literal(value)

    case parse(normalized) do
      {:ok, tuple} -> tuple |> :inet.ntoa() |> to_string()
      _ -> normalized
    end
  end

  def canonical(value), do: value

  @doc "Returns a stable binary sort key for canonical ordering of IPv4 and IPv6 addresses."
  def sort_key(value) when is_binary(value) do
    normalized = normalize_literal(value)

    case parse(normalized) do
      {:ok, {a, b, c, d}} ->
        <<4, a, b, c, d>>

      {:ok, tuple} when tuple_size(tuple) == 8 ->
        <<6, (tuple_to_binary16(tuple))::binary>>

      _ ->
        <<255, normalized::binary>>
    end
  end

  def sort_key(value), do: <<255, to_string(value)::binary>>

  defp normalize_literal(value) do
    value
    |> String.trim()
    |> extract_host()
    |> strip_scope()
  end

  defp extract_host("[" <> rest) do
    rest
    |> String.split("]", parts: 2)
    |> List.first()
  end

  defp extract_host(value) do
    case String.split(value, ":", parts: 3) do
      [host, port] ->
        if String.contains?(host, ".") and String.match?(port, ~r/^\d+$/), do: host, else: value

      _ ->
        value
    end
  end

  defp strip_scope(value) do
    value
    |> String.split("%", parts: 2)
    |> List.first()
  end

  defp parse(""), do: :error

  defp parse(value) do
    value
    |> String.to_charlist()
    |> :inet.parse_address()
  end

  defp tuple_to_binary16(tuple) do
    tuple
    |> Tuple.to_list()
    |> Enum.reduce(<<>>, fn segment, acc -> <<acc::binary, segment::16>> end)
  end

  defp classify_tuple({:ok, {10, _, _, _}}), do: :private
  defp classify_tuple({:ok, {127, _, _, _}}), do: :loopback
  defp classify_tuple({:ok, {169, 254, _, _}}), do: :link_local
  defp classify_tuple({:ok, {172, second, _, _}}) when second >= 16 and second <= 31, do: :private
  defp classify_tuple({:ok, {192, 168, _, _}}), do: :private
  defp classify_tuple({:ok, {0, 0, 0, 0}}), do: :unspecified

  defp classify_tuple({:ok, {0, 0, 0, 0, 0, 0, 0, 0}}), do: :unspecified
  defp classify_tuple({:ok, {0, 0, 0, 0, 0, 0, 0, 1}}), do: :loopback
  defp classify_tuple({:ok, {first, _, _, _, _, _, _, _}}) when (first &&& 0xFFC0) == 0xFE80, do: :link_local
  defp classify_tuple({:ok, {first, _, _, _, _, _, _, _}}) when (first &&& 0xFE00) == 0xFC00, do: :unique_local

  defp classify_tuple({:ok, {0, 0, 0, 0, 0, 0xFFFF, high, low}}) do
    high_a = high >>> 8
    high_b = high &&& 0xFF
    low_a = low >>> 8
    low_b = low &&& 0xFF

    classify_tuple({:ok, {high_a, high_b, low_a, low_b}})
  end

  defp classify_tuple({:ok, tuple}) when is_tuple(tuple), do: :public
  defp classify_tuple(_), do: :invalid
end
