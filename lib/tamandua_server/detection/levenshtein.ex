defmodule TamanduaServer.Detection.Levenshtein do
  @moduledoc false

  @spec compare(String.t(), String.t()) :: non_neg_integer()
  def compare(left, right) when left == right, do: 0

  def compare(left, right) do
    left_chars = String.graphemes(left)
    right_chars = String.graphemes(right)

    initial_row = Enum.to_list(0..length(right_chars))

    left_chars
    |> Enum.with_index(1)
    |> Enum.reduce(initial_row, fn {left_char, row_index}, previous_row ->
      {_last_cost, row} =
        right_chars
        |> Enum.with_index(1)
        |> Enum.reduce({row_index, [row_index]}, fn {right_char, col_index}, {previous_cost, acc} ->
          insertion = previous_cost + 1
          deletion = Enum.at(previous_row, col_index) + 1
          substitution = Enum.at(previous_row, col_index - 1) + if(left_char == right_char, do: 0, else: 1)
          cost = min(insertion, min(deletion, substitution))
          {cost, [cost | acc]}
        end)

      Enum.reverse(row)
    end)
    |> List.last()
  end
end
