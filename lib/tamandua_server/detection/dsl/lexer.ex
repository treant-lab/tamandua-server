defmodule TamanduaServer.Detection.DSL.Lexer do
  @moduledoc """
  Lexical analyzer for Tamandua DSL.

  Tokenizes DSL source code into a stream of tokens.
  """

  alias TamanduaServer.Detection.DSL.Grammar

  @type token :: Grammar.token()
  @type position :: {line :: non_neg_integer(), column :: non_neg_integer()}

  @doc """
  Tokenize DSL source code.

  Returns `{:ok, tokens}` or `{:error, message}`.
  """
  @spec tokenize(String.t()) :: {:ok, [token()]} | {:error, String.t()}
  def tokenize(source) do
    try do
      tokens =
        source
        |> String.split("\n", trim: false)
        |> Enum.with_index(1)
        |> Enum.flat_map(&tokenize_line/1)
        |> Enum.concat([:eof])

      {:ok, tokens}
    rescue
      e -> {:error, "Lexer error: #{Exception.message(e)}"}
    end
  end

  defp tokenize_line({line, line_number}) do
    line
    |> remove_comments()
    |> tokenize_string(line_number, 1, [])
  end

  defp remove_comments(line) do
    case String.split(line, "#", parts: 2) do
      [code, _comment] -> code
      [code] -> code
    end
  end

  defp tokenize_string("", _line, _col, acc), do: Enum.reverse(acc)

  # Skip whitespace
  defp tokenize_string(<<c::utf8, rest::binary>>, line, col, acc)
       when c in [?\s, ?\t, ?\r, ?\n] do
    tokenize_string(rest, line, col + 1, acc)
  end

  # String literals
  defp tokenize_string(<<?", rest::binary>>, line, col, acc) do
    {string_content, remaining, new_col} = extract_string(rest, col + 1, "")
    tokenize_string(remaining, line, new_col, [{:string, string_content} | acc])
  end

  # Regex literals
  defp tokenize_string(<<?/, rest::binary>>, line, col, acc) do
    case extract_regex(rest, col + 1, "") do
      {:ok, pattern, remaining, new_col} ->
        tokenize_string(remaining, line, new_col, [{:regex, pattern} | acc])

      :not_regex ->
        # It's just a division operator or symbol
        tokenize_string(rest, line, col + 1, [{:symbol, "/"} | acc])
    end
  end

  # Numbers (including decimals)
  defp tokenize_string(<<c::utf8, rest::binary>>, line, col, acc)
       when c >= ?0 and c <= ?9 do
    {number, remaining, new_col} = extract_number(<<c::utf8, rest::binary>>, col, "")

    # Check if it's a duration (e.g., 5m, 10s)
    case remaining do
      <<unit::utf8, r::binary>> when unit in [?s, ?m, ?h, ?d] ->
        unit_str = <<unit::utf8>>
        tokenize_string(r, line, new_col + 1, [{:duration, {number, unit_str}} | acc])

      _ ->
        tokenize_string(remaining, line, new_col, [{:number, number} | acc])
    end
  end

  # Multi-character operators
  defp tokenize_string(<<"!=", rest::binary>>, line, col, acc) do
    tokenize_string(rest, line, col + 2, [{:operator, "!="} | acc])
  end

  defp tokenize_string(<<">=", rest::binary>>, line, col, acc) do
    tokenize_string(rest, line, col + 2, [{:operator, ">="} | acc])
  end

  defp tokenize_string(<<"<=", rest::binary>>, line, col, acc) do
    tokenize_string(rest, line, col + 2, [{:operator, "<="} | acc])
  end

  defp tokenize_string(<<"->", rest::binary>>, line, col, acc) do
    tokenize_string(rest, line, col + 2, [{:symbol, "->"} | acc])
  end

  # Single-character operators
  defp tokenize_string(<<c::utf8, rest::binary>>, line, col, acc) when c in [?=, ?>, ?<] do
    tokenize_string(rest, line, col + 1, [{:operator, <<c::utf8>>} | acc])
  end

  # Symbols
  defp tokenize_string(<<c::utf8, rest::binary>>, line, col, acc)
       when c in [?{, ?}, ?(, ?), ?[, ?], ?:, ?,, ?.] do
    tokenize_string(rest, line, col + 1, [{:symbol, <<c::utf8>>} | acc])
  end

  # Identifiers and keywords
  defp tokenize_string(<<c::utf8, rest::binary>>, line, col, acc)
       when (c >= ?a and c <= ?z) or (c >= ?A and c <= ?Z) or c == ?_ do
    {identifier, remaining, new_col} = extract_identifier(<<c::utf8, rest::binary>>, col, "")
    token = classify_identifier(identifier)
    tokenize_string(remaining, line, new_col, [token | acc])
  end

  # Unknown character
  defp tokenize_string(<<c::utf8, _rest::binary>>, line, col, _acc) do
    raise "Unexpected character '#{<<c::utf8>>}' at line #{line}, column #{col}"
  end

  # Extract string content (handles escapes)
  defp extract_string(<<?", rest::binary>>, col, acc) do
    {acc, rest, col + 1}
  end

  defp extract_string(<<?\\, ?", rest::binary>>, col, acc) do
    extract_string(rest, col + 2, acc <> "\"")
  end

  defp extract_string(<<?\\, ?n, rest::binary>>, col, acc) do
    extract_string(rest, col + 2, acc <> "\n")
  end

  defp extract_string(<<?\\, ?t, rest::binary>>, col, acc) do
    extract_string(rest, col + 2, acc <> "\t")
  end

  defp extract_string(<<?\\, c::utf8, rest::binary>>, col, acc) do
    extract_string(rest, col + 2, acc <> <<c::utf8>>)
  end

  defp extract_string(<<c::utf8, rest::binary>>, col, acc) do
    extract_string(rest, col + 1, acc <> <<c::utf8>>)
  end

  defp extract_string("", col, _acc) do
    raise "Unterminated string at column #{col}"
  end

  # Extract regex pattern
  defp extract_regex(<<?/, rest::binary>>, col, acc) do
    {:ok, acc, rest, col + 1}
  end

  defp extract_regex(<<?\\, ?/, rest::binary>>, col, acc) do
    extract_regex(rest, col + 2, acc <> "/")
  end

  defp extract_regex(<<c::utf8, rest::binary>>, col, acc) when c != ?\n do
    extract_regex(rest, col + 1, acc <> <<c::utf8>>)
  end

  defp extract_regex(_, _col, _acc) do
    :not_regex
  end

  # Extract number (integer or float)
  defp extract_number(<<c::utf8, rest::binary>>, col, acc)
       when (c >= ?0 and c <= ?9) or c == ?. do
    extract_number(rest, col + 1, acc <> <<c::utf8>>)
  end

  defp extract_number(rest, col, acc) do
    number =
      case String.contains?(acc, ".") do
        true -> String.to_float(acc)
        false -> String.to_integer(acc)
      end

    {number, rest, col}
  end

  # Extract identifier
  defp extract_identifier(<<c::utf8, rest::binary>>, col, acc)
       when (c >= ?a and c <= ?z) or (c >= ?A and c <= ?Z) or (c >= ?0 and c <= ?9) or
              c == ?_ do
    extract_identifier(rest, col + 1, acc <> <<c::utf8>>)
  end

  defp extract_identifier(rest, col, acc) do
    {acc, rest, col}
  end

  # Classify identifier as keyword or identifier
  defp classify_identifier(text) do
    lower = String.downcase(text)

    cond do
      lower in Grammar.keywords() -> {:keyword, lower}
      lower in Grammar.operators() -> {:operator, lower}
      lower in ["true", "false"] -> {:boolean, lower == "true"}
      true -> {:identifier, text}
    end
  end

  @doc """
  Pretty print tokens for debugging.
  """
  def format_tokens(tokens) do
    tokens
    |> Enum.map(fn
      {:identifier, name} -> "IDENT(#{name})"
      {:string, str} -> "STRING(\"#{str}\")"
      {:number, num} -> "NUM(#{num})"
      {:boolean, bool} -> "BOOL(#{bool})"
      {:operator, op} -> "OP(#{op})"
      {:keyword, kw} -> "KW(#{kw})"
      {:symbol, sym} -> "SYM(#{sym})"
      {:duration, {val, unit}} -> "DUR(#{val}#{unit})"
      {:regex, pattern} -> "REGEX(/#{pattern}/)"
      :eof -> "EOF"
    end)
    |> Enum.join(" ")
  end
end
