defmodule TamanduaServer.Detection.PIIDetector do
  @moduledoc """
  Fast PII (Personally Identifiable Information) pattern detection using compiled regex.

  Detects:
  - SSN (Social Security Numbers)
  - Credit cards (Visa, Mastercard, Amex, Discover with Luhn validation)
  - Email addresses
  - Phone numbers (US formats)
  - IP addresses (IPv4 and IPv6)
  - API keys (AWS, GitHub, Stripe patterns)
  - Street addresses

  Performance target: <5ms for 10KB text.

  Usage:
      {:ok, result} = PIIDetector.detect("Contact me at john@example.com or 555-123-4567")
      result.has_pii  # => true
      result.pii_types  # => [:email, :phone]
  """

  require Logger

  # ============================================================================
  # Compiled Regex Patterns (module attributes for compile-time optimization)
  # ============================================================================

  # SSN patterns
  @ssn_dashed ~r/\b\d{3}-\d{2}-\d{4}\b/
  @ssn_nodash ~r/\b(?<!\d)\d{9}(?!\d)\b/

  # Credit card patterns (simplified - Luhn validation done separately)
  @visa ~r/\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/
  @mastercard ~r/\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/
  @amex ~r/\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b/
  @discover ~r/\b6(?:011|5\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/

  # Email pattern (simplified RFC 5322)
  @email ~r/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/

  # Phone patterns (US formats)
  @phone_parens ~r/\(\d{3}\)\s*\d{3}[\s-]?\d{4}\b/
  @phone_dashed ~r/\b\d{3}-\d{3}-\d{4}\b/
  @phone_intl ~r/\+1\s?\d{10}\b/
  @phone_dots ~r/\b\d{3}\.\d{3}\.\d{4}\b/

  # IP address patterns
  @ipv4 ~r/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/
  @ipv6 ~r/\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/
  @ipv6_compressed ~r/\b(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b/

  # API key patterns
  @aws_access_key ~r/\bAKIA[0-9A-Z]{16}\b/
  @aws_secret_key ~r/\b[A-Za-z0-9\/+=]{40}\b/
  @github_token ~r/\bgh[pousr]_[A-Za-z0-9_]{36,}\b/
  @stripe_key ~r/\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}\b/
  @generic_api_key ~r/\b(?:api[_-]?key|apikey)[=:]\s*['"]?([A-Za-z0-9_-]{20,})/i

  # Street address patterns
  @street_address ~r/\b\d{1,5}\s+(?:[A-Za-z]+\s+){1,4}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Court|Ct|Way|Circle|Cir|Place|Pl)\.?\b/i

  # ============================================================================
  # Type Definitions
  # ============================================================================

  @type pii_type :: :ssn | :credit_card | :email | :phone | :ip_address | :api_key | :address

  @type pii_match :: %{
          type: pii_type(),
          value: String.t(),
          position: {non_neg_integer(), non_neg_integer()}
        }

  @type detection_result :: %{
          has_pii: boolean(),
          pii_types: list(pii_type()),
          matches: list(pii_match()),
          latency_ms: non_neg_integer()
        }

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Detect PII patterns in text.

  Returns {:ok, result} with:
  - has_pii: Whether any PII was found
  - pii_types: List of PII types found
  - matches: List of matches with type, value, and position
  - latency_ms: Processing time in milliseconds
  """
  @spec detect(String.t()) :: {:ok, detection_result()}
  def detect(text) when is_binary(text) do
    start_time = System.monotonic_time(:millisecond)

    matches =
      []
      |> detect_ssn(text)
      |> detect_credit_cards(text)
      |> detect_emails(text)
      |> detect_phones(text)
      |> detect_ip_addresses(text)
      |> detect_api_keys(text)
      |> detect_addresses(text)

    # Deduplicate overlapping matches
    matches = deduplicate_matches(matches)

    pii_types = matches |> Enum.map(& &1.type) |> Enum.uniq()

    elapsed = System.monotonic_time(:millisecond) - start_time

    # Emit telemetry
    :telemetry.execute(
      [:tamandua, :pii, :detect],
      %{latency_ms: elapsed, match_count: length(matches)},
      %{pii_found: length(matches) > 0, pii_types: pii_types}
    )

    {:ok,
     %{
       has_pii: length(matches) > 0,
       pii_types: pii_types,
       matches: matches,
       latency_ms: elapsed
     }}
  end

  def detect(nil), do: {:ok, %{has_pii: false, pii_types: [], matches: [], latency_ms: 0}}

  @doc """
  Redact PII from text, replacing matches with [REDACTED:type] placeholders.

  ## Examples

      {:ok, text} = PIIDetector.redact("Email me at john@example.com")
      text  # => "Email me at [REDACTED:email]"
  """
  @spec redact(String.t()) :: {:ok, String.t()}
  def redact(text) when is_binary(text) do
    {:ok, result} = detect(text)

    # Sort matches by position in reverse order to maintain correct offsets during replacement
    sorted_matches =
      result.matches
      |> Enum.sort_by(fn %{position: {start, _}} -> start end, :desc)

    redacted =
      Enum.reduce(sorted_matches, text, fn %{type: type, position: {start, finish}}, acc ->
        replacement = "[REDACTED:#{type}]"
        String.slice(acc, 0, start) <> replacement <> String.slice(acc, finish..-1//1)
      end)

    {:ok, redacted}
  end

  def redact(nil), do: {:ok, ""}

  @doc """
  Return list of supported PII types.
  """
  @spec pii_types() :: list(pii_type())
  def pii_types do
    [:ssn, :credit_card, :email, :phone, :ip_address, :api_key, :address]
  end

  # ============================================================================
  # Private Detection Functions
  # ============================================================================

  defp detect_ssn(matches, text) do
    # Dashed SSN
    dashed = scan_pattern(@ssn_dashed, text, :ssn)

    # 9-digit SSN (with validation to reduce false positives)
    nodash =
      @ssn_nodash
      |> Regex.scan(text, return: :index)
      |> Enum.filter(fn [{start, len}] ->
        value = String.slice(text, start, len)
        valid_ssn_format?(value)
      end)
      |> Enum.map(fn [{start, len}] ->
        %{
          type: :ssn,
          value: mask_ssn(String.slice(text, start, len)),
          position: {start, start + len}
        }
      end)

    matches ++ dashed ++ nodash
  end

  defp detect_credit_cards(matches, text) do
    visa = scan_and_validate_cc(@visa, text)
    mastercard = scan_and_validate_cc(@mastercard, text)
    amex = scan_and_validate_cc(@amex, text)
    discover = scan_and_validate_cc(@discover, text)

    matches ++ visa ++ mastercard ++ amex ++ discover
  end

  defp detect_emails(matches, text) do
    matches ++ scan_pattern(@email, text, :email)
  end

  defp detect_phones(matches, text) do
    parens = scan_pattern(@phone_parens, text, :phone)
    dashed = scan_pattern(@phone_dashed, text, :phone)
    intl = scan_pattern(@phone_intl, text, :phone)
    dots = scan_pattern(@phone_dots, text, :phone)

    matches ++ parens ++ dashed ++ intl ++ dots
  end

  defp detect_ip_addresses(matches, text) do
    ipv4 = scan_pattern(@ipv4, text, :ip_address)
    ipv6 = scan_pattern(@ipv6, text, :ip_address)
    ipv6_comp = scan_pattern(@ipv6_compressed, text, :ip_address)

    matches ++ ipv4 ++ ipv6 ++ ipv6_comp
  end

  defp detect_api_keys(matches, text) do
    aws_access = scan_pattern(@aws_access_key, text, :api_key)
    aws_secret = scan_pattern(@aws_secret_key, text, :api_key)
    github = scan_pattern(@github_token, text, :api_key)
    stripe = scan_pattern(@stripe_key, text, :api_key)
    generic = scan_pattern(@generic_api_key, text, :api_key)

    # Filter out aws_secret matches that are too short or likely false positives
    aws_secret_filtered =
      Enum.filter(aws_secret, fn %{value: value} ->
        String.length(value) >= 35 and String.contains?(value, "/")
      end)

    matches ++ aws_access ++ aws_secret_filtered ++ github ++ stripe ++ generic
  end

  defp detect_addresses(matches, text) do
    matches ++ scan_pattern(@street_address, text, :address)
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp scan_pattern(pattern, text, type) do
    pattern
    |> Regex.scan(text, return: :index)
    |> Enum.map(fn
      [{start, len}] ->
        %{
          type: type,
          value: String.slice(text, start, len),
          position: {start, start + len}
        }

      [{start, len} | _captures] ->
        %{
          type: type,
          value: String.slice(text, start, len),
          position: {start, start + len}
        }
    end)
  end

  defp scan_and_validate_cc(pattern, text) do
    pattern
    |> Regex.scan(text, return: :index)
    |> Enum.filter(fn [{start, len}] ->
      value = String.slice(text, start, len)
      luhn_valid?(normalize_cc(value))
    end)
    |> Enum.map(fn [{start, len}] ->
      value = String.slice(text, start, len)

      %{
        type: :credit_card,
        value: mask_credit_card(value),
        position: {start, start + len}
      }
    end)
  end

  defp normalize_cc(value) do
    String.replace(value, ~r/[\s-]/, "")
  end

  # Luhn algorithm for credit card validation
  defp luhn_valid?(number) when is_binary(number) do
    digits = String.graphemes(number)

    if Enum.all?(digits, &(&1 >= "0" and &1 <= "9")) do
      digits
      |> Enum.reverse()
      |> Enum.with_index()
      |> Enum.reduce(0, fn {digit, index}, sum ->
        d = String.to_integer(digit)

        if rem(index, 2) == 1 do
          doubled = d * 2
          sum + if doubled > 9, do: doubled - 9, else: doubled
        else
          sum + d
        end
      end)
      |> rem(10) == 0
    else
      false
    end
  end

  defp valid_ssn_format?(value) do
    # SSN cannot start with 000, 666, or 900-999
    # Also cannot have 00 in middle or 0000 at end
    case String.graphemes(value) do
      [a, b, c, d, e, f, g, h, i] ->
        area = String.to_integer(a <> b <> c)
        group = String.to_integer(d <> e)
        serial = String.to_integer(f <> g <> h <> i)

        area > 0 and area != 666 and area < 900 and
          group > 0 and
          serial > 0

      _ ->
        false
    end
  end

  defp mask_ssn(value) do
    # Mask as XXX-XX-1234
    case String.length(value) do
      9 -> "XXX-XX-" <> String.slice(value, -4, 4)
      11 -> "XXX-XX-" <> String.slice(value, -4, 4)
      _ -> "XXX-XX-XXXX"
    end
  end

  defp mask_credit_card(value) do
    normalized = normalize_cc(value)
    len = String.length(normalized)

    if len >= 4 do
      "**** **** **** " <> String.slice(normalized, -4, 4)
    else
      "****"
    end
  end

  defp deduplicate_matches(matches) do
    # Remove overlapping matches, keeping the more specific one
    matches
    |> Enum.sort_by(fn %{position: {start, _}} -> start end)
    |> Enum.reduce([], fn match, acc ->
      case acc do
        [] ->
          [match]

        [last | rest] ->
          {last_start, last_end} = last.position
          {match_start, match_end} = match.position

          if match_start < last_end do
            # Overlapping - keep the longer match
            if match_end - match_start > last_end - last_start do
              [match | rest]
            else
              acc
            end
          else
            [match | acc]
          end
      end
    end)
    |> Enum.reverse()
  end
end
